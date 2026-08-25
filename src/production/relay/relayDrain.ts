import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import type {
  RelayBridgePort,
  RelayInstallationStore,
} from "../storage/relayInstallationStore";
import {
  conversationTag,
  renderOutbound,
  type RelayEnvelopeContext,
} from "./relayFormat";

/**
 * ADR 0006 §4, the outbound path. For every active relay: join any
 * Welcome addressed to it (the relay is always the welcomed side), then
 * fold every envelope after its processed position into the sealed state -
 * Commits are merged, application messages are opened and forwarded to the
 * served member's verified channel with the relayFormat rendering - and
 * advance the watermarks. All of it under FOR UPDATE of the relay row
 * (relayInstallationStore.withState), one relay per transaction.
 *
 * Failure model: a channel send that fails after the message was opened is
 * logged and counted as forwarded - MLS ratchets forward, the plaintext is
 * never persisted, and the member still has the message in the app. A
 * bridge failure on one relay leaves that relay at its previous state and
 * never blocks the others.
 */

export interface RelayDrainDeps {
  readonly sql: Sql;
  readonly relays: RelayInstallationStore;
  readonly bridge: RelayBridgePort;
  /** Verified channel targets for an account (notificationChannelStore.activeTargets). */
  readonly activeTargets: (
    accountId: string,
  ) => Promise<readonly { kind: string; target: string }[]>;
  /** Channel delivery; false means the provider refused. */
  readonly sendText: (
    channelKind: string,
    target: string,
    text: string,
  ) => Promise<boolean>;
  /** Best-effort display name; null falls back to "Project #id". */
  readonly projectName: (
    chainId: string,
    projectId: string,
  ) => Promise<string | null>;
}

export interface RelayDrainReport {
  readonly relays: number;
  readonly joined: number;
  readonly commits: number;
  readonly forwarded: number;
  readonly sendFailures: number;
  readonly skipped: readonly string[];
}

export async function runRelayDrain(deps: RelayDrainDeps): Promise<RelayDrainReport> {
  const relays = await deps.relays.listActive();
  const report = {
    relays: relays.length,
    joined: 0,
    commits: 0,
    forwarded: 0,
    sendFailures: 0,
    skipped: [] as string[],
  };
  for (const relay of relays) {
    try {
      const outcome = await drainOne(deps, relay);
      report.joined += outcome.joined;
      report.commits += outcome.commits;
      report.forwarded += outcome.forwarded;
      report.sendFailures += outcome.sendFailures;
    } catch (error) {
      console.error(
        `relay drain skipped ${relay.relayInstallationId}: ${String(error)}`,
      );
      report.skipped.push(relay.relayInstallationId);
    }
  }
  return Object.freeze({ ...report, skipped: Object.freeze(report.skipped) });
}

async function drainOne(
  deps: RelayDrainDeps,
  relay: { relayInstallationId: string; servedAccountId: string; channelKind: string },
): Promise<{ joined: number; commits: number; forwarded: number; sendFailures: number }> {
  const target = (await deps.activeTargets(relay.servedAccountId)).find(
    (candidate) => candidate.kind === relay.channelKind,
  );
  return deps.relays.withState(relay.relayInstallationId, async (initial, tx) => {
    let state = initial;
    let joined = 0;
    let commits = 0;
    let forwarded = 0;
    let sendFailures = 0;

    // 1. Welcomes the relay has not joined yet.
    const welcomes = await tx`
      SELECT w.conversation_id, w.commit_position,
             encode(w.welcome_bytes, 'base64') AS welcome
      FROM mls_welcomes w
      WHERE w.target_installation_id = ${relay.relayInstallationId}
        AND NOT EXISTS (
          SELECT 1 FROM relay_forward_watermarks f
          WHERE f.relay_installation_id = ${relay.relayInstallationId}
            AND f.conversation_id = w.conversation_id
        )
      ORDER BY w.created_at`;
    for (const welcome of welcomes) {
      const welcomeBase64Url = Buffer.from(
        String(welcome.welcome).replace(/\s/g, ""),
        "base64",
      ).toString("base64url");
      const result = await deps.bridge.joinWelcome(state, welcomeBase64Url);
      state = result.state;
      await tx`
        INSERT INTO relay_forward_watermarks (
          relay_installation_id, conversation_id, forwarded_position,
          processed_position, mls_group_id, updated_at
        ) VALUES (
          ${relay.relayInstallationId}, ${String(welcome.conversation_id)},
          ${String(welcome.commit_position)}, ${String(welcome.commit_position)},
          ${Buffer.from(result.groupId, "base64url")}, delivery_db_now()
        )`;
      joined += 1;
    }

    // 2. Every conversation the relay is seated in, in envelope order.
    const seats = await tx`
      SELECT f.conversation_id, f.processed_position, f.forwarded_position,
             encode(f.mls_group_id, 'base64') AS group_id,
             c.state AS conversation_state, c.project_ref_id,
             p.chain_id, p.project_id::text AS project_id
      FROM relay_forward_watermarks f
      JOIN memberships m
        ON m.conversation_id = f.conversation_id
       AND m.installation_id = f.relay_installation_id
       AND m.removed_at IS NULL
      JOIN conversations c ON c.conversation_id = f.conversation_id
      JOIN project_refs p ON p.project_ref_id = c.project_ref_id
      WHERE f.relay_installation_id = ${relay.relayInstallationId}
        AND f.mls_group_id IS NOT NULL
      ORDER BY f.conversation_id`;
    for (const seat of seats) {
      const conversationId = String(seat.conversation_id);
      const groupId = Buffer.from(
        String(seat.group_id).replace(/\s/g, ""),
        "base64",
      ).toString("base64url");
      const envelopes = await tx`
        SELECT e.position, e.envelope_class, e.sender_installation_id,
               encode(e.envelope_bytes, 'base64') AS bytes, m.role
        FROM envelopes e
        LEFT JOIN memberships m
          ON m.conversation_id = e.conversation_id
         AND m.installation_id = e.sender_installation_id
        WHERE e.conversation_id = ${conversationId}
          AND e.position > ${String(seat.processed_position)}
        ORDER BY e.position`;
      let processed = String(seat.processed_position);
      let forwardedPosition = String(seat.forwarded_position);
      let context: RelayEnvelopeContext | null = null;
      for (const envelope of envelopes) {
        const position = String(envelope.position);
        const bytes = Buffer.from(
          String(envelope.bytes).replace(/\s/g, ""),
          "base64",
        ).toString("base64url");
        const envelopeClass = String(envelope.envelope_class);
        if (envelopeClass === "mls_commit") {
          state = (await deps.bridge.processCommit(state, groupId, bytes)).state;
          commits += 1;
        } else if (
          envelopeClass === "application" &&
          String(envelope.sender_installation_id) !== relay.relayInstallationId
        ) {
          const opened = await deps.bridge.openApplication(state, groupId, bytes);
          state = opened.state;
          if (target) {
            context ??= {
              projectName: await deps.projectName(
                String(seat.chain_id),
                String(seat.project_id),
              ),
              projectId: String(seat.project_id),
              senderRole: String(envelope.role ?? "project-staff"),
              tag: conversationTag(conversationId),
            };
            const text = renderOutbound(
              { ...context, senderRole: String(envelope.role ?? "project-staff") },
              Buffer.from(opened.plaintext).toString("utf8"),
            );
            const sent = await deps.sendText(relay.channelKind, target.target, text);
            if (sent) forwarded += 1;
            else sendFailures += 1;
          }
          forwardedPosition = position;
        }
        processed = position;
      }
      if (processed !== String(seat.processed_position)) {
        await tx`
          UPDATE relay_forward_watermarks SET
            processed_position = ${processed},
            forwarded_position = ${forwardedPosition},
            updated_at = delivery_db_now()
          WHERE relay_installation_id = ${relay.relayInstallationId}
            AND conversation_id = ${conversationId}`;
      }
    }
    return { state, result: { joined, commits, forwarded, sendFailures } };
  });
}
