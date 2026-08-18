import { readFileSync, writeFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import {
  LAB_CONVERSATION_ID,
  LAB_GENESIS_PREVIOUS_HEAD_HASH,
  fictionalAppendRequest,
  fictionalDeliveryLabSeed,
  fictionalDeliveryTrustContext,
} from "../delivery/fixtures.testing";
import { createFictionalDeliveryCryptoPorts } from "../delivery/fictionalCryptoPorts.testing";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeLogHeadHash,
} from "../delivery/hashes";
import type { ProductionDeliveryPorts } from "../delivery/ports";
import { spawnSync } from "node:child_process";
import process from "node:process";
import {
  createApplicationEnvelopeDeliveryService,
  parsePendingApplicationAppendIntent,
} from "../delivery/service";
import {
  parseConversationId,
  parseHash32,
  parseRfc3339Millis,
  parseSigningKeyId,
  type Rfc3339Millis,
} from "../delivery/valueObjects";
import { installDeliveryLabClock } from "./postgresDeliveryLab.testing";
import {
  createPostgresDeliveryAppendStore,
  type PostgresDeliveryAppendStore,
} from "./postgresDeliveryStore";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const PHASE = process.env.JBM_RESTORE_DRILL_PHASE;
const STATE_PATH = process.env.JBM_RESTORE_DRILL_STATE;
const describeDrill =
  DATABASE_URL && PHASE && STATE_PATH ? describe : describe.skip;

const STRAND_ENVELOPE_ID = "655609f1-9662-49f6-9cda-9ef319abe51d";
const STRAND_IDEMPOTENCY_KEY = "0198a5df-4c58-7e31-bbf1-0fd4c09e4acf";
const DRAIN_ENVELOPE_ID = "665609f1-9662-49f6-9cda-9ef319abe51d";
const DRAIN_IDEMPOTENCY_KEY = "0198a5e0-4c58-7e31-bbf1-0fd4c09e4acf";
const PREPARE_NOW = "2026-08-14T16:22:30.123Z";
const VERIFY_NOW = "2026-08-14T16:23:30.123Z";

interface DrillState {
  readonly originalReceipt: unknown;
  readonly strandedIntentDigest: string;
  readonly strandedPosition: string;
  readonly acceptedPositions: readonly string[];
}

describeDrill(`restore drill (${PHASE} phase)`, () => {
  const seed = fictionalDeliveryLabSeed();
  let sql: Sql;
  let store: PostgresDeliveryAppendStore;
  const now: Rfc3339Millis = parseRfc3339Millis(
    PHASE === "prepare" ? PREPARE_NOW : VERIFY_NOW,
  );

  const buildPorts = (
    overrides: Partial<ProductionDeliveryPorts> = {},
  ): ProductionDeliveryPorts => {
    const crypto = createFictionalDeliveryCryptoPorts({
      now: () => now,
      snapshot: () =>
        store.loadSnapshot(parseConversationId(LAB_CONVERSATION_ID)),
      signingKeyId: parseSigningKeyId(seed.signingKeyId),
      signingKeyValidFrom: parseRfc3339Millis(seed.signingKeyValidFrom),
      signingKeyValidUntil: parseRfc3339Millis(seed.signingKeyValidUntil),
    });
    const unavailablePort = {
      verify: () =>
        Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
    };
    return {
      mlsWireInspector: crypto.mlsWireInspector,
      mlsCommitProjectionVerifier: unavailablePort,
      mlsExternalProposalVerifier: unavailablePort,
      policyHeadProofVerifier: crypto.policyHeadProofVerifier,
      conversationPolicyReplayVerifier: unavailablePort,
      checkpointSigner: crypto.checkpointSigner,
      signerFenceEvidenceVerifier: crypto.signerFenceEvidenceVerifier,
      checkpointSignatureVerifier: crypto.checkpointSignatureVerifier,
      conversationPageProofVerifier: unavailablePort,
      conversationLogHeadProofVerifier: unavailablePort,
      applicationAppendPreflight: store.applicationAppendPreflight,
      atomicPersistence: store.atomicPersistence,
      clock: { now: () => now },
      conversationCursorCodec: {
        decode: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
        encode: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      invariantIncident: {
        record: () => Promise.resolve({ status: "recorded-in-fictional-lab" }),
      },
      ...overrides,
    };
  };

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    store = createPostgresDeliveryAppendStore({ sql, now: () => now });
    await installDeliveryLabClock(sql, now);
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  if (PHASE === "prepare") {
    it("records the client-visible receipt and strands one live pending for the backup", async () => {
      const service = createApplicationEnvelopeDeliveryService(
        buildPorts(),
        fictionalDeliveryTrustContext(),
      );
      const replay = await service.appendApplicationEnvelope(
        fictionalAppendRequest(),
      );
      expect(replay).toMatchObject({ status: "accepted" });
      if (replay.status !== "accepted") throw new Error("replay not accepted");

      let strand = true;
      const strandingService = createApplicationEnvelopeDeliveryService(
        buildPorts({
          checkpointSigner: {
            signExact: async (request) => {
              if (strand) {
                strand = false;
                return {
                  status: "unavailable",
                  reasonCode: "dependency-unavailable",
                };
              }
              return buildPorts().checkpointSigner.signExact(request);
            },
            resolveOrCancelIfUnsigned: (request) =>
              buildPorts().checkpointSigner.resolveOrCancelIfUnsigned(request),
          },
        }),
        fictionalDeliveryTrustContext(),
      );
      const stranded = await strandingService.appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: STRAND_ENVELOPE_ID,
          idempotencyKey: STRAND_IDEMPOTENCY_KEY,
          ciphertextText: "restore drill stranded application",
        }),
      );
      expect(stranded).toEqual({
        status: "unavailable",
        reasonCode: "dependency-unavailable",
      });
      const [pendingRow] = await sql`
        SELECT encode(intent_digest, 'hex') AS intent_digest, position
        FROM application_append_pendings
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      const acceptedRows = await sql`
        SELECT position FROM application_append_acceptances
        WHERE conversation_id = ${LAB_CONVERSATION_ID} ORDER BY position`;
      const state: DrillState = {
        originalReceipt: replay.receipt,
        strandedIntentDigest: String(pendingRow.intent_digest),
        strandedPosition: String(pendingRow.position),
        acceptedPositions: acceptedRows.map((row) => String(row.position)),
      };
      writeFileSync(STATE_PATH!, JSON.stringify(state));
    });
    return;
  }

  const state = (): DrillState =>
    JSON.parse(readFileSync(STATE_PATH!, "utf8")) as DrillState;

  it("verifies migration checksums against the restored ledger", () => {
    const migratePath = new URL(
      "../../../scripts/storage/migrate.mjs",
      import.meta.url,
    ).pathname;
    const settle = spawnSync(process.execPath, [migratePath], {
      encoding: "utf8",
      env: { ...process.env, JBM_STORAGE_DATABASE_URL: DATABASE_URL },
    });
    expect(settle.status).toBe(0);
    expect(settle.stderr).toMatch(/migrations, 0 newly applied/);
  });

  it("recomputes the envelope hash chain from restored relational rows alone", async () => {
    const rows = await sql`
      SELECT position, envelope_id, envelope_class, sender_account_id,
             sender_installation_id, epoch, roster_version, content_type,
             encode(envelope_sha256, 'base64') AS envelope_sha256,
             encode(previous_head_hash, 'base64') AS previous_head_hash,
             encode(leaf_hash, 'base64') AS leaf_hash,
             encode(head_hash, 'base64') AS head_hash,
             log_signing_key_id,
             encode(log_checkpoint_digest, 'base64') AS log_checkpoint_digest,
             received_at
      FROM envelopes
      WHERE conversation_id = ${LAB_CONVERSATION_ID}
      ORDER BY position`;
    expect(rows.length).toBeGreaterThan(0);
    let previousHead = parseHash32(LAB_GENESIS_PREVIOUS_HEAD_HASH);
    for (const row of rows) {
      const receivedAt = parseRfc3339Millis(
        new Date(row.received_at).toISOString(),
      );
      const leaf = computeEnvelopeLeafHash({
        conversationId: parseConversationId(LAB_CONVERSATION_ID),
        position: String(row.position),
        envelopeId: String(row.envelope_id),
        envelopeClass: String(row.envelope_class),
        sender: {
          type: "installation",
          accountId: String(row.sender_account_id),
          installationId: String(row.sender_installation_id),
        },
        epoch: String(row.epoch),
        rosterVersion: String(row.roster_version),
        contentType: String(row.content_type),
        envelopeSha256: parseHash32(fromPgBase64(row.envelope_sha256)),
        receivedAt,
      } as Parameters<typeof computeEnvelopeLeafHash>[0]);
      expect(fromPgBase64(row.previous_head_hash)).toBe(previousHead);
      expect(fromPgBase64(row.leaf_hash)).toBe(leaf);
      const head = computeLogHeadHash(previousHead, leaf);
      expect(fromPgBase64(row.head_hash)).toBe(head);
      expect(fromPgBase64(row.log_checkpoint_digest)).toBe(
        computeDeliveryLogCheckpointDigest({
          conversationId: parseConversationId(LAB_CONVERSATION_ID),
          position: String(row.position),
          previousHeadHash: previousHead,
          headHash: head,
          signingKeyId: parseSigningKeyId(String(row.log_signing_key_id)),
        } as Parameters<typeof computeDeliveryLogCheckpointDigest>[0]),
      );
      previousHead = head;
    }
    const [conversationRow] = await sql`
      SELECT last_position, encode(current_log_head_hash, 'base64') AS head
      FROM conversations WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(conversationRow.last_position)).toBe(
      String(rows.at(-1)!.position),
    );
    expect(fromPgBase64(conversationRow.head)).toBe(previousHead);
  });

  it("verifies mailbox boundaries and acceptance linkage without decryption", async () => {
    const mailboxes = await sql`
      SELECT installation_id, array_agg(mailbox_position ORDER BY mailbox_position) AS positions
      FROM mailbox_entries GROUP BY installation_id`;
    for (const mailbox of mailboxes) {
      const positions = (mailbox.positions as unknown[]).map(String);
      positions.forEach((position, index) => {
        expect(position).toBe(String(index + 1));
      });
    }
    const [linkage] = await sql`
      SELECT count(*) AS broken
      FROM application_append_acceptances a
      LEFT JOIN envelopes e
        ON e.conversation_id = a.conversation_id AND e.position = a.position
          AND e.envelope_id = a.envelope_id
      WHERE e.position IS NULL`;
    expect(String(linkage.broken)).toBe("0");
    expect(
      (
        await sql`SELECT position FROM application_append_acceptances
                  WHERE conversation_id = ${LAB_CONVERSATION_ID} ORDER BY position`
      ).map((row) => String(row.position)),
    ).toEqual(state().acceptedPositions);
  });

  it("keeps the stranded reservation as the sole non-reusable lane fence", async () => {
    const pendings = await sql`
      SELECT pending_canonical, encode(intent_digest, 'hex') AS intent_digest, position
      FROM application_append_pendings
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(pendings.length).toBe(1);
    expect(String(pendings[0].intent_digest)).toBe(state().strandedIntentDigest);
    const pending = parsePendingApplicationAppendIntent(
      typeof pendings[0].pending_canonical === "string"
        ? JSON.parse(pendings[0].pending_canonical)
        : pendings[0].pending_canonical,
    );
    expect(pending.envelope.position).toBe(state().strandedPosition);
    const [acceptedAtPosition] = await sql`
      SELECT count(*) AS conflicts FROM application_append_acceptances
      WHERE conversation_id = ${LAB_CONVERSATION_ID}
        AND position = ${state().strandedPosition}`;
    expect(String(acceptedAtPosition.conflicts)).toBe("0");
  });

  it("replays the acknowledged envelope with an identical client-visible receipt", async () => {
    const service = createApplicationEnvelopeDeliveryService(
      buildPorts(),
      fictionalDeliveryTrustContext(),
    );
    const replay = await service.appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    expect(replay).toMatchObject({ status: "accepted" });
    if (replay.status !== "accepted") throw new Error("replay not accepted");
    expect(JSON.stringify(replay.receipt)).toBe(
      JSON.stringify(state().originalReceipt),
    );
  });

  it("drains the restored stranded pending and reuses its fenced position", async () => {
    const service = createApplicationEnvelopeDeliveryService(
      buildPorts(),
      fictionalDeliveryTrustContext(),
    );
    const drained = await service.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: DRAIN_ENVELOPE_ID,
        idempotencyKey: DRAIN_IDEMPOTENCY_KEY,
        ciphertextText: "post-restore drained application",
      }),
    );
    expect(drained).toMatchObject({
      status: "accepted",
      receipt: { position: state().strandedPosition },
    });
    const [tombstones] = await sql`
      SELECT count(*) AS retirements FROM application_append_retirements
      WHERE conversation_id = ${LAB_CONVERSATION_ID}
        AND encode(intent_digest, 'hex') = ${state().strandedIntentDigest}`;
    expect(String(tombstones.retirements)).toBe("1");
  });
});

function fromPgBase64(value: unknown): string {
  return String(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
