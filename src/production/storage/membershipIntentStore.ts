import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import { computeApplicationAppendMlsRosterHash } from "../delivery/state";
import { refreshCustodySnapshotDigest } from "./postgresDeliveryStore";

const INTENT_TTL_MILLISECONDS = 5 * 60 * 1_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SEND_ROLES: Record<string, readonly string[]> = {
  purchase_support: ["customer", "project-staff"],
  community: ["member", "moderator"],
  announcement: ["publisher"],
};

export interface MembershipIntentStoreContext {
  readonly sql: Sql;
}

export type MembershipIntentCreation =
  | {
      readonly status: "created";
      readonly intentId: string;
      readonly operation: "add" | "remove";
      readonly baseEpoch: string;
      readonly baseRosterVersion: string;
      readonly proposedRosterHash: string;
      readonly takenKeyPackage: {
        readonly keyPackageRef: string;
        readonly keyPackageSha256: string;
        readonly keyPackage: string;
      } | null;
      readonly authorizedCommitterInstallationIds: readonly string[];
      readonly expiresAt: string;
    }
  | { readonly status: "conflict"; readonly reasonCode: "membership_intent_conflict" }
  | {
      readonly status: "refused";
      readonly reasonCode:
        | "conversation-not-active"
        | "grant-required"
        | "grant-invalid"
        | "target-not-enrolled"
        | "target-credential-missing"
        | "target-not-a-member"
        | "key-package-unavailable"
        | "malformed-request";
    };

export type MembershipIntentResolution =
  | { readonly status: "resolved"; readonly intentId: string; readonly state: string }
  | { readonly status: "unknown" };

export interface MembershipIntentStore {
  readonly createIntent: (input: unknown) => Promise<MembershipIntentCreation>;
  readonly cancelIntent: (
    intentId: string,
    requestedByInstallationId: string,
  ) => Promise<MembershipIntentResolution>;
  readonly expireIntents: () => Promise<number>;
  readonly readIntent: (intentId: string) => Promise<MembershipIntentResolution>;
}

/**
 * The membership-intent state machine over the spec-baseline tables
 * (service-api.md membership-intents section, ADR 0003 for the two gap
 * decisions). Creating an add intent atomically and irreversibly takes the
 * target's one available KeyPackage - expiry and cancellation never return
 * it to inventory - and flips the conversation to membership_pending by
 * compare-and-swap; one live intent per target is a partial unique index,
 * not code. Eligibility arrives as a pre-resolved grant ID (the HTTP layer
 * resolves the claim handle) and is re-validated relationally here: active,
 * unexpired, owned by the target's account, capability admitting the
 * conversation's purpose. The authorized-committer set is derived from
 * live memberships under the closed role matrix, never stored. Expiry of a
 * non-removal intent returns the conversation to active; expired removal
 * intents leave it pending, because an unresolved removal still blocks
 * application sends. The MLS proposal/Commit consumption path is the next
 * unit; this store never fabricates MLS facts.
 */
export function createMembershipIntentStore(
  context: MembershipIntentStoreContext,
): MembershipIntentStore {
  const { sql } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  const authorizedCommitters = async (
    tx: TransactionSql,
    conversationId: string,
    purpose: string,
    excludedInstallationId: string | null,
  ): Promise<readonly string[]> => {
    const roles = SEND_ROLES[purpose] ?? [];
    const rows = await tx`
      SELECT m.installation_id FROM memberships m
      WHERE m.conversation_id = ${conversationId}
        AND m.removed_at IS NULL
        AND m.role = ANY(${roles as string[]})
        AND m.installation_id NOT IN (
          SELECT target_installation_id FROM membership_intents
          WHERE conversation_id = ${conversationId}
            AND operation = 'remove'
            AND state IN ('requested', 'authorized', 'proposed')
        )
      ORDER BY m.installation_id`;
    return rows
      .map((row) => String(row.installation_id))
      .filter((id) => id !== excludedInstallationId);
  };

  return Object.freeze({
    async createIntent(inputValue: unknown): Promise<MembershipIntentCreation> {
      let operation: "add" | "remove";
      let conversationId: string;
      let targetInstallationId: string;
      let requestedByInstallationId: string | null;
      let grantId: string | null;
      try {
        const record = expectRecord(inputValue, [
          "operation",
          "conversationId",
          "targetInstallationId",
          "requestedByInstallationId",
          "grantId",
        ]);
        if (record.operation !== "add" && record.operation !== "remove") {
          throw new TypeError("Unsupported membership operation.");
        }
        operation = record.operation;
        conversationId = expectUuid(record.conversationId);
        targetInstallationId = expectUuid(record.targetInstallationId);
        requestedByInstallationId =
          record.requestedByInstallationId === null
            ? null
            : expectUuid(record.requestedByInstallationId);
        grantId = record.grantId === null ? null : expectUuid(record.grantId);
      } catch {
        return Object.freeze({
          status: "refused",
          reasonCode: "malformed-request",
        });
      }

      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const conversations = await tx`
          SELECT delivery_purpose, state, epoch, roster_version,
                 confirmed_transcript_hash, generation
          FROM conversations
          WHERE conversation_id = ${conversationId}
          FOR UPDATE`;
        if (conversations.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "conversation-not-active" as const,
          });
        }
        // A duplicate intent for the same target reports conflict even while
        // the conversation is already membership_pending; the partial unique
        // index below stays the race backstop.
        const liveIntents = await tx`
          SELECT 1 FROM membership_intents
          WHERE conversation_id = ${conversationId}
            AND target_installation_id = ${targetInstallationId}
            AND state IN ('requested', 'authorized', 'proposed')`;
        if (liveIntents.length !== 0) {
          return Object.freeze({
            status: "conflict" as const,
            reasonCode: "membership_intent_conflict" as const,
          });
        }
        if (String(conversations[0].state) !== "active") {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "conversation-not-active" as const,
          });
        }
        const conversation = conversations[0];
        const purpose = String(conversation.delivery_purpose);

        const targets = await tx`
          SELECT account_id, status FROM installations
          WHERE installation_id = ${targetInstallationId}`;
        if (targets.length !== 1 || String(targets[0].status) !== "active") {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "target-not-enrolled" as const,
          });
        }
        const targetAccountId = String(targets[0].account_id);

        if (operation === "add") {
          if (grantId === null) {
            return Object.freeze({
              status: "refused" as const,
              reasonCode: "grant-required" as const,
            });
          }
          const grants = await tx`
            SELECT account_id, state, valid_until, capability
            FROM eligibility_grants
            WHERE grant_id = ${grantId} FOR UPDATE`;
          const admittedCapabilities =
            purpose === "purchase_support"
              ? ["purchase-support", "project-staff"]
              : ["purchase-support", "project-staff", "token-holder", "item-set-buyer"];
          if (
            grants.length !== 1 ||
            String(grants[0].state) !== "active" ||
            new Date(grants[0].valid_until as Date).toISOString() <= now ||
            String(grants[0].account_id) !== targetAccountId ||
            !admittedCapabilities.includes(String(grants[0].capability))
          ) {
            return Object.freeze({
              status: "refused" as const,
              reasonCode: "grant-invalid" as const,
            });
          }
        } else {
          const memberships = await tx`
            SELECT 1 FROM memberships
            WHERE conversation_id = ${conversationId}
              AND installation_id = ${targetInstallationId}
              AND removed_at IS NULL`;
          if (memberships.length !== 1) {
            return Object.freeze({
              status: "refused" as const,
              reasonCode: "target-not-a-member" as const,
            });
          }
        }

        const intentId = uuidV7(now);
        const expiresAt = new Date(
          Date.parse(now) + INTENT_TTL_MILLISECONDS,
        ).toISOString();

        // The taken_by_intent_id FK points at membership_intents, so the take
        // is locked here but written only after the intent row exists.
        let takenKeyPackage: {
          readonly keyPackageRef: string;
          readonly keyPackageSha256: string;
          readonly keyPackage: string;
        } | null = null;
        if (operation === "add") {
          const locked = await tx`
            SELECT encode(key_package_ref, 'base64') AS ref,
                   encode(package_sha256, 'base64') AS sha,
                   encode(package_bytes, 'base64') AS bytes
            FROM key_packages
            WHERE installation_id = ${targetInstallationId}
              AND state = 'available' AND taken_at IS NULL
              AND expires_at > ${now}::timestamptz
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED`;
          if (locked.length !== 1) {
            return Object.freeze({
              status: "refused" as const,
              reasonCode: "key-package-unavailable" as const,
            });
          }
          takenKeyPackage = Object.freeze({
            keyPackageRef: fromPgBase64(locked[0].ref),
            keyPackageSha256: fromPgBase64(locked[0].sha),
            keyPackage: fromPgBase64(locked[0].bytes),
          });
        }

        const rosterRows = await tx`
          SELECT installation_id, account_id, credential_id,
                 encode(credential_fingerprint, 'base64') AS fingerprint,
                 conversation_generation, roster_version
          FROM conversation_roster_projections
          WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
        const projectedRoster = rosterRows
          .filter(
            (row) =>
              operation !== "remove" ||
              String(row.installation_id) !== targetInstallationId,
          )
          .map((row) => ({
            conversationId,
            conversationGeneration: String(row.conversation_generation),
            rosterVersion: String(BigInt(String(row.roster_version)) + 1n),
            accountId: String(row.account_id),
            installationId: String(row.installation_id),
            credentialId: String(row.credential_id),
            credentialFingerprint: fromPgBase64(row.fingerprint),
          }));
        if (operation === "add") {
          // The roster projects the target's conversation role credential -
          // the same identity the Commit's membership row binds - so the
          // proposed hash computed here is provable at Commit time.
          const credentials = await tx`
            SELECT credential_id,
                   encode(credential_fingerprint, 'base64') AS fingerprint
            FROM role_credentials
            WHERE conversation_id = ${conversationId}
              AND installation_id = ${targetInstallationId}
              AND state = 'active'
              AND expires_at > ${now}::timestamptz`;
          if (credentials.length !== 1) {
            return Object.freeze({
              status: "refused" as const,
              reasonCode: "target-credential-missing" as const,
            });
          }
          projectedRoster.push({
            conversationId,
            conversationGeneration: String(conversation.generation),
            rosterVersion: String(
              BigInt(String(conversation.roster_version)) + 1n,
            ),
            accountId: targetAccountId,
            installationId: targetInstallationId,
            credentialId: String(credentials[0].credential_id),
            credentialFingerprint: fromPgBase64(credentials[0].fingerprint),
          });
        }
        const proposedRosterHash = computeApplicationAppendMlsRosterHash(
          projectedRoster as unknown as Parameters<
            typeof computeApplicationAppendMlsRosterHash
          >[0],
        );

        try {
          await tx`
            INSERT INTO membership_intents (
              intent_id, conversation_id, operation, target_installation_id,
              requested_by_installation_id, grant_id, key_package_ref,
              base_epoch, base_roster_version, base_confirmed_transcript_hash,
              proposed_roster_hash, state, created_at, expires_at
            ) VALUES (
              ${intentId}, ${conversationId}, ${operation},
              ${targetInstallationId}, ${requestedByInstallationId}, ${grantId},
              ${
                takenKeyPackage === null
                  ? null
                  : Buffer.from(takenKeyPackage.keyPackageRef, "base64url")
              },
              ${String(conversation.epoch)},
              ${String(conversation.roster_version)},
              ${Buffer.from(conversation.confirmed_transcript_hash as Uint8Array)},
              ${Buffer.from(proposedRosterHash, "base64url")}, 'requested',
              ${now}::timestamptz, ${expiresAt}::timestamptz
            )`;
        } catch (error) {
          if (String(error).includes("membership_one_pending_target_idx")) {
            return Object.freeze({
              status: "conflict" as const,
              reasonCode: "membership_intent_conflict" as const,
            });
          }
          throw error;
        }
        if (takenKeyPackage !== null) {
          const taken = await tx`
            UPDATE key_packages SET
              state = 'taken', taken_at = ${now}::timestamptz,
              taken_by_intent_id = ${intentId}
            WHERE key_package_ref = ${Buffer.from(
              takenKeyPackage.keyPackageRef,
              "base64url",
            )} AND state = 'available'`;
          if (taken.count !== 1) {
            throw new Error("The locked KeyPackage vanished mid-take.");
          }
        }
        await tx`
          UPDATE conversations SET state = 'membership_pending'
          WHERE conversation_id = ${conversationId} AND state = 'active'`;
        // State and pending-removal count are custody-fenced fields.
        await refreshCustodySnapshotDigest(tx, conversationId);
        return Object.freeze({
          status: "created" as const,
          intentId,
          operation,
          baseEpoch: String(conversation.epoch),
          baseRosterVersion: String(conversation.roster_version),
          proposedRosterHash,
          takenKeyPackage,
          authorizedCommitterInstallationIds: await authorizedCommitters(
            tx,
            conversationId,
            purpose,
            operation === "remove" ? targetInstallationId : null,
          ),
          expiresAt,
        });
      });
    },

    async cancelIntent(
      intentId: string,
      requestedByInstallationId: string,
    ): Promise<MembershipIntentResolution> {
      if (!UUID_PATTERN.test(intentId)) return Object.freeze({ status: "unknown" });
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT conversation_id, operation, state FROM membership_intents
          WHERE intent_id = ${intentId} FOR UPDATE`;
        if (
          rows.length !== 1 ||
          !["requested", "authorized", "proposed"].includes(String(rows[0].state))
        ) {
          return Object.freeze({ status: "unknown" as const });
        }
        void requestedByInstallationId;
        await tx`
          UPDATE membership_intents SET state = 'cancelled'
          WHERE intent_id = ${intentId}`;
        // The taken KeyPackage is NEVER returned to inventory.
        if (String(rows[0].operation) !== "remove") {
          await returnConversationToActiveIfClear(
            tx,
            String(rows[0].conversation_id),
          );
        }
        await refreshCustodySnapshotDigest(
          tx,
          String(rows[0].conversation_id),
        );
        return Object.freeze({
          status: "resolved" as const,
          intentId,
          state: "cancelled",
        });
      });
    },

    async expireIntents(): Promise<number> {
      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const expired = await tx`
          UPDATE membership_intents SET state = 'expired'
          WHERE state IN ('requested', 'authorized', 'proposed')
            AND expires_at <= ${now}::timestamptz
          RETURNING intent_id, conversation_id, operation`;
        const touched = new Set<string>();
        for (const row of expired) {
          if (String(row.operation) !== "remove") {
            await returnConversationToActiveIfClear(
              tx,
              String(row.conversation_id),
            );
          }
          touched.add(String(row.conversation_id));
        }
        for (const conversationId of touched) {
          await refreshCustodySnapshotDigest(tx, conversationId);
        }
        return expired.length;
      });
    },

    async readIntent(intentId: string): Promise<MembershipIntentResolution> {
      if (!UUID_PATTERN.test(intentId)) return Object.freeze({ status: "unknown" });
      const rows = await sql`
        SELECT state FROM membership_intents WHERE intent_id = ${intentId}`;
      return rows.length === 1
        ? Object.freeze({
            status: "resolved",
            intentId,
            state: String(rows[0].state),
          })
        : Object.freeze({ status: "unknown" });
    },
  });

  async function returnConversationToActiveIfClear(
    tx: TransactionSql,
    conversationId: string,
  ): Promise<void> {
    await tx`
      UPDATE conversations SET state = 'active'
      WHERE conversation_id = ${conversationId}
        AND state = 'membership_pending'
        AND NOT EXISTS (
          SELECT 1 FROM membership_intents
          WHERE conversation_id = ${conversationId}
            AND state IN ('requested', 'authorized', 'proposed')
        )`;
  }
}

function expectRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Membership intent input must be a plain record.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new TypeError("Membership intent input has an unexpected shape.");
  }
  return value as Record<string, unknown>;
}

function expectUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError("Expected a lowercase UUID.");
  }
  return value;
}

function fromPgBase64(value: unknown): string {
  return Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
    "base64url",
  );
}

function uuidV7(nowIsoValue: string): string {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.parse(nowIsoValue));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((milliseconds >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
