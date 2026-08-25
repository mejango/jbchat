import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  type EnvelopeLeafInput,
  type DeliveryLogCheckpointInput,
} from "../delivery/hashes";
import {
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendRecipientSetHash,
} from "../delivery/state";
import type { Hash32 } from "../delivery/valueObjects";
import {
  insertPageEndProjectionFromRows,
  refreshCustodySnapshotDigest,
} from "./postgresDeliveryStore";
import type { ExternalProposalSigningPort } from "./externalProposalStore";
import {
  ensureMemberQuotaBindings,
  issueConversationPolicyHead,
  readProjectProvision,
  type GrantMaterial,
} from "./appendAuthority";

const ENVELOPE_RETENTION_MILLISECONDS = 365 * 24 * 60 * 60 * 1_000;
const COMMIT_CONTENT_TYPE =
  "application/vnd.juicebox.messaging.mls-public-message";
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const SEND_ROLES: Record<string, readonly string[]> = {
  purchase_support: ["customer", "project-staff"],
  community: ["member", "moderator"],
  announcement: ["publisher"],
};

class CommitCasError extends Error {
  readonly reasonCode: string;
  constructor(reasonCode: string) {
    super(`Membership commit CAS failed (${reasonCode}).`);
    this.reasonCode = reasonCode;
  }
}

export interface MembershipCommitStoreContext {
  readonly sql: Sql;
  readonly signer: ExternalProposalSigningPort;
  /** Derives the policy-head signer and grant evidence ids (appendAuthority). */
  readonly provisioningSeed: Buffer;
}

export type MembershipCommitResult =
  | {
      readonly status: "committed";
      readonly intentId: string;
      readonly envelopeId: string;
      readonly position: string;
      readonly headHash: string;
      readonly resultingEpoch: string;
      readonly resultingRosterVersion: string;
      readonly consumedProposals: readonly {
        readonly proposalId: string;
        readonly proposalHash: string;
      }[];
    }
  | { readonly status: "cas-failed"; readonly reasonCode: string }
  | { readonly status: "refused"; readonly reasonCode: "malformed-request" };

export interface MembershipCommitStore {
  readonly consumeCommit: (input: unknown) => Promise<MembershipCommitResult>;
}

/**
 * Consumes an MLS membership Commit against a proposed intent under the
 * spec's CAS: lock order is conversation, intent/proposals, key package/
 * memberships, usage, mailbox counters. The Commit bytes themselves are
 * opaque here - MLS validity is the client's and the projection verifier's
 * job - but every relational fact is enforced: exact base epoch, roster
 * version, base transcript checkpoint, resultingEpoch = expected + 1, the
 * exact ordered mandatory (proposalId, proposalHash) set from the current
 * signed policy head, the intent's grant still active (ADR 0003: the lease
 * is the authority), an authorized committer under the closed role matrix,
 * and exactly one Welcome per welcome-mode Add. The transaction appends
 * the Commit under the caller's UUIDv4 envelope ID, binds the intent's
 * composite FK to that exact row, marks the taken KeyPackage used, applies
 * the membership boundary inclusively at the Commit position, rewrites the
 * roster and recipient projections (the recomputed roster hash must equal
 * the intent's proposed hash or the CAS fails), fans out one mailbox item
 * per live member with the target's Welcome augmenting its own item, emits
 * an outbox event, and rewrites the custody digest fence.
 */
export function createMembershipCommitStore(
  context: MembershipCommitStoreContext,
): MembershipCommitStore {
  const { sql, signer, provisioningSeed } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  return Object.freeze({
    async consumeCommit(inputValue: unknown): Promise<MembershipCommitResult> {
      let input: {
        intentId: string;
        committerInstallationId: string;
        expectedEpoch: string;
        expectedRosterVersion: string;
        proposedRosterHash: string;
        mandatoryProposals: { proposalId: string; proposalHash: string }[];
        envelopeId: string;
        commit: Buffer;
        envelopeSha256: string;
        baseConfirmedTranscriptHash: string;
        resultingConfirmedTranscriptHash: string;
        resultingEpoch: string;
        welcomeByInstallation: { installationId: string; welcome: Buffer }[];
        targetCredentialId: string | null;
      };
      try {
        const record = inputValue as Record<string, unknown>;
        if (!inputValue || typeof inputValue !== "object") {
          throw new TypeError("Unexpected shape.");
        }
        const commit = Buffer.from(
          expectBase64Url(record.commit),
          "base64url",
        );
        if (commit.length === 0 || commit.length > 524288) {
          throw new TypeError("Commit size is out of range.");
        }
        if (!UUID_V4_PATTERN.test(String(record.envelopeId))) {
          throw new TypeError("envelopeId must be a UUIDv4.");
        }
        input = {
          intentId: expectUuid(record.intentId),
          committerInstallationId: expectUuid(record.committerInstallationId),
          expectedEpoch: expectUint(record.expectedEpoch),
          expectedRosterVersion: expectUint(record.expectedRosterVersion),
          proposedRosterHash: expectHash(record.proposedRosterHash),
          mandatoryProposals: (record.mandatoryProposals as unknown[]).map(
            (pair) => {
              const p = pair as Record<string, unknown>;
              return {
                proposalId: expectUuid(p.proposalId),
                proposalHash: expectHash(p.proposalHash),
              };
            },
          ),
          envelopeId: String(record.envelopeId),
          commit,
          envelopeSha256: expectHash(record.envelopeSha256),
          baseConfirmedTranscriptHash: expectHash(
            record.baseConfirmedTranscriptHash,
          ),
          resultingConfirmedTranscriptHash: expectHash(
            record.resultingConfirmedTranscriptHash,
          ),
          resultingEpoch: expectUint(record.resultingEpoch),
          welcomeByInstallation: (
            record.welcomeByInstallation as unknown[]
          ).map((entry) => {
            const e = entry as Record<string, unknown>;
            const welcome = Buffer.from(
              expectBase64Url(e.welcome),
              "base64url",
            );
            if (welcome.length === 0 || welcome.length > 262144) {
              throw new TypeError("Welcome size is out of range.");
            }
            return { installationId: expectUuid(e.installationId), welcome };
          }),
          targetCredentialId:
            record.targetCredentialId === null ||
            record.targetCredentialId === undefined
              ? null
              : expectUuid(record.targetCredentialId),
        };
        if (computeEnvelopeSha256(commit) !== input.envelopeSha256) {
          throw new TypeError("envelopeSha256 does not match the bytes.");
        }
        if (
          BigInt(input.resultingEpoch) !==
          BigInt(input.expectedEpoch) + 1n
        ) {
          throw new TypeError("resultingEpoch must advance by exactly one.");
        }
      } catch {
        return Object.freeze({
          status: "refused",
          reasonCode: "malformed-request",
        });
      }

      try {
        return await sql.begin(async (tx) => {
          const now = await dbNow(tx);

          // 1. Conversation.
          const intentPeek = await tx`
            SELECT conversation_id FROM membership_intents
            WHERE intent_id = ${input.intentId}`;
          if (intentPeek.length !== 1) throw new CommitCasError("intent-unknown");
          const conversationId = String(intentPeek[0].conversation_id);
          const conversations = await tx`
            SELECT * FROM conversations
            WHERE conversation_id = ${conversationId} FOR UPDATE`;
          const conversation = conversations[0];
          if (
            String(conversation.state) !== "membership_pending" ||
            String(conversation.epoch) !== input.expectedEpoch ||
            String(conversation.roster_version) !== input.expectedRosterVersion ||
            b64(conversation.confirmed_transcript_hash as Uint8Array) !==
              input.baseConfirmedTranscriptHash
          ) {
            throw new CommitCasError("stale-counters");
          }
          const purpose = String(conversation.delivery_purpose);

          // 2. Intent and proposals.
          const intents = await tx`
            SELECT * FROM membership_intents
            WHERE intent_id = ${input.intentId} FOR UPDATE`;
          const intent = intents[0];
          if (
            String(intent.state) !== "proposed" ||
            new Date(intent.expires_at as Date).toISOString() <= now ||
            b64(intent.proposed_roster_hash as Uint8Array) !==
              input.proposedRosterHash
          ) {
            throw new CommitCasError("intent-not-proposed");
          }
          const operation = String(intent.operation);
          const targetInstallationId = String(intent.target_installation_id);

          if (operation === "add") {
            // ADR 0003: the grant lease, not the claim handle, is the
            // authority - it must still be live at Commit time.
            const grants = await tx`
              SELECT state, valid_until FROM eligibility_grants
              WHERE grant_id = ${String(intent.grant_id)}`;
            if (
              grants.length !== 1 ||
              String(grants[0].state) !== "active" ||
              new Date(grants[0].valid_until as Date).toISOString() <= now
            ) {
              throw new CommitCasError("grant-not-live");
            }
          }

          const intentProposals = await tx`
            SELECT proposal_id, proposal_hash FROM external_proposals
            WHERE intent_id = ${input.intentId}
              AND committed_at IS NULL
              AND expires_at > ${now}::timestamptz
            FOR UPDATE`;
          if (intentProposals.length !== 1) {
            throw new CommitCasError("proposal-not-live");
          }

          const anchors = await tx`
            SELECT policy_head_id FROM delivery_policy_head_anchors
            WHERE conversation_id = ${conversationId}`;
          const requiredPairs =
            anchors.length === 1
              ? await tx`
                  SELECT proposal_id, proposal_hash
                  FROM policy_head_mandatory_proposals
                  WHERE policy_head_id = ${String(anchors[0].policy_head_id)}
                  ORDER BY ordinal`
              : [];
          if (requiredPairs.length !== input.mandatoryProposals.length) {
            throw new CommitCasError("mandatory-proposal-set-mismatch");
          }
          for (let index = 0; index < requiredPairs.length; index += 1) {
            const required = requiredPairs[index];
            const offered = input.mandatoryProposals[index];
            if (
              String(required.proposal_id) !== offered.proposalId ||
              b64(required.proposal_hash as Uint8Array) !== offered.proposalHash
            ) {
              throw new CommitCasError("mandatory-proposal-set-mismatch");
            }
            const resolved = await tx`
              SELECT 1 FROM external_proposals
              WHERE proposal_id = ${offered.proposalId}
                AND proposal_hash = ${Buffer.from(
                  offered.proposalHash,
                  "base64url",
                )}
                AND conversation_id = ${conversationId}
                AND expires_at > ${now}::timestamptz
              FOR UPDATE`;
            if (resolved.length !== 1) {
              throw new CommitCasError("mandatory-proposal-unresolved");
            }
          }

          // Authorized committer: live membership under the closed role
          // matrix, never the removal target, no pending removal.
          const committers = await tx`
            SELECT account_id FROM memberships
            WHERE conversation_id = ${conversationId}
              AND installation_id = ${input.committerInstallationId}
              AND removed_at IS NULL
              AND role = ANY(${(SEND_ROLES[purpose] ?? []) as string[]})`;
          if (
            committers.length !== 1 ||
            (operation === "remove" &&
              input.committerInstallationId === targetInstallationId)
          ) {
            throw new CommitCasError("committer-not-authorized");
          }
          const committerAccountId = String(committers[0].account_id);

          // Welcome set: exactly one for the added target, none otherwise.
          if (operation === "add") {
            if (
              input.welcomeByInstallation.length !== 1 ||
              input.welcomeByInstallation[0].installationId !==
                targetInstallationId
            ) {
              throw new CommitCasError("welcome-set-mismatch");
            }
          } else if (input.welcomeByInstallation.length !== 0) {
            throw new CommitCasError("welcome-set-mismatch");
          }

          // 3. Key package and memberships.
          let targetRole: string | null = null;
          let targetAccountId: string | null = null;
          let targetFingerprint: Buffer | null = null;
          let targetCredentialState: string | null = null;
          let targetCredentialRevocationVersion: string | null = null;
          let targetCredentialExpiresAt: Date | null = null;
          if (operation === "add") {
            const packages = await tx`
              SELECT key_package_ref FROM key_packages
              WHERE taken_by_intent_id = ${input.intentId}
                AND state = 'taken'
              FOR UPDATE`;
            if (packages.length !== 1) {
              throw new CommitCasError("key-package-not-taken");
            }
            if (input.targetCredentialId === null) {
              throw new CommitCasError("target-credential-required");
            }
            const credentials = await tx`
              SELECT * FROM role_credentials
              WHERE credential_id = ${input.targetCredentialId}
                AND conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}
                AND state = 'active'
                AND expires_at > ${now}::timestamptz`;
            if (credentials.length !== 1) {
              throw new CommitCasError("target-credential-invalid");
            }
            targetRole = String(credentials[0].role);
            targetAccountId = String(credentials[0].account_id);
            targetFingerprint = Buffer.from(
              credentials[0].credential_fingerprint as Uint8Array,
            );
            targetCredentialState = String(credentials[0].state);
            targetCredentialRevocationVersion = String(
              credentials[0].revocation_version,
            );
            targetCredentialExpiresAt = credentials[0].expires_at as Date;
            await tx`
              SELECT 1 FROM memberships
              WHERE conversation_id = ${conversationId} FOR UPDATE`;
          } else {
            const targets = await tx`
              SELECT 1 FROM memberships
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}
                AND removed_at IS NULL
              FOR UPDATE`;
            if (targets.length !== 1) {
              throw new CommitCasError("removal-target-not-a-member");
            }
          }

          // 4. Usage.
          await tx`
            SELECT 1 FROM conversation_usage
            WHERE conversation_id = ${conversationId} FOR UPDATE`;

          // Append the Commit envelope under the caller's exact envelopeId.
          const custody = await tx`
            SELECT a.active_signing_key_id
            FROM delivery_conversation_authority a
            JOIN delivery_log_signing_keys k
              ON k.key_id = a.active_signing_key_id
            WHERE a.conversation_id = ${conversationId}
              AND k.state = 'active'
              AND k.valid_from <= ${now}::timestamptz
              AND k.valid_until > ${now}::timestamptz
            FOR UPDATE OF a`;
          if (custody.length !== 1) {
            throw new CommitCasError("log-authority-unavailable");
          }
          const signingKeyId = String(custody[0].active_signing_key_id);
          const position = String(
            BigInt(String(conversation.last_position)) + 1n,
          );
          const leafHash = computeEnvelopeLeafHash({
            conversationId,
            position,
            envelopeId: input.envelopeId,
            envelopeClass: "mls_commit",
            sender: {
              type: "installation",
              accountId: committerAccountId,
              installationId: input.committerInstallationId,
            },
            epoch: input.expectedEpoch,
            rosterVersion: input.expectedRosterVersion,
            contentType: COMMIT_CONTENT_TYPE,
            envelopeSha256: input.envelopeSha256,
            receivedAt: now,
          } as unknown as EnvelopeLeafInput);
          const previousHeadHash = b64(
            conversation.current_log_head_hash as Uint8Array,
          );
          const headHash = computeLogHeadHash(
            previousHeadHash as Hash32,
            leafHash,
          );
          const checkpointDigest = computeDeliveryLogCheckpointDigest({
            conversationId,
            position,
            previousHeadHash,
            headHash,
            signingKeyId,
          } as unknown as DeliveryLogCheckpointInput);
          const signature = await signer.signCheckpointDigest(
            signingKeyId,
            checkpointDigest,
          );
          const envelopeExpiresAt = new Date(
            Date.parse(now) + ENVELOPE_RETENTION_MILLISECONDS,
          ).toISOString();
          await tx`
            INSERT INTO envelopes (
              conversation_id, position, envelope_id, envelope_class,
              sender_type, sender_account_id, sender_installation_id,
              epoch, roster_version, base_confirmed_transcript_hash,
              resulting_confirmed_transcript_hash, content_type,
              envelope_bytes, envelope_sha256, previous_head_hash, leaf_hash,
              head_hash, log_signing_key_id, log_checkpoint_digest,
              log_head_signature, received_at, expires_at
            ) VALUES (
              ${conversationId}, ${position}, ${input.envelopeId},
              'mls_commit', 'installation', ${committerAccountId},
              ${input.committerInstallationId}, ${input.expectedEpoch},
              ${input.expectedRosterVersion},
              ${Buffer.from(input.baseConfirmedTranscriptHash, "base64url")},
              ${Buffer.from(
                input.resultingConfirmedTranscriptHash,
                "base64url",
              )},
              ${COMMIT_CONTENT_TYPE}, ${input.commit},
              ${Buffer.from(input.envelopeSha256, "base64url")},
              ${Buffer.from(previousHeadHash, "base64url")},
              ${Buffer.from(leafHash, "base64url")},
              ${Buffer.from(headHash, "base64url")},
              ${signingKeyId},
              ${Buffer.from(checkpointDigest, "base64url")},
              ${Buffer.from(signature, "base64url")},
              ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
            )`;

          // Consume proposals and bind the intent one-to-one to this row.
          const consumedProposals: { proposalId: string; proposalHash: string }[] =
            [];
          for (const row of intentProposals) {
            consumedProposals.push({
              proposalId: String(row.proposal_id),
              proposalHash: b64(row.proposal_hash as Uint8Array),
            });
          }
          for (const pair of input.mandatoryProposals) {
            if (!consumedProposals.some((p) => p.proposalId === pair.proposalId)) {
              consumedProposals.push(pair);
            }
          }
          for (const pair of consumedProposals) {
            await tx`
              UPDATE external_proposals SET committed_at = ${now}::timestamptz
              WHERE proposal_id = ${pair.proposalId}`;
          }
          await tx`
            UPDATE membership_intents SET
              state = 'committed',
              committed_envelope_id = ${input.envelopeId},
              committed_envelope_position = ${position}
            WHERE intent_id = ${input.intentId}`;

          // Membership boundary, inclusive at the Commit position.
          const resultingRosterVersion = String(
            BigInt(input.expectedRosterVersion) + 1n,
          );
          if (operation === "add") {
            await tx`
              UPDATE key_packages SET state = 'used',
                used_at = ${now}::timestamptz
              WHERE taken_by_intent_id = ${input.intentId}`;
            // A member removed earlier may be added again (a relay seat
            // re-enabled): its membership row keeps the PK, so the window
            // resets in place and the stale Welcome (which references the
            // old window) is retired first.
            const rejoin = await tx`
              SELECT 1 FROM memberships
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}
                AND removed_at IS NOT NULL`;
            if (rejoin.length === 1) {
              await tx`
                DELETE FROM mls_welcomes
                WHERE conversation_id = ${conversationId}
                  AND target_installation_id = ${targetInstallationId}`;
              await tx`
                UPDATE memberships SET
                  account_id = ${targetAccountId},
                  credential_id = ${input.targetCredentialId},
                  role = ${targetRole},
                  bootstrap_mode = 'welcome',
                  joined_position = ${position},
                  joined_at = ${now}::timestamptz,
                  removed_position = NULL,
                  removed_at = NULL
                WHERE conversation_id = ${conversationId}
                  AND installation_id = ${targetInstallationId}`;
            } else {
              await tx`
                INSERT INTO memberships (
                  conversation_id, installation_id, account_id, credential_id,
                  role, delivery_purpose, bootstrap_mode, joined_position,
                  joined_at
                ) VALUES (
                  ${conversationId}, ${targetInstallationId},
                  ${targetAccountId}, ${input.targetCredentialId},
                  ${targetRole}, ${purpose}, 'welcome', ${position},
                  ${now}::timestamptz
                )`;
            }
            const welcome = input.welcomeByInstallation[0].welcome;
            await tx`
              INSERT INTO mls_welcomes (
                conversation_id, commit_position, commit_envelope_id,
                target_installation_id, welcome_bytes, welcome_sha256,
                created_at, expires_at
              ) VALUES (
                ${conversationId}, ${position}, ${input.envelopeId},
                ${targetInstallationId}, ${welcome},
                ${createHash("sha256").update(welcome).digest()},
                ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
              )`;
          } else {
            await tx`
              UPDATE memberships SET
                removed_position = ${position},
                removed_at = ${now}::timestamptz
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}`;
          }

          // Rewrite the roster projections and prove the proposed hash.
          if (operation === "remove") {
            await tx`
              DELETE FROM conversation_roster_projections
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}`;
          }
          await tx`
            UPDATE conversation_roster_projections
            SET roster_version = ${resultingRosterVersion}
            WHERE conversation_id = ${conversationId}`;
          if (operation === "add") {
            const nextOrdinal = await tx`
              SELECT coalesce(max(ordinal), -1) + 1 AS next
              FROM conversation_roster_projections
              WHERE conversation_id = ${conversationId}`;
            await tx`
              INSERT INTO conversation_roster_projections (
                conversation_id, conversation_generation, roster_version,
                account_id, installation_id, credential_id,
                credential_fingerprint, ordinal
              ) VALUES (
                ${conversationId}, ${String(conversation.generation)},
                ${resultingRosterVersion}, ${targetAccountId},
                ${targetInstallationId}, ${input.targetCredentialId},
                ${targetFingerprint}, ${String(nextOrdinal[0].next)}
              )`;
          }
          const rosterRows = await tx`
            SELECT account_id, installation_id, credential_id,
                   encode(credential_fingerprint, 'base64') AS fingerprint
            FROM conversation_roster_projections
            WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
          const recomputedRosterHash = computeApplicationAppendMlsRosterHash(
            rosterRows.map((row) => ({
              conversationId,
              conversationGeneration: String(conversation.generation),
              rosterVersion: resultingRosterVersion,
              accountId: String(row.account_id),
              installationId: String(row.installation_id),
              credentialId: String(row.credential_id),
              credentialFingerprint: fromPgBase64(row.fingerprint),
            })) as unknown as Parameters<
              typeof computeApplicationAppendMlsRosterHash
            >[0],
          );
          if (recomputedRosterHash !== input.proposedRosterHash) {
            throw new CommitCasError("roster-hash-mismatch");
          }

          // Rewrite the recipient projections and their conversation hash.
          const resultingRecipientSetVersion = String(
            BigInt(String(conversation.recipient_set_version)) + 1n,
          );
          if (operation === "remove") {
            await tx`
              DELETE FROM conversation_recipient_projections
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}`;
          }
          await tx`
            UPDATE conversation_recipient_projections
            SET recipient_set_version = ${resultingRecipientSetVersion}
            WHERE conversation_id = ${conversationId}`;
          if (operation === "add") {
            const nextOrdinal = await tx`
              SELECT coalesce(max(ordinal), -1) + 1 AS next
              FROM conversation_recipient_projections
              WHERE conversation_id = ${conversationId}`;
            await tx`
              INSERT INTO conversation_recipient_projections (
                conversation_id, conversation_generation,
                recipient_set_version, account_id, installation_id,
                credential_id, credential_fingerprint,
                credential_revocation_version, credential_state,
                credential_expires_at, joined_position, removed_position,
                installation_state, ordinal
              ) VALUES (
                ${conversationId}, ${String(conversation.generation)},
                ${resultingRecipientSetVersion}, ${targetAccountId},
                ${targetInstallationId}, ${input.targetCredentialId},
                ${targetFingerprint}, ${targetCredentialRevocationVersion},
                ${targetCredentialState},
                ${targetCredentialExpiresAt}::timestamptz,
                ${position}, ${null}, 'active', ${String(nextOrdinal[0].next)}
              )`;
          }
          const recipientRows = await tx`
            SELECT account_id, installation_id, credential_id,
                   encode(credential_fingerprint, 'base64') AS fingerprint,
                   credential_revocation_version, credential_state,
                   credential_expires_at, joined_position, removed_position,
                   installation_state
            FROM conversation_recipient_projections
            WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
          const recipientSetHash = computeApplicationAppendRecipientSetHash(
            recipientRows.map((row) => ({
              conversationId,
              conversationGeneration: String(conversation.generation),
              recipientSetVersion: resultingRecipientSetVersion,
              accountId: String(row.account_id),
              installationId: String(row.installation_id),
              credentialId: String(row.credential_id),
              credentialFingerprint: fromPgBase64(row.fingerprint),
              credentialRevocationVersion: String(
                row.credential_revocation_version,
              ),
              credentialState: String(row.credential_state),
              credentialExpiresAt: new Date(
                row.credential_expires_at as Date,
              ).toISOString(),
              joinedPosition: String(row.joined_position),
              removedPosition:
                row.removed_position === null
                  ? null
                  : String(row.removed_position),
              installationState: String(row.installation_state),
            })) as unknown as Parameters<
              typeof computeApplicationAppendRecipientSetHash
            >[0],
          );

          await tx`
            UPDATE conversations SET
              state = 'active',
              epoch = ${input.resultingEpoch},
              roster_version = ${resultingRosterVersion},
              etag = ${`"e${input.resultingEpoch}-r${resultingRosterVersion}"`},
              roster_hash = ${Buffer.from(
                input.proposedRosterHash,
                "base64url",
              )},
              confirmed_transcript_hash = ${Buffer.from(
                input.resultingConfirmedTranscriptHash,
                "base64url",
              )},
              recipient_set_version = ${resultingRecipientSetVersion},
              recipient_set_hash = ${Buffer.from(
                recipientSetHash,
                "base64url",
              )},
              last_position = ${position},
              current_log_head_hash = ${Buffer.from(headHash, "base64url")},
              last_activity_at = ${now}::timestamptz
            WHERE conversation_id = ${conversationId}`;
          await tx`
            UPDATE conversation_usage SET
              envelope_count = envelope_count + 1,
              envelope_bytes = envelope_bytes + ${input.commit.length},
              updated_at = ${now}::timestamptz
            WHERE conversation_id = ${conversationId}`;

          // 4b. Append authority for the added member: its own quota
          // bindings, then a re-issued policy head whose send-grant set
          // includes the target - every existing grant is re-anchored at the
          // new head, the anchor drops back to witness_state='missing', and
          // appends stay closed for everyone until the witness cosigns the
          // new checkpoint. Issued AFTER the conversation row advanced so
          // the head carries the post-Commit epoch/roster/transcript.
          if (operation === "add") {
            const projectRefId = String(conversation.project_ref_id);
            const provision = await readProjectProvision(tx, projectRefId);
            if (!provision) {
              throw new CommitCasError("authority-provision-missing");
            }
            const quotaPolicyDigest = Buffer.from(
              conversation.quota_policy_digest as Uint8Array,
            );
            await ensureMemberQuotaBindings(tx, {
              conversationId,
              accountId: targetAccountId!,
              installationId: targetInstallationId,
              projectRefId,
              realmId: String(conversation.realm_id),
              quotaPolicyDigest,
              windowStartedAt: now,
              now,
            });
            const existingGrants = await tx`
              SELECT installation_id, credential_id, role,
                     role_credential_fingerprint,
                     role_credential_subject_account_id,
                     role_credential_valid_from, role_credential_valid_until,
                     expires_at
              FROM conversation_send_grants
              WHERE conversation_id = ${conversationId}
                AND installation_id <> ${targetInstallationId}
              ORDER BY installation_id`;
            const targetCredentialExpiry = new Date(
              targetCredentialExpiresAt!,
            ).toISOString();
            const grants: GrantMaterial[] = [
              ...existingGrants.map((row) => ({
                installationId: String(row.installation_id),
                accountId: String(row.role_credential_subject_account_id),
                credentialId: String(row.credential_id),
                role: String(row.role),
                credentialFingerprint: b64(
                  row.role_credential_fingerprint as Uint8Array,
                ),
                validFrom: new Date(
                  row.role_credential_valid_from as Date,
                ).toISOString(),
                validUntil: new Date(
                  row.role_credential_valid_until as Date,
                ).toISOString(),
                expiresAt: new Date(row.expires_at as Date).toISOString(),
              })),
              {
                installationId: targetInstallationId,
                accountId: targetAccountId!,
                credentialId: input.targetCredentialId!,
                role: targetRole!,
                credentialFingerprint: b64(targetFingerprint!),
                validFrom: now,
                validUntil: targetCredentialExpiry,
                expiresAt: targetCredentialExpiry,
              },
            ];
            const issued = await issueConversationPolicyHead(tx, {
              provisioningSeed,
              conversationId,
              projectRefId,
              provision,
              conversationKind: purpose,
              conversationGeneration: String(conversation.generation),
              quotaPolicyDigest,
              grants,
              // The anchor's selected pair is a projection default the
              // reconstruction replaces per sender; the target is the one
              // member guaranteed to be in the issued set.
              selectedInstallationId: targetInstallationId,
              anchor: { mode: "update" },
              now,
            });
            if (issued.status !== "issued") {
              throw new CommitCasError("policy-head-unavailable");
            }
            await recordPolicyTransition(tx, conversationId, issued, position, now);
          } else {
            // 4c. A Remove revokes the removed member's send grant and
            // re-issues the head over the remaining grants, so the anchor
            // matches the post-Commit epoch/roster and the removed member
            // holds no authority the append lane would ever consult.
            const projectRefId = String(conversation.project_ref_id);
            const provision = await readProjectProvision(tx, projectRefId);
            if (!provision) {
              throw new CommitCasError("authority-provision-missing");
            }
            await tx`
              UPDATE conversation_send_grants SET state = 'revoked'
              WHERE conversation_id = ${conversationId}
                AND installation_id = ${targetInstallationId}`;
            const remaining = await tx`
              SELECT installation_id, credential_id, role,
                     role_credential_fingerprint,
                     role_credential_subject_account_id,
                     role_credential_valid_from, role_credential_valid_until,
                     expires_at
              FROM conversation_send_grants
              WHERE conversation_id = ${conversationId}
                AND state = 'active'
              ORDER BY installation_id`;
            if (remaining.length === 0) {
              throw new CommitCasError("no-remaining-send-grants");
            }
            const grants: GrantMaterial[] = remaining.map((row) => ({
              installationId: String(row.installation_id),
              accountId: String(row.role_credential_subject_account_id),
              credentialId: String(row.credential_id),
              role: String(row.role),
              credentialFingerprint: b64(
                row.role_credential_fingerprint as Uint8Array,
              ),
              validFrom: new Date(
                row.role_credential_valid_from as Date,
              ).toISOString(),
              validUntil: new Date(
                row.role_credential_valid_until as Date,
              ).toISOString(),
              expiresAt: new Date(row.expires_at as Date).toISOString(),
            }));
            const issued = await issueConversationPolicyHead(tx, {
              provisioningSeed,
              conversationId,
              projectRefId,
              provision,
              conversationKind: purpose,
              conversationGeneration: String(conversation.generation),
              quotaPolicyDigest: Buffer.from(
                conversation.quota_policy_digest as Uint8Array,
              ),
              grants,
              selectedInstallationId: grants[0].installationId,
              anchor: { mode: "update" },
              now,
            });
            if (issued.status !== "issued") {
              throw new CommitCasError("policy-head-unavailable");
            }
            await recordPolicyTransition(tx, conversationId, issued, position, now);
          }

          // 5. Mailbox fan-out: one item per live member; the added target's
          // Welcome augments its own item and never creates a second one.
          const fanout = await tx`
            SELECT installation_id FROM memberships
            WHERE conversation_id = ${conversationId}
              AND removed_at IS NULL
            ORDER BY installation_id`;
          for (const member of fanout) {
            const memberInstallationId = String(member.installation_id);
            const counter = await tx`
              INSERT INTO mailbox_counters (installation_id, last_position)
              VALUES (${memberInstallationId}, 1)
              ON CONFLICT (installation_id)
              DO UPDATE SET last_position = mailbox_counters.last_position + 1
              RETURNING last_position`;
            await tx`
              INSERT INTO mailbox_entries (
                installation_id, mailbox_position, conversation_id,
                envelope_position, envelope_id, delivery_class, created_at,
                expires_at
              ) VALUES (
                ${memberInstallationId},
                ${String(counter[0].last_position)}, ${conversationId},
                ${position}, ${input.envelopeId}, 'commit',
                ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
              )`;
          }
          await tx`
            INSERT INTO outbox_events (
              aggregate_type, aggregate_id_hash, event_type, payload,
              created_at, available_at
            ) VALUES (
              'conversation',
              ${createHash("sha256").update(conversationId).digest()},
              'membership-commit-accepted',
              ${JSON.stringify({
                conversationId,
                intentId: input.intentId,
                position,
              })}::jsonb,
              ${now}::timestamptz, ${now}::timestamptz
            )`;

          await insertPageEndProjectionFromRows(
            tx,
            conversationId,
            position,
            now,
          );
          await refreshCustodySnapshotDigest(tx, conversationId);
          return Object.freeze({
            status: "committed" as const,
            intentId: input.intentId,
            envelopeId: input.envelopeId,
            position,
            headHash,
            resultingEpoch: input.resultingEpoch,
            resultingRosterVersion,
            consumedProposals,
          });
        });
      } catch (error) {
        if (error instanceof CommitCasError) {
          return Object.freeze({
            status: "cas-failed",
            reasonCode: error.reasonCode,
          });
        }
        throw error;
      }
    },
  });
}

function expectUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError("Expected a lowercase UUID.");
  }
  return value;
}

function expectUint(value: unknown): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError("Expected a decimal unsigned integer string.");
  }
  return value;
}

function expectBase64Url(value: unknown): string {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) {
    throw new TypeError("Expected canonical base64url.");
  }
  return value;
}

function expectHash(value: unknown): string {
  const text = expectBase64Url(value);
  if (Buffer.from(text, "base64url").length !== 32) {
    throw new TypeError("Expected a 32-byte base64url hash.");
  }
  return text;
}

async function recordPolicyTransition(
  tx: TransactionSql,
  conversationId: string,
  issued: { policyHeadSequence: string; policyHeadId: string; policyHeadHash: string },
  position: string,
  now: string,
): Promise<void> {
  await tx`
    INSERT INTO conversation_policy_transitions (
      conversation_id, policy_head_sequence, policy_head_id,
      policy_head_hash, effective_from_position, created_at
    ) VALUES (
      ${conversationId}, ${issued.policyHeadSequence}, ${issued.policyHeadId},
      ${Buffer.from(issued.policyHeadHash, "base64url")},
      ${position}, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;
}

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function fromPgBase64(value: unknown): string {
  return Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
    "base64url",
  );
}
