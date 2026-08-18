import { Buffer } from "node:buffer";
import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifyNodeSignature,
} from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  canonicalJcs,
  computeMandatoryProposalSetHash,
  computePolicyHeadHash,
  computeSendGrantSetHash,
  type MandatoryProposalEntry,
  type PolicyHeadSignerPort,
  type SendGrantSetMemberEntry,
} from "../delivery/policyHeadIssuance";

const SEQUENCE_CEILING = 9223372036854775807n;
const HEAD_VALIDITY_MILLISECONDS = 5 * 60 * 1_000;
const MAX_CANONICAL_BODY_BYTES = 65_536;
const ZERO_HASH_32 = Buffer.alloc(32);

export interface PolicyHeadIssuanceInput {
  readonly conversationId: string;
  readonly policyId: string;
  readonly policyRevision: string;
  readonly policyHash: string;
  readonly authorizedQuotaPolicyDigest: string;
  readonly evaluatedChainId: string;
  readonly evaluatedBlock: string;
  readonly evaluatedBlockHash: string;
  readonly activeExternalSenderCredentialId: string;
  readonly activeExternalSenderFingerprint: string;
  readonly activeSignerGeneration: string;
  readonly directoryCheckpointId: string;
  readonly policyLogCheckpointId: string;
  readonly mandatoryProposals: readonly MandatoryProposalEntry[];
  readonly sendGrantSetMembers: readonly SendGrantSetMemberEntry[];
}

export interface IssuedPolicyHead {
  readonly policyHeadId: string;
  readonly policyHeadSequence: string;
  readonly policyHeadHash: string;
  readonly previousPolicyHeadHash: string;
  readonly canonicalSignedBody: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface ServedPolicyHead extends IssuedPolicyHead {
  readonly signerKeyId: string;
  readonly signature: string;
}

export interface PolicyHeadIssuanceStore {
  readonly issuePolicyHead: (
    input: PolicyHeadIssuanceInput,
  ) => Promise<IssuedPolicyHead>;
  readonly readNewestPolicyHead: (
    conversationId: string,
    afterSequence?: string,
  ) => Promise<ServedPolicyHead | null>;
}

/**
 * The policy-head issuance transaction (storage-and-retention.md section 3.3):
 * locks the conversation, allocates the gap-free monotonic sequence, copies
 * the exact locked delivery-log prefix into the signed anchors, binds the
 * ordered mandatory-proposal set and the send-grant set root recomputed over
 * its persisted leaves, builds the RFC 8785 canonical unsigned body, persists
 * the immutable canonical bytes and their SHA-256 before signing, signs the
 * domain-separated head hash, inserts the head with its proposal and
 * set-member rows, and advances the conversation sequence/hash in one
 * transaction. Serving re-derives the body digest and verifies the signature
 * from the immutable bytes - never from mutable conversation columns.
 *
 * What this store does NOT claim: the independent policy log/witness has no
 * producer, so issued heads are unwitnessed and the append lane must not
 * consume them as verified; chain evaluation fields are caller-supplied
 * fictional facts in the lab; and the send-grant set root is full-set
 * recomputation evidence, not a succinct per-grant inclusion proof.
 */
export function createPolicyHeadIssuanceStore(context: {
  readonly sql: Sql;
  readonly signer: PolicyHeadSignerPort;
}): PolicyHeadIssuanceStore {
  const { sql, signer } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  return Object.freeze({
    async issuePolicyHead(
      input: PolicyHeadIssuanceInput,
    ): Promise<IssuedPolicyHead> {
      // Composable inside a caller's transaction: a TransactionSql runs a
      // savepoint instead of a nested BEGIN.
      const begin =
        typeof (sql as { begin?: unknown }).begin === "function"
          ? (sql as Sql).begin.bind(sql)
          : (sql as unknown as { savepoint: Sql["begin"] }).savepoint.bind(
              sql as unknown as { savepoint: Sql["begin"] },
            );
      return begin(async (tx) => {
        const issuedAt = await dbNow(tx);
        const expiresAt = new Date(
          Date.parse(issuedAt) + HEAD_VALIDITY_MILLISECONDS,
        ).toISOString();
        const conversations = await tx`
          SELECT last_policy_head_sequence, current_policy_head_hash,
                 last_position, current_log_head_hash, epoch, roster_version,
                 roster_hash, confirmed_transcript_hash
          FROM conversations
          WHERE conversation_id = ${input.conversationId}
          FOR UPDATE`;
        if (conversations.length !== 1) {
          throw new Error("Policy-head issuance requires a registered conversation.");
        }
        const conversation = conversations[0];
        const sequence =
          BigInt(String(conversation.last_policy_head_sequence)) + 1n;
        if (sequence > SEQUENCE_CEILING) {
          throw new Error("Policy-head sequence ceiling reached.");
        }
        const previousHash =
          sequence === 1n
            ? ZERO_HASH_32
            : Buffer.from(conversation.current_policy_head_hash as Uint8Array);
        const policyHeadId = uuidV4();
        const mandatorySetHash = computeMandatoryProposalSetHash(
          input.mandatoryProposals,
        );
        const sendGrantSetHash = computeSendGrantSetHash(
          input.sendGrantSetMembers,
        );
        const unsignedBody = {
          policyHeadId,
          policyHeadSequence: String(sequence),
          previousPolicyHeadHash: b64(previousHash),
          conversationId: input.conversationId,
          epoch: String(conversation.epoch),
          rosterVersion: String(conversation.roster_version),
          rosterHash: b64(conversation.roster_hash as Uint8Array),
          confirmedTranscriptHash: b64(
            conversation.confirmed_transcript_hash as Uint8Array,
          ),
          policyId: input.policyId,
          policyRevision: input.policyRevision,
          policyHash: input.policyHash,
          authorizedSendGrantSetHash: b64(sendGrantSetHash),
          authorizedQuotaPolicyDigest: input.authorizedQuotaPolicyDigest,
          evaluatedChainId: input.evaluatedChainId,
          evaluatedBlock: input.evaluatedBlock,
          evaluatedBlockHash: input.evaluatedBlockHash,
          mandatoryProposalCount: String(input.mandatoryProposals.length),
          mandatoryProposalSetHash: b64(mandatorySetHash),
          mandatoryProposals: input.mandatoryProposals.map((proposal) => ({
            proposalId: proposal.proposalId,
            proposalHash: proposal.proposalHash,
          })),
          activeExternalSenderCredentialId:
            input.activeExternalSenderCredentialId,
          activeExternalSenderFingerprint:
            input.activeExternalSenderFingerprint,
          activeSignerGeneration: input.activeSignerGeneration,
          directoryCheckpointId: input.directoryCheckpointId,
          policyLogCheckpointId: input.policyLogCheckpointId,
          deliveryLogPosition: String(conversation.last_position),
          deliveryLogHeadHash: b64(
            conversation.current_log_head_hash as Uint8Array,
          ),
          evaluationLogPosition: String(conversation.last_position),
          evaluationLogHeadHash: b64(
            conversation.current_log_head_hash as Uint8Array,
          ),
          issuedAt,
          expiresAt,
          signerKeyId: signer.signerKeyId,
        };
        const canonicalBody = Buffer.from(canonicalJcs(unsignedBody), "utf8");
        if (canonicalBody.byteLength > MAX_CANONICAL_BODY_BYTES) {
          throw new Error("Policy-head canonical body exceeds its ceiling.");
        }
        const policyHeadHash = computePolicyHeadHash(canonicalBody);
        const signature = signer.sign(policyHeadHash);
        await tx`
          INSERT INTO policy_heads (
            policy_head_id, conversation_id, policy_head_sequence,
            previous_policy_head_hash, policy_head_hash, epoch, roster_version,
            roster_hash, confirmed_transcript_hash, delivery_log_position,
            delivery_log_head_hash, evaluation_log_position,
            evaluation_log_head_hash, policy_id, policy_revision, policy_hash,
            mandatory_proposal_count, mandatory_proposal_set_hash,
            authorized_send_grant_set_hash, authorized_quota_policy_digest,
            evaluated_chain_id, evaluated_block, evaluated_block_hash,
            directory_checkpoint_id, policy_log_checkpoint_id,
            active_external_sender_credential_id,
            active_external_sender_fingerprint, active_signer_generation,
            issued_at, expires_at, policy_head_signing_key_id,
            canonical_signed_body, canonical_signed_body_sha256, signature
          ) VALUES (
            ${policyHeadId}, ${input.conversationId}, ${String(sequence)},
            ${previousHash}, ${policyHeadHash},
            ${String(conversation.epoch)},
            ${String(conversation.roster_version)},
            ${Buffer.from(conversation.roster_hash as Uint8Array)},
            ${Buffer.from(conversation.confirmed_transcript_hash as Uint8Array)},
            ${String(conversation.last_position)},
            ${Buffer.from(conversation.current_log_head_hash as Uint8Array)},
            ${String(conversation.last_position)},
            ${Buffer.from(conversation.current_log_head_hash as Uint8Array)},
            ${input.policyId}, ${input.policyRevision},
            ${bytea(input.policyHash)},
            ${input.mandatoryProposals.length}, ${mandatorySetHash},
            ${sendGrantSetHash}, ${bytea(input.authorizedQuotaPolicyDigest)},
            ${input.evaluatedChainId}, ${input.evaluatedBlock},
            ${bytea(input.evaluatedBlockHash)},
            ${input.directoryCheckpointId}, ${input.policyLogCheckpointId},
            ${input.activeExternalSenderCredentialId},
            ${bytea(input.activeExternalSenderFingerprint)},
            ${input.activeSignerGeneration}, ${issuedAt}::timestamptz,
            ${expiresAt}::timestamptz, ${signer.signerKeyId},
            ${canonicalBody}, ${sha256(canonicalBody)}, ${signature}
          )`;
        for (const [ordinal, proposal] of input.mandatoryProposals.entries()) {
          await tx`
            INSERT INTO policy_head_mandatory_proposals (
              policy_head_id, ordinal, proposal_id, proposal_hash
            ) VALUES (
              ${policyHeadId}, ${ordinal}, ${proposal.proposalId},
              ${bytea(proposal.proposalHash)}
            )`;
        }
        for (const member of input.sendGrantSetMembers) {
          await tx`
            INSERT INTO policy_head_send_grant_set_members (
              policy_head_id, grant_evidence_digest,
              grant_inclusion_evidence_digest, installation_id, credential_id,
              role
            ) VALUES (
              ${policyHeadId}, ${bytea(member.grantEvidenceDigest)},
              ${bytea(member.grantInclusionEvidenceDigest)},
              ${member.installationId}, ${member.credentialId}, ${member.role}
            )`;
        }
        await tx`
          UPDATE conversations SET
            last_policy_head_sequence = ${String(sequence)},
            current_policy_head_hash = ${policyHeadHash}
          WHERE conversation_id = ${input.conversationId}`;
        return Object.freeze({
          policyHeadId,
          policyHeadSequence: String(sequence),
          policyHeadHash: b64(policyHeadHash),
          previousPolicyHeadHash: b64(previousHash),
          canonicalSignedBody: canonicalBody.toString("utf8"),
          issuedAt,
          expiresAt,
        });
      });
    },

    async readNewestPolicyHead(
      conversationId: string,
      afterSequence = "0",
    ): Promise<ServedPolicyHead | null> {
      const rows = await sql`
        SELECT h.policy_head_id, h.policy_head_sequence, h.policy_head_hash,
               h.previous_policy_head_hash, h.canonical_signed_body,
               h.canonical_signed_body_sha256, h.signature, h.issued_at,
               h.expires_at, h.policy_head_signing_key_id, k.public_key,
               k.lifecycle_state, k.not_before, k.expires_at AS key_expires_at
        FROM policy_heads h
        JOIN policy_head_signing_keys k
          ON k.policy_head_signing_key_id = h.policy_head_signing_key_id
        WHERE h.conversation_id = ${conversationId}
          AND h.policy_head_sequence > ${afterSequence}
        ORDER BY h.policy_head_sequence DESC
        LIMIT 1`;
      if (rows.length === 0) return null;
      const row = rows[0];
      const canonicalBody = Buffer.from(
        row.canonical_signed_body as Uint8Array,
      );
      const derivedHash = computePolicyHeadHash(canonicalBody);
      if (
        !derivedHash.equals(Buffer.from(row.policy_head_hash as Uint8Array)) ||
        !sha256(canonicalBody).equals(
          Buffer.from(row.canonical_signed_body_sha256 as Uint8Array),
        )
      ) {
        throw new Error(
          "Served policy head does not re-derive from its immutable body.",
        );
      }
      if (
        String(row.lifecycle_state) !== "active" ||
        new Date(row.issued_at as Date).toISOString() <
          new Date(row.not_before as Date).toISOString() ||
        new Date(row.issued_at as Date).toISOString() >=
          new Date(row.key_expires_at as Date).toISOString()
      ) {
        throw new Error("Served policy head signer is outside its validity.");
      }
      if (
        !verifyEd25519Raw(
          Buffer.from(row.public_key as Uint8Array),
          derivedHash,
          Buffer.from(row.signature as Uint8Array),
        )
      ) {
        throw new Error("Served policy head signature does not verify.");
      }
      return Object.freeze({
        policyHeadId: String(row.policy_head_id),
        policyHeadSequence: String(row.policy_head_sequence),
        policyHeadHash: b64(row.policy_head_hash as Uint8Array),
        previousPolicyHeadHash: b64(
          row.previous_policy_head_hash as Uint8Array,
        ),
        canonicalSignedBody: canonicalBody.toString("utf8"),
        issuedAt: new Date(row.issued_at as Date).toISOString(),
        expiresAt: new Date(row.expires_at as Date).toISOString(),
        signerKeyId: String(row.policy_head_signing_key_id),
        signature: b64(row.signature as Uint8Array),
      });
    },
  });
}

function verifyEd25519Raw(
  rawPublicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): boolean {
  const key = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      rawPublicKey,
    ]),
    format: "der",
    type: "spki",
  });
  return verifyNodeSignature(null, message, key, signature);
}

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function bytea(base64url: string): Buffer {
  const bytes = Buffer.from(base64url, "base64url");
  if (bytes.byteLength !== 32) {
    throw new TypeError("Expected 32 base64url-encoded bytes.");
  }
  return bytes;
}

function sha256(value: Buffer): Buffer {
  return createHash("sha256").update(value).digest();
}

function uuidV4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
