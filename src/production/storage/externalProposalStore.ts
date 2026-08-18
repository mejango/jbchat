import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeExternalProposalHash,
  computeLogHeadHash,
  type EnvelopeLeafInput,
  type DeliveryLogCheckpointInput,
} from "../delivery/hashes";
import type { Hash32 } from "../delivery/valueObjects";
import { refreshCustodySnapshotDigest } from "./postgresDeliveryStore";

const ENVELOPE_RETENTION_MILLISECONDS = 365 * 24 * 60 * 60 * 1_000;
const PROPOSAL_CONTENT_TYPE =
  "application/vnd.juicebox.messaging.mls-public-message";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface ExternalProposalSigningPort {
  readonly signCheckpointDigest: (
    signingKeyId: string,
    digest: Hash32,
  ) => Promise<string>;
}

export interface ExternalProposalStoreContext {
  readonly sql: Sql;
  readonly signer: ExternalProposalSigningPort;
}

export type ExternalProposalRecording =
  | {
      readonly status: "recorded";
      readonly proposalId: string;
      readonly intentId: string;
      readonly envelopeId: string;
      readonly envelopePosition: string;
      readonly proposalHash: string;
      readonly headHash: string;
      readonly expiresAt: string;
    }
  | { readonly status: "conflict"; readonly reasonCode: "proposal-exists" }
  | {
      readonly status: "refused";
      readonly reasonCode:
        | "intent-not-live"
        | "signer-credential-invalid"
        | "checkpoint-unknown"
        | "log-authority-unavailable"
        | "malformed-request";
    };

export interface ExternalProposalStore {
  readonly recordProposal: (input: unknown) => Promise<ExternalProposalRecording>;
}

/**
 * Records the server-side external proposal for a live membership intent:
 * appends the MLS PublicMessage to the conversation's gap-free envelope log
 * as an entitlement_signer envelope (chained leaf/head hashes, checkpoint
 * digest signed by the active delivery log key), writes the
 * external_proposals row binding the exact bytes via the shared
 * jb-msg-external-proposal/v1 hash, and moves the intent to `proposed`.
 * The PublicMessage and authorization record arrive from the MLS layer;
 * this store never fabricates MLS facts. Appending moves custody-fenced
 * fields, so the fence is rewritten in the same transaction.
 */
export function createExternalProposalStore(
  context: ExternalProposalStoreContext,
): ExternalProposalStore {
  const { sql, signer } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  return Object.freeze({
    async recordProposal(inputValue: unknown): Promise<ExternalProposalRecording> {
      let intentId: string;
      let publicMessage: Buffer;
      let authorizationRecordHash: string;
      let signerExternalSenderCredentialId: string;
      let transparencyCheckpointId: string;
      try {
        const record = inputValue as Record<string, unknown>;
        if (
          !inputValue ||
          typeof inputValue !== "object" ||
          Reflect.ownKeys(record).length !== 5
        ) {
          throw new TypeError("Unexpected shape.");
        }
        intentId = expectUuid(record.intentId);
        publicMessage = Buffer.from(
          expectBase64Url(record.publicMessage),
          "base64url",
        );
        if (publicMessage.length === 0 || publicMessage.length > 262144) {
          throw new TypeError("PublicMessage size is out of range.");
        }
        authorizationRecordHash = expectBase64Url(
          record.authorizationRecordHash,
        );
        if (Buffer.from(authorizationRecordHash, "base64url").length !== 32) {
          throw new TypeError("authorizationRecordHash must be 32 bytes.");
        }
        signerExternalSenderCredentialId = expectUuid(
          record.signerExternalSenderCredentialId,
        );
        transparencyCheckpointId = expectUuid(record.transparencyCheckpointId);
      } catch {
        return Object.freeze({
          status: "refused",
          reasonCode: "malformed-request",
        });
      }

      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const intents = await tx`
          SELECT conversation_id, state, expires_at, base_epoch
          FROM membership_intents
          WHERE intent_id = ${intentId} FOR UPDATE`;
        if (
          intents.length !== 1 ||
          !["requested", "authorized"].includes(String(intents[0].state)) ||
          new Date(intents[0].expires_at as Date).toISOString() <= now
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "intent-not-live" as const,
          });
        }
        const intent = intents[0];
        const conversationId = String(intent.conversation_id);

        const existing = await tx`
          SELECT 1 FROM external_proposals WHERE intent_id = ${intentId}`;
        if (existing.length !== 0) {
          return Object.freeze({
            status: "conflict" as const,
            reasonCode: "proposal-exists" as const,
          });
        }

        const conversations = await tx`
          SELECT project_ref_id, epoch, roster_version, last_position,
                 current_log_head_hash
          FROM conversations
          WHERE conversation_id = ${conversationId} FOR UPDATE`;
        if (conversations.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "intent-not-live" as const,
          });
        }
        const conversation = conversations[0];

        const credentials = await tx`
          SELECT credential_fingerprint, signer_generation
          FROM external_sender_credentials
          WHERE external_sender_credential_id =
                ${signerExternalSenderCredentialId}
            AND project_ref_id = ${String(conversation.project_ref_id)}
            AND lifecycle_state = 'published'
            AND not_before <= ${now}::timestamptz
            AND expires_at > ${now}::timestamptz`;
        if (credentials.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "signer-credential-invalid" as const,
          });
        }
        const credential = credentials[0];
        const fingerprint = Buffer.from(
          credential.credential_fingerprint as Uint8Array,
        ).toString("base64url");
        const signerGeneration = String(credential.signer_generation);

        const checkpoints = await tx`
          SELECT 1 FROM policy_log_checkpoints
          WHERE checkpoint_id = ${transparencyCheckpointId}`;
        if (checkpoints.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "checkpoint-unknown" as const,
          });
        }

        const custody = await tx`
          SELECT a.active_signing_key_id
          FROM delivery_conversation_authority a
          JOIN delivery_log_signing_keys k ON k.key_id = a.active_signing_key_id
          WHERE a.conversation_id = ${conversationId}
            AND k.state = 'active'
            AND k.valid_from <= ${now}::timestamptz
            AND k.valid_until > ${now}::timestamptz
          FOR UPDATE OF a`;
        if (custody.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "log-authority-unavailable" as const,
          });
        }
        const signingKeyId = String(custody[0].active_signing_key_id);

        const position = String(
          BigInt(String(conversation.last_position)) + 1n,
        );
        const envelopeId = randomUUID();
        const envelopeSha256 = computeEnvelopeSha256(publicMessage);
        const leafHash = computeEnvelopeLeafHash({
          conversationId,
          position,
          envelopeId,
          envelopeClass: "external_proposal",
          sender: {
            type: "entitlement_signer",
            credentialId: signerExternalSenderCredentialId,
            fingerprint,
            signerGeneration,
          },
          epoch: String(conversation.epoch),
          rosterVersion: String(conversation.roster_version),
          contentType: PROPOSAL_CONTENT_TYPE,
          envelopeSha256,
          receivedAt: now,
        } as unknown as EnvelopeLeafInput);
        const previousHeadHash = Buffer.from(
          conversation.current_log_head_hash as Uint8Array,
        ).toString("base64url");
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
            sender_type, sender_external_credential_id,
            sender_external_fingerprint, sender_signer_generation,
            epoch, roster_version, content_type, envelope_bytes,
            envelope_sha256, previous_head_hash, leaf_hash, head_hash,
            log_signing_key_id, log_checkpoint_digest, log_head_signature,
            received_at, expires_at
          ) VALUES (
            ${conversationId}, ${position}, ${envelopeId},
            'external_proposal', 'entitlement_signer',
            ${signerExternalSenderCredentialId},
            ${Buffer.from(fingerprint, "base64url")}, ${signerGeneration},
            ${String(conversation.epoch)},
            ${String(conversation.roster_version)},
            ${PROPOSAL_CONTENT_TYPE}, ${publicMessage},
            ${Buffer.from(envelopeSha256, "base64url")},
            ${Buffer.from(previousHeadHash, "base64url")},
            ${Buffer.from(leafHash, "base64url")},
            ${Buffer.from(headHash, "base64url")},
            ${signingKeyId}, ${Buffer.from(checkpointDigest, "base64url")},
            ${Buffer.from(signature, "base64url")},
            ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
          )`;
        await tx`
          UPDATE conversations SET
            last_position = ${position},
            current_log_head_hash = ${Buffer.from(headHash, "base64url")},
            last_activity_at = ${now}::timestamptz
          WHERE conversation_id = ${conversationId}`;

        const proposalHash = computeExternalProposalHash(
          publicMessage,
          authorizationRecordHash as Hash32,
        );
        const proposalId = randomUUID();
        const expiresAt = new Date(intent.expires_at as Date).toISOString();
        await tx`
          INSERT INTO external_proposals (
            proposal_id, proposal_hash, intent_id, conversation_id,
            envelope_id, envelope_position, base_epoch, public_message,
            public_message_sha256, authorization_record_hash,
            signer_external_sender_credential_id,
            signer_external_sender_fingerprint, signer_generation,
            transparency_checkpoint_id, created_at, expires_at
          ) VALUES (
            ${proposalId}, ${Buffer.from(proposalHash, "base64url")},
            ${intentId}, ${conversationId}, ${envelopeId}, ${position},
            ${String(intent.base_epoch)}, ${publicMessage},
            ${Buffer.from(envelopeSha256, "base64url")},
            ${Buffer.from(authorizationRecordHash, "base64url")},
            ${signerExternalSenderCredentialId},
            ${Buffer.from(fingerprint, "base64url")}, ${signerGeneration},
            ${transparencyCheckpointId}, ${now}::timestamptz,
            ${expiresAt}::timestamptz
          )`;
        await tx`
          UPDATE membership_intents SET state = 'proposed'
          WHERE intent_id = ${intentId}`;
        // last_position and current_log_head_hash are custody-fenced fields.
        await refreshCustodySnapshotDigest(tx, conversationId);
        return Object.freeze({
          status: "recorded" as const,
          proposalId,
          intentId,
          envelopeId,
          envelopePosition: position,
          proposalHash,
          headHash,
          expiresAt,
        });
      });
    },
  });
}

function expectUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError("Expected a lowercase UUID.");
  }
  return value;
}

function expectBase64Url(value: unknown): string {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) {
    throw new TypeError("Expected canonical base64url.");
  }
  return value;
}

