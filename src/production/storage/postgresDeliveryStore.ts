import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  buildFanoutEvidence,
  commandTrustMatchesSnapshot,
  convertQuotaCapacity,
  httpIdempotencyScopeKey,
  signerFenceExpectationFor,
} from "../delivery/appendPersistence";
import {
  applicationEnvelopeSemanticallyEqual,
  enforceApplicationAppendDeliveryLimits,
  enforceStoredEnvelopeDeliveryLimits,
  parseStoredEnvelope,
  type StoredApplicationEnvelope,
} from "../delivery/envelopes";
import { sha256Bytes } from "../delivery/hashes";
import { classifyHttpIdempotencyCommitment } from "../delivery/idempotency";
import { parsePolicyEvidenceForSnapshot } from "../delivery/appendPersistence";
import {
  computeApplicationAppendFenceTokenHash,
  parseApplicationAppendReservationFence,
  parseApplicationAppendSignerFenceResolution,
  parseApplicationAppendSignerFenceVerificationEvidence,
  parseDurableApplicationAppendSignerFenceSignedResolution,
  type ApplicationAppendReservationFence,
  type ApplicationAppendSignerFenceResolution,
  type ApplicationAppendSignerFenceVerificationEvidence,
  type ApplicationAppendPreflightReaderPort,
  type AtomicApplicationAppendCommand,
  type AtomicApplicationAppendReservation,
  type AtomicDeliveryPersistencePort,
  type DeliveryCheckpointSigningRequest,
  type DeliveryInvocationContext,
  type FinalizeApplicationAppendInput,
  type PrepareUnsignedApplicationAppend,
  type RetireExpiredApplicationAppendInput,
} from "../delivery/ports";
import {
  acceptedApplicationAppendIntentFromPending,
  computeAtomicApplicationAppendCommandDigest,
  parseAtomicApplicationAppendCommand,
  parseMlsApplicationWireInspectionEvidence,
  parsePendingApplicationAppendIntent,
  parsePreparedApplicationAppend,
  receiptFromStoredApplicationEnvelope,
  type AcceptedApplicationAppendIntent,
  type ApplicationEnvelopeReceipt,
  type PendingApplicationAppendIntent,
} from "../delivery/service";
import {
  computeLockedApplicationAppendSnapshotDigest,
  parseApplicationAppendFanoutPlan,
  parseLockedApplicationAppendSnapshot,
  refreshLockedApplicationAppendAuthorizationSnapshot,
  type ApplicationAppendFanoutEvidence,
  type LockedApplicationAppendSnapshot,
} from "../delivery/state";
import {
  parseDeliveryCheckpointSignatureEvidence,
  type DeliveryCheckpointSignatureEvidence,
} from "../delivery/sync";
import {
  parseEd25519Signature,
  parseHash32,
  parseRfc3339Millis,
  uint63FromBigInt,
  type ConversationId,
  type Hash32,
  type Rfc3339Millis,
  type Uint63String,
} from "../delivery/valueObjects";

const HTTP_IDEMPOTENCY_TTL_MILLISECONDS = 7 * 24 * 60 * 60 * 1_000;
const TRANSACTION_DEADLINE_MARGIN_MILLISECONDS = 250;
const ENVELOPE_RETENTION_MILLISECONDS = 365 * 24 * 60 * 60 * 1_000;

export interface PostgresDeliveryStoreContext {
  readonly sql: Sql;
  readonly now: () => Rfc3339Millis;
}

export interface PostgresDeliveryAppendStore {
  readonly applicationAppendPreflight: ApplicationAppendPreflightReaderPort;
  readonly atomicPersistence: AtomicDeliveryPersistencePort;
  readonly loadSnapshot: (
    conversationId: ConversationId,
  ) => Promise<LockedApplicationAppendSnapshot>;
}

interface AuthorityRow {
  readonly snapshot: LockedApplicationAppendSnapshot;
  readonly snapshotDigest: Hash32;
  readonly realmId: string;
  readonly mlsRosterCanonical: unknown;
  readonly recipientProjectionsCanonical: unknown;
  readonly activeSigningKeyId: string;
  readonly activeSigningKeyValidUntil: Rfc3339Millis;
  readonly rowVersion: string;
}

interface StoredAcceptance {
  readonly receipt: ApplicationEnvelopeReceipt;
  readonly acceptedIntent: AcceptedApplicationAppendIntent;
  readonly envelope: StoredApplicationEnvelope;
  readonly signatureEvidence: DeliveryCheckpointSignatureEvidence;
  readonly signerFenceEvidence: ApplicationAppendSignerFenceVerificationEvidence;
  readonly fanoutEvidence: ApplicationAppendFanoutEvidence;
  readonly finalizedAt: Rfc3339Millis;
}

/**
 * Production-shaped PostgreSQL adapter for the application-append lane. All
 * canonical documents are strictly re-parsed and digest-verified on every
 * read; the relational columns carry the lane, position, replay, and
 * acceptance fences that migrations 0001-0009 enforce. Attachment references
 * must name ready, unbound attachments owned by the sending installation in
 * this conversation; finalize binds them to the accepted envelope.
 */
const graphError = (component: string): Error =>
  new Error(
    `The relational authority graph is incomplete or ambiguous (${component}).`,
  );

/**
 * Rebuilds the locked append-authority snapshot purely from the relational
 * rows - no custody compare. loadAuthority wraps this with the digest fence;
 * refreshCustodySnapshotDigest wraps it to rewrite the fence after a writer
 * legitimately changes fenced fields (conversation state, positions,
 * pending-removal count).
 */
async function reconstructAuthoritySnapshot(
  tx: TransactionSql,
  conversationId: ConversationId,
  sender?: { readonly installationId: string },
) {
  const conversationRows = await tx`
    SELECT * FROM conversations WHERE conversation_id = ${conversationId}`;
  if (conversationRows.length !== 1) throw graphError("conversation");
  const c = conversationRows[0];

  const grantRows = sender
    ? await tx`
        SELECT * FROM conversation_send_grants
        WHERE conversation_id = ${conversationId}
          AND installation_id = ${sender.installationId}`
    : await tx`
        SELECT * FROM conversation_send_grants
        WHERE conversation_id = ${conversationId}`;
  if (grantRows.length !== 1) throw graphError("send-grant");
  const g = grantRows[0];

  const memberRows = await tx`
    SELECT m.account_id, m.installation_id, m.credential_id,
           m.joined_position, m.removed_position, rc.credential_fingerprint,
           rc.revocation_version, rc.state AS credential_state,
           rc.expires_at, i.status
    FROM memberships m
    JOIN role_credentials rc ON rc.credential_id = m.credential_id
    JOIN installations i ON i.installation_id = m.installation_id
    WHERE m.conversation_id = ${conversationId}
      AND m.installation_id = ${String(g.installation_id)}`;
  if (memberRows.length !== 1) throw graphError("membership");
  const m = memberRows[0];

  const headRows = await tx`
    SELECT * FROM delivery_policy_head_anchors
    WHERE conversation_id = ${conversationId}`;
  if (headRows.length !== 1) throw graphError("policy-head");
  const h = headRows[0];

  const pendingRemovals = await tx`
    SELECT count(*)::int AS total FROM membership_intents
    WHERE conversation_id = ${conversationId} AND operation = 'remove'
      AND state IN ('requested', 'authorized', 'proposed')`;

  const usageRows = await tx`
    SELECT * FROM conversation_usage
    WHERE conversation_id = ${conversationId}`;
  if (usageRows.length !== 1) throw graphError("usage");
  const u = usageRows[0];

  const bindingRows = await tx`
    SELECT * FROM conversation_quota_bindings
    WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
  if (bindingRows.length === 0) throw graphError("quota-bindings");

  const quotaBindings: Record<string, unknown>[] = [];
  const quotas: Record<string, unknown>[] = [];
  for (const binding of bindingRows) {
    const identity = {
      scope: String(binding.scope_type),
      scopeHash: b64(binding.scope_hash as Uint8Array),
      quotaName: String(binding.quota_name),
      windowStartedAt: iso(binding.window_started_at as Date),
      windowSeconds: String(binding.window_seconds),
      operationLimit: String(binding.operation_limit),
      byteLimit: String(binding.byte_limit),
    };
    quotaBindings.push(identity);
    const counters = await tx`
      SELECT operation_count, byte_count, reserved_operation_count,
             reserved_byte_count, row_version
      FROM quota_counters
      WHERE scope_type = ${String(binding.scope_type)}
        AND scope_hash = ${binding.scope_hash as Buffer}
        AND quota_name = ${String(binding.quota_name)}
        AND window_started_at = ${binding.window_started_at as Date}`;
    if (counters.length !== 1) throw graphError("quota-counter");
    const counter = counters[0];
    const liveRows = await tx`
      SELECT reservation_operation_count, reservation_byte_count
      FROM application_append_quota_reservations
      WHERE state = 'live' AND scope_type = ${String(binding.scope_type)}
        AND scope_hash = ${binding.scope_hash as Buffer}
        AND quota_name = ${String(binding.quota_name)}
        AND window_started_at = ${binding.window_started_at as Date}`;
    let liveOperations = 0n;
    let liveBytes = 0n;
    for (const live of liveRows) {
      liveOperations += BigInt(String(live.reservation_operation_count));
      liveBytes += BigInt(String(live.reservation_byte_count));
    }
    quotas.push({
      ...identity,
      operationCount: String(counter.operation_count),
      byteCount: String(counter.byte_count),
      reservedOperationCount: String(
        BigInt(String(counter.reserved_operation_count)) - liveOperations,
      ),
      reservedByteCount: String(
        BigInt(String(counter.reserved_byte_count)) - liveBytes,
      ),
      rowVersion: String(
        BigInt(String(counter.row_version)) - BigInt(liveRows.length),
      ),
    });
  }

  const rosterRows = await tx`
    SELECT * FROM conversation_roster_projections
    WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
  if (rosterRows.length === 0) throw graphError("roster-projection");
  const roster = rosterRows.map((row) => ({
    conversationId,
    conversationGeneration: String(row.conversation_generation),
    rosterVersion: String(row.roster_version),
    accountId: String(row.account_id),
    installationId: String(row.installation_id),
    credentialId: String(row.credential_id),
    credentialFingerprint: b64(row.credential_fingerprint as Uint8Array),
  }));

  const recipientRows = await tx`
    SELECT * FROM conversation_recipient_projections
    WHERE conversation_id = ${conversationId} ORDER BY ordinal`;
  if (recipientRows.length === 0) throw graphError("recipient-projection");
  const recipients = recipientRows.map((row) => ({
    conversationId,
    conversationGeneration: String(row.conversation_generation),
    recipientSetVersion: String(row.recipient_set_version),
    accountId: String(row.account_id),
    installationId: String(row.installation_id),
    credentialId: String(row.credential_id),
    credentialFingerprint: b64(row.credential_fingerprint as Uint8Array),
    credentialRevocationVersion: String(row.credential_revocation_version),
    credentialState: String(row.credential_state),
    credentialExpiresAt: iso(row.credential_expires_at as Date),
    joinedPosition: String(row.joined_position),
    removedPosition:
      row.removed_position === null ? null : String(row.removed_position),
    installationState: String(row.installation_state),
  }));

  const snapshot = parseLockedApplicationAppendSnapshot({
    conversation: {
      realmId: String(c.realm_id),
      conversationId,
      projectScopeId: String(c.project_scope_id),
      tenantScopeId: String(c.tenant_scope_id),
      kind: String(c.delivery_purpose),
      generation: String(c.generation),
      releaseProfileId: String(c.release_profile_id),
      deliveryLimitsDigest: b64(c.delivery_limits_digest as Uint8Array),
      releaseTrustRootDigest: b64(c.release_trust_root_digest as Uint8Array),
      quotaPolicyDigest: b64(c.quota_policy_digest as Uint8Array),
      groupIdHash: b64(c.group_id_hash as Uint8Array),
      state: String(c.state),
      etag: String(c.etag),
      epoch: String(c.epoch),
      rosterVersion: String(c.roster_version),
      rosterHash: b64(c.roster_hash as Uint8Array),
      recipientSetVersion: String(c.recipient_set_version),
      recipientSetHash: b64(c.recipient_set_hash as Uint8Array),
      confirmedTranscriptHash: b64(c.confirmed_transcript_hash as Uint8Array),
      lastPosition: String(c.last_position),
      currentLogHeadHash: b64(c.current_log_head_hash as Uint8Array),
      currentPolicyHeadSequence: String(c.last_policy_head_sequence),
      currentPolicyHeadHash: b64(c.current_policy_head_hash as Uint8Array),
    },
    membership: {
      conversationId,
      accountId: String(m.account_id),
      installationId: String(m.installation_id),
      credentialId: String(m.credential_id),
      credentialFingerprint: b64(m.credential_fingerprint as Uint8Array),
      credentialRevocationVersion: String(m.revocation_version),
      installationState: String(m.status),
      credentialState: String(m.credential_state),
      credentialExpiresAt: iso(m.expires_at as Date),
      joinedPosition: String(m.joined_position),
      removedPosition:
        m.removed_position === null ? null : String(m.removed_position),
    },
    policyHead: {
      policyHeadId: String(h.policy_head_id),
      conversationId,
      policyHeadSequence: String(h.policy_head_sequence),
      policyHeadHash: b64(h.policy_head_hash as Uint8Array),
      deliveryLogPosition: String(h.delivery_log_position),
      deliveryLogHeadHash: b64(h.delivery_log_head_hash as Uint8Array),
      evaluationLogPosition: String(h.evaluation_log_position),
      evaluationLogHeadHash: b64(h.evaluation_log_head_hash as Uint8Array),
      epoch: String(h.epoch),
      rosterVersion: String(h.roster_version),
      confirmedTranscriptHash: b64(h.confirmed_transcript_hash as Uint8Array),
      policyRevision: String(h.policy_revision),
      signedBodySha256: b64(h.signed_body_sha256 as Uint8Array),
      signerKeyId: String(h.signer_key_id),
      signatureSha256: b64(h.signature_sha256 as Uint8Array),
      witnessEvidenceDigest: b64(h.witness_evidence_digest as Uint8Array),
      proofEvidenceDigest: b64(h.proof_evidence_digest as Uint8Array),
      policyConsistencyEvidenceDigest: b64(
        h.policy_consistency_evidence_digest as Uint8Array,
      ),
      proofVerifiedAt: iso(h.proof_verified_at as Date),
      issuedAt: iso(h.issued_at as Date),
      expiresAt: iso(h.expires_at as Date),
      witnessState: String(h.witness_state),
      witnessCheckpointId:
        h.witness_checkpoint_id === null
          ? null
          : String(h.witness_checkpoint_id),
      witnessedPolicyHeadHash:
        h.witnessed_policy_head_hash === null
          ? null
          : b64(h.witnessed_policy_head_hash as Uint8Array),
      mandatoryProposalCount: String(h.mandatory_proposal_count),
      mandatoryProposalSetHash: b64(
        h.mandatory_proposal_set_hash as Uint8Array,
      ),
      authorizedSendGrantSetHash: b64(
        h.authorized_send_grant_set_hash as Uint8Array,
      ),
      selectedSendGrantEvidenceDigest: b64(
        h.selected_send_grant_evidence_digest as Uint8Array,
      ),
      selectedSendGrantInclusionEvidenceDigest: b64(
        h.selected_send_grant_inclusion_evidence_digest as Uint8Array,
      ),
      authorizedQuotaPolicyDigest: b64(
        h.authorized_quota_policy_digest as Uint8Array,
      ),
      priorPolicyHeadSequence: String(h.prior_policy_head_sequence),
      priorPolicyHeadHash: b64(h.prior_policy_head_hash as Uint8Array),
      priorPolicyWitnessCheckpointId: String(
        h.prior_policy_witness_checkpoint_id,
      ),
      priorPolicyWitnessEvidenceDigest: b64(
        h.prior_policy_witness_evidence_digest as Uint8Array,
      ),
    },
    sendGrant: {
      conversationId,
      installationId: String(g.installation_id),
      credentialId: String(g.credential_id),
      conversationKind: String(g.conversation_kind),
      conversationGeneration: String(g.conversation_generation),
      role: String(g.role),
      roleCredentialId: String(g.role_credential_id),
      roleCredentialFingerprint: b64(
        g.role_credential_fingerprint as Uint8Array,
      ),
      roleCredentialSubjectAccountId: String(
        g.role_credential_subject_account_id,
      ),
      roleCredentialSubjectInstallationId: String(
        g.role_credential_subject_installation_id,
      ),
      roleCredentialValidFrom: iso(g.role_credential_valid_from as Date),
      roleCredentialValidUntil: iso(g.role_credential_valid_until as Date),
      capability: String(g.capability),
      state: String(g.state),
      policyRevision: String(g.policy_revision),
      policyHeadSequence: String(g.policy_head_sequence),
      policyHeadHash: b64(g.policy_head_hash as Uint8Array),
      expiresAt: iso(g.expires_at as Date),
      grantEvidenceDigest: b64(g.grant_evidence_digest as Uint8Array),
      grantInclusionEvidenceDigest: b64(
        g.grant_inclusion_evidence_digest as Uint8Array,
      ),
    },
    pendingRemovalCount: String(pendingRemovals[0].total),
    usage: {
      conversationId,
      envelopeCount: String(u.envelope_count),
      envelopeBytes: String(u.envelope_bytes),
      attachmentBytes: String(u.attachment_bytes),
      envelopeCountLimit: String(u.envelope_count_limit),
      envelopeBytesLimit: String(u.envelope_bytes_limit),
      attachmentBytesLimit: String(u.attachment_bytes_limit),
    },
    quotaBindings,
    quotas,
  });
  const snapshotDigest = computeLockedApplicationAppendSnapshotDigest(snapshot);
  return { snapshot, snapshotDigest, roster, recipients };
}


/**
 * Writes the immutable page-end projection for an envelope appended
 * outside the application finalize path (external proposals, membership
 * Commits). Any position can end a page, so every append must leave the
 * exact historical projection behind or the page reader correctly reports
 * history-gone. Reads the POST-append conversation row, so call it after
 * the conversations update in the same transaction.
 */
export async function insertPageEndProjectionFromRows(
  tx: TransactionSql,
  conversationId: string,
  position: string,
  observedAt: string,
): Promise<void> {
  const conversations = await tx`
    SELECT generation, release_profile_id, delivery_limits_digest, etag,
           epoch, roster_version, confirmed_transcript_hash
    FROM conversations WHERE conversation_id = ${conversationId}`;
  const anchors = await tx`
    SELECT * FROM delivery_policy_head_anchors
    WHERE conversation_id = ${conversationId}`;
  if (conversations.length !== 1 || anchors.length !== 1) {
    throw new Error(
      "The page-end projection needs exactly one conversation and anchor row.",
    );
  }
  const c = conversations[0];
  const h = anchors[0];
  await tx`
    INSERT INTO conversation_page_end_projections (
      conversation_id, position, generation, release_profile_id,
      delivery_limits_digest, etag, epoch, roster_version,
      confirmed_transcript_hash, policy_head_id, policy_revision,
      policy_mandatory_proposal_count, policy_mandatory_proposal_set_hash,
      policy_authorized_send_grant_set_hash,
      policy_authorized_quota_policy_digest, policy_head_sequence,
      policy_head_hash, policy_delivery_log_position,
      policy_delivery_log_head_hash, policy_witness_checkpoint_id,
      policy_witness_evidence_digest, created_at
    ) VALUES (
      ${conversationId}, ${position}, ${String(c.generation)},
      ${String(c.release_profile_id)},
      ${Buffer.from(c.delivery_limits_digest as Uint8Array)},
      ${String(c.etag)}, ${String(c.epoch)}, ${String(c.roster_version)},
      ${Buffer.from(c.confirmed_transcript_hash as Uint8Array)},
      ${String(h.policy_head_id)}, ${String(h.policy_revision)},
      ${String(h.mandatory_proposal_count)},
      ${Buffer.from(h.mandatory_proposal_set_hash as Uint8Array)},
      ${Buffer.from(h.authorized_send_grant_set_hash as Uint8Array)},
      ${Buffer.from(h.authorized_quota_policy_digest as Uint8Array)},
      ${String(h.policy_head_sequence)},
      ${Buffer.from(h.policy_head_hash as Uint8Array)},
      ${String(h.delivery_log_position)},
      ${Buffer.from(h.delivery_log_head_hash as Uint8Array)},
      ${h.witness_checkpoint_id === null ? null : String(h.witness_checkpoint_id)},
      ${Buffer.from(h.witness_evidence_digest as Uint8Array)},
      ${observedAt}::timestamptz
    )`;
}

/**
 * Recomputes and rewrites the custody snapshot digest after a transaction
 * mutated fenced fields outside the application-append finalize path
 * (membership intents, external proposals). No-op when the conversation has
 * no custody row. Must run inside the same transaction as the mutation.
 */
export async function refreshCustodySnapshotDigest(
  tx: TransactionSql,
  conversationId: string,
): Promise<void> {
  const custody = await tx`
    SELECT conversation_id FROM delivery_conversation_authority
    WHERE conversation_id = ${conversationId} FOR UPDATE`;
  if (custody.length === 0) return;
  const rebuilt = await reconstructAuthoritySnapshot(
    tx,
    conversationId as ConversationId,
  );
  await tx`
    UPDATE delivery_conversation_authority SET
      snapshot_digest = ${bytea(rebuilt.snapshotDigest)},
      row_version = row_version + 1
    WHERE conversation_id = ${conversationId}`;
}

export function createPostgresDeliveryAppendStore(
  context: PostgresDeliveryStoreContext,
): PostgresDeliveryAppendStore {
  const { sql } = context;

  const dbNow = async (tx: TransactionSql): Promise<Rfc3339Millis> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return iso(rows[0].db_now as Date);
  };

  /**
   * Reconstructs the locked append-authority snapshot from the relational
   * authority graph - the rows ARE the snapshot. The custody row supplies
   * only the lane lock, the active signing key, and the persisted snapshot
   * digest, which the reconstruction must reproduce exactly; any divergence
   * between the graph and the fence fails closed. Quota counters subtract
   * live reservation deltas so the reconstruction reflects the pre-reserve
   * base the digest fence was computed over.
   */
  const loadAuthority = async (
    tx: TransactionSql,
    conversationId: ConversationId,
    lock: boolean,
    sender?: { readonly installationId: string },
  ): Promise<AuthorityRow | null> => {
    const custody = lock
      ? await tx`
          SELECT a.snapshot_digest, a.realm_id, a.active_signing_key_id,
                 a.row_version, k.valid_until
          FROM delivery_conversation_authority a
          JOIN delivery_log_signing_keys k ON k.key_id = a.active_signing_key_id
          WHERE a.conversation_id = ${conversationId}
          FOR UPDATE OF a`
      : await tx`
          SELECT a.snapshot_digest, a.realm_id, a.active_signing_key_id,
                 a.row_version, k.valid_until
          FROM delivery_conversation_authority a
          JOIN delivery_log_signing_keys k ON k.key_id = a.active_signing_key_id
          WHERE a.conversation_id = ${conversationId}`;
    if (custody.length === 0) return null;
    const custodyRow = custody[0];

    const rebuilt = await reconstructAuthoritySnapshot(tx, conversationId, sender);
    const { snapshot, snapshotDigest, roster, recipients } = rebuilt;
    if (snapshotDigest !== b64(custodyRow.snapshot_digest)) {
      throw new Error(
        "Reconstructed authority snapshot does not match the custody digest fence.",
      );
    }
    return {
      snapshot,
      snapshotDigest,
      realmId: String(custodyRow.realm_id),
      mlsRosterCanonical: roster,
      recipientProjectionsCanonical: recipients,
      activeSigningKeyId: String(custodyRow.active_signing_key_id),
      activeSigningKeyValidUntil: iso(custodyRow.valid_until),
      rowVersion: String(custodyRow.row_version),
    };
  };


  const loadPending = async (
    tx: TransactionSql,
    conversationId: ConversationId,
    lock: boolean,
  ): Promise<{ pending: PendingApplicationAppendIntent; reservedAt: Rfc3339Millis } | null> => {
    const rows = lock
      ? await tx`SELECT pending_canonical, reserved_at FROM application_append_pendings
                 WHERE conversation_id = ${conversationId} FOR UPDATE`
      : await tx`SELECT pending_canonical, reserved_at FROM application_append_pendings
                 WHERE conversation_id = ${conversationId}`;
    if (rows.length === 0) return null;
    return {
      pending: parsePendingApplicationAppendIntent(canonicalJson(rows[0].pending_canonical)),
      reservedAt: iso(rows[0].reserved_at),
    };
  };

  const loadAcceptanceBySemanticIdentity = async (
    tx: TransactionSql,
    realmId: string,
    conversationId: ConversationId,
    envelopeId: string,
  ): Promise<StoredAcceptance | null> => {
    const rows = await tx`
      SELECT acceptance_canonical FROM application_append_acceptances
      WHERE realm_id = ${realmId} AND conversation_id = ${conversationId}
        AND envelope_id = ${envelopeId}`;
    if (rows.length === 0) return null;
    return canonicalJson(rows[0].acceptance_canonical) as StoredAcceptance;
  };

  const lookupAcceptedReplay = async (
    tx: TransactionSql,
    command: AtomicApplicationAppendCommand,
    observedAt: Rfc3339Millis,
  ): Promise<unknown | null> => {
    const scopeHash = httpScopeHash(command);
    const httpRows = await tx`
      SELECT h.request_commitment, a.acceptance_canonical
      FROM application_append_http_idempotency h
      JOIN application_append_acceptances a
        ON a.realm_id = h.realm_id AND a.conversation_id = h.conversation_id
          AND a.envelope_id = h.envelope_id
      WHERE h.http_scope_hash = ${scopeHash}
        AND h.expires_at > delivery_db_now()`;
    if (httpRows.length > 0) {
      const classification = classifyHttpIdempotencyCommitment(
        parseHash32(b64(httpRows[0].request_commitment)),
        command.requestCommitment,
      );
      return classification.kind === "conflict"
        ? conflict()
        : acceptedResultFor(
            command,
            canonicalJson(httpRows[0].acceptance_canonical) as StoredAcceptance,
            "http",
            observedAt,
          );
    }
    const identity = command.semanticIdentity;
    const acceptance = await loadAcceptanceBySemanticIdentity(
      tx,
      command.realmId,
      identity.conversationId,
      identity.append.envelopeId,
    );
    if (!acceptance) return null;
    return applicationEnvelopeSemanticallyEqual(
      acceptance.acceptedIntent.admissionCommand.semanticIdentity,
      identity,
    )
      ? acceptedResultFor(command, acceptance, "envelope", observedAt)
      : conflict();
  };

  const lookupPendingReplay = async (
    tx: TransactionSql,
    command: AtomicApplicationAppendCommand,
    lock: boolean,
    observedAt: Rfc3339Millis,
  ): Promise<unknown | null> => {
    const located = await loadPending(
      tx,
      command.semanticIdentity.conversationId,
      lock,
    );
    if (!located) return null;
    const { pending, reservedAt } = located;
    const admitted = pending.admissionCommand;
    if (
      httpIdempotencyScopeKey(admitted) === httpIdempotencyScopeKey(command)
    ) {
      const classification = classifyHttpIdempotencyCommitment(
        admitted.requestCommitment,
        command.requestCommitment,
      );
      return classification.kind === "conflict"
        ? conflict()
        : pendingResultFor(command, pending, "http", reservedAt, observedAt);
    }
    if (
      admitted.realmId === command.realmId &&
      admitted.semanticIdentity.conversationId ===
        command.semanticIdentity.conversationId &&
      admitted.semanticIdentity.append.envelopeId ===
        command.semanticIdentity.append.envelopeId
    ) {
      return applicationEnvelopeSemanticallyEqual(
        admitted.semanticIdentity,
        command.semanticIdentity,
      )
        ? pendingResultFor(command, pending, "envelope", reservedAt, observedAt)
        : conflict();
    }
    if (
      admitted.realmId === command.realmId &&
      admitted.semanticIdentity.conversationId ===
        command.semanticIdentity.conversationId
    ) {
      return blockedByPendingResultFor(command, pending, reservedAt, observedAt);
    }
    return null;
  };

  const invocationIsLive = (invocation: DeliveryInvocationContext): boolean =>
    !invocation.signal.aborted && invocation.deadline > context.now();

  const measureAttachments = async (
    tx: TransactionSql,
    command: AtomicApplicationAppendCommand,
  ): Promise<Uint63String | null> => {
    const identity = command.semanticIdentity;
    let total = 0n;
    for (const attachmentId of identity.append.attachmentIds) {
      const rows = await tx`
        SELECT ciphertext_bytes FROM attachments
        WHERE attachment_id = ${attachmentId}
          AND conversation_id = ${identity.conversationId}
          AND owner_installation_id = ${identity.authenticatedSender.installationId}
          AND state = 'ready'
          AND bound_envelope_position IS NULL
        FOR UPDATE`;
      if (rows.length === 0) return null;
      total += BigInt(rows[0].ciphertext_bytes);
    }
    try {
      return uint63FromBigInt(total);
    } catch {
      return null;
    }
  };

  return Object.freeze({
    applicationAppendPreflight: {
      read: (
        commandValue: AtomicApplicationAppendCommand,
        invocation: DeliveryInvocationContext,
      ): Promise<unknown> =>
        sql.begin(async (tx) => {
          if (!invocationIsLive(invocation)) return unavailable("timeout");
          const command = parseAtomicApplicationAppendCommand(commandValue);
          const observedAt = await dbNow(tx);
          const accepted = await lookupAcceptedReplay(tx, command, observedAt);
          if (accepted !== null) return accepted;
          const pendingReplay = await lookupPendingReplay(
            tx,
            command,
            false,
            observedAt,
          );
          if (pendingReplay !== null) return pendingReplay;
          const authority = await loadAuthority(
            tx,
            command.semanticIdentity.conversationId,
            false,
            command.semanticIdentity.authenticatedSender,
          );
          if (!authority) return rejected("conversation-not-found");
          if (!commandTrustMatchesSnapshot(command, authority.snapshot)) {
            return rejected("conversation-state-changed");
          }
          const attachmentByteLength = await measureAttachments(tx, command);
          if (attachmentByteLength === null) {
            return rejected("attachment-invalid");
          }
          return Object.freeze({
            status: "miss",
            invocationCommandDigest:
              computeAtomicApplicationAppendCommandDigest(command),
            lockedSnapshot: authority.snapshot,
            snapshotDigest: authority.snapshotDigest,
            previousHeadHash: authority.snapshot.conversation.currentLogHeadHash,
            attachmentByteLength,
            observedAt,
          });
        }),
    },
    atomicPersistence: {
      reserveApplicationAppendAtomically: (
        reservationValue: AtomicApplicationAppendReservation,
        prepareUnsigned: PrepareUnsignedApplicationAppend,
        invocation: DeliveryInvocationContext,
      ): Promise<unknown> =>
        sql.begin(async (tx) => {
          if (!invocationIsLive(invocation)) return unavailable("timeout");
          const command = parseAtomicApplicationAppendCommand(
            reservationValue.command,
          );
          const admissionStartedAt = parseRfc3339Millis(
            reservationValue.admissionStartedAt,
            "reservation admission start",
          );
          const authority = await loadAuthority(
            tx,
            command.semanticIdentity.conversationId,
            true,
            command.semanticIdentity.authenticatedSender,
          );
          const observedAt = await dbNow(tx);
          const accepted = await lookupAcceptedReplay(tx, command, observedAt);
          if (accepted !== null) return accepted;
          const pendingReplay = await lookupPendingReplay(
            tx,
            command,
            true,
            observedAt,
          );
          if (pendingReplay !== null) return pendingReplay;
          if (!authority) return rejected("conversation-not-found");
          if (!commandTrustMatchesSnapshot(command, authority.snapshot)) {
            return rejected("conversation-state-changed");
          }
          if (
            parseHash32(reservationValue.expectedSnapshotDigest) !==
            authority.snapshotDigest
          ) {
            return retry();
          }
          try {
            enforceApplicationAppendDeliveryLimits(
              command.semanticIdentity.append,
              command.deliveryLimits,
            );
          } catch {
            return rejected("delivery-limit-exceeded");
          }
          const attachmentByteLength = await measureAttachments(tx, command);
          if (attachmentByteLength === null) {
            return rejected("attachment-invalid");
          }
          const wireEvidence = parseMlsApplicationWireInspectionEvidence(
            reservationValue.wireInspectionEvidence,
          );
          const policyEvidence = parsePolicyEvidenceForSnapshot(
            reservationValue.policyHeadProofEvidence,
            authority.snapshot,
          );
          const authorizationSnapshot =
            refreshLockedApplicationAppendAuthorizationSnapshot({
              persistedSnapshot: authority.snapshot,
              policyHeadProofEvidence: policyEvidence,
            });
          const expectedAuthorizationSnapshotDigest = parseHash32(
            reservationValue.expectedAuthorizationSnapshotDigest,
          );
          if (
            expectedAuthorizationSnapshotDigest !==
            computeLockedApplicationAppendSnapshotDigest(authorizationSnapshot)
          ) {
            return retry();
          }
          const laneRows = await tx`
            INSERT INTO application_append_lanes (conversation_id, lane_generation)
            VALUES (${command.semanticIdentity.conversationId}, 1)
            ON CONFLICT (conversation_id)
            DO UPDATE SET lane_generation = application_append_lanes.lane_generation + 1
            RETURNING lane_generation`;
          const reservationFence = parseApplicationAppendReservationFence({
            generation: String(laneRows[0].lane_generation),
            token: randomBytes(32).toString("base64url"),
          });
          const preparedValue = prepareUnsigned({
            lockedSnapshot: authorizationSnapshot,
            authoritativeReceivedAt: observedAt,
            previousHeadHash: authority.snapshot.conversation.currentLogHeadHash,
            attachmentByteLength,
            activeSigningKeyId: authority.activeSigningKeyId,
            activeSigningKeyValidUntil: authority.activeSigningKeyValidUntil,
            reservationFence: {
              generation: reservationFence.generation,
              token: reservationFence.token,
            },
            mlsRosterProjections: authority.mlsRosterCanonical,
            recipientProjections: authority.recipientProjectionsCanonical,
            transactionDeadline: transactionDeadline(
              context.now(),
              invocation.deadline,
            ),
          });
          if (isThenable(preparedValue)) {
            throw new TypeError(
              "Reservation callback must be synchronous and local-only.",
            );
          }
          const prepared = parsePreparedApplicationAppend(preparedValue);
          if (prepared.status !== "ready") return prepared;
          const pending = prepared.pendingIntent;
          if (
            pending.admissionCommandDigest !==
              computeAtomicApplicationAppendCommandDigest(command) ||
            pending.expectedSnapshotDigest !== authority.snapshotDigest ||
            pending.expectedAuthorizationSnapshotDigest !==
              expectedAuthorizationSnapshotDigest ||
            pending.admissionStartedAt !== admissionStartedAt ||
            pending.reservationFence.generation !== reservationFence.generation ||
            pending.reservationFence.token !== reservationFence.token ||
            pending.wireInspectionEvidence.evidenceDigest !==
              wireEvidence.evidenceDigest ||
            pending.policyHeadProofEvidence.evidenceDigest !==
              policyEvidence.evidenceDigest
          ) {
            throw new TypeError(
              "Reservation callback substituted command or proof facts.",
            );
          }
          for (const reservation of pending.commitProjection
            .quotaCapacityReservations) {
            const reserved = await tx`
              UPDATE quota_counters SET
                reserved_operation_count = reserved_operation_count
                  + ${reservation.reservationOperationCount},
                reserved_byte_count = reserved_byte_count
                  + ${reservation.reservationByteCount},
                row_version = ${reservation.rowVersionAfter},
                updated_at = ${observedAt}::timestamptz
              WHERE scope_type = ${reservation.scope}
                AND scope_hash = ${bytea(reservation.scopeHash)}
                AND quota_name = ${reservation.quotaName}
                AND window_started_at = ${reservation.windowStartedAt}::timestamptz
                AND row_version = ${reservation.rowVersionBefore}
              RETURNING row_version`;
            if (reserved.length !== 1) return retry();
          }
          await tx`
            INSERT INTO application_append_pendings (
              conversation_id, realm_id, intent_digest, admission_command_digest,
              request_commitment, http_scope_hash, envelope_id, position,
              expected_snapshot_digest, fence_generation, fence_token_hash,
              pending_canonical, reserved_at, pending_expires_at
            ) VALUES (
              ${pending.envelope.conversationId}, ${command.realmId},
              ${bytea(pending.intentDigest)}, ${bytea(pending.admissionCommandDigest)},
              ${bytea(command.requestCommitment)}, ${httpScopeHash(command)},
              ${pending.envelope.envelopeId}, ${pending.envelope.position},
              ${bytea(pending.expectedSnapshotDigest)},
              ${pending.reservationFence.generation},
              ${bytea(fenceTokenHashOf(pending.reservationFence))},
              ${JSON.stringify(pending)}::jsonb,
              ${observedAt}::timestamptz, ${pending.pendingExpiresAt}::timestamptz
            )`;
          for (const reservation of pending.commitProjection
            .quotaCapacityReservations) {
            await tx`
              INSERT INTO application_append_quota_reservations (
                reservation_id, pending_intent_digest, scope_type, scope_hash,
                quota_name, window_started_at, reservation_operation_count,
                reservation_byte_count, fence_generation, fence_token_hash,
                state, row_version_before, row_version_after, created_at
              ) VALUES (
                ${bytea(reservation.reservationId)}, ${bytea(pending.intentDigest)},
                ${reservation.scope}, ${bytea(reservation.scopeHash)},
                ${reservation.quotaName},
                ${reservation.windowStartedAt}::timestamptz,
                ${reservation.reservationOperationCount},
                ${reservation.reservationByteCount},
                ${reservation.fenceGeneration},
                ${bytea(reservation.fenceTokenHash)}, 'live',
                ${reservation.rowVersionBefore}, ${reservation.rowVersionAfter},
                ${observedAt}::timestamptz
              )`;
          }
          return pendingResultFor(command, pending, "none", observedAt, observedAt);
        }),
      finalizeApplicationAppendAtomically: (
        inputValue: FinalizeApplicationAppendInput,
        invocation: DeliveryInvocationContext,
      ): Promise<unknown> =>
        sql.begin(async (tx) => {
          if (!invocationIsLive(invocation)) return unavailable("timeout");
          const command = parseAtomicApplicationAppendCommand(inputValue.command);
          const pending = parsePendingApplicationAppendIntent(
            inputValue.pendingIntent,
          );
          const authority = await loadAuthority(
            tx,
            pending.envelope.conversationId,
            true,
            pending.admissionCommand.semanticIdentity.authenticatedSender,
          );
          const observedAt = await dbNow(tx);
          const accepted = await lookupAcceptedReplay(tx, command, observedAt);
          if (accepted !== null) return accepted;
          const located = await loadPending(
            tx,
            pending.envelope.conversationId,
            true,
          );
          if (!located || located.pending.intentDigest !== pending.intentDigest) {
            const admitted = pending.admissionCommand;
            const finalizedAcceptance = await loadAcceptanceBySemanticIdentity(
              tx,
              admitted.realmId,
              admitted.semanticIdentity.conversationId,
              admitted.semanticIdentity.append.envelopeId,
            );
            if (
              finalizedAcceptance &&
              finalizedAcceptance.acceptedIntent.intentDigest ===
                pending.intentDigest
            ) {
              return acceptedResultFor(
                command,
                finalizedAcceptance,
                replayClassification(command, pending),
                observedAt,
              );
            }
            return retry();
          }
          if (!authority) return retry();
          const inputFence = parseApplicationAppendReservationFence(
            inputValue.reservationFence,
          );
          const fanoutPlan = parseApplicationAppendFanoutPlan(
            inputValue.fanoutPlan,
            pending.admissionCommand.deliveryLimits
              .conversationRecipientInstallationsMax,
          );
          if (
            parseHash32(inputValue.pendingIntentDigest) !== pending.intentDigest ||
            inputFence.generation !== pending.reservationFence.generation ||
            inputFence.token !== pending.reservationFence.token ||
            parseRfc3339Millis(inputValue.pendingExpiresAt) !==
              pending.pendingExpiresAt ||
            fanoutPlan.planDigest !== pending.fanoutPlan.planDigest
          ) {
            return unavailable("malformed-dependency-response");
          }
          const signature = parseEd25519Signature(inputValue.signature);
          const signedResolution =
            parseDurableApplicationAppendSignerFenceSignedResolution(
              inputValue.signedFenceResolution,
              signerFenceExpectationFor(pending),
            );
          if (signedResolution.checkpointSignature !== signature) {
            return unavailable("malformed-dependency-response");
          }
          const fenceEvidence = parseApplicationAppendSignerFenceVerificationEvidence(
            inputValue.verifiedSignerFenceEvidence,
            signedResolution,
            parseRfc3339Millis(
              dataValue(inputValue.verifiedSignerFenceEvidence, "verifiedAt"),
            ),
          );
          const signedEnvelope = parseStoredEnvelope({
            ...pending.envelope,
            logHeadSignature: signature,
          });
          if (signedEnvelope.envelopeClass !== "application") {
            throw new TypeError("Pending application finalized as another class.");
          }
          enforceStoredEnvelopeDeliveryLimits(
            signedEnvelope,
            pending.admissionCommand.deliveryLimits,
          );
          const signatureEvidence = parseDeliveryCheckpointSignatureEvidence(
            {
              status: "verified",
              ...(inputValue.verifiedSignatureEvidence as Record<string, unknown>),
            },
            checkpointVerificationRequest(
              signedEnvelope,
              pending,
              signature,
              parseRfc3339Millis(
                dataValue(inputValue.verifiedSignatureEvidence, "verifiedAt"),
              ),
              invocation,
            ),
          );
          if (
            authority.snapshotDigest !== pending.expectedSnapshotDigest ||
            authority.activeSigningKeyId !== signedEnvelope.logSigningKeyId
          ) {
            return retry();
          }
          if (
            (await measureAttachments(tx, pending.admissionCommand)) !==
            pending.attachmentByteLength
          ) {
            return rejected("attachment-invalid");
          }
          const quotas = convertQuotaCapacity(pending, "finalize");
          for (const reservation of pending.commitProjection
            .quotaCapacityReservations) {
            const post = pending.postReservationQuotas.find(
              ({ scope }) => scope === reservation.scope,
            );
            const next = quotas.find(({ scope }) => scope === reservation.scope);
            if (!post || !next) return retry();
            const consumed = await tx`
              UPDATE quota_counters SET
                operation_count = operation_count
                  + ${reservation.reservationOperationCount},
                byte_count = byte_count + ${reservation.reservationByteCount},
                reserved_operation_count = reserved_operation_count
                  - ${reservation.reservationOperationCount},
                reserved_byte_count = reserved_byte_count
                  - ${reservation.reservationByteCount},
                row_version = ${next.rowVersion},
                updated_at = ${observedAt}::timestamptz
              WHERE scope_type = ${reservation.scope}
                AND scope_hash = ${bytea(reservation.scopeHash)}
                AND quota_name = ${reservation.quotaName}
                AND window_started_at = ${reservation.windowStartedAt}::timestamptz
                AND row_version = ${post.rowVersion}
              RETURNING row_version`;
            if (consumed.length !== 1) return retry();
            await tx`
              UPDATE application_append_quota_reservations
              SET state = 'consumed', resolved_at = ${observedAt}::timestamptz
              WHERE reservation_id = ${bytea(reservation.reservationId)}
                AND state = 'live'`;
          }
          const nextSnapshot = parseLockedApplicationAppendSnapshot({
            conversation: { ...pending.commitProjection.conversation },
            membership: { ...authority.snapshot.membership },
            policyHead: { ...authority.snapshot.policyHead },
            sendGrant: { ...authority.snapshot.sendGrant },
            pendingRemovalCount: authority.snapshot.pendingRemovalCount,
            usage: { ...pending.commitProjection.usage },
            quotaBindings: authority.snapshot.quotaBindings.map((binding) => ({
              ...binding,
            })),
            quotas: quotas.map((quota) => ({ ...quota })),
          });
          const nextSnapshotDigest =
            computeLockedApplicationAppendSnapshotDigest(nextSnapshot);
          const receipt = receiptFromStoredApplicationEnvelope(signedEnvelope);
          const acceptedIntent = acceptedApplicationAppendIntentFromPending(
            pending,
            signedResolution,
          );
          const fanoutEvidence = buildFanoutEvidence(
            pending.fanoutPlan,
            signedEnvelope,
          );
          const acceptance: StoredAcceptance = Object.freeze({
            receipt,
            acceptedIntent,
            envelope: signedEnvelope,
            signatureEvidence,
            signerFenceEvidence: fenceEvidence,
            fanoutEvidence,
            finalizedAt: observedAt,
          });

          await tx`
            UPDATE delivery_conversation_authority SET
              snapshot_digest = ${bytea(nextSnapshotDigest)},
              row_version = row_version + 1,
              updated_at = ${observedAt}::timestamptz
            WHERE conversation_id = ${signedEnvelope.conversationId}`;
          await tx`
            UPDATE conversations SET
              last_position = ${signedEnvelope.position},
              current_log_head_hash = ${bytea(signedEnvelope.headHash)},
              last_activity_at = ${observedAt}::timestamptz,
              etag = ${nextSnapshot.conversation.etag},
              epoch = ${nextSnapshot.conversation.epoch},
              roster_version = ${nextSnapshot.conversation.rosterVersion},
              roster_hash = ${bytea(nextSnapshot.conversation.rosterHash)},
              recipient_set_version =
                ${nextSnapshot.conversation.recipientSetVersion},
              recipient_set_hash =
                ${bytea(nextSnapshot.conversation.recipientSetHash)},
              confirmed_transcript_hash =
                ${bytea(nextSnapshot.conversation.confirmedTranscriptHash)},
              last_policy_head_sequence =
                ${nextSnapshot.conversation.currentPolicyHeadSequence},
              current_policy_head_hash =
                ${bytea(nextSnapshot.conversation.currentPolicyHeadHash)}
            WHERE conversation_id = ${signedEnvelope.conversationId}`;
          await tx`
            INSERT INTO envelopes (
              conversation_id, position, envelope_id, envelope_class,
              sender_type, sender_account_id, sender_installation_id,
              epoch, roster_version, content_type, envelope_bytes,
              envelope_sha256, previous_head_hash, leaf_hash, head_hash,
              log_signing_key_id, log_checkpoint_digest, log_head_signature,
              received_at, expires_at
            ) VALUES (
              ${signedEnvelope.conversationId}, ${signedEnvelope.position},
              ${signedEnvelope.envelopeId}, 'application', 'installation',
              ${signedEnvelope.sender.accountId},
              ${signedEnvelope.sender.installationId},
              ${signedEnvelope.epoch}, ${signedEnvelope.rosterVersion},
              ${signedEnvelope.contentType},
              ${Buffer.from(signedEnvelope.envelopeBytes, "base64url")},
              ${bytea(signedEnvelope.envelopeSha256)},
              ${bytea(signedEnvelope.previousHeadHash)},
              ${bytea(signedEnvelope.leafHash)},
              ${bytea(signedEnvelope.headHash)},
              ${signedEnvelope.logSigningKeyId},
              ${bytea(signedEnvelope.logCheckpointDigest)},
              ${Buffer.from(signedEnvelope.logHeadSignature, "base64url")},
              ${signedEnvelope.receivedAt}::timestamptz,
              ${envelopeExpiry(signedEnvelope.receivedAt)}::timestamptz
            )`;
          const attachmentIds =
            pending.admissionCommand.semanticIdentity.append.attachmentIds;
          for (let ordinal = 0; ordinal < attachmentIds.length; ordinal += 1) {
            await tx`
              UPDATE attachments SET state = 'bound',
                bound_envelope_position = ${signedEnvelope.position}
              WHERE attachment_id = ${attachmentIds[ordinal]}`;
            await tx`
              INSERT INTO envelope_attachments (
                conversation_id, envelope_position, ordinal, attachment_id
              ) VALUES (
                ${signedEnvelope.conversationId}, ${signedEnvelope.position},
                ${ordinal}, ${attachmentIds[ordinal]}
              )`;
          }
          for (const installationId of pending.fanoutPlan.recipientInstallationIds) {
            const counter = await tx`
              INSERT INTO mailbox_counters (installation_id, last_position)
              VALUES (${installationId}, 1)
              ON CONFLICT (installation_id)
              DO UPDATE SET last_position = mailbox_counters.last_position + 1
              RETURNING last_position`;
            await tx`
              INSERT INTO mailbox_entries (
                installation_id, mailbox_position, conversation_id,
                envelope_position, envelope_id, delivery_class,
                created_at, expires_at
              ) VALUES (
                ${installationId}, ${String(counter[0].last_position)},
                ${signedEnvelope.conversationId}, ${signedEnvelope.position},
                ${signedEnvelope.envelopeId}, 'application',
                ${observedAt}::timestamptz,
                ${envelopeExpiry(signedEnvelope.receivedAt)}::timestamptz
              )`;
          }
          await tx`
            UPDATE conversation_usage SET
              envelope_count = ${nextSnapshot.usage.envelopeCount},
              envelope_bytes = ${nextSnapshot.usage.envelopeBytes},
              attachment_bytes = ${nextSnapshot.usage.attachmentBytes},
              updated_at = ${observedAt}::timestamptz
            WHERE conversation_id = ${signedEnvelope.conversationId}`;
          await tx`
            INSERT INTO outbox_events (
              aggregate_type, aggregate_id_hash, event_type, payload,
              created_at, available_at
            ) VALUES (
              'conversation',
              ${bytea(sha256Bytes(Buffer.from(signedEnvelope.conversationId)))},
              'application-envelope-accepted',
              ${JSON.stringify({
                conversationId: signedEnvelope.conversationId,
                envelopeId: signedEnvelope.envelopeId,
                position: signedEnvelope.position,
              })}::jsonb,
              ${observedAt}::timestamptz, ${observedAt}::timestamptz
            )`;
          await tx`
            INSERT INTO application_append_acceptances (
              realm_id, conversation_id, envelope_id, position, intent_digest,
              admission_command_digest, semantic_identity_digest,
              acceptance_canonical, finalized_at
            ) VALUES (
              ${pending.admissionCommand.realmId},
              ${signedEnvelope.conversationId}, ${signedEnvelope.envelopeId},
              ${signedEnvelope.position}, ${bytea(pending.intentDigest)},
              ${bytea(pending.admissionCommandDigest)},
              ${bytea(pending.semanticIdentityDigest)},
              ${JSON.stringify(acceptance)}::jsonb,
              ${observedAt}::timestamptz
            )`;
          await tx`
            INSERT INTO conversation_page_end_projections (
              conversation_id, position, generation, release_profile_id,
              delivery_limits_digest, etag, epoch, roster_version,
              confirmed_transcript_hash, policy_head_id, policy_revision,
              policy_mandatory_proposal_count,
              policy_mandatory_proposal_set_hash,
              policy_authorized_send_grant_set_hash,
              policy_authorized_quota_policy_digest, policy_head_sequence,
              policy_head_hash, policy_delivery_log_position,
              policy_delivery_log_head_hash, policy_witness_checkpoint_id,
              policy_witness_evidence_digest, created_at
            ) VALUES (
              ${signedEnvelope.conversationId}, ${signedEnvelope.position},
              ${nextSnapshot.conversation.generation},
              ${nextSnapshot.conversation.releaseProfileId},
              ${bytea(nextSnapshot.conversation.deliveryLimitsDigest)},
              ${nextSnapshot.conversation.etag},
              ${nextSnapshot.conversation.epoch},
              ${nextSnapshot.conversation.rosterVersion},
              ${bytea(nextSnapshot.conversation.confirmedTranscriptHash)},
              ${nextSnapshot.policyHead.policyHeadId},
              ${nextSnapshot.policyHead.policyRevision},
              ${nextSnapshot.policyHead.mandatoryProposalCount},
              ${bytea(nextSnapshot.policyHead.mandatoryProposalSetHash)},
              ${bytea(nextSnapshot.policyHead.authorizedSendGrantSetHash)},
              ${bytea(nextSnapshot.policyHead.authorizedQuotaPolicyDigest)},
              ${nextSnapshot.policyHead.policyHeadSequence},
              ${bytea(nextSnapshot.policyHead.policyHeadHash)},
              ${nextSnapshot.policyHead.deliveryLogPosition},
              ${bytea(nextSnapshot.policyHead.deliveryLogHeadHash)},
              ${nextSnapshot.policyHead.witnessCheckpointId},
              ${bytea(nextSnapshot.policyHead.witnessEvidenceDigest)},
              ${observedAt}::timestamptz
            )`;
          await tx`
            INSERT INTO conversation_policy_transitions (
              conversation_id, policy_head_sequence, policy_head_id,
              policy_head_hash, effective_from_position, created_at
            ) VALUES (
              ${signedEnvelope.conversationId},
              ${nextSnapshot.policyHead.policyHeadSequence},
              ${nextSnapshot.policyHead.policyHeadId},
              ${bytea(nextSnapshot.policyHead.policyHeadHash)},
              ${signedEnvelope.position}, ${observedAt}::timestamptz
            ) ON CONFLICT (conversation_id, policy_head_sequence) DO NOTHING`;
          const semanticallyEqual = applicationEnvelopeSemanticallyEqual(
            pending.admissionCommand.semanticIdentity,
            command.semanticIdentity,
          );
          const idempotencyCommands = semanticallyEqual
            ? [pending.admissionCommand, command]
            : [pending.admissionCommand];
          for (const idempotencyCommand of idempotencyCommands) {
            await tx`
              INSERT INTO application_append_http_idempotency (
                http_scope_hash, request_commitment, realm_id,
                conversation_id, envelope_id, expires_at
              ) VALUES (
                ${httpScopeHash(idempotencyCommand)},
                ${bytea(idempotencyCommand.requestCommitment)},
                ${pending.admissionCommand.realmId},
                ${signedEnvelope.conversationId}, ${signedEnvelope.envelopeId},
                ${new Date(
                  Date.parse(observedAt) + HTTP_IDEMPOTENCY_TTL_MILLISECONDS,
                ).toISOString()}::timestamptz
              ) ON CONFLICT (http_scope_hash) DO NOTHING`;
          }
          await tx`
            DELETE FROM application_append_pendings
            WHERE conversation_id = ${signedEnvelope.conversationId}`;
          return acceptedResultFor(
            command,
            acceptance,
            replayClassification(command, pending),
            observedAt,
          );
        }),
      retireExpiredApplicationAppendAtomically: (
        inputValue: RetireExpiredApplicationAppendInput,
        invocation: DeliveryInvocationContext,
      ): Promise<unknown> =>
        sql.begin(async (tx) => {
          if (!invocationIsLive(invocation)) return unavailable("timeout");
          const command = parseAtomicApplicationAppendCommand(inputValue.command);
          const pendingIntentDigest = parseHash32(inputValue.pendingIntentDigest);
          const observedAt = await dbNow(tx);
          const tombstones = await tx`
            SELECT retired_at FROM application_append_retirements
            WHERE intent_digest = ${bytea(pendingIntentDigest)}`;
          if (tombstones.length > 0) {
            return retiredResultFor(
              command,
              pendingIntentDigest,
              iso(tombstones[0].retired_at),
              observedAt,
            );
          }
          const pending = parsePendingApplicationAppendIntent(
            inputValue.pendingIntent,
          );
          const authority = await loadAuthority(
            tx,
            pending.envelope.conversationId,
            true,
            pending.admissionCommand.semanticIdentity.authenticatedSender,
          );
          const located = await loadPending(
            tx,
            pending.envelope.conversationId,
            true,
          );
          if (!located || located.pending.intentDigest !== pendingIntentDigest) {
            return located
              ? blockedByPendingResultFor(
                  command,
                  located.pending,
                  located.reservedAt,
                  observedAt,
                )
              : unavailable("malformed-dependency-response");
          }
          if (!authority) return unavailable("malformed-dependency-response");
          const inputFence = parseApplicationAppendReservationFence(
            inputValue.reservationFence,
          );
          if (
            pending.intentDigest !== located.pending.intentDigest ||
            inputFence.generation !== pending.reservationFence.generation ||
            inputFence.token !== pending.reservationFence.token ||
            parseRfc3339Millis(inputValue.pendingExpiresAt) !==
              pending.pendingExpiresAt ||
            observedAt < pending.pendingExpiresAt
          ) {
            return unavailable("malformed-dependency-response");
          }
          let resolution: ApplicationAppendSignerFenceResolution;
          try {
            resolution = parseApplicationAppendSignerFenceResolution(
              inputValue.cancellationResolution,
              signingRequestFor(pending, invocation),
            );
          } catch {
            return unavailable("malformed-dependency-response");
          }
          if (resolution.status !== "cancelled") {
            return unavailable("malformed-dependency-response");
          }
          try {
            parseApplicationAppendSignerFenceVerificationEvidence(
              inputValue.verifiedCancellationEvidence,
              resolution,
              parseRfc3339Millis(
                dataValue(inputValue.verifiedCancellationEvidence, "verifiedAt"),
              ),
            );
          } catch {
            return unavailable("malformed-dependency-response");
          }
          const releasedQuotas = convertQuotaCapacity(pending, "release");
          for (const reservation of pending.commitProjection
            .quotaCapacityReservations) {
            const post = pending.postReservationQuotas.find(
              ({ scope }) => scope === reservation.scope,
            );
            const next = releasedQuotas.find(
              ({ scope }) => scope === reservation.scope,
            );
            if (!post || !next) {
              return unavailable("malformed-dependency-response");
            }
            const released = await tx`
              UPDATE quota_counters SET
                reserved_operation_count = reserved_operation_count
                  - ${reservation.reservationOperationCount},
                reserved_byte_count = reserved_byte_count
                  - ${reservation.reservationByteCount},
                row_version = ${next.rowVersion},
                updated_at = ${observedAt}::timestamptz
              WHERE scope_type = ${reservation.scope}
                AND scope_hash = ${bytea(reservation.scopeHash)}
                AND quota_name = ${reservation.quotaName}
                AND window_started_at = ${reservation.windowStartedAt}::timestamptz
                AND row_version = ${post.rowVersion}
              RETURNING row_version`;
            if (released.length !== 1) {
              return unavailable("malformed-dependency-response");
            }
            await tx`
              UPDATE application_append_quota_reservations
              SET state = 'released', resolved_at = ${observedAt}::timestamptz
              WHERE reservation_id = ${bytea(reservation.reservationId)}
                AND state = 'live'`;
          }
          const retiredSnapshot = parseLockedApplicationAppendSnapshot({
            conversation: { ...authority.snapshot.conversation },
            membership: { ...authority.snapshot.membership },
            policyHead: { ...authority.snapshot.policyHead },
            sendGrant: { ...authority.snapshot.sendGrant },
            pendingRemovalCount: authority.snapshot.pendingRemovalCount,
            usage: { ...authority.snapshot.usage },
            quotaBindings: authority.snapshot.quotaBindings.map((binding) => ({
              ...binding,
            })),
            quotas: releasedQuotas.map((quota) => ({ ...quota })),
          });
          await tx`
            UPDATE delivery_conversation_authority SET
              snapshot_digest = ${bytea(
                computeLockedApplicationAppendSnapshotDigest(retiredSnapshot),
              )},
              row_version = row_version + 1,
              updated_at = ${observedAt}::timestamptz
            WHERE conversation_id = ${pending.envelope.conversationId}`;
          await tx`
            DELETE FROM application_append_pendings
            WHERE conversation_id = ${pending.envelope.conversationId}`;
          await tx`
            INSERT INTO application_append_retirements (
              intent_digest, conversation_id, fence_generation,
              fence_token_hash, retired_at
            ) VALUES (
              ${bytea(pendingIntentDigest)},
              ${pending.envelope.conversationId},
              ${pending.reservationFence.generation},
              ${bytea(fenceTokenHashOf(pending.reservationFence))},
              ${observedAt}::timestamptz
            )`;
          return retiredResultFor(command, pendingIntentDigest, observedAt, observedAt);
        }),
    },
    loadSnapshot: async (
      conversationId: ConversationId,
    ): Promise<LockedApplicationAppendSnapshot> => {
      const result = await sql.begin((tx) =>
        loadAuthority(tx, conversationId, false),
      );
      if (!result) {
        throw new Error("Delivery conversation authority row is missing.");
      }
      return result.snapshot;
    },
  });
}

function replayClassification(
  command: AtomicApplicationAppendCommand,
  pending: PendingApplicationAppendIntent,
): "none" | "envelope" | "blocked" {
  if (
    computeAtomicApplicationAppendCommandDigest(command) ===
    pending.admissionCommandDigest
  ) {
    return "none";
  }
  return applicationEnvelopeSemanticallyEqual(
    pending.admissionCommand.semanticIdentity,
    command.semanticIdentity,
  )
    ? "envelope"
    : "blocked";
}

function signingRequestFor(
  pending: PendingApplicationAppendIntent,
  invocation: DeliveryInvocationContext,
): DeliveryCheckpointSigningRequest {
  const expectation = signerFenceExpectationFor(pending);
  return Object.freeze({
    profile: "delivery-log-checkpoint.v1" as const,
    realmId: expectation.realmId,
    conversationGeneration: expectation.conversationGeneration,
    releaseProfileId: expectation.releaseProfileId,
    releaseTrustRootDigest: expectation.releaseTrustRootDigest,
    conversationId: expectation.conversationId,
    position: expectation.position,
    previousHeadHash: expectation.previousHeadHash,
    headHash: expectation.headHash,
    signingKeyId: expectation.signingKeyId,
    checkpointDigest: expectation.checkpointDigest,
    checkpointReceivedAt: expectation.checkpointReceivedAt,
    pendingIntentDigest: expectation.pendingIntentDigest,
    reservationFence: pending.reservationFence,
    pendingExpiresAt: expectation.pendingExpiresAt,
    admissionStartedAt: expectation.admissionStartedAt,
    invocationStartedAt: invocation.invocationStartedAt,
    deadline: invocation.deadline,
    signal: invocation.signal,
  });
}

function checkpointVerificationRequest(
  envelope: StoredApplicationEnvelope,
  pending: PendingApplicationAppendIntent,
  signature: ReturnType<typeof parseEd25519Signature>,
  verifiedAt: Rfc3339Millis,
  invocation: DeliveryInvocationContext,
) {
  return Object.freeze({
    profile: "delivery-log-checkpoint.v1" as const,
    realmId: pending.admissionCommand.realmId,
    conversationId: envelope.conversationId,
    conversationGeneration: pending.priorSnapshot.conversation.generation,
    releaseProfileId: pending.admissionCommand.releaseProfileId,
    releaseTrustRootDigest: pending.admissionCommand.releaseTrustRootDigest,
    position: envelope.position,
    previousHeadHash: envelope.previousHeadHash,
    headHash: envelope.headHash,
    signingKeyId: envelope.logSigningKeyId,
    checkpointDigest: envelope.logCheckpointDigest,
    signature,
    checkpointReceivedAt: envelope.receivedAt,
    verifiedAt,
    ...invocation,
  });
}

function pendingResultFor(
  command: AtomicApplicationAppendCommand,
  pendingIntent: PendingApplicationAppendIntent,
  replay: "none" | "http" | "envelope",
  reservedAt: Rfc3339Millis,
  observedAt: Rfc3339Millis,
) {
  return Object.freeze({
    status: "pending",
    replay,
    invocationCommandDigest:
      computeAtomicApplicationAppendCommandDigest(command),
    pendingIntent,
    reservedAt,
    observedAt,
  });
}

function blockedByPendingResultFor(
  command: AtomicApplicationAppendCommand,
  pendingIntent: PendingApplicationAppendIntent,
  reservedAt: Rfc3339Millis,
  observedAt: Rfc3339Millis,
) {
  return Object.freeze({
    status: "blocked-by-pending",
    invocationCommandDigest:
      computeAtomicApplicationAppendCommandDigest(command),
    pendingIntent,
    reservedAt,
    observedAt,
  });
}

function retiredResultFor(
  command: AtomicApplicationAppendCommand,
  pendingIntentDigest: Hash32,
  retiredAt: Rfc3339Millis,
  observedAt: Rfc3339Millis,
) {
  return Object.freeze({
    status: "retired",
    invocationCommandDigest:
      computeAtomicApplicationAppendCommandDigest(command),
    pendingIntentDigest,
    retiredAt,
    observedAt,
  });
}

function acceptedResultFor(
  command: AtomicApplicationAppendCommand,
  acceptance: StoredAcceptance,
  replay: "none" | "http" | "envelope" | "blocked",
  observedAt: Rfc3339Millis,
) {
  return Object.freeze({
    status: "accepted",
    replay,
    invocationCommandDigest:
      computeAtomicApplicationAppendCommandDigest(command),
    acceptedIntent: acceptance.acceptedIntent,
    envelope: acceptance.envelope,
    receipt: acceptance.receipt,
    signatureEvidence: acceptance.signatureEvidence,
    signerFenceEvidence: acceptance.signerFenceEvidence,
    fanoutEvidence: acceptance.fanoutEvidence,
    finalizedAt: acceptance.finalizedAt,
    observedAt,
  });
}

function fenceTokenHashOf(fence: ApplicationAppendReservationFence): Hash32 {
  return computeApplicationAppendFenceTokenHash(fence.token);
}

function httpScopeHash(command: AtomicApplicationAppendCommand): Buffer {
  return bytea(
    sha256Bytes(Buffer.from(httpIdempotencyScopeKey(command), "utf8")),
  );
}

function rejected(
  reasonCode:
    | "conversation-not-found"
    | "conversation-state-changed"
    | "attachment-invalid"
    | "delivery-limit-exceeded",
) {
  return Object.freeze({ status: "rejected", reasonCode });
}

function retry() {
  return Object.freeze({ status: "retry", reasonCode: "snapshot-changed" });
}

function conflict() {
  return Object.freeze({
    status: "conflict",
    reasonCode: "idempotency-conflict",
  });
}

function unavailable(
  reasonCode:
    | "not-configured"
    | "dependency-unavailable"
    | "timeout"
    | "malformed-dependency-response" = "not-configured",
) {
  return Object.freeze({ status: "unavailable", reasonCode });
}

function canonicalJson(value: unknown): unknown {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function bytea(base64url: string): Buffer {
  return Buffer.from(base64url, "base64url");
}

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function iso(value: Date | string): Rfc3339Millis {
  return parseRfc3339Millis(new Date(value).toISOString());
}

function envelopeExpiry(receivedAt: Rfc3339Millis): string {
  return new Date(
    Date.parse(receivedAt) + ENVELOPE_RETENTION_MILLISECONDS,
  ).toISOString();
}

function transactionDeadline(
  now: Rfc3339Millis,
  invocationDeadline: Rfc3339Millis,
): Rfc3339Millis {
  const candidate = new Date(
    Date.parse(now) + TRANSACTION_DEADLINE_MARGIN_MILLISECONDS,
  ).toISOString();
  return parseRfc3339Millis(
    candidate < invocationDeadline ? candidate : invocationDeadline,
  );
}

function dataValue(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${key} is unavailable on a data record.`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) {
    throw new TypeError(`${key} must be an own data property.`);
  }
  return descriptor.value;
}

function isThenable(value: unknown): boolean {
  if (!value || (typeof value !== "object" && typeof value !== "function")) {
    return false;
  }
  let current: object | null = value;
  while (current !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, "then");
    if (descriptor) {
      return (
        !("value" in descriptor) || typeof descriptor.value === "function"
      );
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return false;
}
