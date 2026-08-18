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
export function createPostgresDeliveryAppendStore(
  context: PostgresDeliveryStoreContext,
): PostgresDeliveryAppendStore {
  const { sql } = context;

  const dbNow = async (tx: TransactionSql): Promise<Rfc3339Millis> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return iso(rows[0].db_now as Date);
  };

  /**
   * The custody snapshot and the relational quota anchors must advance in
   * lockstep: the counters row equals the snapshot counter plus every live
   * relational reservation on that scope. Any divergence is corruption and
   * fails closed rather than trusting either copy.
   */
  const assertQuotaAnchors = async (
    tx: TransactionSql,
    snapshot: LockedApplicationAppendSnapshot,
  ): Promise<void> => {
    for (const quota of snapshot.quotas) {
      const counters = await tx`
        SELECT operation_count, byte_count, reserved_operation_count,
               reserved_byte_count, row_version
        FROM quota_counters
        WHERE scope_type = ${quota.scope}
          AND scope_hash = ${bytea(quota.scopeHash)}
          AND quota_name = ${quota.quotaName}
          AND window_started_at = ${quota.windowStartedAt}::timestamptz`;
      const liveRows = await tx`
        SELECT reservation_operation_count, reservation_byte_count
        FROM application_append_quota_reservations
        WHERE state = 'live' AND scope_type = ${quota.scope}
          AND scope_hash = ${bytea(quota.scopeHash)}
          AND quota_name = ${quota.quotaName}
          AND window_started_at = ${quota.windowStartedAt}::timestamptz`;
      let liveOperations = 0n;
      let liveBytes = 0n;
      for (const row of liveRows) {
        liveOperations += BigInt(String(row.reservation_operation_count));
        liveBytes += BigInt(String(row.reservation_byte_count));
      }
      const counter = counters[0];
      if (
        !counter ||
        BigInt(String(counter.operation_count)) !== BigInt(quota.operationCount) ||
        BigInt(String(counter.byte_count)) !== BigInt(quota.byteCount) ||
        BigInt(String(counter.reserved_operation_count)) !==
          BigInt(quota.reservedOperationCount) + liveOperations ||
        BigInt(String(counter.reserved_byte_count)) !==
          BigInt(quota.reservedByteCount) + liveBytes ||
        BigInt(String(counter.row_version)) !==
          BigInt(quota.rowVersion) + BigInt(liveRows.length)
      ) {
        throw new Error(
          "Authority quota counters diverge from their relational anchors.",
        );
      }
    }
  };


  /**
   * The relational authority graph is load-bearing: every snapshot component
   * must equal its relational rows (conversation projection, sender
   * membership, selected send grant, witnessed policy head, roster and
   * recipient projections, usage). Divergence in either direction is
   * corruption and fails closed.
   */
  const assertRelationalAuthorityGraph = async (
    tx: TransactionSql,
    snapshot: LockedApplicationAppendSnapshot,
    rosterCanonical: unknown,
    recipientsCanonical: unknown,
  ): Promise<void> => {
    const fail = (component: string): never => {
      throw new Error(
        `Authority snapshot diverges from the relational authority graph (${component}).`,
      );
    };
    const conversation = snapshot.conversation;
    const conversationRows = await tx`
      SELECT delivery_purpose, generation, state, epoch, roster_version,
             roster_hash, recipient_set_version, recipient_set_hash,
             confirmed_transcript_hash, last_position, current_log_head_hash,
             last_policy_head_sequence, current_policy_head_hash,
             quota_policy_digest, group_id_hash, realm_id, project_scope_id,
             tenant_scope_id, etag, release_profile_id, delivery_limits_digest,
             release_trust_root_digest
      FROM conversations WHERE conversation_id = ${conversation.conversationId}`;
    const row = conversationRows[0];
    if (
      !row ||
      String(row.delivery_purpose) !== conversation.kind ||
      String(row.generation) !== conversation.generation ||
      String(row.state) !== conversation.state ||
      String(row.epoch) !== conversation.epoch ||
      String(row.roster_version) !== conversation.rosterVersion ||
      b64(row.roster_hash) !== conversation.rosterHash ||
      String(row.recipient_set_version) !== conversation.recipientSetVersion ||
      b64(row.recipient_set_hash) !== conversation.recipientSetHash ||
      b64(row.confirmed_transcript_hash) !== conversation.confirmedTranscriptHash ||
      String(row.last_position) !== conversation.lastPosition ||
      b64(row.current_log_head_hash) !== conversation.currentLogHeadHash ||
      String(row.last_policy_head_sequence) !==
        conversation.currentPolicyHeadSequence ||
      b64(row.current_policy_head_hash) !== conversation.currentPolicyHeadHash ||
      b64(row.quota_policy_digest) !== conversation.quotaPolicyDigest ||
      b64(row.group_id_hash) !== conversation.groupIdHash ||
      String(row.realm_id) !== conversation.realmId ||
      String(row.project_scope_id) !== conversation.projectScopeId ||
      String(row.tenant_scope_id) !== conversation.tenantScopeId ||
      String(row.etag) !== conversation.etag ||
      String(row.release_profile_id) !== conversation.releaseProfileId ||
      b64(row.delivery_limits_digest) !== conversation.deliveryLimitsDigest ||
      b64(row.release_trust_root_digest) !== conversation.releaseTrustRootDigest
    ) {
      fail("conversation");
    }
    const membership = snapshot.membership;
    const membershipRows = await tx`
      SELECT m.joined_position, m.removed_position, m.account_id,
             c.credential_fingerprint, c.revocation_version,
             c.state AS credential_state, c.expires_at, i.status
      FROM memberships m
      JOIN role_credentials c ON c.credential_id = m.credential_id
      JOIN installations i ON i.installation_id = m.installation_id
      WHERE m.conversation_id = ${membership.conversationId}
        AND m.installation_id = ${membership.installationId}
        AND m.credential_id = ${membership.credentialId}`;
    const memberRow = membershipRows[0];
    if (
      !memberRow ||
      String(memberRow.account_id) !== membership.accountId ||
      String(memberRow.joined_position) !== membership.joinedPosition ||
      (memberRow.removed_position === null
        ? membership.removedPosition !== null
        : String(memberRow.removed_position) !== membership.removedPosition) ||
      b64(memberRow.credential_fingerprint) !== membership.credentialFingerprint ||
      String(memberRow.revocation_version) !==
        membership.credentialRevocationVersion ||
      String(memberRow.credential_state) !== membership.credentialState ||
      iso(memberRow.expires_at) !== membership.credentialExpiresAt ||
      String(memberRow.status) !== membership.installationState
    ) {
      fail("membership");
    }
    const sendGrant = snapshot.sendGrant;
    const grantRows = await tx`
      SELECT role, role_credential_id, role_credential_fingerprint,
             role_credential_subject_account_id,
             role_credential_subject_installation_id,
             role_credential_valid_from, role_credential_valid_until,
             capability, state, policy_revision, policy_head_sequence,
             policy_head_hash, expires_at, grant_evidence_digest,
             grant_inclusion_evidence_digest, conversation_generation
      FROM conversation_send_grants
      WHERE conversation_id = ${sendGrant.conversationId}
        AND installation_id = ${sendGrant.installationId}
        AND credential_id = ${sendGrant.credentialId}`;
    const grantRow = grantRows[0];
    if (
      !grantRow ||
      String(grantRow.role) !== sendGrant.role ||
      String(grantRow.role_credential_id) !== sendGrant.roleCredentialId ||
      b64(grantRow.role_credential_fingerprint) !==
        sendGrant.roleCredentialFingerprint ||
      String(grantRow.role_credential_subject_account_id) !==
        sendGrant.roleCredentialSubjectAccountId ||
      String(grantRow.role_credential_subject_installation_id) !==
        sendGrant.roleCredentialSubjectInstallationId ||
      iso(grantRow.role_credential_valid_from) !==
        sendGrant.roleCredentialValidFrom ||
      iso(grantRow.role_credential_valid_until) !==
        sendGrant.roleCredentialValidUntil ||
      String(grantRow.capability) !== sendGrant.capability ||
      String(grantRow.state) !== sendGrant.state ||
      String(grantRow.policy_revision) !== sendGrant.policyRevision ||
      String(grantRow.policy_head_sequence) !== sendGrant.policyHeadSequence ||
      b64(grantRow.policy_head_hash) !== sendGrant.policyHeadHash ||
      iso(grantRow.expires_at) !== sendGrant.expiresAt ||
      b64(grantRow.grant_evidence_digest) !== sendGrant.grantEvidenceDigest ||
      b64(grantRow.grant_inclusion_evidence_digest) !==
        sendGrant.grantInclusionEvidenceDigest ||
      String(grantRow.conversation_generation) !==
        sendGrant.conversationGeneration
    ) {
      fail("send-grant");
    }
    const head = snapshot.policyHead;
    const headRows = await tx`
      SELECT * FROM delivery_policy_head_anchors
      WHERE conversation_id = ${head.conversationId}`;
    const headRow = headRows[0];
    if (
      !headRow ||
      String(headRow.policy_head_id) !== head.policyHeadId ||
      String(headRow.policy_head_sequence) !== head.policyHeadSequence ||
      b64(headRow.policy_head_hash) !== head.policyHeadHash ||
      String(headRow.delivery_log_position) !== head.deliveryLogPosition ||
      b64(headRow.delivery_log_head_hash) !== head.deliveryLogHeadHash ||
      String(headRow.evaluation_log_position) !== head.evaluationLogPosition ||
      b64(headRow.evaluation_log_head_hash) !== head.evaluationLogHeadHash ||
      String(headRow.epoch) !== head.epoch ||
      String(headRow.roster_version) !== head.rosterVersion ||
      b64(headRow.confirmed_transcript_hash) !== head.confirmedTranscriptHash ||
      String(headRow.policy_revision) !== head.policyRevision ||
      b64(headRow.signed_body_sha256) !== head.signedBodySha256 ||
      String(headRow.signer_key_id) !== head.signerKeyId ||
      b64(headRow.signature_sha256) !== head.signatureSha256 ||
      b64(headRow.witness_evidence_digest) !== head.witnessEvidenceDigest ||
      b64(headRow.proof_evidence_digest) !== head.proofEvidenceDigest ||
      b64(headRow.policy_consistency_evidence_digest) !==
        head.policyConsistencyEvidenceDigest ||
      iso(headRow.proof_verified_at) !== head.proofVerifiedAt ||
      iso(headRow.issued_at) !== head.issuedAt ||
      iso(headRow.expires_at) !== head.expiresAt ||
      String(headRow.witness_state) !== head.witnessState ||
      (headRow.witness_checkpoint_id === null
        ? head.witnessCheckpointId !== null
        : String(headRow.witness_checkpoint_id) !== head.witnessCheckpointId) ||
      (headRow.witnessed_policy_head_hash === null
        ? head.witnessedPolicyHeadHash !== null
        : b64(headRow.witnessed_policy_head_hash) !==
          head.witnessedPolicyHeadHash) ||
      String(headRow.mandatory_proposal_count) !== head.mandatoryProposalCount ||
      b64(headRow.mandatory_proposal_set_hash) !==
        head.mandatoryProposalSetHash ||
      b64(headRow.authorized_send_grant_set_hash) !==
        head.authorizedSendGrantSetHash ||
      b64(headRow.selected_send_grant_evidence_digest) !==
        head.selectedSendGrantEvidenceDigest ||
      b64(headRow.selected_send_grant_inclusion_evidence_digest) !==
        head.selectedSendGrantInclusionEvidenceDigest ||
      b64(headRow.authorized_quota_policy_digest) !==
        head.authorizedQuotaPolicyDigest ||
      String(headRow.prior_policy_head_sequence) !==
        head.priorPolicyHeadSequence ||
      b64(headRow.prior_policy_head_hash) !== head.priorPolicyHeadHash ||
      String(headRow.prior_policy_witness_checkpoint_id) !==
        head.priorPolicyWitnessCheckpointId ||
      b64(headRow.prior_policy_witness_evidence_digest) !==
        head.priorPolicyWitnessEvidenceDigest
    ) {
      fail("policy-head");
    }
    const rosterEntries = (
      Array.isArray(rosterCanonical) ? rosterCanonical : []
    ) as readonly Record<string, unknown>[];
    const rosterRows = await tx`
      SELECT installation_id, account_id, credential_id, credential_fingerprint,
             conversation_generation, roster_version
      FROM conversation_roster_projections
      WHERE conversation_id = ${conversation.conversationId}`;
    if (rosterRows.length !== rosterEntries.length) fail("roster-projection");
    for (const entry of rosterEntries) {
      const match = rosterRows.find(
        (candidate) =>
          String(candidate.installation_id) === String(entry.installationId),
      );
      if (
        !match ||
        String(match.account_id) !== String(entry.accountId) ||
        String(match.credential_id) !== String(entry.credentialId) ||
        b64(match.credential_fingerprint) !== String(entry.credentialFingerprint) ||
        String(match.conversation_generation) !==
          String(entry.conversationGeneration) ||
        String(match.roster_version) !== String(entry.rosterVersion)
      ) {
        fail("roster-projection");
      }
    }
    const recipientEntries = (
      Array.isArray(recipientsCanonical) ? recipientsCanonical : []
    ) as readonly Record<string, unknown>[];
    const recipientRows = await tx`
      SELECT installation_id, account_id, credential_id, credential_fingerprint,
             credential_revocation_version, credential_state,
             credential_expires_at, joined_position, removed_position,
             installation_state, conversation_generation, recipient_set_version
      FROM conversation_recipient_projections
      WHERE conversation_id = ${conversation.conversationId}`;
    if (recipientRows.length !== recipientEntries.length) {
      fail("recipient-projection");
    }
    for (const entry of recipientEntries) {
      const match = recipientRows.find(
        (candidate) =>
          String(candidate.installation_id) === String(entry.installationId),
      );
      if (
        !match ||
        String(match.account_id) !== String(entry.accountId) ||
        String(match.credential_id) !== String(entry.credentialId) ||
        b64(match.credential_fingerprint) !== String(entry.credentialFingerprint) ||
        String(match.credential_revocation_version) !==
          String(entry.credentialRevocationVersion) ||
        String(match.credential_state) !== String(entry.credentialState) ||
        iso(match.credential_expires_at) !== String(entry.credentialExpiresAt) ||
        String(match.joined_position) !== String(entry.joinedPosition) ||
        (match.removed_position === null
          ? entry.removedPosition !== null
          : String(match.removed_position) !== String(entry.removedPosition)) ||
        String(match.installation_state) !== String(entry.installationState) ||
        String(match.conversation_generation) !==
          String(entry.conversationGeneration) ||
        String(match.recipient_set_version) !== String(entry.recipientSetVersion)
      ) {
        fail("recipient-projection");
      }
    }
    const usageRows = await tx`
      SELECT envelope_count, envelope_bytes, attachment_bytes
      FROM conversation_usage
      WHERE conversation_id = ${conversation.conversationId}`;
    const usageRow = usageRows[0];
    if (
      !usageRow ||
      String(usageRow.envelope_count) !== snapshot.usage.envelopeCount ||
      String(usageRow.envelope_bytes) !== snapshot.usage.envelopeBytes ||
      String(usageRow.attachment_bytes) !== snapshot.usage.attachmentBytes
    ) {
      fail("usage");
    }
  };

  const loadAuthority = async (
    tx: TransactionSql,
    conversationId: ConversationId,
    lock: boolean,
  ): Promise<AuthorityRow | null> => {
    const rows = lock
      ? await tx`
          SELECT a.snapshot_canonical, a.snapshot_digest, a.realm_id,
                 a.mls_roster_canonical, a.recipient_projections_canonical,
                 a.active_signing_key_id, a.row_version, k.valid_until
          FROM delivery_conversation_authority a
          JOIN delivery_log_signing_keys k ON k.key_id = a.active_signing_key_id
          WHERE a.conversation_id = ${conversationId}
          FOR UPDATE OF a`
      : await tx`
          SELECT a.snapshot_canonical, a.snapshot_digest, a.realm_id,
                 a.mls_roster_canonical, a.recipient_projections_canonical,
                 a.active_signing_key_id, a.row_version, k.valid_until
          FROM delivery_conversation_authority a
          JOIN delivery_log_signing_keys k ON k.key_id = a.active_signing_key_id
          WHERE a.conversation_id = ${conversationId}`;
    if (rows.length === 0) return null;
    const row = rows[0];
    const snapshot = parseLockedApplicationAppendSnapshot(canonicalJson(row.snapshot_canonical));
    const snapshotDigest = computeLockedApplicationAppendSnapshotDigest(snapshot);
    if (snapshotDigest !== b64(row.snapshot_digest)) {
      throw new Error("Authority snapshot custody digest is inconsistent.");
    }
    await assertQuotaAnchors(tx, snapshot);
    await assertRelationalAuthorityGraph(
      tx,
      snapshot,
      canonicalJson(row.mls_roster_canonical),
      canonicalJson(row.recipient_projections_canonical),
    );
    return {
      snapshot,
      snapshotDigest,
      realmId: row.realm_id,
      mlsRosterCanonical: canonicalJson(row.mls_roster_canonical),
      recipientProjectionsCanonical: canonicalJson(row.recipient_projections_canonical),
      activeSigningKeyId: row.active_signing_key_id,
      activeSigningKeyValidUntil: iso(row.valid_until),
      rowVersion: String(row.row_version),
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
              snapshot_canonical = ${JSON.stringify(nextSnapshot)}::jsonb,
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
              snapshot_canonical = ${JSON.stringify(retiredSnapshot)}::jsonb,
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
