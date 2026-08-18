import {
  computeApplicationAppendFenceTokenHash,
  type ApplicationAppendSignerFenceResolutionExpectation,
  type AtomicApplicationAppendCommand,
} from "./ports";
import type { PendingApplicationAppendIntent } from "./service";
import {
  computeApplicationAppendFanoutEvidenceDigest,
  computeApplicationAppendMailboxProjectionDigest,
  computeApplicationAppendOutboxProjectionDigest,
  parseApplicationAppendFanoutEvidence,
  parsePolicyHeadProofEvidence,
  validateLockedApplicationAppendQuotaFinalizationTransition,
  validateLockedApplicationAppendQuotaReleaseTransition,
  type ApplicationAppendFanoutEvidence,
  type ApplicationAppendFanoutPlan,
  type ApplicationAppendQuotaCapacityReservation,
  type LockedApplicationAppendSnapshot,
  type LockedQuotaCounter,
  type PolicyHeadProofEvidence,
} from "./state";
import type { StoredApplicationEnvelope } from "./envelopes";
import { parseDeliveryRealmId } from "./sync";
import {
  parseRfc3339Millis,
  uint63FromBigInt,
  type ConversationId,
  type EnvelopeId,
  type Rfc3339Millis,
} from "./valueObjects";

/**
 * Shared, side-effect-free derivations every AtomicDeliveryPersistencePort
 * adapter needs, so the in-memory lab and the PostgreSQL repository cannot
 * drift on fence expectations, quota conversion, replay keys, or fanout
 * evidence.
 */

export function signerFenceExpectationFor(
  pending: PendingApplicationAppendIntent,
): ApplicationAppendSignerFenceResolutionExpectation {
  const envelope = pending.envelope;
  return Object.freeze({
    realmId: parseDeliveryRealmId(pending.admissionCommand.realmId),
    conversationGeneration: pending.priorSnapshot.conversation.generation,
    releaseProfileId: pending.admissionCommand.releaseProfileId,
    releaseTrustRootDigest: pending.admissionCommand.releaseTrustRootDigest,
    conversationId: envelope.conversationId,
    position: envelope.position,
    previousHeadHash: envelope.previousHeadHash,
    headHash: envelope.headHash,
    signingKeyId: envelope.logSigningKeyId,
    checkpointDigest: envelope.logCheckpointDigest,
    checkpointReceivedAt: envelope.receivedAt,
    pendingIntentDigest: pending.intentDigest,
    fenceGeneration: pending.reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      pending.reservationFence.token,
    ),
    pendingExpiresAt: pending.pendingExpiresAt,
    admissionStartedAt: pending.admissionStartedAt,
  });
}

/**
 * Computes and validates the exact quota-capacity conversion for finalizing
 * or releasing one pending append. Reserved capacity lives inside the pending
 * intent, so the conversion always starts from postReservationQuotas.
 */
export function convertQuotaCapacity(
  pending: PendingApplicationAppendIntent,
  mode: "finalize" | "release",
): readonly LockedQuotaCounter[] {
  const reservations = pending.commitProjection.quotaCapacityReservations;
  const preparedFinalQuotas = pending.postReservationQuotas.map((quota) => {
    const reservation = reservations.find(
      ({ scope }) => scope === quota.scope,
    );
    if (!reservation) {
      throw new TypeError("Quota reservation scope disappeared in persistence.");
    }
    return Object.freeze({
      ...quota,
      operationCount:
        mode === "finalize"
          ? uint63FromBigInt(
              BigInt(quota.operationCount) +
                BigInt(reservation.reservationOperationCount),
            )
          : quota.operationCount,
      byteCount:
        mode === "finalize"
          ? uint63FromBigInt(
              BigInt(quota.byteCount) + BigInt(reservation.reservationByteCount),
            )
          : quota.byteCount,
      reservedOperationCount: uint63FromBigInt(
        BigInt(quota.reservedOperationCount) -
          BigInt(reservation.reservationOperationCount),
      ),
      reservedByteCount: uint63FromBigInt(
        BigInt(quota.reservedByteCount) -
          BigInt(reservation.reservationByteCount),
      ),
      rowVersion: uint63FromBigInt(BigInt(quota.rowVersion) + 1n),
    });
  });
  const terminalState = mode === "finalize" ? "consumed" : "released";
  const preparedFinalReservations: readonly ApplicationAppendQuotaCapacityReservation[] =
    reservations.map((reservation) =>
      Object.freeze({
        ...reservation,
        state: terminalState as "consumed" | "released",
      }),
    );
  const input = {
    currentQuotas: pending.postReservationQuotas,
    currentCapacityReservations: reservations,
    pendingPreparationDigest: pending.preparationDigest,
    fenceGeneration: pending.reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      pending.reservationFence.token,
    ),
    preparedFinalQuotas,
    preparedFinalReservations,
  };
  const conversion =
    mode === "finalize"
      ? validateLockedApplicationAppendQuotaFinalizationTransition(input)
      : validateLockedApplicationAppendQuotaReleaseTransition(input);
  return conversion.quotas;
}

export function buildFanoutEvidence(
  plan: ApplicationAppendFanoutPlan,
  envelope: StoredApplicationEnvelope,
): ApplicationAppendFanoutEvidence {
  const mailboxProjectionDigest = computeApplicationAppendMailboxProjectionDigest({
    plan,
    envelopeId: envelope.envelopeId,
  });
  const outboxProjectionDigest = computeApplicationAppendOutboxProjectionDigest({
    conversationId: envelope.conversationId,
    envelopeId: envelope.envelopeId,
    position: envelope.position,
    headHash: envelope.headHash,
  });
  return parseApplicationAppendFanoutEvidence(
    {
      profile: "application-append-fanout.v1",
      status: "committed",
      conversationId: envelope.conversationId,
      envelopeId: envelope.envelopeId,
      position: envelope.position,
      headHash: envelope.headHash,
      rosterHash: plan.rosterHash,
      planDigest: plan.planDigest,
      recipientCount: plan.recipientCount,
      mailboxProjectionDigest,
      outboxProjectionDigest,
      evidenceDigest: computeApplicationAppendFanoutEvidenceDigest({
        conversationId: envelope.conversationId,
        envelopeId: envelope.envelopeId,
        position: envelope.position,
        headHash: envelope.headHash,
        rosterHash: plan.rosterHash,
        planDigest: plan.planDigest,
        recipientCount: plan.recipientCount,
        mailboxProjectionDigest,
        outboxProjectionDigest,
      }),
    },
    {
      plan,
      envelopeId: envelope.envelopeId,
      headHash: envelope.headHash,
    },
  );
}

export function httpIdempotencyScopeKey(
  command: AtomicApplicationAppendCommand,
): string {
  const identity = command.semanticIdentity;
  return [
    command.realmId,
    identity.authenticatedSender.accountId,
    identity.authenticatedSender.installationId,
    "POST",
    "/v1/conversations/{conversationId}/envelopes",
    identity.conversationId,
    command.idempotencyKey,
  ].join("\u0000");
}

export function semanticEnvelopeKeyOf(
  realmId: string,
  conversationId: ConversationId,
  envelopeId: EnvelopeId,
): string {
  return `${realmId}\u0000${conversationId}\u0000${envelopeId}`;
}

export function policyExpectation(
  snapshot: LockedApplicationAppendSnapshot,
  verifiedAt: Rfc3339Millis,
) {
  const conversation = snapshot.conversation;
  const policy = snapshot.policyHead;
  return Object.freeze({
    realmId: parseDeliveryRealmId(conversation.realmId),
    conversationGeneration: conversation.generation,
    releaseTrustRootDigest: conversation.releaseTrustRootDigest,
    purpose: "append-authorization" as const,
    releaseProfileId: conversation.releaseProfileId,
    deliveryLimitsDigest: conversation.deliveryLimitsDigest,
    conversationId: conversation.conversationId,
    policyHeadId: policy.policyHeadId,
    policyHeadSequence: policy.policyHeadSequence,
    policyHeadHash: policy.policyHeadHash,
    deliveryLogPosition: policy.deliveryLogPosition,
    deliveryLogHeadHash: policy.deliveryLogHeadHash,
    evaluationLogPosition: conversation.lastPosition,
    evaluationLogHeadHash: conversation.currentLogHeadHash,
    epoch: policy.epoch,
    rosterVersion: policy.rosterVersion,
    confirmedTranscriptHash: policy.confirmedTranscriptHash,
    policyRevision: policy.policyRevision,
    mandatoryProposalCount: policy.mandatoryProposalCount,
    mandatoryProposalSetHash: policy.mandatoryProposalSetHash,
    authorizedSendGrantSetHash: policy.authorizedSendGrantSetHash,
    selectedSendGrantEvidenceDigest:
      policy.selectedSendGrantEvidenceDigest,
    selectedSendGrantInclusionEvidenceDigest:
      policy.selectedSendGrantInclusionEvidenceDigest,
    authorizedQuotaPolicyDigest: policy.authorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: policy.priorPolicyHeadSequence,
    priorPolicyHeadHash: policy.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId:
      policy.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      policy.priorPolicyWitnessEvidenceDigest,
    verifiedAt,
  });
}

export function parsePolicyEvidenceForSnapshot(
  value: unknown,
  snapshot: LockedApplicationAppendSnapshot,
): PolicyHeadProofEvidence {
  const verifiedAt = parseRfc3339Millis(ownDataValue(value, "verifiedAt"));
  return parsePolicyHeadProofEvidence(
    value,
    policyExpectation(snapshot, verifiedAt),
  );
}

export function ownDataValue(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${key} is unavailable on a data record.`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) {
    throw new TypeError(`${key} must be an own data property.`);
  }
  return descriptor.value;
}

export function commandTrustMatchesSnapshot(
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
): boolean {
  const conversation = snapshot.conversation;
  return (
    command.realmId === conversation.realmId &&
    command.releaseProfileId === conversation.releaseProfileId &&
    command.deliveryLimitsDigest === conversation.deliveryLimitsDigest &&
    command.releaseTrustRootDigest === conversation.releaseTrustRootDigest
  );
}
