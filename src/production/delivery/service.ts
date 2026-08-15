import {
  applicationEnvelopeSemanticallyEqual,
  enforceApplicationAppendDeliveryLimits,
  enforceStoredEnvelopeDeliveryLimits,
  parseApplicationAppendJson,
  parseApplicationEnvelopeSemanticIdentity,
  parseStoredEnvelope,
  type ApplicationEnvelopeSemanticIdentity,
  type StoredApplicationEnvelope,
} from "./envelopes";
import {
  canonicalLengthPrefixed,
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  sha256Bytes,
} from "./hashes";
import {
  computeIdempotencyRequestCommitment,
  parseIdempotencyKeyHeader,
  parseIdempotencyRequestCommitmentInput,
  type ParsedIdempotencyRequestCommitmentInput,
} from "./idempotency";
import {
  DELIVERY_LIMIT_KEYS,
  parseDeliveryLimits,
  type DeliveryLimits,
} from "./limits";
import {
  computeApplicationAppendFenceTokenHash,
  parseDurableApplicationAppendSignerFenceSignedResolution,
  parseApplicationAppendReservationFence,
  parseApplicationAppendSignerFenceResolution,
  parseApplicationAppendSignerFenceVerificationEvidence,
  parseDeliveryPortUnavailable,
  type ApplicationAppendReservationFence,
  type ApplicationAppendSignerFenceResolution,
  type ApplicationAppendSignerFenceSignedResolution,
  type ApplicationAppendSignerFenceVerificationEvidence,
  type AtomicApplicationAppendCommand,
  type DeliveryCheckpointSigningRequest,
  type DeliveryCheckpointSignatureVerificationRequest,
  type DeliveryInvocationContext,
  type DeliveryPortUnavailable,
  type PolicyHeadProofVerificationRequest,
  type ProductionDeliveryPorts,
} from "./ports";
import {
  bindApplicationAppendQuotaCapacityReservations,
  computeApplicationAppendFanoutEvidenceDigest,
  computeApplicationAppendFanoutPlanDigest,
  computeApplicationAppendMailboxProjectionDigest,
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendOutboxProjectionDigest,
  computeApplicationAppendPendingExpiresAt,
  computeApplicationAppendQuotaReservationSetDigest,
  computeApplicationAppendRecipientSetHash,
  computeDeliveryLimitsDigest,
  computeLockedApplicationAppendSnapshotDigest,
  deriveApplicationAppendFanoutPlan,
  evaluateLockedApplicationAppend,
  parseApplicationAppendExpectation,
  parseApplicationAppendFanoutEvidence,
  parseApplicationAppendFanoutPlan,
  parseApplicationAppendMlsRosterProjections,
  parseApplicationAppendQuotaCapacityReservations,
  parseApplicationAppendRecipientProjections,
  parseApplicationAppendRejectionReason,
  parseLockedApplicationAppendCommitProjection,
  parseLockedApplicationAppendSnapshot,
  parsePolicyHeadProofEvidence,
  refreshLockedApplicationAppendAuthorizationSnapshot,
  validateLockedApplicationAppendQuotaReservationTransition,
  validateLockedApplicationAppendStateTransition,
  type ApplicationAppendExpectation,
  type ApplicationAppendFanoutEvidence,
  type ApplicationAppendFanoutPlan,
  type ApplicationAppendMlsRosterProjection,
  type ApplicationAppendQuotaCapacityReservation,
  type ApplicationAppendQuotaCapacityDelta,
  type ApplicationAppendRecipientProjection,
  type ApplicationAppendRejectionReason,
  type LockedApplicationAppendCommitProjection,
  type LockedApplicationAppendSnapshot,
  type LockedQuotaCounter,
  type PolicyHeadProofEvidence,
} from "./state";
import {
  parseDeliveryRealmId,
  parseDeliveryCheckpointSignatureEvidence,
  type DeliveryRealmId,
  type DeliveryCheckpointSignatureEvidence,
} from "./sync";
import {
  API_V1_MEDIA_TYPE,
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  copyBytes,
  decodeFingerprint32,
  decodeHash32,
  expectExactRecord,
  parseCanonicalBase64Url,
  parseCanonicalBase64UrlBytes,
  parseConversationEtag,
  parseConversationId,
  parseCredentialId,
  parseEd25519Signature,
  parseEnvelopeContentType,
  parseEnvelopeId,
  parseEnvelopeSender,
  parseFingerprint32,
  parseHash32,
  parseIdempotencyKey,
  parsePositiveUint63String,
  parseReleaseProfileId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  uint63FromBigInt,
  type CanonicalBase64Url,
  type ConversationEtag,
  type ConversationId,
  type CredentialId,
  type Ed25519Signature,
  type EnvelopeId,
  type Fingerprint32,
  type Hash32,
  type IdempotencyKey,
  type InstallationEnvelopeSender,
  type ReleaseProfileId,
  type Rfc3339Millis,
  type SigningKeyId,
  type Uint63String,
} from "./valueObjects";

const encoder = new TextEncoder();
const MAX_APPLICATION_BYTES = 64 * 1024;
const MAX_PHASE_RETRIES = 64;

export const APPLICATION_APPEND_OPERATION_TIMEOUT_MILLISECONDS = 1_000;
export const APPLICATION_ENVELOPE_APPEND_ROUTE =
  "/v1/conversations/{conversationId}/envelopes" as const;
export const ATOMIC_APPLICATION_APPEND_COMMAND_DIGEST_DOMAIN =
  "jb-msg-atomic-application-append-command/v1" as const;
export const APPLICATION_ENVELOPE_SEMANTIC_DIGEST_DOMAIN =
  "jb-msg-application-envelope-semantic-identity/v1" as const;
export const APPLICATION_APPEND_WIRE_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-application-wire-inspection-evidence/v1" as const;
export const APPLICATION_APPEND_PREPARATION_DIGEST_DOMAIN =
  "jb-msg-application-append-preparation/v1" as const;
export const APPLICATION_APPEND_PENDING_INTENT_DIGEST_DOMAIN =
  "jb-msg-application-append-pending-intent/v1" as const;

const APPEND_REQUEST_KEYS = [
  "idempotencyKey",
  "authenticatedSender",
  "authenticatedCredentialId",
  "authenticatedCredentialFingerprint",
  "authenticatedCredentialRevocationVersion",
  "request",
] as const;

const LAB_ADAPTER_REJECTION_REASONS = [
  "conversation-not-found",
  "attachment-invalid",
  "delivery-limit-exceeded",
] as const;

type LabAdapterRejectionReason =
  (typeof LAB_ADAPTER_REJECTION_REASONS)[number];

export class DeliveryServiceValidationError extends Error {
  readonly code = "invalid_delivery_service_input";

  constructor(message: string) {
    super(message);
    this.name = "DeliveryServiceValidationError";
  }
}

export interface AppendApplicationEnvelopeRequest {
  readonly idempotencyKey: IdempotencyKey;
  readonly authenticatedSender: InstallationEnvelopeSender;
  readonly authenticatedCredentialId: CredentialId;
  readonly authenticatedCredentialFingerprint: Fingerprint32;
  readonly authenticatedCredentialRevocationVersion: Uint63String;
  readonly request: ParsedIdempotencyRequestCommitmentInput & {
    readonly ifMatch: ConversationEtag;
  };
  readonly semanticIdentity: ApplicationEnvelopeSemanticIdentity;
}

export interface ApplicationEnvelopeLogHeadReceipt {
  readonly position: Uint63String;
  readonly previousHeadHash: Hash32;
  readonly headHash: Hash32;
  readonly signingKeyId: SigningKeyId;
  readonly checkpointDigest: Hash32;
  readonly signature: Ed25519Signature;
}

export interface ApplicationEnvelopeReceipt {
  readonly envelopeId: EnvelopeId;
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly epoch: Uint63String;
  readonly rosterVersion: Uint63String;
  readonly sender: InstallationEnvelopeSender;
  readonly receivedAt: Rfc3339Millis;
  readonly logHead: ApplicationEnvelopeLogHeadReceipt;
}

export type ApplicationEnvelopeAppendResult =
  | {
      readonly status: "accepted";
      readonly receipt: ApplicationEnvelopeReceipt;
      readonly replay: "none" | "http" | "envelope";
    }
  | {
      readonly status: "rejected";
      readonly reasonCode:
        | ApplicationAppendRejectionReason
        | LabAdapterRejectionReason;
    }
  | {
      readonly status: "conflict";
      readonly reasonCode: "idempotency-conflict";
    }
  | DeliveryPortUnavailable;

export interface MlsApplicationWireInspectionEvidence {
  readonly profile: "mls-application-wire-inspection.v1";
  readonly releaseProfileId: ReleaseProfileId;
  readonly expectedGroupIdHash: Hash32;
  readonly expectedEpoch: Uint63String;
  readonly wireKind: "private-application";
  readonly contentType: typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;
  readonly envelopeSha256: Hash32;
  readonly inspectionStatus: "verified";
  readonly evidenceDigest: Hash32;
}

export interface UnsignedStoredApplicationEnvelope {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly envelopeId: EnvelopeId;
  readonly envelopeClass: "application";
  readonly contentType: typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;
  readonly envelopeBytes: CanonicalBase64Url;
  readonly envelopeSha256: Hash32;
  readonly epoch: Uint63String;
  readonly rosterVersion: Uint63String;
  readonly sender: InstallationEnvelopeSender;
  readonly receivedAt: Rfc3339Millis;
  readonly leafHash: Hash32;
  readonly previousHeadHash: Hash32;
  readonly headHash: Hash32;
  readonly logSigningKeyId: SigningKeyId;
  readonly logCheckpointDigest: Hash32;
}

export interface PendingApplicationAppendIntent {
  readonly profile: "application-append-pending-intent.v1";
  readonly admissionCommand: AtomicApplicationAppendCommand;
  readonly admissionCommandDigest: Hash32;
  readonly semanticIdentityDigest: Hash32;
  readonly expectedSnapshotDigest: Hash32;
  readonly persistedSnapshot: LockedApplicationAppendSnapshot;
  readonly expectedAuthorizationSnapshotDigest: Hash32;
  /** Current-head policy authorization overlay used by the pure evaluator. */
  readonly priorSnapshot: LockedApplicationAppendSnapshot;
  readonly expectation: ApplicationAppendExpectation;
  readonly attachmentByteLength: Uint63String;
  readonly admissionStartedAt: Rfc3339Millis;
  readonly pendingExpiresAt: Rfc3339Millis;
  readonly activeSigningKeyValidUntil: Rfc3339Millis;
  /** Live bearer secret. It is never copied into acceptance, receipts, or incidents. */
  readonly reservationFence: ApplicationAppendReservationFence;
  readonly mlsRosterProjections: readonly ApplicationAppendMlsRosterProjection[];
  readonly recipientProjections: readonly ApplicationAppendRecipientProjection[];
  readonly fanoutPlan: ApplicationAppendFanoutPlan;
  readonly commitProjection: LockedApplicationAppendCommitProjection;
  readonly postReservationQuotas: readonly LockedQuotaCounter[];
  readonly envelope: UnsignedStoredApplicationEnvelope;
  readonly wireInspectionEvidence: MlsApplicationWireInspectionEvidence;
  readonly policyHeadProofEvidence: PolicyHeadProofEvidence;
  readonly preparationDigest: Hash32;
  readonly intentDigest: Hash32;
}

export type PreparedApplicationAppend =
  | {
      readonly status: "ready";
      readonly pendingIntent: PendingApplicationAppendIntent;
    }
  | {
      readonly status: "rejected";
      readonly reasonCode: ApplicationAppendRejectionReason;
    }
  | DeliveryPortUnavailable;

export interface PersistedApplicationAppendAcceptance {
  readonly receipt: ApplicationEnvelopeReceipt;
  readonly replay: "none" | "http" | "envelope" | "blocked";
  readonly invocationCommandDigest: Hash32;
  readonly acceptedIntent: AcceptedApplicationAppendIntent;
  readonly envelope: StoredApplicationEnvelope;
  readonly signatureEvidence: DeliveryCheckpointSignatureEvidence;
  readonly signerFenceEvidence: ApplicationAppendSignerFenceVerificationEvidence;
  readonly fanoutEvidence: ApplicationAppendFanoutEvidence;
  readonly finalizedAt: Rfc3339Millis;
  /** Fresh DB observation time for this response, distinct from immutable finalize time. */
  readonly observedAt: Rfc3339Millis;
}

/** Durable accepted projection. The live fence token and mutable quota rows are absent. */
export interface AcceptedApplicationAppendIntent {
  readonly profile: "application-append-accepted-intent.v1";
  readonly admissionCommand: AtomicApplicationAppendCommand;
  readonly admissionCommandDigest: Hash32;
  readonly semanticIdentityDigest: Hash32;
  readonly priorSnapshot: LockedApplicationAppendSnapshot;
  readonly envelope: UnsignedStoredApplicationEnvelope;
  readonly wireInspectionEvidence: MlsApplicationWireInspectionEvidence;
  readonly policyHeadProofEvidence: PolicyHeadProofEvidence;
  readonly preparationDigest: Hash32;
  readonly intentDigest: Hash32;
  readonly admissionStartedAt: Rfc3339Millis;
  readonly pendingExpiresAt: Rfc3339Millis;
  readonly fenceGeneration: Uint63String;
  readonly fenceTokenHash: Hash32;
  readonly fanoutPlan: ApplicationAppendFanoutPlan;
  readonly quotaReservationSetDigest: Hash32;
  readonly signerFenceResolution: ApplicationAppendSignerFenceSignedResolution;
}

type ApplicationAppendPhaseResult =
  | {
      readonly status: "accepted";
      readonly acceptance: PersistedApplicationAppendAcceptance;
    }
  | {
      readonly status: "pending";
      readonly replay: "none" | "http" | "envelope";
      readonly invocationCommandDigest: Hash32;
      readonly pendingIntent: PendingApplicationAppendIntent;
      readonly reservedAt: Rfc3339Millis;
      readonly observedAt: Rfc3339Millis;
    }
  | {
      readonly status: "blocked-by-pending";
      readonly invocationCommandDigest: Hash32;
      readonly pendingIntent: PendingApplicationAppendIntent;
      readonly reservedAt: Rfc3339Millis;
      readonly observedAt: Rfc3339Millis;
    }
  | {
      readonly status: "miss";
      readonly invocationCommandDigest: Hash32;
      readonly lockedSnapshot: LockedApplicationAppendSnapshot;
      readonly snapshotDigest: Hash32;
      readonly previousHeadHash: Hash32;
      readonly attachmentByteLength: Uint63String;
      readonly observedAt: Rfc3339Millis;
    }
  | {
      readonly status: "retry";
      readonly reasonCode: "snapshot-changed";
    }
  | {
      readonly status: "retired";
      readonly invocationCommandDigest: Hash32;
      readonly pendingIntentDigest: Hash32;
      readonly retiredAt: Rfc3339Millis;
      readonly observedAt: Rfc3339Millis;
    }
  | Exclude<ApplicationEnvelopeAppendResult, { readonly status: "accepted" }>;

export interface ApplicationEnvelopeDeliveryService {
  appendApplicationEnvelope(
    value: unknown,
  ): Promise<ApplicationEnvelopeAppendResult>;
}

/**
 * Authenticated, archived release metadata supplied by composition code.
 * Conversation generation and MLS group identity remain authoritative locked
 * conversation state and are deliberately not configurable here.
 */
export interface ApplicationEnvelopeDeliveryTrustContext {
  readonly realmId: DeliveryRealmId;
  readonly releaseProfileId: ReleaseProfileId;
  readonly releaseTrustRootDigest: Hash32;
  readonly deliveryLimitsDigest: Hash32;
  readonly deliveryLimits: DeliveryLimits;
}

/**
 * Production-shaped orchestration only. No route, credential, signer, or
 * storage adapter is selected here. The in-memory adapter is fictional-data-
 * only and pre-G1; the production default remains unavailable.
 */
export function createApplicationEnvelopeDeliveryService(
  ports: ProductionDeliveryPorts,
  trustContextValue: unknown,
): ApplicationEnvelopeDeliveryService {
  const trustContext = parseApplicationEnvelopeDeliveryTrustContext(
    trustContextValue,
  );
  const deliveryLimits = trustContext.deliveryLimits;

  return Object.freeze({
    async appendApplicationEnvelope(
      value: unknown,
    ): Promise<ApplicationEnvelopeAppendResult> {
      let request: AppendApplicationEnvelopeRequest;
      try {
        request = parseAppendApplicationEnvelopeRequest(value);
      } catch (error) {
        if (error instanceof DeliveryServiceValidationError) throw error;
        throw invalid("Application envelope service request is invalid.");
      }
      const command = parseAtomicApplicationAppendCommand({
        realmId: trustContext.realmId,
        idempotencyKey: request.idempotencyKey,
        requestCommitment: computeIdempotencyRequestCommitment(request.request),
        semanticIdentity: request.semanticIdentity,
        authenticatedCredentialId: request.authenticatedCredentialId,
        authenticatedCredentialFingerprint:
          request.authenticatedCredentialFingerprint,
        authenticatedCredentialRevocationVersion:
          request.authenticatedCredentialRevocationVersion,
        releaseProfileId: trustContext.releaseProfileId,
        deliveryLimitsDigest: trustContext.deliveryLimitsDigest,
        releaseTrustRootDigest: trustContext.releaseTrustRootDigest,
        deliveryLimits,
      });
      const invocation = beginInvocation(ports);
      if ("status" in invocation) return invocation;

      try {
        for (let attempt = 0; attempt < MAX_PHASE_RETRIES; attempt += 1) {
          if (invocation.context.signal.aborted) return timeoutUnavailable();
          const preflightValue = await callBounded(
            () =>
              ports.applicationAppendPreflight.read(
                command,
                invocation.context,
              ),
            invocation,
          );
          if (preflightValue === TIMED_OUT) return timeoutUnavailable();
          if (preflightValue === PORT_FAILED) return malformedDependency();
          const preflight = parsePhaseResultFromPort(
            preflightValue,
            command,
            ports,
            invocation,
          );

          if (preflight.status === "accepted") {
            if (
              preflight.acceptance.replay === "blocked" ||
              !phaseTimestampIsCurrent(
                ports,
                preflight.acceptance.observedAt,
                invocation,
              )
            ) {
              return malformedDependency();
            }
            const verified = await verifyHistoricalAcceptance(
              ports,
              preflight.acceptance,
              invocation,
            );
            if (verified.status === "unavailable") return verified;
            return publicAcceptance(preflight.acceptance);
          }
          if (preflight.status === "pending") {
            if (!phaseTimestampIsCurrent(ports, preflight.observedAt, invocation)) {
              return malformedDependency();
            }
            const resumed = await resumePendingApplicationAppend(
              ports,
              command,
              preflight.pendingIntent,
              invocation,
              true,
            );
            if (resumed === PENDING_DRAINED) continue;
            return resumed;
          }
          if (preflight.status === "blocked-by-pending") {
            if (!phaseTimestampIsCurrent(ports, preflight.observedAt, invocation)) {
              return malformedDependency();
            }
            const drained = await resumePendingApplicationAppend(
              ports,
              command,
              preflight.pendingIntent,
              invocation,
              false,
            );
            if (drained === PENDING_DRAINED) continue;
            return drained;
          }
          if (preflight.status === "retry") {
            await Promise.resolve();
            continue;
          }
          if (preflight.status !== "miss") return malformedDependency();
          const preflightCompletedAt = readClockNow(ports);
          if (isUnavailable(preflightCompletedAt)) return preflightCompletedAt;
          if (
            !timestampWasObservedDuringInvocation(
              preflight.observedAt,
              preflightCompletedAt,
              invocation,
            )
          ) {
            reportInvariantIncident(
              ports,
              command,
              invocation,
              "atomic-persistence-ambiguity",
            );
            return malformedDependency();
          }

          try {
            enforceApplicationAppendDeliveryLimits(
              command.semanticIdentity.append,
              command.deliveryLimits,
            );
          } catch {
            return rejected("delivery-limit-exceeded");
          }

          const snapshot = preflight.lockedSnapshot;
          const expectedLimitsDigest = computeDeliveryLimitsDigest(
            command.deliveryLimits,
          );
          if (
            snapshot.conversation.realmId !== command.realmId ||
            snapshot.conversation.releaseProfileId !== command.releaseProfileId ||
            snapshot.conversation.deliveryLimitsDigest !== expectedLimitsDigest ||
            snapshot.conversation.releaseTrustRootDigest !==
              command.releaseTrustRootDigest
          ) {
            return rejected("conversation-state-changed");
          }
          const [wire, policy] = await Promise.all([
            inspectApplicationWire(
              ports,
              command,
              snapshot,
              invocation,
            ),
            verifyPolicyHead(
              ports,
              snapshot,
              preflight.observedAt,
              invocation,
            ),
          ]);
          if (isUnavailable(wire)) return wire;
          if (isUnavailable(policy)) return policy;
          let authorizationSnapshot: LockedApplicationAppendSnapshot;
          try {
            authorizationSnapshot =
              refreshLockedApplicationAppendAuthorizationSnapshot({
                persistedSnapshot: snapshot,
                policyHeadProofEvidence: policy,
              });
          } catch {
            reportInvariantIncident(
              ports,
              command,
              invocation,
              "atomic-persistence-ambiguity",
            );
            return malformedDependency();
          }
          const expectedAuthorizationSnapshotDigest =
            computeLockedApplicationAppendSnapshotDigest(
              authorizationSnapshot,
            );
          const expectation = buildApplicationAppendExpectation(
            command,
            authorizationSnapshot,
            preflight.attachmentByteLength,
          );
          const preflightDecision = evaluateLockedApplicationAppend(
            authorizationSnapshot,
            expectation,
            preflight.observedAt,
          );
          if (preflightDecision.status === "rejected") {
            return preflightDecision;
          }

          const reservationValue = await callBounded(
            () =>
              ports.atomicPersistence.reserveApplicationAppendAtomically(
                {
                  command,
                  admissionStartedAt: invocation.startedAt,
                  expectedSnapshotDigest: preflight.snapshotDigest,
                  expectedAuthorizationSnapshotDigest,
                  wireInspectionEvidence: Object.freeze({
                    status: "verified" as const,
                    ...wire,
                  }),
                  policyHeadProofEvidence: Object.freeze({
                    status: "verified" as const,
                    ...policy,
                  }),
                },
                (context) =>
                  prepareUnsignedApplicationAppend(
                    command,
                    preflight.snapshotDigest,
                    expectedAuthorizationSnapshotDigest,
                    snapshot,
                    wire,
                    policy,
                    ports,
                    invocation,
                    context,
                  ),
                invocation.context,
              ),
            invocation,
          );
          if (reservationValue === TIMED_OUT) return timeoutUnavailable();
          if (reservationValue === PORT_FAILED) return malformedDependency();
          const reservation = parsePhaseResultFromPort(
            reservationValue,
            command,
            ports,
            invocation,
          );
          if (reservation.status === "accepted") {
            if (
              reservation.acceptance.replay === "blocked" ||
              !phaseTimestampIsCurrent(
                ports,
                reservation.acceptance.observedAt,
                invocation,
              )
            ) {
              return malformedDependency();
            }
            const verified = await verifyHistoricalAcceptance(
              ports,
              reservation.acceptance,
              invocation,
            );
            if (verified.status === "unavailable") return verified;
            return publicAcceptance(reservation.acceptance);
          }
          if (reservation.status === "pending") {
            if (!phaseTimestampIsCurrent(ports, reservation.observedAt, invocation)) {
              return malformedDependency();
            }
            const resumed = await resumePendingApplicationAppend(
              ports,
              command,
              reservation.pendingIntent,
              invocation,
              true,
            );
            if (resumed === PENDING_DRAINED) continue;
            return resumed;
          }
          if (reservation.status === "blocked-by-pending") {
            if (!phaseTimestampIsCurrent(ports, reservation.observedAt, invocation)) {
              return malformedDependency();
            }
            const drained = await resumePendingApplicationAppend(
              ports,
              command,
              reservation.pendingIntent,
              invocation,
              false,
            );
            if (drained === PENDING_DRAINED) continue;
            return drained;
          }
          if (reservation.status === "retry") {
            await Promise.resolve();
            continue;
          }
          if (
            reservation.status === "miss"
          ) {
            throw invalid("Atomic reservation returned a preflight-only miss.");
          }
          return malformedDependency();
        }
        return timeoutUnavailable();
      } finally {
        invocation.dispose();
      }
    },
  });
}

export function parseApplicationEnvelopeDeliveryTrustContext(
  value: unknown,
): ApplicationEnvelopeDeliveryTrustContext {
  const record = expectExactRecord(
    value,
    [
      "realmId",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "deliveryLimitsDigest",
      "deliveryLimits",
    ],
    "application envelope delivery trust context",
  );
  const limits = parseDeliveryLimits(record.deliveryLimits);
  const deliveryLimitsDigest = parseHash32(record.deliveryLimitsDigest);
  if (deliveryLimitsDigest !== computeDeliveryLimitsDigest(limits)) {
    throw invalid("Delivery trust context limits digest is inconsistent.");
  }
  return Object.freeze({
    realmId: parseDeliveryRealmId(record.realmId),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    releaseTrustRootDigest: parseHash32(record.releaseTrustRootDigest),
    deliveryLimitsDigest,
    deliveryLimits: limits,
  });
}

export function parseAppendApplicationEnvelopeRequest(
  value: unknown,
): AppendApplicationEnvelopeRequest {
  const record = expectExactRecord(
    value,
    APPEND_REQUEST_KEYS,
    "application envelope service request",
  );
  const request = parseIdempotencyRequestCommitmentInput(record.request);
  if (
    request.method !== "POST" ||
    request.routeTemplate !== APPLICATION_ENVELOPE_APPEND_ROUTE ||
    request.mediaType !== API_V1_MEDIA_TYPE ||
    request.ifMatch === ""
  ) {
    throw invalid(
      "Application envelopes require the exact POST route, media type, and non-empty If-Match.",
    );
  }
  const conversationId = parseConversationId(request.resourceId);
  const sender = parseEnvelopeSender(
    record.authenticatedSender,
    "authenticatedSender",
  );
  if (sender.type !== "installation") {
    throw invalid("Application envelopes require an installation sender.");
  }
  const parsedAppend = parseApplicationAppendJson(request.rawBodyBytes);
  const ifMatch = parseConversationEtag(request.ifMatch, "request.ifMatch");
  const semanticIdentity = parseApplicationEnvelopeSemanticIdentity({
    conversationId,
    ifMatch,
    authenticatedSender: sender,
    append: parsedAppend.body,
  });
  return Object.freeze({
    idempotencyKey: parseIdempotencyKeyHeader(record.idempotencyKey),
    authenticatedSender: sender,
    authenticatedCredentialId: parseCredentialId(
      record.authenticatedCredentialId,
      "authenticatedCredentialId",
    ),
    authenticatedCredentialFingerprint: parseFingerprint32(
      record.authenticatedCredentialFingerprint,
      "authenticatedCredentialFingerprint",
    ),
    authenticatedCredentialRevocationVersion: parsePositiveUint63String(
      record.authenticatedCredentialRevocationVersion,
      "authenticatedCredentialRevocationVersion",
    ),
    request: Object.freeze({ ...request, ifMatch }),
    semanticIdentity,
  });
}

export function parseAtomicApplicationAppendCommand(
  value: unknown,
): AtomicApplicationAppendCommand {
  const record = expectExactRecord(
    value,
    [
      "realmId",
      "idempotencyKey",
      "requestCommitment",
      "semanticIdentity",
      "authenticatedCredentialId",
      "authenticatedCredentialFingerprint",
      "authenticatedCredentialRevocationVersion",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "releaseTrustRootDigest",
      "deliveryLimits",
    ],
    "atomic application append command",
  );
  const deliveryLimits = parseDeliveryLimits(record.deliveryLimits);
  const deliveryLimitsDigest = parseHash32(record.deliveryLimitsDigest);
  if (deliveryLimitsDigest !== computeDeliveryLimitsDigest(deliveryLimits)) {
    throw invalid("Atomic command delivery limits digest is inconsistent.");
  }
  return Object.freeze({
    realmId: parseDeliveryRealmId(record.realmId),
    idempotencyKey: parseIdempotencyKey(record.idempotencyKey),
    requestCommitment: parseHash32(record.requestCommitment),
    semanticIdentity: parseApplicationEnvelopeSemanticIdentity(
      record.semanticIdentity,
    ),
    authenticatedCredentialId: parseCredentialId(
      record.authenticatedCredentialId,
    ),
    authenticatedCredentialFingerprint: parseFingerprint32(
      record.authenticatedCredentialFingerprint,
    ),
    authenticatedCredentialRevocationVersion: parsePositiveUint63String(
      record.authenticatedCredentialRevocationVersion,
      "authenticated credential revocation version",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest,
    releaseTrustRootDigest: parseHash32(record.releaseTrustRootDigest),
    deliveryLimits,
  });
}

/**
 * Correlates an unknown persistence result with every current invocation fact.
 * This function intentionally performs no current admission check: historical
 * replay lookup must happen before limits can reject a request.
 */
export function computeAtomicApplicationAppendCommandDigest(
  value: unknown,
): Hash32 {
  const command = parseAtomicApplicationAppendCommand(value);
  return sha256Bytes(
    utf8(ATOMIC_APPLICATION_APPEND_COMMAND_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(command.realmId),
      utf8(command.idempotencyKey),
      decodeHash32(command.requestCommitment),
      decodeHash32(
        computeApplicationEnvelopeSemanticIdentityDigest(
          command.semanticIdentity,
        ),
      ),
      utf8(command.authenticatedCredentialId),
      decodeFingerprint32(command.authenticatedCredentialFingerprint),
      utf8(command.authenticatedCredentialRevocationVersion),
      utf8(command.releaseProfileId),
      decodeHash32(command.deliveryLimitsDigest),
      decodeHash32(command.releaseTrustRootDigest),
      canonicalLengthPrefixed(
        ...DELIVERY_LIMIT_KEYS.flatMap((key) => [
          utf8(key),
          utf8(command.deliveryLimits[key]),
        ]),
      ),
    ),
  );
}

export function computeApplicationEnvelopeSemanticIdentityDigest(
  value: unknown,
): Hash32 {
  const identity = parseApplicationEnvelopeSemanticIdentity(value);
  const append = identity.append;
  return sha256Bytes(
    utf8(APPLICATION_ENVELOPE_SEMANTIC_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(identity.conversationId),
      utf8(identity.ifMatch),
      utf8(identity.authenticatedSender.type),
      utf8(identity.authenticatedSender.accountId),
      utf8(identity.authenticatedSender.installationId),
      utf8(append.envelopeId),
      utf8(append.policyHeadId),
      utf8(append.policyHeadSequence),
      decodeHash32(append.policyHeadHash),
      utf8(append.expectedEpoch),
      utf8(append.expectedRosterVersion),
      decodeHash32(append.expectedConfirmedTranscriptHash),
      utf8(append.contentType),
      parseCanonicalBase64UrlBytes(append.ciphertext, "ciphertext", {
        minBytes: 1,
        maxBytes: MAX_APPLICATION_BYTES,
      }),
      decodeHash32(append.envelopeSha256),
      canonicalLengthPrefixed(
        utf8(append.attachmentIds.length.toString(10)),
        ...append.attachmentIds.map((attachmentId) => utf8(attachmentId)),
      ),
    ),
  );
}

function buildApplicationAppendExpectation(
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
  attachmentByteLength: Uint63String,
): ApplicationAppendExpectation {
  const identity = command.semanticIdentity;
  const append = identity.append;
  const envelopeBytes = parseCanonicalBase64UrlBytes(
    append.ciphertext,
    "ciphertext",
    { minBytes: 1, maxBytes: MAX_APPLICATION_BYTES },
  );
  return parseApplicationAppendExpectation({
    realmId: command.realmId,
    conversationId: identity.conversationId,
    accountId: identity.authenticatedSender.accountId,
    installationId: identity.authenticatedSender.installationId,
    credentialId: command.authenticatedCredentialId,
    credentialFingerprint: command.authenticatedCredentialFingerprint,
    credentialRevocationVersion:
      command.authenticatedCredentialRevocationVersion,
    releaseProfileId: command.releaseProfileId,
    expectedDeliveryLimitsDigest: computeDeliveryLimitsDigest(
      command.deliveryLimits,
    ),
    expectedQuotaPolicyDigest: snapshot.conversation.quotaPolicyDigest,
    expectedProjectScopeId: snapshot.conversation.projectScopeId,
    expectedTenantScopeId: snapshot.conversation.tenantScopeId,
    expectedGroupIdHash: snapshot.conversation.groupIdHash,
    ifMatch: identity.ifMatch,
    expectedEpoch: append.expectedEpoch,
    expectedRosterVersion: append.expectedRosterVersion,
    expectedConfirmedTranscriptHash: append.expectedConfirmedTranscriptHash,
    policyHeadId: append.policyHeadId,
    policyHeadSequence: append.policyHeadSequence,
    policyHeadHash: append.policyHeadHash,
    policyEvaluationLogPosition: snapshot.conversation.lastPosition,
    policyEvaluationLogHeadHash: snapshot.conversation.currentLogHeadHash,
    envelopeByteLength: uint63FromBigInt(BigInt(envelopeBytes.byteLength)),
    attachmentByteLength,
  });
}

function prepareUnsignedApplicationAppend(
  command: AtomicApplicationAppendCommand,
  expectedSnapshotDigest: Hash32,
  expectedAuthorizationSnapshotDigest: Hash32,
  persistedSnapshot: LockedApplicationAppendSnapshot,
  wireInspectionEvidence: MlsApplicationWireInspectionEvidence,
  policyHeadProofEvidence: PolicyHeadProofEvidence,
  ports: ProductionDeliveryPorts,
  invocation: ActiveInvocation,
  contextValue: {
    readonly lockedSnapshot: unknown;
    readonly authoritativeReceivedAt: unknown;
    readonly previousHeadHash: unknown;
    readonly attachmentByteLength: unknown;
    readonly activeSigningKeyId: unknown;
    readonly activeSigningKeyValidUntil: unknown;
    readonly reservationFence: unknown;
    readonly mlsRosterProjections: unknown;
    readonly recipientProjections: unknown;
    readonly transactionDeadline: unknown;
  },
): PreparedApplicationAppend {
  const snapshot = parseLockedApplicationAppendSnapshot(
    contextValue.lockedSnapshot,
  );
  const receivedAt = parseRfc3339Millis(
    contextValue.authoritativeReceivedAt,
    "authoritativeReceivedAt",
  );
  const previousHeadHash = parseHash32(
    contextValue.previousHeadHash,
    "previousHeadHash",
  );
  const attachmentByteLength = parseUint63String(
    contextValue.attachmentByteLength,
    "attachmentByteLength",
  );
  const activeSigningKeyId = parseSigningKeyId(
    contextValue.activeSigningKeyId,
    "activeSigningKeyId",
  );
  const activeSigningKeyValidUntil = parseRfc3339Millis(
    contextValue.activeSigningKeyValidUntil,
    "activeSigningKeyValidUntil",
  );
  const reservationFence = parseApplicationAppendReservationFence(
    contextValue.reservationFence,
  );
  const mlsRosterProjections = parseApplicationAppendMlsRosterProjections(
    contextValue.mlsRosterProjections,
    command.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const recipientProjections = parseApplicationAppendRecipientProjections(
    contextValue.recipientProjections,
    command.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const transactionDeadline = parseRfc3339Millis(
    contextValue.transactionDeadline,
    "transactionDeadline",
  );
  const reservationCompletedAt = readClockNow(ports);
  if (isUnavailable(reservationCompletedAt)) return reservationCompletedAt;
  if (
    !timestampWasObservedDuringInvocation(
      receivedAt,
      reservationCompletedAt,
      invocation,
    ) ||
    transactionDeadline <= receivedAt ||
    transactionDeadline > invocation.context.deadline
  ) {
    return malformedDependency();
  }
  if (
    computeLockedApplicationAppendSnapshotDigest(snapshot) !==
      expectedAuthorizationSnapshotDigest ||
    computeLockedApplicationAppendSnapshotDigest(persistedSnapshot) !==
      expectedSnapshotDigest ||
    snapshot.conversation.currentLogHeadHash !== previousHeadHash
  ) {
    return Object.freeze({
      status: "rejected",
      reasonCode: "conversation-state-changed",
    });
  }
  try {
    enforceApplicationAppendDeliveryLimits(
      command.semanticIdentity.append,
      command.deliveryLimits,
    );
  } catch {
    return Object.freeze({
      status: "rejected",
      reasonCode: "conversation-state-changed",
    });
  }
  const expectation = buildApplicationAppendExpectation(
    command,
    snapshot,
    attachmentByteLength,
  );
  const decision = evaluateLockedApplicationAppend(
    snapshot,
    expectation,
    receivedAt,
  );
  if (decision.status === "rejected") return Object.freeze(decision);

  assertWireEvidenceMatches(
    wireInspectionEvidence,
    command,
    snapshot,
  );
  assertPolicyEvidenceMatches(
    policyHeadProofEvidence,
    snapshot,
  );
  if (policyHeadProofEvidence.verifiedAt > receivedAt) {
    throw invalid("Policy proof was verified after the reservation timestamp.");
  }

  const identity = command.semanticIdentity;
  const append = identity.append;
  const leafHash = computeEnvelopeLeafHash({
    conversationId: identity.conversationId,
    position: decision.nextPosition,
    envelopeId: append.envelopeId,
    envelopeClass: "application",
    sender: identity.authenticatedSender,
    epoch: snapshot.conversation.epoch,
    rosterVersion: snapshot.conversation.rosterVersion,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    envelopeSha256: append.envelopeSha256,
    receivedAt,
  });
  const headHash = computeLogHeadHash(previousHeadHash, leafHash);
  const checkpointDigest = computeDeliveryLogCheckpointDigest({
    conversationId: identity.conversationId,
    position: decision.nextPosition,
    previousHeadHash,
    headHash,
    signingKeyId: activeSigningKeyId,
  });
  const envelope = parseUnsignedStoredApplicationEnvelope({
    conversationId: identity.conversationId,
    position: decision.nextPosition,
    envelopeId: append.envelopeId,
    envelopeClass: "application",
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    envelopeBytes: append.ciphertext,
    envelopeSha256: append.envelopeSha256,
    epoch: snapshot.conversation.epoch,
    rosterVersion: snapshot.conversation.rosterVersion,
    sender: identity.authenticatedSender,
    receivedAt,
    leafHash,
    previousHeadHash,
    headHash,
    logSigningKeyId: activeSigningKeyId,
    logCheckpointDigest: checkpointDigest,
  });
  let pendingExpiresAt: Rfc3339Millis;
  let fanoutPlan: ApplicationAppendFanoutPlan;
  try {
    pendingExpiresAt = computeApplicationAppendPendingExpiresAt({
      snapshot,
      admissionStartedAt: invocation.startedAt,
      authoritativeReceivedAt: receivedAt,
      activeSigningKeyValidUntil,
    });
    fanoutPlan = deriveApplicationAppendFanoutPlan({
      conversation: snapshot.conversation,
      senderMembership: snapshot.membership,
      position: decision.nextPosition,
      authoritativeReceivedAt: receivedAt,
      recipientInstallationsMax:
        command.deliveryLimits.conversationRecipientInstallationsMax,
      mlsRosterProjections,
      recipientProjections,
    });
  } catch {
    return malformedDependency();
  }
  const preparationDigest = computeApplicationAppendPreparationDigest({
    admissionCommandDigest: computeAtomicApplicationAppendCommandDigest(command),
    semanticIdentityDigest: computeApplicationEnvelopeSemanticIdentityDigest(
      command.semanticIdentity,
    ),
    expectedSnapshotDigest,
    expectedAuthorizationSnapshotDigest,
    admissionStartedAt: invocation.startedAt,
    pendingExpiresAt,
    activeSigningKeyValidUntil,
    fenceGeneration: reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      reservationFence.token,
    ),
    attachmentByteLength,
    envelope,
    wireEvidenceDigest: wireInspectionEvidence.evidenceDigest,
    policyEvidenceDigest: policyHeadProofEvidence.evidenceDigest,
    fanoutPlanDigest: fanoutPlan.planDigest,
    quotaCapacityDeltas: decision.quotaCapacityDeltas,
    postReservationQuotas: decision.postReservationQuotas,
  });
  const quotaCapacityReservations =
    bindApplicationAppendQuotaCapacityReservations({
      deltas: decision.quotaCapacityDeltas,
      pendingPreparationDigest: preparationDigest,
      fenceGeneration: reservationFence.generation,
      fenceTokenHash: computeApplicationAppendFenceTokenHash(
        reservationFence.token,
      ),
    });
  const commitProjection = validateLockedApplicationAppendStateTransition({
    priorSnapshot: snapshot,
    expectation,
    authoritativeReceivedAt: receivedAt,
    nextHeadHash: headHash,
    preparedNextConversation: {
      ...snapshot.conversation,
      lastPosition: decision.nextPosition,
      currentLogHeadHash: headHash,
    },
    preparedNextUsage: decision.nextUsage,
    quotaCapacityReservations,
  });
  const postReservationQuotas =
    validateLockedApplicationAppendQuotaReservationTransition({
      priorSnapshot: snapshot,
      expectation,
      authoritativeReceivedAt: receivedAt,
      quotaCapacityReservations,
      preparedPostReservationQuotas: decision.postReservationQuotas,
    });
  return Object.freeze({
    status: "ready",
    pendingIntent: parsePendingApplicationAppendIntent(
      createPendingIntentValue({
        command,
        expectedSnapshotDigest,
        persistedSnapshot,
        expectedAuthorizationSnapshotDigest,
        priorSnapshot: snapshot,
        expectation,
        attachmentByteLength,
        admissionStartedAt: invocation.startedAt,
        pendingExpiresAt,
        activeSigningKeyValidUntil,
        reservationFence,
        mlsRosterProjections,
        recipientProjections,
        fanoutPlan,
        commitProjection,
        postReservationQuotas,
        envelope,
        wireInspectionEvidence,
        policyHeadProofEvidence,
        preparationDigest,
      }),
    ),
  });
}

function createPendingIntentValue(input: {
  readonly command: AtomicApplicationAppendCommand;
  readonly expectedSnapshotDigest: Hash32;
  readonly persistedSnapshot: LockedApplicationAppendSnapshot;
  readonly expectedAuthorizationSnapshotDigest: Hash32;
  readonly priorSnapshot: LockedApplicationAppendSnapshot;
  readonly expectation: ApplicationAppendExpectation;
  readonly attachmentByteLength: Uint63String;
  readonly admissionStartedAt: Rfc3339Millis;
  readonly pendingExpiresAt: Rfc3339Millis;
  readonly activeSigningKeyValidUntil: Rfc3339Millis;
  readonly reservationFence: ApplicationAppendReservationFence;
  readonly mlsRosterProjections: readonly ApplicationAppendMlsRosterProjection[];
  readonly recipientProjections: readonly ApplicationAppendRecipientProjection[];
  readonly fanoutPlan: ApplicationAppendFanoutPlan;
  readonly commitProjection: LockedApplicationAppendCommitProjection;
  readonly postReservationQuotas: readonly LockedQuotaCounter[];
  readonly envelope: UnsignedStoredApplicationEnvelope;
  readonly wireInspectionEvidence: MlsApplicationWireInspectionEvidence;
  readonly policyHeadProofEvidence: PolicyHeadProofEvidence;
  readonly preparationDigest: Hash32;
}) {
  const admissionCommandDigest =
    computeAtomicApplicationAppendCommandDigest(input.command);
  const semanticIdentityDigest =
    computeApplicationEnvelopeSemanticIdentityDigest(
      input.command.semanticIdentity,
    );
  const preparationDigest = parseHash32(input.preparationDigest);
  const quotaReservationSetDigest =
    computeApplicationAppendQuotaReservationSetDigest(
      input.commitProjection.quotaCapacityReservations,
    );
  const intentDigest = sha256Bytes(
    utf8(APPLICATION_APPEND_PENDING_INTENT_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      decodeHash32(admissionCommandDigest),
      decodeHash32(semanticIdentityDigest),
      decodeHash32(preparationDigest),
      decodeHash32(quotaReservationSetDigest),
      decodeHash32(input.fanoutPlan.planDigest),
      utf8(input.reservationFence.generation),
      decodeHash32(
        computeApplicationAppendFenceTokenHash(input.reservationFence.token),
      ),
      utf8(input.pendingExpiresAt),
    ),
  );
  return {
    profile: "application-append-pending-intent.v1",
    admissionCommand: input.command,
    admissionCommandDigest,
    semanticIdentityDigest,
    expectedSnapshotDigest: input.expectedSnapshotDigest,
    persistedSnapshot: input.persistedSnapshot,
    expectedAuthorizationSnapshotDigest:
      input.expectedAuthorizationSnapshotDigest,
    priorSnapshot: input.priorSnapshot,
    expectation: input.expectation,
    attachmentByteLength: input.attachmentByteLength,
    admissionStartedAt: input.admissionStartedAt,
    pendingExpiresAt: input.pendingExpiresAt,
    activeSigningKeyValidUntil: input.activeSigningKeyValidUntil,
    reservationFence: input.reservationFence,
    mlsRosterProjections: input.mlsRosterProjections,
    recipientProjections: input.recipientProjections,
    fanoutPlan: input.fanoutPlan,
    commitProjection: input.commitProjection,
    postReservationQuotas: input.postReservationQuotas,
    envelope: input.envelope,
    wireInspectionEvidence: input.wireInspectionEvidence,
    policyHeadProofEvidence: input.policyHeadProofEvidence,
    preparationDigest,
    intentDigest,
  };
}

export function parsePendingApplicationAppendIntent(
  value: unknown,
): PendingApplicationAppendIntent {
  const record = expectExactRecord(
    value,
    [
      "profile",
      "admissionCommand",
      "admissionCommandDigest",
      "semanticIdentityDigest",
      "expectedSnapshotDigest",
      "persistedSnapshot",
      "expectedAuthorizationSnapshotDigest",
      "priorSnapshot",
      "expectation",
      "attachmentByteLength",
      "admissionStartedAt",
      "pendingExpiresAt",
      "activeSigningKeyValidUntil",
      "reservationFence",
      "mlsRosterProjections",
      "recipientProjections",
      "fanoutPlan",
      "commitProjection",
      "postReservationQuotas",
      "envelope",
      "wireInspectionEvidence",
      "policyHeadProofEvidence",
      "preparationDigest",
      "intentDigest",
    ],
    "pending application append intent",
  );
  if (record.profile !== "application-append-pending-intent.v1") {
    throw invalid("Pending application append profile is unsupported.");
  }
  const admissionCommand = parseAtomicApplicationAppendCommand(
    record.admissionCommand,
  );
  const admissionCommandDigest = parseHash32(
    record.admissionCommandDigest,
    "pending admission command digest",
  );
  if (
    admissionCommandDigest !==
    computeAtomicApplicationAppendCommandDigest(admissionCommand)
  ) {
    throw invalid("Pending admission command digest is inconsistent.");
  }
  const semanticIdentityDigest = parseHash32(
    record.semanticIdentityDigest,
    "pending semantic identity digest",
  );
  if (
    semanticIdentityDigest !==
    computeApplicationEnvelopeSemanticIdentityDigest(
      admissionCommand.semanticIdentity,
    )
  ) {
    throw invalid("Pending semantic identity digest is inconsistent.");
  }
  const persistedSnapshot = parseLockedApplicationAppendSnapshot(
    record.persistedSnapshot,
  );
  const expectedSnapshotDigest = parseHash32(
    record.expectedSnapshotDigest,
    "pending snapshot digest",
  );
  if (
    expectedSnapshotDigest !==
    computeLockedApplicationAppendSnapshotDigest(persistedSnapshot)
  ) {
    throw invalid("Pending snapshot digest is inconsistent.");
  }
  const priorSnapshot = parseLockedApplicationAppendSnapshot(
    record.priorSnapshot,
  );
  const expectedAuthorizationSnapshotDigest = parseHash32(
    record.expectedAuthorizationSnapshotDigest,
    "pending authorization snapshot digest",
  );
  if (
    expectedAuthorizationSnapshotDigest !==
    computeLockedApplicationAppendSnapshotDigest(priorSnapshot)
  ) {
    throw invalid("Pending authorization snapshot digest is inconsistent.");
  }
  const expectation = parseApplicationAppendExpectation(record.expectation);
  const attachmentByteLength = parseUint63String(
    record.attachmentByteLength,
    "pending attachment byte length",
  );
  const envelope = parseUnsignedStoredApplicationEnvelope(record.envelope);
  const admissionStartedAt = parseRfc3339Millis(record.admissionStartedAt);
  const pendingExpiresAt = parseRfc3339Millis(record.pendingExpiresAt);
  const activeSigningKeyValidUntil = parseRfc3339Millis(
    record.activeSigningKeyValidUntil,
  );
  const reservationFence = parseApplicationAppendReservationFence(
    record.reservationFence,
  );
  const mlsRosterProjections = parseApplicationAppendMlsRosterProjections(
    record.mlsRosterProjections,
    admissionCommand.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const recipientProjections = parseApplicationAppendRecipientProjections(
    record.recipientProjections,
    admissionCommand.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const fanoutPlan = parseApplicationAppendFanoutPlan(
    record.fanoutPlan,
    admissionCommand.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const commitProjection = parseLockedApplicationAppendCommitProjection(
    record.commitProjection,
  );
  const wireInspectionEvidence = parseMlsApplicationWireInspectionEvidence(
    record.wireInspectionEvidence,
  );
  const policyHeadProofEvidence = parseStoredPolicyEvidence(
    record.policyHeadProofEvidence,
    persistedSnapshot,
  );
  const reconstructedAuthorizationSnapshot =
    refreshLockedApplicationAppendAuthorizationSnapshot({
      persistedSnapshot,
      policyHeadProofEvidence,
    });
  if (!sameData(priorSnapshot, reconstructedAuthorizationSnapshot)) {
    throw invalid("Pending authorization snapshot overlay was substituted.");
  }

  try {
    enforceApplicationAppendDeliveryLimits(
      admissionCommand.semanticIdentity.append,
      admissionCommand.deliveryLimits,
    );
  } catch {
    throw invalid("Pending intent violates its historical admission limits.");
  }
  if (
    priorSnapshot.conversation.realmId !== admissionCommand.realmId ||
    priorSnapshot.conversation.releaseProfileId !==
      admissionCommand.releaseProfileId ||
    priorSnapshot.conversation.deliveryLimitsDigest !==
      admissionCommand.deliveryLimitsDigest ||
    priorSnapshot.conversation.releaseTrustRootDigest !==
      admissionCommand.releaseTrustRootDigest
  ) {
    throw invalid("Pending intent is detached from its generation profile.");
  }
  assertWireEvidenceMatches(
    wireInspectionEvidence,
    admissionCommand,
    priorSnapshot,
  );
  assertPolicyEvidenceMatches(policyHeadProofEvidence, priorSnapshot);
  requireUnsignedEnvelopeMatchesCommand(
    envelope,
    admissionCommand,
    priorSnapshot,
  );
  const expectedExpectation = buildApplicationAppendExpectation(
    admissionCommand,
    priorSnapshot,
    attachmentByteLength,
  );
  if (!sameData(expectation, expectedExpectation)) {
    throw invalid("Pending append expectation was substituted.");
  }
  if (
    pendingExpiresAt !== computeApplicationAppendPendingExpiresAt({
      snapshot: priorSnapshot,
      admissionStartedAt,
      authoritativeReceivedAt: envelope.receivedAt,
      activeSigningKeyValidUntil,
    }) ||
    !sameData(
      fanoutPlan,
      deriveApplicationAppendFanoutPlan({
        conversation: priorSnapshot.conversation,
        senderMembership: priorSnapshot.membership,
        position: envelope.position,
        authoritativeReceivedAt: envelope.receivedAt,
        recipientInstallationsMax:
          admissionCommand.deliveryLimits.conversationRecipientInstallationsMax,
        mlsRosterProjections,
        recipientProjections,
      }),
    )
  ) {
    throw invalid("Pending expiry or fanout plan was substituted.");
  }
  const decision = evaluateLockedApplicationAppend(
    priorSnapshot,
    expectation,
    envelope.receivedAt,
  );
  if (decision.status !== "allowed") {
    throw invalid("Pending append is no longer a valid historical admission.");
  }
  const preparationDigest = parseHash32(
    record.preparationDigest,
    "pending preparation digest",
  );
  const expectedPreparationDigest = computeApplicationAppendPreparationDigest({
    admissionCommandDigest,
    semanticIdentityDigest,
    expectedSnapshotDigest,
    expectedAuthorizationSnapshotDigest,
    admissionStartedAt,
    pendingExpiresAt,
    activeSigningKeyValidUntil,
    fenceGeneration: reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      reservationFence.token,
    ),
    attachmentByteLength,
    envelope,
    wireEvidenceDigest: wireInspectionEvidence.evidenceDigest,
    policyEvidenceDigest: policyHeadProofEvidence.evidenceDigest,
    fanoutPlanDigest: fanoutPlan.planDigest,
    quotaCapacityDeltas: decision.quotaCapacityDeltas,
    postReservationQuotas: decision.postReservationQuotas,
  });
  if (preparationDigest !== expectedPreparationDigest) {
    throw invalid("Pending preparation digest is inconsistent.");
  }
  const expectedReservations = bindApplicationAppendQuotaCapacityReservations({
    deltas: decision.quotaCapacityDeltas,
    pendingPreparationDigest: preparationDigest,
    fenceGeneration: reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      reservationFence.token,
    ),
  });
  if (!sameData(commitProjection.quotaCapacityReservations, expectedReservations)) {
    throw invalid("Pending quota reservations were substituted.");
  }
  const validatedProjection = validateLockedApplicationAppendStateTransition({
    priorSnapshot,
    expectation,
    authoritativeReceivedAt: envelope.receivedAt,
    nextHeadHash: envelope.headHash,
    preparedNextConversation: commitProjection.conversation,
    preparedNextUsage: commitProjection.usage,
    quotaCapacityReservations: commitProjection.quotaCapacityReservations,
  });
  if (!sameData(validatedProjection, commitProjection)) {
    throw invalid("Pending commit projection was substituted.");
  }
  const postReservationQuotas =
    validateLockedApplicationAppendQuotaReservationTransition({
      priorSnapshot,
      expectation,
      authoritativeReceivedAt: envelope.receivedAt,
      quotaCapacityReservations: commitProjection.quotaCapacityReservations,
      preparedPostReservationQuotas: record.postReservationQuotas as readonly LockedQuotaCounter[],
    });
  const intentDigest = parseHash32(
    record.intentDigest,
    "pending intent digest",
  );
  if (
    intentDigest !==
    sha256Bytes(
      utf8(APPLICATION_APPEND_PENDING_INTENT_DIGEST_DOMAIN),
      canonicalLengthPrefixed(
        decodeHash32(admissionCommandDigest),
        decodeHash32(semanticIdentityDigest),
        decodeHash32(preparationDigest),
        decodeHash32(
          computeApplicationAppendQuotaReservationSetDigest(
            commitProjection.quotaCapacityReservations,
          ),
        ),
        decodeHash32(fanoutPlan.planDigest),
        utf8(reservationFence.generation),
        decodeHash32(
          computeApplicationAppendFenceTokenHash(reservationFence.token),
        ),
        utf8(pendingExpiresAt),
      ),
    )
  ) {
    throw invalid("Pending intent digest is inconsistent.");
  }
  return Object.freeze({
    profile: "application-append-pending-intent.v1",
    admissionCommand,
    admissionCommandDigest,
    semanticIdentityDigest,
    expectedSnapshotDigest,
    persistedSnapshot,
    expectedAuthorizationSnapshotDigest,
    priorSnapshot,
    expectation,
    attachmentByteLength,
    admissionStartedAt,
    pendingExpiresAt,
    activeSigningKeyValidUntil,
    reservationFence,
    mlsRosterProjections,
    recipientProjections,
    fanoutPlan,
    commitProjection,
    postReservationQuotas,
    envelope,
    wireInspectionEvidence,
    policyHeadProofEvidence,
    preparationDigest,
    intentDigest,
  });
}

export function parsePreparedApplicationAppend(
  value: unknown,
): PreparedApplicationAppend {
  const status = readStatus(value);
  if (status === "unavailable") return parseDeliveryPortUnavailable(value);
  if (status === "rejected") {
    const record = expectExactRecord(
      value,
      ["status", "reasonCode"],
      "prepared application rejection",
    );
    return Object.freeze({
      status: "rejected",
      reasonCode: parseApplicationAppendRejectionReason(record.reasonCode),
    });
  }
  const record = expectExactRecord(
    value,
    ["status", "pendingIntent"],
    "prepared unsigned application append",
  );
  if (record.status !== "ready") {
    throw invalid("Prepared application append status is unsupported.");
  }
  return Object.freeze({
    status: "ready",
    pendingIntent: parsePendingApplicationAppendIntent(record.pendingIntent),
  });
}

function computeApplicationAppendPreparationDigest(input: {
  readonly admissionCommandDigest: Hash32;
  readonly semanticIdentityDigest: Hash32;
  readonly expectedSnapshotDigest: Hash32;
  readonly expectedAuthorizationSnapshotDigest: Hash32;
  readonly admissionStartedAt: Rfc3339Millis;
  readonly pendingExpiresAt: Rfc3339Millis;
  readonly activeSigningKeyValidUntil: Rfc3339Millis;
  readonly fenceGeneration: Uint63String;
  readonly fenceTokenHash: Hash32;
  readonly attachmentByteLength: Uint63String;
  readonly envelope: UnsignedStoredApplicationEnvelope;
  readonly wireEvidenceDigest: Hash32;
  readonly policyEvidenceDigest: Hash32;
  readonly fanoutPlanDigest: Hash32;
  readonly quotaCapacityDeltas: readonly ApplicationAppendQuotaCapacityDelta[];
  readonly postReservationQuotas: readonly LockedQuotaCounter[];
}): Hash32 {
  const envelope = input.envelope;
  return sha256Bytes(
    utf8(APPLICATION_APPEND_PREPARATION_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      decodeHash32(input.admissionCommandDigest),
      decodeHash32(input.semanticIdentityDigest),
      decodeHash32(input.expectedSnapshotDigest),
      decodeHash32(input.expectedAuthorizationSnapshotDigest),
      utf8(input.admissionStartedAt),
      utf8(input.pendingExpiresAt),
      utf8(input.activeSigningKeyValidUntil),
      utf8(input.fenceGeneration),
      decodeHash32(input.fenceTokenHash),
      utf8(input.attachmentByteLength),
      utf8(envelope.conversationId),
      utf8(envelope.position),
      utf8(envelope.envelopeId),
      decodeHash32(envelope.envelopeSha256),
      utf8(envelope.epoch),
      utf8(envelope.rosterVersion),
      utf8(envelope.receivedAt),
      decodeHash32(envelope.leafHash),
      decodeHash32(envelope.previousHeadHash),
      decodeHash32(envelope.headHash),
      utf8(envelope.logSigningKeyId),
      decodeHash32(envelope.logCheckpointDigest),
      decodeHash32(input.wireEvidenceDigest),
      decodeHash32(input.policyEvidenceDigest),
      decodeHash32(input.fanoutPlanDigest),
      canonicalLengthPrefixed(
        ...input.quotaCapacityDeltas.flatMap((delta) => [
          utf8(delta.scope),
          decodeHash32(delta.scopeHash),
          utf8(delta.quotaName),
          utf8(delta.windowStartedAt),
          utf8(delta.windowSeconds),
          utf8(delta.reservationOperationCount),
          utf8(delta.reservationByteCount),
          utf8(delta.rowVersionBefore),
          utf8(delta.rowVersionAfter),
        ]),
      ),
      canonicalLengthPrefixed(
        ...input.postReservationQuotas.flatMap((quota) => [
          utf8(quota.scope),
          decodeHash32(quota.scopeHash),
          utf8(quota.quotaName),
          utf8(quota.windowStartedAt),
          utf8(quota.windowSeconds),
          utf8(quota.operationCount),
          utf8(quota.byteCount),
          utf8(quota.reservedOperationCount),
          utf8(quota.reservedByteCount),
          utf8(quota.rowVersion),
          utf8(quota.operationLimit),
          utf8(quota.byteLimit),
        ]),
      ),
    ),
  );
}

export function parseUnsignedStoredApplicationEnvelope(
  value: unknown,
): UnsignedStoredApplicationEnvelope {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "position",
      "envelopeId",
      "envelopeClass",
      "contentType",
      "envelopeBytes",
      "envelopeSha256",
      "epoch",
      "rosterVersion",
      "sender",
      "receivedAt",
      "leafHash",
      "previousHeadHash",
      "headHash",
      "logSigningKeyId",
      "logCheckpointDigest",
    ],
    "unsigned stored application envelope",
  );
  if (record.envelopeClass !== "application") {
    throw invalid("Unsigned envelope class is unsupported.");
  }
  const contentType = parseEnvelopeContentType(record.contentType);
  if (contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE) {
    throw invalid("Unsigned application content type is unsupported.");
  }
  const envelopeBytes = parseCanonicalBase64Url(
    record.envelopeBytes,
    "unsigned envelope bytes",
    { minBytes: 1, maxBytes: MAX_APPLICATION_BYTES },
  );
  const decoded = parseCanonicalBase64UrlBytes(
    envelopeBytes,
    "unsigned envelope bytes",
    { minBytes: 1, maxBytes: MAX_APPLICATION_BYTES },
  );
  const sender = parseEnvelopeSender(record.sender, "unsigned sender");
  if (sender.type !== "installation") {
    throw invalid("Unsigned application sender must be an installation.");
  }
  const parsed = Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    position: parsePositiveUint63String(record.position),
    envelopeId: parseEnvelopeId(record.envelopeId),
    envelopeClass: "application" as const,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    envelopeBytes,
    envelopeSha256: parseHash32(record.envelopeSha256),
    epoch: parseUint63String(record.epoch),
    rosterVersion: parseUint63String(record.rosterVersion),
    sender,
    receivedAt: parseRfc3339Millis(record.receivedAt),
    leafHash: parseHash32(record.leafHash),
    previousHeadHash: parseHash32(record.previousHeadHash),
    headHash: parseHash32(record.headHash),
    logSigningKeyId: parseSigningKeyId(record.logSigningKeyId),
    logCheckpointDigest: parseHash32(record.logCheckpointDigest),
  });
  const leafHash = computeEnvelopeLeafHash({
    conversationId: parsed.conversationId,
    position: parsed.position,
    envelopeId: parsed.envelopeId,
    envelopeClass: "application",
    sender: parsed.sender,
    epoch: parsed.epoch,
    rosterVersion: parsed.rosterVersion,
    contentType: parsed.contentType,
    envelopeSha256: parsed.envelopeSha256,
    receivedAt: parsed.receivedAt,
  });
  if (
    computeEnvelopeSha256(decoded) !== parsed.envelopeSha256 ||
    leafHash !== parsed.leafHash ||
    computeLogHeadHash(parsed.previousHeadHash, leafHash) !== parsed.headHash ||
    (parsed.position === "1" && parsed.previousHeadHash !== ZERO_HASH32) ||
    parsed.logCheckpointDigest !==
      computeDeliveryLogCheckpointDigest({
        conversationId: parsed.conversationId,
        position: parsed.position,
        previousHeadHash: parsed.previousHeadHash,
        headHash: parsed.headHash,
        signingKeyId: parsed.logSigningKeyId,
      })
  ) {
    throw invalid("Unsigned envelope hash-chain or checkpoint binding is invalid.");
  }
  return parsed;
}

export function parseMlsApplicationWireInspectionEvidence(
  value: unknown,
): MlsApplicationWireInspectionEvidence {
  const hasRawStatus = readStatus(value) === "verified";
  const record = expectExactRecord(
    value,
    [
      ...(hasRawStatus ? (["status"] as const) : []),
      "profile",
      "releaseProfileId",
      "expectedGroupIdHash",
      "expectedEpoch",
      "wireKind",
      "contentType",
      "envelopeSha256",
      "inspectionStatus",
      "evidenceDigest",
    ],
    "MLS application wire inspection evidence",
  );
  if (
    (hasRawStatus && record.status !== "verified") ||
    record.profile !== "mls-application-wire-inspection.v1" ||
    record.wireKind !== "private-application" ||
    record.inspectionStatus !== "verified"
  ) {
    throw invalid("MLS application wire was not verified.");
  }
  const contentType = parseEnvelopeContentType(record.contentType);
  if (contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE) {
    throw invalid("MLS application wire content type is unsupported.");
  }
  const parsed = Object.freeze({
    profile: "mls-application-wire-inspection.v1" as const,
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    expectedGroupIdHash: parseHash32(record.expectedGroupIdHash),
    expectedEpoch: parseUint63String(record.expectedEpoch),
    wireKind: "private-application" as const,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    envelopeSha256: parseHash32(record.envelopeSha256),
    inspectionStatus: "verified" as const,
    evidenceDigest: parseHash32(record.evidenceDigest),
  });
  if (
    parsed.evidenceDigest !==
    computeMlsApplicationWireInspectionEvidenceDigest(parsed)
  ) {
    throw invalid("MLS wire evidence digest is inconsistent.");
  }
  return parsed;
}

export function computeMlsApplicationWireInspectionEvidenceDigest(input: {
  readonly releaseProfileId: ReleaseProfileId;
  readonly expectedGroupIdHash: Hash32;
  readonly expectedEpoch: Uint63String;
  readonly wireKind: "private-application";
  readonly contentType: typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;
  readonly envelopeSha256: Hash32;
  readonly inspectionStatus: "verified";
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_WIRE_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.releaseProfileId),
      decodeHash32(input.expectedGroupIdHash),
      utf8(input.expectedEpoch),
      utf8(input.wireKind),
      utf8(input.contentType),
      decodeHash32(input.envelopeSha256),
      utf8(input.inspectionStatus),
    ),
  );
}

async function inspectApplicationWire(
  ports: ProductionDeliveryPorts,
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
  invocation: ActiveInvocation,
): Promise<MlsApplicationWireInspectionEvidence | DeliveryPortUnavailable> {
  const envelopeBytes = parseCanonicalBase64UrlBytes(
    command.semanticIdentity.append.ciphertext,
    "ciphertext",
    { minBytes: 1, maxBytes: MAX_APPLICATION_BYTES },
  );
  const raw = await callBounded(
    () =>
      ports.mlsWireInspector.inspect({
        releaseProfileId: command.releaseProfileId,
        expectedGroupIdHash: snapshot.conversation.groupIdHash,
        expectedEpoch: snapshot.conversation.epoch,
        expectedWireKind: "private-application",
        contentType: command.semanticIdentity.append.contentType,
        envelopeBytes: copyBytes(
          envelopeBytes,
          "MLS application ciphertext",
          MAX_APPLICATION_BYTES,
        ),
        envelopeSha256: command.semanticIdentity.append.envelopeSha256,
        ...invocation.context,
      }),
    invocation,
  );
  if (raw === TIMED_OUT) return timeoutUnavailable();
  if (raw === PORT_FAILED) return malformedDependency();
  try {
    if (readStatus(raw) === "unavailable") {
      return parseDeliveryPortUnavailable(raw);
    }
    const evidence = parseMlsApplicationWireInspectionEvidence(raw);
    assertWireEvidenceMatches(evidence, command, snapshot);
    return evidence;
  } catch {
    return malformedDependency();
  }
}

async function verifyPolicyHead(
  ports: ProductionDeliveryPorts,
  snapshot: LockedApplicationAppendSnapshot,
  verifiedAt: Rfc3339Millis,
  invocation: ActiveInvocation,
): Promise<PolicyHeadProofEvidence | DeliveryPortUnavailable> {
  const expected = policyProofExpectation(snapshot, verifiedAt);
  const request: PolicyHeadProofVerificationRequest = Object.freeze({
    profile: "conversation-policy-head-proof.v1",
    ...expected,
    ...invocation.context,
  });
  const raw = await callBounded(
    () => ports.policyHeadProofVerifier.verify(request),
    invocation,
  );
  if (raw === TIMED_OUT) return timeoutUnavailable();
  if (raw === PORT_FAILED) return malformedDependency();
  try {
    if (readStatus(raw) === "unavailable") {
      return parseDeliveryPortUnavailable(raw);
    }
    return parsePolicyHeadProofEvidence(raw, expected);
  } catch {
    return malformedDependency();
  }
}

function policyProofExpectation(
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

function parseStoredPolicyEvidence(
  value: unknown,
  snapshot: LockedApplicationAppendSnapshot,
): PolicyHeadProofEvidence {
  const verifiedAt = parseRfc3339Millis(
    ownDataValue(value, "verifiedAt"),
    "stored policy evidence verification time",
  );
  return parsePolicyHeadProofEvidence(
    withVerifiedStatus(value, "stored policy-head proof evidence"),
    policyProofExpectation(snapshot, verifiedAt),
  );
}

function assertPolicyEvidenceMatches(
  evidence: PolicyHeadProofEvidence,
  snapshot: LockedApplicationAppendSnapshot,
): void {
  parsePolicyHeadProofEvidence(
    { status: "verified", ...evidence },
    policyProofExpectation(snapshot, evidence.verifiedAt),
  );
}

function assertWireEvidenceMatches(
  evidence: MlsApplicationWireInspectionEvidence,
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
): void {
  if (
    evidence.releaseProfileId !== command.releaseProfileId ||
    evidence.expectedGroupIdHash !== snapshot.conversation.groupIdHash ||
    evidence.expectedEpoch !== snapshot.conversation.epoch ||
    evidence.contentType !== command.semanticIdentity.append.contentType ||
    evidence.envelopeSha256 !==
      command.semanticIdentity.append.envelopeSha256
  ) {
    throw invalid("MLS wire inspection evidence was substituted.");
  }
}

const PENDING_DRAINED = Symbol("application-append-pending-drained");

type PendingResumeResult =
  | ApplicationEnvelopeAppendResult
  | typeof PENDING_DRAINED;

async function resumePendingApplicationAppend(
  ports: ProductionDeliveryPorts,
  currentCommand: AtomicApplicationAppendCommand,
  pending: PendingApplicationAppendIntent,
  invocation: ActiveInvocation,
  returnAcceptance: boolean,
): Promise<PendingResumeResult> {
  const envelope = pending.envelope;
  const signingRequest = checkpointSigningRequest(pending, invocation.context);
  const beforeSigner = readClockNow(ports);
  if (isUnavailable(beforeSigner)) return beforeSigner;
  const resolveExpired = beforeSigner >= pending.pendingExpiresAt;
  const signerRaw = await callBounded(
    () => resolveExpired
      ? ports.checkpointSigner.resolveOrCancelIfUnsigned({
          ...signingRequest,
          profile: "application-append-signer-fence-resolution.v1",
        })
      : ports.checkpointSigner.signExact(signingRequest),
    invocation,
  );
  if (signerRaw === TIMED_OUT) return timeoutUnavailable();
  if (signerRaw === PORT_FAILED) return malformedDependency();
  let resolution: ApplicationAppendSignerFenceResolution;
  try {
    if (readStatus(signerRaw) === "unavailable") {
      return parseDeliveryPortUnavailable(signerRaw);
    }
    resolution = parseApplicationAppendSignerFenceResolution(
      signerRaw,
      signingRequest,
    );
  } catch {
    reportInvariantIncident(
      ports,
      currentCommand,
      invocation,
      "checkpoint-substitution",
    );
    return malformedDependency();
  }
  const signerCompletedAt = readClockNow(ports);
  if (isUnavailable(signerCompletedAt)) return signerCompletedAt;
  if (
    (!resolveExpired &&
      (resolution.status !== "signed" ||
        !timestampWasObservedDuringInvocation(
          resolution.signedAt,
          signerCompletedAt,
          invocation,
        ))) ||
    (resolveExpired &&
      resolution.status === "cancelled" &&
      resolution.cancelledAt > signerCompletedAt) ||
    signerCompletedAt >= invocation.context.deadline
  ) {
    return malformedDependency();
  }

  const fenceVerifiedAt = readClockNow(ports);
  if (isUnavailable(fenceVerifiedAt)) return fenceVerifiedAt;
  const fenceRaw = await callBounded(
    () => ports.signerFenceEvidenceVerifier.verify({
      profile: "application-append-signer-fence-evidence.v1",
      resolution,
      verifiedAt: fenceVerifiedAt,
      deadline: invocation.context.deadline,
      signal: invocation.context.signal,
    }),
    invocation,
  );
  if (fenceRaw === TIMED_OUT) return timeoutUnavailable();
  if (fenceRaw === PORT_FAILED) return malformedDependency();
  let fenceEvidence: ApplicationAppendSignerFenceVerificationEvidence;
  try {
    if (readStatus(fenceRaw) === "unavailable") {
      return parseDeliveryPortUnavailable(fenceRaw);
    }
    fenceEvidence = parseApplicationAppendSignerFenceVerificationEvidence(
      fenceRaw,
      resolution,
      fenceVerifiedAt,
    );
  } catch {
    reportInvariantIncident(
      ports,
      currentCommand,
      invocation,
      "checkpoint-substitution",
    );
    return malformedDependency();
  }
  const fenceCompletedAt = readClockNow(ports);
  if (isUnavailable(fenceCompletedAt)) return fenceCompletedAt;
  if (
    !timestampWasObservedDuringInvocation(
      fenceVerifiedAt,
      fenceCompletedAt,
      invocation,
    )
  ) {
    return malformedDependency();
  }

  if (resolution.status === "cancelled") {
    for (let attempt = 0; attempt < MAX_PHASE_RETRIES; attempt += 1) {
      const retiredValue = await callBounded(
        () => ports.atomicPersistence.retireExpiredApplicationAppendAtomically(
          {
            command: currentCommand,
            pendingIntent: pending,
            pendingIntentDigest: pending.intentDigest,
            reservationFence: pending.reservationFence,
            pendingExpiresAt: pending.pendingExpiresAt,
            invocationStartedAt: invocation.startedAt,
            cancellationResolution: resolution,
            verifiedCancellationEvidence: Object.freeze({
              ...fenceEvidence,
            }),
          },
          invocation.context,
        ),
        invocation,
      );
      if (retiredValue === TIMED_OUT) return timeoutUnavailable();
      if (retiredValue === PORT_FAILED) return malformedDependency();
      const retired = parsePhaseResultFromPort(
        retiredValue,
        currentCommand,
        ports,
        invocation,
      );
      if (retired.status === "retired") {
        const completedAt = readClockNow(ports);
        if (
          isUnavailable(completedAt) ||
          retired.pendingIntentDigest !== pending.intentDigest ||
          retired.retiredAt > retired.observedAt ||
          !timestampWasObservedDuringInvocation(
            retired.observedAt,
            completedAt,
            invocation,
          )
        ) {
          return isUnavailable(completedAt)
            ? completedAt
            : malformedDependency();
        }
        return PENDING_DRAINED;
      }
      if (
        retired.status === "retry" ||
        (retired.status === "blocked-by-pending" &&
          retired.pendingIntent.intentDigest === pending.intentDigest)
      ) {
        await Promise.resolve();
        continue;
      }
      return malformedDependency();
    }
    return timeoutUnavailable();
  }

  const verifiedAt = readClockNow(ports);
  if (isUnavailable(verifiedAt)) return verifiedAt;
  const verificationRequest = checkpointVerificationRequest(
    envelope,
    pending,
    resolution.checkpointSignature,
    verifiedAt,
    invocation.context,
  );
  const verifierRaw = await callBounded(
    () => ports.checkpointSignatureVerifier.verify(verificationRequest),
    invocation,
  );
  if (verifierRaw === TIMED_OUT) return timeoutUnavailable();
  if (verifierRaw === PORT_FAILED) return malformedDependency();
  let signatureEvidence: DeliveryCheckpointSignatureEvidence;
  try {
    if (readStatus(verifierRaw) === "unavailable") {
      const unavailable = parseDeliveryPortUnavailable(verifierRaw);
      if (unavailable.reasonCode === "malformed-dependency-response") {
        reportInvariantIncident(
          ports,
          currentCommand,
          invocation,
          "checkpoint-substitution",
        );
      }
      return unavailable;
    }
    signatureEvidence = parseDeliveryCheckpointSignatureEvidence(
      verifierRaw,
      verificationRequest,
    );
  } catch {
    reportInvariantIncident(
      ports,
      currentCommand,
      invocation,
      "checkpoint-substitution",
    );
    return malformedDependency();
  }
  const signatureVerificationCompletedAt = readClockNow(ports);
  if (isUnavailable(signatureVerificationCompletedAt)) {
    return signatureVerificationCompletedAt;
  }
  if (
    !timestampWasObservedDuringInvocation(
      verifiedAt,
      signatureVerificationCompletedAt,
      invocation,
    )
  ) {
    return malformedDependency();
  }

  for (let attempt = 0; attempt < MAX_PHASE_RETRIES; attempt += 1) {
    if (invocation.context.signal.aborted) return timeoutUnavailable();
    const finalizedValue = await callBounded(
      () =>
        ports.atomicPersistence.finalizeApplicationAppendAtomically(
          {
            command: currentCommand,
            pendingIntent: pending,
            pendingIntentDigest: pending.intentDigest,
            reservationFence: pending.reservationFence,
            pendingExpiresAt: pending.pendingExpiresAt,
            invocationStartedAt: invocation.startedAt,
            fanoutPlan: pending.fanoutPlan,
            signature: resolution.checkpointSignature,
            signedFenceResolution: resolution,
            verifiedSignatureEvidence: Object.freeze({
              ...signatureEvidence,
            }),
            verifiedSignerFenceEvidence: Object.freeze({ ...fenceEvidence }),
          },
          invocation.context,
        ),
      invocation,
    );
    if (finalizedValue === TIMED_OUT) return timeoutUnavailable();
    if (finalizedValue === PORT_FAILED) return malformedDependency();
    const finalized = parsePhaseResultFromPort(
      finalizedValue,
      currentCommand,
      ports,
      invocation,
    );
    if (finalized.status === "accepted") {
      const completedAt = readClockNow(ports);
      if (
        isUnavailable(completedAt) ||
        finalized.acceptance.acceptedIntent.intentDigest !==
          pending.intentDigest ||
        finalized.acceptance.signatureEvidence.evidenceDigest !==
          signatureEvidence.evidenceDigest ||
        finalized.acceptance.signerFenceEvidence.evidenceDigest !==
          fenceEvidence.evidenceDigest ||
        finalized.acceptance.finalizedAt > finalized.acceptance.observedAt ||
        !timestampWasObservedDuringInvocation(
          finalized.acceptance.observedAt,
          completedAt,
          invocation,
        )
      ) {
        reportInvariantIncident(
          ports,
          currentCommand,
          invocation,
          "atomic-persistence-ambiguity",
        );
        return malformedDependency();
      }
      if (isUnavailable(completedAt)) return completedAt;
      return returnAcceptance
        ? publicAcceptance(finalized.acceptance)
        : PENDING_DRAINED;
    }
    if (finalized.status === "pending") {
      if (finalized.pendingIntent.intentDigest !== pending.intentDigest) {
        reportInvariantIncident(
          ports,
          currentCommand,
          invocation,
          "atomic-persistence-ambiguity",
        );
        return malformedDependency();
      }
      await Promise.resolve();
      continue;
    }
    if (finalized.status === "retry") {
      await Promise.resolve();
      continue;
    }
    if (
      finalized.status === "miss" ||
      finalized.status === "retired" ||
      finalized.status === "blocked-by-pending"
    ) {
      reportInvariantIncident(
        ports,
        currentCommand,
        invocation,
        "atomic-persistence-ambiguity",
      );
      return malformedDependency();
    }
    return finalized;
  }
  return timeoutUnavailable();
}

function checkpointSigningRequest(
  pending: PendingApplicationAppendIntent,
  invocation: DeliveryInvocationContext,
): DeliveryCheckpointSigningRequest {
  const envelope = pending.envelope;
  return Object.freeze({
    profile: "delivery-log-checkpoint.v1",
    realmId: pending.admissionCommand.realmId,
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
    reservationFence: pending.reservationFence,
    pendingExpiresAt: pending.pendingExpiresAt,
    admissionStartedAt: pending.admissionStartedAt,
    invocationStartedAt: invocation.invocationStartedAt,
    deadline: invocation.deadline,
    signal: invocation.signal,
  });
}

function checkpointVerificationRequest(
  envelope: UnsignedStoredApplicationEnvelope,
  pending: Pick<
    AcceptedApplicationAppendIntent,
    "admissionCommand" | "priorSnapshot"
  >,
  signature: Ed25519Signature,
  verifiedAt: Rfc3339Millis,
  invocation: DeliveryInvocationContext,
): DeliveryCheckpointSignatureVerificationRequest {
  return Object.freeze({
    profile: "delivery-log-checkpoint.v1",
    realmId: pending.admissionCommand.realmId,
    conversationId: envelope.conversationId,
    conversationGeneration: pending.priorSnapshot.conversation.generation,
    releaseProfileId: pending.admissionCommand.releaseProfileId,
    releaseTrustRootDigest:
      pending.admissionCommand.releaseTrustRootDigest,
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

async function verifyHistoricalAcceptance(
  ports: ProductionDeliveryPorts,
  acceptance: PersistedApplicationAppendAcceptance,
  invocation: ActiveInvocation,
): Promise<{ readonly status: "verified" } | DeliveryPortUnavailable> {
  const acceptedIntent = acceptance.acceptedIntent;
  const envelope = acceptedIntent.envelope;
  const fenceVerifiedAt = readClockNow(ports);
  if (isUnavailable(fenceVerifiedAt)) return fenceVerifiedAt;
  const fenceRaw = await callBounded(
    () => ports.signerFenceEvidenceVerifier.verify({
      profile: "application-append-signer-fence-evidence.v1",
      resolution: acceptedIntent.signerFenceResolution,
      verifiedAt: fenceVerifiedAt,
      deadline: invocation.context.deadline,
      signal: invocation.context.signal,
    }),
    invocation,
  );
  if (fenceRaw === TIMED_OUT) return timeoutUnavailable();
  if (fenceRaw === PORT_FAILED) return malformedDependency();
  try {
    if (readStatus(fenceRaw) === "unavailable") {
      return parseDeliveryPortUnavailable(fenceRaw);
    }
    const freshFenceEvidence =
      parseApplicationAppendSignerFenceVerificationEvidence(
        fenceRaw,
        acceptedIntent.signerFenceResolution,
        fenceVerifiedAt,
      );
    if (!sameSignerFenceEvidenceIdentity(
      freshFenceEvidence,
      acceptance.signerFenceEvidence,
    )) {
      throw invalid("Historical signer-fence evidence identity changed.");
    }
  } catch {
    reportInvariantIncident(
      ports,
      acceptedIntent.admissionCommand,
      invocation,
      "checkpoint-substitution",
    );
    return malformedDependency();
  }
  const fenceCompletedAt = readClockNow(ports);
  if (
    isUnavailable(fenceCompletedAt) ||
    !timestampWasObservedDuringInvocation(
      fenceVerifiedAt,
      fenceCompletedAt,
      invocation,
    )
  ) {
    return isUnavailable(fenceCompletedAt)
      ? fenceCompletedAt
      : malformedDependency();
  }
  const verifiedAt = readClockNow(ports);
  if (isUnavailable(verifiedAt)) return verifiedAt;
  const request = checkpointVerificationRequest(
    envelope,
    acceptedIntent,
    acceptance.envelope.logHeadSignature,
    verifiedAt,
    invocation.context,
  );
  const raw = await callBounded(
    () => ports.checkpointSignatureVerifier.verify(request),
    invocation,
  );
  if (raw === TIMED_OUT) return timeoutUnavailable();
  if (raw === PORT_FAILED) return malformedDependency();
  try {
    if (readStatus(raw) === "unavailable") {
      return parseDeliveryPortUnavailable(raw);
    }
    const evidence = parseDeliveryCheckpointSignatureEvidence(raw, request);
    if (!sameCheckpointSignatureEvidenceIdentity(
      evidence,
      acceptance.signatureEvidence,
    )) {
      reportInvariantIncident(
        ports,
        acceptedIntent.admissionCommand,
        invocation,
        "checkpoint-substitution",
      );
      return malformedDependency();
    }
    const completedAt = readClockNow(ports);
    if (
      isUnavailable(completedAt) ||
      !timestampWasObservedDuringInvocation(
        verifiedAt,
        completedAt,
        invocation,
      )
    ) {
      return isUnavailable(completedAt)
        ? completedAt
        : malformedDependency();
    }
    return Object.freeze({ status: "verified" });
  } catch {
    reportInvariantIncident(
      ports,
      acceptedIntent.admissionCommand,
      invocation,
      "checkpoint-substitution",
    );
    return malformedDependency();
  }
}

export function parseApplicationAppendPhaseResult(
  value: unknown,
  currentCommandValue: unknown,
): ApplicationAppendPhaseResult {
  const currentCommand = parseAtomicApplicationAppendCommand(
    currentCommandValue,
  );
  const currentDigest = computeAtomicApplicationAppendCommandDigest(
    currentCommand,
  );
  const status = readStatus(value);
  if (status === "unavailable") return parseDeliveryPortUnavailable(value);
  if (status === "conflict") {
    const record = expectExactRecord(
      value,
      ["status", "reasonCode"],
      "application append conflict",
    );
    if (record.reasonCode !== "idempotency-conflict") {
      throw invalid("Application append conflict reason is unsupported.");
    }
    return Object.freeze({
      status: "conflict",
      reasonCode: "idempotency-conflict",
    });
  }
  if (status === "rejected") {
    const record = expectExactRecord(
      value,
      ["status", "reasonCode"],
      "application append rejection",
    );
    return Object.freeze({
      status: "rejected",
      reasonCode: parseAppendResultRejection(record.reasonCode),
    });
  }
  if (status === "retry") {
    const record = expectExactRecord(
      value,
      ["status", "reasonCode"],
      "application append retry",
    );
    if (record.reasonCode !== "snapshot-changed") {
      throw invalid("Application append retry reason is unsupported.");
    }
    return Object.freeze({
      status: "retry",
      reasonCode: record.reasonCode,
    });
  }
  if (status === "retired") {
    const record = expectExactRecord(
      value,
      [
        "status",
        "invocationCommandDigest",
        "pendingIntentDigest",
        "retiredAt",
        "observedAt",
      ],
      "retired application append result",
    );
    const invocationCommandDigest = parseHash32(record.invocationCommandDigest);
    if (invocationCommandDigest !== currentDigest) {
      throw invalid("Retired result is detached from its current command.");
    }
    const retiredAt = parseRfc3339Millis(record.retiredAt);
    const observedAt = parseRfc3339Millis(record.observedAt);
    if (retiredAt > observedAt) {
      throw invalid("Retirement time is after its response observation.");
    }
    return Object.freeze({
      status: "retired",
      invocationCommandDigest,
      pendingIntentDigest: parseHash32(record.pendingIntentDigest),
      retiredAt,
      observedAt,
    });
  }
  if (status === "miss") {
    const record = expectExactRecord(
      value,
      [
        "status",
        "invocationCommandDigest",
        "lockedSnapshot",
        "snapshotDigest",
        "previousHeadHash",
        "attachmentByteLength",
        "observedAt",
      ],
      "application append preflight miss",
    );
    const invocationCommandDigest = parseHash32(
      record.invocationCommandDigest,
    );
    if (invocationCommandDigest !== currentDigest) {
      throw invalid("Preflight miss is detached from its current command.");
    }
    const lockedSnapshot = parseLockedApplicationAppendSnapshot(
      record.lockedSnapshot,
    );
    const snapshotDigest = parseHash32(record.snapshotDigest);
    const previousHeadHash = parseHash32(record.previousHeadHash);
    if (
      snapshotDigest !==
        computeLockedApplicationAppendSnapshotDigest(lockedSnapshot) ||
      previousHeadHash !== lockedSnapshot.conversation.currentLogHeadHash
    ) {
      throw invalid("Preflight snapshot fence or log head is inconsistent.");
    }
    return Object.freeze({
      status: "miss",
      invocationCommandDigest,
      lockedSnapshot,
      snapshotDigest,
      previousHeadHash,
      attachmentByteLength: parseUint63String(
        record.attachmentByteLength,
      ),
      observedAt: parseRfc3339Millis(record.observedAt),
    });
  }
  if (status === "pending" || status === "blocked-by-pending") {
    const blocked = status === "blocked-by-pending";
    const record = expectExactRecord(
      value,
      blocked
        ? [
            "status",
            "invocationCommandDigest",
            "pendingIntent",
            "reservedAt",
            "observedAt",
          ]
        : [
            "status",
            "replay",
            "invocationCommandDigest",
            "pendingIntent",
            "reservedAt",
            "observedAt",
          ],
      "pending application append result",
    );
    const invocationCommandDigest = parseHash32(
      record.invocationCommandDigest,
    );
    if (invocationCommandDigest !== currentDigest) {
      throw invalid("Pending result is detached from its current command.");
    }
    const pendingIntent = parsePendingApplicationAppendIntent(
      record.pendingIntent,
    );
    const reservedAt = parseRfc3339Millis(record.reservedAt);
    const observedAt = parseRfc3339Millis(record.observedAt);
    if (reservedAt > observedAt) {
      throw invalid("Reservation time is after its response observation.");
    }
    if (blocked) {
      if (
        pendingIntent.admissionCommand.realmId !== currentCommand.realmId ||
        pendingIntent.admissionCommand.semanticIdentity.conversationId !==
          currentCommand.semanticIdentity.conversationId
      ) {
        throw invalid("Blocking pending intent belongs to another lane.");
      }
      return Object.freeze({
        status: "blocked-by-pending",
        invocationCommandDigest,
        pendingIntent,
        reservedAt,
        observedAt,
      });
    }
    const replay = parseReplayClassification(record.replay, false);
    requireReplayMatchesCurrentCommand(replay, currentCommand, pendingIntent.admissionCommand);
    return Object.freeze({
      status: "pending",
      replay,
      invocationCommandDigest,
      pendingIntent,
      reservedAt,
      observedAt,
    });
  }
  if (status === "accepted") {
    return Object.freeze({
      status: "accepted",
      acceptance: parsePersistedApplicationAppendAcceptance(
        value,
        currentCommand,
      ),
    });
  }
  throw invalid("Application append phase status is unsupported.");
}

function parsePhaseResultFromPort(
  value: unknown,
  currentCommand: AtomicApplicationAppendCommand,
  ports: ProductionDeliveryPorts,
  invocation: ActiveInvocation,
): ApplicationAppendPhaseResult {
  try {
    return parseApplicationAppendPhaseResult(value, currentCommand);
  } catch {
    reportInvariantIncident(
      ports,
      currentCommand,
      invocation,
      "atomic-persistence-ambiguity",
    );
    return malformedDependency();
  }
}

export function acceptedApplicationAppendIntentFromPending(
  pendingValue: unknown,
  signedResolutionValue: unknown,
): AcceptedApplicationAppendIntent {
  const pending = parsePendingApplicationAppendIntent(pendingValue);
  const signedResolution = parseStoredSignerFenceSignedResolution(
    signedResolutionValue,
    {
      admissionCommand: pending.admissionCommand,
      priorSnapshot: pending.priorSnapshot,
      envelope: pending.envelope,
      intentDigest: pending.intentDigest,
      admissionStartedAt: pending.admissionStartedAt,
      pendingExpiresAt: pending.pendingExpiresAt,
      fenceGeneration: pending.reservationFence.generation,
      fenceTokenHash: computeApplicationAppendFenceTokenHash(
        pending.reservationFence.token,
      ),
    },
  );
  return parseAcceptedApplicationAppendIntent({
    profile: "application-append-accepted-intent.v1",
    admissionCommand: pending.admissionCommand,
    admissionCommandDigest: pending.admissionCommandDigest,
    semanticIdentityDigest: pending.semanticIdentityDigest,
    priorSnapshot: pending.priorSnapshot,
    envelope: pending.envelope,
    wireInspectionEvidence: pending.wireInspectionEvidence,
    policyHeadProofEvidence: pending.policyHeadProofEvidence,
    preparationDigest: pending.preparationDigest,
    intentDigest: pending.intentDigest,
    admissionStartedAt: pending.admissionStartedAt,
    pendingExpiresAt: pending.pendingExpiresAt,
    fenceGeneration: pending.reservationFence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(
      pending.reservationFence.token,
    ),
    fanoutPlan: pending.fanoutPlan,
    quotaReservationSetDigest:
      computeApplicationAppendQuotaReservationSetDigest(
        pending.commitProjection.quotaCapacityReservations,
      ),
    signerFenceResolution: signedResolution,
  });
}

export function parseAcceptedApplicationAppendIntent(
  value: unknown,
): AcceptedApplicationAppendIntent {
  const record = expectExactRecord(
    value,
    [
      "profile",
      "admissionCommand",
      "admissionCommandDigest",
      "semanticIdentityDigest",
      "priorSnapshot",
      "envelope",
      "wireInspectionEvidence",
      "policyHeadProofEvidence",
      "preparationDigest",
      "intentDigest",
      "admissionStartedAt",
      "pendingExpiresAt",
      "fenceGeneration",
      "fenceTokenHash",
      "fanoutPlan",
      "quotaReservationSetDigest",
      "signerFenceResolution",
    ],
    "accepted application append intent",
  );
  if (record.profile !== "application-append-accepted-intent.v1") {
    throw invalid("Accepted application append intent profile is unsupported.");
  }
  const admissionCommand = parseAtomicApplicationAppendCommand(
    record.admissionCommand,
  );
  const admissionCommandDigest = parseHash32(record.admissionCommandDigest);
  const semanticIdentityDigest = parseHash32(record.semanticIdentityDigest);
  const priorSnapshot = parseLockedApplicationAppendSnapshot(record.priorSnapshot);
  const envelope = parseUnsignedStoredApplicationEnvelope(record.envelope);
  const wireInspectionEvidence = parseMlsApplicationWireInspectionEvidence(
    record.wireInspectionEvidence,
  );
  const policyHeadProofEvidence = parseStoredPolicyEvidence(
    record.policyHeadProofEvidence,
    priorSnapshot,
  );
  const preparationDigest = parseHash32(record.preparationDigest);
  const intentDigest = parseHash32(record.intentDigest);
  const admissionStartedAt = parseRfc3339Millis(record.admissionStartedAt);
  const pendingExpiresAt = parseRfc3339Millis(record.pendingExpiresAt);
  const fenceGeneration = parsePositiveUint63String(record.fenceGeneration);
  const fenceTokenHash = parseHash32(record.fenceTokenHash);
  const fanoutPlan = parseApplicationAppendFanoutPlan(
    record.fanoutPlan,
    admissionCommand.deliveryLimits.conversationRecipientInstallationsMax,
  );
  const quotaReservationSetDigest = parseHash32(
    record.quotaReservationSetDigest,
  );
  if (
    admissionCommandDigest !==
      computeAtomicApplicationAppendCommandDigest(admissionCommand) ||
    semanticIdentityDigest !==
      computeApplicationEnvelopeSemanticIdentityDigest(
        admissionCommand.semanticIdentity,
      ) ||
    priorSnapshot.conversation.realmId !== admissionCommand.realmId ||
    priorSnapshot.conversation.releaseProfileId !==
      admissionCommand.releaseProfileId ||
    priorSnapshot.conversation.deliveryLimitsDigest !==
      admissionCommand.deliveryLimitsDigest ||
    priorSnapshot.conversation.releaseTrustRootDigest !==
      admissionCommand.releaseTrustRootDigest ||
    fanoutPlan.conversationId !== envelope.conversationId ||
    fanoutPlan.conversationGeneration !==
      priorSnapshot.conversation.generation ||
    fanoutPlan.rosterHash !== priorSnapshot.conversation.rosterHash ||
    fanoutPlan.recipientSetHash !==
      priorSnapshot.conversation.recipientSetHash ||
    fanoutPlan.position !== envelope.position
  ) {
    throw invalid("Accepted application append intent was substituted.");
  }
  try {
    enforceApplicationAppendDeliveryLimits(
      admissionCommand.semanticIdentity.append,
      admissionCommand.deliveryLimits,
    );
  } catch {
    throw invalid("Accepted intent violates its historical admission limits.");
  }
  assertWireEvidenceMatches(wireInspectionEvidence, admissionCommand, priorSnapshot);
  assertPolicyEvidenceMatches(policyHeadProofEvidence, priorSnapshot);
  requireUnsignedEnvelopeMatchesCommand(envelope, admissionCommand, priorSnapshot);
  const expectedIntentDigest = sha256Bytes(
    utf8(APPLICATION_APPEND_PENDING_INTENT_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      decodeHash32(admissionCommandDigest),
      decodeHash32(semanticIdentityDigest),
      decodeHash32(preparationDigest),
      decodeHash32(quotaReservationSetDigest),
      decodeHash32(fanoutPlan.planDigest),
      utf8(fenceGeneration),
      decodeHash32(fenceTokenHash),
      utf8(pendingExpiresAt),
    ),
  );
  if (intentDigest !== expectedIntentDigest) {
    throw invalid("Accepted intent digest is inconsistent.");
  }
  const signerFenceResolution = parseStoredSignerFenceSignedResolution(
    record.signerFenceResolution,
    {
      admissionCommand,
      priorSnapshot,
      envelope,
      intentDigest,
      admissionStartedAt,
      pendingExpiresAt,
      fenceGeneration,
      fenceTokenHash,
    },
  );
  return Object.freeze({
    profile: "application-append-accepted-intent.v1",
    admissionCommand,
    admissionCommandDigest,
    semanticIdentityDigest,
    priorSnapshot,
    envelope,
    wireInspectionEvidence,
    policyHeadProofEvidence,
    preparationDigest,
    intentDigest,
    admissionStartedAt,
    pendingExpiresAt,
    fenceGeneration,
    fenceTokenHash,
    fanoutPlan,
    quotaReservationSetDigest,
    signerFenceResolution,
  });
}

function parseStoredSignerFenceSignedResolution(
  value: unknown,
  expected: Pick<
    AcceptedApplicationAppendIntent,
    | "admissionCommand"
    | "priorSnapshot"
    | "envelope"
    | "intentDigest"
    | "admissionStartedAt"
    | "pendingExpiresAt"
    | "fenceGeneration"
    | "fenceTokenHash"
  >,
): ApplicationAppendSignerFenceSignedResolution {
  const envelope = expected.envelope;
  return parseDurableApplicationAppendSignerFenceSignedResolution(value, {
    realmId: expected.admissionCommand.realmId,
    conversationGeneration: expected.priorSnapshot.conversation.generation,
    releaseProfileId: expected.admissionCommand.releaseProfileId,
    releaseTrustRootDigest: expected.admissionCommand.releaseTrustRootDigest,
    conversationId: envelope.conversationId,
    position: envelope.position,
    previousHeadHash: envelope.previousHeadHash,
    headHash: envelope.headHash,
    signingKeyId: envelope.logSigningKeyId,
    checkpointDigest: envelope.logCheckpointDigest,
    checkpointReceivedAt: envelope.receivedAt,
    pendingIntentDigest: expected.intentDigest,
    fenceGeneration: expected.fenceGeneration,
    fenceTokenHash: expected.fenceTokenHash,
    pendingExpiresAt: expected.pendingExpiresAt,
    admissionStartedAt: expected.admissionStartedAt,
  });
}

export function parsePersistedApplicationAppendAcceptance(
  value: unknown,
  currentCommandValue: unknown,
): PersistedApplicationAppendAcceptance {
  const currentCommand = parseAtomicApplicationAppendCommand(
    currentCommandValue,
  );
  const record = expectExactRecord(
    value,
    [
      "status",
      "replay",
      "invocationCommandDigest",
      "acceptedIntent",
      "envelope",
      "receipt",
      "signatureEvidence",
      "signerFenceEvidence",
      "fanoutEvidence",
      "finalizedAt",
      "observedAt",
    ],
    "persisted application append acceptance",
  );
  if (record.status !== "accepted") {
    throw invalid("Persisted application append was not accepted.");
  }
  const replay = parseReplayClassification(record.replay, true);
  const invocationCommandDigest = parseHash32(
    record.invocationCommandDigest,
  );
  if (
    invocationCommandDigest !==
    computeAtomicApplicationAppendCommandDigest(currentCommand)
  ) {
    throw invalid("Accepted result is detached from its current command.");
  }
  const acceptedIntent = parseAcceptedApplicationAppendIntent(
    record.acceptedIntent,
  );
  requireReplayMatchesCurrentCommand(
    replay,
    currentCommand,
    acceptedIntent.admissionCommand,
  );
  const envelope = parseStoredEnvelope(record.envelope);
  if (envelope.envelopeClass !== "application") {
    throw invalid("Accepted envelope is not an application envelope.");
  }
  enforceStoredEnvelopeDeliveryLimits(
    envelope,
    acceptedIntent.admissionCommand.deliveryLimits,
  );
  requireSignedEnvelopeMatchesPending(envelope, acceptedIntent.envelope);
  const receipt = parseApplicationEnvelopeReceipt(record.receipt);
  requireReceiptMatchesEnvelope(receipt, envelope);
  const signatureEvidence = parseStoredCheckpointSignatureEvidence(
    record.signatureEvidence,
    envelope,
    acceptedIntent,
  );
  const signerFenceEvidence = parseApplicationAppendSignerFenceVerificationEvidence(
    record.signerFenceEvidence,
    acceptedIntent.signerFenceResolution,
    parseRfc3339Millis(
      ownDataValue(record.signerFenceEvidence, "verifiedAt"),
    ),
  );
  const fanoutEvidence = parseApplicationAppendFanoutEvidence(
    record.fanoutEvidence,
    {
      plan: acceptedIntent.fanoutPlan,
      envelopeId: envelope.envelopeId,
      headHash: envelope.headHash,
    },
  );
  const finalizedAt = parseRfc3339Millis(record.finalizedAt);
  const observedAt = parseRfc3339Millis(record.observedAt);
  if (finalizedAt > observedAt) {
    throw invalid("Finalization time is after its response observation.");
  }
  return Object.freeze({
    receipt,
    replay,
    invocationCommandDigest,
    acceptedIntent,
    envelope,
    signatureEvidence,
    signerFenceEvidence,
    fanoutEvidence,
    finalizedAt,
    observedAt,
  });
}

/** Public-result parser retained for focused adapter tests. */
export function parseApplicationEnvelopeAppendResult(
  value: unknown,
  currentCommandValue: unknown,
): ApplicationEnvelopeAppendResult {
  const parsed = parseApplicationAppendPhaseResult(value, currentCommandValue);
  if (parsed.status === "accepted") return publicAcceptance(parsed.acceptance);
  if (
    parsed.status === "pending" ||
    parsed.status === "blocked-by-pending" ||
    parsed.status === "miss" ||
    parsed.status === "retry" ||
    parsed.status === "retired"
  ) {
    throw invalid("Application append has not reached a terminal result.");
  }
  return parsed;
}

function requireReplayMatchesCurrentCommand(
  replay: "none" | "http" | "envelope" | "blocked",
  current: AtomicApplicationAppendCommand,
  admitted: AtomicApplicationAppendCommand,
): void {
  if (replay === "blocked") {
    if (
      current.realmId !== admitted.realmId ||
      current.semanticIdentity.conversationId !==
        admitted.semanticIdentity.conversationId
    ) {
      throw invalid("Recovered blocker belongs to another conversation lane.");
    }
    return;
  }
  if (
    current.realmId !== admitted.realmId ||
    !applicationEnvelopeSemanticallyEqual(
      admitted.semanticIdentity,
      current.semanticIdentity,
    )
  ) {
    throw invalid("Persistence returned another envelope's acceptance.");
  }
  if (
    replay === "none" &&
    computeAtomicApplicationAppendCommandDigest(current) !==
      computeAtomicApplicationAppendCommandDigest(admitted)
  ) {
    throw invalid("A new acceptance must bind the exact admitted command.");
  }
  if (
    replay === "http" &&
    (current.idempotencyKey !== admitted.idempotencyKey ||
      current.requestCommitment !== admitted.requestCommitment)
  ) {
    throw invalid("HTTP replay is detached from its immutable commitment.");
  }
}

function parseReplayClassification(
  value: unknown,
  allowBlocked: false,
): "none" | "http" | "envelope";
function parseReplayClassification(
  value: unknown,
  allowBlocked: true,
): "none" | "http" | "envelope" | "blocked";
function parseReplayClassification(
  value: unknown,
  allowBlocked: boolean,
): "none" | "http" | "envelope" | "blocked" {
  if (
    value !== "none" &&
    value !== "http" &&
    value !== "envelope" &&
    (!allowBlocked || value !== "blocked")
  ) {
    throw invalid("Application append replay classification is unsupported.");
  }
  return value;
}

function parseStoredCheckpointSignatureEvidence(
  value: unknown,
  envelope: StoredApplicationEnvelope,
  pending: Pick<
    AcceptedApplicationAppendIntent,
    "admissionCommand" | "priorSnapshot"
  >,
): DeliveryCheckpointSignatureEvidence {
  const verifiedAt = parseRfc3339Millis(
    ownDataValue(value, "verifiedAt"),
    "stored checkpoint verification time",
  );
  const controller = new AbortController();
  return parseDeliveryCheckpointSignatureEvidence(
    withVerifiedStatus(value, "stored checkpoint signature evidence"),
    {
      profile: "delivery-log-checkpoint.v1",
      realmId: pending.admissionCommand.realmId,
      conversationId: envelope.conversationId,
      conversationGeneration: pending.priorSnapshot.conversation.generation,
      releaseProfileId: pending.admissionCommand.releaseProfileId,
      releaseTrustRootDigest:
        pending.admissionCommand.releaseTrustRootDigest,
      position: envelope.position,
      previousHeadHash: envelope.previousHeadHash,
      headHash: envelope.headHash,
      signingKeyId: envelope.logSigningKeyId,
      checkpointDigest: envelope.logCheckpointDigest,
      signature: envelope.logHeadSignature,
      checkpointReceivedAt: envelope.receivedAt,
      verifiedAt,
      deadline: verifiedAt,
      signal: controller.signal,
    },
  );
}

export function parseApplicationEnvelopeReceipt(
  value: unknown,
): ApplicationEnvelopeReceipt {
  const record = expectExactRecord(
    value,
    [
      "envelopeId",
      "conversationId",
      "position",
      "epoch",
      "rosterVersion",
      "sender",
      "receivedAt",
      "logHead",
    ],
    "application envelope receipt",
  );
  const sender = parseEnvelopeSender(record.sender, "receipt.sender");
  if (sender.type !== "installation") {
    throw invalid("Application receipt sender must be an installation.");
  }
  const position = parsePositiveUint63String(record.position);
  const conversationId = parseConversationId(record.conversationId);
  const log = expectExactRecord(
    record.logHead,
    [
      "position",
      "previousHeadHash",
      "headHash",
      "signingKeyId",
      "checkpointDigest",
      "signature",
    ],
    "application envelope log-head receipt",
  );
  const logPosition = parsePositiveUint63String(log.position);
  if (logPosition !== position) {
    throw invalid("Receipt and log-head positions differ.");
  }
  const previousHeadHash = parseHash32(log.previousHeadHash);
  const headHash = parseHash32(log.headHash);
  const signingKeyId = parseSigningKeyId(log.signingKeyId);
  const checkpointDigest = parseHash32(log.checkpointDigest);
  if (
    checkpointDigest !==
    computeDeliveryLogCheckpointDigest({
      conversationId,
      position,
      previousHeadHash,
      headHash,
      signingKeyId,
    })
  ) {
    throw invalid("Receipt checkpoint digest does not match its exact log head.");
  }
  return Object.freeze({
    envelopeId: parseEnvelopeId(record.envelopeId),
    conversationId,
    position,
    epoch: parseUint63String(record.epoch),
    rosterVersion: parseUint63String(record.rosterVersion),
    sender,
    receivedAt: parseRfc3339Millis(record.receivedAt),
    logHead: Object.freeze({
      position,
      previousHeadHash,
      headHash,
      signingKeyId,
      checkpointDigest,
      signature: parseEd25519Signature(log.signature),
    }),
  });
}

export function receiptFromStoredApplicationEnvelope(
  envelope: StoredApplicationEnvelope,
): ApplicationEnvelopeReceipt {
  return parseApplicationEnvelopeReceipt({
    envelopeId: envelope.envelopeId,
    conversationId: envelope.conversationId,
    position: envelope.position,
    epoch: envelope.epoch,
    rosterVersion: envelope.rosterVersion,
    sender: envelope.sender,
    receivedAt: envelope.receivedAt,
    logHead: {
      position: envelope.position,
      previousHeadHash: envelope.previousHeadHash,
      headHash: envelope.headHash,
      signingKeyId: envelope.logSigningKeyId,
      checkpointDigest: envelope.logCheckpointDigest,
      signature: envelope.logHeadSignature,
    },
  });
}

function requireUnsignedEnvelopeMatchesCommand(
  envelope: UnsignedStoredApplicationEnvelope,
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
): void {
  const identity = command.semanticIdentity;
  const append = identity.append;
  if (
    envelope.conversationId !== identity.conversationId ||
    envelope.envelopeId !== append.envelopeId ||
    envelope.envelopeBytes !== append.ciphertext ||
    envelope.envelopeSha256 !== append.envelopeSha256 ||
    envelope.epoch !== snapshot.conversation.epoch ||
    envelope.rosterVersion !== snapshot.conversation.rosterVersion ||
    envelope.sender.accountId !== identity.authenticatedSender.accountId ||
    envelope.sender.installationId !==
      identity.authenticatedSender.installationId ||
    envelope.previousHeadHash !== snapshot.conversation.currentLogHeadHash
  ) {
    throw invalid("Pending envelope is detached from its command and state.");
  }
}

function requireSignedEnvelopeMatchesPending(
  signed: StoredApplicationEnvelope,
  unsigned: UnsignedStoredApplicationEnvelope,
): void {
  const signedWithoutSignature = Object.fromEntries(
    Object.entries(signed).filter(([key]) => key !== "logHeadSignature"),
  );
  if (!sameData(signedWithoutSignature, unsigned)) {
    throw invalid("Accepted envelope differs from its durable pending intent.");
  }
}

function requireReceiptMatchesEnvelope(
  receipt: ApplicationEnvelopeReceipt,
  envelope: StoredApplicationEnvelope,
): void {
  if (
    receipt.envelopeId !== envelope.envelopeId ||
    receipt.conversationId !== envelope.conversationId ||
    receipt.position !== envelope.position ||
    receipt.epoch !== envelope.epoch ||
    receipt.rosterVersion !== envelope.rosterVersion ||
    receipt.sender.accountId !== envelope.sender.accountId ||
    receipt.sender.installationId !== envelope.sender.installationId ||
    receipt.receivedAt !== envelope.receivedAt ||
    receipt.logHead.position !== envelope.position ||
    receipt.logHead.previousHeadHash !== envelope.previousHeadHash ||
    receipt.logHead.headHash !== envelope.headHash ||
    receipt.logHead.signingKeyId !== envelope.logSigningKeyId ||
    receipt.logHead.checkpointDigest !== envelope.logCheckpointDigest ||
    receipt.logHead.signature !== envelope.logHeadSignature
  ) {
    throw invalid("Receipt does not exactly describe its accepted envelope.");
  }
}

function publicAcceptance(
  acceptance: PersistedApplicationAppendAcceptance,
): ApplicationEnvelopeAppendResult {
  if (acceptance.replay === "blocked") {
    throw invalid("A recovered blocker is not the current command's result.");
  }
  return Object.freeze({
    status: "accepted",
    receipt: acceptance.receipt,
    replay: acceptance.replay,
  });
}

interface ActiveInvocation {
  readonly startedAt: Rfc3339Millis;
  readonly context: DeliveryInvocationContext;
  readonly dispose: () => void;
}

function timestampWasObservedDuringInvocation(
  value: Rfc3339Millis,
  completedAt: Rfc3339Millis,
  invocation: ActiveInvocation,
): boolean {
  return (
    value >= invocation.startedAt &&
    value <= completedAt &&
    completedAt < invocation.context.deadline
  );
}

function phaseTimestampIsCurrent(
  ports: ProductionDeliveryPorts,
  value: Rfc3339Millis,
  invocation: ActiveInvocation,
): boolean {
  const completedAt = readClockNow(ports);
  return (
    !isUnavailable(completedAt) &&
    timestampWasObservedDuringInvocation(value, completedAt, invocation)
  );
}

function sameSignerFenceEvidenceIdentity(
  left: ApplicationAppendSignerFenceVerificationEvidence,
  right: ApplicationAppendSignerFenceVerificationEvidence,
): boolean {
  return (
    left.profile === right.profile &&
    left.status === right.status &&
    left.resolutionStatus === right.resolutionStatus &&
    left.pendingIntentDigest === right.pendingIntentDigest &&
    left.fenceGeneration === right.fenceGeneration &&
    left.fenceTokenHash === right.fenceTokenHash &&
    left.fenceRecordKeyProfile === right.fenceRecordKeyProfile &&
    left.fenceRecordDigest === right.fenceRecordDigest &&
    left.fenceRecordSigningKeyId === right.fenceRecordSigningKeyId &&
    left.fenceRecordSignatureSha256 === right.fenceRecordSignatureSha256 &&
    left.keyStatus === right.keyStatus &&
    left.recordSignatureStatus === right.recordSignatureStatus
  );
}

function sameCheckpointSignatureEvidenceIdentity(
  left: DeliveryCheckpointSignatureEvidence,
  right: DeliveryCheckpointSignatureEvidence,
): boolean {
  return (
    left.profile === right.profile &&
    left.realmId === right.realmId &&
    left.conversationId === right.conversationId &&
    left.conversationGeneration === right.conversationGeneration &&
    left.releaseProfileId === right.releaseProfileId &&
    left.releaseTrustRootDigest === right.releaseTrustRootDigest &&
    left.position === right.position &&
    left.previousHeadHash === right.previousHeadHash &&
    left.headHash === right.headHash &&
    left.signingKeyId === right.signingKeyId &&
    left.checkpointDigest === right.checkpointDigest &&
    left.signatureSha256 === right.signatureSha256 &&
    left.checkpointReceivedAt === right.checkpointReceivedAt &&
    left.keyState === right.keyState &&
    left.validFrom === right.validFrom &&
    left.validUntil === right.validUntil
  );
}

function reportInvariantIncident(
  ports: ProductionDeliveryPorts,
  command: AtomicApplicationAppendCommand,
  invocation: ActiveInvocation,
  incidentCode:
    | "checkpoint-substitution"
    | "atomic-persistence-ambiguity",
): void {
  const controller = new AbortController();
  const reportTimeout = setTimeout(() => controller.abort(), 100);
  const deadline = addMilliseconds(invocation.startedAt, 100);
  try {
    const pending = ports.invariantIncident.record(
      Object.freeze({
        incidentCode,
        conversationId: command.semanticIdentity.conversationId,
        evidenceDigest: computeAtomicApplicationAppendCommandDigest(command),
        detectedAt: invocation.startedAt,
        deadline:
          deadline < invocation.context.deadline
            ? deadline
            : invocation.context.deadline,
        signal: controller.signal,
      }),
    );
    void Promise.resolve(pending)
      .catch(() => undefined)
      .finally(() => clearTimeout(reportTimeout));
  } catch {
    clearTimeout(reportTimeout);
  }
}

const TIMED_OUT = Symbol("delivery-operation-timed-out");
const PORT_FAILED = Symbol("delivery-port-failed");

function beginInvocation(
  ports: ProductionDeliveryPorts,
): ActiveInvocation | DeliveryPortUnavailable {
  const startedAt = readClockNow(ports);
  if (isUnavailable(startedAt)) return startedAt;
  const deadline = addMilliseconds(
    startedAt,
    APPLICATION_APPEND_OPERATION_TIMEOUT_MILLISECONDS,
  );
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    APPLICATION_APPEND_OPERATION_TIMEOUT_MILLISECONDS,
  );
  return Object.freeze({
    startedAt,
    context: Object.freeze({
      invocationStartedAt: startedAt,
      deadline,
      signal: controller.signal,
    }),
    dispose: () => {
      clearTimeout(timer);
      controller.abort();
    },
  });
}

async function callBounded(
  operation: () => Promise<unknown>,
  invocation: ActiveInvocation,
): Promise<unknown | typeof TIMED_OUT | typeof PORT_FAILED> {
  if (invocation.context.signal.aborted) return TIMED_OUT;
  let removeAbortListener: () => void = () => {};
  const aborted = new Promise<typeof TIMED_OUT>((resolve) => {
    const onAbort = () => resolve(TIMED_OUT);
    invocation.context.signal.addEventListener("abort", onAbort, { once: true });
    removeAbortListener = () =>
      invocation.context.signal.removeEventListener("abort", onAbort);
  });
  try {
    return await Promise.race([operation(), aborted]);
  } catch {
    return PORT_FAILED;
  } finally {
    removeAbortListener();
  }
}

function readClockNow(
  ports: ProductionDeliveryPorts,
): Rfc3339Millis | DeliveryPortUnavailable {
  try {
    const value = ports.clock.now();
    if (readStatus(value) === "unavailable") {
      return parseDeliveryPortUnavailable(value);
    }
    return parseRfc3339Millis(value, "delivery clock");
  } catch {
    return malformedDependency();
  }
}

function addMilliseconds(
  value: Rfc3339Millis,
  milliseconds: number,
): Rfc3339Millis {
  return parseRfc3339Millis(
    new Date(Date.parse(value) + milliseconds).toISOString(),
  );
}

function parseAppendResultRejection(
  value: unknown,
): ApplicationAppendRejectionReason | LabAdapterRejectionReason {
  if (
    typeof value === "string" &&
    LAB_ADAPTER_REJECTION_REASONS.includes(
      value as LabAdapterRejectionReason,
    )
  ) {
    return value as LabAdapterRejectionReason;
  }
  return parseApplicationAppendRejectionReason(value);
}

function ownDataValue(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${key} is unavailable on a plain data record.`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) {
    throw invalid(`${key} must be an own data property.`);
  }
  return descriptor.value;
}

function withVerifiedStatus(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${label} must be a plain data record.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalid(`${label} must be a plain data record.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const entries: [string, unknown][] = [];
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || key === "status") {
      throw invalid(`${label} has an unexpected shape.`);
    }
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      descriptor.value === undefined
    ) {
      throw invalid(`${label} must contain only defined data properties.`);
    }
    entries.push([key, descriptor.value]);
  }
  return Object.freeze({ status: "verified", ...Object.fromEntries(entries) });
}

function readStatus(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, "status");
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

function isUnavailable(
  value: unknown,
): value is DeliveryPortUnavailable {
  return readStatus(value) === "unavailable";
}

function rejected(
  reasonCode:
    | ApplicationAppendRejectionReason
    | LabAdapterRejectionReason,
): ApplicationEnvelopeAppendResult {
  return Object.freeze({ status: "rejected", reasonCode });
}

function malformedDependency(): DeliveryPortUnavailable {
  return Object.freeze({
    status: "unavailable",
    reasonCode: "malformed-dependency-response",
  });
}

function timeoutUnavailable(): DeliveryPortUnavailable {
  return Object.freeze({ status: "unavailable", reasonCode: "timeout" });
}

function sameData(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

function invalid(message: string): DeliveryServiceValidationError {
  return new DeliveryServiceValidationError(message);
}
