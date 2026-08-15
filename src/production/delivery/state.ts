import {
  canonicalLengthPrefixed,
  sha256Bytes,
} from "./hashes";
import {
  DELIVERY_LIMIT_KEYS,
  parseDeliveryLimits,
  type DeliveryLimits,
} from "./limits";
import { DELIVERY_MANDATORY_PROPOSALS_MAX } from "./ports";
import {
  decodeFingerprint32,
  decodeHash32,
  expectExactRecord,
  parseAccountId,
  parseConversationEtag,
  parseConversationId,
  parseCredentialId,
  parseEnvelopeId,
  parseFingerprint32,
  parseHash32,
  parseInstallationId,
  parsePolicyHeadId,
  parseReleaseProfileId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  parseWitnessCheckpointId,
  ZERO_HASH32,
  type AccountId,
  type ConversationEtag,
  type ConversationId,
  type CredentialId,
  type EnvelopeId,
  type Fingerprint32,
  type Hash32,
  type InstallationId,
  type PolicyHeadId,
  type ReleaseProfileId,
  type Rfc3339Millis,
  type SigningKeyId,
  type Uint63String,
  type WitnessCheckpointId,
} from "./valueObjects";

const UINT63_MAX = (1n << 63n) - 1n;

export const APPLICATION_APPEND_QUOTA_SCOPES = [
  "installation",
  "account",
  "project",
  "conversation",
  "tenant",
] as const;

export type ApplicationAppendQuotaScope =
  (typeof APPLICATION_APPEND_QUOTA_SCOPES)[number];

export type DeliveryConversationState =
  | "provisioning"
  | "active"
  | "membership_pending"
  | "suspended"
  | "closing"
  | "closed"
  | "retention_expired"
  | "purged";

export interface LockedConversationState {
  realmId: string;
  conversationId: ConversationId;
  projectScopeId: string;
  tenantScopeId: string;
  kind: "purchase_support" | "announcement" | "community";
  generation: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  quotaPolicyDigest: Hash32;
  groupIdHash: Hash32;
  state: DeliveryConversationState;
  etag: ConversationEtag;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  /** Canonical commitment to the complete active MLS roster projection. */
  rosterHash: Hash32;
  /** Independent monotonic routing/install-state projection commitment. */
  recipientSetVersion: Uint63String;
  recipientSetHash: Hash32;
  confirmedTranscriptHash: Hash32;
  lastPosition: Uint63String;
  currentLogHeadHash: Hash32;
  currentPolicyHeadSequence: Uint63String;
  currentPolicyHeadHash: Hash32;
}

export interface LockedSenderMembership {
  conversationId: ConversationId;
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  credentialRevocationVersion: Uint63String;
  installationState: "active" | "suspended" | "revoked";
  credentialState: "active" | "suspended" | "revoked" | "superseded";
  credentialExpiresAt: Rfc3339Millis;
  joinedPosition: Uint63String;
  removedPosition: Uint63String | null;
}

export type ConversationSendRole =
  | "customer"
  | "project-staff"
  | "publisher"
  | "subscriber"
  | "member"
  | "moderator";

export interface LockedConversationSendGrant {
  conversationId: ConversationId;
  installationId: InstallationId;
  credentialId: CredentialId;
  conversationKind: LockedConversationState["kind"];
  conversationGeneration: Uint63String;
  role: ConversationSendRole;
  roleCredentialId: CredentialId;
  roleCredentialFingerprint: Fingerprint32;
  roleCredentialSubjectAccountId: AccountId;
  roleCredentialSubjectInstallationId: InstallationId;
  roleCredentialValidFrom: Rfc3339Millis;
  roleCredentialValidUntil: Rfc3339Millis;
  capability: "send_application";
  state: "active" | "suspended" | "revoked" | "expired";
  policyRevision: Uint63String;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  expiresAt: Rfc3339Millis;
  grantEvidenceDigest: Hash32;
  grantInclusionEvidenceDigest: Hash32;
}

export interface LockedWitnessedPolicyHead {
  policyHeadId: PolicyHeadId;
  conversationId: ConversationId;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  deliveryLogPosition: Uint63String;
  deliveryLogHeadHash: Hash32;
  evaluationLogPosition: Uint63String;
  evaluationLogHeadHash: Hash32;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  confirmedTranscriptHash: Hash32;
  policyRevision: Uint63String;
  signedBodySha256: Hash32;
  signerKeyId: SigningKeyId;
  signatureSha256: Hash32;
  witnessEvidenceDigest: Hash32;
  proofEvidenceDigest: Hash32;
  policyConsistencyEvidenceDigest: Hash32;
  proofVerifiedAt: Rfc3339Millis;
  issuedAt: Rfc3339Millis;
  expiresAt: Rfc3339Millis;
  witnessState: "verified" | "missing" | "inconsistent" | "stale";
  witnessCheckpointId: WitnessCheckpointId | null;
  witnessedPolicyHeadHash: Hash32 | null;
  mandatoryProposalCount: Uint63String;
  mandatoryProposalSetHash: Hash32;
  authorizedSendGrantSetHash: Hash32;
  selectedSendGrantEvidenceDigest: Hash32;
  selectedSendGrantInclusionEvidenceDigest: Hash32;
  authorizedQuotaPolicyDigest: Hash32;
  priorPolicyHeadSequence: Uint63String;
  priorPolicyHeadHash: Hash32;
  priorPolicyWitnessCheckpointId: WitnessCheckpointId;
  priorPolicyWitnessEvidenceDigest: Hash32;
}

export interface PolicyHeadProofExpectation {
  realmId: string;
  conversationGeneration: Uint63String;
  releaseTrustRootDigest: Hash32;
  purpose: "append-authorization" | "historical-page";
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  conversationId: ConversationId;
  policyHeadId: PolicyHeadId;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  deliveryLogPosition: Uint63String;
  deliveryLogHeadHash: Hash32;
  evaluationLogPosition: Uint63String;
  evaluationLogHeadHash: Hash32;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  confirmedTranscriptHash: Hash32;
  policyRevision: Uint63String;
  mandatoryProposalCount: Uint63String;
  mandatoryProposalSetHash: Hash32;
  authorizedSendGrantSetHash: Hash32;
  selectedSendGrantEvidenceDigest: Hash32;
  selectedSendGrantInclusionEvidenceDigest: Hash32;
  authorizedQuotaPolicyDigest: Hash32;
  priorPolicyHeadSequence: Uint63String;
  priorPolicyHeadHash: Hash32;
  priorPolicyWitnessCheckpointId: WitnessCheckpointId;
  priorPolicyWitnessEvidenceDigest: Hash32;
  verifiedAt: Rfc3339Millis;
}

export interface PolicyHeadProofEvidence extends PolicyHeadProofExpectation {
  profile: "conversation-policy-head-proof.v1";
  signedBodySha256: Hash32;
  signerKeyId: SigningKeyId;
  signatureSha256: Hash32;
  witnessCheckpointId: WitnessCheckpointId;
  witnessedPolicyHeadHash: Hash32;
  witnessEvidenceDigest: Hash32;
  issuedAt: Rfc3339Millis;
  expiresAt: Rfc3339Millis;
  signatureStatus: "verified";
  keyStatus: "valid-for-checkpoint";
  witnessStatus: "verified";
  freshnessStatus: "fresh" | "historical";
  currentStatus: "current" | "page-exact";
  policyConsistencyStatus: "verified";
  sendGrantInclusionStatus: "verified" | "not-requested";
  policyConsistencyEvidenceDigest: Hash32;
  evidenceDigest: Hash32;
}

export interface LockedConversationUsage {
  conversationId: ConversationId;
  envelopeCount: Uint63String;
  envelopeBytes: Uint63String;
  attachmentBytes: Uint63String;
  envelopeCountLimit: Uint63String;
  envelopeBytesLimit: Uint63String;
  attachmentBytesLimit: Uint63String;
}

export interface LockedQuotaCounter {
  scope: ApplicationAppendQuotaScope;
  scopeHash: Hash32;
  quotaName: string;
  windowStartedAt: Rfc3339Millis;
  windowSeconds: Uint63String;
  operationCount: Uint63String;
  byteCount: Uint63String;
  /** Aggregate capacity held by live, not-yet-finalized append reservations. */
  reservedOperationCount: Uint63String;
  reservedByteCount: Uint63String;
  /** Monotonic row mutation fence; never used for stale whole-row overwrite. */
  rowVersion: Uint63String;
  operationLimit: Uint63String;
  byteLimit: Uint63String;
}

export interface ApplicationAppendQuotaCapacityDelta {
  scope: ApplicationAppendQuotaScope;
  scopeHash: Hash32;
  quotaName: string;
  windowStartedAt: Rfc3339Millis;
  windowSeconds: Uint63String;
  reservationOperationCount: Uint63String;
  reservationByteCount: Uint63String;
  rowVersionBefore: Uint63String;
  rowVersionAfter: Uint63String;
}

export interface ApplicationAppendQuotaCapacityReservation
  extends ApplicationAppendQuotaCapacityDelta {
  reservationId: Hash32;
  pendingPreparationDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  state: "live" | "consumed" | "released";
}

export interface ApplicationAppendRecipientProjection {
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  recipientSetVersion: Uint63String;
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  credentialRevocationVersion: Uint63String;
  credentialState: "active" | "suspended" | "revoked" | "superseded";
  credentialExpiresAt: Rfc3339Millis;
  joinedPosition: Uint63String;
  removedPosition: Uint63String | null;
  installationState: "active" | "suspended" | "revoked";
}

export interface ApplicationAppendMlsRosterProjection {
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  rosterVersion: Uint63String;
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
}

export interface ApplicationAppendFanoutPlan {
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  rosterVersion: Uint63String;
  rosterHash: Hash32;
  recipientSetVersion: Uint63String;
  recipientSetHash: Hash32;
  position: Uint63String;
  recipientInstallationIds: readonly InstallationId[];
  recipientCount: Uint63String;
  planDigest: Hash32;
}

export interface ApplicationAppendFanoutEvidence {
  profile: "application-append-fanout.v1";
  status: "committed";
  conversationId: ConversationId;
  envelopeId: EnvelopeId;
  position: Uint63String;
  headHash: Hash32;
  rosterHash: Hash32;
  planDigest: Hash32;
  recipientCount: Uint63String;
  mailboxProjectionDigest: Hash32;
  outboxProjectionDigest: Hash32;
  evidenceDigest: Hash32;
}

export interface LockedApplicationAppendCommitProjection {
  conversation: LockedConversationState;
  usage: LockedConversationUsage;
  quotaCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
}

export interface ApplicationAppendQuotaCapacityConversion {
  quotas: readonly LockedQuotaCounter[];
  reservations: readonly ApplicationAppendQuotaCapacityReservation[];
}

export interface LockedApplicationAppendSnapshot {
  conversation: LockedConversationState;
  membership: LockedSenderMembership;
  policyHead: LockedWitnessedPolicyHead;
  sendGrant: LockedConversationSendGrant;
  pendingRemovalCount: Uint63String;
  usage: LockedConversationUsage;
  /** Derived from separately locked subject/tenant/project mapping rows. */
  quotaBindings: readonly ExpectedAppendQuotaIdentity[];
  quotas: readonly LockedQuotaCounter[];
}

export interface ApplicationAppendExpectation {
  realmId: string;
  conversationId: ConversationId;
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  credentialRevocationVersion: Uint63String;
  releaseProfileId: ReleaseProfileId;
  expectedDeliveryLimitsDigest: Hash32;
  expectedQuotaPolicyDigest: Hash32;
  expectedProjectScopeId: string;
  expectedTenantScopeId: string;
  expectedGroupIdHash: Hash32;
  ifMatch: ConversationEtag;
  expectedEpoch: Uint63String;
  expectedRosterVersion: Uint63String;
  expectedConfirmedTranscriptHash: Hash32;
  policyHeadId: PolicyHeadId;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  policyEvaluationLogPosition: Uint63String;
  policyEvaluationLogHeadHash: Hash32;
  envelopeByteLength: Uint63String;
  attachmentByteLength: Uint63String;
}

export interface ExpectedAppendQuotaIdentity {
  scope: ApplicationAppendQuotaScope;
  scopeHash: Hash32;
  quotaName: string;
  windowStartedAt: Rfc3339Millis;
  windowSeconds: Uint63String;
  operationLimit: Uint63String;
  byteLimit: Uint63String;
}

export const APPLICATION_APPEND_REJECTION_REASONS = [
  "conversation-not-active",
  "conversation-state-invalid",
  "conversation-state-changed",
  "sender-membership-inactive",
  "sender-credential-mismatch",
  "sender-credential-inactive",
  "sender-credential-expired",
  "send-grant-invalid",
  "policy-head-not-current",
  "policy-head-not-witnessed",
  "policy-head-expired",
  "mandatory-proposal-pending",
  "removal-pending",
  "counter-exhausted",
  "quota-exceeded",
] as const;

export type ApplicationAppendRejectionReason =
  (typeof APPLICATION_APPEND_REJECTION_REASONS)[number];

export type LockedApplicationAppendDecision =
  | {
      status: "allowed";
      nextPosition: Uint63String;
      nextUsage: LockedConversationUsage;
      quotaCapacityDeltas: readonly ApplicationAppendQuotaCapacityDelta[];
      postReservationQuotas: readonly LockedQuotaCounter[];
    }
  | {
      status: "rejected";
      reasonCode: ApplicationAppendRejectionReason;
    };

export class DeliveryStateValidationError extends Error {
  readonly code = "invalid_delivery_state";

  constructor(message: string) {
    super(message);
    this.name = "DeliveryStateValidationError";
  }
}

export const LOCKED_APPLICATION_APPEND_SNAPSHOT_DIGEST_DOMAIN =
  "jb-msg-locked-application-append-snapshot/v1" as const;
export const POLICY_HEAD_PROOF_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-policy-head-proof-evidence/v1" as const;
export const DELIVERY_LIMITS_DIGEST_DOMAIN =
  "jb-msg-delivery-limits/v1" as const;
export const APPLICATION_APPEND_QUOTA_SCOPE_HASH_DOMAIN =
  "jb-msg-application-append-quota-scope/v1" as const;
export const APPLICATION_APPEND_QUOTA_POLICY_DIGEST_DOMAIN =
  "jb-msg-application-append-quota-policy/v1" as const;
export const APPLICATION_APPEND_QUOTA_RESERVATION_ID_DOMAIN =
  "jb-msg-application-append-quota-reservation-id/v1" as const;
export const APPLICATION_APPEND_QUOTA_RESERVATION_SET_DIGEST_DOMAIN =
  "jb-msg-application-append-quota-reservation-set/v1" as const;
export const CONVERSATION_SEND_GRANT_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-conversation-send-grant-evidence/v1" as const;
export const APPLICATION_APPEND_FANOUT_PLAN_DIGEST_DOMAIN =
  "jb-msg-application-append-fanout-plan/v1" as const;
export const APPLICATION_APPEND_RECIPIENT_SET_DIGEST_DOMAIN =
  "jb-msg-application-append-recipient-set/v1" as const;
export const APPLICATION_APPEND_MLS_ROSTER_DIGEST_DOMAIN =
  "jb-msg-application-append-mls-roster/v1" as const;
export const APPLICATION_APPEND_FANOUT_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-application-append-fanout-evidence/v1" as const;
export const APPLICATION_APPEND_MAILBOX_PROJECTION_DIGEST_DOMAIN =
  "jb-msg-application-append-mailbox-projection/v1" as const;
export const APPLICATION_APPEND_OUTBOX_PROJECTION_DIGEST_DOMAIN =
  "jb-msg-application-append-outbox-projection/v1" as const;
export const APPLICATION_APPEND_RECIPIENT_INSTALLATIONS_HARD_MAX = 2_500n;
export const APPLICATION_APPEND_PENDING_MAX_TTL_MILLISECONDS = 30_000n;
export const APPLICATION_APPEND_ADMISSION_MAX_AGE_MILLISECONDS = 15_000n;

export function computeApplicationAppendPendingExpiresAt(input: {
  snapshot: LockedApplicationAppendSnapshot;
  admissionStartedAt: Rfc3339Millis;
  authoritativeReceivedAt: Rfc3339Millis;
  activeSigningKeyValidUntil: Rfc3339Millis;
}): Rfc3339Millis {
  const snapshot = parseLockedApplicationAppendSnapshot(input.snapshot);
  const admissionStartedAt = parseRfc3339Millis(
    input.admissionStartedAt,
    "append admission start",
  );
  const receivedAt = parseRfc3339Millis(
    input.authoritativeReceivedAt,
    "authoritative append receipt time",
  );
  const signingKeyValidUntil = parseRfc3339Millis(
    input.activeSigningKeyValidUntil,
    "active signing key expiry",
  );
  const admissionMilliseconds = BigInt(Date.parse(admissionStartedAt));
  const receivedMilliseconds = BigInt(Date.parse(receivedAt));
  if (
    receivedMilliseconds < admissionMilliseconds ||
    receivedMilliseconds - admissionMilliseconds >
      APPLICATION_APPEND_ADMISSION_MAX_AGE_MILLISECONDS
  ) {
    throw invalid("Append admission start is outside the authoritative time bound.");
  }
  const bounds = [
    receivedMilliseconds + APPLICATION_APPEND_PENDING_MAX_TTL_MILLISECONDS,
    BigInt(Date.parse(snapshot.policyHead.expiresAt)),
    BigInt(Date.parse(snapshot.membership.credentialExpiresAt)),
    BigInt(Date.parse(snapshot.sendGrant.expiresAt)),
    BigInt(Date.parse(snapshot.sendGrant.roleCredentialValidUntil)),
    BigInt(Date.parse(signingKeyValidUntil)),
    ...snapshot.quotas.map(
      (quota) =>
        BigInt(Date.parse(quota.windowStartedAt)) +
        BigInt(quota.windowSeconds) * 1_000n,
    ),
  ];
  if (bounds.some((bound) => bound <= receivedMilliseconds)) {
    throw invalid("Append pending intent has no positive live interval.");
  }
  const expiresAtMilliseconds = bounds.reduce((left, right) =>
    left < right ? left : right,
  );
  return parseRfc3339Millis(
    new Date(Number(expiresAtMilliseconds)).toISOString(),
    "append pending expiry",
  );
}

export function deriveApplicationAppendFanoutPlan(input: {
  conversation: LockedConversationState;
  senderMembership: LockedSenderMembership;
  position: Uint63String;
  authoritativeReceivedAt: Rfc3339Millis;
  recipientInstallationsMax: Uint63String;
  mlsRosterProjections: readonly ApplicationAppendMlsRosterProjection[];
  recipientProjections: readonly ApplicationAppendRecipientProjection[];
}): ApplicationAppendFanoutPlan {
  const conversation = parseLockedConversationState(input.conversation);
  const membership = parseLockedSenderMembership(input.senderMembership);
  const position = parsePositiveUint63(
    input.position,
    "application fanout position",
  );
  const authoritativeReceivedAt = parseRfc3339Millis(
    input.authoritativeReceivedAt,
    "application fanout authoritative time",
  );
  const recipientInstallationsMax = parsePositiveUint63(
    input.recipientInstallationsMax,
    "application fanout recipient ceiling",
  );
  if (
    BigInt(recipientInstallationsMax) >
      APPLICATION_APPEND_RECIPIENT_INSTALLATIONS_HARD_MAX
  ) {
    throw invalid("Application fanout recipient ceiling exceeds the reviewed cap.");
  }
  const projections = parseApplicationAppendRecipientProjections(
    input.recipientProjections,
    recipientInstallationsMax,
  );
  const mlsRoster = parseApplicationAppendMlsRosterProjections(
    input.mlsRosterProjections,
    recipientInstallationsMax,
  );
  if (
    membership.conversationId !== conversation.conversationId ||
    BigInt(position) !== BigInt(conversation.lastPosition) + 1n
  ) {
    throw invalid("Application fanout is detached from its conversation lane.");
  }
  for (const projection of projections) {
    if (
      projection.conversationId !== conversation.conversationId ||
      projection.conversationGeneration !== conversation.generation ||
      projection.recipientSetVersion !== conversation.recipientSetVersion
    ) {
      throw invalid("Application fanout contains a foreign routing row.");
    }
  }
  for (const projection of mlsRoster) {
    if (
      projection.conversationId !== conversation.conversationId ||
      projection.conversationGeneration !== conversation.generation ||
      projection.rosterVersion !== conversation.rosterVersion
    ) {
      throw invalid("Application fanout contains a foreign MLS roster row.");
    }
  }
  if (computeApplicationAppendMlsRosterHash(mlsRoster) !== conversation.rosterHash) {
    throw invalid("Application fanout MLS roster is incomplete or substituted.");
  }
  const recipientSetHash = computeApplicationAppendRecipientSetHash(projections);
  if (recipientSetHash !== conversation.recipientSetHash) {
    throw invalid("Application fanout routing projection is incomplete or substituted.");
  }
  for (const rosterMember of mlsRoster) {
    const route = projections.find(
      ({ installationId }) => installationId === rosterMember.installationId,
    );
    if (!route || !sameRecipientIdentity(route, rosterMember)) {
      throw invalid("An active MLS roster member lacks its exact routing row.");
    }
  }
  const senderProjection = projections.find(
    ({ installationId }) => installationId === membership.installationId,
  );
  if (
    !senderProjection ||
    senderProjection.accountId !== membership.accountId ||
    senderProjection.credentialId !== membership.credentialId ||
    senderProjection.credentialFingerprint !== membership.credentialFingerprint ||
    senderProjection.credentialRevocationVersion !==
      membership.credentialRevocationVersion ||
    senderProjection.credentialState !== membership.credentialState ||
    senderProjection.credentialExpiresAt !== membership.credentialExpiresAt ||
    senderProjection.joinedPosition !== membership.joinedPosition ||
    membership.removedPosition !== null ||
    senderProjection.removedPosition !== membership.removedPosition ||
    senderProjection.installationState !== membership.installationState
  ) {
    throw invalid("Application fanout does not contain the exact active sender roster row.");
  }
  const recipientInstallationIds = Object.freeze(
    projections
      .filter(
        (projection) =>
          mlsRoster.some(
            (member) =>
              member.installationId === projection.installationId &&
              sameRecipientIdentity(projection, member),
          ) &&
          BigInt(projection.joinedPosition) <= BigInt(position) &&
          (projection.removedPosition === null ||
            BigInt(position) <= BigInt(projection.removedPosition)) &&
          projection.installationState === "active" &&
          projection.credentialState === "active" &&
          projection.credentialExpiresAt > authoritativeReceivedAt,
      )
      .map(({ installationId }) => installationId)
      .sort((left, right) => left.localeCompare(right)),
  );
  const recipientCount = parseUint63String(
    String(recipientInstallationIds.length),
    "application fanout recipient count",
  );
  const planDigest = computeApplicationAppendFanoutPlanDigest({
    conversationId: conversation.conversationId,
    conversationGeneration: conversation.generation,
    rosterVersion: conversation.rosterVersion,
    rosterHash: conversation.rosterHash,
    recipientSetVersion: conversation.recipientSetVersion,
    recipientSetHash,
    position,
    recipientInstallationIds,
  });
  return Object.freeze({
    conversationId: conversation.conversationId,
    conversationGeneration: conversation.generation,
    rosterVersion: conversation.rosterVersion,
    rosterHash: conversation.rosterHash,
    recipientSetVersion: conversation.recipientSetVersion,
    recipientSetHash,
    position,
    recipientInstallationIds,
    recipientCount,
    planDigest,
  });
}

export function parseApplicationAppendRecipientProjections(
  value: unknown,
  recipientInstallationsMax: Uint63String,
): readonly ApplicationAppendRecipientProjection[] {
  const maximum = BigInt(parsePositiveUint63(
    recipientInstallationsMax,
    "application recipient projection ceiling",
  ));
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length === 0 ||
    BigInt(value.length) > maximum ||
    BigInt(value.length) > APPLICATION_APPEND_RECIPIENT_INSTALLATIONS_HARD_MAX ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Application recipient projections exceed their exact bounded array.");
  }
  const parsed = value.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "conversationId",
        "conversationGeneration",
        "recipientSetVersion",
        "accountId",
        "installationId",
        "credentialId",
        "credentialFingerprint",
        "credentialRevocationVersion",
        "credentialState",
        "credentialExpiresAt",
        "joinedPosition",
        "removedPosition",
        "installationState",
      ],
      `application recipient projection ${index}`,
    );
    const removedPosition = record.removedPosition === null
      ? null
      : parsePositiveUint63(
          record.removedPosition,
          `application recipient projection ${index} removed position`,
        );
    const joinedPosition = parsePositiveUint63(
      record.joinedPosition,
      `application recipient projection ${index} joined position`,
    );
    if (
      removedPosition !== null &&
      BigInt(removedPosition) < BigInt(joinedPosition)
    ) {
      throw invalid(
        `Application recipient projection ${index} removal precedes its join.`,
      );
    }
    return Object.freeze({
      conversationId: parseConversationId(record.conversationId),
      conversationGeneration: parsePositiveUint63(
        record.conversationGeneration,
        `application recipient projection ${index} generation`,
      ),
      recipientSetVersion: parseUint63String(record.recipientSetVersion),
      accountId: parseAccountId(record.accountId),
      installationId: parseInstallationId(record.installationId),
      credentialId: parseCredentialId(record.credentialId),
      credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
      credentialRevocationVersion: parsePositiveUint63(
        record.credentialRevocationVersion,
        `application recipient projection ${index} revocation version`,
      ),
      credentialState: parseOneOf(
        record.credentialState,
        ["active", "suspended", "revoked", "superseded"] as const,
        `application recipient projection ${index} credential state`,
      ),
      credentialExpiresAt: parseRfc3339Millis(record.credentialExpiresAt),
      joinedPosition,
      removedPosition,
      installationState: parseOneOf(
        record.installationState,
        ["active", "suspended", "revoked"] as const,
        `application recipient projection ${index} installation state`,
      ),
    });
  });
  const installationIds = new Set(parsed.map(({ installationId }) => installationId));
  const credentialIds = new Set(parsed.map(({ credentialId }) => credentialId));
  if (
    installationIds.size !== parsed.length ||
    credentialIds.size !== parsed.length
  ) {
    throw invalid("Application recipient projections contain duplicate roster identities.");
  }
  return Object.freeze(
    [...parsed].sort((left, right) =>
      left.installationId.localeCompare(right.installationId),
    ),
  );
}

export function parseApplicationAppendMlsRosterProjections(
  value: unknown,
  recipientInstallationsMax: Uint63String,
): readonly ApplicationAppendMlsRosterProjection[] {
  const maximum = BigInt(parsePositiveUint63(
    recipientInstallationsMax,
    "application MLS roster ceiling",
  ));
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length === 0 ||
    BigInt(value.length) > maximum ||
    BigInt(value.length) > APPLICATION_APPEND_RECIPIENT_INSTALLATIONS_HARD_MAX ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Application MLS roster projections exceed their bounded array.");
  }
  const parsed = value.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "conversationId",
        "conversationGeneration",
        "rosterVersion",
        "accountId",
        "installationId",
        "credentialId",
        "credentialFingerprint",
      ],
      `application MLS roster projection ${index}`,
    );
    return Object.freeze({
      conversationId: parseConversationId(record.conversationId),
      conversationGeneration: parsePositiveUint63(record.conversationGeneration, "MLS roster generation"),
      rosterVersion: parseUint63String(record.rosterVersion),
      accountId: parseAccountId(record.accountId),
      installationId: parseInstallationId(record.installationId),
      credentialId: parseCredentialId(record.credentialId),
      credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
    });
  });
  if (
    new Set(parsed.map(({ installationId }) => installationId)).size !== parsed.length ||
    new Set(parsed.map(({ credentialId }) => credentialId)).size !== parsed.length
  ) {
    throw invalid("Application MLS roster projections contain duplicate identities.");
  }
  return Object.freeze([...parsed].sort((left, right) =>
    left.installationId.localeCompare(right.installationId),
  ));
}

export function computeApplicationAppendRecipientSetHash(
  projectionsValue: readonly ApplicationAppendRecipientProjection[],
): Hash32 {
  const ceiling = parseUint63String(
    String(projectionsValue.length),
    "application recipient-set projection length",
  );
  const projections = parseApplicationAppendRecipientProjections(
    projectionsValue,
    ceiling,
  );
  const fields: Uint8Array[] = [];
  for (const projection of projections) {
    fields.push(
      utf8(projection.conversationId),
      utf8(projection.conversationGeneration),
      utf8(projection.recipientSetVersion),
      utf8(projection.accountId),
      utf8(projection.installationId),
      utf8(projection.credentialId),
      decodeFingerprint32(projection.credentialFingerprint),
      utf8(projection.credentialRevocationVersion),
      utf8(projection.credentialState),
      utf8(projection.credentialExpiresAt),
      utf8(projection.joinedPosition),
      encodeNullableText(projection.removedPosition),
      utf8(projection.installationState),
    );
  }
  return sha256Bytes(
    utf8(APPLICATION_APPEND_RECIPIENT_SET_DIGEST_DOMAIN),
    canonicalLengthPrefixed(...fields),
  );
}

export function computeApplicationAppendMlsRosterHash(
  projectionsValue: readonly ApplicationAppendMlsRosterProjection[],
): Hash32 {
  const ceiling = parseUint63String(
    String(projectionsValue.length),
    "application MLS roster length",
  );
  const projections = parseApplicationAppendMlsRosterProjections(
    projectionsValue,
    ceiling,
  );
  return sha256Bytes(
    utf8(APPLICATION_APPEND_MLS_ROSTER_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      ...projections.flatMap((projection) => [
        utf8(projection.conversationId),
        utf8(projection.conversationGeneration),
        utf8(projection.rosterVersion),
        utf8(projection.accountId),
        utf8(projection.installationId),
        utf8(projection.credentialId),
        decodeFingerprint32(projection.credentialFingerprint),
      ]),
    ),
  );
}

export function computeApplicationAppendFanoutPlanDigest(input: {
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  rosterVersion: Uint63String;
  rosterHash: Hash32;
  recipientSetVersion: Uint63String;
  recipientSetHash: Hash32;
  position: Uint63String;
  recipientInstallationIds: readonly InstallationId[];
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_FANOUT_PLAN_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.conversationGeneration),
      utf8(input.rosterVersion),
      decodeHash32(input.rosterHash),
      utf8(input.recipientSetVersion),
      decodeHash32(input.recipientSetHash),
      utf8(input.position),
      ...input.recipientInstallationIds.map((installationId) =>
        utf8(parseInstallationId(installationId)),
      ),
    ),
  );
}

export function parseApplicationAppendFanoutPlan(
  value: unknown,
  recipientInstallationsMax: Uint63String,
): ApplicationAppendFanoutPlan {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "conversationGeneration",
      "rosterVersion",
      "rosterHash",
      "recipientSetVersion",
      "recipientSetHash",
      "position",
      "recipientInstallationIds",
      "recipientCount",
      "planDigest",
    ],
    "application append fanout plan",
  );
  const maximum = BigInt(parsePositiveUint63(
    recipientInstallationsMax,
    "application fanout recipient ceiling",
  ));
  if (
    !Array.isArray(record.recipientInstallationIds) ||
    Object.getPrototypeOf(record.recipientInstallationIds) !== Array.prototype ||
    BigInt(record.recipientInstallationIds.length) > maximum ||
    BigInt(record.recipientInstallationIds.length) >
      APPLICATION_APPEND_RECIPIENT_INSTALLATIONS_HARD_MAX ||
    Reflect.ownKeys(record.recipientInstallationIds).length !==
      record.recipientInstallationIds.length + 1
  ) {
    throw invalid("Application fanout recipient IDs exceed their bounded array.");
  }
  const recipientInstallationIds = Object.freeze(
    record.recipientInstallationIds.map((entry, index) =>
      parseInstallationId(entry, `application fanout recipient ${index}`),
    ),
  );
  if (
    new Set(recipientInstallationIds).size !== recipientInstallationIds.length ||
    recipientInstallationIds.some(
      (entry, index) => index > 0 && recipientInstallationIds[index - 1] >= entry,
    )
  ) {
    throw invalid("Application fanout recipient IDs are not canonical sorted unique.");
  }
  const parsed = Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    conversationGeneration: parsePositiveUint63(record.conversationGeneration, "fanout generation"),
    rosterVersion: parseUint63String(record.rosterVersion),
    rosterHash: parseHash32(record.rosterHash),
    recipientSetVersion: parseUint63String(record.recipientSetVersion),
    recipientSetHash: parseHash32(record.recipientSetHash),
    position: parsePositiveUint63(record.position, "fanout position"),
    recipientInstallationIds,
    recipientCount: parseUint63String(record.recipientCount),
    planDigest: parseHash32(record.planDigest),
  });
  if (
    BigInt(parsed.recipientCount) !== BigInt(recipientInstallationIds.length) ||
    parsed.planDigest !== computeApplicationAppendFanoutPlanDigest(parsed)
  ) {
    throw invalid("Application fanout plan count or digest is inconsistent.");
  }
  return parsed;
}

export function parseApplicationAppendFanoutEvidence(
  value: unknown,
  expected: {
    plan: ApplicationAppendFanoutPlan;
    envelopeId: EnvelopeId;
    headHash: Hash32;
  },
): ApplicationAppendFanoutEvidence {
  const record = expectExactRecord(
    value,
    [
      "profile",
      "status",
      "conversationId",
      "envelopeId",
      "position",
      "headHash",
      "rosterHash",
      "planDigest",
      "recipientCount",
      "mailboxProjectionDigest",
      "outboxProjectionDigest",
      "evidenceDigest",
    ],
    "application append fanout evidence",
  );
  const envelopeId = parseEnvelopeId(record.envelopeId);
  const headHash = parseHash32(record.headHash);
  const mailboxProjectionDigest = computeApplicationAppendMailboxProjectionDigest({
    plan: expected.plan,
    envelopeId,
  });
  const outboxProjectionDigest = computeApplicationAppendOutboxProjectionDigest({
    conversationId: expected.plan.conversationId,
    envelopeId,
    position: expected.plan.position,
    headHash,
  });
  const parsed = Object.freeze({
    profile: record.profile,
    status: record.status,
    conversationId: parseConversationId(record.conversationId),
    envelopeId,
    position: parsePositiveUint63(record.position, "fanout evidence position"),
    headHash,
    rosterHash: parseHash32(record.rosterHash),
    planDigest: parseHash32(record.planDigest),
    recipientCount: parseUint63String(record.recipientCount),
    mailboxProjectionDigest: parseHash32(record.mailboxProjectionDigest),
    outboxProjectionDigest: parseHash32(record.outboxProjectionDigest),
    evidenceDigest: parseHash32(record.evidenceDigest),
  });
  if (
    parsed.profile !== "application-append-fanout.v1" ||
    parsed.status !== "committed" ||
    parsed.conversationId !== expected.plan.conversationId ||
    parsed.envelopeId !== expected.envelopeId ||
    parsed.position !== expected.plan.position ||
    parsed.headHash !== expected.headHash ||
    parsed.rosterHash !== expected.plan.rosterHash ||
    parsed.planDigest !== expected.plan.planDigest ||
    parsed.recipientCount !== expected.plan.recipientCount ||
    parsed.mailboxProjectionDigest !== mailboxProjectionDigest ||
    parsed.outboxProjectionDigest !== outboxProjectionDigest ||
    parsed.evidenceDigest !== computeApplicationAppendFanoutEvidenceDigest({
      conversationId: parsed.conversationId,
      envelopeId,
      position: parsed.position,
      headHash,
      rosterHash: parsed.rosterHash,
      planDigest: parsed.planDigest,
      recipientCount: parsed.recipientCount,
      mailboxProjectionDigest,
      outboxProjectionDigest,
    })
  ) {
    throw invalid("Application append fanout evidence is detached or incomplete.");
  }
  return parsed as ApplicationAppendFanoutEvidence;
}

export function computeApplicationAppendMailboxProjectionDigest(input: {
  plan: ApplicationAppendFanoutPlan;
  envelopeId: EnvelopeId;
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_MAILBOX_PROJECTION_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.plan.conversationId),
      utf8(input.envelopeId),
      utf8(input.plan.position),
      decodeHash32(input.plan.planDigest),
      utf8(input.plan.recipientCount),
      ...input.plan.recipientInstallationIds.map((id) => utf8(id)),
    ),
  );
}

export function computeApplicationAppendOutboxProjectionDigest(input: {
  conversationId: ConversationId;
  envelopeId: EnvelopeId;
  position: Uint63String;
  headHash: Hash32;
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_OUTBOX_PROJECTION_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.envelopeId),
      utf8(input.position),
      decodeHash32(input.headHash),
    ),
  );
}

export function computeApplicationAppendFanoutEvidenceDigest(input: Omit<
  ApplicationAppendFanoutEvidence,
  "profile" | "status" | "evidenceDigest"
>): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_FANOUT_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.envelopeId),
      utf8(input.position),
      decodeHash32(input.headHash),
      decodeHash32(input.rosterHash),
      decodeHash32(input.planDigest),
      utf8(input.recipientCount),
      decodeHash32(input.mailboxProjectionDigest),
      decodeHash32(input.outboxProjectionDigest),
      utf8("committed"),
    ),
  );
}

export function parseApplicationAppendRejectionReason(
  value: unknown,
): ApplicationAppendRejectionReason {
  return parseOneOf(
    value,
    APPLICATION_APPEND_REJECTION_REASONS,
    "application append rejection reason",
  );
}

export function computeDeliveryLimitsDigest(value: DeliveryLimits): Hash32 {
  const limits = parseDeliveryLimits(value);
  return sha256Bytes(
    utf8(DELIVERY_LIMITS_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      ...DELIVERY_LIMIT_KEYS.flatMap((key) => [utf8(key), utf8(limits[key])]),
    ),
  );
}

export function computeApplicationAppendQuotaScopeHash(input: {
  realmId: string;
  scope: ApplicationAppendQuotaScope;
  subjectId: string;
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_QUOTA_SCOPE_HASH_DOMAIN),
    canonicalLengthPrefixed(
      utf8(parsePolicyRealmId(input.realmId)),
      utf8(parseOneOf(input.scope, APPLICATION_APPEND_QUOTA_SCOPES, "quota scope")),
      utf8(parseScopeSubjectId(input.subjectId, "quota subject ID")),
    ),
  );
}

export function computeApplicationAppendQuotaPolicyDigest(
  value: readonly ExpectedAppendQuotaIdentity[],
): Hash32 {
  const bindings = parseExpectedQuotaIdentities(value);
  return sha256Bytes(
    utf8(APPLICATION_APPEND_QUOTA_POLICY_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      ...bindings.flatMap((binding) => [
        utf8(binding.scope),
        utf8(binding.quotaName),
        utf8(binding.windowSeconds),
        utf8(binding.operationLimit),
        utf8(binding.byteLimit),
      ]),
    ),
  );
}

export function computeConversationSendGrantEvidenceDigest(
  value: Omit<
    LockedConversationSendGrant,
    "grantEvidenceDigest" | "grantInclusionEvidenceDigest"
  >,
): Hash32 {
  return sha256Bytes(
    utf8(CONVERSATION_SEND_GRANT_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(value.conversationId),
      utf8(value.installationId),
      utf8(value.credentialId),
      utf8(value.conversationKind),
      utf8(value.conversationGeneration),
      utf8(value.role),
      utf8(value.roleCredentialId),
      decodeFingerprint32(value.roleCredentialFingerprint),
      utf8(value.roleCredentialSubjectAccountId),
      utf8(value.roleCredentialSubjectInstallationId),
      utf8(value.roleCredentialValidFrom),
      utf8(value.roleCredentialValidUntil),
      utf8(value.capability),
      utf8(value.state),
      utf8(value.policyRevision),
      utf8(value.policyHeadSequence),
      decodeHash32(value.policyHeadHash),
      utf8(value.expiresAt),
    ),
  );
}

export function parsePolicyHeadProofEvidence(
  value: unknown,
  expectedValue: PolicyHeadProofExpectation,
): PolicyHeadProofEvidence {
  const expected = parsePolicyHeadProofExpectation(expectedValue);
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationGeneration",
      "releaseTrustRootDigest",
      "purpose",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "conversationId",
      "policyHeadId",
      "policyHeadSequence",
      "policyHeadHash",
      "deliveryLogPosition",
      "deliveryLogHeadHash",
      "evaluationLogPosition",
      "evaluationLogHeadHash",
      "epoch",
      "rosterVersion",
      "confirmedTranscriptHash",
      "policyRevision",
      "mandatoryProposalCount",
      "mandatoryProposalSetHash",
      "authorizedSendGrantSetHash",
      "selectedSendGrantEvidenceDigest",
      "selectedSendGrantInclusionEvidenceDigest",
      "authorizedQuotaPolicyDigest",
      "priorPolicyHeadSequence",
      "priorPolicyHeadHash",
      "priorPolicyWitnessCheckpointId",
      "priorPolicyWitnessEvidenceDigest",
      "signedBodySha256",
      "signerKeyId",
      "signatureSha256",
      "witnessCheckpointId",
      "witnessedPolicyHeadHash",
      "witnessEvidenceDigest",
      "issuedAt",
      "expiresAt",
      "verifiedAt",
      "signatureStatus",
      "keyStatus",
      "witnessStatus",
      "freshnessStatus",
      "currentStatus",
      "policyConsistencyStatus",
      "policyConsistencyEvidenceDigest",
      "sendGrantInclusionStatus",
      "evidenceDigest",
    ],
    "policy-head proof evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "conversation-policy-head-proof.v1"
  ) {
    throw invalid("Policy-head proof was not verified under the v1 profile.");
  }
  const parsed: PolicyHeadProofEvidence = Object.freeze({
    profile: "conversation-policy-head-proof.v1",
    realmId: parsePolicyRealmId(record.realmId),
    conversationGeneration: parsePositiveUint63(
      record.conversationGeneration,
      "policy proof conversation generation",
    ),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "policy proof release trust-root digest",
    ),
    purpose: parseOneOf(
      record.purpose,
      ["append-authorization", "historical-page"] as const,
      "policy proof purpose",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "policy proof delivery limits digest",
    ),
    conversationId: parseConversationId(record.conversationId),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyHeadSequence: parsePositiveUint63(
      record.policyHeadSequence,
      "policy proof head sequence",
    ),
    policyHeadHash: parseNonZeroHash32(
      record.policyHeadHash,
      "policy proof head hash",
    ),
    deliveryLogPosition: parseUint63String(
      record.deliveryLogPosition,
      "policy proof delivery-log position",
    ),
    deliveryLogHeadHash: parseHash32(
      record.deliveryLogHeadHash,
      "policy proof delivery-log head hash",
    ),
    evaluationLogPosition: parseUint63String(
      record.evaluationLogPosition,
      "policy proof evaluation-log position",
    ),
    evaluationLogHeadHash: parseHash32(
      record.evaluationLogHeadHash,
      "policy proof evaluation-log head hash",
    ),
    epoch: parseUint63String(record.epoch, "policy proof epoch"),
    rosterVersion: parseUint63String(
      record.rosterVersion,
      "policy proof roster version",
    ),
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "policy proof confirmed transcript hash",
    ),
    policyRevision: parsePositiveUint63(
      record.policyRevision,
      "policy proof revision",
    ),
    mandatoryProposalCount: parseMandatoryProposalCount(
      record.mandatoryProposalCount,
      "policy proof mandatory proposal count",
    ),
    mandatoryProposalSetHash: parseHash32(
      record.mandatoryProposalSetHash,
      "policy proof mandatory proposal set hash",
    ),
    authorizedSendGrantSetHash: parseHash32(
      record.authorizedSendGrantSetHash,
      "policy proof authorized send-grant set hash",
    ),
    selectedSendGrantEvidenceDigest: parseHash32(
      record.selectedSendGrantEvidenceDigest,
      "policy proof selected send-grant evidence digest",
    ),
    selectedSendGrantInclusionEvidenceDigest: parseHash32(
      record.selectedSendGrantInclusionEvidenceDigest,
      "policy proof selected send-grant inclusion evidence digest",
    ),
    authorizedQuotaPolicyDigest: parseHash32(
      record.authorizedQuotaPolicyDigest,
      "policy proof authorized quota policy digest",
    ),
    priorPolicyHeadSequence: parseUint63String(
      record.priorPolicyHeadSequence,
      "prior policy-head sequence",
    ),
    priorPolicyHeadHash: parseHash32(
      record.priorPolicyHeadHash,
      "prior policy-head hash",
    ),
    priorPolicyWitnessCheckpointId: parseWitnessCheckpointId(
      record.priorPolicyWitnessCheckpointId,
    ),
    priorPolicyWitnessEvidenceDigest: parseHash32(
      record.priorPolicyWitnessEvidenceDigest,
      "prior policy witness evidence digest",
    ),
    signedBodySha256: parseHash32(
      record.signedBodySha256,
      "policy proof signed-body SHA-256",
    ),
    signerKeyId: parseSigningKeyId(record.signerKeyId, "policy signer key ID"),
    signatureSha256: parseHash32(
      record.signatureSha256,
      "policy signature SHA-256",
    ),
    witnessCheckpointId: parseWitnessCheckpointId(record.witnessCheckpointId),
    witnessedPolicyHeadHash: parseHash32(
      record.witnessedPolicyHeadHash,
      "witnessed policy-head hash",
    ),
    witnessEvidenceDigest: parseHash32(
      record.witnessEvidenceDigest,
      "policy witness evidence digest",
    ),
    issuedAt: parseRfc3339Millis(record.issuedAt, "policy proof issuedAt"),
    expiresAt: parseRfc3339Millis(record.expiresAt, "policy proof expiresAt"),
    verifiedAt: parseRfc3339Millis(record.verifiedAt, "policy proof verifiedAt"),
    signatureStatus: parseRequiredLiteral(record.signatureStatus, "verified"),
    keyStatus: parseRequiredLiteral(record.keyStatus, "valid-for-checkpoint"),
    witnessStatus: parseRequiredLiteral(record.witnessStatus, "verified"),
    freshnessStatus: parseOneOf(
      record.freshnessStatus,
      ["fresh", "historical"] as const,
      "policy proof freshness status",
    ),
    currentStatus: parseOneOf(
      record.currentStatus,
      ["current", "page-exact"] as const,
      "policy proof current status",
    ),
    policyConsistencyStatus: parseRequiredLiteral(
      record.policyConsistencyStatus,
      "verified",
    ),
    sendGrantInclusionStatus: parseOneOf(
      record.sendGrantInclusionStatus,
      ["verified", "not-requested"] as const,
      "send-grant inclusion status",
    ),
    policyConsistencyEvidenceDigest: parseHash32(
      record.policyConsistencyEvidenceDigest,
      "policy consistency evidence digest",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "policy proof evidence digest",
    ),
  });
  for (const key of Object.keys(expected) as (keyof PolicyHeadProofExpectation)[]) {
    if (parsed[key] !== expected[key]) {
      throw invalid("Policy-head proof evidence was substituted.");
    }
  }
  if (
    parsed.witnessedPolicyHeadHash !== parsed.policyHeadHash ||
    (parsed.purpose === "append-authorization" &&
      (BigInt(parsed.policyHeadSequence) <
        BigInt(parsed.priorPolicyHeadSequence) ||
        (parsed.policyHeadSequence === parsed.priorPolicyHeadSequence &&
          parsed.policyHeadHash !== parsed.priorPolicyHeadHash))) ||
    BigInt(parsed.deliveryLogPosition) > BigInt(parsed.evaluationLogPosition) ||
    (parsed.deliveryLogPosition === "0") !==
      (parsed.deliveryLogHeadHash === ZERO_HASH32) ||
    (parsed.evaluationLogPosition === "0") !==
      (parsed.evaluationLogHeadHash === ZERO_HASH32) ||
    parsed.issuedAt > parsed.verifiedAt ||
    parsed.expiresAt <= parsed.issuedAt ||
    Date.parse(parsed.expiresAt) - Date.parse(parsed.issuedAt) > 300_000
  ) {
    throw invalid("Policy-head proof validity or witness binding is inconsistent.");
  }
  if (
    (parsed.purpose === "append-authorization" &&
      (parsed.freshnessStatus !== "fresh" ||
        parsed.currentStatus !== "current" ||
        parsed.sendGrantInclusionStatus !== "verified" ||
        parsed.selectedSendGrantEvidenceDigest === ZERO_HASH32 ||
        parsed.selectedSendGrantInclusionEvidenceDigest === ZERO_HASH32 ||
        parsed.expiresAt <= parsed.verifiedAt)) ||
    (parsed.purpose === "historical-page" &&
      (parsed.freshnessStatus !== "historical" ||
        parsed.currentStatus !== "page-exact" ||
        parsed.sendGrantInclusionStatus !== "not-requested" ||
        parsed.selectedSendGrantEvidenceDigest !== ZERO_HASH32 ||
        parsed.selectedSendGrantInclusionEvidenceDigest !== ZERO_HASH32))
  ) {
    throw invalid("Policy-head proof status is invalid for its purpose.");
  }
  if (parsed.evidenceDigest !== computePolicyHeadProofEvidenceDigest(parsed)) {
    throw invalid("Policy-head proof evidence digest is inconsistent.");
  }
  return parsed;
}

export function computePolicyHeadProofEvidenceDigest(
  input: Omit<PolicyHeadProofEvidence, "profile" | "evidenceDigest">,
): Hash32 {
  return sha256Bytes(
    utf8(POLICY_HEAD_PROOF_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationGeneration),
      decodeHash32(input.releaseTrustRootDigest),
      utf8(input.releaseProfileId),
      decodeHash32(input.deliveryLimitsDigest),
      utf8(input.purpose),
      utf8(input.conversationId),
      utf8(input.policyHeadId),
      utf8(input.policyHeadSequence),
      decodeHash32(input.policyHeadHash),
      utf8(input.deliveryLogPosition),
      decodeHash32(input.deliveryLogHeadHash),
      utf8(input.evaluationLogPosition),
      decodeHash32(input.evaluationLogHeadHash),
      utf8(input.epoch),
      utf8(input.rosterVersion),
      decodeHash32(input.confirmedTranscriptHash),
      utf8(input.policyRevision),
      utf8(input.mandatoryProposalCount),
      decodeHash32(input.mandatoryProposalSetHash),
      decodeHash32(input.authorizedSendGrantSetHash),
      decodeHash32(input.selectedSendGrantEvidenceDigest),
      decodeHash32(input.selectedSendGrantInclusionEvidenceDigest),
      decodeHash32(input.authorizedQuotaPolicyDigest),
      utf8(input.priorPolicyHeadSequence),
      decodeHash32(input.priorPolicyHeadHash),
      utf8(input.priorPolicyWitnessCheckpointId),
      decodeHash32(input.priorPolicyWitnessEvidenceDigest),
      decodeHash32(input.signedBodySha256),
      utf8(input.signerKeyId),
      decodeHash32(input.signatureSha256),
      utf8(input.witnessCheckpointId),
      decodeHash32(input.witnessedPolicyHeadHash),
      decodeHash32(input.witnessEvidenceDigest),
      utf8(input.issuedAt),
      utf8(input.expiresAt),
      utf8(input.verifiedAt),
      utf8(input.signatureStatus),
      utf8(input.keyStatus),
      utf8(input.witnessStatus),
      utf8(input.freshnessStatus),
      utf8(input.currentStatus),
      utf8(input.policyConsistencyStatus),
      decodeHash32(input.policyConsistencyEvidenceDigest),
      utf8(input.sendGrantInclusionStatus),
    ),
  );
}

function parsePolicyHeadProofExpectation(
  value: PolicyHeadProofExpectation,
): PolicyHeadProofExpectation {
  const record = expectExactRecord(
    value,
    [
      "realmId",
      "conversationGeneration",
      "releaseTrustRootDigest",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "purpose",
      "conversationId",
      "policyHeadId",
      "policyHeadSequence",
      "policyHeadHash",
      "deliveryLogPosition",
      "deliveryLogHeadHash",
      "evaluationLogPosition",
      "evaluationLogHeadHash",
      "epoch",
      "rosterVersion",
      "confirmedTranscriptHash",
      "policyRevision",
      "mandatoryProposalCount",
      "mandatoryProposalSetHash",
      "authorizedSendGrantSetHash",
      "selectedSendGrantEvidenceDigest",
      "selectedSendGrantInclusionEvidenceDigest",
      "authorizedQuotaPolicyDigest",
      "priorPolicyHeadSequence",
      "priorPolicyHeadHash",
      "priorPolicyWitnessCheckpointId",
      "priorPolicyWitnessEvidenceDigest",
      "verifiedAt",
    ],
    "policy-head proof expectation",
  );
  const parsed = Object.freeze({
    realmId: parsePolicyRealmId(record.realmId),
    conversationGeneration: parsePositiveUint63(
      record.conversationGeneration,
      "expected policy conversation generation",
    ),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "expected policy release trust-root digest",
    ),
    purpose: parseOneOf(
      record.purpose,
      ["append-authorization", "historical-page"] as const,
      "expected policy proof purpose",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "expected policy delivery limits digest",
    ),
    conversationId: parseConversationId(record.conversationId),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyHeadSequence: parsePositiveUint63(
      record.policyHeadSequence,
      "expected policy-head sequence",
    ),
    policyHeadHash: parseNonZeroHash32(
      record.policyHeadHash,
      "expected policy-head hash",
    ),
    deliveryLogPosition: parseUint63String(
      record.deliveryLogPosition,
      "expected policy delivery-log position",
    ),
    deliveryLogHeadHash: parseHash32(
      record.deliveryLogHeadHash,
      "expected policy delivery-log head hash",
    ),
    evaluationLogPosition: parseUint63String(
      record.evaluationLogPosition,
      "expected policy evaluation-log position",
    ),
    evaluationLogHeadHash: parseHash32(
      record.evaluationLogHeadHash,
      "expected policy evaluation-log head hash",
    ),
    epoch: parseUint63String(record.epoch, "expected policy epoch"),
    rosterVersion: parseUint63String(
      record.rosterVersion,
      "expected policy roster version",
    ),
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "expected policy confirmed transcript hash",
    ),
    policyRevision: parsePositiveUint63(
      record.policyRevision,
      "expected policy revision",
    ),
    mandatoryProposalCount: parseMandatoryProposalCount(
      record.mandatoryProposalCount,
      "expected mandatory proposal count",
    ),
    mandatoryProposalSetHash: parseHash32(
      record.mandatoryProposalSetHash,
      "expected mandatory proposal set hash",
    ),
    authorizedSendGrantSetHash: parseHash32(
      record.authorizedSendGrantSetHash,
      "expected authorized send-grant set hash",
    ),
    selectedSendGrantEvidenceDigest: parseHash32(
      record.selectedSendGrantEvidenceDigest,
      "expected selected send-grant evidence digest",
    ),
    selectedSendGrantInclusionEvidenceDigest: parseHash32(
      record.selectedSendGrantInclusionEvidenceDigest,
      "expected selected send-grant inclusion evidence digest",
    ),
    authorizedQuotaPolicyDigest: parseHash32(
      record.authorizedQuotaPolicyDigest,
      "expected authorized quota policy digest",
    ),
    priorPolicyHeadSequence: parseUint63String(
      record.priorPolicyHeadSequence,
      "expected prior policy-head sequence",
    ),
    priorPolicyHeadHash: parseHash32(
      record.priorPolicyHeadHash,
      "expected prior policy-head hash",
    ),
    priorPolicyWitnessCheckpointId: parseWitnessCheckpointId(
      record.priorPolicyWitnessCheckpointId,
    ),
    priorPolicyWitnessEvidenceDigest: parseHash32(
      record.priorPolicyWitnessEvidenceDigest,
      "expected prior policy witness evidence digest",
    ),
    verifiedAt: parseRfc3339Millis(record.verifiedAt, "expected proof time"),
  });
  if (
    (parsed.priorPolicyHeadSequence === "0") !==
    (parsed.priorPolicyHeadHash === ZERO_HASH32) ||
    (parsed.deliveryLogPosition === "0") !==
      (parsed.deliveryLogHeadHash === ZERO_HASH32) ||
    (parsed.evaluationLogPosition === "0") !==
      (parsed.evaluationLogHeadHash === ZERO_HASH32) ||
    (parsed.purpose === "append-authorization" &&
      (parsed.selectedSendGrantEvidenceDigest === ZERO_HASH32 ||
        parsed.selectedSendGrantInclusionEvidenceDigest === ZERO_HASH32)) ||
    (parsed.purpose === "historical-page" &&
      (parsed.selectedSendGrantEvidenceDigest !== ZERO_HASH32 ||
        parsed.selectedSendGrantInclusionEvidenceDigest !== ZERO_HASH32))
  ) {
    throw invalid("Policy proof expectation has an invalid anchor or grant sentinel.");
  }
  return parsed;
}

export function parseLockedApplicationAppendSnapshot(
  value: unknown,
): LockedApplicationAppendSnapshot {
  const record = expectExactRecord(
    value,
    [
      "conversation",
      "membership",
      "policyHead",
      "sendGrant",
      "pendingRemovalCount",
      "usage",
      "quotaBindings",
      "quotas",
    ],
    "locked application append snapshot",
  );

  const conversation = parseLockedConversationState(record.conversation);
  const membership = parseLockedSenderMembership(record.membership);
  const policyHead = parseLockedWitnessedPolicyHead(record.policyHead);
  const sendGrant = parseLockedConversationSendGrant(record.sendGrant);
  const pendingRemovalCount = parseUint63String(
    record.pendingRemovalCount,
    "pending removal count",
  );
  const usage = parseLockedConversationUsage(record.usage);
  const quotaBindings = parseExpectedQuotaIdentities(record.quotaBindings);
  const quotas = parseLockedQuotaCounters(record.quotas);

  if (
    membership.conversationId !== conversation.conversationId ||
    policyHead.conversationId !== conversation.conversationId ||
    sendGrant.conversationId !== conversation.conversationId ||
    usage.conversationId !== conversation.conversationId
  ) {
    throw invalid("Locked rows do not belong to one conversation.");
  }
  if (
    (conversation.lastPosition === "0") !==
    (conversation.currentLogHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Locked conversation position and log head are inconsistent.");
  }
  if (
    BigInt(policyHead.deliveryLogPosition) > BigInt(conversation.lastPosition) ||
    (policyHead.deliveryLogPosition === "0") !==
      (policyHead.deliveryLogHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Locked policy head has an invalid delivery-log anchor.");
  }
  if (
    BigInt(policyHead.evaluationLogPosition) > BigInt(conversation.lastPosition) ||
    BigInt(policyHead.deliveryLogPosition) >
      BigInt(policyHead.evaluationLogPosition) ||
    (policyHead.evaluationLogPosition === "0") !==
      (policyHead.evaluationLogHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Locked policy proof has an invalid evaluation-log anchor.");
  }
  if (
    policyHead.witnessState === "verified" &&
    policyHead.proofEvidenceDigest !==
      computePolicyHeadProofEvidenceDigest({
        realmId: conversation.realmId,
        conversationGeneration: conversation.generation,
        releaseTrustRootDigest: conversation.releaseTrustRootDigest,
        purpose: "append-authorization",
        releaseProfileId: conversation.releaseProfileId,
        deliveryLimitsDigest: conversation.deliveryLimitsDigest,
        conversationId: policyHead.conversationId,
        policyHeadId: policyHead.policyHeadId,
        policyHeadSequence: policyHead.policyHeadSequence,
        policyHeadHash: policyHead.policyHeadHash,
        deliveryLogPosition: policyHead.deliveryLogPosition,
        deliveryLogHeadHash: policyHead.deliveryLogHeadHash,
        evaluationLogPosition: policyHead.evaluationLogPosition,
        evaluationLogHeadHash: policyHead.evaluationLogHeadHash,
        epoch: policyHead.epoch,
        rosterVersion: policyHead.rosterVersion,
        confirmedTranscriptHash: policyHead.confirmedTranscriptHash,
        policyRevision: policyHead.policyRevision,
        mandatoryProposalCount: policyHead.mandatoryProposalCount,
        mandatoryProposalSetHash: policyHead.mandatoryProposalSetHash,
        authorizedSendGrantSetHash: policyHead.authorizedSendGrantSetHash,
        selectedSendGrantEvidenceDigest:
          policyHead.selectedSendGrantEvidenceDigest,
        selectedSendGrantInclusionEvidenceDigest:
          policyHead.selectedSendGrantInclusionEvidenceDigest,
        authorizedQuotaPolicyDigest:
          policyHead.authorizedQuotaPolicyDigest,
        priorPolicyHeadSequence: policyHead.priorPolicyHeadSequence,
        priorPolicyHeadHash: policyHead.priorPolicyHeadHash,
        priorPolicyWitnessCheckpointId:
          policyHead.priorPolicyWitnessCheckpointId,
        priorPolicyWitnessEvidenceDigest:
          policyHead.priorPolicyWitnessEvidenceDigest,
        signedBodySha256: policyHead.signedBodySha256,
        signerKeyId: policyHead.signerKeyId,
        signatureSha256: policyHead.signatureSha256,
        witnessCheckpointId: policyHead.witnessCheckpointId!,
        witnessedPolicyHeadHash: policyHead.witnessedPolicyHeadHash!,
        witnessEvidenceDigest: policyHead.witnessEvidenceDigest,
        issuedAt: policyHead.issuedAt,
        expiresAt: policyHead.expiresAt,
        verifiedAt: policyHead.proofVerifiedAt,
        signatureStatus: "verified",
        keyStatus: "valid-for-checkpoint",
        witnessStatus: "verified",
        freshnessStatus: "fresh",
        currentStatus: "current",
        policyConsistencyStatus: "verified",
        policyConsistencyEvidenceDigest:
          policyHead.policyConsistencyEvidenceDigest,
        sendGrantInclusionStatus: "verified",
      })
  ) {
    throw invalid("Locked policy-head proof evidence digest is inconsistent.");
  }
  assertQuotaBindingsMatchCounters(quotaBindings, quotas);
  for (const binding of quotaBindings) {
    const subjectId = quotaSubjectId(conversation, membership, binding.scope);
    if (
      binding.scopeHash !==
      computeApplicationAppendQuotaScopeHash({
        realmId: conversation.realmId,
        scope: binding.scope,
        subjectId,
      })
    ) {
      throw invalid("Append quota scope hash is detached from its locked subject.");
    }
  }
  if (
    computeApplicationAppendQuotaPolicyDigest(quotaBindings) !==
    conversation.quotaPolicyDigest
  ) {
    throw invalid("Append quota configuration is detached from its signed policy.");
  }
  if (
    sendGrant.grantEvidenceDigest !==
      computeConversationSendGrantEvidenceDigest(sendGrant) ||
    policyHead.selectedSendGrantEvidenceDigest !== sendGrant.grantEvidenceDigest ||
    policyHead.selectedSendGrantInclusionEvidenceDigest !==
      sendGrant.grantInclusionEvidenceDigest ||
    policyHead.authorizedQuotaPolicyDigest !== conversation.quotaPolicyDigest
  ) {
    throw invalid("Conversation send grant is detached from its policy proof.");
  }

  return Object.freeze({
    conversation,
    membership,
    policyHead,
    sendGrant,
    pendingRemovalCount,
    usage,
    quotaBindings,
    quotas,
  });
}

/**
 * Builds the sole permitted current-head authorization overlay from a
 * separately verified policy proof. The persisted preflight snapshot remains
 * the CAS source; callers digest this returned snapshot independently for the
 * reserve authorization fence.
 */
export function refreshLockedApplicationAppendAuthorizationSnapshot(input: {
  persistedSnapshot: LockedApplicationAppendSnapshot;
  policyHeadProofEvidence: PolicyHeadProofEvidence;
}): LockedApplicationAppendSnapshot {
  const snapshot = parseLockedApplicationAppendSnapshot(
    input.persistedSnapshot,
  );
  const { conversation, policyHead, sendGrant } = snapshot;
  const proof = parsePolicyHeadProofEvidence(
    Object.freeze({ status: "verified", ...input.policyHeadProofEvidence }),
    {
    realmId: conversation.realmId,
    conversationGeneration: conversation.generation,
    releaseTrustRootDigest: conversation.releaseTrustRootDigest,
    purpose: "append-authorization",
    releaseProfileId: conversation.releaseProfileId,
    deliveryLimitsDigest: conversation.deliveryLimitsDigest,
    conversationId: conversation.conversationId,
    policyHeadId: policyHead.policyHeadId,
    policyHeadSequence: conversation.currentPolicyHeadSequence,
    policyHeadHash: conversation.currentPolicyHeadHash,
    deliveryLogPosition: policyHead.deliveryLogPosition,
    deliveryLogHeadHash: policyHead.deliveryLogHeadHash,
    evaluationLogPosition: conversation.lastPosition,
    evaluationLogHeadHash: conversation.currentLogHeadHash,
    epoch: conversation.epoch,
    rosterVersion: conversation.rosterVersion,
    confirmedTranscriptHash: conversation.confirmedTranscriptHash,
    policyRevision: policyHead.policyRevision,
    mandatoryProposalCount: policyHead.mandatoryProposalCount,
    mandatoryProposalSetHash: policyHead.mandatoryProposalSetHash,
    authorizedSendGrantSetHash: policyHead.authorizedSendGrantSetHash,
    selectedSendGrantEvidenceDigest: sendGrant.grantEvidenceDigest,
    selectedSendGrantInclusionEvidenceDigest:
      sendGrant.grantInclusionEvidenceDigest,
    authorizedQuotaPolicyDigest: conversation.quotaPolicyDigest,
    priorPolicyHeadSequence: policyHead.priorPolicyHeadSequence,
    priorPolicyHeadHash: policyHead.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId:
      policyHead.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      policyHead.priorPolicyWitnessEvidenceDigest,
      verifiedAt: input.policyHeadProofEvidence.verifiedAt,
    },
  );
  return parseLockedApplicationAppendSnapshot({
    ...snapshot,
    policyHead: {
      ...policyHead,
      deliveryLogPosition: proof.deliveryLogPosition,
      deliveryLogHeadHash: proof.deliveryLogHeadHash,
      evaluationLogPosition: proof.evaluationLogPosition,
      evaluationLogHeadHash: proof.evaluationLogHeadHash,
      signedBodySha256: proof.signedBodySha256,
      signerKeyId: proof.signerKeyId,
      signatureSha256: proof.signatureSha256,
      witnessEvidenceDigest: proof.witnessEvidenceDigest,
      proofEvidenceDigest: proof.evidenceDigest,
      policyConsistencyEvidenceDigest:
        proof.policyConsistencyEvidenceDigest,
      proofVerifiedAt: proof.verifiedAt,
      issuedAt: proof.issuedAt,
      expiresAt: proof.expiresAt,
      witnessState: "verified",
      witnessCheckpointId: proof.witnessCheckpointId,
      witnessedPolicyHeadHash: proof.witnessedPolicyHeadHash,
      selectedSendGrantEvidenceDigest:
        proof.selectedSendGrantEvidenceDigest,
      selectedSendGrantInclusionEvidenceDigest:
        proof.selectedSendGrantInclusionEvidenceDigest,
      authorizedQuotaPolicyDigest: proof.authorizedQuotaPolicyDigest,
    },
  });
}

/** Canonical digest used only for the preflight-to-reservation CAS fence. */
export function computeLockedApplicationAppendSnapshotDigest(
  value: LockedApplicationAppendSnapshot,
): Hash32 {
  const snapshot = parseLockedApplicationAppendSnapshot(value);
  const { conversation, membership, policyHead, sendGrant, usage } = snapshot;
  const fields: Uint8Array[] = [
    utf8(conversation.realmId),
    utf8(conversation.conversationId),
    utf8(conversation.projectScopeId),
    utf8(conversation.tenantScopeId),
    utf8(conversation.kind),
    utf8(conversation.generation),
    utf8(conversation.releaseProfileId),
    decodeHash32(conversation.deliveryLimitsDigest),
    decodeHash32(conversation.releaseTrustRootDigest),
    decodeHash32(conversation.quotaPolicyDigest),
    decodeHash32(conversation.groupIdHash),
    utf8(conversation.state),
    utf8(conversation.etag),
    utf8(conversation.epoch),
    utf8(conversation.rosterVersion),
    decodeHash32(conversation.rosterHash),
    utf8(conversation.recipientSetVersion),
    decodeHash32(conversation.recipientSetHash),
    decodeHash32(conversation.confirmedTranscriptHash),
    utf8(conversation.lastPosition),
    decodeHash32(conversation.currentLogHeadHash),
    utf8(conversation.currentPolicyHeadSequence),
    decodeHash32(conversation.currentPolicyHeadHash),
    utf8(membership.conversationId),
    utf8(membership.accountId),
    utf8(membership.installationId),
    utf8(membership.credentialId),
    decodeFingerprint32(membership.credentialFingerprint),
    utf8(membership.credentialRevocationVersion),
    utf8(membership.installationState),
    utf8(membership.credentialState),
    utf8(membership.credentialExpiresAt),
    utf8(membership.joinedPosition),
    encodeNullableText(membership.removedPosition),
    utf8(policyHead.policyHeadId),
    utf8(policyHead.conversationId),
    utf8(policyHead.policyHeadSequence),
    decodeHash32(policyHead.policyHeadHash),
    utf8(policyHead.deliveryLogPosition),
    decodeHash32(policyHead.deliveryLogHeadHash),
    utf8(policyHead.evaluationLogPosition),
    decodeHash32(policyHead.evaluationLogHeadHash),
    utf8(policyHead.epoch),
    utf8(policyHead.rosterVersion),
    decodeHash32(policyHead.confirmedTranscriptHash),
    utf8(policyHead.policyRevision),
    decodeHash32(policyHead.signedBodySha256),
    utf8(policyHead.signerKeyId),
    decodeHash32(policyHead.signatureSha256),
    decodeHash32(policyHead.witnessEvidenceDigest),
    decodeHash32(policyHead.proofEvidenceDigest),
    decodeHash32(policyHead.policyConsistencyEvidenceDigest),
    utf8(policyHead.proofVerifiedAt),
    utf8(policyHead.issuedAt),
    utf8(policyHead.expiresAt),
    utf8(policyHead.witnessState),
    encodeNullableText(policyHead.witnessCheckpointId),
    encodeNullableHash(policyHead.witnessedPolicyHeadHash),
    utf8(policyHead.mandatoryProposalCount),
    decodeHash32(policyHead.mandatoryProposalSetHash),
    decodeHash32(policyHead.authorizedSendGrantSetHash),
    decodeHash32(policyHead.selectedSendGrantEvidenceDigest),
    decodeHash32(policyHead.selectedSendGrantInclusionEvidenceDigest),
    decodeHash32(policyHead.authorizedQuotaPolicyDigest),
    utf8(policyHead.priorPolicyHeadSequence),
    decodeHash32(policyHead.priorPolicyHeadHash),
    utf8(policyHead.priorPolicyWitnessCheckpointId),
    decodeHash32(policyHead.priorPolicyWitnessEvidenceDigest),
    utf8(sendGrant.conversationId),
    utf8(sendGrant.installationId),
    utf8(sendGrant.credentialId),
    utf8(sendGrant.conversationKind),
    utf8(sendGrant.conversationGeneration),
    utf8(sendGrant.role),
    utf8(sendGrant.roleCredentialId),
    decodeFingerprint32(sendGrant.roleCredentialFingerprint),
    utf8(sendGrant.roleCredentialSubjectAccountId),
    utf8(sendGrant.roleCredentialSubjectInstallationId),
    utf8(sendGrant.roleCredentialValidFrom),
    utf8(sendGrant.roleCredentialValidUntil),
    utf8(sendGrant.capability),
    utf8(sendGrant.state),
    utf8(sendGrant.policyRevision),
    utf8(sendGrant.policyHeadSequence),
    decodeHash32(sendGrant.policyHeadHash),
    utf8(sendGrant.expiresAt),
    decodeHash32(sendGrant.grantEvidenceDigest),
    decodeHash32(sendGrant.grantInclusionEvidenceDigest),
    utf8(snapshot.pendingRemovalCount),
    utf8(usage.conversationId),
    utf8(usage.envelopeCount),
    utf8(usage.envelopeBytes),
    utf8(usage.attachmentBytes),
    utf8(usage.envelopeCountLimit),
    utf8(usage.envelopeBytesLimit),
    utf8(usage.attachmentBytesLimit),
  ];
  for (const binding of snapshot.quotaBindings) {
    fields.push(
      utf8(binding.scope),
      decodeHash32(binding.scopeHash),
      utf8(binding.quotaName),
      utf8(binding.windowStartedAt),
      utf8(binding.windowSeconds),
      utf8(binding.operationLimit),
      utf8(binding.byteLimit),
    );
  }
  for (const quota of snapshot.quotas) {
    fields.push(
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
    );
  }
  return sha256Bytes(
    utf8(LOCKED_APPLICATION_APPEND_SNAPSHOT_DIGEST_DOMAIN),
    canonicalLengthPrefixed(...fields),
  );
}

export function parseApplicationAppendExpectation(
  value: unknown,
): ApplicationAppendExpectation {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "realmId",
      "accountId",
      "installationId",
      "credentialId",
      "credentialFingerprint",
      "credentialRevocationVersion",
      "releaseProfileId",
      "expectedDeliveryLimitsDigest",
      "expectedQuotaPolicyDigest",
      "expectedProjectScopeId",
      "expectedTenantScopeId",
      "expectedGroupIdHash",
      "ifMatch",
      "expectedEpoch",
      "expectedRosterVersion",
      "expectedConfirmedTranscriptHash",
      "policyHeadId",
      "policyHeadSequence",
      "policyHeadHash",
      "policyEvaluationLogPosition",
      "policyEvaluationLogHeadHash",
      "envelopeByteLength",
      "attachmentByteLength",
    ],
    "application append expectation",
  );

  const envelopeByteLength = parseUint63String(
    record.envelopeByteLength,
    "envelope byte length",
  );
  if (envelopeByteLength === "0") {
    throw invalid("Envelope byte length must be positive.");
  }

  return {
    realmId: parsePolicyRealmId(record.realmId),
    conversationId: parseConversationId(record.conversationId),
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    credentialId: parseCredentialId(record.credentialId),
    credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
    credentialRevocationVersion: parseUint63String(
      record.credentialRevocationVersion,
      "credential revocation version",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    expectedDeliveryLimitsDigest: parseHash32(
      record.expectedDeliveryLimitsDigest,
      "expected delivery limits digest",
    ),
    expectedQuotaPolicyDigest: parseHash32(
      record.expectedQuotaPolicyDigest,
      "expected append quota policy digest",
    ),
    expectedProjectScopeId: parseScopeSubjectId(
      record.expectedProjectScopeId,
      "expected project quota subject ID",
    ),
    expectedTenantScopeId: parseScopeSubjectId(
      record.expectedTenantScopeId,
      "expected tenant quota subject ID",
    ),
    expectedGroupIdHash: parseHash32(
      record.expectedGroupIdHash,
      "expected MLS group ID hash",
    ),
    ifMatch: parseConversationEtag(record.ifMatch),
    expectedEpoch: parseUint63String(record.expectedEpoch, "expected epoch"),
    expectedRosterVersion: parseUint63String(
      record.expectedRosterVersion,
      "expected roster version",
    ),
    expectedConfirmedTranscriptHash: parseHash32(
      record.expectedConfirmedTranscriptHash,
      "expected confirmed transcript hash",
    ),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyHeadSequence: parseUint63String(
      record.policyHeadSequence,
      "policy head sequence",
    ),
    policyHeadHash: parseNonZeroHash32(record.policyHeadHash, "policy head hash"),
    policyEvaluationLogPosition: parseUint63String(
      record.policyEvaluationLogPosition,
      "policy evaluation-log position",
    ),
    policyEvaluationLogHeadHash: parseHash32(
      record.policyEvaluationLogHeadHash,
      "policy evaluation-log head hash",
    ),
    envelopeByteLength,
    attachmentByteLength: parseUint63String(
      record.attachmentByteLength,
      "attachment byte length",
    ),
  };
}

/**
 * Evaluates only values read while the conversation, usage, and quota rows are
 * locked. It does not inspect MLS bytes, verify a witness proof, sign a head,
 * persist state, or mint a receipt.
 */
export function evaluateLockedApplicationAppend(
  snapshot: LockedApplicationAppendSnapshot,
  expectation: ApplicationAppendExpectation,
  now: Rfc3339Millis,
): LockedApplicationAppendDecision {
  const { conversation, membership, policyHead, usage } = snapshot;

  if (conversation.state !== "active") {
    return reject("conversation-not-active");
  }

  const canonicalEtag = `"e${conversation.epoch}-r${conversation.rosterVersion}"`;
  if (conversation.etag !== canonicalEtag) {
    return reject("conversation-state-invalid");
  }

  if (
    expectation.realmId !== conversation.realmId ||
    expectation.conversationId !== conversation.conversationId ||
    expectation.releaseProfileId !== conversation.releaseProfileId ||
    expectation.expectedDeliveryLimitsDigest !==
      conversation.deliveryLimitsDigest ||
    expectation.expectedQuotaPolicyDigest !== conversation.quotaPolicyDigest ||
    expectation.expectedProjectScopeId !== conversation.projectScopeId ||
    expectation.expectedTenantScopeId !== conversation.tenantScopeId ||
    expectation.expectedGroupIdHash !== conversation.groupIdHash ||
    expectation.ifMatch !== conversation.etag ||
    expectation.expectedEpoch !== conversation.epoch ||
    expectation.expectedRosterVersion !== conversation.rosterVersion ||
    expectation.expectedConfirmedTranscriptHash !==
      conversation.confirmedTranscriptHash
  ) {
    return reject("conversation-state-changed");
  }

  if (
    membership.conversationId !== conversation.conversationId ||
    membership.removedPosition !== null ||
    BigInt(membership.joinedPosition) > BigInt(conversation.lastPosition)
  ) {
    return reject("sender-membership-inactive");
  }

  if (
    expectation.accountId !== membership.accountId ||
    expectation.installationId !== membership.installationId ||
    expectation.credentialId !== membership.credentialId ||
    expectation.credentialFingerprint !== membership.credentialFingerprint ||
    expectation.credentialRevocationVersion !==
      membership.credentialRevocationVersion
  ) {
    return reject("sender-credential-mismatch");
  }

  if (
    membership.installationState !== "active" ||
    membership.credentialState !== "active"
  ) {
    return reject("sender-credential-inactive");
  }
  if (membership.credentialExpiresAt <= now) {
    return reject("sender-credential-expired");
  }

  const { sendGrant } = snapshot;
  if (
    sendGrant.conversationId !== conversation.conversationId ||
    sendGrant.installationId !== membership.installationId ||
    sendGrant.credentialId !== membership.credentialId ||
    sendGrant.roleCredentialSubjectAccountId !== membership.accountId ||
    sendGrant.roleCredentialSubjectInstallationId !==
      membership.installationId ||
    sendGrant.roleCredentialValidFrom > now ||
    sendGrant.roleCredentialValidUntil <= now ||
    sendGrant.roleCredentialValidUntil <= sendGrant.roleCredentialValidFrom ||
    sendGrant.grantEvidenceDigest !==
      computeConversationSendGrantEvidenceDigest(sendGrant) ||
    sendGrant.conversationKind !== conversation.kind ||
    sendGrant.conversationGeneration !== conversation.generation ||
    sendGrant.capability !== "send_application" ||
    sendGrant.state !== "active" ||
    sendGrant.expiresAt <= now ||
    !roleMaySend(conversation.kind, sendGrant.role)
  ) {
    return reject("send-grant-invalid");
  }

  if (
    policyHead.conversationId !== conversation.conversationId ||
    policyHead.policyHeadId !== expectation.policyHeadId ||
    policyHead.policyHeadSequence !== expectation.policyHeadSequence ||
    policyHead.policyHeadHash !== expectation.policyHeadHash ||
    policyHead.policyHeadSequence !== conversation.currentPolicyHeadSequence ||
    policyHead.policyHeadHash !== conversation.currentPolicyHeadHash ||
    expectation.policyEvaluationLogPosition !== conversation.lastPosition ||
    expectation.policyEvaluationLogHeadHash !==
      conversation.currentLogHeadHash ||
    policyHead.evaluationLogPosition !==
      expectation.policyEvaluationLogPosition ||
    policyHead.evaluationLogHeadHash !== expectation.policyEvaluationLogHeadHash ||
    policyHead.epoch !== conversation.epoch ||
    policyHead.rosterVersion !== conversation.rosterVersion ||
    policyHead.confirmedTranscriptHash !== conversation.confirmedTranscriptHash
  ) {
    return reject("policy-head-not-current");
  }

  if (
    policyHead.witnessState !== "verified" ||
    policyHead.witnessCheckpointId === null ||
    policyHead.witnessedPolicyHeadHash !== policyHead.policyHeadHash
  ) {
    return reject("policy-head-not-witnessed");
  }
  if (
    policyHead.issuedAt > now ||
    policyHead.proofVerifiedAt > now ||
    policyHead.expiresAt <= now
  ) {
    return reject("policy-head-expired");
  }
  if (
    sendGrant.policyRevision !== policyHead.policyRevision ||
    sendGrant.policyHeadSequence !== policyHead.policyHeadSequence ||
    sendGrant.policyHeadHash !== policyHead.policyHeadHash
    || policyHead.selectedSendGrantEvidenceDigest !==
      sendGrant.grantEvidenceDigest
    || policyHead.selectedSendGrantInclusionEvidenceDigest !==
      sendGrant.grantInclusionEvidenceDigest
    || policyHead.authorizedQuotaPolicyDigest !== conversation.quotaPolicyDigest
  ) {
    return reject("send-grant-invalid");
  }
  if (policyHead.mandatoryProposalCount !== "0") {
    return reject("mandatory-proposal-pending");
  }
  if (snapshot.pendingRemovalCount !== "0") {
    return reject("removal-pending");
  }

  const envelopeBytes = BigInt(expectation.envelopeByteLength);
  const attachmentBytes = BigInt(expectation.attachmentByteLength);
  const totalChargedBytes = envelopeBytes + attachmentBytes;
  const nextPosition = addUint63(conversation.lastPosition, 1n);
  const nextEnvelopeCount = addUint63(usage.envelopeCount, 1n);
  const nextEnvelopeBytes = addUint63(usage.envelopeBytes, envelopeBytes);
  const nextAttachmentBytes = addUint63(
    usage.attachmentBytes,
    attachmentBytes,
  );
  if (
    nextPosition === null ||
    nextEnvelopeCount === null ||
    nextEnvelopeBytes === null ||
    nextAttachmentBytes === null
  ) {
    return reject("counter-exhausted");
  }

  if (
    BigInt(nextEnvelopeCount) > BigInt(usage.envelopeCountLimit) ||
    BigInt(nextEnvelopeBytes) > BigInt(usage.envelopeBytesLimit) ||
    BigInt(nextAttachmentBytes) > BigInt(usage.attachmentBytesLimit)
  ) {
    return reject("quota-exceeded");
  }

  const quotaCapacityDeltas: ApplicationAppendQuotaCapacityDelta[] = [];
  const postReservationQuotas: LockedQuotaCounter[] = [];
  for (const quota of snapshot.quotas) {
    const expectedQuota = snapshot.quotaBindings.find(
      ({ scope }) => scope === quota.scope,
    );
    if (
      !expectedQuota ||
      expectedQuota.scopeHash !== quota.scopeHash ||
      expectedQuota.quotaName !== quota.quotaName ||
      expectedQuota.windowStartedAt !== quota.windowStartedAt ||
      expectedQuota.windowSeconds !== quota.windowSeconds ||
      !isWithinQuotaWindow(quota, now)
    ) {
      return reject("quota-exceeded");
    }
    const operationCount = addUint63(quota.operationCount, 1n);
    const byteCount = addUint63(quota.byteCount, totalChargedBytes);
    const reservedOperationCount = addUint63(
      quota.reservedOperationCount,
      1n,
    );
    const reservedByteCount = addUint63(
      quota.reservedByteCount,
      totalChargedBytes,
    );
    const rowVersionAfter = addUint63(quota.rowVersion, 1n);
    if (
      operationCount === null ||
      byteCount === null ||
      reservedOperationCount === null ||
      reservedByteCount === null ||
      rowVersionAfter === null
    ) {
      return reject("counter-exhausted");
    }
    if (
      BigInt(quota.operationCount) + BigInt(reservedOperationCount) >
        BigInt(quota.operationLimit) ||
      BigInt(quota.byteCount) + BigInt(reservedByteCount) >
        BigInt(quota.byteLimit)
    ) {
      return reject("quota-exceeded");
    }
    quotaCapacityDeltas.push({
      scope: quota.scope,
      scopeHash: quota.scopeHash,
      quotaName: quota.quotaName,
      windowStartedAt: quota.windowStartedAt,
      windowSeconds: quota.windowSeconds,
      reservationOperationCount: "1" as Uint63String,
      reservationByteCount: totalChargedBytes.toString() as Uint63String,
      rowVersionBefore: quota.rowVersion,
      rowVersionAfter,
    });
    postReservationQuotas.push({
      ...quota,
      reservedOperationCount,
      reservedByteCount,
      rowVersion: rowVersionAfter,
    });
  }

  return {
    status: "allowed",
    nextPosition,
    nextUsage: {
      ...usage,
      envelopeCount: nextEnvelopeCount,
      envelopeBytes: nextEnvelopeBytes,
      attachmentBytes: nextAttachmentBytes,
    },
    quotaCapacityDeltas: Object.freeze(quotaCapacityDeltas),
    postReservationQuotas: Object.freeze(postReservationQuotas),
  };
}

/**
 * Recomputes the only legal locked-state transition for one application
 * append. Persistence adapters call this before accepting a reservation plan.
 */
export function validateLockedApplicationAppendStateTransition(input: {
  priorSnapshot: LockedApplicationAppendSnapshot;
  expectation: ApplicationAppendExpectation;
  authoritativeReceivedAt: Rfc3339Millis;
  nextHeadHash: Hash32;
  preparedNextConversation: LockedConversationState;
  preparedNextUsage: LockedConversationUsage;
  quotaCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
}): LockedApplicationAppendCommitProjection {
  const prior = parseLockedApplicationAppendSnapshot(input.priorSnapshot);
  const expectation = parseApplicationAppendExpectation(input.expectation);
  const authoritativeReceivedAt = parseRfc3339Millis(
    input.authoritativeReceivedAt,
    "authoritative append time",
  );
  const nextHeadHash = parseHash32(input.nextHeadHash, "next log head hash");
  if (nextHeadHash === ZERO_HASH32) {
    throw invalid("An appended envelope cannot produce the zero log head.");
  }
  const decision = evaluateLockedApplicationAppend(
    prior,
    expectation,
    authoritativeReceivedAt,
  );
  if (decision.status !== "allowed") {
    throw invalid(`Rejected append cannot transition state: ${decision.reasonCode}.`);
  }
  const expectedConversation = parseLockedConversationState({
    ...prior.conversation,
    lastPosition: decision.nextPosition,
    currentLogHeadHash: nextHeadHash,
  });
  const preparedConversation = parseLockedConversationState(
    input.preparedNextConversation,
  );
  const preparedUsage = parseLockedConversationUsage(input.preparedNextUsage);
  const reservations = parseApplicationAppendQuotaCapacityReservations(
    input.quotaCapacityReservations,
  );
  if (
    !sameCanonicalObject(preparedConversation, expectedConversation) ||
    !sameCanonicalObject(preparedUsage, decision.nextUsage) ||
    reservations.some(({ state }) => state !== "live") ||
    !sameCanonicalObject(
      reservations.map(quotaReservationDelta),
      decision.quotaCapacityDeltas,
    )
  ) {
    throw invalid("Prepared append state transition contains an unauthorized change.");
  }
  return Object.freeze({
    conversation: preparedConversation,
    usage: preparedUsage,
    quotaCapacityReservations: reservations,
  });
}

export function parseLockedApplicationAppendCommitProjection(
  value: unknown,
): LockedApplicationAppendCommitProjection {
  const record = expectExactRecord(
    value,
    ["conversation", "usage", "quotaCapacityReservations"],
    "locked application append commit projection",
  );
  return Object.freeze({
    conversation: parseLockedConversationState(record.conversation),
    usage: parseLockedConversationUsage(record.usage),
    quotaCapacityReservations:
      parseApplicationAppendQuotaCapacityReservations(
        record.quotaCapacityReservations,
      ),
  });
}

export function validateLockedApplicationAppendQuotaReservationTransition(input: {
  priorSnapshot: LockedApplicationAppendSnapshot;
  expectation: ApplicationAppendExpectation;
  authoritativeReceivedAt: Rfc3339Millis;
  quotaCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
  preparedPostReservationQuotas: readonly LockedQuotaCounter[];
}): readonly LockedQuotaCounter[] {
  const prior = parseLockedApplicationAppendSnapshot(input.priorSnapshot);
  const expectation = parseApplicationAppendExpectation(input.expectation);
  const at = parseRfc3339Millis(input.authoritativeReceivedAt);
  const decision = evaluateLockedApplicationAppend(prior, expectation, at);
  if (decision.status !== "allowed") {
    throw invalid(`Rejected append cannot reserve quota: ${decision.reasonCode}.`);
  }
  const reservations = parseApplicationAppendQuotaCapacityReservations(
    input.quotaCapacityReservations,
  );
  const prepared = parseLockedQuotaCounters(input.preparedPostReservationQuotas);
  if (
    reservations.some(({ state }) => state !== "live") ||
    !sameCanonicalObject(
      reservations.map(quotaReservationDelta),
      decision.quotaCapacityDeltas,
    ) ||
    !sameCanonicalObject(prepared, decision.postReservationQuotas)
  ) {
    throw invalid("Prepared quota-capacity reservation transition is invalid.");
  }
  return prepared;
}

export function validateLockedApplicationAppendQuotaFinalizationTransition(input: {
  currentQuotas: readonly LockedQuotaCounter[];
  currentCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
  pendingPreparationDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  preparedFinalQuotas: readonly LockedQuotaCounter[];
  preparedFinalReservations: readonly ApplicationAppendQuotaCapacityReservation[];
}): ApplicationAppendQuotaCapacityConversion {
  return validateQuotaCapacityConversion(input, "finalize");
}

export function validateLockedApplicationAppendQuotaReleaseTransition(input: {
  currentQuotas: readonly LockedQuotaCounter[];
  currentCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
  pendingPreparationDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  preparedFinalQuotas: readonly LockedQuotaCounter[];
  preparedFinalReservations: readonly ApplicationAppendQuotaCapacityReservation[];
}): ApplicationAppendQuotaCapacityConversion {
  return validateQuotaCapacityConversion(input, "release");
}

function parseLockedConversationState(value: unknown): LockedConversationState {
  const record = expectExactRecord(
    value,
    [
      "realmId",
      "conversationId",
      "projectScopeId",
      "tenantScopeId",
      "kind",
      "generation",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "releaseTrustRootDigest",
      "quotaPolicyDigest",
      "groupIdHash",
      "state",
      "etag",
      "epoch",
      "rosterVersion",
      "rosterHash",
      "recipientSetVersion",
      "recipientSetHash",
      "confirmedTranscriptHash",
      "lastPosition",
      "currentLogHeadHash",
      "currentPolicyHeadSequence",
      "currentPolicyHeadHash",
    ],
    "locked conversation",
  );
  const state = parseConversationState(record.state);
  return {
    realmId: parsePolicyRealmId(record.realmId),
    conversationId: parseConversationId(record.conversationId),
    projectScopeId: parseScopeSubjectId(
      record.projectScopeId,
      "project quota subject ID",
    ),
    tenantScopeId: parseScopeSubjectId(
      record.tenantScopeId,
      "tenant quota subject ID",
    ),
    kind: parseOneOf(
      record.kind,
      ["purchase_support", "announcement", "community"] as const,
      "conversation kind",
    ),
    generation: parsePositiveUint63(
      record.generation,
      "conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "delivery limits digest",
    ),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "release trust-root digest",
    ),
    quotaPolicyDigest: parseHash32(
      record.quotaPolicyDigest,
      "append quota policy digest",
    ),
    groupIdHash: parseHash32(record.groupIdHash, "MLS group ID hash"),
    state,
    etag: parseConversationEtag(record.etag),
    epoch: parseUint63String(record.epoch, "conversation epoch"),
    rosterVersion: parseUint63String(
      record.rosterVersion,
      "conversation roster version",
    ),
    rosterHash: parseHash32(record.rosterHash, "conversation roster hash"),
    recipientSetVersion: parseUint63String(
      record.recipientSetVersion,
      "conversation recipient-set version",
    ),
    recipientSetHash: parseHash32(
      record.recipientSetHash,
      "conversation recipient-set hash",
    ),
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "conversation confirmed transcript hash",
    ),
    lastPosition: parseUint63String(
      record.lastPosition,
      "conversation last position",
    ),
    currentLogHeadHash: parseHash32(
      record.currentLogHeadHash,
      "conversation current log head hash",
    ),
    currentPolicyHeadSequence: parseUint63String(
      record.currentPolicyHeadSequence,
      "current policy head sequence",
    ),
    currentPolicyHeadHash: parseHash32(
      record.currentPolicyHeadHash,
      "current policy head hash",
    ),
  };
}

function parseLockedSenderMembership(value: unknown): LockedSenderMembership {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "accountId",
      "installationId",
      "credentialId",
      "credentialFingerprint",
      "credentialRevocationVersion",
      "installationState",
      "credentialState",
      "credentialExpiresAt",
      "joinedPosition",
      "removedPosition",
    ],
    "locked sender membership",
  );
  return {
    conversationId: parseConversationId(record.conversationId),
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    credentialId: parseCredentialId(record.credentialId),
    credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
    credentialRevocationVersion: parseUint63String(
      record.credentialRevocationVersion,
      "credential revocation version",
    ),
    installationState: parseOneOf(
      record.installationState,
      ["active", "suspended", "revoked"] as const,
      "installation state",
    ),
    credentialState: parseOneOf(
      record.credentialState,
      ["active", "suspended", "revoked", "superseded"] as const,
      "credential state",
    ),
    credentialExpiresAt: parseRfc3339Millis(
      record.credentialExpiresAt,
      "credential expiry",
    ),
    joinedPosition: parsePositiveUint63(
      record.joinedPosition,
      "membership joined position",
    ),
    removedPosition:
      record.removedPosition === null
        ? null
        : parsePositiveUint63(
            record.removedPosition,
            "membership removed position",
          ),
  };
}

function parseLockedConversationSendGrant(
  value: unknown,
): LockedConversationSendGrant {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "installationId",
      "credentialId",
      "conversationKind",
      "conversationGeneration",
      "role",
      "roleCredentialId",
      "roleCredentialFingerprint",
      "roleCredentialSubjectAccountId",
      "roleCredentialSubjectInstallationId",
      "roleCredentialValidFrom",
      "roleCredentialValidUntil",
      "capability",
      "state",
      "policyRevision",
      "policyHeadSequence",
      "policyHeadHash",
      "expiresAt",
      "grantEvidenceDigest",
      "grantInclusionEvidenceDigest",
    ],
    "locked conversation send grant",
  );
  if (record.capability !== "send_application") {
    throw invalid("Send grant capability is unsupported.");
  }
  return {
    conversationId: parseConversationId(record.conversationId),
    installationId: parseInstallationId(record.installationId),
    credentialId: parseCredentialId(record.credentialId),
    conversationKind: parseOneOf(
      record.conversationKind,
      ["purchase_support", "announcement", "community"] as const,
      "send grant conversation kind",
    ),
    conversationGeneration: parsePositiveUint63(
      record.conversationGeneration,
      "send grant conversation generation",
    ),
    role: parseOneOf(
      record.role,
      [
        "customer",
        "project-staff",
        "publisher",
        "subscriber",
        "member",
        "moderator",
      ] as const,
      "send grant role",
    ),
    roleCredentialId: parseCredentialId(record.roleCredentialId),
    roleCredentialFingerprint: parseFingerprint32(
      record.roleCredentialFingerprint,
    ),
    roleCredentialSubjectAccountId: parseAccountId(
      record.roleCredentialSubjectAccountId,
    ),
    roleCredentialSubjectInstallationId: parseInstallationId(
      record.roleCredentialSubjectInstallationId,
    ),
    roleCredentialValidFrom: parseRfc3339Millis(
      record.roleCredentialValidFrom,
      "role credential validFrom",
    ),
    roleCredentialValidUntil: parseRfc3339Millis(
      record.roleCredentialValidUntil,
      "role credential validUntil",
    ),
    capability: "send_application",
    state: parseOneOf(
      record.state,
      ["active", "suspended", "revoked", "expired"] as const,
      "send grant state",
    ),
    policyRevision: parsePositiveUint63(
      record.policyRevision,
      "send grant policy revision",
    ),
    policyHeadSequence: parsePositiveUint63(
      record.policyHeadSequence,
      "send grant policy-head sequence",
    ),
    policyHeadHash: parseHash32(
      record.policyHeadHash,
      "send grant policy-head hash",
    ),
    expiresAt: parseRfc3339Millis(record.expiresAt, "send grant expiry"),
    grantEvidenceDigest: parseHash32(
      record.grantEvidenceDigest,
      "send-grant evidence digest",
    ),
    grantInclusionEvidenceDigest: parseHash32(
      record.grantInclusionEvidenceDigest,
      "send-grant inclusion evidence digest",
    ),
  };
}

function parseLockedWitnessedPolicyHead(
  value: unknown,
): LockedWitnessedPolicyHead {
  const record = expectExactRecord(
    value,
    [
      "policyHeadId",
      "conversationId",
      "policyHeadSequence",
      "policyHeadHash",
      "deliveryLogPosition",
      "deliveryLogHeadHash",
      "evaluationLogPosition",
      "evaluationLogHeadHash",
      "epoch",
      "rosterVersion",
      "confirmedTranscriptHash",
      "policyRevision",
      "signedBodySha256",
      "signerKeyId",
      "signatureSha256",
      "witnessEvidenceDigest",
      "proofEvidenceDigest",
      "policyConsistencyEvidenceDigest",
      "proofVerifiedAt",
      "issuedAt",
      "expiresAt",
      "witnessState",
      "witnessCheckpointId",
      "witnessedPolicyHeadHash",
      "mandatoryProposalCount",
      "mandatoryProposalSetHash",
      "authorizedSendGrantSetHash",
      "selectedSendGrantEvidenceDigest",
      "selectedSendGrantInclusionEvidenceDigest",
      "authorizedQuotaPolicyDigest",
      "priorPolicyHeadSequence",
      "priorPolicyHeadHash",
      "priorPolicyWitnessCheckpointId",
      "priorPolicyWitnessEvidenceDigest",
    ],
    "locked witnessed policy head",
  );
  const witnessState = parseOneOf(
    record.witnessState,
    ["verified", "missing", "inconsistent", "stale"] as const,
    "policy-head witness state",
  );
  const witnessCheckpointId =
    record.witnessCheckpointId === null
      ? null
      : parseWitnessCheckpointId(record.witnessCheckpointId);
  const witnessedPolicyHeadHash =
    record.witnessedPolicyHeadHash === null
      ? null
      : parseHash32(record.witnessedPolicyHeadHash, "witnessed policy head hash");
  if (
    witnessState === "verified" &&
    (witnessCheckpointId === null || witnessedPolicyHeadHash === null)
  ) {
    throw invalid("A verified policy head requires complete witness bindings.");
  }
  if (
    witnessState !== "verified" &&
    (witnessCheckpointId !== null || witnessedPolicyHeadHash !== null)
  ) {
    throw invalid("An unverified policy head cannot carry trusted witness bindings.");
  }
  const issuedAt = parseRfc3339Millis(record.issuedAt, "policy head issuance");
  const expiresAt = parseRfc3339Millis(record.expiresAt, "policy head expiry");
  const proofVerifiedAt = parseRfc3339Millis(
    record.proofVerifiedAt,
    "policy proof verification time",
  );
  if (
    issuedAt >= expiresAt ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 300_000 ||
    proofVerifiedAt < issuedAt ||
    proofVerifiedAt >= expiresAt
  ) {
    throw invalid("Policy proof and validity interval are inconsistent.");
  }
  return Object.freeze({
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    conversationId: parseConversationId(record.conversationId),
    policyHeadSequence: parsePositiveUint63(
      record.policyHeadSequence,
      "policy head sequence",
    ),
    policyHeadHash: parseHash32(record.policyHeadHash, "policy head hash"),
    deliveryLogPosition: parseUint63String(
      record.deliveryLogPosition,
      "policy delivery-log position",
    ),
    deliveryLogHeadHash: parseHash32(
      record.deliveryLogHeadHash,
      "policy delivery-log head hash",
    ),
    evaluationLogPosition: parseUint63String(
      record.evaluationLogPosition,
      "policy evaluation-log position",
    ),
    evaluationLogHeadHash: parseHash32(
      record.evaluationLogHeadHash,
      "policy evaluation-log head hash",
    ),
    epoch: parseUint63String(record.epoch, "policy head epoch"),
    rosterVersion: parseUint63String(
      record.rosterVersion,
      "policy head roster version",
    ),
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "policy head confirmed transcript hash",
    ),
    policyRevision: parsePositiveUint63(
      record.policyRevision,
      "policy revision",
    ),
    signedBodySha256: parseHash32(
      record.signedBodySha256,
      "policy signed body SHA-256",
    ),
    signerKeyId: parseSigningKeyId(record.signerKeyId, "policy signer key ID"),
    signatureSha256: parseHash32(
      record.signatureSha256,
      "policy signature SHA-256",
    ),
    witnessEvidenceDigest: parseHash32(
      record.witnessEvidenceDigest,
      "policy witness evidence digest",
    ),
    proofEvidenceDigest: parseHash32(
      record.proofEvidenceDigest,
      "policy proof evidence digest",
    ),
    policyConsistencyEvidenceDigest: parseHash32(
      record.policyConsistencyEvidenceDigest,
      "policy consistency evidence digest",
    ),
    proofVerifiedAt,
    issuedAt,
    expiresAt,
    witnessState,
    witnessCheckpointId,
    witnessedPolicyHeadHash,
    mandatoryProposalCount: parseMandatoryProposalCount(
      record.mandatoryProposalCount,
      "mandatory proposal count",
    ),
    mandatoryProposalSetHash: parseHash32(
      record.mandatoryProposalSetHash,
      "mandatory proposal set hash",
    ),
    authorizedSendGrantSetHash: parseHash32(
      record.authorizedSendGrantSetHash,
      "authorized send-grant set hash",
    ),
    selectedSendGrantEvidenceDigest: parseHash32(
      record.selectedSendGrantEvidenceDigest,
      "selected send-grant evidence digest",
    ),
    selectedSendGrantInclusionEvidenceDigest: parseHash32(
      record.selectedSendGrantInclusionEvidenceDigest,
      "selected send-grant inclusion evidence digest",
    ),
    authorizedQuotaPolicyDigest: parseHash32(
      record.authorizedQuotaPolicyDigest,
      "authorized quota policy digest",
    ),
    priorPolicyHeadSequence: parseUint63String(
      record.priorPolicyHeadSequence,
      "prior policy-head sequence",
    ),
    priorPolicyHeadHash: parseHash32(
      record.priorPolicyHeadHash,
      "prior policy-head hash",
    ),
    priorPolicyWitnessCheckpointId: parseWitnessCheckpointId(
      record.priorPolicyWitnessCheckpointId,
    ),
    priorPolicyWitnessEvidenceDigest: parseHash32(
      record.priorPolicyWitnessEvidenceDigest,
      "prior policy witness evidence digest",
    ),
  });
}

function parseLockedConversationUsage(value: unknown): LockedConversationUsage {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "envelopeCount",
      "envelopeBytes",
      "attachmentBytes",
      "envelopeCountLimit",
      "envelopeBytesLimit",
      "attachmentBytesLimit",
    ],
    "locked conversation usage",
  );
  const usage: LockedConversationUsage = {
    conversationId: parseConversationId(record.conversationId),
    envelopeCount: parseUint63String(record.envelopeCount, "envelope count"),
    envelopeBytes: parseUint63String(record.envelopeBytes, "envelope bytes"),
    attachmentBytes: parseUint63String(
      record.attachmentBytes,
      "attachment bytes",
    ),
    envelopeCountLimit: parseUint63String(
      record.envelopeCountLimit,
      "envelope count limit",
    ),
    envelopeBytesLimit: parseUint63String(
      record.envelopeBytesLimit,
      "envelope bytes limit",
    ),
    attachmentBytesLimit: parseUint63String(
      record.attachmentBytesLimit,
      "attachment bytes limit",
    ),
  };
  if (
    BigInt(usage.envelopeCount) > BigInt(usage.envelopeCountLimit) ||
    BigInt(usage.envelopeBytes) > BigInt(usage.envelopeBytesLimit) ||
    BigInt(usage.attachmentBytes) > BigInt(usage.attachmentBytesLimit)
  ) {
    throw invalid("Locked conversation usage already exceeds its hard limit.");
  }
  return usage;
}

function parseLockedQuotaCounters(value: unknown): readonly LockedQuotaCounter[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Every mandatory append quota scope must be locked exactly once.");
  }
  const quotas = value.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "scope",
        "scopeHash",
        "quotaName",
        "windowStartedAt",
        "windowSeconds",
        "operationCount",
        "byteCount",
        "reservedOperationCount",
        "reservedByteCount",
        "rowVersion",
        "operationLimit",
        "byteLimit",
      ],
      `locked quota ${index}`,
    );
    const scope = parseOneOf(
      record.scope,
      APPLICATION_APPEND_QUOTA_SCOPES,
      `locked quota ${index} scope`,
    );
    const quota: LockedQuotaCounter = {
      scope,
      scopeHash: parseHash32(
        record.scopeHash,
        `locked quota ${index} scope hash`,
      ),
      quotaName: parseQuotaName(record.quotaName, `locked quota ${index} name`),
      windowStartedAt: parseRfc3339Millis(
        record.windowStartedAt,
        `locked quota ${index} window start`,
      ),
      windowSeconds: parsePositiveUint63(
        record.windowSeconds,
        `locked quota ${index} window seconds`,
      ),
      operationCount: parseUint63String(
        record.operationCount,
        `locked quota ${index} operation count`,
      ),
      byteCount: parseUint63String(
        record.byteCount,
        `locked quota ${index} byte count`,
      ),
      reservedOperationCount: parseUint63String(
        record.reservedOperationCount,
        `locked quota ${index} reserved operation count`,
      ),
      reservedByteCount: parseUint63String(
        record.reservedByteCount,
        `locked quota ${index} reserved byte count`,
      ),
      rowVersion: parseUint63String(
        record.rowVersion,
        `locked quota ${index} row version`,
      ),
      operationLimit: parseUint63String(
        record.operationLimit,
        `locked quota ${index} operation limit`,
      ),
      byteLimit: parseUint63String(
        record.byteLimit,
        `locked quota ${index} byte limit`,
      ),
    };
    if (
      BigInt(quota.operationCount) + BigInt(quota.reservedOperationCount) >
        BigInt(quota.operationLimit) ||
      BigInt(quota.byteCount) + BigInt(quota.reservedByteCount) >
        BigInt(quota.byteLimit)
    ) {
      throw invalid(`Locked quota ${index} already exceeds its hard limit.`);
    }
    return quota;
  });
  const scopes = new Set(quotas.map(({ scope }) => scope));
  if (
    scopes.size !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    APPLICATION_APPEND_QUOTA_SCOPES.some((scope) => !scopes.has(scope))
  ) {
    throw invalid("Append quota scopes are missing or duplicated.");
  }
  return Object.freeze(
    APPLICATION_APPEND_QUOTA_SCOPES.map((scope) =>
      Object.freeze(quotas.find((quota) => quota.scope === scope)!),
    ),
  );
}

function parseQuotaCapacityDeltaRecord(
  value: unknown,
  index: number,
): ApplicationAppendQuotaCapacityDelta {
  const record = expectExactRecord(
    value,
    [
      "scope",
      "scopeHash",
      "quotaName",
      "windowStartedAt",
      "windowSeconds",
      "reservationOperationCount",
      "reservationByteCount",
      "rowVersionBefore",
      "rowVersionAfter",
    ],
    `append quota capacity delta ${index}`,
  );
  const rowVersionBefore = parseUint63String(record.rowVersionBefore);
  const rowVersionAfter = parseUint63String(record.rowVersionAfter);
  if (
    record.reservationOperationCount !== "1" ||
    addUint63(rowVersionBefore, 1n) !== rowVersionAfter
  ) {
    throw invalid("Append quota capacity delta or row fence is invalid.");
  }
  return Object.freeze({
    scope: parseOneOf(
      record.scope,
      APPLICATION_APPEND_QUOTA_SCOPES,
      `append quota capacity delta ${index} scope`,
    ),
    scopeHash: parseHash32(record.scopeHash),
    quotaName: parseQuotaName(record.quotaName, `append quota capacity delta ${index} name`),
    windowStartedAt: parseRfc3339Millis(record.windowStartedAt),
    windowSeconds: parsePositiveUint63(record.windowSeconds, "quota window seconds"),
    reservationOperationCount: "1" as Uint63String,
    reservationByteCount: parseUint63String(record.reservationByteCount),
    rowVersionBefore,
    rowVersionAfter,
  });
}

export function parseApplicationAppendQuotaCapacityDeltas(
  value: unknown,
): readonly ApplicationAppendQuotaCapacityDelta[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Every append quota row requires one capacity reservation.");
  }
  const parsed = value.map((entry, index) =>
    parseQuotaCapacityDeltaRecord(entry, index),
  );
  const scopes = new Set(parsed.map(({ scope }) => scope));
  if (
    scopes.size !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    APPLICATION_APPEND_QUOTA_SCOPES.some((scope) => !scopes.has(scope))
  ) {
    throw invalid("Append quota capacity reservation scopes are incomplete.");
  }
  return Object.freeze(
    APPLICATION_APPEND_QUOTA_SCOPES.map((scope) =>
      parsed.find((reservation) => reservation.scope === scope)!,
    ),
  );
}

export function bindApplicationAppendQuotaCapacityReservations(input: {
  deltas: readonly ApplicationAppendQuotaCapacityDelta[];
  pendingPreparationDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
}): readonly ApplicationAppendQuotaCapacityReservation[] {
  const deltas = parseApplicationAppendQuotaCapacityDeltas(input.deltas);
  const pendingPreparationDigest = parseHash32(input.pendingPreparationDigest);
  const fenceGeneration = parsePositiveUint63(
    input.fenceGeneration,
    "quota reservation fence generation",
  );
  const fenceTokenHash = parseNonZeroHash32(
    input.fenceTokenHash,
    "quota reservation fence token hash",
  );
  return Object.freeze(
    deltas.map((delta) => Object.freeze({
      ...delta,
      reservationId: computeApplicationAppendQuotaReservationId({
        pendingPreparationDigest,
        fenceGeneration,
        fenceTokenHash,
        delta,
      }),
      pendingPreparationDigest,
      fenceGeneration,
      fenceTokenHash,
      state: "live" as const,
    })),
  );
}

export function parseApplicationAppendQuotaCapacityReservations(
  value: unknown,
): readonly ApplicationAppendQuotaCapacityReservation[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Every append quota row requires one owned capacity reservation.");
  }
  const parsed = value.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "scope",
        "scopeHash",
        "quotaName",
        "windowStartedAt",
        "windowSeconds",
        "reservationOperationCount",
        "reservationByteCount",
        "rowVersionBefore",
        "rowVersionAfter",
        "reservationId",
        "pendingPreparationDigest",
        "fenceGeneration",
        "fenceTokenHash",
        "state",
      ],
      `owned append quota capacity reservation ${index}`,
    );
    const delta = parseQuotaCapacityDeltaRecord({
      scope: record.scope,
      scopeHash: record.scopeHash,
      quotaName: record.quotaName,
      windowStartedAt: record.windowStartedAt,
      windowSeconds: record.windowSeconds,
      reservationOperationCount: record.reservationOperationCount,
      reservationByteCount: record.reservationByteCount,
      rowVersionBefore: record.rowVersionBefore,
      rowVersionAfter: record.rowVersionAfter,
    }, index);
    const pendingPreparationDigest = parseHash32(record.pendingPreparationDigest);
    const fenceGeneration = parsePositiveUint63(
      record.fenceGeneration,
      `owned quota reservation ${index} fence generation`,
    );
    const fenceTokenHash = parseNonZeroHash32(
      record.fenceTokenHash,
      `owned quota reservation ${index} fence token hash`,
    );
    const reservation = Object.freeze({
      ...delta,
      reservationId: parseNonZeroHash32(
        record.reservationId,
        `owned quota reservation ${index} ID`,
      ),
      pendingPreparationDigest,
      fenceGeneration,
      fenceTokenHash,
      state: parseOneOf(
        record.state,
        ["live", "consumed", "released"] as const,
        `owned quota reservation ${index} state`,
      ),
    });
    if (
      reservation.reservationId !== computeApplicationAppendQuotaReservationId({
        pendingPreparationDigest,
        fenceGeneration,
        fenceTokenHash,
        delta,
      })
    ) {
      throw invalid("Owned quota reservation ID is inconsistent.");
    }
    return reservation;
  });
  const ordered = Object.freeze(
    APPLICATION_APPEND_QUOTA_SCOPES.map((scope) => {
      const matches = parsed.filter((reservation) => reservation.scope === scope);
      if (matches.length !== 1) throw invalid("Owned quota reservation scopes are incomplete.");
      return matches[0];
    }),
  );
  if (new Set(ordered.map(({ reservationId }) => reservationId)).size !== ordered.length) {
    throw invalid("Owned quota reservation IDs are duplicated.");
  }
  return ordered;
}

export function computeApplicationAppendQuotaReservationId(input: {
  pendingPreparationDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  delta: ApplicationAppendQuotaCapacityDelta;
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_QUOTA_RESERVATION_ID_DOMAIN),
    canonicalLengthPrefixed(
      decodeHash32(parseHash32(input.pendingPreparationDigest)),
      utf8(parsePositiveUint63(input.fenceGeneration, "quota reservation generation")),
      decodeHash32(parseNonZeroHash32(input.fenceTokenHash, "quota fence token hash")),
      utf8(input.delta.scope),
      decodeHash32(input.delta.scopeHash),
      utf8(input.delta.quotaName),
      utf8(input.delta.windowStartedAt),
      utf8(input.delta.windowSeconds),
      utf8(input.delta.reservationOperationCount),
      utf8(input.delta.reservationByteCount),
      utf8(input.delta.rowVersionBefore),
      utf8(input.delta.rowVersionAfter),
    ),
  );
}

export function computeApplicationAppendQuotaReservationSetDigest(
  value: readonly ApplicationAppendQuotaCapacityReservation[],
): Hash32 {
  const reservations = parseApplicationAppendQuotaCapacityReservations(value);
  return sha256Bytes(
    utf8(APPLICATION_APPEND_QUOTA_RESERVATION_SET_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      ...reservations.flatMap((reservation) => [
        decodeHash32(reservation.reservationId),
        utf8(reservation.scope),
        utf8(reservation.state),
      ]),
    ),
  );
}

function validateQuotaCapacityConversion(
  input: {
    currentQuotas: readonly LockedQuotaCounter[];
    currentCapacityReservations: readonly ApplicationAppendQuotaCapacityReservation[];
    pendingPreparationDigest: Hash32;
    fenceGeneration: Uint63String;
    fenceTokenHash: Hash32;
    preparedFinalQuotas: readonly LockedQuotaCounter[];
    preparedFinalReservations: readonly ApplicationAppendQuotaCapacityReservation[];
  },
  mode: "finalize" | "release",
): ApplicationAppendQuotaCapacityConversion {
  const current = parseLockedQuotaCounters(input.currentQuotas);
  const reservations = parseApplicationAppendQuotaCapacityReservations(
    input.currentCapacityReservations,
  );
  const pendingPreparationDigest = parseHash32(input.pendingPreparationDigest);
  const fenceGeneration = parsePositiveUint63(input.fenceGeneration, "quota conversion fence generation");
  const fenceTokenHash = parseNonZeroHash32(input.fenceTokenHash, "quota conversion token hash");
  if (
    reservations.some(
      (reservation) =>
        reservation.state !== "live" ||
        reservation.pendingPreparationDigest !== pendingPreparationDigest ||
        reservation.fenceGeneration !== fenceGeneration ||
        reservation.fenceTokenHash !== fenceTokenHash,
    )
  ) {
    throw invalid("Quota capacity reservation is not owned by this exact live pending.");
  }
  const expected = current.map((quota) => {
    const reservation = reservations.find(({ scope }) => scope === quota.scope)!;
    if (
      reservation.scopeHash !== quota.scopeHash ||
      reservation.quotaName !== quota.quotaName ||
      reservation.windowStartedAt !== quota.windowStartedAt ||
      reservation.windowSeconds !== quota.windowSeconds ||
      BigInt(quota.rowVersion) < BigInt(reservation.rowVersionAfter) ||
      BigInt(quota.reservedOperationCount) <
        BigInt(reservation.reservationOperationCount) ||
      BigInt(quota.reservedByteCount) <
        BigInt(reservation.reservationByteCount)
    ) {
      throw invalid("Quota capacity reservation is not live on its exact row.");
    }
    const rowVersion = addUint63(quota.rowVersion, 1n);
    const reservedOperationCount = subtractUint63(
      quota.reservedOperationCount,
      reservation.reservationOperationCount,
    );
    const reservedByteCount = subtractUint63(
      quota.reservedByteCount,
      reservation.reservationByteCount,
    );
    const operationCount = mode === "finalize"
      ? addUint63(quota.operationCount, BigInt(reservation.reservationOperationCount))
      : quota.operationCount;
    const byteCount = mode === "finalize"
      ? addUint63(quota.byteCount, BigInt(reservation.reservationByteCount))
      : quota.byteCount;
    if (
      rowVersion === null ||
      reservedOperationCount === null ||
      reservedByteCount === null ||
      operationCount === null ||
      byteCount === null ||
      BigInt(operationCount) + BigInt(reservedOperationCount) >
        BigInt(quota.operationLimit) ||
      BigInt(byteCount) + BigInt(reservedByteCount) > BigInt(quota.byteLimit)
    ) {
      throw invalid("Quota capacity conversion overflows or exceeds its row.");
    }
    return Object.freeze({
      ...quota,
      operationCount,
      byteCount,
      reservedOperationCount,
      reservedByteCount,
      rowVersion,
    });
  });
  const prepared = parseLockedQuotaCounters(input.preparedFinalQuotas);
  const preparedReservations = parseApplicationAppendQuotaCapacityReservations(
    input.preparedFinalReservations,
  );
  const expectedReservationState = mode === "finalize" ? "consumed" : "released";
  const expectedReservations = reservations.map((reservation) =>
    Object.freeze({ ...reservation, state: expectedReservationState }),
  );
  if (!sameCanonicalObject(prepared, expected)) {
    throw invalid("Prepared quota capacity conversion is not additive.");
  }
  if (!sameCanonicalObject(preparedReservations, expectedReservations)) {
    throw invalid("Prepared quota reservation terminal state is not exact.");
  }
  return Object.freeze({
    quotas: prepared,
    reservations: preparedReservations,
  });
}

function parseExpectedQuotaIdentities(
  value: unknown,
): readonly ExpectedAppendQuotaIdentity[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    throw invalid("Every authoritative append quota binding is required once.");
  }
  const parsed = value.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "scope",
        "scopeHash",
        "quotaName",
        "windowStartedAt",
        "windowSeconds",
        "operationLimit",
        "byteLimit",
      ],
      `quota binding ${index}`,
    );
    return Object.freeze({
      scope: parseOneOf(
        record.scope,
        APPLICATION_APPEND_QUOTA_SCOPES,
        `quota binding ${index} scope`,
      ),
      scopeHash: parseHash32(
        record.scopeHash,
        `quota binding ${index} scope hash`,
      ),
      quotaName: parseQuotaName(
        record.quotaName,
        `quota binding ${index} name`,
      ),
      windowStartedAt: parseRfc3339Millis(
        record.windowStartedAt,
        `quota binding ${index} window start`,
      ),
      windowSeconds: parsePositiveUint63(
        record.windowSeconds,
        `quota binding ${index} window seconds`,
      ),
      operationLimit: parseUint63String(
        record.operationLimit,
        `quota binding ${index} operation limit`,
      ),
      byteLimit: parseUint63String(
        record.byteLimit,
        `quota binding ${index} byte limit`,
      ),
    });
  });
  const scopes = new Set(parsed.map(({ scope }) => scope));
  const compoundKeys = new Set(
    parsed.map(
      ({
        scope,
        scopeHash,
        quotaName,
        windowStartedAt,
        windowSeconds,
        operationLimit,
        byteLimit,
      }) =>
        `${scope}\u0000${scopeHash}\u0000${quotaName}\u0000${windowStartedAt}\u0000${windowSeconds}\u0000${operationLimit}\u0000${byteLimit}`,
    ),
  );
  if (
    scopes.size !== APPLICATION_APPEND_QUOTA_SCOPES.length ||
    compoundKeys.size !== APPLICATION_APPEND_QUOTA_SCOPES.length
  ) {
    throw invalid("Authoritative append quota bindings are missing or duplicated.");
  }
  return Object.freeze(
    APPLICATION_APPEND_QUOTA_SCOPES.map((scope) =>
      parsed.find((binding) => binding.scope === scope)!,
    ),
  );
}

function assertQuotaBindingsMatchCounters(
  bindings: readonly ExpectedAppendQuotaIdentity[],
  counters: readonly LockedQuotaCounter[],
): void {
  for (const scope of APPLICATION_APPEND_QUOTA_SCOPES) {
    const binding = bindings.find((candidate) => candidate.scope === scope);
    const counter = counters.find((candidate) => candidate.scope === scope);
    if (
      !binding ||
      !counter ||
      binding.scopeHash !== counter.scopeHash ||
      binding.quotaName !== counter.quotaName ||
      binding.windowStartedAt !== counter.windowStartedAt ||
      binding.windowSeconds !== counter.windowSeconds ||
      binding.operationLimit !== counter.operationLimit ||
      binding.byteLimit !== counter.byteLimit
    ) {
      throw invalid("Locked quota counter identity does not match its authoritative binding.");
    }
  }
}

function roleMaySend(
  kind: LockedConversationState["kind"],
  role: ConversationSendRole,
): boolean {
  switch (kind) {
    case "purchase_support":
      return role === "customer" || role === "project-staff";
    case "announcement":
      return role === "publisher";
    case "community":
      return role === "member" || role === "moderator";
  }
}

function isWithinQuotaWindow(
  quota: Pick<LockedQuotaCounter, "windowStartedAt" | "windowSeconds">,
  now: Rfc3339Millis,
): boolean {
  const nowMilliseconds = BigInt(Date.parse(now));
  const startsAt = BigInt(Date.parse(quota.windowStartedAt));
  const duration = BigInt(quota.windowSeconds) * 1_000n;
  const expectedStart = (nowMilliseconds / duration) * duration;
  return startsAt === expectedStart && nowMilliseconds < startsAt + duration;
}

function quotaSubjectId(
  conversation: LockedConversationState,
  membership: LockedSenderMembership,
  scope: ApplicationAppendQuotaScope,
): string {
  switch (scope) {
    case "installation":
      return membership.installationId;
    case "account":
      return membership.accountId;
    case "project":
      return conversation.projectScopeId;
    case "conversation":
      return conversation.conversationId;
    case "tenant":
      return conversation.tenantScopeId;
  }
}

function parseScopeSubjectId(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/.test(value)
  ) {
    throw invalid(`${label} must be bounded canonical ASCII.`);
  }
  return value;
}

function parseQuotaName(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value)
  ) {
    throw invalid(`${label} must be bounded canonical lowercase ASCII.`);
  }
  return value;
}

function parsePolicyRealmId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value)
  ) {
    throw invalid("Policy proof realm ID is not canonical.");
  }
  return value;
}

function encodeNullableText(value: string | null): Uint8Array {
  return value === null
    ? canonicalLengthPrefixed(utf8("absent"))
    : canonicalLengthPrefixed(utf8("present"), utf8(value));
}

function encodeNullableHash(value: Hash32 | null): Uint8Array {
  return value === null
    ? canonicalLengthPrefixed(utf8("absent"))
    : canonicalLengthPrefixed(utf8("present"), decodeHash32(value));
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function parseConversationState(value: unknown): DeliveryConversationState {
  return parseOneOf(
    value,
    [
      "provisioning",
      "active",
      "membership_pending",
      "suspended",
      "closing",
      "closed",
      "retention_expired",
      "purged",
    ] as const,
    "conversation state",
  );
}

function parsePositiveUint63(value: unknown, label: string): Uint63String {
  const parsed = parseUint63String(value, label);
  if (parsed === "0") {
    throw invalid(`${label} must be positive.`);
  }
  return parsed;
}

function parseMandatoryProposalCount(
  value: unknown,
  label: string,
): Uint63String {
  const parsed = parseUint63String(value, label);
  if (BigInt(parsed) > BigInt(DELIVERY_MANDATORY_PROPOSALS_MAX)) {
    throw invalid(`${label} exceeds the protocol queue bound.`);
  }
  return parsed;
}

function parseNonZeroHash32(value: unknown, label: string): Hash32 {
  const parsed = parseHash32(value, label);
  if (parsed === ZERO_HASH32) {
    throw invalid(`${label} cannot use the reserved zero hash.`);
  }
  return parsed;
}

function parseOneOf<const Value extends string>(
  value: unknown,
  allowed: readonly Value[],
  label: string,
): Value {
  if (typeof value !== "string" || !allowed.includes(value as Value)) {
    throw invalid(`${label} is unsupported.`);
  }
  return value as Value;
}

function parseRequiredLiteral<const Value extends string>(
  value: unknown,
  expected: Value,
): Value {
  if (value !== expected) {
    throw invalid(`Expected exact ${expected} evidence status.`);
  }
  return expected;
}

function addUint63(value: Uint63String, increment: bigint): Uint63String | null {
  const result = BigInt(value) + increment;
  if (result < 0n || result > UINT63_MAX) {
    return null;
  }
  return result.toString(10) as Uint63String;
}

function subtractUint63(
  value: Uint63String,
  decrement: Uint63String,
): Uint63String | null {
  return addUint63(value, -BigInt(decrement));
}

function quotaReservationDelta(
  reservation: ApplicationAppendQuotaCapacityReservation,
): ApplicationAppendQuotaCapacityDelta {
  return Object.freeze({
    scope: reservation.scope,
    scopeHash: reservation.scopeHash,
    quotaName: reservation.quotaName,
    windowStartedAt: reservation.windowStartedAt,
    windowSeconds: reservation.windowSeconds,
    reservationOperationCount: reservation.reservationOperationCount,
    reservationByteCount: reservation.reservationByteCount,
    rowVersionBefore: reservation.rowVersionBefore,
    rowVersionAfter: reservation.rowVersionAfter,
  });
}

function sameRecipientIdentity(
  route: ApplicationAppendRecipientProjection,
  roster: ApplicationAppendMlsRosterProjection,
): boolean {
  return (
    route.conversationId === roster.conversationId &&
    route.conversationGeneration === roster.conversationGeneration &&
    route.accountId === roster.accountId &&
    route.installationId === roster.installationId &&
    route.credentialId === roster.credentialId &&
    route.credentialFingerprint === roster.credentialFingerprint
  );
}

function sameCanonicalObject(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function reject(
  reasonCode: ApplicationAppendRejectionReason,
): LockedApplicationAppendDecision {
  return { status: "rejected", reasonCode };
}

function invalid(message: string): DeliveryStateValidationError {
  return new DeliveryStateValidationError(message);
}
