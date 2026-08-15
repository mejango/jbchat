import type {
  ApplicationEnvelopeSemanticIdentity,
} from "./envelopes";
import type { DeliveryLimits } from "./limits";
import type {
  ConversationCursorContext,
  ConversationCursorPlaintext,
  DeliveryRealmId,
} from "./sync";
import { canonicalLengthPrefixed, sha256Bytes } from "./hashes";
import {
  decodeHash32,
  DeliveryValidationError,
  expectExactRecord,
  parseCanonicalBase64UrlBytes,
  parseConversationId,
  parseEd25519Signature,
  parseHash32,
  parsePositiveUint63String,
  parseReleaseProfileId,
  parseRfc3339Millis,
  parseSigningKeyId,
  ZERO_HASH32,
} from "./valueObjects";
import type {
  ConversationId,
  AccountId,
  CredentialId,
  EnvelopeId,
  EnvelopeContentType,
  Ed25519Signature,
  Fingerprint32,
  Hash32,
  IdempotencyKey,
  InstallationId,
  MembershipIntentId,
  PolicyHeadId,
  ProposalId,
  ReleaseProfileId,
  Rfc3339Millis,
  CanonicalBase64Url,
  SigningKeyId,
  Uint63String,
  WitnessCheckpointId,
} from "./valueObjects";

export const DELIVERY_PORT_UNAVAILABLE_REASONS = [
  "not-configured",
  "dependency-unavailable",
  "timeout",
  "malformed-dependency-response",
] as const;

/** Protocol-wide admission and replay bound for one active mandatory queue. */
export const DELIVERY_MANDATORY_PROPOSALS_MAX = 100;

export type DeliveryPortUnavailableReason =
  (typeof DELIVERY_PORT_UNAVAILABLE_REASONS)[number];

export interface DeliveryPortUnavailable {
  status: "unavailable";
  reasonCode: DeliveryPortUnavailableReason;
}

export function parseDeliveryPortUnavailable(
  value: unknown,
): DeliveryPortUnavailable {
  const record = expectExactRecord(
    value,
    ["status", "reasonCode"],
    "delivery port unavailable result",
  );
  if (
    record.status !== "unavailable" ||
    typeof record.reasonCode !== "string" ||
    !DELIVERY_PORT_UNAVAILABLE_REASONS.includes(
      record.reasonCode as DeliveryPortUnavailableReason,
    )
  ) {
    throw new DeliveryValidationError(
      "Delivery port unavailable result is unsupported.",
    );
  }
  return Object.freeze({
    status: "unavailable",
    reasonCode: record.reasonCode as DeliveryPortUnavailableReason,
  });
}

export interface MlsWireInspectionRequest {
  releaseProfileId: ReleaseProfileId;
  expectedGroupIdHash: Hash32;
  expectedEpoch: Uint63String;
  expectedWireKind: "private-application";
  contentType: EnvelopeContentType;
  envelopeBytes: Uint8Array;
  envelopeSha256: Hash32;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface MlsWireInspectorPort {
  /**
   * Checks only public framing/group/epoch/wire-kind/hash. MLS PrivateMessage
   * SenderData is encrypted and cannot be authenticated by the Delivery
   * Service without group secrets; HTTP device/DPoP binding is separate, and
   * recipients must compare the decrypted MLS leaf credential with the
   * server-stamped routing sender and raise an invariant incident on mismatch.
   */
  inspect(request: MlsWireInspectionRequest): Promise<unknown>;
}

export interface MlsCommitProjectionVerificationRequest {
  profile: "mls-commit-projection.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeBytes: CanonicalBase64Url;
  envelopeSha256: Hash32;
  expectedAccountId: AccountId;
  expectedInstallationId: InstallationId;
  expectedCredentialId: CredentialId;
  expectedCredentialFingerprint: Fingerprint32;
  expectedCredentialRevocationVersion: Uint63String;
  expectedSenderGeneration: Uint63String;
  commitEpoch: Uint63String;
  commitRosterVersion: Uint63String;
  previousEpoch: Uint63String;
  previousRosterVersion: Uint63String;
  previousConfirmedTranscriptHash: Hash32;
  baseConfirmedTranscriptHash: Hash32;
  resultingConfirmedTranscriptHash: Hash32;
  /** Exact ordered, already verified proposals staged before this Commit. */
  stagedProposals: readonly MlsStagedExternalProposalBinding[];
  /** Exact active signed policy set that this Commit must consume. */
  requiredProposals: readonly PolicyMandatoryProposalBinding[];
  creatorBootstrapTarget: MlsMembershipTargetIdentity | null;
  removalTarget: MlsMembershipTargetIdentity | null;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface MlsMembershipTargetIdentity {
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
}

export interface MlsStagedExternalProposalBinding {
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeSha256: Hash32;
  epoch: Uint63String;
  proposalId: ProposalId;
  proposalHash: Hash32;
  authorizationRecordHash: Hash32;
  membershipIntentId: MembershipIntentId;
  membershipIntentHash: Hash32;
  membershipIntentEvidenceDigest: Hash32;
  proposalType: "add" | "remove";
  proposalRequirement: "mandatory" | "optional";
  authorizingPolicyHeadSequence: Uint63String;
  authorizingPolicyHeadHash: Hash32;
}

export interface MlsCommittedIntentBinding {
  membershipIntentId: MembershipIntentId;
  membershipIntentHash: Hash32;
  membershipIntentEvidenceDigest: Hash32;
  proposalId: ProposalId;
  proposalHash: Hash32;
  commitPosition: Uint63String;
  commitEnvelopeId: EnvelopeId;
  commitEnvelopeSha256: Hash32;
}

export interface PolicyMandatoryProposalBinding {
  proposalId: ProposalId;
  proposalHash: Hash32;
}

export interface ConversationPolicyReplayProjection {
  policyHeadId: PolicyHeadId;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  deliveryLogPosition: Uint63String;
  deliveryLogHeadHash: Hash32;
  mandatoryProposals: readonly PolicyMandatoryProposalBinding[];
  witnessCheckpointId: WitnessCheckpointId;
  witnessEvidenceDigest: Hash32;
}

export interface ConversationPolicyReplayEventBinding {
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeClass: "application" | "external_proposal" | "mls_commit";
  envelopeSha256: Hash32;
  headHash: Hash32;
}

export type ConversationPolicyReplayTransition =
  ConversationPolicyReplayProjection;

export interface ConversationPolicyReplayVerificationRequest {
  profile: "conversation-policy-replay.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  conversationId: ConversationId;
  pageStartPosition: Uint63String;
  pageStartHeadHash: Hash32;
  pageStartPolicy: ConversationPolicyReplayProjection;
  pageEndPosition: Uint63String;
  pageEndHeadHash: Hash32;
  pageEndPolicy: ConversationPolicyReplayProjection;
  policyLogHighWaterSequence: Uint63String;
  policyLogHighWaterHash: Hash32;
  policyLogHighWaterWitnessCheckpointId: WitnessCheckpointId;
  policyLogHighWaterWitnessEvidenceDigest: Hash32;
  events: readonly ConversationPolicyReplayEventBinding[];
  verifiedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ConversationPolicyReplayVerifierPort {
  /**
   * Verifies the complete witnessed policy-log interval for this historical
   * page, including mandatory-proposal cutoffs that were later cleared. The
   * current policy-log high-water is a consistency anchor, never substituted
   * for the historical page projections. It returns one coalesced final
   * cutoff per delivery position plus a succinct complete-range proof over
   * arbitrarily many policy-log-only refreshes at that position.
   */
  verify(request: ConversationPolicyReplayVerificationRequest): Promise<unknown>;
}

export interface MlsCommitProjectionVerifierPort {
  /** Uses the release-pinned MLS core; output is untrusted until strictly bound. */
  verify(request: MlsCommitProjectionVerificationRequest): Promise<unknown>;
}

export interface MlsExternalProposalVerificationRequest {
  profile: "mls-external-proposal.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeBytes: CanonicalBase64Url;
  envelopeSha256: Hash32;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  signerGeneration: Uint63String;
  checkpointReceivedAt: Rfc3339Millis;
  /** Exact historical page end at which this event is being replayed. */
  pageEndPosition: Uint63String;
  pageEndHeadHash: Hash32;
  pageEndPolicyHeadSequence: Uint63String;
  pageEndPolicyHeadHash: Hash32;
  /** Exact page-start historical policy anchor used for ordered forward replay. */
  priorPolicyHeadSequence: Uint63String;
  priorPolicyHeadHash: Hash32;
  priorPolicyWitnessCheckpointId: WitnessCheckpointId;
  priorPolicyWitnessEvidenceDigest: Hash32;
  /** Separate persisted current policy-log high-water; historical replay never lowers it. */
  policyLogHighWaterSequence: Uint63String;
  policyLogHighWaterHash: Hash32;
  policyLogHighWaterWitnessCheckpointId: WitnessCheckpointId;
  policyLogHighWaterWitnessEvidenceDigest: Hash32;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface MlsExternalProposalVerifierPort {
  /**
   * Composite verification of one release-pinned PublicMessage plus the
   * immutable proposal/intent records and their one-to-one composite FK to
   * this exact conversation/position/envelope ID/bytes hash.
   */
  verify(request: MlsExternalProposalVerificationRequest): Promise<unknown>;
}

export interface PolicyHeadProofVerificationRequest {
  profile: "conversation-policy-head-proof.v1";
  realmId: DeliveryRealmId;
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
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface PolicyHeadProofVerifierPort {
  /** Verifies the exact signed/witnessed head and freshness; never a boolean grant. */
  verify(request: PolicyHeadProofVerificationRequest): Promise<unknown>;
}

export interface DeliveryCheckpointSigningRequest {
  profile: "delivery-log-checkpoint.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  pendingIntentDigest: Hash32;
  reservationFence: ApplicationAppendReservationFence;
  pendingExpiresAt: Rfc3339Millis;
  /** Immutable start of the original admission which created this pending. */
  admissionStartedAt: Rfc3339Millis;
  /** Start of this sign/recovery invocation; it may be later on retry. */
  invocationStartedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

declare const applicationAppendFenceTokenBrand: unique symbol;

export type ApplicationAppendFenceToken = string & {
  readonly [applicationAppendFenceTokenBrand]: "ApplicationAppendFenceToken";
};

export interface ApplicationAppendReservationFence {
  /** Monotonically increasing durable lane generation; zero is never issued. */
  generation: Uint63String;
  /** Opaque 256-bit bearer secret. Never expose it in APIs, receipts, logs, or incidents. */
  token: ApplicationAppendFenceToken;
}

export function parseApplicationAppendReservationFence(
  value: unknown,
): ApplicationAppendReservationFence {
  const record = expectExactRecord(
    value,
    ["generation", "token"],
    "application append reservation fence",
  );
  const parsedToken = parseHash32(record.token, "application append fence token");
  if (parsedToken === ZERO_HASH32) {
    throw new DeliveryValidationError(
      "Application append fence token cannot be the reserved zero hash.",
    );
  }
  return Object.freeze({
    generation: parsePositiveUint63String(
      record.generation,
      "application append fence generation",
    ),
    token: parsedToken as unknown as ApplicationAppendFenceToken,
  });
}

export interface ApplicationAppendSignerFenceResolutionRequest
  extends Omit<DeliveryCheckpointSigningRequest, "profile"> {
  profile: "application-append-signer-fence-resolution.v1";
}

interface ApplicationAppendSignerFenceResolutionCommon {
  profile: "application-append-signer-fence-resolution.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  pendingIntentDigest: Hash32;
  fenceGeneration: Uint63String;
  /** Domain-separated hash of the bearer token; the raw token never leaves live calls. */
  fenceTokenHash: Hash32;
  pendingExpiresAt: Rfc3339Millis;
  admissionStartedAt: Rfc3339Millis;
  fenceRecordKeyProfile: "application-append-fence-record-ed25519.v1";
  fenceRecordDigest: Hash32;
  fenceRecordSigningKeyId: SigningKeyId;
  fenceRecordSignature: Ed25519Signature;
}

export interface ApplicationAppendSignerFenceSignedResolution
  extends ApplicationAppendSignerFenceResolutionCommon {
  status: "signed";
  checkpointSignature: Ed25519Signature;
  /** Signer-authoritative instant; it must be strictly before pendingExpiresAt. */
  signedAt: Rfc3339Millis;
}

export interface ApplicationAppendSignerFenceCancelledResolution
  extends ApplicationAppendSignerFenceResolutionCommon {
  status: "cancelled";
  cancellationStatus: "irreversible-cancelled";
  /** Signer-authoritative instant; it must be at or after pendingExpiresAt. */
  cancelledAt: Rfc3339Millis;
}

export type ApplicationAppendSignerFenceResolution =
  | ApplicationAppendSignerFenceSignedResolution
  | ApplicationAppendSignerFenceCancelledResolution;

/**
 * Redacted durable tuple used to revalidate a signer-fence record after the
 * live bearer token has been discarded. It is safe to persist with an
 * accepted append; the token hash is not a signing/finalization capability.
 */
export interface ApplicationAppendSignerFenceResolutionExpectation {
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  pendingIntentDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  pendingExpiresAt: Rfc3339Millis;
  admissionStartedAt: Rfc3339Millis;
}

/** A signed fence record is the durable, bearer-free signer resolution. */
export type DurableApplicationAppendSignerFenceSignedResolution =
  ApplicationAppendSignerFenceSignedResolution;

export const APPLICATION_APPEND_SIGNER_FENCE_RECORD_DIGEST_DOMAIN =
  "jb-msg-application-append-signer-fence-record/v1" as const;
export const APPLICATION_APPEND_SIGNER_FENCE_VERIFICATION_DIGEST_DOMAIN =
  "jb-msg-application-append-signer-fence-verification/v1" as const;
export const APPLICATION_APPEND_FENCE_TOKEN_HASH_DOMAIN =
  "jb-msg-application-append-fence-token-hash/v1" as const;

export function computeApplicationAppendFenceTokenHash(
  token: ApplicationAppendFenceToken,
): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_FENCE_TOKEN_HASH_DOMAIN),
    canonicalLengthPrefixed(decodeHash32(parseHash32(token))),
  );
}

export function buildApplicationAppendSignerFenceResolutionExpectation(
  request: DeliveryCheckpointSigningRequest,
): ApplicationAppendSignerFenceResolutionExpectation {
  const fence = parseApplicationAppendReservationFence(
    request.reservationFence,
  );
  return Object.freeze({
    realmId: request.realmId,
    conversationGeneration: parsePositiveUint63String(
      request.conversationGeneration,
      "signer-fence conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(request.releaseProfileId),
    releaseTrustRootDigest: parseHash32(request.releaseTrustRootDigest),
    conversationId: parseConversationId(request.conversationId),
    position: parsePositiveUint63String(request.position),
    previousHeadHash: parseHash32(request.previousHeadHash),
    headHash: parseHash32(request.headHash),
    signingKeyId: parseSigningKeyId(request.signingKeyId),
    checkpointDigest: parseHash32(request.checkpointDigest),
    checkpointReceivedAt: parseRfc3339Millis(request.checkpointReceivedAt),
    pendingIntentDigest: parseHash32(request.pendingIntentDigest),
    fenceGeneration: fence.generation,
    fenceTokenHash: computeApplicationAppendFenceTokenHash(fence.token),
    pendingExpiresAt: parseRfc3339Millis(request.pendingExpiresAt),
    admissionStartedAt: parseRfc3339Millis(request.admissionStartedAt),
  });
}

export function parseApplicationAppendSignerFenceResolution(
  value: unknown,
  expectedRequest: DeliveryCheckpointSigningRequest,
): ApplicationAppendSignerFenceResolution {
  return parseApplicationAppendSignerFenceResolutionAgainstExpectation(
    value,
    buildApplicationAppendSignerFenceResolutionExpectation(expectedRequest),
  );
}

export function parseDurableApplicationAppendSignerFenceSignedResolution(
  value: unknown,
  expected: ApplicationAppendSignerFenceResolutionExpectation,
): DurableApplicationAppendSignerFenceSignedResolution {
  const resolution = parseApplicationAppendSignerFenceResolutionAgainstExpectation(
    value,
    expected,
  );
  if (resolution.status !== "signed") {
    throw new DeliveryValidationError(
      "Durable application append signer-fence record is not signed.",
    );
  }
  return resolution;
}

function parseApplicationAppendSignerFenceResolutionAgainstExpectation(
  value: unknown,
  expected: ApplicationAppendSignerFenceResolutionExpectation,
): ApplicationAppendSignerFenceResolution {
  const status = readOwnStatus(value);
  const signed = status === "signed";
  if (!signed && status !== "cancelled") {
    throw new DeliveryValidationError(
      "Application append signer-fence resolution status is unsupported.",
    );
  }
  const commonKeys = [
    "status",
    "profile",
    "realmId",
    "conversationGeneration",
    "releaseProfileId",
    "releaseTrustRootDigest",
    "conversationId",
    "position",
    "previousHeadHash",
    "headHash",
    "signingKeyId",
    "checkpointDigest",
    "checkpointReceivedAt",
    "pendingIntentDigest",
    "fenceGeneration",
    "fenceTokenHash",
    "pendingExpiresAt",
    "admissionStartedAt",
    "fenceRecordKeyProfile",
    "fenceRecordDigest",
    "fenceRecordSigningKeyId",
    "fenceRecordSignature",
  ] as const;
  const record = expectExactRecord(
    value,
    signed
      ? [...commonKeys, "checkpointSignature", "signedAt"]
      : [...commonKeys, "cancellationStatus", "cancelledAt"],
    "application append signer-fence resolution",
  );
  if (record.profile !== "application-append-signer-fence-resolution.v1") {
    throw new DeliveryValidationError(
      "Application append signer-fence resolution profile is unsupported.",
    );
  }
  const parsedCommon = {
    profile: "application-append-signer-fence-resolution.v1" as const,
    realmId: expected.realmId,
    conversationGeneration: parsePositiveUint63String(
      record.conversationGeneration,
      "signer-fence conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    releaseTrustRootDigest: parseHash32(record.releaseTrustRootDigest),
    conversationId: parseConversationId(record.conversationId),
    position: parsePositiveUint63String(record.position),
    previousHeadHash: parseHash32(record.previousHeadHash),
    headHash: parseHash32(record.headHash),
    signingKeyId: parseSigningKeyId(record.signingKeyId),
    checkpointDigest: parseHash32(record.checkpointDigest),
    checkpointReceivedAt: parseRfc3339Millis(record.checkpointReceivedAt),
    pendingIntentDigest: parseHash32(record.pendingIntentDigest),
    fenceGeneration: parsePositiveUint63String(record.fenceGeneration),
    fenceTokenHash: parseHash32(record.fenceTokenHash),
    pendingExpiresAt: parseRfc3339Millis(record.pendingExpiresAt),
    admissionStartedAt: parseRfc3339Millis(record.admissionStartedAt),
    fenceRecordKeyProfile: parseFenceRecordKeyProfile(
      record.fenceRecordKeyProfile,
    ),
    fenceRecordDigest: parseHash32(record.fenceRecordDigest),
    fenceRecordSigningKeyId: parseSigningKeyId(record.fenceRecordSigningKeyId),
    fenceRecordSignature: parseEd25519Signature(record.fenceRecordSignature),
  };
  if (
    record.realmId !== expected.realmId ||
    parsedCommon.conversationGeneration !==
      expected.conversationGeneration ||
    parsedCommon.releaseProfileId !== expected.releaseProfileId ||
    parsedCommon.releaseTrustRootDigest !==
      expected.releaseTrustRootDigest ||
    parsedCommon.conversationId !== expected.conversationId ||
    parsedCommon.position !== expected.position ||
    parsedCommon.previousHeadHash !== expected.previousHeadHash ||
    parsedCommon.headHash !== expected.headHash ||
    parsedCommon.signingKeyId !== expected.signingKeyId ||
    parsedCommon.checkpointDigest !== expected.checkpointDigest ||
    parsedCommon.checkpointReceivedAt !==
      expected.checkpointReceivedAt ||
    parsedCommon.pendingIntentDigest !== expected.pendingIntentDigest ||
    parsedCommon.fenceGeneration !== expected.fenceGeneration ||
    parsedCommon.fenceTokenHash !== expected.fenceTokenHash ||
    parsedCommon.pendingExpiresAt !== expected.pendingExpiresAt ||
    parsedCommon.admissionStartedAt !== expected.admissionStartedAt ||
    parsedCommon.fenceRecordKeyProfile !==
      "application-append-fence-record-ed25519.v1" ||
    parsedCommon.admissionStartedAt > parsedCommon.checkpointReceivedAt ||
    parsedCommon.checkpointReceivedAt >= parsedCommon.pendingExpiresAt
  ) {
    throw new DeliveryValidationError(
      "Application append signer-fence resolution is detached from its pending tuple.",
    );
  }
  const resolution = signed
    ? Object.freeze({
        status: "signed" as const,
        ...parsedCommon,
        checkpointSignature: parseEd25519Signature(record.checkpointSignature),
        signedAt: parseRfc3339Millis(record.signedAt),
      })
    : Object.freeze({
        status: "cancelled" as const,
        ...parsedCommon,
        cancellationStatus: parseIrreversibleCancellationStatus(
          record.cancellationStatus,
        ),
        cancelledAt: parseRfc3339Millis(record.cancelledAt),
      });
  const resolvedAt = resolution.status === "signed"
    ? resolution.signedAt
    : resolution.cancelledAt;
  if (
    (resolution.status === "signed" &&
      (resolvedAt < resolution.checkpointReceivedAt ||
        resolvedAt >= resolution.pendingExpiresAt)) ||
    (resolution.status === "cancelled" &&
      resolvedAt < resolution.pendingExpiresAt) ||
    resolution.fenceRecordDigest !==
      computeApplicationAppendSignerFenceRecordDigest(resolution)
  ) {
    throw new DeliveryValidationError(
      "Application append signer-fence resolution time or digest is invalid.",
    );
  }
  return resolution;
}

export function computeApplicationAppendSignerFenceRecordDigest(
  resolution: ApplicationAppendSignerFenceResolution,
): Hash32 {
  const statusFields = resolution.status === "signed"
    ? [
        parseCanonicalBase64UrlBytes(
          resolution.checkpointSignature,
          "fenced checkpoint signature",
          { minBytes: 64, maxBytes: 64 },
        ),
        utf8(resolution.signedAt),
      ]
    : [
        utf8(resolution.cancellationStatus),
        utf8(resolution.cancelledAt),
      ];
  return sha256Bytes(
    utf8(APPLICATION_APPEND_SIGNER_FENCE_RECORD_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(resolution.realmId),
      utf8(resolution.conversationGeneration),
      utf8(resolution.releaseProfileId),
      decodeHash32(resolution.releaseTrustRootDigest),
      utf8(resolution.conversationId),
      utf8(resolution.position),
      decodeHash32(resolution.previousHeadHash),
      decodeHash32(resolution.headHash),
      utf8(resolution.signingKeyId),
      decodeHash32(resolution.checkpointDigest),
      utf8(resolution.checkpointReceivedAt),
      decodeHash32(resolution.pendingIntentDigest),
      utf8(resolution.fenceGeneration),
      decodeHash32(resolution.fenceTokenHash),
      utf8(resolution.pendingExpiresAt),
      utf8(resolution.admissionStartedAt),
      utf8(resolution.status),
      ...statusFields,
      utf8(resolution.fenceRecordKeyProfile),
      utf8(resolution.fenceRecordSigningKeyId),
    ),
  );
}

export interface ApplicationAppendSignerFenceVerificationEvidence {
  profile: "application-append-signer-fence-evidence.v1";
  status: "verified";
  resolutionStatus: "signed" | "irreversible-cancelled";
  pendingIntentDigest: Hash32;
  fenceGeneration: Uint63String;
  fenceTokenHash: Hash32;
  fenceRecordKeyProfile: "application-append-fence-record-ed25519.v1";
  fenceRecordDigest: Hash32;
  fenceRecordSigningKeyId: SigningKeyId;
  fenceRecordSignatureSha256: Hash32;
  verifiedAt: Rfc3339Millis;
  keyStatus: "trusted-for-record";
  recordSignatureStatus: "verified";
  evidenceDigest: Hash32;
}

export function parseApplicationAppendSignerFenceVerificationEvidence(
  value: unknown,
  resolution: ApplicationAppendSignerFenceResolution,
  expectedVerifiedAt: Rfc3339Millis,
): ApplicationAppendSignerFenceVerificationEvidence {
  const record = expectExactRecord(
    value,
    [
      "profile",
      "status",
      "resolutionStatus",
      "pendingIntentDigest",
      "fenceGeneration",
      "fenceTokenHash",
      "fenceRecordKeyProfile",
      "fenceRecordDigest",
      "fenceRecordSigningKeyId",
      "fenceRecordSignatureSha256",
      "verifiedAt",
      "keyStatus",
      "recordSignatureStatus",
      "evidenceDigest",
    ],
    "application append signer-fence verification evidence",
  );
  const resolutionStatus = resolution.status === "signed"
    ? "signed" as const
    : "irreversible-cancelled" as const;
  const fenceRecordSignatureSha256 = sha256Bytes(
    parseCanonicalBase64UrlBytes(
      resolution.fenceRecordSignature,
      "signer-fence record signature",
      { minBytes: 64, maxBytes: 64 },
    ),
  );
  const parsed = Object.freeze({
    profile: "application-append-signer-fence-evidence.v1" as const,
    status: "verified" as const,
    resolutionStatus,
    pendingIntentDigest: parseHash32(record.pendingIntentDigest),
    fenceGeneration: parsePositiveUint63String(record.fenceGeneration),
    fenceTokenHash: parseHash32(record.fenceTokenHash),
    fenceRecordKeyProfile: record.fenceRecordKeyProfile,
    fenceRecordDigest: parseHash32(record.fenceRecordDigest),
    fenceRecordSigningKeyId: parseSigningKeyId(record.fenceRecordSigningKeyId),
    fenceRecordSignatureSha256: parseHash32(record.fenceRecordSignatureSha256),
    verifiedAt: parseRfc3339Millis(record.verifiedAt),
    keyStatus: record.keyStatus,
    recordSignatureStatus: record.recordSignatureStatus,
    evidenceDigest: parseHash32(record.evidenceDigest),
  });
  const resolvedAt = resolution.status === "signed"
    ? resolution.signedAt
    : resolution.cancelledAt;
  if (
    record.profile !== parsed.profile ||
    record.status !== parsed.status ||
    record.resolutionStatus !== resolutionStatus ||
    parsed.pendingIntentDigest !== resolution.pendingIntentDigest ||
    parsed.fenceGeneration !== resolution.fenceGeneration ||
    parsed.fenceTokenHash !== resolution.fenceTokenHash ||
    parsed.fenceRecordKeyProfile !==
      "application-append-fence-record-ed25519.v1" ||
    parsed.fenceRecordDigest !== resolution.fenceRecordDigest ||
    parsed.fenceRecordSigningKeyId !== resolution.fenceRecordSigningKeyId ||
    parsed.fenceRecordSignatureSha256 !== fenceRecordSignatureSha256 ||
    parsed.verifiedAt !== expectedVerifiedAt ||
    parsed.verifiedAt < resolvedAt ||
    parsed.keyStatus !== "trusted-for-record" ||
    parsed.recordSignatureStatus !== "verified" ||
    parsed.evidenceDigest !== computeApplicationAppendSignerFenceVerificationEvidenceDigest({
      resolution,
      resolutionStatus,
      fenceRecordSignatureSha256,
      verifiedAt: parsed.verifiedAt,
    })
  ) {
    throw new DeliveryValidationError(
      "Application append signer-fence verification evidence is invalid.",
    );
  }
  return parsed as ApplicationAppendSignerFenceVerificationEvidence;
}

export function computeApplicationAppendSignerFenceVerificationEvidenceDigest(input: {
  resolution: ApplicationAppendSignerFenceResolution;
  resolutionStatus: "signed" | "irreversible-cancelled";
  fenceRecordSignatureSha256: Hash32;
  verifiedAt: Rfc3339Millis;
}): Hash32 {
  return sha256Bytes(
    utf8(APPLICATION_APPEND_SIGNER_FENCE_VERIFICATION_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      decodeHash32(input.resolution.releaseTrustRootDigest),
      decodeHash32(input.resolution.pendingIntentDigest),
      utf8(input.resolution.fenceGeneration),
      decodeHash32(input.resolution.fenceTokenHash),
      utf8(input.resolution.fenceRecordKeyProfile),
      decodeHash32(input.resolution.fenceRecordDigest),
      utf8(input.resolution.fenceRecordSigningKeyId),
      decodeHash32(input.fenceRecordSignatureSha256),
      utf8(input.resolutionStatus),
      utf8(input.verifiedAt),
      utf8("trusted-for-record"),
      utf8("verified"),
    ),
  );
}

function parseIrreversibleCancellationStatus(
  value: unknown,
): "irreversible-cancelled" {
  if (value !== "irreversible-cancelled") {
    throw new DeliveryValidationError(
      "Application append cancellation is not irreversible.",
    );
  }
  return value;
}

function parseFenceRecordKeyProfile(
  value: unknown,
): "application-append-fence-record-ed25519.v1" {
  if (value !== "application-append-fence-record-ed25519.v1") {
    throw new DeliveryValidationError(
      "Application append fence-record key profile is unsupported.",
    );
  }
  return value;
}

export interface DeliveryCheckpointSignerReservationPort {
  /**
   * Durably signs the exact pending/fence/checkpoint tuple. Signing linearizes
   * with resolution and is permitted only strictly before pendingExpiresAt.
   */
  signExact(request: DeliveryCheckpointSigningRequest): Promise<unknown>;
  /**
   * One atomic signer-side operation. If the fence was signed before expiry it
   * returns that exact durable signature; otherwise, once expired, it records
   * and returns an irreversible cryptographically authenticated cancellation.
   */
  resolveOrCancelIfUnsigned(
    request: ApplicationAppendSignerFenceResolutionRequest,
  ): Promise<unknown>;
}

export interface ApplicationAppendSignerFenceEvidenceVerificationRequest {
  profile: "application-append-signer-fence-evidence.v1";
  resolution: ApplicationAppendSignerFenceResolution;
  verifiedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ApplicationAppendSignerFenceEvidenceVerifierPort {
  /**
   * Independently verifies the fence-record signature/key against the exact
   * release trust root and returns unknown strict evidence. Neither service nor
   * persistence may trust a syntax-only signed/cancelled resolution.
   */
  verify(
    request: ApplicationAppendSignerFenceEvidenceVerificationRequest,
  ): Promise<unknown>;
}

export interface DeliveryCheckpointProofInput {
  conversationId: ConversationId;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signature: Ed25519Signature;
  checkpointReceivedAt: Rfc3339Millis;
}

export interface DeliveryCheckpointSignatureVerificationRequest
  extends DeliveryCheckpointProofInput {
  profile: "delivery-log-checkpoint.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  verifiedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface DeliveryCheckpointSignatureVerifierPort {
  /** Verifies the exact signature and transparent key validity at this checkpoint. */
  verify(
    request: DeliveryCheckpointSignatureVerificationRequest,
  ): Promise<unknown>;
}

export interface DeliveryWitnessProofInput {
  conversationId: ConversationId;
  position: Uint63String;
  headHash: Hash32;
  witnessCheckpointId: WitnessCheckpointId;
  witnessTreeSize: Uint63String;
  witnessRootHash: Hash32;
  witnessKeyId: SigningKeyId;
  witnessSignature: Ed25519Signature;
  witnessedAt: Rfc3339Millis;
}

export interface DeliveryWitnessConsistencyAnchor {
  witnessCheckpointId: WitnessCheckpointId;
  witnessTreeSize: Uint63String;
  witnessRootHash: Hash32;
  witnessedAt: Rfc3339Millis;
}

export interface DeliveryTargetWelcomeProofInput {
  releaseProfileId: ReleaseProfileId;
  conversationId: ConversationId;
  expectedGroupIdHash: Hash32;
  commitEpoch: Uint63String;
  commitPosition: Uint63String;
  commitEnvelopeId: EnvelopeId;
  commitEnvelopeBytes: CanonicalBase64Url;
  commitEnvelopeSha256: Hash32;
  targetAccountId: AccountId;
  targetInstallationId: InstallationId;
  targetCredentialId: CredentialId;
  targetCredentialFingerprint: Fingerprint32;
  welcome: CanonicalBase64Url;
  welcomeSha256: Hash32;
}

export interface ConversationPageProofVerificationRequest {
  profile: "conversation-page-proof-bundle.v1";
  realmId: DeliveryRealmId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  checkpoints: readonly DeliveryCheckpointProofInput[];
  witness: DeliveryWitnessProofInput;
  /** Signature-verified release/bootstrap checkpoint or later persisted anchor. */
  priorWitness: DeliveryWitnessConsistencyAnchor;
  witnessTrustMode: "continuity";
  targetWelcome: DeliveryTargetWelcomeProofInput | null;
  verifiedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ConversationPageProofVerifierPort {
  /**
   * Verifies every delivery signature plus witness inclusion, consistency,
   * freshness, and key validity. The untrusted result is matched field-for-
   * field by the sync verifier; a partial or unavailable result grants nothing.
   */
  verify(request: ConversationPageProofVerificationRequest): Promise<unknown>;
}

export interface ConversationLogHeadProofVerificationRequest {
  profile: "conversation-log-head-proof.v1";
  realmId: DeliveryRealmId;
  accountId: AccountId;
  installationId: InstallationId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  verifiedPrefixEvidenceDigest: Hash32;
  membershipBootstrapMode: "creator" | "welcome";
  membershipCredentialId: CredentialId;
  membershipCredentialFingerprint: Fingerprint32;
  membershipJoinedPosition: Uint63String;
  membershipRemovedPosition: Uint63String | null;
  visibilityMode: "active-high-water" | "removed-boundary";
  removedPosition: Uint63String | null;
  fromPosition: Uint63String;
  fromHeadHash: Hash32;
  current: DeliveryCheckpointProofInput;
  witness: DeliveryWitnessProofInput;
  priorWitness: DeliveryWitnessConsistencyAnchor;
  verifiedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ConversationLogHeadProofVerifierPort {
  /**
   * Verifies the exact current caller-visible head, checkpoint key/time,
   * witness inclusion/freshness/consistency, and append-only consistency from
   * the caller's persisted head. The adapter must resolve the exact durable
   * prefix named by verifiedPrefixEvidenceDigest and match the complete
   * account/installation/membership window before proving visibility. Removed
   * members are capped exactly at their signed removal Commit and receive no
   * post-removal high-water information.
   */
  verify(request: ConversationLogHeadProofVerificationRequest): Promise<unknown>;
}

export interface AtomicApplicationAppendCommand {
  realmId: DeliveryRealmId;
  idempotencyKey: IdempotencyKey;
  requestCommitment: Hash32;
  semanticIdentity: ApplicationEnvelopeSemanticIdentity;
  authenticatedCredentialId: CredentialId;
  authenticatedCredentialFingerprint: Fingerprint32;
  authenticatedCredentialRevocationVersion: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  /** Archived limits pinned by this exact conversation generation. */
  deliveryLimits: DeliveryLimits;
}

export interface DeliveryInvocationContext {
  /** Control-plane deadline; excluded from durable command/intent digests. */
  invocationStartedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ApplicationAppendCompletionTimeExpectation {
  invocationStartedAt: Rfc3339Millis;
  /** DB-authoritative fresh observation included in this phase response. */
  observedAt: Rfc3339Millis;
  /** Fresh trusted local-clock reading taken after the DB call returned. */
  observedCompletedAt: Rfc3339Millis;
  deadline: Rfc3339Millis;
}

export function parseApplicationAppendFinalizedAt(
  value: unknown,
  expected: ApplicationAppendCompletionTimeExpectation,
): Rfc3339Millis {
  return parseApplicationAppendCompletionTime(value, expected, "finalizedAt");
}

export function parseApplicationAppendRetiredAt(
  value: unknown,
  expected: ApplicationAppendCompletionTimeExpectation,
): Rfc3339Millis {
  return parseApplicationAppendCompletionTime(value, expected, "retiredAt");
}

function parseApplicationAppendCompletionTime(
  value: unknown,
  expected: ApplicationAppendCompletionTimeExpectation,
  field: "finalizedAt" | "retiredAt",
): Rfc3339Millis {
  const invocationStartedAt = parseRfc3339Millis(
    expected.invocationStartedAt,
    "application append invocation start",
  );
  const observedCompletedAt = parseRfc3339Millis(
    expected.observedCompletedAt,
    "application append completion observation",
  );
  const observedAt = parseRfc3339Millis(
    expected.observedAt,
    "application append persistence observedAt",
  );
  const deadline = parseRfc3339Millis(
    expected.deadline,
    "application append invocation deadline",
  );
  const parsed = parseRfc3339Millis(value, `application append ${field}`);
  if (
    invocationStartedAt >= deadline ||
    observedCompletedAt < invocationStartedAt ||
    observedCompletedAt >= deadline ||
    observedAt < invocationStartedAt ||
    observedAt > observedCompletedAt ||
    parsed > observedAt
  ) {
    throw new DeliveryValidationError(
      `Application append ${field} is outside its authoritative invocation interval.`,
    );
  }
  return parsed;
}

export interface ApplicationAppendPreflightReaderPort {
  /**
   * Performs a bounded, consistent, read-only lookup. Its unknown result must
   * be strictly parsed and snapshot-digested before any external proof call.
   * It may report an exact accepted/pending idempotency replay, but never
   * creates a reservation or receipt.
   */
  read(
    command: AtomicApplicationAppendCommand,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown>;
}

export interface AtomicApplicationAppendReservation {
  command: AtomicApplicationAppendCommand;
  /** Immutable start of this admission attempt, durably bound into pending. */
  admissionStartedAt: Rfc3339Millis;
  /** Recomputed over every persisted preflight field; this is the DB CAS. */
  expectedSnapshotDigest: Hash32;
  /**
   * Digest after replacing only the policy evaluation-proof projection with
   * the separately verified current-head evidence. It is authorization input,
   * not a claim that the underlying signed policy head changed.
   */
  expectedAuthorizationSnapshotDigest: Hash32;
  /** Strictly parsed/bound by both the service and persistence adapter. */
  wireInspectionEvidence: unknown;
  /** Strictly parsed/bound by both the service and persistence adapter. */
  policyHeadProofEvidence: unknown;
}

export interface ReserveApplicationAppendTransactionContext {
  /** Must be parsed with parseLockedApplicationAppendSnapshot. */
  lockedSnapshot: unknown;
  /** Database/clock-adapter timestamp; must be parsed before use. */
  authoritativeReceivedAt: unknown;
  /** Must equal the locked conversation chain head before the new leaf. */
  previousHeadHash: unknown;
  /** Sum of locked, finalized, owned attachment ciphertext bytes. */
  attachmentByteLength: unknown;
  /** Active transparent checkpoint key selected under the same lock. */
  activeSigningKeyId: unknown;
  /** Exclusive key-validity bound selected with activeSigningKeyId. */
  activeSigningKeyValidUntil: unknown;
  /** Newly allocated opaque durable lane generation/token. */
  reservationFence: unknown;
  /**
   * Complete locked canonical active MLS roster projection. The common
   * derivation recomputes the roster commitment before considering routing.
   */
  mlsRosterProjections: unknown;
  /** Complete locked routing/install projection, including ineligible rows. */
  recipientProjections: unknown;
  /** Adapter-enforced DB transaction/statement deadline. */
  transactionDeadline: unknown;
}

/** Must be synchronous and local-only: no network, KMS, witness, or MLS call. */
export type PrepareUnsignedApplicationAppend = (
  context: ReserveApplicationAppendTransactionContext,
) => unknown;

export interface FinalizeApplicationAppendInput {
  command: AtomicApplicationAppendCommand;
  /** Exact immutable pending intent returned by reserve. */
  pendingIntent: unknown;
  pendingIntentDigest: Hash32;
  reservationFence: ApplicationAppendReservationFence;
  pendingExpiresAt: Rfc3339Millis;
  invocationStartedAt: Rfc3339Millis;
  /** Exact canonical plan already bound into the immutable pending intent. */
  fanoutPlan: unknown;
  /** Exact signature whose hash and tuple are bound by the evidence. */
  signature: Ed25519Signature;
  /** Exact active-key signature verification evidence. */
  verifiedSignatureEvidence: unknown;
  /** Bearer-free durable signer record; must match pending, signature, and fence. */
  signedFenceResolution: DurableApplicationAppendSignerFenceSignedResolution;
  /** Independently trust-root-verified durable signed-fence evidence. */
  verifiedSignerFenceEvidence: unknown;
}

export interface RetireExpiredApplicationAppendInput {
  /** Current invocation; may differ from the immutable pending admission. */
  command: AtomicApplicationAppendCommand;
  pendingIntent: unknown;
  pendingIntentDigest: Hash32;
  reservationFence: ApplicationAppendReservationFence;
  pendingExpiresAt: Rfc3339Millis;
  invocationStartedAt: Rfc3339Millis;
  /** Exact raw irreversible-cancellation resolution authenticated by verifier. */
  cancellationResolution: ApplicationAppendSignerFenceCancelledResolution;
  /** Strict trust-root verification evidence for cancellationResolution. */
  verifiedCancellationEvidence: unknown;
}

export interface AtomicDeliveryPersistencePort {
  /**
   * Re-locks all authoritative rows, requires an exact preflight snapshot
   * digest, reconstructs the one-field-class authorization overlay, requires
   * its exact digest, revalidates proof bindings/freshness at receivedAt,
   * and commits only an immutable pending intent. The callback is synchronous
   * and local-only. It cannot perform any remote await while locks are held.
   * Exactly one live intent may fence a conversation lane. An exact retry
   * resumes that intent; a different command conflicts. Reservation does not
   * advance committed lastPosition, and no competitor may claim the fenced
   * position/head. Abandonment is an explicit durable generation transition;
   * its fence token can never be reused by a late signer or finalizer.
   * A strict result returns immutable DB-authoritative `reservedAt` plus a
   * fresh DB-authoritative `observedAt`. Only observedAt is bracketed by the
   * current invocation; reservedAt may predate it on response-loss recovery.
   */
  reserveApplicationAppendAtomically(
    reservation: AtomicApplicationAppendReservation,
    prepareUnsigned: PrepareUnsignedApplicationAppend,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown>;
  /**
   * Re-locks and exactly revalidates the pending intent and active-key
   * signature evidence, then commits envelope/state/mailboxes/outbox,
   * idempotency result, and durability receipt in one serializable RPO-0
   * transaction. No unsigned success or fabricated receipt is permitted.
   * `command` is the current invocation; pendingIntent contains the immutable
   * original admission profile/limits. Replay equality is request commitment
   * plus full authenticated semantic identity, never ambient manifest equality.
   * A strict accepted result returns immutable DB-authoritative `finalizedAt`
   * plus a fresh DB-authoritative `observedAt`. Only observedAt is bracketed by
   * the current invocation; finalizedAt may predate it on response-loss replay.
   */
  finalizeApplicationAppendAtomically(
    input: FinalizeApplicationAppendInput,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown>;
  /**
   * Re-locks the exact pending/fence/capacity reservations, requires signer-
   * authenticated irreversible unsigned cancellation and authoritative DB now
   * at/after pendingExpiresAt, then releases only this pending's reserved
   * capacity. It writes immutable audit/fence tombstones and bumps the lane
   * generation; it never erases signer history or reuses a fence token. Since
   * no envelope was signed or accepted, a later higher-generation/new-token
   * reservation may again claim the still-current `lastPosition + 1`. Signed
   * or accepted positions are never reusable.
   * The same exact command may re-admit, but changed HTTP commitment or
   * semantic reuse of the old idempotency/envelope identities conflicts
   * forever. If a pre-expiry signature exists, retirement is forbidden and the
   * original pending must be finalized/recovered before a different command is
   * preflighted again.
   * A strict retirement result returns immutable DB-authoritative `retiredAt`
   * plus a fresh DB-authoritative `observedAt`. Only observedAt is bracketed by
   * the current invocation; retiredAt may predate a recovery invocation.
   */
  retireExpiredApplicationAppendAtomically(
    input: RetireExpiredApplicationAppendInput,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown>;
}

export interface DeliveryClockPort {
  /** Local synchronous clock; result remains untrusted until strictly parsed. */
  now(): unknown;
}

export interface ConversationCursorAuthenticationRejected {
  status: "invalid";
  reasonCode: "authentication-failed";
}

export function parseConversationCursorAuthenticationRejected(
  value: unknown,
): ConversationCursorAuthenticationRejected {
  const record = expectExactRecord(
    value,
    ["status", "reasonCode"],
    "conversation cursor authentication rejection",
  );
  if (
    record.status !== "invalid" ||
    record.reasonCode !== "authentication-failed"
  ) {
    throw new DeliveryValidationError(
      "Conversation cursor authentication rejection is unsupported.",
    );
  }
  return Object.freeze({
    status: "invalid",
    reasonCode: "authentication-failed",
  });
}

export interface ConversationCursorCodecPort {
  /**
   * AES-GCM `cc1.` single-blob decode; output remains untrusted. Tag, AAD,
   * version, KID, or context failure returns the exact authenticated-rejection
   * result. A structurally valid but expired token still returns authenticated
   * claims so the caller can distinguish `cursor_expired` from `invalid_cursor`.
   */
  decode(input: {
    encodedCursor: string;
    context: ConversationCursorContext;
    now: Rfc3339Millis;
    deadline: Rfc3339Millis;
    signal: AbortSignal;
  }): Promise<unknown>;
  /** AES-GCM `cc1.` single-blob encode; output remains untrusted. */
  encode(input: {
    plaintext: ConversationCursorPlaintext;
    context: ConversationCursorContext;
    deadline: Rfc3339Millis;
    signal: AbortSignal;
  }): Promise<unknown>;
}

export interface DeliveryInvariantIncidentPort {
  /** Records only bounded identifiers/digests; never ciphertext or cursor bytes. */
  record(input: {
    incidentCode:
      | "conversation-log-fork"
      | "conversation-position-gap"
      | "checkpoint-substitution"
      | "cursor-binding-failure"
      | "atomic-persistence-ambiguity";
    conversationId: ConversationId | null;
    evidenceDigest: Hash32;
    detectedAt: Rfc3339Millis;
    deadline: Rfc3339Millis;
    signal: AbortSignal;
  }): Promise<unknown>;
}

export interface ProductionDeliveryPorts {
  mlsWireInspector: MlsWireInspectorPort;
  mlsCommitProjectionVerifier: MlsCommitProjectionVerifierPort;
  mlsExternalProposalVerifier: MlsExternalProposalVerifierPort;
  conversationPolicyReplayVerifier: ConversationPolicyReplayVerifierPort;
  policyHeadProofVerifier: PolicyHeadProofVerifierPort;
  checkpointSigner: DeliveryCheckpointSignerReservationPort;
  signerFenceEvidenceVerifier: ApplicationAppendSignerFenceEvidenceVerifierPort;
  checkpointSignatureVerifier: DeliveryCheckpointSignatureVerifierPort;
  conversationPageProofVerifier: ConversationPageProofVerifierPort;
  conversationLogHeadProofVerifier: ConversationLogHeadProofVerifierPort;
  applicationAppendPreflight: ApplicationAppendPreflightReaderPort;
  atomicPersistence: AtomicDeliveryPersistencePort;
  clock: DeliveryClockPort;
  conversationCursorCodec: ConversationCursorCodecPort;
  invariantIncident: DeliveryInvariantIncidentPort;
}

function readOwnStatus(value: unknown): unknown {
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      throw new DeliveryValidationError(
        "Application append signer-fence resolution must be a plain object.",
      );
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, "status");
    if (!descriptor || !("value" in descriptor)) {
      throw new DeliveryValidationError(
        "Application append signer-fence resolution status is missing.",
      );
    }
    return descriptor.value;
  } catch (error) {
    if (error instanceof DeliveryValidationError) throw error;
    throw new DeliveryValidationError(
      "Application append signer-fence resolution is inaccessible.",
    );
  }
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
