import {
  MAX_APPLICATION_ENVELOPE_BYTES,
  MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES,
  MAX_MLS_COMMIT_ENVELOPE_BYTES,
  parseStoredEnvelope,
  type StoredEnvelope,
} from "./envelopes";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  canonicalLengthPrefixed,
  sha256Bytes,

  EXTERNAL_PROPOSAL_HASH_DOMAIN,
  computeExternalProposalHash,
} from "./hashes";
import {
  parseDeliveryLimits,
  type DeliveryLimits,
} from "./limits";
import {
  computePolicyHeadProofEvidenceDigest,
  computeDeliveryLimitsDigest,
  parsePolicyHeadProofEvidence,
  type PolicyHeadProofEvidence,
} from "./state";
import {
  parseDeliveryPortUnavailable,
  type DeliveryPortUnavailable,
  type ConversationCursorCodecPort,
  type ConversationPageProofVerificationRequest,
  type ConversationPageProofVerifierPort,
  type PolicyHeadProofVerificationRequest,
  type PolicyHeadProofVerifierPort,
  type DeliveryCheckpointProofInput,
  type DeliveryCheckpointSignatureVerificationRequest,
  type DeliveryWitnessConsistencyAnchor,
  type MlsCommitProjectionVerificationRequest,
  type MlsCommitProjectionVerifierPort,
  type MlsExternalProposalVerificationRequest,
  type MlsExternalProposalVerifierPort,
  type MlsStagedExternalProposalBinding,
  type MlsCommittedIntentBinding,
  type MlsMembershipTargetIdentity,
  type PolicyMandatoryProposalBinding,
  type ConversationPolicyReplayProjection,
  type ConversationPolicyReplayTransition,
  type ConversationPolicyReplayVerificationRequest,
  type ConversationPolicyReplayVerifierPort,
  type DeliveryInvariantIncidentPort,
  type ConversationLogHeadProofVerificationRequest,
  type ConversationLogHeadProofVerifierPort,
  DELIVERY_MANDATORY_PROPOSALS_MAX,
} from "./ports";
import {
  ZERO_HASH32,
  UINT63_MAX_STRING,
  copyBytes,
  expectExactRecord,
  parseAccountId,
  parseCanonicalBase64Url,
  parseCanonicalBase64UrlBytes,
  parseConversationEtag,
  parseConversationId,
  parseCredentialId,
  decodeCanonicalBase64Url,
  decodeHash32,
  decodeFingerprint32,
  parseEd25519Signature,
  parseEnvelopeId,
  parseFingerprint32,
  parseHash32,
  parseInstallationId,
  parseMembershipIntentId,
  parsePolicyHeadId,
  parseProposalId,
  parseReleaseProfileId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  parseWitnessCheckpointId,
  type AccountId,
  type CanonicalBase64Url,
  type ConversationEtag,
  type ConversationId,
  type CredentialId,
  type Ed25519Signature,
  type EnvelopeId,
  type Fingerprint32,
  type Hash32,
  type InstallationId,
  type MembershipIntentId,
  type PolicyHeadId,
  type ProposalId,
  type Rfc3339Millis,
  type ReleaseProfileId,
  type SigningKeyId,
  type Uint63String,
  type WitnessCheckpointId,
} from "./valueObjects";

export const CONVERSATION_CURSOR_PREFIX = "cc1." as const;
export const CONVERSATION_CURSOR_PROFILE =
  "conversation-cursor-aes-256-gcm.v1" as const;
export const CONVERSATION_EVENTS_ROUTE_TEMPLATE =
  "/v1/conversations/{conversationId}/events" as const;
export const CONVERSATION_CURSOR_MAX_LIFETIME_MILLISECONDS =
  30 * 24 * 60 * 60 * 1_000;
export const CONVERSATION_SYNC_MAX_PORT_WAIT_MILLISECONDS = 15_000;
export const CONVERSATION_PAGE_HARD_MAX_EVENTS = 500;
export const CONVERSATION_POLICY_REPLAY_MAX_COALESCED_TRANSITIONS =
  CONVERSATION_PAGE_HARD_MAX_EVENTS + 1;
export const CONVERSATION_PAGE_HARD_MAX_DECODED_ARTIFACT_BYTES = 4 * 1024 * 1024;
export const CONVERSATION_PAGE_HARD_MAX_SERIALIZED_BYTES = 8 * 1024 * 1024;
export const CONVERSATION_LOG_HEAD_HARD_MAX_SERIALIZED_BYTES = 64 * 1024;
export const CONVERSATION_PAGE_HARD_MAX_FIRST_ITEM_BYTES = 768 * 1024;
export const CONVERSATION_WELCOME_HARD_MAX_BYTES = 256 * 1024;
export const CONVERSATION_SYNC_INCIDENT_MAX_WAIT_MILLISECONDS = 100;
export const CHECKPOINT_PROOF_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-checkpoint-proof-evidence/v1" as const;
export const WITNESS_PROOF_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-witness-proof-evidence/v1" as const;
export const PAGE_PROOF_BUNDLE_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-page-proof-bundle-evidence/v1" as const;
export const CHECKPOINT_SIGNATURE_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-checkpoint-signature-evidence/v1" as const;
export const TARGET_WELCOME_PROOF_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-target-welcome-proof-evidence/v1" as const;
export const MLS_COMMIT_PROJECTION_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-mls-commit-projection-evidence/v1" as const;
export const MLS_EXTERNAL_PROPOSAL_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-mls-external-proposal-evidence/v1" as const;
export const MLS_EXTERNAL_PROPOSAL_HASH_DOMAIN = EXTERNAL_PROPOSAL_HASH_DOMAIN;
export const POLICY_MANDATORY_PROPOSAL_SET_HASH_DOMAIN =
  "jb-msg-policy-mandatory-proposal-set/v1" as const;
export const CONVERSATION_POLICY_REPLAY_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-conversation-policy-replay-evidence/v1" as const;
export const CONVERSATION_VERIFIED_PREFIX_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-conversation-verified-prefix/v1" as const;
export const CONVERSATION_SYNC_INCIDENT_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-conversation-sync-incident/v1" as const;
export const CONVERSATION_LOG_HEAD_PROOF_EVIDENCE_DIGEST_DOMAIN =
  "jb-msg-conversation-log-head-proof-evidence/v1" as const;
export const MLS_EXTERNAL_SIGNER_MAX_LIFETIME_MILLISECONDS =
  90 * 24 * 60 * 60 * 1_000;

const REALM_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CURSOR_BASE64URL = /^[A-Za-z0-9_-]+$/;
const CURSOR_KIND = "conversation-cursor-claims.v1" as const;
const MAX_STRICT_JSON_DEPTH = 20;
const MAX_STRICT_JSON_NODES = 50_000;

const STORED_ENVELOPE_COMMON_KEYS = [
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
  "logHeadSignature",
] as const;

const STORED_COMMIT_KEYS = [
  ...STORED_ENVELOPE_COMMON_KEYS,
  "baseConfirmedTranscriptHash",
  "resultingConfirmedTranscriptHash",
] as const;

declare const syncValueBrand: unique symbol;
export type DeliveryRealmId = string & {
  readonly [syncValueBrand]: "DeliveryRealmId";
};

export interface ConversationCursorContext {
  realmId: DeliveryRealmId;
  accountId: AccountId;
  installationId: InstallationId;
  conversationId: ConversationId;
  routeTemplate: typeof CONVERSATION_EVENTS_ROUTE_TEMPLATE;
}

export interface ConversationCursorClaims extends ConversationCursorContext {
  kind: typeof CURSOR_KIND;
  profile: typeof CONVERSATION_CURSOR_PROFILE;
  encodedCursor: string;
  lastReturnedPosition: Uint63String;
  issuedAt: Rfc3339Millis;
  expiresAt: Rfc3339Millis;
  keyId: SigningKeyId;
  authenticated: true;
}

/** Exact encrypted cc1 plaintext; account and route are AAD-only. */
export interface ConversationCursorPlaintext {
  kind: typeof CURSOR_KIND;
  profile: typeof CONVERSATION_CURSOR_PROFILE;
  realmId: DeliveryRealmId;
  installationId: InstallationId;
  conversationId: ConversationId;
  lastReturnedPosition: Uint63String;
  issuedAt: Rfc3339Millis;
  expiresAt: Rfc3339Millis;
  keyId: SigningKeyId;
}

export interface ConversationMembershipWindow {
  bootstrapMode: "creator" | "welcome";
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  joinedPosition: Uint63String;
  removedPosition: Uint63String | null;
}

export interface ConversationHeadAnchor {
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  checkpointReceivedAt: Rfc3339Millis | null;
}

export interface TargetWelcome {
  targetInstallationId: InstallationId;
  welcome: CanonicalBase64Url;
  welcomeSha256: Hash32;
}

export interface ConversationEventItem {
  envelope: StoredEnvelope;
  welcome: TargetWelcome | null;
}

export interface SignedDeliveryLogHead {
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signature: Ed25519Signature;
  checkpointReceivedAt: Rfc3339Millis;
}

export interface DeliveryLogWitnessReceipt {
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

export interface ConversationPageSnapshot {
  conversationId: ConversationId;
  generation: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  etag: ConversationEtag;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  confirmedTranscriptHash: Hash32;
  policyHeadId: PolicyHeadId;
  policyRevision: Uint63String;
  policyMandatoryProposalCount: Uint63String;
  policyMandatoryProposalSetHash: Hash32;
  policyMandatoryProposals: readonly PolicyMandatoryProposalBinding[];
  policyAuthorizedSendGrantSetHash: Hash32;
  policyAuthorizedQuotaPolicyDigest: Hash32;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  policyDeliveryLogPosition: Uint63String;
  policyDeliveryLogHeadHash: Hash32;
  policyWitnessCheckpointId: WitnessCheckpointId;
  policyWitnessEvidenceDigest: Hash32;
  logHead: SignedDeliveryLogHead;
  witnessReceipt: DeliveryLogWitnessReceipt;
}

export interface VerifiedConversationPage {
  events: readonly ConversationEventItem[];
  nextCursor: string;
  nextCursorClaims: ConversationCursorClaims;
  hasMore: boolean;
  snapshot: ConversationPageSnapshot;
  decodedArtifactBytes: Uint63String;
  serializedBytes: Uint63String;
  proofEvidence: ConversationPageProofEvidence;
  policyHeadEvidence: ConversationPolicyHeadProofEvidence;
  policyReplayEvidence: ConversationPolicyReplayEvidence;
  commitProjectionEvidence: readonly MlsCommitProjectionEvidence[];
  externalProposalEvidence: readonly MlsExternalProposalEvidence[];
  stagedProposalsAtPageEnd: readonly MlsStagedExternalProposalBinding[];
}

type StructurallyVerifiedConversationPage = Omit<
  VerifiedConversationPage,
  | "nextCursorClaims"
  | "proofEvidence"
  | "policyHeadEvidence"
  | "policyReplayEvidence"
  | "commitProjectionEvidence"
  | "externalProposalEvidence"
  | "stagedProposalsAtPageEnd"
>;

export interface DeliveryCheckpointProofEvidence {
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signatureSha256: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  signatureStatus: "verified";
  keyStatus: "valid-for-checkpoint";
  evidenceDigest: Hash32;
}

export interface DeliveryWitnessProofEvidence {
  position: Uint63String;
  headHash: Hash32;
  witnessCheckpointId: WitnessCheckpointId;
  witnessTreeSize: Uint63String;
  witnessRootHash: Hash32;
  witnessKeyId: SigningKeyId;
  witnessSignatureSha256: Hash32;
  witnessedAt: Rfc3339Millis;
  priorWitnessCheckpointId: WitnessCheckpointId | null;
  priorWitnessTreeSize: Uint63String | null;
  priorWitnessRootHash: Hash32 | null;
  signatureStatus: "verified";
  keyStatus: "valid-for-checkpoint";
  inclusionStatus: "verified";
  consistencyStatus: "verified" | "bootstrap";
  freshnessStatus: "fresh";
  evidenceDigest: Hash32;
}

export interface ConversationPageProofEvidence {
  profile: "conversation-page-proof-bundle.v1";
  realmId: DeliveryRealmId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  verifiedAt: Rfc3339Millis;
  checkpoints: readonly DeliveryCheckpointProofEvidence[];
  witness: DeliveryWitnessProofEvidence;
  targetWelcome: TargetWelcomeProofEvidence | null;
  bundleEvidenceDigest: Hash32;
}

export interface TargetWelcomeProofEvidence {
  releaseProfileId: ReleaseProfileId;
  expectedGroupIdHash: Hash32;
  commitEpoch: Uint63String;
  commitPosition: Uint63String;
  commitEnvelopeId: EnvelopeId;
  commitEnvelopeSha256: Hash32;
  targetAccountId: AccountId;
  targetInstallationId: InstallationId;
  targetCredentialId: CredentialId;
  targetCredentialFingerprint: Fingerprint32;
  welcomeSha256: Hash32;
  addCommitStatus: "verified";
  membershipStatus: "verified";
  resultingRosterMembershipStatus: "verified-present";
  mailboxBindingStatus: "verified";
  evidenceDigest: Hash32;
}

export type ConversationPolicyHeadProofEvidence = PolicyHeadProofEvidence;

export interface ConversationPolicyReplayEvidence {
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
  events: readonly Readonly<{
    position: Uint63String;
    envelopeId: EnvelopeId;
    envelopeClass: "application" | "external_proposal" | "mls_commit";
    envelopeSha256: Hash32;
    headHash: Hash32;
  }>[];
  transitions: readonly ConversationPolicyReplayTransition[];
  transitionCompactionStatus: "verified-complete";
  transitionRangeProofDigest: Hash32;
  historicalIntervalStatus: "verified";
  applicationCutoffStatus: "verified";
  policyConsistencyStatus: "verified";
  policyConsistencyEvidenceDigest: Hash32;
  verifiedAt: Rfc3339Millis;
  evidenceDigest: Hash32;
}

export interface DeliveryCheckpointSignatureEvidence {
  profile: "delivery-log-checkpoint.v1";
  realmId: DeliveryRealmId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signatureSha256: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  verifiedAt: Rfc3339Millis;
  keyState: "active";
  validFrom: Rfc3339Millis;
  validUntil: Rfc3339Millis;
  evidenceDigest: Hash32;
}

export interface MlsCommitProjectionEvidence {
  profile: "mls-commit-projection.v1";
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeSha256: Hash32;
  expectedAccountId: AccountId;
  expectedInstallationId: InstallationId;
  expectedCredentialId: CredentialId;
  expectedCredentialFingerprint: Fingerprint32;
  expectedCredentialRevocationVersion: Uint63String;
  expectedSenderGeneration: Uint63String;
  authenticatedCredentialId: CredentialId;
  authenticatedCredentialFingerprint: Fingerprint32;
  authenticatedCredentialRevocationVersion: Uint63String;
  authenticatedSenderGeneration: Uint63String;
  senderBindingStatus: "verified";
  commitEpoch: Uint63String;
  commitRosterVersion: Uint63String;
  previousEpoch: Uint63String;
  previousRosterVersion: Uint63String;
  previousConfirmedTranscriptHash: Hash32;
  baseConfirmedTranscriptHash: Hash32;
  resultingConfirmedTranscriptHash: Hash32;
  commitKind: "membership" | "update";
  resultingEpoch: Uint63String;
  resultingRosterVersion: Uint63String;
  stagedProposals: readonly MlsStagedExternalProposalBinding[];
  requiredProposals: readonly PolicyMandatoryProposalBinding[];
  consumedProposals: readonly MlsStagedExternalProposalBinding[];
  committedIntents: readonly MlsCommittedIntentBinding[];
  proposalConsumptionStatus: "verified";
  intentBindingStatus: "verified";
  creatorBootstrapTarget: MlsMembershipTargetIdentity | null;
  creatorMembershipStatus: "verified-present" | "not-applicable";
  removalTarget: MlsMembershipTargetIdentity | null;
  removalProposalId: ProposalId | null;
  removalProposalHash: Hash32 | null;
  removalMembershipStatus: "verified-absent" | "not-applicable";
  projectionStatus: "verified";
  evidenceDigest: Hash32;
}

export interface MlsExternalProposalEvidence {
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
  envelopeSha256: Hash32;
  epoch: Uint63String;
  rosterVersion: Uint63String;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  signerGeneration: Uint63String;
  checkpointReceivedAt: Rfc3339Millis;
  pageEndPosition: Uint63String;
  pageEndHeadHash: Hash32;
  pageEndPolicyHeadSequence: Uint63String;
  pageEndPolicyHeadHash: Hash32;
  priorPolicyHeadSequence: Uint63String;
  priorPolicyHeadHash: Hash32;
  priorPolicyWitnessCheckpointId: WitnessCheckpointId;
  priorPolicyWitnessEvidenceDigest: Hash32;
  policyLogHighWaterSequence: Uint63String;
  policyLogHighWaterHash: Hash32;
  policyLogHighWaterWitnessCheckpointId: WitnessCheckpointId;
  policyLogHighWaterWitnessEvidenceDigest: Hash32;
  authorizingPolicyHeadId: PolicyHeadId;
  authorizingPolicyHeadSequence: Uint63String;
  authorizingPolicyHeadHash: Hash32;
  proposalId: ProposalId;
  proposalHash: Hash32;
  authorizationRecordHash: Hash32;
  membershipIntentId: MembershipIntentId;
  membershipIntentHash: Hash32;
  membershipIntentEvidenceDigest: Hash32;
  proposalRecordBindingStatus: "verified-one-to-one";
  intentRecordBindingStatus: "verified-one-to-one";
  recordBindingEvidenceDigest: Hash32;
  proposalType: "add" | "remove";
  proposalRequirement: "mandatory" | "optional";
  proposalBodySha256: Hash32;
  activeCredentialStatus: "active";
  credentialValidFrom: Rfc3339Millis;
  credentialValidUntil: Rfc3339Millis;
  publicationWitnessCheckpointId: WitnessCheckpointId;
  publicationWitnessEvidenceDigest: Hash32;
  credentialPublicationStatus: "verified";
  authorizationRecordStatus: "verified";
  policyAuthorizationStatus: "active-at-proposal";
  policyConsistencyStatus: "verified";
  policyConsistencyEvidenceDigest: Hash32;
  proposalStatus: "verified";
  evidenceDigest: Hash32;
}

export interface ConversationMlsProjection {
  epoch: Uint63String;
  rosterVersion: Uint63String;
  confirmedTranscriptHash: Hash32;
}

export interface ConversationPolicyProjection {
  etag: ConversationEtag;
  policyHeadId: PolicyHeadId;
  policyRevision: Uint63String;
  policyMandatoryProposalCount: Uint63String;
  policyMandatoryProposalSetHash: Hash32;
  policyMandatoryProposals: readonly PolicyMandatoryProposalBinding[];
  policyAuthorizedSendGrantSetHash: Hash32;
  policyAuthorizedQuotaPolicyDigest: Hash32;
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  policyDeliveryLogPosition: Uint63String;
  policyDeliveryLogHeadHash: Hash32;
  policyWitnessCheckpointId: WitnessCheckpointId;
  policyWitnessEvidenceDigest: Hash32;
}

export interface ConversationMlsCommitSenderBinding {
  accountId: AccountId;
  installationId: InstallationId;
  credentialId: CredentialId;
  credentialFingerprint: Fingerprint32;
  credentialRevocationVersion: Uint63String;
  senderGeneration: Uint63String;
  activeFromPosition: Uint63String;
  inactiveAtPosition: Uint63String | null;
}

export interface ConversationPolicyConsistencyAnchor {
  policyHeadSequence: Uint63String;
  policyHeadHash: Hash32;
  witnessCheckpointId: WitnessCheckpointId;
  witnessEvidenceDigest: Hash32;
}

export function computePolicyMandatoryProposalSetHash(
  proposals: readonly PolicyMandatoryProposalBinding[],
): Hash32 {
  if (proposals.length > DELIVERY_MANDATORY_PROPOSALS_MAX) {
    throw invalid("Mandatory proposal queue exceeds its protocol bound.");
  }
  if (proposals.length === 0) return ZERO_HASH32;
  return sha256Bytes(
    utf8(POLICY_MANDATORY_PROPOSAL_SET_HASH_DOMAIN),
    canonicalLengthPrefixed(
      ...proposals.flatMap(({ proposalId, proposalHash }) => [
        utf8(proposalId),
        decodeHash32(proposalHash),
      ]),
    ),
  );
}

export function computeConversationVerifiedPrefixEvidenceDigest(
  input: ConversationVerifiedPrefixEvidenceInput,
): Hash32 {
  const context = parseConversationCursorContext(input.cursorContext);
  const membership = parseMembershipWindow(input.membership);
  const anchor = parseHeadAnchor(input.anchor);
  const witness = parseWitnessConsistencyAnchor(input.trustedWitnessAnchor);
  const policy = parsePolicyConsistencyAnchor(input.trustedPolicyAnchor);
  const projection = parseConversationMlsProjection(
    input.mlsProjectionAtAnchor,
  );
  const policyProjection = parseConversationPolicyProjection(
    input.policyProjectionAtAnchor,
  );
  const senderBindings = parseMlsCommitSenderBindings(
    input.mlsCommitSenderBindings,
  );
  const stagedProposals = parseStagedProposalBindings(
    input.stagedProposalsAtAnchor,
    "verified-prefix staged proposals",
  );
  return sha256Bytes(
    utf8(CONVERSATION_VERIFIED_PREFIX_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(context.realmId),
      utf8(context.accountId),
      utf8(context.installationId),
      utf8(context.conversationId),
      utf8(context.routeTemplate),
      utf8(parsePositive(input.conversationGeneration, "conversation generation")),
      utf8(parseReleaseProfileId(input.releaseProfileId)),
      decodeHash32(parseHash32(input.deliveryLimitsDigest, "delivery limits digest")),
      decodeHash32(parseHash32(input.releaseTrustRootDigest, "release trust-root digest")),
      decodeHash32(parseHash32(input.expectedGroupIdHash, "expected MLS group ID hash")),
      utf8(membership.bootstrapMode),
      utf8(membership.credentialId),
      decodeFingerprint32(membership.credentialFingerprint),
      utf8(membership.joinedPosition),
      encodeNullableUtf8(membership.removedPosition),
      utf8(anchor.position),
      decodeHash32(anchor.previousHeadHash),
      decodeHash32(anchor.headHash),
      encodeNullableUtf8(anchor.checkpointReceivedAt),
      utf8(projection.epoch),
      utf8(projection.rosterVersion),
      decodeHash32(projection.confirmedTranscriptHash),
      utf8(policyProjection.etag),
      utf8(policyProjection.policyHeadId),
      utf8(policyProjection.policyRevision),
      utf8(policyProjection.policyMandatoryProposalCount),
      decodeHash32(policyProjection.policyMandatoryProposalSetHash),
      ...encodePolicyMandatoryProposals(
        policyProjection.policyMandatoryProposals,
      ),
      decodeHash32(policyProjection.policyAuthorizedSendGrantSetHash),
      decodeHash32(policyProjection.policyAuthorizedQuotaPolicyDigest),
      utf8(policyProjection.policyHeadSequence),
      decodeHash32(policyProjection.policyHeadHash),
      utf8(policyProjection.policyDeliveryLogPosition),
      decodeHash32(policyProjection.policyDeliveryLogHeadHash),
      utf8(policyProjection.policyWitnessCheckpointId),
      decodeHash32(policyProjection.policyWitnessEvidenceDigest),
      utf8(witness.witnessCheckpointId),
      utf8(witness.witnessTreeSize),
      decodeHash32(witness.witnessRootHash),
      utf8(witness.witnessedAt),
      utf8(policy.policyHeadSequence),
      decodeHash32(policy.policyHeadHash),
      utf8(policy.witnessCheckpointId),
      decodeHash32(policy.witnessEvidenceDigest),
      ...senderBindings.flatMap((binding) => [
        utf8(binding.accountId),
        utf8(binding.installationId),
        utf8(binding.credentialId),
        decodeFingerprint32(binding.credentialFingerprint),
        utf8(binding.credentialRevocationVersion),
        utf8(binding.senderGeneration),
        utf8(binding.activeFromPosition),
        encodeNullableUtf8(binding.inactiveAtPosition),
      ]),
      ...encodeStagedProposals(stagedProposals),
    ),
  );
}

export function computeDeliveryCheckpointProofEvidenceDigest(input: {
  conversationId: ConversationId;
  verifiedAt: Rfc3339Millis;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signatureSha256: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  signatureStatus: "verified";
  keyStatus: "valid-for-checkpoint";
}): Hash32 {
  return sha256Bytes(
    utf8(CHECKPOINT_PROOF_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.verifiedAt),
      utf8(input.position),
      decodeHash32(input.previousHeadHash),
      decodeHash32(input.headHash),
      utf8(input.signingKeyId),
      decodeHash32(input.checkpointDigest),
      decodeHash32(input.signatureSha256),
      utf8(input.checkpointReceivedAt),
      utf8(input.signatureStatus),
      utf8(input.keyStatus),
    ),
  );
}

export function computeDeliveryWitnessProofEvidenceDigest(input: {
  conversationId: ConversationId;
  verifiedAt: Rfc3339Millis;
  position: Uint63String;
  headHash: Hash32;
  witnessCheckpointId: WitnessCheckpointId;
  witnessTreeSize: Uint63String;
  witnessRootHash: Hash32;
  witnessKeyId: SigningKeyId;
  witnessSignatureSha256: Hash32;
  witnessedAt: Rfc3339Millis;
  priorWitnessCheckpointId: WitnessCheckpointId | null;
  priorWitnessTreeSize: Uint63String | null;
  priorWitnessRootHash: Hash32 | null;
  signatureStatus: "verified";
  keyStatus: "valid-for-checkpoint";
  inclusionStatus: "verified";
  consistencyStatus: "verified" | "bootstrap";
  freshnessStatus: "fresh";
}): Hash32 {
  return sha256Bytes(
    utf8(WITNESS_PROOF_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.verifiedAt),
      utf8(input.position),
      decodeHash32(input.headHash),
      utf8(input.witnessCheckpointId),
      utf8(input.witnessTreeSize),
      decodeHash32(input.witnessRootHash),
      utf8(input.witnessKeyId),
      decodeHash32(input.witnessSignatureSha256),
      utf8(input.witnessedAt),
      encodeNullableUtf8(input.priorWitnessCheckpointId),
      encodeNullableUtf8(input.priorWitnessTreeSize),
      encodeNullableHash32(input.priorWitnessRootHash),
      utf8(input.signatureStatus),
      utf8(input.keyStatus),
      utf8(input.inclusionStatus),
      utf8(input.consistencyStatus),
      utf8(input.freshnessStatus),
    ),
  );
}

export function computeConversationPageProofBundleEvidenceDigest(input: {
  realmId: DeliveryRealmId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  verifiedAt: Rfc3339Millis;
  checkpointEvidenceDigests: readonly Hash32[];
  witnessEvidenceDigest: Hash32;
  targetWelcomeEvidenceDigest: Hash32 | null;
}): Hash32 {
  if (
    input.checkpointEvidenceDigests.length === 0 ||
    input.checkpointEvidenceDigests.length >
      CONVERSATION_PAGE_HARD_MAX_EVENTS + 1
  ) {
    throw invalid("Proof bundle evidence digest has an invalid checkpoint count.");
  }
  return sha256Bytes(
    utf8(PAGE_PROOF_BUNDLE_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.releaseTrustRootDigest),
      utf8(input.verifiedAt),
      ...input.checkpointEvidenceDigests.map((digest) => decodeHash32(digest)),
      decodeHash32(input.witnessEvidenceDigest),
      utf8(input.targetWelcomeEvidenceDigest === null ? "absent" : "present"),
      ...(input.targetWelcomeEvidenceDigest === null
        ? []
        : [decodeHash32(input.targetWelcomeEvidenceDigest)]),
    ),
  );
}

export interface ConversationPageVerificationInput {
  cursorContext: ConversationCursorContext;
  requestedCursor: string | null;
  requestedLimit: Uint63String;
  membership: ConversationMembershipWindow;
  retainedFloor: Uint63String;
  anchor: ConversationHeadAnchor;
  /** Loaded from a verified release trust anchor or persisted prior receipt. */
  trustedWitnessAnchor: DeliveryWitnessConsistencyAnchor;
  trustedPolicyAnchor: ConversationPolicyConsistencyAnchor;
  mlsProjectionAtAnchor: ConversationMlsProjection;
  policyProjectionAtAnchor: ConversationPolicyProjection;
  /** Authenticated historical roster bindings for every Commit sender in-page. */
  mlsCommitSenderBindings: readonly ConversationMlsCommitSenderBinding[];
  stagedProposalsAtAnchor: readonly MlsStagedExternalProposalBinding[];
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
  /**
   * Digest loaded with the previously authenticated prefix record. It binds
   * identity, membership, chain, MLS, witness, policy, roster credentials,
   * and the signature-verified archived release profile as one unit.
   */
  verifiedPrefixEvidenceDigest: Hash32;
  now: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
  limits: DeliveryLimits;
}

export interface ConversationVerifiedPrefixEvidenceInput {
  cursorContext: ConversationCursorContext;
  membership: ConversationMembershipWindow;
  anchor: ConversationHeadAnchor;
  trustedWitnessAnchor: DeliveryWitnessConsistencyAnchor;
  trustedPolicyAnchor: ConversationPolicyConsistencyAnchor;
  mlsProjectionAtAnchor: ConversationMlsProjection;
  policyProjectionAtAnchor: ConversationPolicyProjection;
  mlsCommitSenderBindings: readonly ConversationMlsCommitSenderBinding[];
  stagedProposalsAtAnchor: readonly MlsStagedExternalProposalBinding[];
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  deliveryLimitsDigest: Hash32;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
}

export interface ConversationLogHeadVerificationInput {
  cursorContext: ConversationCursorContext;
  membership: ConversationMembershipWindow;
  /** Digest of the durable, previously authenticated prefix containing membership. */
  verifiedPrefixEvidenceDigest: Hash32;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  fromAnchor: ConversationHeadAnchor;
  trustedWitnessAnchor: DeliveryWitnessConsistencyAnchor;
  now: Rfc3339Millis;
  deadline: Rfc3339Millis;
  signal: AbortSignal;
}

export interface ConversationLogHeadVerificationPorts {
  logHeadProofVerifier: ConversationLogHeadProofVerifierPort;
  invariantIncident: DeliveryInvariantIncidentPort;
}

export interface ConversationLogHeadProofEvidence {
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
  visibilityStatus: "active-high-water" | "removed-exact";
  fromPosition: Uint63String;
  fromHeadHash: Hash32;
  currentPosition: Uint63String;
  currentHeadHash: Hash32;
  appendOnlyConsistencyStatus: "verified";
  appendOnlyConsistencyEvidenceDigest: Hash32;
  checkpoint: DeliveryCheckpointProofEvidence;
  witness: DeliveryWitnessProofEvidence;
  verifiedAt: Rfc3339Millis;
  evidenceDigest: Hash32;
}

export interface VerifiedConversationLogHead {
  conversationId: ConversationId;
  generation: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  visibility: "active-high-water" | "removed-boundary";
  logHead: SignedDeliveryLogHead;
  witnessReceipt: DeliveryLogWitnessReceipt;
  proofEvidence: ConversationLogHeadProofEvidence;
}

export interface ConversationSyncVerificationPorts {
  cursorCodec: ConversationCursorCodecPort;
  pageProofVerifier: ConversationPageProofVerifierPort;
  policyHeadProofVerifier: PolicyHeadProofVerifierPort;
  policyReplayVerifier: ConversationPolicyReplayVerifierPort;
  mlsCommitProjectionVerifier: MlsCommitProjectionVerifierPort;
  mlsExternalProposalVerifier: MlsExternalProposalVerifierPort;
  invariantIncident: DeliveryInvariantIncidentPort;
}

type InternalConversationPageVerificationInput =
  ConversationPageVerificationInput & {
    requestedCursorClaims: ConversationCursorClaims | null;
  };

export class ConversationSyncValidationError extends Error {
  readonly code = "invalid_conversation_sync";

  constructor(message: string) {
    super(message);
    this.name = "ConversationSyncValidationError";
  }
}

export class ConversationSyncDependencyTimeoutError extends Error {
  readonly code = "conversation_sync_dependency_timeout";

  constructor() {
    super("A conversation sync dependency exceeded its bounded deadline.");
    this.name = "ConversationSyncDependencyTimeoutError";
  }
}

export class ConversationHistoryRetentionError extends Error {
  readonly code = "conversation_history_retention_expired";
  readonly conversationId: ConversationId;
  readonly installationId: InstallationId;
  readonly nextRequiredPosition: Uint63String;

  constructor(input: {
    conversationId: ConversationId;
    installationId: InstallationId;
    nextRequiredPosition: Uint63String;
  }) {
    super("The next required conversation position is no longer retained.");
    this.name = "ConversationHistoryRetentionError";
    this.conversationId = input.conversationId;
    this.installationId = input.installationId;
    this.nextRequiredPosition = input.nextRequiredPosition;
  }
}

export class ConversationCursorExpiredError extends Error {
  readonly code = "cursor_expired";
  readonly conversationId: ConversationId;
  readonly installationId: InstallationId;
  readonly restartAtPosition: Uint63String;

  constructor(input: {
    conversationId: ConversationId;
    installationId: InstallationId;
    restartAtPosition: Uint63String;
  }) {
    super("The authenticated conversation cursor has expired.");
    this.name = "ConversationCursorExpiredError";
    this.conversationId = input.conversationId;
    this.installationId = input.installationId;
    this.restartAtPosition = input.restartAtPosition;
  }
}

export class ConversationCursorInvalidError extends Error {
  readonly code = "invalid_cursor";

  constructor() {
    super("The conversation cursor is invalid.");
    this.name = "ConversationCursorInvalidError";
  }
}

class ConversationCursorBindingFailureError extends ConversationCursorInvalidError {
  constructor() {
    super();
    this.name = "ConversationCursorBindingFailureError";
  }
}

export class ConversationSyncDependencyUnavailableError extends Error {
  readonly code = "conversation_sync_dependency_unavailable";
  readonly unavailable: DeliveryPortUnavailable;

  constructor(unavailable: DeliveryPortUnavailable) {
    super("A required conversation sync dependency is unavailable.");
    this.name = "ConversationSyncDependencyUnavailableError";
    this.unavailable = unavailable;
  }
}

class DecodedConversationCursorExpiredError extends Error {
  constructor(readonly claims: ConversationCursorClaims) {
    super("Authenticated cursor expired.");
  }
}

class DecodedConversationCursorBindingError extends Error {}

export function parseDeliveryRealmId(value: unknown): DeliveryRealmId {
  if (typeof value !== "string" || !REALM_ID.test(value)) {
    throw invalid("Delivery realm ID must be bounded canonical lowercase ASCII.");
  }
  return value as DeliveryRealmId;
}

export function parseConversationCursorContext(
  value: unknown,
): ConversationCursorContext {
  const record = expectExactRecord(
    value,
    ["realmId", "accountId", "installationId", "conversationId", "routeTemplate"],
    "conversation cursor context",
  );
  if (record.routeTemplate !== CONVERSATION_EVENTS_ROUTE_TEMPLATE) {
    throw invalid("Conversation cursor route template is not canonical.");
  }
  return Object.freeze({
    realmId: parseDeliveryRealmId(record.realmId),
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    conversationId: parseConversationId(record.conversationId),
    routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  });
}

export function parseEncodedConversationCursor(
  value: unknown,
  limits: DeliveryLimits,
): string {
  const parsedLimits = parseDeliveryLimits(limits);
  if (
    typeof value !== "string" ||
    value.length > Number(parsedLimits.cursorMaxCharacters) ||
    !value.startsWith(CONVERSATION_CURSOR_PREFIX)
  ) {
    throw invalid("Conversation cursor is not a bounded cc1 token.");
  }
  const blob = value.slice(CONVERSATION_CURSOR_PREFIX.length);
  if (!CURSOR_BASE64URL.test(blob)) {
    throw invalid("Conversation cursor blob must be canonical base64url.");
  }
  parseCanonicalBase64UrlBytes(blob, "conversation cursor blob", {
    minBytes: 29,
    maxBytes: Number(parsedLimits.cursorMaxCharacters),
  });
  return value;
}

export function parseConversationCursorClaims(
  value: unknown,
  expected: {
    encodedCursor: string;
    context: ConversationCursorContext;
    now: Rfc3339Millis;
    limits: DeliveryLimits;
  },
): ConversationCursorClaims {
  const context = parseConversationCursorContext(expected.context);
  const now = parseRfc3339Millis(expected.now, "cursor verification time");
  const encodedCursor = parseEncodedConversationCursor(
    expected.encodedCursor,
    expected.limits,
  );
  const record = expectExactRecord(
    value,
    [
      "kind",
      "profile",
      "encodedCursor",
      "realmId",
      "accountId",
      "installationId",
      "conversationId",
      "routeTemplate",
      "lastReturnedPosition",
      "issuedAt",
      "expiresAt",
      "keyId",
      "authenticated",
    ],
    "conversation cursor claims",
  );
  if (
    record.kind !== CURSOR_KIND ||
    record.profile !== CONVERSATION_CURSOR_PROFILE ||
    record.encodedCursor !== encodedCursor ||
    record.routeTemplate !== CONVERSATION_EVENTS_ROUTE_TEMPLATE ||
    record.authenticated !== true
  ) {
    throw invalid("Conversation cursor claims are not authenticated v1 claims.");
  }
  const parsed: ConversationCursorClaims = Object.freeze({
    kind: CURSOR_KIND,
    profile: CONVERSATION_CURSOR_PROFILE,
    encodedCursor,
    realmId: parseDeliveryRealmId(record.realmId),
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    conversationId: parseConversationId(record.conversationId),
    routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
    lastReturnedPosition: parseUint63String(
      record.lastReturnedPosition,
      "cursor last returned position",
    ),
    issuedAt: parseRfc3339Millis(record.issuedAt, "cursor issuedAt"),
    expiresAt: parseRfc3339Millis(record.expiresAt, "cursor expiresAt"),
    keyId: parseSigningKeyId(record.keyId, "cursor keyId"),
    authenticated: true,
  });
  if (
    parsed.realmId !== context.realmId ||
    parsed.accountId !== context.accountId ||
    parsed.installationId !== context.installationId ||
    parsed.conversationId !== context.conversationId
  ) {
    throw new DecodedConversationCursorBindingError();
  }
  const issuedAt = Date.parse(parsed.issuedAt);
  const expiresAt = Date.parse(parsed.expiresAt);
  if (
    issuedAt > Date.parse(now) ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > CONVERSATION_CURSOR_MAX_LIFETIME_MILLISECONDS
  ) {
    throw invalid("Conversation cursor time window is invalid.");
  }
  if (expiresAt <= Date.parse(now)) {
    throw new DecodedConversationCursorExpiredError(parsed);
  }
  return parsed;
}

export async function parseAndVerifyConversationPageJson(
  rawResponse: unknown,
  input: ConversationPageVerificationInput,
  ports: ConversationSyncVerificationPorts,
): Promise<VerifiedConversationPage> {
  try {
    return await parseAndVerifyConversationPageJsonInternal(
      rawResponse,
      input,
      ports,
    );
  } catch (error) {
    const normalized = normalizeConversationSyncFailure(error);
    await recordConversationSyncIncident(
      normalized,
      input,
      ports.invariantIncident,
    );
    throw normalized;
  }
}

async function parseAndVerifyConversationPageJsonInternal(
  rawResponse: unknown,
  input: ConversationPageVerificationInput,
  ports: ConversationSyncVerificationPorts,
): Promise<VerifiedConversationPage> {
  const limits = parseDeliveryLimits(input.limits);
  const cursorContext = parseConversationCursorContext(input.cursorContext);
  const now = parseRfc3339Millis(input.now, "conversation sync time");
  const deadline = parseRfc3339Millis(input.deadline, "conversation sync deadline");
  if (
    deadline <= now ||
    Date.parse(deadline) - Date.parse(now) >
      CONVERSATION_SYNC_MAX_PORT_WAIT_MILLISECONDS ||
    input.signal.aborted
  ) {
    throw invalid("Conversation sync deadline is expired or cancelled.");
  }
  const releaseProfileId = parseReleaseProfileId(input.releaseProfileId);
  const conversationGeneration = parsePositive(
    input.conversationGeneration,
    "conversation generation",
  );
  const deliveryLimitsDigest = parseHash32(
    input.deliveryLimitsDigest,
    "delivery limits digest",
  );
  if (computeDeliveryLimitsDigest(limits) !== deliveryLimitsDigest) {
    throw invalid("Archived delivery limits do not match their pinned digest.");
  }
  const expectedGroupIdHash = parseHash32(
    input.expectedGroupIdHash,
    "expected MLS group ID hash",
  );
  const releaseTrustRootDigest = parseHash32(
    input.releaseTrustRootDigest,
    "release trust-root digest",
  );
  const trustedWitnessAnchor = parseWitnessConsistencyAnchor(
    input.trustedWitnessAnchor,
  );
  const trustedPolicyAnchor = parsePolicyConsistencyAnchor(
    input.trustedPolicyAnchor,
  );
  const membership = parseMembershipWindow(input.membership);
  const anchor = parseHeadAnchor(input.anchor);
  const mlsProjectionAtAnchor = parseConversationMlsProjection(
    input.mlsProjectionAtAnchor,
  );
  const policyProjectionAtAnchor = parseConversationPolicyProjection(
    input.policyProjectionAtAnchor,
  );
  const commitSenderBindings = parseMlsCommitSenderBindings(
    input.mlsCommitSenderBindings,
  );
  const stagedProposalsAtAnchor = parseStagedProposalBindings(
    input.stagedProposalsAtAnchor,
    "staged proposals at anchor",
  );
  if (
    policyProjectionAtAnchor.etag !==
      `"e${mlsProjectionAtAnchor.epoch}-r${mlsProjectionAtAnchor.rosterVersion}"` ||
    BigInt(policyProjectionAtAnchor.policyDeliveryLogPosition) >
      BigInt(anchor.position) ||
    (policyProjectionAtAnchor.policyDeliveryLogPosition === anchor.position &&
      policyProjectionAtAnchor.policyDeliveryLogHeadHash !== anchor.headHash)
  ) {
    throw invalid("Conversation prefix policy/MLS/log projections are inconsistent.");
  }
  const mandatoryAtAnchor = stagedProposalsAtAnchor
    .filter(({ proposalRequirement }) => proposalRequirement === "mandatory")
    .map(({ proposalId, proposalHash }) => ({ proposalId, proposalHash }));
  if (
    mandatoryAtAnchor.some(
      (staged) =>
        !policyProjectionAtAnchor.policyMandatoryProposals.some(
          (required) =>
            required.proposalId === staged.proposalId &&
            required.proposalHash === staged.proposalHash,
        ),
    )
  ) {
    throw invalid("Staged prefix contains a substituted mandatory proposal.");
  }
  if (
    stagedProposalsAtAnchor.some(
      ({ position }) => BigInt(position) > BigInt(anchor.position),
    )
  ) {
    throw invalid("Staged proposal prefix extends beyond its log-head anchor.");
  }
  const verifiedPrefixEvidenceDigest = parseHash32(
    input.verifiedPrefixEvidenceDigest,
    "verified conversation prefix evidence digest",
  );
  if (
    verifiedPrefixEvidenceDigest !==
    computeConversationVerifiedPrefixEvidenceDigest({
      cursorContext,
      membership,
      anchor,
      trustedWitnessAnchor,
      trustedPolicyAnchor,
      mlsProjectionAtAnchor,
      policyProjectionAtAnchor,
      mlsCommitSenderBindings: commitSenderBindings,
      stagedProposalsAtAnchor,
      conversationGeneration,
      releaseProfileId,
      deliveryLimitsDigest,
      releaseTrustRootDigest,
      expectedGroupIdHash,
    })
  ) {
    throw invalid("Conversation prefix evidence is detached or spliced.");
  }
  let requestedCursorClaims: ConversationCursorClaims | null = null;
  if (input.requestedCursor !== null) {
    let encodedCursor: string;
    try {
      encodedCursor = parseEncodedConversationCursor(
        input.requestedCursor,
        limits,
      );
    } catch {
      throw new ConversationCursorInvalidError();
    }
    const rawCursorClaims = await callDeliveryPort(
      deadline,
      input.signal,
      (signal) =>
        ports.cursorCodec.decode({
          encodedCursor,
          context: cursorContext,
          now,
          deadline,
          signal,
        }),
    );
    if (isAuthenticatedCursorRejection(rawCursorClaims)) {
      throw new ConversationCursorInvalidError();
    }
    throwIfDeliveryPortUnavailable(rawCursorClaims);
    try {
      requestedCursorClaims = parseConversationCursorClaims(
        rawCursorClaims,
        { encodedCursor, context: cursorContext, now, limits },
      );
    } catch (error) {
      if (error instanceof DecodedConversationCursorExpiredError) {
        const retainedFloor = parsePositive(input.retainedFloor, "retained floor");
        if (
          membership.removedPosition !== null &&
          BigInt(retainedFloor) > BigInt(membership.removedPosition)
        ) {
          throw new ConversationHistoryRetentionError({
            conversationId: cursorContext.conversationId,
            installationId: cursorContext.installationId,
            nextRequiredPosition: membership.joinedPosition,
          });
        }
        const restartAtPosition = maximumUint63(
          decrementPositive(membership.joinedPosition),
          decrementPositive(retainedFloor),
        );
        throw new ConversationCursorExpiredError({
          conversationId: cursorContext.conversationId,
          installationId: cursorContext.installationId,
          restartAtPosition,
        });
      }
      if (error instanceof DecodedConversationCursorBindingError) {
        throw new ConversationCursorBindingFailureError();
      }
      throw new ConversationCursorInvalidError();
    }
  }
  const serialized = parseOwnedBytes(
    rawResponse,
    minimum(
      Number(limits.pageSerializedResponseMaxBytes),
      CONVERSATION_PAGE_HARD_MAX_SERIALIZED_BYTES,
    ),
    "conversation page JSON",
  );
  const parsedJson = parseStrictJsonBytes(serialized);
  const page = verifyConversationPage(parsedJson, {
    ...input,
    membership,
    anchor,
    mlsProjectionAtAnchor,
    policyProjectionAtAnchor,
    mlsCommitSenderBindings: commitSenderBindings,
    stagedProposalsAtAnchor,
    conversationGeneration,
    releaseProfileId,
    expectedGroupIdHash,
    deliveryLimitsDigest,
    requestedCursorClaims,
    limits,
    serializedBytes: serialized.byteLength,
  });
  const rawNextCursorClaims = await callDeliveryPort(
    deadline,
    input.signal,
    (signal) =>
      ports.cursorCodec.decode({
        encodedCursor: page.nextCursor,
        context: cursorContext,
        now,
        deadline,
        signal,
      }),
  );
  throwIfDeliveryPortUnavailable(rawNextCursorClaims);
  let nextCursorClaims: ConversationCursorClaims;
  try {
    nextCursorClaims = parseConversationCursorClaims(rawNextCursorClaims, {
      encodedCursor: page.nextCursor,
      context: cursorContext,
      now,
      limits,
    });
  } catch {
    throw invalid("Server-issued next cursor is invalid or expired.");
  }
  const expectedNextPosition =
    page.events.at(-1)?.envelope.position ?? page.snapshot.logHead.position;
  if (nextCursorClaims.lastReturnedPosition !== expectedNextPosition) {
    throw invalid("Next cursor does not name the last returned position.");
  }
  const proofEvidence = await verifyConversationPageProofs(
    page,
    now,
    deadline,
    input.signal,
    releaseProfileId,
    expectedGroupIdHash,
    cursorContext.realmId,
    conversationGeneration,
    releaseTrustRootDigest,
    trustedWitnessAnchor,
    membership,
    cursorContext.accountId,
    ports.pageProofVerifier,
  );
  const policyHeadEvidence = await verifyConversationPolicyHead(
    page.snapshot,
    now,
    deadline,
    input.signal,
    releaseProfileId,
    cursorContext.realmId,
    conversationGeneration,
    releaseTrustRootDigest,
    trustedPolicyAnchor,
    ports.policyHeadProofVerifier,
  );
  const policyReplayEvidence = await verifyConversationPolicyReplay(
    page,
    anchor,
    policyProjectionAtAnchor,
    trustedPolicyAnchor,
    now,
    deadline,
    input.signal,
    cursorContext.realmId,
    conversationGeneration,
    releaseProfileId,
    deliveryLimitsDigest,
    releaseTrustRootDigest,
    ports.policyReplayVerifier,
  );
  const orderedMlsEvidence = await verifyOrderedMlsTranscript(
    page,
    mlsProjectionAtAnchor,
    commitSenderBindings,
    stagedProposalsAtAnchor,
    membership,
    cursorContext,
    policyProjectionAtAnchor,
    cursorContext.realmId,
    conversationGeneration,
    releaseProfileId,
    deliveryLimitsDigest,
    releaseTrustRootDigest,
    expectedGroupIdHash,
    trustedPolicyAnchor,
    policyReplayEvidence,
    deadline,
    input.signal,
    ports.mlsCommitProjectionVerifier,
    ports.mlsExternalProposalVerifier,
  );
  return Object.freeze({
    ...page,
    nextCursorClaims,
    proofEvidence,
    policyHeadEvidence,
    policyReplayEvidence,
    commitProjectionEvidence: orderedMlsEvidence.commitProjectionEvidence,
    externalProposalEvidence: orderedMlsEvidence.externalProposalEvidence,
    stagedProposalsAtPageEnd: orderedMlsEvidence.stagedProposalsAtPageEnd,
  });
}

export async function parseAndVerifyConversationLogHead(
  rawResponse: unknown,
  input: ConversationLogHeadVerificationInput,
  ports: ConversationLogHeadVerificationPorts,
): Promise<VerifiedConversationLogHead> {
  try {
    const serialized = parseOwnedBytes(
      rawResponse,
      CONVERSATION_LOG_HEAD_HARD_MAX_SERIALIZED_BYTES,
      "conversation log-head JSON",
    );
    const value = parseStrictJsonBytes(serialized);
    return await parseAndVerifyConversationLogHeadInternal(value, input, ports);
  } catch (error) {
    const normalized = normalizeConversationSyncFailure(error);
    await recordConversationLogHeadIncident(
      normalized,
      input,
      ports.invariantIncident,
    );
    throw normalized;
  }
}

async function parseAndVerifyConversationLogHeadInternal(
  value: unknown,
  input: ConversationLogHeadVerificationInput,
  ports: ConversationLogHeadVerificationPorts,
): Promise<VerifiedConversationLogHead> {
  const context = parseConversationCursorContext(input.cursorContext);
  const membership = parseMembershipWindow(input.membership);
  const verifiedPrefixEvidenceDigest = parseNonZeroHash32(
    input.verifiedPrefixEvidenceDigest,
    "log-head verified-prefix evidence digest",
  );
  const generation = parsePositive(
    input.conversationGeneration,
    "log-head conversation generation",
  );
  const releaseProfileId = parseReleaseProfileId(input.releaseProfileId);
  const releaseTrustRootDigest = parseHash32(
    input.releaseTrustRootDigest,
    "log-head release trust-root digest",
  );
  const fromAnchor = parseHeadAnchor(input.fromAnchor);
  validateAnchor(fromAnchor);
  const priorWitness = parseWitnessConsistencyAnchor(
    input.trustedWitnessAnchor,
  );
  const verifiedAt = parseRfc3339Millis(input.now, "log-head verification time");
  const deadline = parseRfc3339Millis(input.deadline, "log-head deadline");
  if (
    deadline <= verifiedAt ||
    Date.parse(deadline) - Date.parse(verifiedAt) >
      CONVERSATION_SYNC_MAX_PORT_WAIT_MILLISECONDS ||
    input.signal.aborted
  ) {
    throw invalid("Conversation log-head deadline is expired or cancelled.");
  }
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "generation",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "visibility",
      "logHead",
      "witnessReceipt",
    ],
    "conversation log-head response",
  );
  const conversationId = parseConversationId(record.conversationId);
  const visibility = parseOneOfString(
    record.visibility,
    ["active-high-water", "removed-boundary"] as const,
    "conversation log-head visibility",
  );
  if (
    conversationId !== context.conversationId ||
    parsePositive(record.generation, "log-head generation") !== generation ||
    parseReleaseProfileId(record.releaseProfileId) !== releaseProfileId ||
    parseHash32(record.releaseTrustRootDigest, "log-head trust root") !==
      releaseTrustRootDigest
  ) {
    throw invalid("Conversation log head belongs to another trust domain.");
  }
  const expectedVisibility =
    membership.removedPosition === null
      ? "active-high-water"
      : "removed-boundary";
  if (visibility !== expectedVisibility) {
    throw invalid("Conversation log-head visibility is invalid for membership.");
  }
  const logHead = parseSignedDeliveryLogHead(record.logHead, conversationId);
  const witnessReceipt = parseWitnessReceipt(record.witnessReceipt);
  if (
    witnessReceipt.conversationId !== conversationId ||
    witnessReceipt.position !== logHead.position ||
    witnessReceipt.headHash !== logHead.headHash
  ) {
    throw invalid("Conversation log-head witness is detached from the checkpoint.");
  }
  if (
    BigInt(logHead.position) < BigInt(fromAnchor.position) ||
    (membership.removedPosition === null &&
      BigInt(logHead.position) < BigInt(membership.joinedPosition)) ||
    (logHead.position === fromAnchor.position &&
      (logHead.previousHeadHash !== fromAnchor.previousHeadHash ||
        logHead.headHash !== fromAnchor.headHash ||
        logHead.checkpointReceivedAt !== fromAnchor.checkpointReceivedAt)) ||
    (BigInt(logHead.position) === BigInt(fromAnchor.position) + 1n &&
      logHead.previousHeadHash !== fromAnchor.headHash) ||
    (membership.removedPosition !== null &&
      logHead.position !== membership.removedPosition)
  ) {
    throw invalid("Conversation log head rolls back, forks, or exceeds visibility.");
  }
  const request: ConversationLogHeadProofVerificationRequest = Object.freeze({
    profile: "conversation-log-head-proof.v1",
    realmId: context.realmId,
    accountId: context.accountId,
    installationId: context.installationId,
    conversationId,
    conversationGeneration: generation,
    releaseProfileId,
    releaseTrustRootDigest,
    verifiedPrefixEvidenceDigest,
    membershipBootstrapMode: membership.bootstrapMode,
    membershipCredentialId: membership.credentialId,
    membershipCredentialFingerprint: membership.credentialFingerprint,
    membershipJoinedPosition: membership.joinedPosition,
    membershipRemovedPosition: membership.removedPosition,
    visibilityMode:
      visibility === "active-high-water"
        ? "active-high-water"
        : "removed-boundary",
    removedPosition: membership.removedPosition,
    fromPosition: fromAnchor.position,
    fromHeadHash: fromAnchor.headHash,
    current: Object.freeze({
      conversationId,
      position: logHead.position,
      previousHeadHash: logHead.previousHeadHash,
      headHash: logHead.headHash,
      signingKeyId: logHead.signingKeyId,
      checkpointDigest: logHead.checkpointDigest,
      signature: logHead.signature,
      checkpointReceivedAt: logHead.checkpointReceivedAt,
    }),
    witness: Object.freeze({ ...witnessReceipt }),
    priorWitness,
    verifiedAt,
    deadline,
    signal: input.signal,
  });
  const raw = await callDeliveryPort(deadline, input.signal, (signal) =>
    ports.logHeadProofVerifier.verify(
      Object.freeze({ ...request, signal }),
    ),
  );
  throwIfDeliveryPortUnavailable(raw);
  const proofEvidence = parseConversationLogHeadProofEvidence(raw, request);
  return Object.freeze({
    conversationId,
    generation,
    releaseProfileId,
    releaseTrustRootDigest,
    visibility,
    logHead,
    witnessReceipt,
    proofEvidence,
  });
}

async function verifyMlsExternalProposal(
  page: StructurallyVerifiedConversationPage,
  envelope: StoredEnvelope,
  realmId: DeliveryRealmId,
  conversationGeneration: Uint63String,
  releaseProfileId: ReleaseProfileId,
  deliveryLimitsDigest: Hash32,
  releaseTrustRootDigest: Hash32,
  expectedGroupIdHash: Hash32,
  pageStartPolicy: ConversationPolicyProjection,
  policyLogHighWater: ConversationPolicyConsistencyAnchor,
  deadline: Rfc3339Millis,
  signal: AbortSignal,
  verifier: MlsExternalProposalVerifierPort,
): Promise<MlsExternalProposalEvidence> {
  if (
    envelope.envelopeClass !== "external_proposal" ||
    envelope.sender.type !== "entitlement_signer"
  ) {
    throw invalid("External proposal sender is not an entitlement signer.");
  }
  const request: MlsExternalProposalVerificationRequest = Object.freeze({
      profile: "mls-external-proposal.v1",
      realmId,
      conversationGeneration,
      releaseProfileId,
      deliveryLimitsDigest,
      releaseTrustRootDigest,
      expectedGroupIdHash,
      conversationId: envelope.conversationId,
      position: envelope.position,
      envelopeId: envelope.envelopeId,
      envelopeBytes: envelope.envelopeBytes,
      envelopeSha256: envelope.envelopeSha256,
      epoch: envelope.epoch,
      rosterVersion: envelope.rosterVersion,
      credentialId: envelope.sender.credentialId,
      credentialFingerprint: envelope.sender.fingerprint,
      signerGeneration: envelope.sender.signerGeneration,
      checkpointReceivedAt: envelope.receivedAt,
      pageEndPosition: page.snapshot.logHead.position,
      pageEndHeadHash: page.snapshot.logHead.headHash,
      pageEndPolicyHeadSequence: page.snapshot.policyHeadSequence,
      pageEndPolicyHeadHash: page.snapshot.policyHeadHash,
      priorPolicyHeadSequence: pageStartPolicy.policyHeadSequence,
      priorPolicyHeadHash: pageStartPolicy.policyHeadHash,
      priorPolicyWitnessCheckpointId:
        pageStartPolicy.policyWitnessCheckpointId,
      priorPolicyWitnessEvidenceDigest:
        pageStartPolicy.policyWitnessEvidenceDigest,
      policyLogHighWaterSequence: policyLogHighWater.policyHeadSequence,
      policyLogHighWaterHash: policyLogHighWater.policyHeadHash,
      policyLogHighWaterWitnessCheckpointId:
        policyLogHighWater.witnessCheckpointId,
      policyLogHighWaterWitnessEvidenceDigest:
        policyLogHighWater.witnessEvidenceDigest,
      deadline,
      signal,
  });
  const raw = await callDeliveryPort(deadline, signal, (portSignal) =>
    verifier.verify(Object.freeze({ ...request, signal: portSignal })),
  );
  throwIfDeliveryPortUnavailable(raw);
  return parseMlsExternalProposalEvidence(raw, request);
}

function verifyConversationPage(
  value: unknown,
  input: InternalConversationPageVerificationInput & { serializedBytes: number },
): StructurallyVerifiedConversationPage {
  const context = parseConversationCursorContext(input.cursorContext);
  const requestedLimit = parseUint63String(input.requestedLimit, "requested limit");
  if (
    requestedLimit === "0" ||
    BigInt(requestedLimit) > BigInt(input.limits.conversationEventsMaxPerPage) ||
    BigInt(requestedLimit) > BigInt(CONVERSATION_PAGE_HARD_MAX_EVENTS)
  ) {
    throw invalid("Conversation page limit is outside the reviewed bound.");
  }
  const membership = parseMembershipWindow(input.membership);
  const retainedFloor = parsePositive(input.retainedFloor, "retained floor");
  const anchor = parseHeadAnchor(input.anchor);
  const boundaryBeforeJoin = decrementPositive(membership.joinedPosition);
  let requestedAfterPosition = boundaryBeforeJoin;
  if (input.requestedCursor === null) {
    if (input.requestedCursorClaims !== null) {
      throw invalid("Missing cursor cannot carry decoded cursor claims.");
    }
  } else {
    if (input.requestedCursorClaims === null) {
      throw invalid("A supplied cursor requires authenticated decoded claims.");
    }
    requestedAfterPosition = input.requestedCursorClaims.lastReturnedPosition;
  }

  if (
    BigInt(requestedAfterPosition) < BigInt(boundaryBeforeJoin) ||
    (membership.removedPosition !== null &&
      BigInt(requestedAfterPosition) > BigInt(membership.removedPosition))
  ) {
    throw invalid("Conversation cursor is outside the membership boundary.");
  }
  if (anchor.position !== requestedAfterPosition) {
    throw invalid("Conversation cursor and verified head anchor disagree.");
  }
  validateAnchor(anchor);
  const expectedWelcomeCommitPosition =
    requestedAfterPosition === boundaryBeforeJoin &&
    membership.bootstrapMode === "welcome"
      ? membership.joinedPosition
      : null;
  const requiresJoinCommit = requestedAfterPosition === boundaryBeforeJoin;

  const mayHaveVisibleNext =
    requestedAfterPosition !== UINT63_MAX_STRING &&
    (membership.removedPosition === null ||
      BigInt(requestedAfterPosition) < BigInt(membership.removedPosition));
  if (mayHaveVisibleNext) {
    const nextRequired = increment(
      requestedAfterPosition,
      "next required position",
    );
    if (BigInt(retainedFloor) > BigInt(nextRequired)) {
      throw new ConversationHistoryRetentionError({
        conversationId: context.conversationId,
        installationId: context.installationId,
        nextRequiredPosition: nextRequired,
      });
    }
  }

  const record = expectExactRecord(
    value,
    ["events", "nextCursor", "hasMore", "snapshot"],
    "conversation page",
  );
  const rawEvents = expectDenseArray(
    record.events,
    Number(requestedLimit),
    "conversation page events",
  );
  if (typeof record.hasMore !== "boolean") {
    throw invalid("Conversation page hasMore must be a boolean.");
  }
  const nextCursor = parseEncodedConversationCursor(record.nextCursor, input.limits);
  const snapshot = parseConversationPageSnapshot(record.snapshot);
  if (
    snapshot.conversationId !== context.conversationId ||
    snapshot.generation !== input.conversationGeneration ||
    snapshot.releaseProfileId !== input.releaseProfileId ||
    snapshot.deliveryLimitsDigest !== input.deliveryLimitsDigest
  ) {
    throw invalid("Conversation page snapshot belongs to another conversation.");
  }

  let previousPosition = BigInt(requestedAfterPosition);
  let previousHeadHash = anchor.headHash;
  let decodedArtifactBytes = 0n;
  let welcomeCount = 0;
  const envelopeIds = new Set<string>();
  const headHashes = new Set<string>();
  const events: ConversationEventItem[] = [];

  for (let index = 0; index < rawEvents.length; index += 1) {
    const item = parseConversationEventItem(
      rawEvents[index],
      context.installationId,
      input.limits,
    );
    const envelope = item.envelope;
    const position = BigInt(envelope.position);
    if (
      envelope.conversationId !== context.conversationId ||
      position !== previousPosition + 1n ||
      envelope.previousHeadHash !== previousHeadHash
    ) {
      throw invalid("Conversation page contains a gap, reorder, or foreign envelope.");
    }
    if (
      position < BigInt(membership.joinedPosition) ||
      (membership.removedPosition !== null &&
        position > BigInt(membership.removedPosition))
    ) {
      throw invalid("Conversation event is outside the membership boundary.");
    }
    if (envelopeIds.has(envelope.envelopeId) || headHashes.has(envelope.headHash)) {
      throw invalid("Conversation page contains a duplicate envelope or head.");
    }
    envelopeIds.add(envelope.envelopeId);
    headHashes.add(envelope.headHash);

    verifyStoredEnvelopeHashes(envelope);
    const envelopeBytes = decodedEnvelopeLength(envelope, input.limits);
    let itemBytes = BigInt(envelopeBytes);
    if (item.welcome !== null) {
      welcomeCount += 1;
      itemBytes += BigInt(
        parseCanonicalBase64UrlBytes(item.welcome.welcome, "Welcome bytes", {
          minBytes: 1,
          maxBytes: minimum(
            Number(input.limits.welcomeDecodedMaxBytes),
            CONVERSATION_WELCOME_HARD_MAX_BYTES,
          ),
        }).byteLength,
      );
      if (
        expectedWelcomeCommitPosition === null ||
        envelope.position !== expectedWelcomeCommitPosition
      ) {
        throw invalid("Target Welcome is not bound to the expected Add Commit.");
      }
    }
    if (itemBytes > BigInt(CONVERSATION_PAGE_HARD_MAX_FIRST_ITEM_BYTES)) {
      throw invalid("A conversation page item exceeds the 768 KiB progress bound.");
    }
    decodedArtifactBytes += itemBytes;
    if (
      decodedArtifactBytes > BigInt(input.limits.pageDecodedArtifactsMaxBytes) ||
      decodedArtifactBytes >
        BigInt(CONVERSATION_PAGE_HARD_MAX_DECODED_ARTIFACT_BYTES)
    ) {
      throw invalid("Conversation page decoded artifacts exceed the aggregate bound.");
    }

    previousPosition = position;
    previousHeadHash = envelope.headHash;
    events.push(item);
  }

  if (welcomeCount > 1) {
    throw invalid("A target may receive at most one joined Welcome augmentation.");
  }
  if (
    requiresJoinCommit &&
    (events[0]?.envelope.position !== membership.joinedPosition ||
      events[0].envelope.envelopeClass !== "mls_commit")
  ) {
    throw invalid("First sync must return the authoritative initial/join Commit.");
  }
  if (expectedWelcomeCommitPosition !== null && welcomeCount !== 1) {
    throw invalid("Expected target Welcome is missing from its Commit item.");
  }

  verifySnapshotHead(snapshot, anchor, events);
  verifySnapshotPolicyDeliveryAnchor(snapshot, anchor, events);
  const snapshotPosition = BigInt(snapshot.logHead.position);
  if (events.length === 0) {
    if (record.hasMore || snapshotPosition !== BigInt(requestedAfterPosition)) {
      throw invalid("An empty page cannot conceal a visible event or claim more data.");
    }
    if (
      !snapshotMatchesPolicyProjection(
        snapshot,
        parseConversationPolicyProjection(input.policyProjectionAtAnchor),
      )
    ) {
      throw invalid("Empty page policy snapshot differs from its verified anchor.");
    }
  } else if (snapshotPosition !== previousPosition) {
    throw invalid("Page checkpoint must equal the last returned event.");
  }
  if (
    membership.removedPosition !== null &&
    snapshotPosition > BigInt(membership.removedPosition)
  ) {
    throw invalid("Removed membership received a post-removal snapshot.");
  }
  if (
    membership.removedPosition !== null &&
    snapshot.logHead.position === membership.removedPosition &&
    record.hasMore
  ) {
    throw invalid("A page at the removal boundary cannot claim more visible data.");
  }
  return Object.freeze({
    events: Object.freeze(events),
    nextCursor,
    hasMore: record.hasMore,
    snapshot,
    decodedArtifactBytes: decodedArtifactBytes.toString(10) as Uint63String,
    serializedBytes: input.serializedBytes.toString(10) as Uint63String,
  });
}

function verifySnapshotPolicyDeliveryAnchor(
  snapshot: ConversationPageSnapshot,
  anchor: ConversationHeadAnchor,
  events: readonly ConversationEventItem[],
): void {
  const position = BigInt(snapshot.policyDeliveryLogPosition);
  if (position === BigInt(anchor.position)) {
    if (snapshot.policyDeliveryLogHeadHash !== anchor.headHash) {
      throw invalid("Policy projection is detached from the page-start head.");
    }
    return;
  }
  if (position < BigInt(anchor.position)) return;
  const event = events.find(
    ({ envelope }) => envelope.position === snapshot.policyDeliveryLogPosition,
  );
  if (
    event === undefined ||
    event.envelope.headHash !== snapshot.policyDeliveryLogHeadHash
  ) {
    throw invalid("Policy projection is detached from its in-page log head.");
  }
}

function snapshotMatchesPolicyProjection(
  snapshot: ConversationPageSnapshot,
  projection: ConversationPolicyProjection,
): boolean {
  return (
    snapshot.etag === projection.etag &&
    snapshot.policyHeadId === projection.policyHeadId &&
    snapshot.policyRevision === projection.policyRevision &&
    snapshot.policyMandatoryProposalCount ===
      projection.policyMandatoryProposalCount &&
    snapshot.policyMandatoryProposalSetHash ===
      projection.policyMandatoryProposalSetHash &&
    samePolicyMandatoryProposals(
      snapshot.policyMandatoryProposals,
      projection.policyMandatoryProposals,
    ) &&
    snapshot.policyAuthorizedSendGrantSetHash ===
      projection.policyAuthorizedSendGrantSetHash &&
    snapshot.policyAuthorizedQuotaPolicyDigest ===
      projection.policyAuthorizedQuotaPolicyDigest &&
    snapshot.policyHeadSequence === projection.policyHeadSequence &&
    snapshot.policyHeadHash === projection.policyHeadHash &&
    snapshot.policyDeliveryLogPosition ===
      projection.policyDeliveryLogPosition &&
    snapshot.policyDeliveryLogHeadHash ===
      projection.policyDeliveryLogHeadHash &&
    snapshot.policyWitnessCheckpointId === projection.policyWitnessCheckpointId &&
    snapshot.policyWitnessEvidenceDigest === projection.policyWitnessEvidenceDigest
  );
}

async function verifyConversationPageProofs(
  page: StructurallyVerifiedConversationPage,
  verifiedAt: Rfc3339Millis,
  deadline: Rfc3339Millis,
  signal: AbortSignal,
  releaseProfileId: ReleaseProfileId,
  expectedGroupIdHash: Hash32,
  realmId: DeliveryRealmId,
  conversationGeneration: Uint63String,
  releaseTrustRootDigest: Hash32,
  priorWitness: DeliveryWitnessConsistencyAnchor,
  membership: ConversationMembershipWindow,
  targetAccountId: AccountId,
  verifier: ConversationPageProofVerifierPort,
): Promise<ConversationPageProofEvidence> {
  const checkpoints: DeliveryCheckpointProofInput[] = [];
  for (const { envelope } of page.events) {
    checkpoints.push({
      conversationId: envelope.conversationId,
      position: envelope.position,
      previousHeadHash: envelope.previousHeadHash,
      headHash: envelope.headHash,
      signingKeyId: envelope.logSigningKeyId,
      checkpointDigest: envelope.logCheckpointDigest,
      signature: envelope.logHeadSignature,
      checkpointReceivedAt: envelope.receivedAt,
    });
  }
  checkpoints.push({
    conversationId: page.snapshot.conversationId,
    position: page.snapshot.logHead.position,
    previousHeadHash: page.snapshot.logHead.previousHeadHash,
    headHash: page.snapshot.logHead.headHash,
    signingKeyId: page.snapshot.logHead.signingKeyId,
    checkpointDigest: page.snapshot.logHead.checkpointDigest,
    signature: page.snapshot.logHead.signature,
    checkpointReceivedAt: page.snapshot.logHead.checkpointReceivedAt,
  });
  if (checkpoints.length === 0 || checkpoints.length > CONVERSATION_PAGE_HARD_MAX_EVENTS + 1) {
    throw invalid("Conversation page proof bundle has an invalid checkpoint count.");
  }

  const welcomeItem = page.events.find(({ welcome }) => welcome !== null);
  const targetWelcome =
    welcomeItem?.welcome === null || welcomeItem === undefined
      ? null
      : Object.freeze({
          releaseProfileId,
          conversationId: welcomeItem.envelope.conversationId,
          expectedGroupIdHash,
          commitEpoch: welcomeItem.envelope.epoch,
          commitPosition: welcomeItem.envelope.position,
          commitEnvelopeId: welcomeItem.envelope.envelopeId,
          commitEnvelopeBytes: welcomeItem.envelope.envelopeBytes,
          commitEnvelopeSha256: welcomeItem.envelope.envelopeSha256,
          targetAccountId,
          targetInstallationId: welcomeItem.welcome.targetInstallationId,
          targetCredentialId: membership.credentialId,
          targetCredentialFingerprint: membership.credentialFingerprint,
          welcome: welcomeItem.welcome.welcome,
          welcomeSha256: welcomeItem.welcome.welcomeSha256,
        });
  const request: ConversationPageProofVerificationRequest = Object.freeze({
    profile: "conversation-page-proof-bundle.v1",
    realmId,
    conversationId: page.snapshot.conversationId,
    conversationGeneration,
    releaseProfileId,
    releaseTrustRootDigest,
    checkpoints: Object.freeze(checkpoints),
    witness: Object.freeze({ ...page.snapshot.witnessReceipt }),
    priorWitness,
    witnessTrustMode: "continuity",
    targetWelcome,
    verifiedAt,
    deadline,
    signal,
  });
  const rawEvidence = await callDeliveryPort(deadline, signal, (portSignal) =>
    verifier.verify(Object.freeze({ ...request, signal: portSignal })),
  );
  throwIfDeliveryPortUnavailable(rawEvidence);
  return parseConversationPageProofEvidence(rawEvidence, request);
}

async function verifyOrderedMlsTranscript(
  page: StructurallyVerifiedConversationPage,
  projectionAtAnchor: ConversationMlsProjection,
  senderBindings: readonly ConversationMlsCommitSenderBinding[],
  stagedProposalsAtAnchor: readonly MlsStagedExternalProposalBinding[],
  membership: ConversationMembershipWindow,
  cursorContext: ConversationCursorContext,
  pageStartPolicy: ConversationPolicyProjection,
  realmId: DeliveryRealmId,
  conversationGeneration: Uint63String,
  releaseProfileId: ReleaseProfileId,
  deliveryLimitsDigest: Hash32,
  releaseTrustRootDigest: Hash32,
  expectedGroupIdHash: Hash32,
  priorPolicy: ConversationPolicyConsistencyAnchor,
  policyReplay: ConversationPolicyReplayEvidence,
  deadline: Rfc3339Millis,
  signal: AbortSignal,
  commitVerifier: MlsCommitProjectionVerifierPort,
  proposalVerifier: MlsExternalProposalVerifierPort,
): Promise<{
  commitProjectionEvidence: readonly MlsCommitProjectionEvidence[];
  externalProposalEvidence: readonly MlsExternalProposalEvidence[];
  stagedProposalsAtPageEnd: readonly MlsStagedExternalProposalBinding[];
}> {
  let projection = projectionAtAnchor;
  let stagedProposals = [...stagedProposalsAtAnchor];
  if (stagedProposals.some(({ epoch }) => epoch !== projection.epoch)) {
    throw invalid("Staged proposal anchor contains a stale MLS epoch.");
  }
  const commitEvidence: MlsCommitProjectionEvidence[] = [];
  const proposalEvidence: MlsExternalProposalEvidence[] = [];
  let activePolicy = policyReplay.pageStartPolicy;
  let transitionIndex = 0;
  let lastCommit: MlsCommitProjectionEvidence | null = null;
  const applyCutoffTransitions = (
    throughPosition: Uint63String,
    inclusive: boolean,
  ): void => {
    while (transitionIndex < policyReplay.transitions.length) {
      const transition = policyReplay.transitions[transitionIndex]!;
      const comparison =
        BigInt(transition.deliveryLogPosition) - BigInt(throughPosition);
      if (comparison > 0n || (!inclusive && comparison === 0n)) break;
      const removedRequirements = activePolicy.mandatoryProposals.filter(
        (required) =>
          !transition.mandatoryProposals.some(
            (next) =>
              next.proposalId === required.proposalId &&
              next.proposalHash === required.proposalHash,
          ),
      );
      if (
        removedRequirements.length > 0 &&
        (lastCommit === null ||
          lastCommit.position !== transition.deliveryLogPosition ||
          removedRequirements.some(
            (required) =>
              !lastCommit!.consumedProposals.some(
                (consumed) =>
                  consumed.proposalId === required.proposalId &&
                  consumed.proposalHash === required.proposalHash,
              ),
          ))
      ) {
        throw invalid(
          "Policy mandatory cutoff was cleared without its exact verified Commit.",
        );
      }
      activePolicy = transition;
      transitionIndex += 1;
    }
  };
  for (const { envelope } of page.events) {
    applyCutoffTransitions(envelope.position, false);
    if (
      envelope.epoch !== projection.epoch ||
      envelope.rosterVersion !== projection.rosterVersion
    ) {
      throw invalid("Envelope MLS projection is stale or skips state.");
    }
    if (
      envelope.envelopeClass === "application" &&
      (activePolicy.mandatoryProposals.length > 0 || stagedProposals.length > 0)
    ) {
      throw invalid("Application traffic is frozen behind a mandatory MLS proposal.");
    }
    if (envelope.envelopeClass === "external_proposal") {
      const verifiedProposal = await verifyMlsExternalProposal(
        page,
        envelope,
        realmId,
        conversationGeneration,
        releaseProfileId,
        deliveryLimitsDigest,
        releaseTrustRootDigest,
        expectedGroupIdHash,
        pageStartPolicy,
        priorPolicy,
        deadline,
        signal,
        proposalVerifier,
      );
      proposalEvidence.push(verifiedProposal);
      stagedProposals.push(
        Object.freeze({
          position: verifiedProposal.position,
          envelopeId: verifiedProposal.envelopeId,
          envelopeSha256: verifiedProposal.envelopeSha256,
          epoch: verifiedProposal.epoch,
          proposalId: verifiedProposal.proposalId,
          proposalHash: verifiedProposal.proposalHash,
          authorizationRecordHash: verifiedProposal.authorizationRecordHash,
          membershipIntentId: verifiedProposal.membershipIntentId,
          membershipIntentHash: verifiedProposal.membershipIntentHash,
          membershipIntentEvidenceDigest:
            verifiedProposal.membershipIntentEvidenceDigest,
          proposalType: verifiedProposal.proposalType,
          proposalRequirement: verifiedProposal.proposalRequirement,
          authorizingPolicyHeadSequence:
            verifiedProposal.authorizingPolicyHeadSequence,
          authorizingPolicyHeadHash:
            verifiedProposal.authorizingPolicyHeadHash,
        }),
      );
      stagedProposals = [
        ...parseStagedProposalBindings(
          stagedProposals,
          "ordered staged proposal queue",
        ),
      ];
      applyCutoffTransitions(envelope.position, true);
      const isRequired = activePolicy.mandatoryProposals.some(
        (required) =>
          required.proposalId === verifiedProposal.proposalId &&
          required.proposalHash === verifiedProposal.proposalHash,
      );
      if (
        verifiedProposal.proposalRequirement !==
        (isRequired ? "mandatory" : "optional")
      ) {
        throw invalid(
          "External proposal requirement disagrees with the witnessed policy cutoff.",
        );
      }
      continue;
    }
    if (envelope.envelopeClass !== "mls_commit") continue;
    const missingRequiredProposal = activePolicy.mandatoryProposals.some(
      (required) =>
        !stagedProposals.some(
          (staged) =>
            staged.proposalId === required.proposalId &&
            staged.proposalHash === required.proposalHash,
        ),
    );
    if (missingRequiredProposal) {
      throw invalid("Commit is missing a canonical required proposal envelope.");
    }
    if (
      envelope.baseConfirmedTranscriptHash !== projection.confirmedTranscriptHash
    ) {
      throw invalid("Commit base transcript hash does not match the verified prefix.");
    }
    const senderBinding = senderBindings.find(
      (binding) =>
        binding.accountId === envelope.sender.accountId &&
        binding.installationId === envelope.sender.installationId &&
        BigInt(binding.activeFromPosition) <= BigInt(envelope.position) &&
        (binding.inactiveAtPosition === null ||
          BigInt(envelope.position) < BigInt(binding.inactiveAtPosition)),
    );
    if (!senderBinding) {
      throw invalid("Commit sender has no authenticated roster credential binding.");
    }
    const request: MlsCommitProjectionVerificationRequest = Object.freeze({
      profile: "mls-commit-projection.v1",
      realmId,
      conversationGeneration,
      releaseProfileId,
      releaseTrustRootDigest,
      expectedGroupIdHash,
      conversationId: envelope.conversationId,
      position: envelope.position,
      envelopeId: envelope.envelopeId,
      envelopeBytes: envelope.envelopeBytes,
      envelopeSha256: envelope.envelopeSha256,
      expectedAccountId: envelope.sender.accountId,
      expectedInstallationId: envelope.sender.installationId,
      expectedCredentialId: senderBinding.credentialId,
      expectedCredentialFingerprint: senderBinding.credentialFingerprint,
      expectedCredentialRevocationVersion:
        senderBinding.credentialRevocationVersion,
      expectedSenderGeneration: senderBinding.senderGeneration,
      commitEpoch: envelope.epoch,
      commitRosterVersion: envelope.rosterVersion,
      previousEpoch: projection.epoch,
      previousRosterVersion: projection.rosterVersion,
      previousConfirmedTranscriptHash: projection.confirmedTranscriptHash,
      baseConfirmedTranscriptHash: envelope.baseConfirmedTranscriptHash,
      resultingConfirmedTranscriptHash:
        envelope.resultingConfirmedTranscriptHash,
      stagedProposals: Object.freeze([...stagedProposals]),
      requiredProposals: Object.freeze([
        ...activePolicy.mandatoryProposals,
      ]),
      creatorBootstrapTarget:
        membership.bootstrapMode === "creator" &&
        envelope.position === membership.joinedPosition
          ? Object.freeze({
              accountId: cursorContext.accountId,
              installationId: cursorContext.installationId,
              credentialId: membership.credentialId,
              credentialFingerprint: membership.credentialFingerprint,
            })
          : null,
      removalTarget:
        membership.removedPosition !== null &&
        envelope.position === membership.removedPosition
          ? Object.freeze({
              accountId: cursorContext.accountId,
              installationId: cursorContext.installationId,
              credentialId: membership.credentialId,
              credentialFingerprint: membership.credentialFingerprint,
            })
          : null,
      deadline,
      signal,
    });
    const raw = await callDeliveryPort(deadline, signal, (portSignal) =>
      commitVerifier.verify(Object.freeze({ ...request, signal: portSignal })),
    );
    throwIfDeliveryPortUnavailable(raw);
    const parsed = parseMlsCommitProjectionEvidence(raw, request);
    commitEvidence.push(parsed);
    lastCommit = parsed;
    // Every Commit advances the epoch. Optional proposals not consumed by it
    // are stale as well, so the entire prior-epoch staging queue is discarded.
    stagedProposals = [];
    projection = Object.freeze({
      epoch: parsed.resultingEpoch,
      rosterVersion: parsed.resultingRosterVersion,
      confirmedTranscriptHash: parsed.resultingConfirmedTranscriptHash,
    });
    applyCutoffTransitions(envelope.position, true);
  }
  applyCutoffTransitions(page.snapshot.logHead.position, true);
  if (
    transitionIndex !== policyReplay.transitions.length ||
    !samePolicyMandatoryProposals(
      activePolicy.mandatoryProposals,
      policyReplay.pageEndPolicy.mandatoryProposals,
    )
  ) {
    throw invalid("Ordered replay did not reach the verified page-end policy cutoff.");
  }
  if (
    page.snapshot.epoch !== projection.epoch ||
    page.snapshot.rosterVersion !== projection.rosterVersion ||
    page.snapshot.confirmedTranscriptHash !== projection.confirmedTranscriptHash
  ) {
    throw invalid(
      "Snapshot MLS projection is not the verified page projection head.",
    );
  }
  return Object.freeze({
    commitProjectionEvidence: Object.freeze(commitEvidence),
    externalProposalEvidence: Object.freeze(proposalEvidence),
    stagedProposalsAtPageEnd: Object.freeze(stagedProposals),
  });
}

async function verifyConversationPolicyHead(
  snapshot: ConversationPageSnapshot,
  verifiedAt: Rfc3339Millis,
  deadline: Rfc3339Millis,
  signal: AbortSignal,
  releaseProfileId: ReleaseProfileId,
  realmId: DeliveryRealmId,
  conversationGeneration: Uint63String,
  releaseTrustRootDigest: Hash32,
  priorPolicy: ConversationPolicyConsistencyAnchor,
  verifier: PolicyHeadProofVerifierPort,
): Promise<ConversationPolicyHeadProofEvidence> {
  const request: PolicyHeadProofVerificationRequest = Object.freeze({
    profile: "conversation-policy-head-proof.v1",
    realmId,
    conversationGeneration,
    releaseTrustRootDigest,
    purpose: "historical-page",
    releaseProfileId,
    deliveryLimitsDigest: snapshot.deliveryLimitsDigest,
    conversationId: snapshot.conversationId,
    epoch: snapshot.epoch,
    rosterVersion: snapshot.rosterVersion,
    confirmedTranscriptHash: snapshot.confirmedTranscriptHash,
    policyHeadId: snapshot.policyHeadId,
    policyRevision: snapshot.policyRevision,
    mandatoryProposalCount: snapshot.policyMandatoryProposalCount,
    mandatoryProposalSetHash: snapshot.policyMandatoryProposalSetHash,
    authorizedSendGrantSetHash: snapshot.policyAuthorizedSendGrantSetHash,
    selectedSendGrantEvidenceDigest: ZERO_HASH32,
    selectedSendGrantInclusionEvidenceDigest: ZERO_HASH32,
    authorizedQuotaPolicyDigest: snapshot.policyAuthorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: priorPolicy.policyHeadSequence,
    priorPolicyHeadHash: priorPolicy.policyHeadHash,
    priorPolicyWitnessCheckpointId: priorPolicy.witnessCheckpointId,
    priorPolicyWitnessEvidenceDigest: priorPolicy.witnessEvidenceDigest,
    policyHeadSequence: snapshot.policyHeadSequence,
    policyHeadHash: snapshot.policyHeadHash,
    deliveryLogPosition: snapshot.policyDeliveryLogPosition,
    deliveryLogHeadHash: snapshot.policyDeliveryLogHeadHash,
    evaluationLogPosition: snapshot.logHead.position,
    evaluationLogHeadHash: snapshot.logHead.headHash,
    verifiedAt,
    deadline,
    signal,
  });
  const raw = await callDeliveryPort(deadline, signal, (portSignal) =>
    verifier.verify(Object.freeze({ ...request, signal: portSignal })),
  );
  throwIfDeliveryPortUnavailable(raw);
  return parseConversationPolicyHeadProofEvidence(raw, request);
}

async function verifyConversationPolicyReplay(
  page: StructurallyVerifiedConversationPage,
  anchor: ConversationHeadAnchor,
  pageStartPolicy: ConversationPolicyProjection,
  policyLogHighWater: ConversationPolicyConsistencyAnchor,
  verifiedAt: Rfc3339Millis,
  deadline: Rfc3339Millis,
  signal: AbortSignal,
  realmId: DeliveryRealmId,
  conversationGeneration: Uint63String,
  releaseProfileId: ReleaseProfileId,
  deliveryLimitsDigest: Hash32,
  releaseTrustRootDigest: Hash32,
  verifier: ConversationPolicyReplayVerifierPort,
): Promise<ConversationPolicyReplayEvidence> {
  const request: ConversationPolicyReplayVerificationRequest = Object.freeze({
    profile: "conversation-policy-replay.v1",
    realmId,
    conversationGeneration,
    releaseProfileId,
    deliveryLimitsDigest,
    releaseTrustRootDigest,
    conversationId: page.snapshot.conversationId,
    pageStartPosition: anchor.position,
    pageStartHeadHash: anchor.headHash,
    pageStartPolicy: toPolicyReplayProjection(pageStartPolicy),
    pageEndPosition: page.snapshot.logHead.position,
    pageEndHeadHash: page.snapshot.logHead.headHash,
    pageEndPolicy: snapshotPolicyReplayProjection(page.snapshot),
    policyLogHighWaterSequence: policyLogHighWater.policyHeadSequence,
    policyLogHighWaterHash: policyLogHighWater.policyHeadHash,
    policyLogHighWaterWitnessCheckpointId:
      policyLogHighWater.witnessCheckpointId,
    policyLogHighWaterWitnessEvidenceDigest:
      policyLogHighWater.witnessEvidenceDigest,
    events: Object.freeze(
      page.events.map(({ envelope }) =>
        Object.freeze({
          position: envelope.position,
          envelopeId: envelope.envelopeId,
          envelopeClass: envelope.envelopeClass,
          envelopeSha256: envelope.envelopeSha256,
          headHash: envelope.headHash,
        }),
      ),
    ),
    verifiedAt,
    deadline,
    signal,
  });
  const raw = await callDeliveryPort(deadline, signal, (portSignal) =>
    verifier.verify(Object.freeze({ ...request, signal: portSignal })),
  );
  throwIfDeliveryPortUnavailable(raw);
  return parseConversationPolicyReplayEvidence(raw, request);
}

function toPolicyReplayProjection(
  projection: ConversationPolicyProjection,
): ConversationPolicyReplayProjection {
  return Object.freeze({
    policyHeadId: projection.policyHeadId,
    policyHeadSequence: projection.policyHeadSequence,
    policyHeadHash: projection.policyHeadHash,
    deliveryLogPosition: projection.policyDeliveryLogPosition,
    deliveryLogHeadHash: projection.policyDeliveryLogHeadHash,
    mandatoryProposals: Object.freeze([...projection.policyMandatoryProposals]),
    witnessCheckpointId: projection.policyWitnessCheckpointId,
    witnessEvidenceDigest: projection.policyWitnessEvidenceDigest,
  });
}

function snapshotPolicyReplayProjection(
  snapshot: ConversationPageSnapshot,
): ConversationPolicyReplayProjection {
  return Object.freeze({
    policyHeadId: snapshot.policyHeadId,
    policyHeadSequence: snapshot.policyHeadSequence,
    policyHeadHash: snapshot.policyHeadHash,
    deliveryLogPosition: snapshot.policyDeliveryLogPosition,
    deliveryLogHeadHash: snapshot.policyDeliveryLogHeadHash,
    mandatoryProposals: Object.freeze([...snapshot.policyMandatoryProposals]),
    witnessCheckpointId: snapshot.policyWitnessCheckpointId,
    witnessEvidenceDigest: snapshot.policyWitnessEvidenceDigest,
  });
}

export function parseConversationPolicyReplayEvidence(
  value: unknown,
  expected: ConversationPolicyReplayVerificationRequest,
): ConversationPolicyReplayEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationGeneration",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "releaseTrustRootDigest",
      "conversationId",
      "pageStartPosition",
      "pageStartHeadHash",
      "pageStartPolicy",
      "pageEndPosition",
      "pageEndHeadHash",
      "pageEndPolicy",
      "policyLogHighWaterSequence",
      "policyLogHighWaterHash",
      "policyLogHighWaterWitnessCheckpointId",
      "policyLogHighWaterWitnessEvidenceDigest",
      "events",
      "transitions",
      "transitionCompactionStatus",
      "transitionRangeProofDigest",
      "historicalIntervalStatus",
      "applicationCutoffStatus",
      "policyConsistencyStatus",
      "policyConsistencyEvidenceDigest",
      "verifiedAt",
      "evidenceDigest",
    ],
    "conversation policy replay evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "conversation-policy-replay.v1"
  ) {
    throw invalid("Conversation policy replay was not verified.");
  }
  const parsed: ConversationPolicyReplayEvidence = Object.freeze({
    profile: "conversation-policy-replay.v1",
    realmId: parseDeliveryRealmId(record.realmId),
    conversationGeneration: parsePositive(
      record.conversationGeneration,
      "policy replay conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "policy replay delivery limits digest",
    ),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "policy replay trust-root digest",
    ),
    conversationId: parseConversationId(record.conversationId),
    pageStartPosition: parseUint63String(
      record.pageStartPosition,
      "policy replay page-start position",
    ),
    pageStartHeadHash: parseHash32(
      record.pageStartHeadHash,
      "policy replay page-start head",
    ),
    pageStartPolicy: parsePolicyReplayProjection(
      record.pageStartPolicy,
      "policy replay page-start projection",
    ),
    pageEndPosition: parsePositive(
      record.pageEndPosition,
      "policy replay page-end position",
    ),
    pageEndHeadHash: parseHash32(
      record.pageEndHeadHash,
      "policy replay page-end head",
    ),
    pageEndPolicy: parsePolicyReplayProjection(
      record.pageEndPolicy,
      "policy replay page-end projection",
    ),
    policyLogHighWaterSequence: parseUint63String(
      record.policyLogHighWaterSequence,
      "policy replay high-water sequence",
    ),
    policyLogHighWaterHash: parseHash32(
      record.policyLogHighWaterHash,
      "policy replay high-water hash",
    ),
    policyLogHighWaterWitnessCheckpointId: parseWitnessCheckpointId(
      record.policyLogHighWaterWitnessCheckpointId,
    ),
    policyLogHighWaterWitnessEvidenceDigest: parseHash32(
      record.policyLogHighWaterWitnessEvidenceDigest,
      "policy replay high-water witness digest",
    ),
    events: parsePolicyReplayEvents(record.events),
    transitions: parsePolicyReplayTransitions(record.transitions),
    transitionCompactionStatus: parseExactLiteral(
      record.transitionCompactionStatus,
      "verified-complete",
      "policy replay transition compaction status",
    ),
    transitionRangeProofDigest: parseHash32(
      record.transitionRangeProofDigest,
      "policy replay transition range proof digest",
    ),
    historicalIntervalStatus: parseExactLiteral(
      record.historicalIntervalStatus,
      "verified",
      "policy replay historical interval status",
    ),
    applicationCutoffStatus: parseExactLiteral(
      record.applicationCutoffStatus,
      "verified",
      "policy replay application cutoff status",
    ),
    policyConsistencyStatus: parseExactLiteral(
      record.policyConsistencyStatus,
      "verified",
      "policy replay consistency status",
    ),
    policyConsistencyEvidenceDigest: parseHash32(
      record.policyConsistencyEvidenceDigest,
      "policy replay consistency evidence digest",
    ),
    verifiedAt: parseRfc3339Millis(
      record.verifiedAt,
      "policy replay verifiedAt",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "policy replay evidence digest",
    ),
  });
  assertPolicyReplayMatchesRequest(parsed, expected);
  validatePolicyReplayInterval(parsed);
  if (
    parsed.evidenceDigest !== computeConversationPolicyReplayEvidenceDigest(parsed)
  ) {
    throw invalid("Conversation policy replay evidence digest is inconsistent.");
  }
  return parsed;
}

function parsePolicyReplayProjection(
  value: unknown,
  label: string,
): ConversationPolicyReplayProjection {
  const record = expectExactRecord(
    value,
    [
      "policyHeadId",
      "policyHeadSequence",
      "policyHeadHash",
      "deliveryLogPosition",
      "deliveryLogHeadHash",
      "mandatoryProposals",
      "witnessCheckpointId",
      "witnessEvidenceDigest",
    ],
    label,
  );
  const deliveryLogPosition = parseUint63String(
    record.deliveryLogPosition,
    `${label} delivery-log position`,
  );
  const deliveryLogHeadHash = parseHash32(
    record.deliveryLogHeadHash,
    `${label} delivery-log head`,
  );
  if (
    (deliveryLogPosition === "0") !==
    (deliveryLogHeadHash === ZERO_HASH32)
  ) {
    throw invalid(`${label} has an invalid delivery-log sentinel.`);
  }
  return Object.freeze({
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyHeadSequence: parsePositive(
      record.policyHeadSequence,
      `${label} sequence`,
    ),
    policyHeadHash: parseNonZeroHash32(record.policyHeadHash, `${label} hash`),
    deliveryLogPosition,
    deliveryLogHeadHash,
    mandatoryProposals: parsePolicyMandatoryProposals(
      record.mandatoryProposals,
      `${label} mandatory proposals`,
    ),
    witnessCheckpointId: parseWitnessCheckpointId(
      record.witnessCheckpointId,
    ),
    witnessEvidenceDigest: parseHash32(
      record.witnessEvidenceDigest,
      `${label} witness evidence digest`,
    ),
  });
}

function parsePolicyReplayEvents(
  value: unknown,
): ConversationPolicyReplayEvidence["events"] {
  const entries = expectDenseArray(
    value,
    CONVERSATION_PAGE_HARD_MAX_EVENTS,
    "policy replay events",
  );
  let priorPosition = 0n;
  return Object.freeze(
    entries.map((entry, index) => {
      const record = expectExactRecord(
        entry,
        ["position", "envelopeId", "envelopeClass", "envelopeSha256", "headHash"],
        `policy replay event ${index}`,
      );
      const parsed = Object.freeze({
        position: parsePositive(record.position, "policy replay event position"),
        envelopeId: parseEnvelopeId(record.envelopeId),
        envelopeClass: parseOneOfString(
          record.envelopeClass,
          ["application", "external_proposal", "mls_commit"] as const,
          "policy replay envelope class",
        ),
        envelopeSha256: parseHash32(
          record.envelopeSha256,
          "policy replay envelope SHA-256",
        ),
        headHash: parseHash32(record.headHash, "policy replay event head"),
      });
      if (BigInt(parsed.position) <= priorPosition) {
        throw invalid("Policy replay events must be strictly ordered.");
      }
      priorPosition = BigInt(parsed.position);
      return parsed;
    }),
  );
}

function parsePolicyReplayTransitions(
  value: unknown,
): readonly ConversationPolicyReplayTransition[] {
  const entries = expectDenseArray(
    value,
    CONVERSATION_POLICY_REPLAY_MAX_COALESCED_TRANSITIONS,
    "policy replay cutoff transitions",
  );
  return Object.freeze(
    entries.map((entry, index) =>
      parsePolicyReplayProjection(
        entry,
        `policy replay cutoff transition ${index}`,
      ),
    ),
  );
}

function samePolicyReplayProjection(
  left: ConversationPolicyReplayProjection,
  right: ConversationPolicyReplayProjection,
): boolean {
  return (
    left.policyHeadId === right.policyHeadId &&
    left.policyHeadSequence === right.policyHeadSequence &&
    left.policyHeadHash === right.policyHeadHash &&
    left.deliveryLogPosition === right.deliveryLogPosition &&
    left.deliveryLogHeadHash === right.deliveryLogHeadHash &&
    samePolicyMandatoryProposals(
      left.mandatoryProposals,
      right.mandatoryProposals,
    ) &&
    left.witnessCheckpointId === right.witnessCheckpointId &&
    left.witnessEvidenceDigest === right.witnessEvidenceDigest
  );
}

function assertPolicyReplayMatchesRequest(
  parsed: ConversationPolicyReplayEvidence,
  expected: ConversationPolicyReplayVerificationRequest,
): void {
  if (
    parsed.realmId !== expected.realmId ||
    parsed.conversationGeneration !== expected.conversationGeneration ||
    parsed.releaseProfileId !== expected.releaseProfileId ||
    parsed.deliveryLimitsDigest !== expected.deliveryLimitsDigest ||
    parsed.releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    parsed.conversationId !== expected.conversationId ||
    parsed.pageStartPosition !== expected.pageStartPosition ||
    parsed.pageStartHeadHash !== expected.pageStartHeadHash ||
    !samePolicyReplayProjection(parsed.pageStartPolicy, expected.pageStartPolicy) ||
    parsed.pageEndPosition !== expected.pageEndPosition ||
    parsed.pageEndHeadHash !== expected.pageEndHeadHash ||
    !samePolicyReplayProjection(parsed.pageEndPolicy, expected.pageEndPolicy) ||
    parsed.policyLogHighWaterSequence !==
      expected.policyLogHighWaterSequence ||
    parsed.policyLogHighWaterHash !== expected.policyLogHighWaterHash ||
    parsed.policyLogHighWaterWitnessCheckpointId !==
      expected.policyLogHighWaterWitnessCheckpointId ||
    parsed.policyLogHighWaterWitnessEvidenceDigest !==
      expected.policyLogHighWaterWitnessEvidenceDigest ||
    parsed.verifiedAt !== expected.verifiedAt ||
    parsed.events.length !== expected.events.length ||
    parsed.events.some((event, index) => {
      const expectedEvent = expected.events[index]!;
      return (
        event.position !== expectedEvent.position ||
        event.envelopeId !== expectedEvent.envelopeId ||
        event.envelopeClass !== expectedEvent.envelopeClass ||
        event.envelopeSha256 !== expectedEvent.envelopeSha256 ||
        event.headHash !== expectedEvent.headHash
      );
    })
  ) {
    throw invalid("Conversation policy replay evidence was substituted.");
  }
}

function validatePolicyReplayInterval(
  evidence: ConversationPolicyReplayEvidence,
): void {
  if (
    BigInt(evidence.pageEndPosition) < BigInt(evidence.pageStartPosition) ||
    evidence.transitionRangeProofDigest === ZERO_HASH32 ||
    BigInt(evidence.pageEndPolicy.policyHeadSequence) <
      BigInt(evidence.pageStartPolicy.policyHeadSequence) ||
    (evidence.pageEndPolicy.policyHeadSequence ===
      evidence.pageStartPolicy.policyHeadSequence &&
      !samePolicyReplayProjection(
        evidence.pageEndPolicy,
        evidence.pageStartPolicy,
      )) ||
    BigInt(evidence.pageEndPolicy.deliveryLogPosition) <
      BigInt(evidence.pageStartPolicy.deliveryLogPosition) ||
    BigInt(evidence.policyLogHighWaterSequence) <
      BigInt(evidence.pageEndPolicy.policyHeadSequence) ||
    (evidence.policyLogHighWaterSequence ===
      evidence.pageEndPolicy.policyHeadSequence &&
      evidence.policyLogHighWaterHash !== evidence.pageEndPolicy.policyHeadHash)
  ) {
    throw invalid("Policy replay rolls back a delivery or policy-log high-water.");
  }
  let prior = evidence.pageStartPolicy;
  for (const transition of evidence.transitions) {
    if (
      BigInt(transition.policyHeadSequence) <=
        BigInt(prior.policyHeadSequence) ||
      BigInt(transition.policyHeadSequence) >
        BigInt(evidence.pageEndPolicy.policyHeadSequence) ||
      BigInt(transition.deliveryLogPosition) <
        BigInt(evidence.pageStartPosition) ||
      BigInt(transition.deliveryLogPosition) >
        BigInt(evidence.pageEndPosition) ||
      BigInt(transition.deliveryLogPosition) <
        BigInt(prior.deliveryLogPosition) ||
      samePolicyMandatoryProposals(
        transition.mandatoryProposals,
        prior.mandatoryProposals,
      ) ||
      !policyReplayHeadMatchesPage(evidence, transition)
    ) {
      throw invalid("Policy replay cutoff transitions are incomplete or invalid.");
    }
    prior = transition;
  }
  if (
    !samePolicyMandatoryProposals(
      prior.mandatoryProposals,
      evidence.pageEndPolicy.mandatoryProposals,
    )
  ) {
    throw invalid("Policy replay does not reach the page-end mandatory set.");
  }
  let active = evidence.pageStartPolicy.mandatoryProposals;
  let transitionIndex = 0;
  for (const event of evidence.events) {
    while (
      transitionIndex < evidence.transitions.length &&
      BigInt(evidence.transitions[transitionIndex]!.deliveryLogPosition) <
        BigInt(event.position)
    ) {
      active = evidence.transitions[transitionIndex]!.mandatoryProposals;
      transitionIndex += 1;
    }
    if (event.envelopeClass === "application" && active.length > 0) {
      throw invalid("Policy replay contains application traffic after a cutoff.");
    }
    while (
      transitionIndex < evidence.transitions.length &&
      evidence.transitions[transitionIndex]!.deliveryLogPosition ===
        event.position
    ) {
      const transition = evidence.transitions[transitionIndex]!;
      const clearsRequirement = active.some(
        (required) =>
          !transition.mandatoryProposals.some(
            (next) =>
              next.proposalId === required.proposalId &&
              next.proposalHash === required.proposalHash,
          ),
      );
      if (clearsRequirement && event.envelopeClass !== "mls_commit") {
        throw invalid("Policy cutoff was cleared without a Commit position.");
      }
      active = transition.mandatoryProposals;
      transitionIndex += 1;
    }
  }
}

function policyReplayHeadMatchesPage(
  evidence: ConversationPolicyReplayEvidence,
  projection: ConversationPolicyReplayProjection,
): boolean {
  if (projection.deliveryLogPosition === evidence.pageStartPosition) {
    return projection.deliveryLogHeadHash === evidence.pageStartHeadHash;
  }
  return evidence.events.some(
    (event) =>
      event.position === projection.deliveryLogPosition &&
      event.headHash === projection.deliveryLogHeadHash,
  );
}

export function computeConversationPolicyReplayEvidenceDigest(
  input: Omit<ConversationPolicyReplayEvidence, "profile" | "evidenceDigest">,
): Hash32 {
  return sha256Bytes(
    utf8(CONVERSATION_POLICY_REPLAY_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.deliveryLimitsDigest),
      decodeHash32(input.releaseTrustRootDigest),
      utf8(input.conversationId),
      utf8(input.pageStartPosition),
      decodeHash32(input.pageStartHeadHash),
      ...encodePolicyReplayProjection(input.pageStartPolicy),
      utf8(input.pageEndPosition),
      decodeHash32(input.pageEndHeadHash),
      ...encodePolicyReplayProjection(input.pageEndPolicy),
      utf8(input.policyLogHighWaterSequence),
      decodeHash32(input.policyLogHighWaterHash),
      utf8(input.policyLogHighWaterWitnessCheckpointId),
      decodeHash32(input.policyLogHighWaterWitnessEvidenceDigest),
      utf8(input.events.length.toString(10)),
      ...input.events.flatMap((event) => [
        utf8(event.position),
        utf8(event.envelopeId),
        utf8(event.envelopeClass),
        decodeHash32(event.envelopeSha256),
        decodeHash32(event.headHash),
      ]),
      utf8(input.transitions.length.toString(10)),
      ...input.transitions.flatMap(encodePolicyReplayProjection),
      utf8(input.transitionCompactionStatus),
      decodeHash32(input.transitionRangeProofDigest),
      utf8(input.historicalIntervalStatus),
      utf8(input.applicationCutoffStatus),
      utf8(input.policyConsistencyStatus),
      decodeHash32(input.policyConsistencyEvidenceDigest),
      utf8(input.verifiedAt),
    ),
  );
}

function encodePolicyReplayProjection(
  projection: ConversationPolicyReplayProjection,
): readonly Uint8Array[] {
  return [
    utf8(projection.policyHeadId),
    utf8(projection.policyHeadSequence),
    decodeHash32(projection.policyHeadHash),
    utf8(projection.deliveryLogPosition),
    decodeHash32(projection.deliveryLogHeadHash),
    ...encodePolicyMandatoryProposals(projection.mandatoryProposals),
    utf8(projection.witnessCheckpointId),
    decodeHash32(projection.witnessEvidenceDigest),
  ];
}

export function parseConversationPolicyHeadProofEvidence(
  value: unknown,
  expected: PolicyHeadProofVerificationRequest,
): ConversationPolicyHeadProofEvidence {
  return parsePolicyHeadProofEvidence(value, {
    realmId: expected.realmId,
    conversationGeneration: expected.conversationGeneration,
    releaseTrustRootDigest: expected.releaseTrustRootDigest,
    purpose: expected.purpose,
    releaseProfileId: expected.releaseProfileId,
    deliveryLimitsDigest: expected.deliveryLimitsDigest,
    conversationId: expected.conversationId,
    policyHeadId: expected.policyHeadId,
    policyHeadSequence: expected.policyHeadSequence,
    policyHeadHash: expected.policyHeadHash,
    deliveryLogPosition: expected.deliveryLogPosition,
    deliveryLogHeadHash: expected.deliveryLogHeadHash,
    evaluationLogPosition: expected.evaluationLogPosition,
    evaluationLogHeadHash: expected.evaluationLogHeadHash,
    epoch: expected.epoch,
    rosterVersion: expected.rosterVersion,
    confirmedTranscriptHash: expected.confirmedTranscriptHash,
    policyRevision: expected.policyRevision,
    mandatoryProposalCount: expected.mandatoryProposalCount,
    mandatoryProposalSetHash: expected.mandatoryProposalSetHash,
    authorizedSendGrantSetHash: expected.authorizedSendGrantSetHash,
    selectedSendGrantEvidenceDigest:
      expected.selectedSendGrantEvidenceDigest,
    selectedSendGrantInclusionEvidenceDigest:
      expected.selectedSendGrantInclusionEvidenceDigest,
    authorizedQuotaPolicyDigest: expected.authorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: expected.priorPolicyHeadSequence,
    priorPolicyHeadHash: expected.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId: expected.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      expected.priorPolicyWitnessEvidenceDigest,
    verifiedAt: expected.verifiedAt,
  });
}

export function computeConversationPolicyHeadProofEvidenceDigest(
  input: Omit<PolicyHeadProofEvidence, "profile" | "evidenceDigest">,
): Hash32 {
  return computePolicyHeadProofEvidenceDigest(input);
}

export function parseDeliveryCheckpointSignatureEvidence(
  value: unknown,
  expected: DeliveryCheckpointSignatureVerificationRequest,
): DeliveryCheckpointSignatureEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationId",
      "conversationGeneration",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "position",
      "previousHeadHash",
      "headHash",
      "signingKeyId",
      "checkpointDigest",
      "signatureSha256",
      "checkpointReceivedAt",
      "verifiedAt",
      "keyState",
      "validFrom",
      "validUntil",
      "evidenceDigest",
    ],
    "delivery checkpoint signature evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "delivery-log-checkpoint.v1"
  ) {
    throw invalid("Delivery checkpoint signature was not verified.");
  }
  const parsed: DeliveryCheckpointSignatureEvidence = Object.freeze({
    profile: "delivery-log-checkpoint.v1",
    realmId: parseDeliveryRealmId(record.realmId),
    conversationId: parseConversationId(record.conversationId),
    conversationGeneration: parsePositive(
      record.conversationGeneration,
      "verified checkpoint conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "verified checkpoint release trust-root digest",
    ),
    position: parsePositive(record.position, "verified checkpoint position"),
    previousHeadHash: parseHash32(
      record.previousHeadHash,
      "verified checkpoint predecessor",
    ),
    headHash: parseHash32(record.headHash, "verified checkpoint head"),
    signingKeyId: parseSigningKeyId(record.signingKeyId),
    checkpointDigest: parseHash32(
      record.checkpointDigest,
      "verified checkpoint digest",
    ),
    signatureSha256: parseHash32(
      record.signatureSha256,
      "verified checkpoint signature SHA-256",
    ),
    checkpointReceivedAt: parseRfc3339Millis(
      record.checkpointReceivedAt,
      "proof checkpoint receivedAt",
    ),
    verifiedAt: parseRfc3339Millis(
      record.verifiedAt,
      "checkpoint verification time",
    ),
    keyState: parseExactLiteral(
      record.keyState,
      "active",
      "checkpoint signing key state",
    ),
    validFrom: parseRfc3339Millis(record.validFrom, "checkpoint key validFrom"),
    validUntil: parseRfc3339Millis(
      record.validUntil,
      "checkpoint key validUntil",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "checkpoint signature evidence digest",
    ),
  });
  if (
    parsed.realmId !== expected.realmId ||
    parsed.conversationId !== expected.conversationId ||
    parsed.conversationGeneration !== expected.conversationGeneration ||
    parsed.releaseProfileId !== expected.releaseProfileId ||
    parsed.releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    parsed.position !== expected.position ||
    parsed.previousHeadHash !== expected.previousHeadHash ||
    parsed.headHash !== expected.headHash ||
    parsed.signingKeyId !== expected.signingKeyId ||
    parsed.checkpointDigest !== expected.checkpointDigest ||
    parsed.signatureSha256 !== hashSignature(expected.signature) ||
    parsed.checkpointReceivedAt !== expected.checkpointReceivedAt ||
    parsed.verifiedAt !== expected.verifiedAt
  ) {
    throw invalid("Delivery checkpoint signature evidence was substituted.");
  }
  if (
    parsed.validFrom > parsed.checkpointReceivedAt ||
    parsed.validUntil <= parsed.checkpointReceivedAt ||
    parsed.verifiedAt < parsed.checkpointReceivedAt ||
    parsed.validUntil <= parsed.validFrom
  ) {
    throw invalid("Delivery checkpoint signing key is not active at verification.");
  }
  if (
    parsed.evidenceDigest !==
    computeDeliveryCheckpointSignatureEvidenceDigest(parsed)
  ) {
    throw invalid("Delivery checkpoint signature evidence digest is inconsistent.");
  }
  return parsed;
}

export function computeDeliveryCheckpointSignatureEvidenceDigest(input: {
  realmId: DeliveryRealmId;
  conversationId: ConversationId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  position: Uint63String;
  previousHeadHash: Hash32;
  headHash: Hash32;
  signingKeyId: SigningKeyId;
  checkpointDigest: Hash32;
  signatureSha256: Hash32;
  checkpointReceivedAt: Rfc3339Millis;
  verifiedAt: Rfc3339Millis;
  keyState: "active";
  validFrom: Rfc3339Millis;
  validUntil: Rfc3339Millis;
}): Hash32 {
  return sha256Bytes(
    utf8(CHECKPOINT_SIGNATURE_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.releaseTrustRootDigest),
      utf8(input.position),
      decodeHash32(input.previousHeadHash),
      decodeHash32(input.headHash),
      utf8(input.signingKeyId),
      decodeHash32(input.checkpointDigest),
      decodeHash32(input.signatureSha256),
      utf8(input.checkpointReceivedAt),
      utf8(input.verifiedAt),
      utf8(input.keyState),
      utf8(input.validFrom),
      utf8(input.validUntil),
    ),
  );
}

export function parseMlsExternalProposalEvidence(
  value: unknown,
  expected: MlsExternalProposalVerificationRequest,
): MlsExternalProposalEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationGeneration",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "releaseTrustRootDigest",
      "expectedGroupIdHash",
      "conversationId",
      "position",
      "envelopeId",
      "envelopeSha256",
      "epoch",
      "rosterVersion",
      "credentialId",
      "credentialFingerprint",
      "signerGeneration",
      "checkpointReceivedAt",
      "pageEndPosition",
      "pageEndHeadHash",
      "pageEndPolicyHeadSequence",
      "pageEndPolicyHeadHash",
      "priorPolicyHeadSequence",
      "priorPolicyHeadHash",
      "priorPolicyWitnessCheckpointId",
      "priorPolicyWitnessEvidenceDigest",
      "policyLogHighWaterSequence",
      "policyLogHighWaterHash",
      "policyLogHighWaterWitnessCheckpointId",
      "policyLogHighWaterWitnessEvidenceDigest",
      "authorizingPolicyHeadId",
      "authorizingPolicyHeadSequence",
      "authorizingPolicyHeadHash",
      "proposalId",
      "proposalHash",
      "authorizationRecordHash",
      "membershipIntentId",
      "membershipIntentHash",
      "membershipIntentEvidenceDigest",
      "proposalRecordBindingStatus",
      "intentRecordBindingStatus",
      "recordBindingEvidenceDigest",
      "proposalType",
      "proposalRequirement",
      "proposalBodySha256",
      "activeCredentialStatus",
      "credentialValidFrom",
      "credentialValidUntil",
      "publicationWitnessCheckpointId",
      "publicationWitnessEvidenceDigest",
      "credentialPublicationStatus",
      "authorizationRecordStatus",
      "policyAuthorizationStatus",
      "policyConsistencyStatus",
      "policyConsistencyEvidenceDigest",
      "proposalStatus",
      "evidenceDigest",
    ],
    "MLS external proposal evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "mls-external-proposal.v1"
  ) {
    throw invalid("MLS external proposal was not verified.");
  }
  const parsed: MlsExternalProposalEvidence = Object.freeze({
    profile: "mls-external-proposal.v1",
    realmId: parseDeliveryRealmId(record.realmId),
    conversationGeneration: parsePositive(
      record.conversationGeneration,
      "proposal conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "proposal delivery limits digest",
    ),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "proposal release trust-root digest",
    ),
    expectedGroupIdHash: parseHash32(
      record.expectedGroupIdHash,
      "proposal expected group ID hash",
    ),
    conversationId: parseConversationId(record.conversationId),
    position: parsePositive(record.position, "proposal position"),
    envelopeId: parseEnvelopeId(record.envelopeId),
    envelopeSha256: parseHash32(record.envelopeSha256, "proposal envelope SHA-256"),
    epoch: parseUint63String(record.epoch, "proposal epoch"),
    rosterVersion: parseUint63String(record.rosterVersion, "proposal roster version"),
    credentialId: parseCredentialId(record.credentialId),
    credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
    signerGeneration: parsePositive(record.signerGeneration, "proposal signer generation"),
    checkpointReceivedAt: parseRfc3339Millis(
      record.checkpointReceivedAt,
      "proposal checkpoint receivedAt",
    ),
    pageEndPosition: parsePositive(
      record.pageEndPosition,
      "proposal page-end position",
    ),
    pageEndHeadHash: parseHash32(
      record.pageEndHeadHash,
      "proposal page-end head hash",
    ),
    pageEndPolicyHeadSequence: parsePositive(
      record.pageEndPolicyHeadSequence,
      "proposal page-end policy-head sequence",
    ),
    pageEndPolicyHeadHash: parseHash32(
      record.pageEndPolicyHeadHash,
      "proposal page-end policy-head hash",
    ),
    priorPolicyHeadSequence: parseUint63String(
      record.priorPolicyHeadSequence,
      "proposal prior policy-head sequence",
    ),
    priorPolicyHeadHash: parseHash32(
      record.priorPolicyHeadHash,
      "proposal prior policy-head hash",
    ),
    priorPolicyWitnessCheckpointId: parseWitnessCheckpointId(
      record.priorPolicyWitnessCheckpointId,
    ),
    priorPolicyWitnessEvidenceDigest: parseHash32(
      record.priorPolicyWitnessEvidenceDigest,
      "proposal prior policy witness evidence digest",
    ),
    policyLogHighWaterSequence: parseUint63String(
      record.policyLogHighWaterSequence,
      "proposal policy-log high-water sequence",
    ),
    policyLogHighWaterHash: parseHash32(
      record.policyLogHighWaterHash,
      "proposal policy-log high-water hash",
    ),
    policyLogHighWaterWitnessCheckpointId: parseWitnessCheckpointId(
      record.policyLogHighWaterWitnessCheckpointId,
    ),
    policyLogHighWaterWitnessEvidenceDigest: parseHash32(
      record.policyLogHighWaterWitnessEvidenceDigest,
      "proposal policy-log high-water witness evidence digest",
    ),
    authorizingPolicyHeadId: parsePolicyHeadId(
      record.authorizingPolicyHeadId,
    ),
    authorizingPolicyHeadSequence: parsePositive(
      record.authorizingPolicyHeadSequence,
      "proposal authorizing policy sequence",
    ),
    authorizingPolicyHeadHash: parseHash32(
      record.authorizingPolicyHeadHash,
      "proposal authorizing policy hash",
    ),
    proposalId: parseProposalId(record.proposalId),
    proposalHash: parseHash32(record.proposalHash, "proposal hash"),
    authorizationRecordHash: parseHash32(
      record.authorizationRecordHash,
      "proposal authorization-record hash",
    ),
    membershipIntentId: parseMembershipIntentId(record.membershipIntentId),
    membershipIntentHash: parseHash32(
      record.membershipIntentHash,
      "proposal membership-intent hash",
    ),
    membershipIntentEvidenceDigest: parseHash32(
      record.membershipIntentEvidenceDigest,
      "proposal membership-intent evidence digest",
    ),
    proposalRecordBindingStatus: parseExactLiteral(
      record.proposalRecordBindingStatus,
      "verified-one-to-one",
      "proposal record binding status",
    ),
    intentRecordBindingStatus: parseExactLiteral(
      record.intentRecordBindingStatus,
      "verified-one-to-one",
      "intent record binding status",
    ),
    recordBindingEvidenceDigest: parseHash32(
      record.recordBindingEvidenceDigest,
      "proposal/intent record binding evidence digest",
    ),
    proposalType: parseOneOfString(
      record.proposalType,
      ["add", "remove"] as const,
      "external proposal type",
    ),
    proposalRequirement: parseOneOfString(
      record.proposalRequirement,
      ["mandatory", "optional"] as const,
      "external proposal requirement",
    ),
    proposalBodySha256: parseHash32(
      record.proposalBodySha256,
      "proposal body SHA-256",
    ),
    activeCredentialStatus: parseExactLiteral(
      record.activeCredentialStatus,
      "active",
      "external signer credential status",
    ),
    credentialValidFrom: parseRfc3339Millis(
      record.credentialValidFrom,
      "external credential validFrom",
    ),
    credentialValidUntil: parseRfc3339Millis(
      record.credentialValidUntil,
      "external credential validUntil",
    ),
    publicationWitnessCheckpointId: parseWitnessCheckpointId(
      record.publicationWitnessCheckpointId,
    ),
    publicationWitnessEvidenceDigest: parseHash32(
      record.publicationWitnessEvidenceDigest,
      "external credential publication witness digest",
    ),
    credentialPublicationStatus: parseExactLiteral(
      record.credentialPublicationStatus,
      "verified",
      "external credential publication status",
    ),
    authorizationRecordStatus: parseExactLiteral(
      record.authorizationRecordStatus,
      "verified",
      "external proposal authorization-record status",
    ),
    policyAuthorizationStatus: parseExactLiteral(
      record.policyAuthorizationStatus,
      "active-at-proposal",
      "external proposal policy authorization status",
    ),
    policyConsistencyStatus: parseExactLiteral(
      record.policyConsistencyStatus,
      "verified",
      "external proposal policy consistency status",
    ),
    policyConsistencyEvidenceDigest: parseHash32(
      record.policyConsistencyEvidenceDigest,
      "external proposal policy consistency evidence digest",
    ),
    proposalStatus: parseExactLiteral(
      record.proposalStatus,
      "verified",
      "external proposal status",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "external proposal evidence digest",
    ),
  });
  if (
    parsed.realmId !== expected.realmId ||
    parsed.conversationGeneration !== expected.conversationGeneration ||
    parsed.releaseProfileId !== expected.releaseProfileId ||
    parsed.deliveryLimitsDigest !== expected.deliveryLimitsDigest ||
    parsed.releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    parsed.expectedGroupIdHash !== expected.expectedGroupIdHash ||
    parsed.conversationId !== expected.conversationId ||
    parsed.position !== expected.position ||
    parsed.envelopeId !== expected.envelopeId ||
    parsed.envelopeSha256 !== expected.envelopeSha256 ||
    parsed.epoch !== expected.epoch ||
    parsed.rosterVersion !== expected.rosterVersion ||
    parsed.credentialId !== expected.credentialId ||
    parsed.credentialFingerprint !== expected.credentialFingerprint ||
    parsed.signerGeneration !== expected.signerGeneration ||
    parsed.checkpointReceivedAt !== expected.checkpointReceivedAt ||
    parsed.pageEndPosition !== expected.pageEndPosition ||
    parsed.pageEndHeadHash !== expected.pageEndHeadHash ||
    parsed.pageEndPolicyHeadSequence !==
      expected.pageEndPolicyHeadSequence ||
    parsed.pageEndPolicyHeadHash !== expected.pageEndPolicyHeadHash ||
    parsed.priorPolicyHeadSequence !== expected.priorPolicyHeadSequence ||
    parsed.priorPolicyHeadHash !== expected.priorPolicyHeadHash ||
    parsed.priorPolicyWitnessCheckpointId !==
      expected.priorPolicyWitnessCheckpointId ||
    parsed.priorPolicyWitnessEvidenceDigest !==
      expected.priorPolicyWitnessEvidenceDigest ||
    parsed.policyLogHighWaterSequence !==
      expected.policyLogHighWaterSequence ||
    parsed.policyLogHighWaterHash !== expected.policyLogHighWaterHash ||
    parsed.policyLogHighWaterWitnessCheckpointId !==
      expected.policyLogHighWaterWitnessCheckpointId ||
    parsed.policyLogHighWaterWitnessEvidenceDigest !==
      expected.policyLogHighWaterWitnessEvidenceDigest
  ) {
    throw invalid("MLS external proposal evidence was substituted.");
  }
  if (
    parsed.credentialValidFrom > parsed.checkpointReceivedAt ||
    parsed.credentialValidUntil <= parsed.checkpointReceivedAt ||
    parsed.credentialValidUntil <= parsed.credentialValidFrom ||
    Date.parse(parsed.credentialValidUntil) -
        Date.parse(parsed.credentialValidFrom) >
      MLS_EXTERNAL_SIGNER_MAX_LIFETIME_MILLISECONDS ||
    BigInt(parsed.authorizingPolicyHeadSequence) === 0n ||
    BigInt(parsed.position) > BigInt(parsed.pageEndPosition) ||
    BigInt(parsed.authorizingPolicyHeadSequence) <
      BigInt(parsed.priorPolicyHeadSequence) ||
    BigInt(parsed.authorizingPolicyHeadSequence) >
      BigInt(parsed.pageEndPolicyHeadSequence) ||
    (parsed.authorizingPolicyHeadSequence ===
      parsed.priorPolicyHeadSequence &&
      parsed.authorizingPolicyHeadHash !== parsed.priorPolicyHeadHash) ||
    (parsed.authorizingPolicyHeadSequence ===
      parsed.pageEndPolicyHeadSequence &&
      parsed.authorizingPolicyHeadHash !== parsed.pageEndPolicyHeadHash) ||
    (parsed.priorPolicyHeadSequence === "0") !==
      (parsed.priorPolicyHeadHash === ZERO_HASH32) ||
    (parsed.policyLogHighWaterSequence === "0") !==
      (parsed.policyLogHighWaterHash === ZERO_HASH32) ||
    parsed.membershipIntentHash === ZERO_HASH32 ||
    parsed.membershipIntentEvidenceDigest === ZERO_HASH32 ||
    parsed.recordBindingEvidenceDigest === ZERO_HASH32
  ) {
    throw invalid("External proposal credential was not active at receipt.");
  }
  const computedProposalHash = computeExternalProposalHash(
    decodeCanonicalBase64Url(expected.envelopeBytes),
    parsed.authorizationRecordHash,
  );
  if (parsed.proposalHash !== computedProposalHash) {
    throw invalid("External proposal hash is not bound to the exact PublicMessage.");
  }
  if (parsed.evidenceDigest !== computeMlsExternalProposalEvidenceDigest(parsed)) {
    throw invalid("MLS external proposal evidence digest is inconsistent.");
  }
  return parsed;
}

export function computeMlsExternalProposalEvidenceDigest(
  input: Omit<MlsExternalProposalEvidence, "profile" | "evidenceDigest">,
): Hash32 {
  return sha256Bytes(
    utf8(MLS_EXTERNAL_PROPOSAL_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.deliveryLimitsDigest),
      decodeHash32(input.releaseTrustRootDigest),
      decodeHash32(input.expectedGroupIdHash),
      utf8(input.conversationId),
      utf8(input.position),
      utf8(input.envelopeId),
      decodeHash32(input.envelopeSha256),
      utf8(input.epoch),
      utf8(input.rosterVersion),
      utf8(input.credentialId),
      decodeFingerprint32(input.credentialFingerprint),
      utf8(input.signerGeneration),
      utf8(input.checkpointReceivedAt),
      utf8(input.pageEndPosition),
      decodeHash32(input.pageEndHeadHash),
      utf8(input.pageEndPolicyHeadSequence),
      decodeHash32(input.pageEndPolicyHeadHash),
      utf8(input.priorPolicyHeadSequence),
      decodeHash32(input.priorPolicyHeadHash),
      utf8(input.priorPolicyWitnessCheckpointId),
      decodeHash32(input.priorPolicyWitnessEvidenceDigest),
      utf8(input.policyLogHighWaterSequence),
      decodeHash32(input.policyLogHighWaterHash),
      utf8(input.policyLogHighWaterWitnessCheckpointId),
      decodeHash32(input.policyLogHighWaterWitnessEvidenceDigest),
      utf8(input.authorizingPolicyHeadId),
      utf8(input.authorizingPolicyHeadSequence),
      decodeHash32(input.authorizingPolicyHeadHash),
      utf8(input.proposalId),
      decodeHash32(input.proposalHash),
      decodeHash32(input.authorizationRecordHash),
      utf8(input.membershipIntentId),
      decodeHash32(input.membershipIntentHash),
      decodeHash32(input.membershipIntentEvidenceDigest),
      utf8(input.proposalRecordBindingStatus),
      utf8(input.intentRecordBindingStatus),
      decodeHash32(input.recordBindingEvidenceDigest),
      utf8(input.proposalType),
      utf8(input.proposalRequirement),
      decodeHash32(input.proposalBodySha256),
      utf8(input.activeCredentialStatus),
      utf8(input.credentialValidFrom),
      utf8(input.credentialValidUntil),
      utf8(input.publicationWitnessCheckpointId),
      decodeHash32(input.publicationWitnessEvidenceDigest),
      utf8(input.credentialPublicationStatus),
      utf8(input.authorizationRecordStatus),
      utf8(input.policyAuthorizationStatus),
      utf8(input.policyConsistencyStatus),
      decodeHash32(input.policyConsistencyEvidenceDigest),
      utf8(input.proposalStatus),
    ),
  );
}

export function parseMlsCommitProjectionEvidence(
  value: unknown,
  expected: MlsCommitProjectionVerificationRequest,
): MlsCommitProjectionEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationGeneration",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "expectedGroupIdHash",
      "conversationId",
      "position",
      "envelopeId",
      "envelopeSha256",
      "expectedAccountId",
      "expectedInstallationId",
      "expectedCredentialId",
      "expectedCredentialFingerprint",
      "expectedCredentialRevocationVersion",
      "expectedSenderGeneration",
      "authenticatedCredentialId",
      "authenticatedCredentialFingerprint",
      "authenticatedCredentialRevocationVersion",
      "authenticatedSenderGeneration",
      "senderBindingStatus",
      "commitEpoch",
      "commitRosterVersion",
      "previousEpoch",
      "previousRosterVersion",
      "previousConfirmedTranscriptHash",
      "baseConfirmedTranscriptHash",
      "resultingConfirmedTranscriptHash",
      "commitKind",
      "resultingEpoch",
      "resultingRosterVersion",
      "stagedProposals",
      "requiredProposals",
      "consumedProposals",
      "committedIntents",
      "proposalConsumptionStatus",
      "intentBindingStatus",
      "creatorBootstrapTarget",
      "creatorMembershipStatus",
      "removalTarget",
      "removalProposalId",
      "removalProposalHash",
      "removalMembershipStatus",
      "projectionStatus",
      "evidenceDigest",
    ],
    "MLS Commit projection evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "mls-commit-projection.v1"
  ) {
    throw invalid("MLS Commit projection was not verified.");
  }
  const parsed: MlsCommitProjectionEvidence = Object.freeze({
    profile: "mls-commit-projection.v1",
    realmId: parseDeliveryRealmId(record.realmId),
    conversationGeneration: parsePositive(
      record.conversationGeneration,
      "Commit projection conversation generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "Commit projection release trust-root digest",
    ),
    expectedGroupIdHash: parseHash32(
      record.expectedGroupIdHash,
      "Commit projection expected group ID hash",
    ),
    conversationId: parseConversationId(record.conversationId),
    position: parsePositive(record.position, "Commit projection position"),
    envelopeId: parseEnvelopeId(record.envelopeId),
    envelopeSha256: parseHash32(
      record.envelopeSha256,
      "Commit projection envelope SHA-256",
    ),
    expectedAccountId: parseAccountId(record.expectedAccountId),
    expectedInstallationId: parseInstallationId(
      record.expectedInstallationId,
    ),
    expectedCredentialId: parseCredentialId(record.expectedCredentialId),
    expectedCredentialFingerprint: parseFingerprint32(
      record.expectedCredentialFingerprint,
    ),
    expectedCredentialRevocationVersion: parseUint63String(
      record.expectedCredentialRevocationVersion,
      "Commit expected credential revocation version",
    ),
    expectedSenderGeneration: parsePositive(
      record.expectedSenderGeneration,
      "Commit expected sender generation",
    ),
    authenticatedCredentialId: parseCredentialId(
      record.authenticatedCredentialId,
    ),
    authenticatedCredentialFingerprint: parseFingerprint32(
      record.authenticatedCredentialFingerprint,
    ),
    authenticatedCredentialRevocationVersion: parseUint63String(
      record.authenticatedCredentialRevocationVersion,
      "Commit authenticated credential revocation version",
    ),
    authenticatedSenderGeneration: parsePositive(
      record.authenticatedSenderGeneration,
      "Commit authenticated sender generation",
    ),
    senderBindingStatus: parseExactLiteral(
      record.senderBindingStatus,
      "verified",
      "Commit sender binding status",
    ),
    commitEpoch: parseUint63String(
      record.commitEpoch,
      "Commit projection epoch",
    ),
    commitRosterVersion: parseUint63String(
      record.commitRosterVersion,
      "Commit projection roster version",
    ),
    previousEpoch: parseUint63String(
      record.previousEpoch,
      "Commit projection previous epoch",
    ),
    previousRosterVersion: parseUint63String(
      record.previousRosterVersion,
      "Commit projection previous roster version",
    ),
    previousConfirmedTranscriptHash: parseHash32(
      record.previousConfirmedTranscriptHash,
      "Commit projection previous transcript hash",
    ),
    baseConfirmedTranscriptHash: parseHash32(
      record.baseConfirmedTranscriptHash,
      "Commit projection base transcript hash",
    ),
    resultingConfirmedTranscriptHash: parseHash32(
      record.resultingConfirmedTranscriptHash,
      "Commit projection resulting transcript hash",
    ),
    commitKind: parseOneOfString(
      record.commitKind,
      ["membership", "update"] as const,
      "Commit projection kind",
    ),
    resultingEpoch: parseUint63String(
      record.resultingEpoch,
      "Commit projection resulting epoch",
    ),
    resultingRosterVersion: parseUint63String(
      record.resultingRosterVersion,
      "Commit projection resulting roster version",
    ),
    stagedProposals: parseStagedProposalBindings(
      record.stagedProposals,
      "Commit staged proposals",
    ),
    requiredProposals: parsePolicyMandatoryProposals(
      record.requiredProposals,
      "Commit required proposals",
    ),
    consumedProposals: parseStagedProposalBindings(
      record.consumedProposals,
      "Commit consumed proposals",
    ),
    committedIntents: parseCommittedIntentBindings(
      record.committedIntents,
      "Commit committed intents",
    ),
    proposalConsumptionStatus: parseExactLiteral(
      record.proposalConsumptionStatus,
      "verified",
      "Commit proposal consumption status",
    ),
    intentBindingStatus: parseExactLiteral(
      record.intentBindingStatus,
      "verified",
      "Commit intent binding status",
    ),
    creatorBootstrapTarget: parseMlsMembershipTarget(
      record.creatorBootstrapTarget,
      "Commit creator-bootstrap target",
    ),
    creatorMembershipStatus: parseOneOfString(
      record.creatorMembershipStatus,
      ["verified-present", "not-applicable"] as const,
      "Commit creator membership status",
    ),
    removalTarget: parseMlsMembershipTarget(
      record.removalTarget,
      "Commit removal target",
    ),
    removalProposalId:
      record.removalProposalId === null
        ? null
        : parseProposalId(record.removalProposalId),
    removalProposalHash:
      record.removalProposalHash === null
        ? null
        : parseHash32(record.removalProposalHash, "Commit removal proposal hash"),
    removalMembershipStatus: parseOneOfString(
      record.removalMembershipStatus,
      ["verified-absent", "not-applicable"] as const,
      "Commit removal membership status",
    ),
    projectionStatus: parseExactLiteral(
      record.projectionStatus,
      "verified",
      "Commit projection status",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "Commit projection evidence digest",
    ),
  });
  if (
    parsed.realmId !== expected.realmId ||
    parsed.conversationGeneration !== expected.conversationGeneration ||
    parsed.releaseProfileId !== expected.releaseProfileId ||
    parsed.releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    parsed.expectedGroupIdHash !== expected.expectedGroupIdHash ||
    parsed.conversationId !== expected.conversationId ||
    parsed.position !== expected.position ||
    parsed.envelopeId !== expected.envelopeId ||
    parsed.envelopeSha256 !== expected.envelopeSha256 ||
    parsed.expectedAccountId !== expected.expectedAccountId ||
    parsed.expectedInstallationId !== expected.expectedInstallationId ||
    parsed.expectedCredentialId !== expected.expectedCredentialId ||
    parsed.expectedCredentialFingerprint !==
      expected.expectedCredentialFingerprint ||
    parsed.expectedCredentialRevocationVersion !==
      expected.expectedCredentialRevocationVersion ||
    parsed.expectedSenderGeneration !== expected.expectedSenderGeneration ||
    parsed.authenticatedCredentialId !== expected.expectedCredentialId ||
    parsed.authenticatedCredentialFingerprint !==
      expected.expectedCredentialFingerprint ||
    parsed.authenticatedCredentialRevocationVersion !==
      expected.expectedCredentialRevocationVersion ||
    parsed.authenticatedSenderGeneration !== expected.expectedSenderGeneration ||
    parsed.commitEpoch !== expected.commitEpoch ||
    parsed.commitRosterVersion !== expected.commitRosterVersion ||
    parsed.previousEpoch !== expected.previousEpoch ||
    parsed.previousRosterVersion !== expected.previousRosterVersion ||
    parsed.previousConfirmedTranscriptHash !==
      expected.previousConfirmedTranscriptHash ||
    parsed.baseConfirmedTranscriptHash !==
      expected.baseConfirmedTranscriptHash ||
    parsed.resultingConfirmedTranscriptHash !==
      expected.resultingConfirmedTranscriptHash ||
    !sameStagedProposals(parsed.stagedProposals, expected.stagedProposals) ||
    !samePolicyMandatoryProposals(
      parsed.requiredProposals,
      expected.requiredProposals,
    ) ||
    !sameMlsMembershipTarget(
      parsed.creatorBootstrapTarget,
      expected.creatorBootstrapTarget,
    ) ||
    !sameMlsMembershipTarget(parsed.removalTarget, expected.removalTarget)
  ) {
    throw invalid("MLS Commit projection evidence was substituted.");
  }
  const expectedResultingEpoch = increment(
    parsed.previousEpoch,
    "Commit resulting epoch",
  );
  const expectedResultingRosterVersion =
    parsed.commitKind === "membership"
      ? increment(parsed.previousRosterVersion, "Commit resulting roster version")
      : parsed.previousRosterVersion;
  if (
    parsed.resultingEpoch !== expectedResultingEpoch ||
    parsed.resultingRosterVersion !== expectedResultingRosterVersion
  ) {
    throw invalid("MLS Commit projection has an invalid epoch or roster transition.");
  }
  const consumedIds = new Map(
    parsed.consumedProposals.map(({ proposalId, proposalHash }) => [
      proposalId,
      proposalHash,
    ]),
  );
  if (
    parsed.consumedProposals.some(
      (proposal) =>
        !parsed.stagedProposals.some(
          (staged) => sameStagedProposal(staged, proposal),
        ),
    ) ||
    parsed.requiredProposals.some(
      (proposal) => consumedIds.get(proposal.proposalId) !== proposal.proposalHash,
    )
  ) {
    throw invalid("MLS Commit did not consume the exact mandatory proposal set.");
  }
  const consumedRemoval = parsed.consumedProposals.find(
    ({ proposalId, proposalHash, proposalType }) =>
      proposalType === "remove" &&
      proposalId === parsed.removalProposalId &&
      proposalHash === parsed.removalProposalHash,
  );
  const everyConsumedProposalHasIntent = parsed.consumedProposals.every(
    (proposal) =>
      parsed.committedIntents.some(
        (intent) =>
          intent.membershipIntentId === proposal.membershipIntentId &&
          intent.membershipIntentHash === proposal.membershipIntentHash &&
          intent.membershipIntentEvidenceDigest ===
            proposal.membershipIntentEvidenceDigest &&
          intent.proposalId === proposal.proposalId &&
          intent.proposalHash === proposal.proposalHash &&
          intent.commitPosition === parsed.position &&
          intent.commitEnvelopeId === parsed.envelopeId &&
          intent.commitEnvelopeSha256 === parsed.envelopeSha256,
      ),
  );
  if (
    (parsed.commitKind === "update" &&
      (parsed.consumedProposals.length !== 0 ||
        parsed.creatorBootstrapTarget !== null ||
        parsed.removalTarget !== null)) ||
    (parsed.commitKind === "membership" &&
      parsed.consumedProposals.length === 0 &&
      parsed.creatorBootstrapTarget === null) ||
    (parsed.creatorBootstrapTarget === null) !==
      (parsed.creatorMembershipStatus === "not-applicable") ||
    (parsed.removalTarget === null) !==
      (parsed.removalMembershipStatus === "not-applicable") ||
    (parsed.removalTarget === null &&
      (parsed.removalProposalId !== null || parsed.removalProposalHash !== null)) ||
    (parsed.removalTarget !== null && !consumedRemoval) ||
    parsed.committedIntents.length !== parsed.consumedProposals.length ||
    !everyConsumedProposalHasIntent
  ) {
    throw invalid("MLS Commit membership target evidence is incomplete.");
  }
  if (
    parsed.evidenceDigest !==
    computeMlsCommitProjectionEvidenceDigest(parsed)
  ) {
    throw invalid("MLS Commit projection evidence digest is inconsistent.");
  }
  return parsed;
}

export function computeMlsCommitProjectionEvidenceDigest(input: {
  realmId: DeliveryRealmId;
  conversationGeneration: Uint63String;
  releaseProfileId: ReleaseProfileId;
  releaseTrustRootDigest: Hash32;
  expectedGroupIdHash: Hash32;
  conversationId: ConversationId;
  position: Uint63String;
  envelopeId: EnvelopeId;
  envelopeSha256: Hash32;
  expectedAccountId: AccountId;
  expectedInstallationId: InstallationId;
  expectedCredentialId: CredentialId;
  expectedCredentialFingerprint: Fingerprint32;
  expectedCredentialRevocationVersion: Uint63String;
  expectedSenderGeneration: Uint63String;
  authenticatedCredentialId: CredentialId;
  authenticatedCredentialFingerprint: Fingerprint32;
  authenticatedCredentialRevocationVersion: Uint63String;
  authenticatedSenderGeneration: Uint63String;
  senderBindingStatus: "verified";
  commitEpoch: Uint63String;
  commitRosterVersion: Uint63String;
  previousEpoch: Uint63String;
  previousRosterVersion: Uint63String;
  previousConfirmedTranscriptHash: Hash32;
  baseConfirmedTranscriptHash: Hash32;
  resultingConfirmedTranscriptHash: Hash32;
  commitKind: "membership" | "update";
  resultingEpoch: Uint63String;
  resultingRosterVersion: Uint63String;
  stagedProposals: readonly MlsStagedExternalProposalBinding[];
  requiredProposals: readonly PolicyMandatoryProposalBinding[];
  consumedProposals: readonly MlsStagedExternalProposalBinding[];
  committedIntents: readonly MlsCommittedIntentBinding[];
  proposalConsumptionStatus: "verified";
  intentBindingStatus: "verified";
  creatorBootstrapTarget: MlsMembershipTargetIdentity | null;
  creatorMembershipStatus: "verified-present" | "not-applicable";
  removalTarget: MlsMembershipTargetIdentity | null;
  removalProposalId: ProposalId | null;
  removalProposalHash: Hash32 | null;
  removalMembershipStatus: "verified-absent" | "not-applicable";
  projectionStatus: "verified";
}): Hash32 {
  return sha256Bytes(
    utf8(MLS_COMMIT_PROJECTION_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.releaseTrustRootDigest),
      decodeHash32(input.expectedGroupIdHash),
      utf8(input.conversationId),
      utf8(input.position),
      utf8(input.envelopeId),
      decodeHash32(input.envelopeSha256),
      utf8(input.expectedAccountId),
      utf8(input.expectedInstallationId),
      utf8(input.expectedCredentialId),
      decodeFingerprint32(input.expectedCredentialFingerprint),
      utf8(input.expectedCredentialRevocationVersion),
      utf8(input.expectedSenderGeneration),
      utf8(input.authenticatedCredentialId),
      decodeFingerprint32(input.authenticatedCredentialFingerprint),
      utf8(input.authenticatedCredentialRevocationVersion),
      utf8(input.authenticatedSenderGeneration),
      utf8(input.senderBindingStatus),
      utf8(input.commitEpoch),
      utf8(input.commitRosterVersion),
      utf8(input.previousEpoch),
      utf8(input.previousRosterVersion),
      decodeHash32(input.previousConfirmedTranscriptHash),
      decodeHash32(input.baseConfirmedTranscriptHash),
      decodeHash32(input.resultingConfirmedTranscriptHash),
      utf8(input.commitKind),
      utf8(input.resultingEpoch),
      utf8(input.resultingRosterVersion),
      ...encodeStagedProposals(input.stagedProposals),
      ...encodePolicyMandatoryProposals(input.requiredProposals),
      ...encodeStagedProposals(input.consumedProposals),
      ...encodeCommittedIntents(input.committedIntents),
      utf8(input.proposalConsumptionStatus),
      utf8(input.intentBindingStatus),
      ...encodeMlsMembershipTarget(input.creatorBootstrapTarget),
      utf8(input.creatorMembershipStatus),
      ...encodeMlsMembershipTarget(input.removalTarget),
      encodeNullableUtf8(input.removalProposalId),
      encodeNullableHash32(input.removalProposalHash),
      utf8(input.removalMembershipStatus),
      utf8(input.projectionStatus),
    ),
  );
}

export function parseConversationLogHeadProofEvidence(
  value: unknown,
  expected: ConversationLogHeadProofVerificationRequest,
): ConversationLogHeadProofEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "accountId",
      "installationId",
      "conversationId",
      "conversationGeneration",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "verifiedPrefixEvidenceDigest",
      "membershipBootstrapMode",
      "membershipCredentialId",
      "membershipCredentialFingerprint",
      "membershipJoinedPosition",
      "membershipRemovedPosition",
      "visibilityStatus",
      "fromPosition",
      "fromHeadHash",
      "currentPosition",
      "currentHeadHash",
      "appendOnlyConsistencyStatus",
      "appendOnlyConsistencyEvidenceDigest",
      "checkpoint",
      "witness",
      "verifiedAt",
      "evidenceDigest",
    ],
    "conversation log-head proof evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "conversation-log-head-proof.v1"
  ) {
    throw invalid("Conversation log-head proof was not verified.");
  }
  const parsedBase = {
    profile: "conversation-log-head-proof.v1" as const,
    realmId: parseDeliveryRealmId(record.realmId),
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    conversationId: parseConversationId(record.conversationId),
    conversationGeneration: parsePositive(
      record.conversationGeneration,
      "log-head proof generation",
    ),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    releaseTrustRootDigest: parseHash32(
      record.releaseTrustRootDigest,
      "log-head proof trust-root digest",
    ),
    verifiedPrefixEvidenceDigest: parseNonZeroHash32(
      record.verifiedPrefixEvidenceDigest,
      "log-head proof verified-prefix digest",
    ),
    membershipBootstrapMode: parseOneOfString(
      record.membershipBootstrapMode,
      ["creator", "welcome"] as const,
      "log-head proof membership bootstrap mode",
    ),
    membershipCredentialId: parseCredentialId(
      record.membershipCredentialId,
    ),
    membershipCredentialFingerprint: parseFingerprint32(
      record.membershipCredentialFingerprint,
    ),
    membershipJoinedPosition: parsePositive(
      record.membershipJoinedPosition,
      "log-head proof membership joined position",
    ),
    membershipRemovedPosition:
      record.membershipRemovedPosition === null
        ? null
        : parsePositive(
            record.membershipRemovedPosition,
            "log-head proof membership removed position",
          ),
    visibilityStatus: parseOneOfString(
      record.visibilityStatus,
      ["active-high-water", "removed-exact"] as const,
      "log-head proof visibility status",
    ),
    fromPosition: parseUint63String(
      record.fromPosition,
      "log-head proof from position",
    ),
    fromHeadHash: parseHash32(
      record.fromHeadHash,
      "log-head proof from hash",
    ),
    currentPosition: parsePositive(
      record.currentPosition,
      "log-head proof current position",
    ),
    currentHeadHash: parseHash32(
      record.currentHeadHash,
      "log-head proof current hash",
    ),
    appendOnlyConsistencyStatus: parseExactLiteral(
      record.appendOnlyConsistencyStatus,
      "verified",
      "log-head append-only consistency status",
    ),
    appendOnlyConsistencyEvidenceDigest: parseHash32(
      record.appendOnlyConsistencyEvidenceDigest,
      "log-head append-only consistency evidence digest",
    ),
    verifiedAt: parseRfc3339Millis(
      record.verifiedAt,
      "log-head proof verification time",
    ),
  };
  if (
    parsedBase.realmId !== expected.realmId ||
    parsedBase.accountId !== expected.accountId ||
    parsedBase.installationId !== expected.installationId ||
    parsedBase.conversationId !== expected.conversationId ||
    parsedBase.conversationGeneration !== expected.conversationGeneration ||
    parsedBase.releaseProfileId !== expected.releaseProfileId ||
    parsedBase.releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    parsedBase.verifiedPrefixEvidenceDigest !==
      expected.verifiedPrefixEvidenceDigest ||
    parsedBase.membershipBootstrapMode !== expected.membershipBootstrapMode ||
    parsedBase.membershipCredentialId !== expected.membershipCredentialId ||
    parsedBase.membershipCredentialFingerprint !==
      expected.membershipCredentialFingerprint ||
    parsedBase.membershipJoinedPosition !== expected.membershipJoinedPosition ||
    parsedBase.membershipRemovedPosition !==
      expected.membershipRemovedPosition ||
    parsedBase.visibilityStatus !==
      (expected.visibilityMode === "active-high-water"
        ? "active-high-water"
        : "removed-exact") ||
    parsedBase.fromPosition !== expected.fromPosition ||
    parsedBase.fromHeadHash !== expected.fromHeadHash ||
    parsedBase.currentPosition !== expected.current.position ||
    parsedBase.currentHeadHash !== expected.current.headHash ||
    parsedBase.verifiedAt !== expected.verifiedAt
  ) {
    throw invalid("Conversation log-head proof evidence was substituted.");
  }
  const checkpoint = parseCheckpointProofEvidence(
    record.checkpoint,
    expected.current,
    expected.conversationId,
    expected.verifiedAt,
  );
  const witness = parseWitnessProofEvidence(
    record.witness,
    expected.witness,
    expected.priorWitness,
    "continuity",
    expected.conversationId,
    expected.verifiedAt,
  );
  const evidenceDigest = parseHash32(
    record.evidenceDigest,
    "conversation log-head proof evidence digest",
  );
  const parsed: ConversationLogHeadProofEvidence = Object.freeze({
    ...parsedBase,
    checkpoint,
    witness,
    evidenceDigest,
  });
  if (
    evidenceDigest !== computeConversationLogHeadProofEvidenceDigest(parsed)
  ) {
    throw invalid("Conversation log-head proof digest is inconsistent.");
  }
  return parsed;
}

export function computeConversationLogHeadProofEvidenceDigest(
  input: Omit<ConversationLogHeadProofEvidence, "profile" | "evidenceDigest">,
): Hash32 {
  return sha256Bytes(
    utf8(CONVERSATION_LOG_HEAD_PROOF_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.realmId),
      utf8(input.accountId),
      utf8(input.installationId),
      utf8(input.conversationId),
      utf8(input.conversationGeneration),
      utf8(input.releaseProfileId),
      decodeHash32(input.releaseTrustRootDigest),
      decodeHash32(input.verifiedPrefixEvidenceDigest),
      utf8(input.membershipBootstrapMode),
      utf8(input.membershipCredentialId),
      decodeFingerprint32(input.membershipCredentialFingerprint),
      utf8(input.membershipJoinedPosition),
      encodeNullableUtf8(input.membershipRemovedPosition),
      utf8(input.visibilityStatus),
      utf8(input.fromPosition),
      decodeHash32(input.fromHeadHash),
      utf8(input.currentPosition),
      decodeHash32(input.currentHeadHash),
      utf8(input.appendOnlyConsistencyStatus),
      decodeHash32(input.appendOnlyConsistencyEvidenceDigest),
      decodeHash32(input.checkpoint.evidenceDigest),
      decodeHash32(input.witness.evidenceDigest),
      utf8(input.verifiedAt),
    ),
  );
}

export function parseConversationPageProofEvidence(
  value: unknown,
  expected: ConversationPageProofVerificationRequest,
): ConversationPageProofEvidence {
  const record = expectExactRecord(
    value,
    [
      "status",
      "profile",
      "realmId",
      "conversationId",
      "conversationGeneration",
      "releaseProfileId",
      "releaseTrustRootDigest",
      "verifiedAt",
      "checkpoints",
      "witness",
      "targetWelcome",
      "bundleEvidenceDigest",
    ],
    "conversation page proof evidence",
  );
  if (
    record.status !== "verified" ||
    record.profile !== "conversation-page-proof-bundle.v1"
  ) {
    throw invalid("Conversation page proof bundle was not verified.");
  }
  const conversationId = parseConversationId(record.conversationId);
  const realmId = parseDeliveryRealmId(record.realmId);
  const conversationGeneration = parsePositive(
    record.conversationGeneration,
    "proof conversation generation",
  );
  const releaseProfileId = parseReleaseProfileId(record.releaseProfileId);
  const releaseTrustRootDigest = parseHash32(
    record.releaseTrustRootDigest,
    "proof release trust-root digest",
  );
  const verifiedAt = parseRfc3339Millis(record.verifiedAt, "proof verifiedAt");
  if (
    realmId !== expected.realmId ||
    conversationId !== expected.conversationId ||
    conversationGeneration !== expected.conversationGeneration ||
    releaseProfileId !== expected.releaseProfileId ||
    releaseTrustRootDigest !== expected.releaseTrustRootDigest ||
    verifiedAt !== expected.verifiedAt
  ) {
    throw invalid("Conversation page proof bundle is detached from its request.");
  }
  const rawCheckpoints = expectDenseArray(
    record.checkpoints,
    expected.checkpoints.length,
    "checkpoint proof evidence",
  );
  if (rawCheckpoints.length !== expected.checkpoints.length) {
    throw invalid("Checkpoint proof evidence is incomplete.");
  }
  const checkpoints = rawCheckpoints.map((entry, index) =>
    parseCheckpointProofEvidence(
      entry,
      expected.checkpoints[index]!,
      conversationId,
      verifiedAt,
    ),
  );
  const witness = parseWitnessProofEvidence(
    record.witness,
    expected.witness,
    expected.priorWitness,
    expected.witnessTrustMode,
    conversationId,
    verifiedAt,
  );
  const targetWelcome = parseTargetWelcomeProofEvidence(
    record.targetWelcome,
    expected.targetWelcome,
    conversationId,
  );
  const bundleEvidenceDigest = parseHash32(
    record.bundleEvidenceDigest,
    "proof bundle evidence digest",
  );
  if (
    bundleEvidenceDigest !==
    computeConversationPageProofBundleEvidenceDigest({
      realmId,
      conversationId,
      conversationGeneration,
      releaseProfileId,
      releaseTrustRootDigest,
      verifiedAt,
      checkpointEvidenceDigests: checkpoints.map(({ evidenceDigest }) =>
        evidenceDigest
      ),
      witnessEvidenceDigest: witness.evidenceDigest,
      targetWelcomeEvidenceDigest: targetWelcome?.evidenceDigest ?? null,
    })
  ) {
    throw invalid("Conversation page proof bundle evidence digest is inconsistent.");
  }
  return Object.freeze({
    profile: "conversation-page-proof-bundle.v1",
    realmId,
    conversationId,
    conversationGeneration,
    releaseProfileId,
    releaseTrustRootDigest,
    verifiedAt,
    checkpoints: Object.freeze(checkpoints),
    witness,
    targetWelcome,
    bundleEvidenceDigest,
  });
}

function parseTargetWelcomeProofEvidence(
  value: unknown,
  expected: ConversationPageProofVerificationRequest["targetWelcome"],
  conversationId: ConversationId,
): TargetWelcomeProofEvidence | null {
  if (expected === null) {
    if (value !== null) {
      throw invalid("Unexpected target Welcome proof evidence was returned.");
    }
    return null;
  }
  const record = expectExactRecord(
    value,
    [
      "releaseProfileId",
      "expectedGroupIdHash",
      "commitEpoch",
      "commitPosition",
      "commitEnvelopeId",
      "commitEnvelopeSha256",
      "targetAccountId",
      "targetInstallationId",
      "targetCredentialId",
      "targetCredentialFingerprint",
      "welcomeSha256",
      "addCommitStatus",
      "membershipStatus",
      "resultingRosterMembershipStatus",
      "mailboxBindingStatus",
      "evidenceDigest",
    ],
    "target Welcome proof evidence",
  );
  const parsed: TargetWelcomeProofEvidence = Object.freeze({
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    expectedGroupIdHash: parseHash32(
      record.expectedGroupIdHash,
      "Welcome proof expected group ID hash",
    ),
    commitEpoch: parseUint63String(
      record.commitEpoch,
      "Welcome proof Commit epoch",
    ),
    commitPosition: parsePositive(
      record.commitPosition,
      "Welcome proof Commit position",
    ),
    commitEnvelopeId: parseEnvelopeId(record.commitEnvelopeId),
    commitEnvelopeSha256: parseHash32(
      record.commitEnvelopeSha256,
      "Welcome proof Commit SHA-256",
    ),
    targetAccountId: parseAccountId(record.targetAccountId),
    targetInstallationId: parseInstallationId(record.targetInstallationId),
    targetCredentialId: parseCredentialId(record.targetCredentialId),
    targetCredentialFingerprint: parseFingerprint32(
      record.targetCredentialFingerprint,
    ),
    welcomeSha256: parseHash32(
      record.welcomeSha256,
      "Welcome proof SHA-256",
    ),
    addCommitStatus: parseExactLiteral(
      record.addCommitStatus,
      "verified",
      "Welcome Add Commit status",
    ),
    membershipStatus: parseExactLiteral(
      record.membershipStatus,
      "verified",
      "Welcome membership status",
    ),
    resultingRosterMembershipStatus: parseExactLiteral(
      record.resultingRosterMembershipStatus,
      "verified-present",
      "Welcome resulting-roster membership status",
    ),
    mailboxBindingStatus: parseExactLiteral(
      record.mailboxBindingStatus,
      "verified",
      "Welcome mailbox binding status",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "Welcome proof evidence digest",
    ),
  });
  if (
    parsed.releaseProfileId !== expected.releaseProfileId ||
    parsed.expectedGroupIdHash !== expected.expectedGroupIdHash ||
    parsed.commitEpoch !== expected.commitEpoch ||
    parsed.commitPosition !== expected.commitPosition ||
    parsed.commitEnvelopeId !== expected.commitEnvelopeId ||
    parsed.commitEnvelopeSha256 !== expected.commitEnvelopeSha256 ||
    parsed.targetAccountId !== expected.targetAccountId ||
    parsed.targetInstallationId !== expected.targetInstallationId ||
    parsed.targetCredentialId !== expected.targetCredentialId ||
    parsed.targetCredentialFingerprint !== expected.targetCredentialFingerprint ||
    parsed.welcomeSha256 !== expected.welcomeSha256
  ) {
    throw invalid("Target Welcome proof evidence was substituted.");
  }
  if (
    parsed.evidenceDigest !==
    computeTargetWelcomeProofEvidenceDigest({ conversationId, ...parsed })
  ) {
    throw invalid("Target Welcome proof evidence digest is inconsistent.");
  }
  return parsed;
}

export function computeTargetWelcomeProofEvidenceDigest(input: {
  conversationId: ConversationId;
  releaseProfileId: ReleaseProfileId;
  expectedGroupIdHash: Hash32;
  commitEpoch: Uint63String;
  commitPosition: Uint63String;
  commitEnvelopeId: EnvelopeId;
  commitEnvelopeSha256: Hash32;
  targetAccountId: AccountId;
  targetInstallationId: InstallationId;
  targetCredentialId: CredentialId;
  targetCredentialFingerprint: Fingerprint32;
  welcomeSha256: Hash32;
  addCommitStatus: "verified";
  membershipStatus: "verified";
  resultingRosterMembershipStatus: "verified-present";
  mailboxBindingStatus: "verified";
}): Hash32 {
  return sha256Bytes(
    utf8(TARGET_WELCOME_PROOF_EVIDENCE_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(input.conversationId),
      utf8(input.releaseProfileId),
      decodeHash32(input.expectedGroupIdHash),
      utf8(input.commitEpoch),
      utf8(input.commitPosition),
      utf8(input.commitEnvelopeId),
      decodeHash32(input.commitEnvelopeSha256),
      utf8(input.targetAccountId),
      utf8(input.targetInstallationId),
      utf8(input.targetCredentialId),
      decodeFingerprint32(input.targetCredentialFingerprint),
      decodeHash32(input.welcomeSha256),
      utf8(input.addCommitStatus),
      utf8(input.membershipStatus),
      utf8(input.resultingRosterMembershipStatus),
      utf8(input.mailboxBindingStatus),
    ),
  );
}

function parseCheckpointProofEvidence(
  value: unknown,
  expected: DeliveryCheckpointProofInput,
  conversationId: ConversationId,
  verifiedAt: Rfc3339Millis,
): DeliveryCheckpointProofEvidence {
  const record = expectExactRecord(
    value,
    [
      "position",
      "previousHeadHash",
      "headHash",
      "signingKeyId",
      "checkpointDigest",
      "signatureSha256",
      "checkpointReceivedAt",
      "signatureStatus",
      "keyStatus",
      "evidenceDigest",
    ],
    "delivery checkpoint proof evidence",
  );
  const parsed: DeliveryCheckpointProofEvidence = Object.freeze({
    position: parsePositive(record.position, "proof checkpoint position"),
    previousHeadHash: parseHash32(
      record.previousHeadHash,
      "proof checkpoint predecessor",
    ),
    headHash: parseHash32(record.headHash, "proof checkpoint head"),
    signingKeyId: parseSigningKeyId(record.signingKeyId),
    checkpointDigest: parseHash32(
      record.checkpointDigest,
      "proof checkpoint digest",
    ),
    signatureSha256: parseHash32(
      record.signatureSha256,
      "proof signature SHA-256",
    ),
    checkpointReceivedAt: parseRfc3339Millis(
      record.checkpointReceivedAt,
      "proof checkpoint receivedAt",
    ),
    signatureStatus: parseExactLiteral(
      record.signatureStatus,
      "verified",
      "checkpoint signature status",
    ),
    keyStatus: parseExactLiteral(
      record.keyStatus,
      "valid-for-checkpoint",
      "checkpoint key status",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "checkpoint proof evidence digest",
    ),
  });
  if (
    parsed.position !== expected.position ||
    parsed.previousHeadHash !== expected.previousHeadHash ||
    parsed.headHash !== expected.headHash ||
    parsed.signingKeyId !== expected.signingKeyId ||
    parsed.checkpointDigest !== expected.checkpointDigest ||
    parsed.signatureSha256 !== hashSignature(expected.signature)
    || parsed.checkpointReceivedAt !== expected.checkpointReceivedAt
  ) {
    throw invalid("Delivery checkpoint proof evidence was substituted.");
  }
  if (
    parsed.evidenceDigest !==
    computeDeliveryCheckpointProofEvidenceDigest({
      conversationId,
      verifiedAt,
      ...parsed,
    })
  ) {
    throw invalid("Delivery checkpoint proof evidence digest is inconsistent.");
  }
  return parsed;
}

function parseWitnessProofEvidence(
  value: unknown,
  expected: ConversationPageProofVerificationRequest["witness"],
  priorWitness: ConversationPageProofVerificationRequest["priorWitness"],
  witnessTrustMode: ConversationPageProofVerificationRequest["witnessTrustMode"],
  conversationId: ConversationId,
  verifiedAt: Rfc3339Millis,
): DeliveryWitnessProofEvidence {
  const record = expectExactRecord(
    value,
    [
      "position",
      "headHash",
      "witnessCheckpointId",
      "witnessTreeSize",
      "witnessRootHash",
      "witnessKeyId",
      "witnessSignatureSha256",
      "witnessedAt",
      "priorWitnessCheckpointId",
      "priorWitnessTreeSize",
      "priorWitnessRootHash",
      "signatureStatus",
      "keyStatus",
      "inclusionStatus",
      "consistencyStatus",
      "freshnessStatus",
      "evidenceDigest",
    ],
    "delivery witness proof evidence",
  );
  const parsed: DeliveryWitnessProofEvidence = Object.freeze({
    position: parsePositive(record.position, "proof witnessed position"),
    headHash: parseHash32(record.headHash, "proof witnessed head"),
    witnessCheckpointId: parseWitnessCheckpointId(record.witnessCheckpointId),
    witnessTreeSize: parseUint63String(
      record.witnessTreeSize,
      "proof witness tree size",
    ),
    witnessRootHash: parseHash32(
      record.witnessRootHash,
      "proof witness root hash",
    ),
    witnessKeyId: parseSigningKeyId(record.witnessKeyId),
    witnessSignatureSha256: parseHash32(
      record.witnessSignatureSha256,
      "witness signature SHA-256",
    ),
    witnessedAt: parseRfc3339Millis(
      record.witnessedAt,
      "proof witnessedAt",
    ),
    priorWitnessCheckpointId:
      record.priorWitnessCheckpointId === null
        ? null
        : parseWitnessCheckpointId(record.priorWitnessCheckpointId),
    priorWitnessTreeSize:
      record.priorWitnessTreeSize === null
        ? null
        : parseUint63String(record.priorWitnessTreeSize, "prior witness tree size"),
    priorWitnessRootHash:
      record.priorWitnessRootHash === null
        ? null
        : parseHash32(record.priorWitnessRootHash, "prior witness root hash"),
    signatureStatus: parseExactLiteral(
      record.signatureStatus,
      "verified",
      "witness signature status",
    ),
    keyStatus: parseExactLiteral(
      record.keyStatus,
      "valid-for-checkpoint",
      "witness key status",
    ),
    inclusionStatus: parseExactLiteral(
      record.inclusionStatus,
      "verified",
      "witness inclusion status",
    ),
    consistencyStatus: parseOneOfString(
      record.consistencyStatus,
      ["verified", "bootstrap"] as const,
      "witness consistency status",
    ),
    freshnessStatus: parseExactLiteral(
      record.freshnessStatus,
      "fresh",
      "witness freshness status",
    ),
    evidenceDigest: parseHash32(
      record.evidenceDigest,
      "witness proof evidence digest",
    ),
  });
  if (
    parsed.position !== expected.position ||
    parsed.headHash !== expected.headHash ||
    parsed.witnessCheckpointId !== expected.witnessCheckpointId ||
    parsed.witnessTreeSize !== expected.witnessTreeSize ||
    parsed.witnessRootHash !== expected.witnessRootHash ||
    parsed.witnessKeyId !== expected.witnessKeyId ||
    parsed.witnessedAt !== expected.witnessedAt ||
    parsed.witnessSignatureSha256 !== hashSignature(expected.witnessSignature) ||
    parsed.priorWitnessCheckpointId !==
      (priorWitness?.witnessCheckpointId ?? null) ||
    parsed.priorWitnessTreeSize !== (priorWitness?.witnessTreeSize ?? null) ||
    parsed.priorWitnessRootHash !== (priorWitness?.witnessRootHash ?? null) ||
    parsed.consistencyStatus !== "verified"
  ) {
    throw invalid("Delivery witness proof evidence was substituted.");
  }
  if (
    priorWitness !== null &&
    (BigInt(parsed.witnessTreeSize) < BigInt(priorWitness.witnessTreeSize) ||
      parsed.witnessedAt < priorWitness.witnessedAt ||
      (parsed.witnessTreeSize === priorWitness.witnessTreeSize &&
        parsed.witnessRootHash !== priorWitness.witnessRootHash))
  ) {
    throw invalid("Delivery witness consistency proof rolls back or equivocates.");
  }
  if (
    parsed.evidenceDigest !==
    computeDeliveryWitnessProofEvidenceDigest({
      conversationId,
      verifiedAt,
      ...parsed,
    })
  ) {
    throw invalid("Delivery witness proof evidence digest is inconsistent.");
  }
  return parsed;
}

function parseConversationEventItem(
  value: unknown,
  targetInstallationId: InstallationId,
  limits: DeliveryLimits,
): ConversationEventItem {
  const envelopeClass = readDataField(value, "envelopeClass", "conversation event");
  const hasWelcome = hasOwnDataField(value, "welcome");
  if (envelopeClass !== "mls_commit" && hasWelcome) {
    throw invalid("Only an MLS Commit may be augmented with a Welcome.");
  }
  const expectedKeys =
    envelopeClass === "mls_commit"
      ? hasWelcome
        ? [...STORED_COMMIT_KEYS, "welcome"]
        : STORED_COMMIT_KEYS
      : STORED_ENVELOPE_COMMON_KEYS;
  const record = expectExactRecord(value, expectedKeys, "conversation event");
  const envelopeRecord = copyRecordWithout(record, "welcome");
  const envelope = parseStoredEnvelope(envelopeRecord);
  decodedEnvelopeLength(envelope, limits);
  const welcome = hasWelcome
    ? parseTargetWelcome(record.welcome, targetInstallationId, limits)
    : null;
  if (welcome !== null && envelope.envelopeClass !== "mls_commit") {
    throw invalid("Welcome augmentation is detached from an MLS Commit.");
  }
  return Object.freeze({ envelope, welcome });
}

function parseTargetWelcome(
  value: unknown,
  expectedInstallationId: InstallationId,
  limits: DeliveryLimits,
): TargetWelcome {
  const record = expectExactRecord(
    value,
    ["targetInstallationId", "welcome", "welcomeSha256"],
    "target Welcome",
  );
  const targetInstallationId = parseInstallationId(record.targetInstallationId);
  if (targetInstallationId !== expectedInstallationId) {
    throw invalid("Welcome is addressed to another installation.");
  }
  const configuredMaximum = Number(limits.welcomeDecodedMaxBytes);
  if (configuredMaximum === 0) {
    throw invalid("Welcome artifacts are disabled by the archived release profile.");
  }
  const maximum = minimum(
    configuredMaximum,
    CONVERSATION_WELCOME_HARD_MAX_BYTES,
  );
  const welcomeBytes = parseCanonicalBase64UrlBytes(record.welcome, "Welcome", {
    minBytes: 1,
    maxBytes: maximum,
  });
  const welcomeSha256 = parseHash32(record.welcomeSha256, "Welcome SHA-256");
  if (computeEnvelopeSha256(welcomeBytes) !== welcomeSha256) {
    throw invalid("Welcome SHA-256 does not match the exact Welcome bytes.");
  }
  return Object.freeze({
    targetInstallationId,
    welcome: parseCanonicalBase64Url(record.welcome, "Welcome", {
      minBytes: 1,
      maxBytes: maximum,
    }),
    welcomeSha256,
  });
}

function verifyStoredEnvelopeHashes(envelope: StoredEnvelope): void {
  const leafHash = computeEnvelopeLeafHash({
    conversationId: envelope.conversationId,
    position: envelope.position,
    envelopeId: envelope.envelopeId,
    envelopeClass: envelope.envelopeClass,
    sender: envelope.sender,
    epoch: envelope.epoch,
    rosterVersion: envelope.rosterVersion,
    contentType: envelope.contentType,
    envelopeSha256: envelope.envelopeSha256,
    receivedAt: envelope.receivedAt,
  });
  if (leafHash !== envelope.leafHash) {
    throw invalid("Envelope leaf hash does not match its canonical fields.");
  }
  if (computeLogHeadHash(envelope.previousHeadHash, leafHash) !== envelope.headHash) {
    throw invalid("Envelope log head does not match its predecessor and leaf.");
  }
  const checkpointDigest = computeDeliveryLogCheckpointDigest({
    conversationId: envelope.conversationId,
    position: envelope.position,
    previousHeadHash: envelope.previousHeadHash,
    headHash: envelope.headHash,
    signingKeyId: envelope.logSigningKeyId,
  });
  if (checkpointDigest !== envelope.logCheckpointDigest) {
    throw invalid("Envelope checkpoint digest does not match its signed tuple.");
  }
}

function decodedEnvelopeLength(
  envelope: StoredEnvelope,
  limits: DeliveryLimits,
): number {
  const hardMaximum =
    envelope.envelopeClass === "application"
      ? MAX_APPLICATION_ENVELOPE_BYTES
      : envelope.envelopeClass === "external_proposal"
        ? MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES
        : MAX_MLS_COMMIT_ENVELOPE_BYTES;
  const configuredMaximum = Number(
    envelope.envelopeClass === "application"
      ? limits.applicationCiphertextDecodedMaxBytes
      : envelope.envelopeClass === "external_proposal"
        ? limits.externalProposalDecodedMaxBytes
        : limits.mlsCommitDecodedMaxBytes,
  );
  if (configuredMaximum === 0) {
    throw invalid(
      `${envelope.envelopeClass} artifacts are disabled by the archived release profile.`,
    );
  }
  const maxBytes = minimum(configuredMaximum, hardMaximum);
  return parseCanonicalBase64UrlBytes(envelope.envelopeBytes, "envelope bytes", {
    minBytes: 1,
    maxBytes,
  }).byteLength;
}

function parseConversationPageSnapshot(value: unknown): ConversationPageSnapshot {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "generation",
      "releaseProfileId",
      "deliveryLimitsDigest",
      "etag",
      "epoch",
      "rosterVersion",
      "confirmedTranscriptHash",
      "policyHeadId",
      "policyRevision",
      "policyMandatoryProposalCount",
      "policyMandatoryProposalSetHash",
      "policyMandatoryProposals",
      "policyAuthorizedSendGrantSetHash",
      "policyAuthorizedQuotaPolicyDigest",
      "policyHeadSequence",
      "policyHeadHash",
      "policyDeliveryLogPosition",
      "policyDeliveryLogHeadHash",
      "policyWitnessCheckpointId",
      "policyWitnessEvidenceDigest",
      "logHead",
      "witnessReceipt",
    ],
    "conversation page snapshot",
  );
  const epoch = parseUint63String(record.epoch, "snapshot epoch");
  const rosterVersion = parseUint63String(
    record.rosterVersion,
    "snapshot roster version",
  );
  const etag = parseConversationEtag(record.etag, "snapshot ETag");
  if (etag !== `"e${epoch}-r${rosterVersion}"`) {
    throw invalid("Snapshot ETag does not match its epoch and roster version.");
  }
  const conversationId = parseConversationId(record.conversationId);
  const logHead = parseSignedDeliveryLogHead(record.logHead, conversationId);
  const policyDeliveryLogPosition = parseUint63String(
    record.policyDeliveryLogPosition,
    "snapshot policy delivery-log position",
  );
  const policyDeliveryLogHeadHash = parseHash32(
    record.policyDeliveryLogHeadHash,
    "snapshot policy delivery-log head hash",
  );
  if (
    BigInt(policyDeliveryLogPosition) > BigInt(logHead.position) ||
    (policyDeliveryLogPosition === "0") !==
      (policyDeliveryLogHeadHash === ZERO_HASH32) ||
    (policyDeliveryLogPosition === logHead.position &&
      policyDeliveryLogHeadHash !== logHead.headHash)
  ) {
    throw invalid("Snapshot policy projection has an invalid delivery-log anchor.");
  }
  const witnessReceipt = parseWitnessReceipt(record.witnessReceipt);
  if (
    witnessReceipt.conversationId !== conversationId ||
    witnessReceipt.position !== logHead.position ||
    witnessReceipt.headHash !== logHead.headHash
  ) {
    throw invalid("Snapshot witness receipt must bind the exact page checkpoint.");
  }
  const policyMandatoryProposalCount = parseUint63String(
    record.policyMandatoryProposalCount,
    "snapshot mandatory proposal count",
  );
  const policyMandatoryProposalSetHash = parseHash32(
    record.policyMandatoryProposalSetHash,
    "snapshot mandatory proposal set hash",
  );
  const policyMandatoryProposals = parsePolicyMandatoryProposals(
    record.policyMandatoryProposals,
    "snapshot mandatory proposals",
  );
  validatePolicyMandatoryProposalProjection({
    count: policyMandatoryProposalCount,
    setHash: policyMandatoryProposalSetHash,
    proposals: policyMandatoryProposals,
  });
  return Object.freeze({
    conversationId,
    generation: parsePositive(record.generation, "snapshot generation"),
    releaseProfileId: parseReleaseProfileId(record.releaseProfileId),
    deliveryLimitsDigest: parseHash32(
      record.deliveryLimitsDigest,
      "snapshot delivery limits digest",
    ),
    etag,
    epoch,
    rosterVersion,
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "snapshot confirmed transcript hash",
    ),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyRevision: parsePositive(
      record.policyRevision,
      "snapshot policy revision",
    ),
    policyMandatoryProposalCount,
    policyMandatoryProposalSetHash,
    policyMandatoryProposals,
    policyAuthorizedSendGrantSetHash: parseHash32(
      record.policyAuthorizedSendGrantSetHash,
      "snapshot authorized send-grant set hash",
    ),
    policyAuthorizedQuotaPolicyDigest: parseHash32(
      record.policyAuthorizedQuotaPolicyDigest,
      "snapshot authorized quota policy digest",
    ),
    policyHeadSequence: parsePositive(
      record.policyHeadSequence,
      "snapshot policy head sequence",
    ),
    policyHeadHash: parseNonZeroHash32(
      record.policyHeadHash,
      "snapshot policy head hash",
    ),
    policyDeliveryLogPosition,
    policyDeliveryLogHeadHash,
    policyWitnessCheckpointId: parseWitnessCheckpointId(
      record.policyWitnessCheckpointId,
    ),
    policyWitnessEvidenceDigest: parseHash32(
      record.policyWitnessEvidenceDigest,
      "policy projection witness evidence digest",
    ),
    logHead,
    witnessReceipt,
  });
}

function parseSignedDeliveryLogHead(
  value: unknown,
  conversationId: ConversationId,
): SignedDeliveryLogHead {
  const record = expectExactRecord(
    value,
    [
      "position",
      "previousHeadHash",
      "headHash",
      "signingKeyId",
      "checkpointDigest",
      "signature",
      "checkpointReceivedAt",
    ],
    "signed delivery log head",
  );
  const position = parsePositive(record.position, "signed log head position");
  const previousHeadHash = parseHash32(
    record.previousHeadHash,
    "signed log previous head hash",
  );
  const headHash = parseNonZeroHash32(record.headHash, "signed log head hash");
  const signingKeyId = parseSigningKeyId(record.signingKeyId);
  const checkpointDigest = parseHash32(
    record.checkpointDigest,
    "signed log checkpoint digest",
  );
  if (
    (position === "1") !== (previousHeadHash === ZERO_HASH32) ||
    computeDeliveryLogCheckpointDigest({
      conversationId,
      position,
      previousHeadHash,
      headHash,
      signingKeyId,
    }) !== checkpointDigest
  ) {
    throw invalid("Signed log checkpoint digest does not match its tuple.");
  }
  return Object.freeze({
    position,
    previousHeadHash,
    headHash,
    signingKeyId,
    checkpointDigest,
    signature: parseSignature(record.signature, "delivery log signature"),
    checkpointReceivedAt: parseRfc3339Millis(
      record.checkpointReceivedAt,
      "signed checkpoint receivedAt",
    ),
  });
}

function parseWitnessReceipt(value: unknown): DeliveryLogWitnessReceipt {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "position",
      "headHash",
      "witnessCheckpointId",
      "witnessTreeSize",
      "witnessRootHash",
      "witnessKeyId",
      "witnessSignature",
      "witnessedAt",
    ],
    "delivery log witness receipt",
  );
  return Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    position: parsePositive(record.position, "witnessed position"),
    headHash: parseNonZeroHash32(record.headHash, "witnessed head hash"),
    witnessCheckpointId: parseWitnessCheckpointId(record.witnessCheckpointId),
    witnessTreeSize: parseUint63String(record.witnessTreeSize, "witness tree size"),
    witnessRootHash: parseHash32(record.witnessRootHash, "witness root hash"),
    witnessKeyId: parseSigningKeyId(record.witnessKeyId, "witness key ID"),
    witnessSignature: parseSignature(record.witnessSignature, "witness signature"),
    witnessedAt: parseRfc3339Millis(record.witnessedAt, "witness time"),
  });
}

function parseWitnessConsistencyAnchor(
  value: unknown,
): DeliveryWitnessConsistencyAnchor {
  const record = expectExactRecord(
    value,
    ["witnessCheckpointId", "witnessTreeSize", "witnessRootHash", "witnessedAt"],
    "prior witness consistency anchor",
  );
  return Object.freeze({
    witnessCheckpointId: parseWitnessCheckpointId(record.witnessCheckpointId),
    witnessTreeSize: parseUint63String(
      record.witnessTreeSize,
      "prior witness tree size",
    ),
    witnessRootHash: parseHash32(
      record.witnessRootHash,
      "prior witness root hash",
    ),
    witnessedAt: parseRfc3339Millis(
      record.witnessedAt,
      "prior witness time",
    ),
  });
}

function parsePolicyConsistencyAnchor(
  value: unknown,
): ConversationPolicyConsistencyAnchor {
  const record = expectExactRecord(
    value,
    [
      "policyHeadSequence",
      "policyHeadHash",
      "witnessCheckpointId",
      "witnessEvidenceDigest",
    ],
    "trusted policy consistency anchor",
  );
  const parsed = Object.freeze({
    policyHeadSequence: parseUint63String(
      record.policyHeadSequence,
      "trusted policy-head sequence",
    ),
    policyHeadHash: parseHash32(
      record.policyHeadHash,
      "trusted policy-head hash",
    ),
    witnessCheckpointId: parseWitnessCheckpointId(record.witnessCheckpointId),
    witnessEvidenceDigest: parseHash32(
      record.witnessEvidenceDigest,
      "trusted policy witness evidence digest",
    ),
  });
  if (
    (parsed.policyHeadSequence === "0") !==
    (parsed.policyHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Trusted policy anchor has an invalid zero-sequence sentinel.");
  }
  return parsed;
}

function verifySnapshotHead(
  snapshot: ConversationPageSnapshot,
  anchor: ConversationHeadAnchor,
  events: readonly ConversationEventItem[],
): void {
  const heads = new Map<string, ConversationHeadAnchor>();
  heads.set(anchor.position, anchor);
  for (const { envelope } of events) {
    heads.set(envelope.position, {
      position: envelope.position,
      previousHeadHash: envelope.previousHeadHash,
      headHash: envelope.headHash,
      checkpointReceivedAt: envelope.receivedAt,
    });
  }
  const snapshotEntry = heads.get(snapshot.logHead.position);
  if (
    !snapshotEntry ||
    snapshotEntry.previousHeadHash !== snapshot.logHead.previousHeadHash ||
    snapshotEntry.headHash !== snapshot.logHead.headHash ||
    snapshotEntry.checkpointReceivedAt !== snapshot.logHead.checkpointReceivedAt
  ) {
    throw invalid("Snapshot signed head is not the verified page-prefix head.");
  }
  const witnessEntry = heads.get(snapshot.witnessReceipt.position);
  const witnessMatchesSnapshot =
    snapshot.witnessReceipt.position === snapshot.logHead.position &&
    snapshot.witnessReceipt.headHash === snapshot.logHead.headHash;
  if (
    (!witnessEntry || witnessEntry.headHash !== snapshot.witnessReceipt.headHash) &&
    !witnessMatchesSnapshot
  ) {
    throw invalid("Snapshot witness receipt is not bound to the verified prefix.");
  }
}

function parseMembershipWindow(value: unknown): ConversationMembershipWindow {
  const record = expectExactRecord(
    value,
    [
      "bootstrapMode",
      "credentialId",
      "credentialFingerprint",
      "joinedPosition",
      "removedPosition",
    ],
    "conversation membership window",
  );
  const joinedPosition = parsePositive(record.joinedPosition, "joined position");
  const removedPosition =
    record.removedPosition === null
      ? null
      : parsePositive(record.removedPosition, "removed position");
  if (removedPosition !== null && BigInt(removedPosition) < BigInt(joinedPosition)) {
    throw invalid("Removal position cannot precede join position.");
  }
  return Object.freeze({
    bootstrapMode: parseOneOfString(
      record.bootstrapMode,
      ["creator", "welcome"] as const,
      "membership bootstrap mode",
    ),
    credentialId: parseCredentialId(record.credentialId),
    credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
    joinedPosition,
    removedPosition,
  });
}

function parseHeadAnchor(value: unknown): ConversationHeadAnchor {
  const record = expectExactRecord(
    value,
    ["position", "previousHeadHash", "headHash", "checkpointReceivedAt"],
    "conversation head anchor",
  );
  return Object.freeze({
    position: parseUint63String(record.position, "anchor position"),
    previousHeadHash: parseHash32(record.previousHeadHash, "anchor previous hash"),
    headHash: parseHash32(record.headHash, "anchor head hash"),
    checkpointReceivedAt:
      record.checkpointReceivedAt === null
        ? null
        : parseRfc3339Millis(
            record.checkpointReceivedAt,
            "anchor checkpoint receivedAt",
          ),
  });
}

function validateAnchor(anchor: ConversationHeadAnchor): void {
  if (anchor.position === "0") {
    if (
      anchor.previousHeadHash !== ZERO_HASH32 ||
      anchor.headHash !== ZERO_HASH32 ||
      anchor.checkpointReceivedAt !== null
    ) {
      throw invalid("Position-zero anchor must use the zero log head.");
    }
    return;
  }
  if (anchor.headHash === ZERO_HASH32 || anchor.checkpointReceivedAt === null) {
    throw invalid("A nonzero anchor position cannot use the zero head.");
  }
  if (
    (anchor.position === "1") !==
    (anchor.previousHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Anchor position and predecessor zero sentinel disagree.");
  }
}

function parseSignature(value: unknown, label: string): Ed25519Signature {
  return parseEd25519Signature(value, label);
}

function hashSignature(value: Ed25519Signature): Hash32 {
  return computeEnvelopeSha256(
    parseCanonicalBase64UrlBytes(value, "proof signature", {
      minBytes: 64,
      maxBytes: 64,
    }),
  );
}

function parseExactLiteral<const Literal extends string>(
  value: unknown,
  expected: Literal,
  label: string,
): Literal {
  if (value !== expected) {
    throw invalid(`${label} must be ${expected}.`);
  }
  return expected;
}

function parseOneOfString<const Value extends string>(
  value: unknown,
  allowed: readonly Value[],
  label: string,
): Value {
  if (typeof value !== "string" || !allowed.includes(value as Value)) {
    throw invalid(`${label} is unsupported.`);
  }
  return value as Value;
}

function parseConversationMlsProjection(
  value: unknown,
): ConversationMlsProjection {
  const record = expectExactRecord(
    value,
    ["epoch", "rosterVersion", "confirmedTranscriptHash"],
    "conversation MLS projection anchor",
  );
  return Object.freeze({
    epoch: parseUint63String(record.epoch, "projection anchor epoch"),
    rosterVersion: parseUint63String(
      record.rosterVersion,
      "projection anchor roster version",
    ),
    confirmedTranscriptHash: parseHash32(
      record.confirmedTranscriptHash,
      "projection anchor confirmed transcript hash",
    ),
  });
}

function parseConversationPolicyProjection(
  value: unknown,
): ConversationPolicyProjection {
  const record = expectExactRecord(
    value,
    [
      "etag",
      "policyHeadId",
      "policyRevision",
      "policyMandatoryProposalCount",
      "policyMandatoryProposalSetHash",
      "policyMandatoryProposals",
      "policyAuthorizedSendGrantSetHash",
      "policyAuthorizedQuotaPolicyDigest",
      "policyHeadSequence",
      "policyHeadHash",
      "policyDeliveryLogPosition",
      "policyDeliveryLogHeadHash",
      "policyWitnessCheckpointId",
      "policyWitnessEvidenceDigest",
    ],
    "conversation policy projection anchor",
  );
  const policyDeliveryLogPosition = parseUint63String(
    record.policyDeliveryLogPosition,
    "policy projection delivery-log position",
  );
  const policyDeliveryLogHeadHash = parseHash32(
    record.policyDeliveryLogHeadHash,
    "policy projection delivery-log head hash",
  );
  if (
    (policyDeliveryLogPosition === "0") !==
    (policyDeliveryLogHeadHash === ZERO_HASH32)
  ) {
    throw invalid("Policy projection has an invalid delivery-log sentinel.");
  }
  const policyMandatoryProposalCount = parseUint63String(
    record.policyMandatoryProposalCount,
    "policy mandatory proposal count",
  );
  const policyMandatoryProposalSetHash = parseHash32(
    record.policyMandatoryProposalSetHash,
    "policy mandatory proposal set hash",
  );
  const policyMandatoryProposals = parsePolicyMandatoryProposals(
    record.policyMandatoryProposals,
    "policy mandatory proposals",
  );
  validatePolicyMandatoryProposalProjection({
    count: policyMandatoryProposalCount,
    setHash: policyMandatoryProposalSetHash,
    proposals: policyMandatoryProposals,
  });
  return Object.freeze({
    etag: parseConversationEtag(record.etag),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyRevision: parsePositive(record.policyRevision, "policy revision"),
    policyMandatoryProposalCount,
    policyMandatoryProposalSetHash,
    policyMandatoryProposals,
    policyAuthorizedSendGrantSetHash: parseHash32(
      record.policyAuthorizedSendGrantSetHash,
      "policy authorized send-grant set hash",
    ),
    policyAuthorizedQuotaPolicyDigest: parseHash32(
      record.policyAuthorizedQuotaPolicyDigest,
      "policy authorized quota policy digest",
    ),
    policyHeadSequence: parsePositive(
      record.policyHeadSequence,
      "policy projection head sequence",
    ),
    policyHeadHash: parseNonZeroHash32(
      record.policyHeadHash,
      "policy projection head hash",
    ),
    policyDeliveryLogPosition,
    policyDeliveryLogHeadHash,
    policyWitnessCheckpointId: parseWitnessCheckpointId(
      record.policyWitnessCheckpointId,
    ),
    policyWitnessEvidenceDigest: parseHash32(
      record.policyWitnessEvidenceDigest,
      "policy projection witness evidence digest",
    ),
  });
}

function parseMlsCommitSenderBindings(
  value: unknown,
): readonly ConversationMlsCommitSenderBinding[] {
  const entries = expectDenseArray(
    value,
    CONVERSATION_PAGE_HARD_MAX_EVENTS,
    "MLS Commit sender bindings",
  );
  const parsed = entries.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "accountId",
        "installationId",
        "credentialId",
        "credentialFingerprint",
        "credentialRevocationVersion",
        "senderGeneration",
        "activeFromPosition",
        "inactiveAtPosition",
      ],
      `MLS Commit sender binding ${index}`,
    );
    const activeFromPosition = parsePositive(
      record.activeFromPosition,
      "MLS sender active-from position",
    );
    const inactiveAtPosition =
      record.inactiveAtPosition === null
        ? null
        : parsePositive(
            record.inactiveAtPosition,
            "MLS sender inactive-at position",
          );
    if (
      inactiveAtPosition !== null &&
      BigInt(inactiveAtPosition) <= BigInt(activeFromPosition)
    ) {
      throw invalid("MLS sender binding has an empty validity range.");
    }
    return Object.freeze({
      accountId: parseAccountId(record.accountId),
      installationId: parseInstallationId(record.installationId),
      credentialId: parseCredentialId(record.credentialId),
      credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
      credentialRevocationVersion: parseUint63String(
        record.credentialRevocationVersion,
        "MLS sender credential revocation version",
      ),
      senderGeneration: parsePositive(
        record.senderGeneration,
        "MLS sender generation",
      ),
      activeFromPosition,
      inactiveAtPosition,
    });
  });
  for (let left = 0; left < parsed.length; left += 1) {
    for (let right = left + 1; right < parsed.length; right += 1) {
      const a = parsed[left]!;
      const b = parsed[right]!;
      if (
        a.accountId === b.accountId &&
        a.installationId === b.installationId &&
        BigInt(a.activeFromPosition) <
          (b.inactiveAtPosition === null
            ? 9_223_372_036_854_775_808n
            : BigInt(b.inactiveAtPosition)) &&
        BigInt(b.activeFromPosition) <
          (a.inactiveAtPosition === null
            ? 9_223_372_036_854_775_808n
            : BigInt(a.inactiveAtPosition))
      ) {
        throw invalid("MLS sender credential bindings overlap.");
      }
    }
  }
  return Object.freeze(parsed);
}

function parseStagedProposalBindings(
  value: unknown,
  label: string,
): readonly MlsStagedExternalProposalBinding[] {
  const entries = expectDenseArray(
    value,
    CONVERSATION_PAGE_HARD_MAX_EVENTS,
    label,
  );
  let previousPosition = 0n;
  const ids = new Set<string>();
  const hashes = new Set<string>();
  const envelopeIds = new Set<string>();
  const parsed = entries.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "position",
        "envelopeId",
        "envelopeSha256",
        "epoch",
        "proposalId",
        "proposalHash",
        "authorizationRecordHash",
        "membershipIntentId",
        "membershipIntentHash",
        "membershipIntentEvidenceDigest",
        "proposalType",
        "proposalRequirement",
        "authorizingPolicyHeadSequence",
        "authorizingPolicyHeadHash",
      ],
      `${label} ${index}`,
    );
    const proposal = Object.freeze({
      position: parsePositive(record.position, `${label} position`),
      envelopeId: parseEnvelopeId(record.envelopeId),
      envelopeSha256: parseHash32(
        record.envelopeSha256,
        `${label} envelope SHA-256`,
      ),
      epoch: parseUint63String(record.epoch, `${label} epoch`),
      proposalId: parseProposalId(record.proposalId),
      proposalHash: parseHash32(record.proposalHash, `${label} proposal hash`),
      authorizationRecordHash: parseHash32(
        record.authorizationRecordHash,
        `${label} authorization-record hash`,
      ),
      membershipIntentId: parseMembershipIntentId(record.membershipIntentId),
      membershipIntentHash: parseHash32(
        record.membershipIntentHash,
        `${label} membership-intent hash`,
      ),
      membershipIntentEvidenceDigest: parseHash32(
        record.membershipIntentEvidenceDigest,
        `${label} membership-intent evidence digest`,
      ),
      proposalType: parseOneOfString(
        record.proposalType,
        ["add", "remove"] as const,
        `${label} proposal type`,
      ),
      proposalRequirement: parseOneOfString(
        record.proposalRequirement,
        ["mandatory", "optional"] as const,
        `${label} proposal requirement`,
      ),
      authorizingPolicyHeadSequence: parsePositive(
        record.authorizingPolicyHeadSequence,
        `${label} policy sequence`,
      ),
      authorizingPolicyHeadHash: parseHash32(
        record.authorizingPolicyHeadHash,
        `${label} policy hash`,
      ),
    });
    if (
      BigInt(proposal.position) <= previousPosition ||
      ids.has(proposal.proposalId) ||
      hashes.has(proposal.proposalHash) ||
      envelopeIds.has(proposal.envelopeId) ||
      proposal.membershipIntentHash === ZERO_HASH32 ||
      proposal.membershipIntentEvidenceDigest === ZERO_HASH32
    ) {
      throw invalid(`${label} must be ordered, unique, and intent-proved.`);
    }
    previousPosition = BigInt(proposal.position);
    ids.add(proposal.proposalId);
    hashes.add(proposal.proposalHash);
    envelopeIds.add(proposal.envelopeId);
    return proposal;
  });
  return Object.freeze(parsed);
}

function parsePolicyMandatoryProposals(
  value: unknown,
  label: string,
): readonly PolicyMandatoryProposalBinding[] {
  const entries = expectDenseArray(
    value,
    DELIVERY_MANDATORY_PROPOSALS_MAX,
    label,
  );
  const ids = new Set<string>();
  const hashes = new Set<string>();
  const parsed = entries.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      ["proposalId", "proposalHash"],
      `${label} ${index}`,
    );
    const proposal = Object.freeze({
      proposalId: parseProposalId(record.proposalId),
      proposalHash: parseHash32(record.proposalHash, `${label} hash`),
    });
    if (ids.has(proposal.proposalId) || hashes.has(proposal.proposalHash)) {
      throw invalid(`${label} must contain unique ID/hash pairs.`);
    }
    ids.add(proposal.proposalId);
    hashes.add(proposal.proposalHash);
    return proposal;
  });
  return Object.freeze(parsed);
}

function validatePolicyMandatoryProposalProjection(input: {
  count: Uint63String;
  setHash: Hash32;
  proposals: readonly PolicyMandatoryProposalBinding[];
}): void {
  if (
    BigInt(input.count) !== BigInt(input.proposals.length) ||
    input.setHash !== computePolicyMandatoryProposalSetHash(input.proposals)
  ) {
    throw invalid("Policy mandatory proposal projection is inconsistent.");
  }
}

function samePolicyMandatoryProposals(
  left: readonly PolicyMandatoryProposalBinding[],
  right: readonly PolicyMandatoryProposalBinding[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (proposal, index) =>
        proposal.proposalId === right[index]!.proposalId &&
        proposal.proposalHash === right[index]!.proposalHash,
    )
  );
}

function encodePolicyMandatoryProposals(
  proposals: readonly PolicyMandatoryProposalBinding[],
): readonly Uint8Array[] {
  return [
    utf8(proposals.length.toString(10)),
    ...proposals.flatMap(({ proposalId, proposalHash }) => [
      utf8(proposalId),
      decodeHash32(proposalHash),
    ]),
  ];
}

function sameStagedProposal(
  left: MlsStagedExternalProposalBinding,
  right: MlsStagedExternalProposalBinding,
): boolean {
  return (
    left.position === right.position &&
    left.envelopeId === right.envelopeId &&
    left.envelopeSha256 === right.envelopeSha256 &&
    left.epoch === right.epoch &&
    left.proposalId === right.proposalId &&
    left.proposalHash === right.proposalHash &&
    left.authorizationRecordHash === right.authorizationRecordHash &&
    left.membershipIntentId === right.membershipIntentId &&
    left.membershipIntentHash === right.membershipIntentHash &&
    left.membershipIntentEvidenceDigest ===
      right.membershipIntentEvidenceDigest &&
    left.proposalType === right.proposalType &&
    left.proposalRequirement === right.proposalRequirement &&
    left.authorizingPolicyHeadSequence === right.authorizingPolicyHeadSequence &&
    left.authorizingPolicyHeadHash === right.authorizingPolicyHeadHash
  );
}

function sameStagedProposals(
  left: readonly MlsStagedExternalProposalBinding[],
  right: readonly MlsStagedExternalProposalBinding[],
): boolean {
  return (
    left.length === right.length &&
    left.every((proposal, index) => sameStagedProposal(proposal, right[index]!))
  );
}

function encodeStagedProposals(
  proposals: readonly MlsStagedExternalProposalBinding[],
): readonly Uint8Array[] {
  return [
    utf8(proposals.length.toString(10)),
    ...proposals.flatMap((proposal) => [
      utf8(proposal.position),
      utf8(proposal.envelopeId),
      decodeHash32(proposal.envelopeSha256),
      utf8(proposal.epoch),
      utf8(proposal.proposalId),
      decodeHash32(proposal.proposalHash),
      decodeHash32(proposal.authorizationRecordHash),
      utf8(proposal.membershipIntentId),
      decodeHash32(proposal.membershipIntentHash),
      decodeHash32(proposal.membershipIntentEvidenceDigest),
      utf8(proposal.proposalType),
      utf8(proposal.proposalRequirement),
      utf8(proposal.authorizingPolicyHeadSequence),
      decodeHash32(proposal.authorizingPolicyHeadHash),
    ]),
  ];
}

function parseCommittedIntentBindings(
  value: unknown,
  label: string,
): readonly MlsCommittedIntentBinding[] {
  const entries = expectDenseArray(
    value,
    CONVERSATION_PAGE_HARD_MAX_EVENTS,
    label,
  );
  const pairs = new Set<string>();
  const parsed = entries.map((entry, index) => {
    const record = expectExactRecord(
      entry,
      [
        "membershipIntentId",
        "membershipIntentHash",
        "membershipIntentEvidenceDigest",
        "proposalId",
        "proposalHash",
        "commitPosition",
        "commitEnvelopeId",
        "commitEnvelopeSha256",
      ],
      `${label} ${index}`,
    );
    const binding = Object.freeze({
      membershipIntentId: parseMembershipIntentId(record.membershipIntentId),
      membershipIntentHash: parseHash32(
        record.membershipIntentHash,
        `${label} intent hash`,
      ),
      membershipIntentEvidenceDigest: parseHash32(
        record.membershipIntentEvidenceDigest,
        `${label} intent evidence digest`,
      ),
      proposalId: parseProposalId(record.proposalId),
      proposalHash: parseHash32(record.proposalHash, `${label} proposal hash`),
      commitPosition: parsePositive(record.commitPosition, `${label} position`),
      commitEnvelopeId: parseEnvelopeId(record.commitEnvelopeId),
      commitEnvelopeSha256: parseHash32(
        record.commitEnvelopeSha256,
        `${label} Commit envelope SHA-256`,
      ),
    });
    const pair = `${binding.membershipIntentId}\u0000${binding.proposalId}`;
    if (
      pairs.has(pair) ||
      binding.membershipIntentHash === ZERO_HASH32 ||
      binding.membershipIntentEvidenceDigest === ZERO_HASH32
    ) {
      throw invalid(`${label} must contain unique, proved intent/proposal pairs.`);
    }
    pairs.add(pair);
    return binding;
  });
  return Object.freeze(parsed);
}

function encodeCommittedIntents(
  intents: readonly MlsCommittedIntentBinding[],
): readonly Uint8Array[] {
  return [
    utf8(intents.length.toString(10)),
    ...intents.flatMap((intent) => [
      utf8(intent.membershipIntentId),
      decodeHash32(intent.membershipIntentHash),
      decodeHash32(intent.membershipIntentEvidenceDigest),
      utf8(intent.proposalId),
      decodeHash32(intent.proposalHash),
      utf8(intent.commitPosition),
      utf8(intent.commitEnvelopeId),
      decodeHash32(intent.commitEnvelopeSha256),
    ]),
  ];
}

function parseMlsMembershipTarget(
  value: unknown,
  label: string,
): MlsMembershipTargetIdentity | null {
  if (value === null) return null;
  const record = expectExactRecord(
    value,
    ["accountId", "installationId", "credentialId", "credentialFingerprint"],
    label,
  );
  return Object.freeze({
    accountId: parseAccountId(record.accountId),
    installationId: parseInstallationId(record.installationId),
    credentialId: parseCredentialId(record.credentialId),
    credentialFingerprint: parseFingerprint32(record.credentialFingerprint),
  });
}

function sameMlsMembershipTarget(
  left: MlsMembershipTargetIdentity | null,
  right: MlsMembershipTargetIdentity | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.accountId === right.accountId &&
      left.installationId === right.installationId &&
      left.credentialId === right.credentialId &&
      left.credentialFingerprint === right.credentialFingerprint)
  );
}

function encodeMlsMembershipTarget(
  value: MlsMembershipTargetIdentity | null,
): readonly Uint8Array[] {
  return value === null
    ? [utf8("absent")]
    : [
        utf8("present"),
        utf8(value.accountId),
        utf8(value.installationId),
        utf8(value.credentialId),
        decodeFingerprint32(value.credentialFingerprint),
      ];
}

function parsePositive(value: unknown, label: string): Uint63String {
  const parsed = parseUint63String(value, label);
  if (parsed === "0") throw invalid(`${label} must be positive.`);
  return parsed;
}

function parseNonZeroHash32(value: unknown, label: string): Hash32 {
  const parsed = parseHash32(value, label);
  if (parsed === ZERO_HASH32) {
    throw invalid(`${label} cannot use the reserved zero hash.`);
  }
  return parsed;
}

function decrementPositive(value: Uint63String): Uint63String {
  return (BigInt(value) - 1n).toString(10) as Uint63String;
}

function increment(value: Uint63String, label: string): Uint63String {
  const next = BigInt(value) + 1n;
  if (next > 9_223_372_036_854_775_807n) {
    throw invalid(`${label} exceeds uint63.`);
  }
  return next.toString(10) as Uint63String;
}

function minimum(left: number, right: number): number {
  return left < right ? left : right;
}

function maximumUint63(left: Uint63String, right: Uint63String): Uint63String {
  return BigInt(left) >= BigInt(right) ? left : right;
}

function throwIfDeliveryPortUnavailable(value: unknown): void {
  if (
    value !== null &&
    typeof value === "object" &&
    Object.getOwnPropertyDescriptor(value, "status")?.value === "unavailable"
  ) {
    try {
      throw new ConversationSyncDependencyUnavailableError(
        parseDeliveryPortUnavailable(value),
      );
    } catch (error) {
      if (error instanceof ConversationSyncDependencyUnavailableError) {
        throw error;
      }
      throw invalid("A dependency returned malformed unavailable evidence.");
    }
  }
}

function isAuthenticatedCursorRejection(value: unknown): boolean {
  try {
    const record = expectExactRecord(
      value,
      ["status", "reasonCode"],
      "cursor authentication rejection",
    );
    return (
      record.status === "invalid" &&
      record.reasonCode === "authentication-failed"
    );
  } catch {
    return false;
  }
}

function normalizeConversationSyncFailure(error: unknown): Error {
  if (
    error instanceof ConversationSyncValidationError ||
    error instanceof ConversationSyncDependencyTimeoutError ||
    error instanceof ConversationSyncDependencyUnavailableError ||
    error instanceof ConversationHistoryRetentionError ||
    error instanceof ConversationCursorExpiredError ||
    error instanceof ConversationCursorInvalidError
  ) {
    return error;
  }
  return invalid("Conversation sync dependency or input failed closed.");
}

async function recordConversationSyncIncident(
  error: unknown,
  input: ConversationPageVerificationInput,
  port: DeliveryInvariantIncidentPort,
): Promise<void> {
  let incidentCode:
    | "conversation-log-fork"
    | "conversation-position-gap"
    | "checkpoint-substitution"
    | "cursor-binding-failure"
    | null = null;
  if (error instanceof ConversationCursorBindingFailureError) {
    incidentCode = "cursor-binding-failure";
  } else if (error instanceof ConversationSyncValidationError) {
    const message = error.message;
    incidentCode = /gap|reorder|position/i.test(message)
      ? "conversation-position-gap"
      : /fork|predecessor|log[- ]head|visibility|chain/i.test(message)
        ? "conversation-log-fork"
        : /checkpoint|proof|signature|witness|substitut/i.test(message)
          ? "checkpoint-substitution"
          : null;
  }
  if (incidentCode === null || input.signal.aborted) return;
  try {
    const context = parseConversationCursorContext(input.cursorContext);
    const detectedAt = parseRfc3339Millis(
      input.now,
      "conversation sync incident time",
    );
    const incidentDeadline = parseRfc3339Millis(
      new Date(
        Date.now() + CONVERSATION_SYNC_INCIDENT_MAX_WAIT_MILLISECONDS,
      ).toISOString(),
      "conversation sync incident deadline",
    );
    const evidenceDigest = sha256Bytes(
      utf8(CONVERSATION_SYNC_INCIDENT_EVIDENCE_DIGEST_DOMAIN),
      canonicalLengthPrefixed(
        utf8(incidentCode),
        utf8(context.realmId),
        utf8(context.conversationId),
        utf8(context.installationId),
        utf8(detectedAt),
      ),
    );
    const incidentController = new AbortController();
    await callDeliveryPort(incidentDeadline, incidentController.signal, (signal) =>
      port.record({
        incidentCode,
        conversationId: context.conversationId,
        evidenceDigest,
        detectedAt,
        deadline: incidentDeadline,
        signal,
      }),
    );
  } catch {
    // Incident recording is best-effort and can never mask the primary reject.
  }
}

async function recordConversationLogHeadIncident(
  error: unknown,
  input: ConversationLogHeadVerificationInput,
  port: DeliveryInvariantIncidentPort,
): Promise<void> {
  if (!(error instanceof ConversationSyncValidationError) || input.signal.aborted) {
    return;
  }
  const message = error.message;
  const incidentCode = /rollback|fork|log[- ]head|visibility|consisten/i.test(message)
    ? "conversation-log-fork"
    : /checkpoint|proof|signature|witness|substitut/i.test(message)
      ? "checkpoint-substitution"
      : null;
  if (incidentCode === null) return;
  try {
    const context = parseConversationCursorContext(input.cursorContext);
    const detectedAt = parseRfc3339Millis(
      input.now,
      "conversation log-head incident time",
    );
    const incidentDeadline = parseRfc3339Millis(
      new Date(
        Date.now() + CONVERSATION_SYNC_INCIDENT_MAX_WAIT_MILLISECONDS,
      ).toISOString(),
      "conversation log-head incident deadline",
    );
    const evidenceDigest = sha256Bytes(
      utf8(CONVERSATION_SYNC_INCIDENT_EVIDENCE_DIGEST_DOMAIN),
      canonicalLengthPrefixed(
        utf8(incidentCode),
        utf8(context.realmId),
        utf8(context.conversationId),
        utf8(context.installationId),
        utf8(detectedAt),
      ),
    );
    const incidentController = new AbortController();
    await callDeliveryPort(incidentDeadline, incidentController.signal, (signal) =>
      port.record({
        incidentCode,
        conversationId: context.conversationId,
        evidenceDigest,
        detectedAt,
        deadline: incidentDeadline,
        signal,
      }),
    );
  } catch {
    // Incident recording is best-effort and can never mask the primary reject.
  }
}

async function callDeliveryPort<T>(
  deadline: Rfc3339Millis,
  outerSignal: AbortSignal,
  invoke: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  if (outerSignal.aborted) {
    throw new ConversationSyncDependencyTimeoutError();
  }
  const rawRemaining = Date.parse(deadline) - Date.now();
  if (rawRemaining <= 0) {
    throw new ConversationSyncDependencyTimeoutError();
  }
  const controller = new AbortController();
  const remaining = Math.min(
    CONVERSATION_SYNC_MAX_PORT_WAIT_MILLISECONDS,
    rawRemaining,
  );
  const portExpiresAt = Date.now() + remaining;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let rejectTimeout: ((reason: unknown) => void) | undefined;
  const timedOut = new Promise<never>((_resolve, reject) => {
    rejectTimeout = reject;
    timeout = setTimeout(() => {
      controller.abort();
      reject(new ConversationSyncDependencyTimeoutError());
    }, remaining);
  });
  const onAbort = (): void => {
    controller.abort();
    rejectTimeout?.(new ConversationSyncDependencyTimeoutError());
  };
  outerSignal.addEventListener("abort", onAbort, { once: true });
  try {
    const result = await Promise.race([
      Promise.resolve().then(() => invoke(controller.signal)),
      timedOut,
    ]);
    if (
      outerSignal.aborted ||
      Date.now() >= portExpiresAt ||
      Date.now() >= Date.parse(deadline)
    ) {
      controller.abort();
      throw new ConversationSyncDependencyTimeoutError();
    }
    return result;
  } catch (error) {
    if (
      error instanceof ConversationSyncDependencyTimeoutError ||
      error instanceof ConversationSyncDependencyUnavailableError
    ) {
      throw error;
    }
    throw new ConversationSyncDependencyUnavailableError(
      Object.freeze({
        status: "unavailable",
        reasonCode: "dependency-unavailable",
      }),
    );
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    outerSignal.removeEventListener("abort", onAbort);
  }
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function encodeNullableUtf8(value: string | null): Uint8Array {
  return value === null
    ? canonicalLengthPrefixed(utf8("absent"))
    : canonicalLengthPrefixed(utf8("present"), utf8(value));
}

function encodeNullableHash32(value: Hash32 | null): Uint8Array {
  return value === null
    ? canonicalLengthPrefixed(utf8("absent"))
    : canonicalLengthPrefixed(utf8("present"), decodeHash32(value));
}

function parseOwnedBytes(value: unknown, maximum: number, label: string): Uint8Array {
  try {
    return copyBytes(value, label, maximum);
  } catch {
    throw invalid(`${label} must be bounded intrinsic-safe exact bytes.`);
  }
}

function expectDenseArray(
  value: unknown,
  maximum: number,
  label: string,
): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw invalid(`${label} must be an array.`);
  }
  if (value.length > maximum) {
    throw invalid(`${label} exceeds the item-count bound.`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || keys.at(-1) !== "length") {
    throw invalid(`${label} must be dense and data-only.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw invalid(`${label} must be dense and data-only.`);
    }
  }
  return value;
}

function hasOwnDataField(value: unknown, key: string): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return Boolean(descriptor && "value" in descriptor && descriptor.enumerable);
}

function readDataField(value: unknown, key: string, label: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${label} must be a plain record.`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    throw invalid(`${label}.${key} must be an own data property.`);
  }
  return descriptor.value;
}

function copyRecordWithout(
  record: Record<string, unknown>,
  omitted: string,
): Record<string, unknown> {
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (key !== omitted) {
      Object.defineProperty(copy, key, {
        value: record[key],
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
  }
  return copy;
}

function parseStrictJsonBytes(bytes: Uint8Array): unknown {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    throw invalid("Conversation page JSON must not contain a UTF-8 BOM.");
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw invalid("Conversation page must be valid UTF-8 JSON.");
  }
  let offset = 0;
  let nodes = 0;
  const numberPattern = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

  function fail(): never {
    throw invalid("Conversation page must be strict JSON without duplicate keys.");
  }
  function skipWhitespace(): void {
    while (
      source[offset] === " " ||
      source[offset] === "\n" ||
      source[offset] === "\r" ||
      source[offset] === "\t"
    ) offset += 1;
  }
  function parseString(): string {
    if (source[offset] !== '"') fail();
    const start = offset++;
    while (offset < source.length) {
      const code = source.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        try {
          return JSON.parse(source.slice(start, offset)) as string;
        } catch {
          fail();
        }
      }
      if (code < 0x20) fail();
      if (code === 0x5c) {
        offset += 1;
        const escaped = source[offset];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(offset + 1, offset + 5))) fail();
          offset += 5;
          continue;
        }
        if (!escaped || !'"\\/bfnrt'.includes(escaped)) fail();
      }
      offset += 1;
    }
    fail();
  }
  function parseNumber(): number {
    numberPattern.lastIndex = offset;
    const match = numberPattern.exec(source);
    if (!match) fail();
    offset = numberPattern.lastIndex;
    const result = Number(match[0]);
    if (!Number.isFinite(result)) fail();
    return result;
  }
  function parseValue(depth: number): unknown {
    if (depth > MAX_STRICT_JSON_DEPTH || ++nodes > MAX_STRICT_JSON_NODES) fail();
    skipWhitespace();
    if (source[offset] === '"') return parseString();
    if (source[offset] === "{") return parseObject(depth + 1);
    if (source[offset] === "[") return parseArray(depth + 1);
    if (source.startsWith("true", offset)) {
      offset += 4;
      return true;
    }
    if (source.startsWith("false", offset)) {
      offset += 5;
      return false;
    }
    if (source.startsWith("null", offset)) {
      offset += 4;
      return null;
    }
    return parseNumber();
  }
  function parseObject(depth: number): Record<string, unknown> {
    offset += 1;
    skipWhitespace();
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    if (source[offset] === "}") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      skipWhitespace();
      if (source[offset++] !== ":") fail();
      const value = parseValue(depth);
      Object.defineProperty(result, key, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      skipWhitespace();
      if (source[offset] === "}") {
        offset += 1;
        return result;
      }
      if (source[offset++] !== ",") fail();
    }
    fail();
  }
  function parseArray(depth: number): unknown[] {
    offset += 1;
    skipWhitespace();
    const result: unknown[] = [];
    if (source[offset] === "]") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      result.push(parseValue(depth));
      skipWhitespace();
      if (source[offset] === "]") {
        offset += 1;
        return result;
      }
      if (source[offset++] !== ",") fail();
    }
    fail();
  }

  const result = parseValue(0);
  skipWhitespace();
  if (offset !== source.length) fail();
  return result;
}

function invalid(message: string): ConversationSyncValidationError {
  return new ConversationSyncValidationError(message);
}
