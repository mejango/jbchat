import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  DELIVERY_MANDATORY_PROPOSALS_MAX,
  buildApplicationAppendSignerFenceResolutionExpectation,
  computeApplicationAppendFenceTokenHash,
  computeApplicationAppendSignerFenceRecordDigest,
  computeApplicationAppendSignerFenceVerificationEvidenceDigest,
  parseApplicationAppendFinalizedAt,
  parseApplicationAppendReservationFence,
  parseApplicationAppendRetiredAt,
  parseApplicationAppendSignerFenceResolution,
  parseApplicationAppendSignerFenceVerificationEvidence,
  parseDurableApplicationAppendSignerFenceSignedResolution,
  type ApplicationAppendSignerFenceSignedResolution,
  type DeliveryCheckpointSigningRequest,
} from "./ports";
import { sha256Bytes } from "./hashes";
import { parseDeliveryRealmId } from "./sync";
import {
  APPLICATION_APPEND_QUOTA_SCOPES,
  bindApplicationAppendQuotaCapacityReservations,
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendPendingExpiresAt,
  computeApplicationAppendRecipientSetHash,
  computeApplicationAppendQuotaPolicyDigest,
  computeApplicationAppendQuotaScopeHash,
  computeConversationSendGrantEvidenceDigest,
  computeLockedApplicationAppendSnapshotDigest,
  computePolicyHeadProofEvidenceDigest,
  evaluateLockedApplicationAppend,
  deriveApplicationAppendFanoutPlan,
  parseApplicationAppendExpectation,
  parseLockedApplicationAppendSnapshot,
  parsePolicyHeadProofEvidence,
  validateLockedApplicationAppendStateTransition,
  validateLockedApplicationAppendQuotaFinalizationTransition,
  validateLockedApplicationAppendQuotaReleaseTransition,
  validateLockedApplicationAppendQuotaReservationTransition,
  type ApplicationAppendExpectation,
  type ApplicationAppendRejectionReason,
  type ConversationSendRole,
  type LockedApplicationAppendSnapshot,
  type LockedApplicationAppendCommitProjection,
  type ApplicationAppendMlsRosterProjection,
  type ApplicationAppendRecipientProjection,
  type LockedConversationSendGrant,
  type LockedConversationState,
  type PolicyHeadProofExpectation,
} from "./state";
import {
  UINT63_MAX_STRING,
  ZERO_HASH32,
  parseAccountId,
  parseConversationEtag,
  parseConversationId,
  parseCredentialId,
  parseEd25519Signature,
  parseFingerprint32,
  parseHash32,
  parseCanonicalBase64UrlBytes,
  parseInstallationId,
  parsePolicyHeadId,
  parseReleaseProfileId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  parseWitnessCheckpointId,
  type Hash32,
  type Rfc3339Millis,
} from "./valueObjects";

type DeepMutable<Value> = Value extends string | number | bigint | boolean | null
  ? Value
  : Value extends readonly (infer Entry)[]
    ? DeepMutable<Entry>[]
    : Value extends object
      ? { -readonly [Key in keyof Value]: DeepMutable<Value[Key]> }
      : Value;

const CONVERSATION_ID = parseConversationId(
  "123e4567-e89b-42d3-a456-426614174000",
);
const OTHER_CONVERSATION_ID = parseConversationId(
  "223e4567-e89b-42d3-a456-426614174001",
);
const ACCOUNT_ID = parseAccountId("323e4567-e89b-42d3-a456-426614174002");
const OTHER_ACCOUNT_ID = parseAccountId(
  "423e4567-e89b-42d3-a456-426614174003",
);
const INSTALLATION_ID = parseInstallationId(
  "523e4567-e89b-42d3-a456-426614174004",
);
const OTHER_INSTALLATION_ID = parseInstallationId(
  "623e4567-e89b-42d3-a456-426614174005",
);
const CREDENTIAL_ID = parseCredentialId(
  "723e4567-e89b-42d3-a456-426614174006",
);
const OTHER_CREDENTIAL_ID = parseCredentialId(
  "823e4567-e89b-42d3-a456-426614174007",
);
const THIRD_ACCOUNT_ID = parseAccountId(
  "e23e4567-e89b-42d3-a456-42661417400e",
);
const THIRD_INSTALLATION_ID = parseInstallationId(
  "f23e4567-e89b-42d3-a456-42661417400f",
);
const THIRD_CREDENTIAL_ID = parseCredentialId(
  "123e4567-e89b-42d3-a456-426614174010",
);
const CUSTOMER_ROLE_CREDENTIAL_ID = parseCredentialId(
  "c23e4567-e89b-42d3-a456-42661417400c",
);
const STAFF_ROLE_CREDENTIAL_ID = parseCredentialId(
  "d23e4567-e89b-42d3-a456-42661417400d",
);
const POLICY_HEAD_ID = parsePolicyHeadId(
  "923e4567-e89b-42d3-a456-426614174008",
);
const WITNESS_CHECKPOINT_ID = parseWitnessCheckpointId(
  "a23e4567-e89b-42d3-a456-426614174009",
);
const PRIOR_WITNESS_CHECKPOINT_ID = parseWitnessCheckpointId(
  "b23e4567-e89b-42d3-a456-42661417400a",
);

const NOW = time("2026-08-14T12:02:00.000Z");
const WINDOW_START = time("2026-08-14T12:00:00.000Z");
const POLICY_ISSUED_AT = time("2026-08-14T12:00:00.000Z");
const POLICY_VERIFIED_AT = time("2026-08-14T12:00:00.000Z");
const POLICY_EXPIRES_AT = time("2026-08-14T12:05:00.000Z");
const GRANT_EXPIRES_AT = time("2026-08-14T12:10:00.000Z");
const CREDENTIAL_EXPIRES_AT = time("2026-08-14T13:00:00.000Z");
const ROLE_CREDENTIAL_VALID_FROM = time("2026-08-14T11:55:00.000Z");
const ROLE_CREDENTIAL_VALID_UNTIL = time("2026-08-14T12:10:00.000Z");

const PROJECT_SCOPE_ID = "eip155:1:juicebox-project:42";
const TENANT_SCOPE_ID = "juicebox-money";

const DELIVERY_LIMITS_DIGEST = hash(1);
const RELEASE_TRUST_ROOT_DIGEST = hash(2);
const GROUP_ID_HASH = hash(3);
const CONFIRMED_TRANSCRIPT_HASH = hash(4);
const LOG_HEAD_HASH = hash(5);
const POLICY_HEAD_HASH = hash(6);
const PRIOR_POLICY_HEAD_HASH = hash(7);
const SIGNED_BODY_SHA256 = hash(8);
const SIGNATURE_SHA256 = hash(9);
const WITNESS_EVIDENCE_DIGEST = hash(10);
const POLICY_CONSISTENCY_EVIDENCE_DIGEST = hash(11);
const PRIOR_POLICY_WITNESS_EVIDENCE_DIGEST = hash(12);
const MANDATORY_PROPOSAL_SET_HASH = hash(13);
const CREDENTIAL_FINGERPRINT = parseFingerprint32(raw32(14));
const OTHER_CREDENTIAL_FINGERPRINT = parseFingerprint32(raw32(15));
const NEXT_LOG_HEAD_HASH = hash(16);
const AUTHORIZED_SEND_GRANT_SET_HASH = hash(17);
const CUSTOMER_GRANT_INCLUSION_EVIDENCE_DIGEST = hash(18);
const STAFF_GRANT_INCLUSION_EVIDENCE_DIGEST = hash(19);
const CUSTOMER_ROLE_CREDENTIAL_FINGERPRINT = parseFingerprint32(raw32(20));
const STAFF_ROLE_CREDENTIAL_FINGERPRINT = parseFingerprint32(raw32(21));
const ROSTER_HASH = hash(22);
const RECIPIENT_SET_HASH = hash(23);
const PREPARATION_DIGEST = hash(24);
const FENCE_TOKEN_HASH = hash(25);
const THIRD_CREDENTIAL_FINGERPRINT = parseFingerprint32(raw32(26));

interface SenderFixture {
  readonly accountId: typeof ACCOUNT_ID;
  readonly installationId: typeof INSTALLATION_ID;
  readonly credentialId: typeof CREDENTIAL_ID;
  readonly credentialFingerprint: typeof CREDENTIAL_FINGERPRINT;
  readonly credentialRevocationVersion: ReturnType<typeof uint>;
  readonly roleCredentialId: typeof CUSTOMER_ROLE_CREDENTIAL_ID;
  readonly roleCredentialFingerprint: typeof CUSTOMER_ROLE_CREDENTIAL_FINGERPRINT;
  readonly grantInclusionEvidenceDigest: Hash32;
}

const CUSTOMER_SENDER: SenderFixture = {
  accountId: ACCOUNT_ID,
  installationId: INSTALLATION_ID,
  credentialId: CREDENTIAL_ID,
  credentialFingerprint: CREDENTIAL_FINGERPRINT,
  credentialRevocationVersion: uint("4"),
  roleCredentialId: CUSTOMER_ROLE_CREDENTIAL_ID,
  roleCredentialFingerprint: CUSTOMER_ROLE_CREDENTIAL_FINGERPRINT,
  grantInclusionEvidenceDigest: CUSTOMER_GRANT_INCLUSION_EVIDENCE_DIGEST,
};

const STAFF_SENDER: SenderFixture = {
  accountId: OTHER_ACCOUNT_ID,
  installationId: OTHER_INSTALLATION_ID,
  credentialId: OTHER_CREDENTIAL_ID,
  credentialFingerprint: OTHER_CREDENTIAL_FINGERPRINT,
  credentialRevocationVersion: uint("9"),
  roleCredentialId: STAFF_ROLE_CREDENTIAL_ID,
  roleCredentialFingerprint: STAFF_ROLE_CREDENTIAL_FINGERPRINT,
  grantInclusionEvidenceDigest: STAFF_GRANT_INCLUSION_EVIDENCE_DIGEST,
};

function raw32(fill: number): string {
  return Buffer.alloc(32, fill).toString("base64url");
}

function raw64(fill: number): string {
  return Buffer.alloc(64, fill).toString("base64url");
}

function hash(fill: number): Hash32 {
  return parseHash32(raw32(fill));
}

function time(value: string): Rfc3339Millis {
  return parseRfc3339Millis(value);
}

function uint(value: string) {
  return parseUint63String(value);
}

function cloneSnapshot(
  snapshot: LockedApplicationAppendSnapshot,
): DeepMutable<LockedApplicationAppendSnapshot> {
  return structuredClone(snapshot) as DeepMutable<LockedApplicationAppendSnapshot>;
}

function policyProofDigest(snapshot: LockedApplicationAppendSnapshot): Hash32 {
  const { conversation, policyHead } = snapshot;
  if (
    policyHead.witnessCheckpointId === null ||
    policyHead.witnessedPolicyHeadHash === null
  ) {
    throw new Error("The test fixture requires a verified witnessed policy head.");
  }
  return computePolicyHeadProofEvidenceDigest({
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
    authorizedQuotaPolicyDigest: policyHead.authorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: policyHead.priorPolicyHeadSequence,
    priorPolicyHeadHash: policyHead.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId:
      policyHead.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      policyHead.priorPolicyWitnessEvidenceDigest,
    signedBodySha256: policyHead.signedBodySha256,
    signerKeyId: policyHead.signerKeyId,
    signatureSha256: policyHead.signatureSha256,
    witnessCheckpointId: policyHead.witnessCheckpointId,
    witnessedPolicyHeadHash: policyHead.witnessedPolicyHeadHash,
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
  });
}

function policyProofExpectation(
  snapshot: LockedApplicationAppendSnapshot,
): PolicyHeadProofExpectation {
  const { conversation, policyHead } = snapshot;
  return {
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
    authorizedQuotaPolicyDigest: policyHead.authorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: policyHead.priorPolicyHeadSequence,
    priorPolicyHeadHash: policyHead.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId:
      policyHead.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      policyHead.priorPolicyWitnessEvidenceDigest,
    verifiedAt: policyHead.proofVerifiedAt,
  };
}

function refreshPolicyProofDigest(
  snapshot: DeepMutable<LockedApplicationAppendSnapshot>,
): void {
  snapshot.policyHead.proofEvidenceDigest = policyProofDigest(snapshot);
}

function refreshGrantBindings(
  snapshot: DeepMutable<LockedApplicationAppendSnapshot>,
): void {
  snapshot.sendGrant.grantEvidenceDigest =
    computeConversationSendGrantEvidenceDigest(snapshot.sendGrant);
  snapshot.policyHead.selectedSendGrantEvidenceDigest =
    snapshot.sendGrant.grantEvidenceDigest;
  snapshot.policyHead.selectedSendGrantInclusionEvidenceDigest =
    snapshot.sendGrant.grantInclusionEvidenceDigest;
  refreshPolicyProofDigest(snapshot);
}

function quotaSubjectId(
  snapshot: Pick<LockedApplicationAppendSnapshot, "conversation" | "membership">,
  scope: (typeof APPLICATION_APPEND_QUOTA_SCOPES)[number],
): string {
  switch (scope) {
    case "installation":
      return snapshot.membership.installationId;
    case "account":
      return snapshot.membership.accountId;
    case "project":
      return snapshot.conversation.projectScopeId;
    case "conversation":
      return snapshot.conversation.conversationId;
    case "tenant":
      return snapshot.conversation.tenantScopeId;
  }
}

function refreshQuotaBindings(
  snapshot: DeepMutable<LockedApplicationAppendSnapshot>,
): void {
  for (const binding of snapshot.quotaBindings) {
    binding.scopeHash = computeApplicationAppendQuotaScopeHash({
      realmId: snapshot.conversation.realmId,
      scope: binding.scope,
      subjectId: quotaSubjectId(snapshot, binding.scope),
    });
    const counter = snapshot.quotas.find(({ scope }) => scope === binding.scope);
    if (!counter) throw new Error(`Missing fixture quota counter: ${binding.scope}`);
    counter.scopeHash = binding.scopeHash;
    counter.quotaName = binding.quotaName;
    counter.windowStartedAt = binding.windowStartedAt;
    counter.windowSeconds = binding.windowSeconds;
    counter.operationLimit = binding.operationLimit;
    counter.byteLimit = binding.byteLimit;
  }
  snapshot.conversation.quotaPolicyDigest =
    computeApplicationAppendQuotaPolicyDigest(snapshot.quotaBindings);
  snapshot.policyHead.authorizedQuotaPolicyDigest =
    snapshot.conversation.quotaPolicyDigest;
  refreshPolicyProofDigest(snapshot);
}

function makeSnapshot(
  kind: LockedConversationState["kind"] = "purchase_support",
  role: ConversationSendRole = "customer",
  sender: SenderFixture = CUSTOMER_SENDER,
): LockedApplicationAppendSnapshot {
  const quotaSubjects = {
    installation: sender.installationId,
    account: sender.accountId,
    project: PROJECT_SCOPE_ID,
    conversation: CONVERSATION_ID,
    tenant: TENANT_SCOPE_ID,
  } satisfies Record<(typeof APPLICATION_APPEND_QUOTA_SCOPES)[number], string>;
  const quotaBindings = APPLICATION_APPEND_QUOTA_SCOPES.map((scope) => ({
    scope,
    scopeHash: computeApplicationAppendQuotaScopeHash({
      realmId: "juicebox-mainnet",
      scope,
      subjectId: quotaSubjects[scope],
    }),
    quotaName: "application-append",
    windowStartedAt: WINDOW_START,
    windowSeconds: uint("3600"),
    operationLimit: uint("100"),
    byteLimit: uint("100000"),
  }));
  const quotaPolicyDigest = computeApplicationAppendQuotaPolicyDigest(
    quotaBindings,
  );
  const grantWithoutDigests = {
    conversationId: CONVERSATION_ID,
    installationId: sender.installationId,
    credentialId: sender.credentialId,
    conversationKind: kind,
    conversationGeneration: uint("1"),
    role,
    roleCredentialId: sender.roleCredentialId,
    roleCredentialFingerprint: sender.roleCredentialFingerprint,
    roleCredentialSubjectAccountId: sender.accountId,
    roleCredentialSubjectInstallationId: sender.installationId,
    roleCredentialValidFrom: ROLE_CREDENTIAL_VALID_FROM,
    roleCredentialValidUntil: ROLE_CREDENTIAL_VALID_UNTIL,
    capability: "send_application" as const,
    state: "active" as const,
    policyRevision: uint("8"),
    policyHeadSequence: uint("3"),
    policyHeadHash: POLICY_HEAD_HASH,
    expiresAt: GRANT_EXPIRES_AT,
  } satisfies Omit<
    LockedConversationSendGrant,
    "grantEvidenceDigest" | "grantInclusionEvidenceDigest"
  >;
  const sendGrant: LockedConversationSendGrant = {
    ...grantWithoutDigests,
    grantEvidenceDigest:
      computeConversationSendGrantEvidenceDigest(grantWithoutDigests),
    grantInclusionEvidenceDigest: sender.grantInclusionEvidenceDigest,
  };
  const snapshot = {
    conversation: {
      realmId: "juicebox-mainnet",
      conversationId: CONVERSATION_ID,
      projectScopeId: PROJECT_SCOPE_ID,
      tenantScopeId: TENANT_SCOPE_ID,
      kind,
      generation: uint("1"),
      releaseProfileId: parseReleaseProfileId("mls-rfc9420-v1"),
      deliveryLimitsDigest: DELIVERY_LIMITS_DIGEST,
      releaseTrustRootDigest: RELEASE_TRUST_ROOT_DIGEST,
      quotaPolicyDigest,
      groupIdHash: GROUP_ID_HASH,
      state: "active" as const,
      etag: parseConversationEtag('"e7-r5"'),
      epoch: uint("7"),
      rosterVersion: uint("5"),
      rosterHash: ROSTER_HASH,
      recipientSetVersion: uint("6"),
      recipientSetHash: RECIPIENT_SET_HASH,
      confirmedTranscriptHash: CONFIRMED_TRANSCRIPT_HASH,
      lastPosition: uint("10"),
      currentLogHeadHash: LOG_HEAD_HASH,
      currentPolicyHeadSequence: uint("3"),
      currentPolicyHeadHash: POLICY_HEAD_HASH,
    },
    membership: {
      conversationId: CONVERSATION_ID,
      accountId: sender.accountId,
      installationId: sender.installationId,
      credentialId: sender.credentialId,
      credentialFingerprint: sender.credentialFingerprint,
      credentialRevocationVersion: sender.credentialRevocationVersion,
      installationState: "active" as const,
      credentialState: "active" as const,
      credentialExpiresAt: CREDENTIAL_EXPIRES_AT,
      joinedPosition: uint("1"),
      removedPosition: null,
    },
    policyHead: {
      policyHeadId: POLICY_HEAD_ID,
      conversationId: CONVERSATION_ID,
      policyHeadSequence: uint("3"),
      policyHeadHash: POLICY_HEAD_HASH,
      deliveryLogPosition: uint("10"),
      deliveryLogHeadHash: LOG_HEAD_HASH,
      evaluationLogPosition: uint("10"),
      evaluationLogHeadHash: LOG_HEAD_HASH,
      epoch: uint("7"),
      rosterVersion: uint("5"),
      confirmedTranscriptHash: CONFIRMED_TRANSCRIPT_HASH,
      policyRevision: uint("8"),
      signedBodySha256: SIGNED_BODY_SHA256,
      signerKeyId: parseSigningKeyId("policy-key-1"),
      signatureSha256: SIGNATURE_SHA256,
      witnessEvidenceDigest: WITNESS_EVIDENCE_DIGEST,
      proofEvidenceDigest: ZERO_HASH32,
      policyConsistencyEvidenceDigest: POLICY_CONSISTENCY_EVIDENCE_DIGEST,
      proofVerifiedAt: POLICY_VERIFIED_AT,
      issuedAt: POLICY_ISSUED_AT,
      expiresAt: POLICY_EXPIRES_AT,
      witnessState: "verified" as const,
      witnessCheckpointId: WITNESS_CHECKPOINT_ID,
      witnessedPolicyHeadHash: POLICY_HEAD_HASH,
      mandatoryProposalCount: uint("0"),
      mandatoryProposalSetHash: MANDATORY_PROPOSAL_SET_HASH,
      authorizedSendGrantSetHash: AUTHORIZED_SEND_GRANT_SET_HASH,
      selectedSendGrantEvidenceDigest: sendGrant.grantEvidenceDigest,
      selectedSendGrantInclusionEvidenceDigest:
        sendGrant.grantInclusionEvidenceDigest,
      authorizedQuotaPolicyDigest: quotaPolicyDigest,
      priorPolicyHeadSequence: uint("2"),
      priorPolicyHeadHash: PRIOR_POLICY_HEAD_HASH,
      priorPolicyWitnessCheckpointId: PRIOR_WITNESS_CHECKPOINT_ID,
      priorPolicyWitnessEvidenceDigest:
        PRIOR_POLICY_WITNESS_EVIDENCE_DIGEST,
    },
    sendGrant,
    pendingRemovalCount: uint("0"),
    usage: {
      conversationId: CONVERSATION_ID,
      envelopeCount: uint("2"),
      envelopeBytes: uint("1000"),
      attachmentBytes: uint("100"),
      envelopeCountLimit: uint("100"),
      envelopeBytesLimit: uint("100000"),
      attachmentBytesLimit: uint("100000"),
    },
    quotaBindings,
    quotas: quotaBindings.map((binding) => ({
      ...binding,
      operationCount: uint("1"),
      byteCount: uint("100"),
      reservedOperationCount: uint("0"),
      reservedByteCount: uint("0"),
      rowVersion: uint("1"),
    })),
  } satisfies LockedApplicationAppendSnapshot;
  snapshot.policyHead.proofEvidenceDigest = policyProofDigest(snapshot);
  return parseLockedApplicationAppendSnapshot(snapshot);
}

function makeExpectation(
  snapshot: LockedApplicationAppendSnapshot = makeSnapshot(),
): ApplicationAppendExpectation {
  return parseApplicationAppendExpectation({
    realmId: snapshot.conversation.realmId,
    conversationId: snapshot.conversation.conversationId,
    accountId: snapshot.membership.accountId,
    installationId: snapshot.membership.installationId,
    credentialId: snapshot.membership.credentialId,
    credentialFingerprint: snapshot.membership.credentialFingerprint,
    credentialRevocationVersion:
      snapshot.membership.credentialRevocationVersion,
    releaseProfileId: snapshot.conversation.releaseProfileId,
    expectedDeliveryLimitsDigest: snapshot.conversation.deliveryLimitsDigest,
    expectedQuotaPolicyDigest: snapshot.conversation.quotaPolicyDigest,
    expectedProjectScopeId: snapshot.conversation.projectScopeId,
    expectedTenantScopeId: snapshot.conversation.tenantScopeId,
    expectedGroupIdHash: snapshot.conversation.groupIdHash,
    ifMatch: snapshot.conversation.etag,
    expectedEpoch: snapshot.conversation.epoch,
    expectedRosterVersion: snapshot.conversation.rosterVersion,
    expectedConfirmedTranscriptHash:
      snapshot.conversation.confirmedTranscriptHash,
    policyHeadId: snapshot.policyHead.policyHeadId,
    policyHeadSequence: snapshot.policyHead.policyHeadSequence,
    policyHeadHash: snapshot.policyHead.policyHeadHash,
    policyEvaluationLogPosition: snapshot.policyHead.evaluationLogPosition,
    policyEvaluationLogHeadHash: snapshot.policyHead.evaluationLogHeadHash,
    envelopeByteLength: "100",
    attachmentByteLength: "25",
  });
}

function expectRejected(
  snapshot: LockedApplicationAppendSnapshot,
  expectation: ApplicationAppendExpectation,
  reasonCode: ApplicationAppendRejectionReason,
  now: Rfc3339Millis = NOW,
): void {
  expect(evaluateLockedApplicationAppend(snapshot, expectation, now)).toEqual({
    status: "rejected",
    reasonCode,
  });
}

function preparedCommitProjection(
  prior: LockedApplicationAppendSnapshot,
  expectation: ApplicationAppendExpectation,
  nextHeadHash: Hash32 = NEXT_LOG_HEAD_HASH,
): LockedApplicationAppendCommitProjection {
  const decision = evaluateLockedApplicationAppend(prior, expectation, NOW);
  if (decision.status !== "allowed") {
    throw new Error(`Fixture append was rejected: ${decision.reasonCode}`);
  }
  return {
    conversation: {
      ...prior.conversation,
      lastPosition: decision.nextPosition,
      currentLogHeadHash: nextHeadHash,
    },
    usage: decision.nextUsage,
    quotaCapacityReservations:
      bindApplicationAppendQuotaCapacityReservations({
        deltas: decision.quotaCapacityDeltas,
        pendingPreparationDigest: PREPARATION_DIGEST,
        fenceGeneration: uint("1"),
        fenceTokenHash: FENCE_TOKEN_HASH,
      }),
  };
}

describe("application append signer-fence evidence", () => {
  it("binds a dedicated-key signed record to the exact redacted fence tuple", () => {
    const reservationFence = parseApplicationAppendReservationFence({
      generation: "7",
      token: raw32(71),
    });
    const request: DeliveryCheckpointSigningRequest = {
      profile: "delivery-log-checkpoint.v1",
      realmId: parseDeliveryRealmId("juicebox-mainnet"),
      conversationGeneration: uint("1"),
      releaseProfileId: parseReleaseProfileId("mls-rfc9420-v1"),
      releaseTrustRootDigest: RELEASE_TRUST_ROOT_DIGEST,
      conversationId: CONVERSATION_ID,
      position: uint("11"),
      previousHeadHash: LOG_HEAD_HASH,
      headHash: NEXT_LOG_HEAD_HASH,
      signingKeyId: parseSigningKeyId("delivery-key-1"),
      checkpointDigest: hash(72),
      checkpointReceivedAt: NOW,
      pendingIntentDigest: hash(73),
      reservationFence,
      pendingExpiresAt: time("2026-08-14T12:02:30.000Z"),
      admissionStartedAt: time("2026-08-14T12:01:59.000Z"),
      invocationStartedAt: NOW,
      deadline: time("2026-08-14T12:02:15.000Z"),
      signal: new AbortController().signal,
    };
    const unsignedResolution: ApplicationAppendSignerFenceSignedResolution = {
      status: "signed",
      profile: "application-append-signer-fence-resolution.v1",
      realmId: request.realmId,
      conversationGeneration: request.conversationGeneration,
      releaseProfileId: request.releaseProfileId,
      releaseTrustRootDigest: request.releaseTrustRootDigest,
      conversationId: request.conversationId,
      position: request.position,
      previousHeadHash: request.previousHeadHash,
      headHash: request.headHash,
      signingKeyId: request.signingKeyId,
      checkpointDigest: request.checkpointDigest,
      checkpointReceivedAt: request.checkpointReceivedAt,
      pendingIntentDigest: request.pendingIntentDigest,
      fenceGeneration: reservationFence.generation,
      fenceTokenHash: computeApplicationAppendFenceTokenHash(
        reservationFence.token,
      ),
      pendingExpiresAt: request.pendingExpiresAt,
      admissionStartedAt: request.admissionStartedAt,
      fenceRecordKeyProfile: "application-append-fence-record-ed25519.v1",
      fenceRecordDigest: ZERO_HASH32,
      fenceRecordSigningKeyId: parseSigningKeyId("fence-record-key-1"),
      fenceRecordSignature: parseEd25519Signature(raw64(74)),
      checkpointSignature: parseEd25519Signature(raw64(75)),
      signedAt: time("2026-08-14T12:02:01.000Z"),
    };
    const resolution = {
      ...unsignedResolution,
      fenceRecordDigest:
        computeApplicationAppendSignerFenceRecordDigest(unsignedResolution),
    };
    expect(resolution.fenceRecordDigest).toBe(
      "YkMwcUEh0R89Y0nmjpE8Qt379NXIWLI8Y0LbrgC1FDA",
    );
    expect(
      parseApplicationAppendSignerFenceResolution(resolution, request),
    ).toEqual(resolution);
    const durableExpectation =
      buildApplicationAppendSignerFenceResolutionExpectation(request);
    expect(
      parseDurableApplicationAppendSignerFenceSignedResolution(
        resolution,
        durableExpectation,
      ),
    ).toEqual(resolution);
    expect(JSON.stringify(resolution)).not.toContain(reservationFence.token);

    const fenceRecordSignatureSha256 = sha256Bytes(
      parseCanonicalBase64UrlBytes(
        resolution.fenceRecordSignature,
        "fence record signature",
        { minBytes: 64, maxBytes: 64 },
      ),
    );
    const verifiedAt = time("2026-08-14T12:02:02.000Z");
    const evidence = {
      profile: "application-append-signer-fence-evidence.v1",
      status: "verified",
      resolutionStatus: "signed",
      pendingIntentDigest: resolution.pendingIntentDigest,
      fenceGeneration: resolution.fenceGeneration,
      fenceTokenHash: resolution.fenceTokenHash,
      fenceRecordKeyProfile: resolution.fenceRecordKeyProfile,
      fenceRecordDigest: resolution.fenceRecordDigest,
      fenceRecordSigningKeyId: resolution.fenceRecordSigningKeyId,
      fenceRecordSignatureSha256,
      verifiedAt,
      keyStatus: "trusted-for-record",
      recordSignatureStatus: "verified",
      evidenceDigest:
        computeApplicationAppendSignerFenceVerificationEvidenceDigest({
          resolution,
          resolutionStatus: "signed",
          fenceRecordSignatureSha256,
          verifiedAt,
        }),
    };
    expect(
      parseApplicationAppendSignerFenceVerificationEvidence(
        evidence,
        resolution,
        verifiedAt,
      ),
    ).toEqual(evidence);
    expect(JSON.stringify(evidence)).not.toContain(reservationFence.token);

    expect(() =>
      parseApplicationAppendSignerFenceResolution(
        { ...resolution, fenceRecordSigningKeyId: "fence-record-key-2" },
        request,
      ),
    ).toThrow(/digest/i);
    expect(() =>
      parseApplicationAppendSignerFenceResolution(
        {
          ...resolution,
          status: "cancelled",
          cancellationStatus: "irreversible-cancelled",
          cancelledAt: request.pendingExpiresAt,
        },
        request,
      ),
    ).toThrow();
    const hostile = new Proxy({}, {
      getPrototypeOf() {
        throw new Error("secret-fence-token");
      },
    });
    expect(() =>
      parseApplicationAppendSignerFenceResolution(hostile, request),
    ).toThrow(/inaccessible/i);
  });

  it("allows historical phase times only through a freshly bracketed DB observation", () => {
    const expected = {
      invocationStartedAt: time("2026-08-14T12:02:00.000Z"),
      observedAt: time("2026-08-14T12:02:01.500Z"),
      observedCompletedAt: time("2026-08-14T12:02:02.000Z"),
      deadline: time("2026-08-14T12:02:03.000Z"),
    };
    expect(
      parseApplicationAppendFinalizedAt(
        "2026-08-14T12:02:01.000Z",
        expected,
      ),
    ).toBe("2026-08-14T12:02:01.000Z");
    expect(
      parseApplicationAppendRetiredAt(
        "2026-08-14T12:02:01.500Z",
        expected,
      ),
    ).toBe("2026-08-14T12:02:01.500Z");
    expect(
      parseApplicationAppendFinalizedAt(
        "2026-08-14T12:01:59.999Z",
        expected,
      ),
    ).toBe("2026-08-14T12:01:59.999Z");
    expect(() =>
      parseApplicationAppendRetiredAt(
        "2026-08-14T12:02:02.001Z",
        expected,
      ),
    ).toThrow(/outside/i);
    expect(() =>
      parseApplicationAppendFinalizedAt(
        "2026-08-14T12:02:01.000Z",
        { ...expected, observedAt: expected.deadline },
      ),
    ).toThrow(/outside/i);
  });
});

describe("locked application append state parsing", () => {
  it("rejects a mandatory proposal count above the shared protocol queue bound", () => {
    const snapshot = cloneSnapshot(makeSnapshot());
    snapshot.policyHead.mandatoryProposalCount = uint(
      (DELIVERY_MANDATORY_PROPOSALS_MAX + 1).toString(10),
    );
    expect(() => parseLockedApplicationAppendSnapshot(snapshot)).toThrow(
      /queue bound/i,
    );
  });
  it("accepts and retains the exact realm binding on the snapshot and expectation", () => {
    const snapshot = makeSnapshot();
    const expectation = makeExpectation(snapshot);

    expect(snapshot.conversation.realmId).toBe("juicebox-mainnet");
    expect(expectation.realmId).toBe("juicebox-mainnet");

    const missingSnapshotRealm = cloneSnapshot(snapshot);
    Reflect.deleteProperty(missingSnapshotRealm.conversation, "realmId");
    expect(() =>
      parseLockedApplicationAppendSnapshot(missingSnapshotRealm),
    ).toThrow();

    const extraSnapshotRealm = cloneSnapshot(snapshot);
    Object.assign(extraSnapshotRealm.conversation, { realm: "legacy" });
    expect(() => parseLockedApplicationAppendSnapshot(extraSnapshotRealm)).toThrow();

    const invalidSnapshotRealm = cloneSnapshot(snapshot);
    invalidSnapshotRealm.conversation.realmId = "Juicebox-Mainnet";
    expect(() =>
      parseLockedApplicationAppendSnapshot(invalidSnapshotRealm),
    ).toThrow();

    const missingExpectationRealm = { ...expectation };
    Reflect.deleteProperty(missingExpectationRealm, "realmId");
    expect(() =>
      parseApplicationAppendExpectation(missingExpectationRealm),
    ).toThrow();

    expect(() =>
      parseApplicationAppendExpectation({
        ...expectation,
        realmId: "Juicebox-Mainnet",
      }),
    ).toThrow();
    expect(() =>
      parseApplicationAppendExpectation({
        ...expectation,
        legacyRealm: "juicebox-mainnet",
      }),
    ).toThrow();
  });

  it("rejects cross-row conversation, log-anchor, witness, and usage inconsistencies", () => {
    const cases: Array<
      (snapshot: DeepMutable<LockedApplicationAppendSnapshot>) => void
    > = [
      (snapshot) => {
        snapshot.membership.conversationId = OTHER_CONVERSATION_ID;
      },
      (snapshot) => {
        snapshot.policyHead.conversationId = OTHER_CONVERSATION_ID;
      },
      (snapshot) => {
        snapshot.sendGrant.conversationId = OTHER_CONVERSATION_ID;
      },
      (snapshot) => {
        snapshot.usage.conversationId = OTHER_CONVERSATION_ID;
      },
      (snapshot) => {
        snapshot.conversation.lastPosition = uint("0");
      },
      (snapshot) => {
        snapshot.policyHead.deliveryLogPosition = uint("11");
      },
      (snapshot) => {
        snapshot.policyHead.evaluationLogPosition = uint("11");
      },
      (snapshot) => {
        snapshot.policyHead.witnessCheckpointId = null;
      },
      (snapshot) => {
        snapshot.usage.envelopeCount = uint("101");
      },
    ];

    for (const mutate of cases) {
      const candidate = cloneSnapshot(makeSnapshot());
      mutate(candidate);
      expect(() => parseLockedApplicationAppendSnapshot(candidate)).toThrow();
    }
  });

  it("requires the locked policy proof digest and exact authoritative quota identities", () => {
    const valid = makeSnapshot();
    for (const binding of valid.quotaBindings) {
      expect(binding.scopeHash).toBe(
        computeApplicationAppendQuotaScopeHash({
          realmId: valid.conversation.realmId,
          scope: binding.scope,
          subjectId: quotaSubjectId(valid, binding.scope),
        }),
      );
      const counter = valid.quotas.find(({ scope }) => scope === binding.scope);
      expect(counter).toMatchObject({
        operationLimit: binding.operationLimit,
        byteLimit: binding.byteLimit,
      });
    }
    expect(computeApplicationAppendQuotaPolicyDigest(valid.quotaBindings)).toBe(
      valid.conversation.quotaPolicyDigest,
    );
    expect(valid.policyHead.authorizedQuotaPolicyDigest).toBe(
      valid.conversation.quotaPolicyDigest,
    );

    const invalidProof = cloneSnapshot(makeSnapshot());
    invalidProof.policyHead.proofEvidenceDigest = hash(99);
    expect(() => parseLockedApplicationAppendSnapshot(invalidProof)).toThrow();

    const substitutedCounter = cloneSnapshot(makeSnapshot());
    substitutedCounter.quotas[0].scopeHash = hash(100);
    expect(() =>
      parseLockedApplicationAppendSnapshot(substitutedCounter),
    ).toThrow();

    const substitutedBinding = cloneSnapshot(makeSnapshot());
    substitutedBinding.quotaBindings[1].quotaName = "different-quota";
    expect(() =>
      parseLockedApplicationAppendSnapshot(substitutedBinding),
    ).toThrow();

    const substitutedLimit = cloneSnapshot(makeSnapshot());
    substitutedLimit.quotaBindings[2].operationLimit = uint("101");
    expect(() =>
      parseLockedApplicationAppendSnapshot(substitutedLimit),
    ).toThrow();

    const detachedSignedQuotaPolicy = cloneSnapshot(makeSnapshot());
    detachedSignedQuotaPolicy.quotaBindings[3].byteLimit = uint("100001");
    detachedSignedQuotaPolicy.quotas[3].byteLimit = uint("100001");
    expect(() =>
      parseLockedApplicationAppendSnapshot(detachedSignedQuotaPolicy),
    ).toThrow();

    const substitutedProjectSubject = cloneSnapshot(makeSnapshot());
    substitutedProjectSubject.conversation.projectScopeId =
      "eip155:1:juicebox-project:99";
    expect(() =>
      parseLockedApplicationAppendSnapshot(substitutedProjectSubject),
    ).toThrow();

    const duplicateScope = cloneSnapshot(makeSnapshot());
    duplicateScope.quotas[1].scope = "installation";
    expect(() => parseLockedApplicationAppendSnapshot(duplicateScope)).toThrow();

    const extraCounterField = cloneSnapshot(makeSnapshot());
    Object.assign(extraCounterField.quotas[0], { legacyLimit: "100" });
    expect(() =>
      parseLockedApplicationAppendSnapshot(extraCounterField),
    ).toThrow();

    const reordered = cloneSnapshot(makeSnapshot());
    reordered.quotas.reverse();
    reordered.quotaBindings.reverse();
    const parsed = parseLockedApplicationAppendSnapshot(reordered);
    expect(parsed.quotas.map(({ scope }) => scope)).toEqual(
      APPLICATION_APPEND_QUOTA_SCOPES,
    );
    expect(parsed.quotaBindings.map(({ scope }) => scope)).toEqual(
      APPLICATION_APPEND_QUOTA_SCOPES,
    );
  });

  it("binds the selected role credential and grant inclusion proof to the policy", () => {
    const snapshot = makeSnapshot();
    expect(snapshot.sendGrant.grantEvidenceDigest).toBe(
      computeConversationSendGrantEvidenceDigest(snapshot.sendGrant),
    );
    expect(snapshot.policyHead.authorizedSendGrantSetHash).toBe(
      AUTHORIZED_SEND_GRANT_SET_HASH,
    );
    expect(snapshot.policyHead.selectedSendGrantEvidenceDigest).toBe(
      snapshot.sendGrant.grantEvidenceDigest,
    );
    expect(snapshot.policyHead.selectedSendGrantInclusionEvidenceDigest).toBe(
      snapshot.sendGrant.grantInclusionEvidenceDigest,
    );

    for (const mutate of [
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.sendGrant.grantEvidenceDigest = hash(111);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.sendGrant.grantInclusionEvidenceDigest = hash(112);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.selectedSendGrantEvidenceDigest = hash(113);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.selectedSendGrantInclusionEvidenceDigest = hash(114);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.authorizedQuotaPolicyDigest = hash(115);
      },
    ]) {
      const candidate = cloneSnapshot(snapshot);
      mutate(candidate);
      expect(() => parseLockedApplicationAppendSnapshot(candidate)).toThrow();
    }
  });

  it("requires verified selected-grant inclusion for append-authorization proofs", () => {
    const snapshot = makeSnapshot();
    const expectation = policyProofExpectation(snapshot);
    const evidence = {
      status: "verified" as const,
      profile: "conversation-policy-head-proof.v1" as const,
      ...expectation,
      signedBodySha256: snapshot.policyHead.signedBodySha256,
      signerKeyId: snapshot.policyHead.signerKeyId,
      signatureSha256: snapshot.policyHead.signatureSha256,
      witnessCheckpointId: snapshot.policyHead.witnessCheckpointId,
      witnessedPolicyHeadHash: snapshot.policyHead.witnessedPolicyHeadHash,
      witnessEvidenceDigest: snapshot.policyHead.witnessEvidenceDigest,
      issuedAt: snapshot.policyHead.issuedAt,
      expiresAt: snapshot.policyHead.expiresAt,
      signatureStatus: "verified" as const,
      keyStatus: "valid-for-checkpoint" as const,
      witnessStatus: "verified" as const,
      freshnessStatus: "fresh" as const,
      currentStatus: "current" as const,
      policyConsistencyStatus: "verified" as const,
      policyConsistencyEvidenceDigest:
        snapshot.policyHead.policyConsistencyEvidenceDigest,
      sendGrantInclusionStatus: "verified" as const,
      evidenceDigest: snapshot.policyHead.proofEvidenceDigest,
    };

    expect(
      parsePolicyHeadProofEvidence(evidence, expectation),
    ).toMatchObject({
      sendGrantInclusionStatus: "verified",
      authorizedSendGrantSetHash: AUTHORIZED_SEND_GRANT_SET_HASH,
      selectedSendGrantEvidenceDigest:
        snapshot.sendGrant.grantEvidenceDigest,
      selectedSendGrantInclusionEvidenceDigest:
        snapshot.sendGrant.grantInclusionEvidenceDigest,
      authorizedQuotaPolicyDigest: snapshot.conversation.quotaPolicyDigest,
    });
    expect(() =>
      parsePolicyHeadProofEvidence(
        { ...evidence, sendGrantInclusionStatus: "not-requested" },
        expectation,
      ),
    ).toThrow();
  });
});

describe("locked append snapshot digest", () => {
  it("is deterministic, order-normalized, and changes across every locked component", () => {
    const base = makeSnapshot();
    const baseDigest = computeLockedApplicationAppendSnapshotDigest(base);
    expect(computeLockedApplicationAppendSnapshotDigest(base)).toBe(baseDigest);

    const reordered = cloneSnapshot(base);
    reordered.quotas.reverse();
    reordered.quotaBindings.reverse();
    expect(
      computeLockedApplicationAppendSnapshotDigest(
        parseLockedApplicationAppendSnapshot(reordered),
      ),
    ).toBe(baseDigest);

    const mutations: Array<{
      name: string;
      mutate: (
        snapshot: DeepMutable<LockedApplicationAppendSnapshot>,
      ) => void;
      refresh?: "proof" | "grant" | "quota";
    }> = [
      {
        name: "conversation realm",
        mutate: (snapshot) => {
          snapshot.conversation.realmId = "revnet-mainnet";
        },
        refresh: "quota",
      },
      {
        name: "conversation group",
        mutate: (snapshot) => {
          snapshot.conversation.groupIdHash = hash(80);
        },
      },
      {
        name: "membership credential revocation version",
        mutate: (snapshot) => {
          snapshot.membership.credentialRevocationVersion = uint("5");
        },
      },
      {
        name: "policy mandatory proposal set",
        mutate: (snapshot) => {
          snapshot.policyHead.mandatoryProposalCount = uint("1");
          snapshot.policyHead.mandatoryProposalSetHash = hash(81);
        },
        refresh: "proof",
      },
      {
        name: "send grant role",
        mutate: (snapshot) => {
          snapshot.sendGrant.role = "project-staff";
        },
        refresh: "grant",
      },
      {
        name: "pending removal count",
        mutate: (snapshot) => {
          snapshot.pendingRemovalCount = uint("1");
        },
      },
      {
        name: "conversation usage",
        mutate: (snapshot) => {
          snapshot.usage.envelopeBytes = uint("1001");
        },
      },
      {
        name: "authoritative quota binding and counter identity",
        mutate: (snapshot) => {
          snapshot.conversation.projectScopeId = "eip155:1:juicebox-project:43";
        },
        refresh: "quota",
      },
      {
        name: "quota counter",
        mutate: (snapshot) => {
          snapshot.quotas[3].operationCount = uint("2");
        },
      },
    ];

    for (const { name, mutate, refresh } of mutations) {
      const candidate = cloneSnapshot(base);
      mutate(candidate);
      if (refresh === "proof") refreshPolicyProofDigest(candidate);
      if (refresh === "grant") refreshGrantBindings(candidate);
      if (refresh === "quota") refreshQuotaBindings(candidate);
      const parsed = parseLockedApplicationAppendSnapshot(candidate);
      expect(
        computeLockedApplicationAppendSnapshotDigest(parsed),
        name,
      ).not.toBe(baseDigest);
    }
  });
});

describe("locked application append evaluation", () => {
  it("allows a fully bound append and returns the exact next usage and quota values", () => {
    const snapshot = makeSnapshot();
    const decision = evaluateLockedApplicationAppend(
      snapshot,
      makeExpectation(snapshot),
      NOW,
    );

    expect(decision).toMatchObject({
      status: "allowed",
      nextPosition: "11",
      nextUsage: {
        conversationId: CONVERSATION_ID,
        envelopeCount: "3",
        envelopeBytes: "1100",
        attachmentBytes: "125",
      },
    });
    if (decision.status !== "allowed") throw new Error("Expected allowed append.");
    expect(decision.postReservationQuotas).toHaveLength(
      APPLICATION_APPEND_QUOTA_SCOPES.length,
    );
    expect(decision.quotaCapacityDeltas).toHaveLength(
      APPLICATION_APPEND_QUOTA_SCOPES.length,
    );
    for (const quota of decision.postReservationQuotas) {
      expect(quota.operationCount).toBe("1");
      expect(quota.byteCount).toBe("100");
      expect(quota.reservedOperationCount).toBe("1");
      expect(quota.reservedByteCount).toBe("125");
      expect(quota.rowVersion).toBe("2");
    }
  });

  it("authorizes two senders from one grant-set root without making grants interchangeable", () => {
    const customer = makeSnapshot(
      "purchase_support",
      "customer",
      CUSTOMER_SENDER,
    );
    const staff = makeSnapshot(
      "purchase_support",
      "project-staff",
      STAFF_SENDER,
    );

    expect(customer.policyHead.authorizedSendGrantSetHash).toBe(
      staff.policyHead.authorizedSendGrantSetHash,
    );
    expect(customer.conversation.quotaPolicyDigest).toBe(
      staff.conversation.quotaPolicyDigest,
    );
    for (const scope of APPLICATION_APPEND_QUOTA_SCOPES) {
      const customerHash = customer.quotaBindings.find(
        (binding) => binding.scope === scope,
      )?.scopeHash;
      const staffHash = staff.quotaBindings.find(
        (binding) => binding.scope === scope,
      )?.scopeHash;
      if (scope === "installation" || scope === "account") {
        expect(customerHash, scope).not.toBe(staffHash);
      } else {
        expect(customerHash, scope).toBe(staffHash);
      }
    }
    expect(customer.policyHead.selectedSendGrantEvidenceDigest).not.toBe(
      staff.policyHead.selectedSendGrantEvidenceDigest,
    );
    expect(
      customer.policyHead.selectedSendGrantInclusionEvidenceDigest,
    ).not.toBe(staff.policyHead.selectedSendGrantInclusionEvidenceDigest);
    expect(
      evaluateLockedApplicationAppend(
        customer,
        makeExpectation(customer),
        NOW,
      ),
    ).toMatchObject({ status: "allowed" });
    expect(
      evaluateLockedApplicationAppend(staff, makeExpectation(staff), NOW),
    ).toMatchObject({ status: "allowed" });

    const detachedGrant = cloneSnapshot(customer);
    detachedGrant.sendGrant = structuredClone(staff.sendGrant);
    expect(() => parseLockedApplicationAppendSnapshot(detachedGrant)).toThrow();

    const crossGrant = cloneSnapshot(customer);
    crossGrant.sendGrant = structuredClone(staff.sendGrant);
    crossGrant.policyHead.selectedSendGrantEvidenceDigest =
      staff.policyHead.selectedSendGrantEvidenceDigest;
    crossGrant.policyHead.selectedSendGrantInclusionEvidenceDigest =
      staff.policyHead.selectedSendGrantInclusionEvidenceDigest;
    refreshPolicyProofDigest(crossGrant);
    const internallyProvedCrossGrant =
      parseLockedApplicationAppendSnapshot(crossGrant);
    expectRejected(
      internallyProvedCrossGrant,
      makeExpectation(customer),
      "send-grant-invalid",
    );
  });

  it("fails closed for every conversation CAS and release binding", () => {
    const snapshot = makeSnapshot();
    const mutations: Array<
      (expectation: DeepMutable<ApplicationAppendExpectation>) => void
    > = [
      (expectation) => {
        expectation.realmId = "revnet-mainnet";
      },
      (expectation) => {
        expectation.conversationId = OTHER_CONVERSATION_ID;
      },
      (expectation) => {
        expectation.releaseProfileId = parseReleaseProfileId("mls-other-v1");
      },
      (expectation) => {
        expectation.expectedDeliveryLimitsDigest = hash(90);
      },
      (expectation) => {
        expectation.expectedQuotaPolicyDigest = hash(93);
      },
      (expectation) => {
        expectation.expectedProjectScopeId = "eip155:1:juicebox-project:99";
      },
      (expectation) => {
        expectation.expectedTenantScopeId = "revnet-money";
      },
      (expectation) => {
        expectation.expectedGroupIdHash = hash(91);
      },
      (expectation) => {
        expectation.ifMatch = parseConversationEtag('"e8-r5"');
      },
      (expectation) => {
        expectation.expectedEpoch = uint("8");
      },
      (expectation) => {
        expectation.expectedRosterVersion = uint("6");
      },
      (expectation) => {
        expectation.expectedConfirmedTranscriptHash = hash(92);
      },
    ];

    for (const mutate of mutations) {
      const expectation = structuredClone(
        makeExpectation(snapshot),
      ) as DeepMutable<ApplicationAppendExpectation>;
      mutate(expectation);
      expectRejected(
        snapshot,
        expectation,
        "conversation-state-changed",
      );
    }

    for (const mutate of [
      (expectation: DeepMutable<ApplicationAppendExpectation>) => {
        expectation.policyEvaluationLogPosition = uint("9");
      },
      (expectation: DeepMutable<ApplicationAppendExpectation>) => {
        expectation.policyEvaluationLogHeadHash = hash(94);
      },
    ]) {
      const expectation = structuredClone(
        makeExpectation(snapshot),
      ) as DeepMutable<ApplicationAppendExpectation>;
      mutate(expectation);
      expectRejected(snapshot, expectation, "policy-head-not-current");
    }

    const badEtag = cloneSnapshot(snapshot);
    badEtag.conversation.etag = parseConversationEtag('"e7-r6"');
    expectRejected(
      badEtag,
      makeExpectation(snapshot),
      "conversation-state-invalid",
    );

    const suspended = cloneSnapshot(snapshot);
    suspended.conversation.state = "suspended";
    expectRejected(
      suspended,
      makeExpectation(snapshot),
      "conversation-not-active",
    );
  });

  it("requires an active joined membership and the exact live credential revision", () => {
    const base = makeSnapshot();
    const expectation = makeExpectation(base);

    const removed = cloneSnapshot(base);
    removed.membership.removedPosition = uint("9");
    expectRejected(removed, expectation, "sender-membership-inactive");

    const notYetJoined = cloneSnapshot(base);
    notYetJoined.membership.joinedPosition = uint("11");
    expectRejected(notYetJoined, expectation, "sender-membership-inactive");

    for (const mutate of [
      (candidate: DeepMutable<ApplicationAppendExpectation>) => {
        candidate.accountId = OTHER_ACCOUNT_ID;
      },
      (candidate: DeepMutable<ApplicationAppendExpectation>) => {
        candidate.installationId = OTHER_INSTALLATION_ID;
      },
      (candidate: DeepMutable<ApplicationAppendExpectation>) => {
        candidate.credentialId = OTHER_CREDENTIAL_ID;
      },
      (candidate: DeepMutable<ApplicationAppendExpectation>) => {
        candidate.credentialFingerprint = OTHER_CREDENTIAL_FINGERPRINT;
      },
      (candidate: DeepMutable<ApplicationAppendExpectation>) => {
        candidate.credentialRevocationVersion = uint("5");
      },
    ]) {
      const candidate = structuredClone(
        expectation,
      ) as DeepMutable<ApplicationAppendExpectation>;
      mutate(candidate);
      expectRejected(base, candidate, "sender-credential-mismatch");
    }

    for (const state of ["suspended", "revoked"] as const) {
      const candidate = cloneSnapshot(base);
      candidate.membership.installationState = state;
      expectRejected(candidate, expectation, "sender-credential-inactive");
    }
    for (const state of ["suspended", "revoked", "superseded"] as const) {
      const candidate = cloneSnapshot(base);
      candidate.membership.credentialState = state;
      expectRejected(candidate, expectation, "sender-credential-inactive");
    }

    const expired = cloneSnapshot(base);
    expired.membership.credentialExpiresAt = NOW;
    expectRejected(expired, expectation, "sender-credential-expired");
  });

  it("requires the role credential subject and validity interval for the selected sender", () => {
    const base = makeSnapshot();
    const expectation = makeExpectation(base);

    const wrongAccount = cloneSnapshot(base);
    wrongAccount.sendGrant.roleCredentialSubjectAccountId = OTHER_ACCOUNT_ID;
    expectRejected(wrongAccount, expectation, "send-grant-invalid");

    const wrongInstallation = cloneSnapshot(base);
    wrongInstallation.sendGrant.roleCredentialSubjectInstallationId =
      OTHER_INSTALLATION_ID;
    expectRejected(wrongInstallation, expectation, "send-grant-invalid");

    const notYetValid = cloneSnapshot(base);
    notYetValid.sendGrant.roleCredentialValidFrom = time(
      "2026-08-14T12:03:00.000Z",
    );
    expectRejected(notYetValid, expectation, "send-grant-invalid");

    const expired = cloneSnapshot(base);
    expired.sendGrant.roleCredentialValidUntil = NOW;
    expectRejected(expired, expectation, "send-grant-invalid");

    const inverted = cloneSnapshot(base);
    inverted.sendGrant.roleCredentialValidFrom = time(
      "2026-08-14T12:04:00.000Z",
    );
    inverted.sendGrant.roleCredentialValidUntil = time(
      "2026-08-14T12:03:00.000Z",
    );
    expectRejected(inverted, expectation, "send-grant-invalid");
  });

  it("enforces the conversation-kind send-role matrix", () => {
    const roles: readonly ConversationSendRole[] = [
      "customer",
      "project-staff",
      "publisher",
      "subscriber",
      "member",
      "moderator",
    ];
    const matrix: Record<
      LockedConversationState["kind"],
      readonly ConversationSendRole[]
    > = {
      purchase_support: ["customer", "project-staff"],
      announcement: ["publisher"],
      community: ["member", "moderator"],
    };

    for (const [kind, allowedRoles] of Object.entries(matrix) as Array<
      [LockedConversationState["kind"], readonly ConversationSendRole[]]
    >) {
      for (const role of roles) {
        const snapshot = makeSnapshot(kind, role);
        const decision = evaluateLockedApplicationAppend(
          snapshot,
          makeExpectation(snapshot),
          NOW,
        );
        if (allowedRoles.includes(role)) {
          expect(decision, `${kind}/${role}`).toMatchObject({ status: "allowed" });
        } else {
          expect(decision, `${kind}/${role}`).toEqual({
            status: "rejected",
            reasonCode: "send-grant-invalid",
          });
        }
      }
    }
  });

  it("requires a current fresh witnessed policy with no mandatory proposal or removal", () => {
    const base = makeSnapshot();
    const expectation = makeExpectation(base);

    for (const mutate of [
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.policyHeadHash = hash(101);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.epoch = uint("8");
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.rosterVersion = uint("6");
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.confirmedTranscriptHash = hash(102);
      },
      (candidate: DeepMutable<LockedApplicationAppendSnapshot>) => {
        candidate.policyHead.evaluationLogPosition = uint("9");
      },
    ]) {
      const candidate = cloneSnapshot(base);
      mutate(candidate);
      expectRejected(candidate, expectation, "policy-head-not-current");
    }

    const unwitnessed = cloneSnapshot(base);
    unwitnessed.policyHead.witnessState = "missing";
    unwitnessed.policyHead.witnessCheckpointId = null;
    unwitnessed.policyHead.witnessedPolicyHeadHash = null;
    expectRejected(unwitnessed, expectation, "policy-head-not-witnessed");

    const expired = cloneSnapshot(base);
    expired.policyHead.expiresAt = NOW;
    expectRejected(expired, expectation, "policy-head-expired");

    const issuedInFuture = cloneSnapshot(base);
    issuedInFuture.policyHead.issuedAt = time("2026-08-14T12:03:00.000Z");
    expectRejected(issuedInFuture, expectation, "policy-head-expired");

    const proposalPending = cloneSnapshot(base);
    proposalPending.policyHead.mandatoryProposalCount = uint("1");
    expectRejected(
      proposalPending,
      expectation,
      "mandatory-proposal-pending",
    );

    const removalPending = cloneSnapshot(base);
    removalPending.pendingRemovalCount = uint("1");
    expectRejected(removalPending, expectation, "removal-pending");

    const staleGrant = cloneSnapshot(base);
    staleGrant.sendGrant.policyRevision = uint("7");
    expectRejected(staleGrant, expectation, "send-grant-invalid");
  });

  it("binds every exact quota identity and treats windows as start-inclusive/end-exclusive", () => {
    const base = makeSnapshot();
    const expectation = makeExpectation(base);

    const substituted = cloneSnapshot(base);
    substituted.quotaBindings[0].scopeHash = hash(103);
    expectRejected(substituted, expectation, "quota-exceeded");

    const futureWindow = cloneSnapshot(base);
    futureWindow.quotaBindings[1].windowStartedAt = time(
      "2026-08-14T12:03:00.000Z",
    );
    futureWindow.quotas[1].windowStartedAt = time(
      "2026-08-14T12:03:00.000Z",
    );
    expectRejected(futureWindow, expectation, "quota-exceeded");

    expect(
      evaluateLockedApplicationAppend(base, expectation, WINDOW_START),
    ).toMatchObject({ status: "allowed" });

    const endingNow = cloneSnapshot(base);
    for (const binding of endingNow.quotaBindings) {
      binding.windowSeconds = uint("120");
    }
    for (const quota of endingNow.quotas) {
      quota.windowSeconds = uint("120");
    }
    expectRejected(endingNow, expectation, "quota-exceeded");

    const usageLimit = cloneSnapshot(base);
    usageLimit.usage.envelopeCountLimit = usageLimit.usage.envelopeCount;
    expectRejected(usageLimit, expectation, "quota-exceeded");

    const operationLimit = cloneSnapshot(base);
    operationLimit.quotas[2].operationLimit =
      operationLimit.quotas[2].operationCount;
    expectRejected(operationLimit, expectation, "quota-exceeded");

    const byteLimit = cloneSnapshot(base);
    byteLimit.quotas[3].byteLimit = uint("224");
    expectRejected(byteLimit, expectation, "quota-exceeded");
  });

  it("never wraps conversation, usage, or quota uint63 counters", () => {
    const base = makeSnapshot();
    const expectation = makeExpectation(base);

    const position = cloneSnapshot(base);
    position.conversation.lastPosition = UINT63_MAX_STRING;
    position.policyHead.evaluationLogPosition = UINT63_MAX_STRING;
    const positionExpectation = structuredClone(
      expectation,
    ) as DeepMutable<ApplicationAppendExpectation>;
    positionExpectation.policyEvaluationLogPosition = UINT63_MAX_STRING;
    expectRejected(position, positionExpectation, "counter-exhausted");

    for (const field of [
      "envelopeCount",
      "envelopeBytes",
      "attachmentBytes",
    ] as const) {
      const candidate = cloneSnapshot(base);
      candidate.usage[field] = UINT63_MAX_STRING;
      candidate.usage[`${field}Limit` as const] = UINT63_MAX_STRING;
      expectRejected(candidate, expectation, "counter-exhausted");
    }

    const quotaOperations = cloneSnapshot(base);
    quotaOperations.quotas[0].operationCount = UINT63_MAX_STRING;
    quotaOperations.quotas[0].operationLimit = UINT63_MAX_STRING;
    expectRejected(quotaOperations, expectation, "counter-exhausted");

    const quotaBytes = cloneSnapshot(base);
    quotaBytes.quotas[0].byteCount = UINT63_MAX_STRING;
    quotaBytes.quotas[0].byteLimit = UINT63_MAX_STRING;
    expectRejected(quotaBytes, expectation, "counter-exhausted");
  });
});

describe("locked application append state transition", () => {
  it("computes a strictly bounded pending expiry from every live authority", () => {
    const snapshot = makeSnapshot();
    expect(
      computeApplicationAppendPendingExpiresAt({
        snapshot,
        admissionStartedAt: time("2026-08-14T12:01:59.000Z"),
        authoritativeReceivedAt: NOW,
        activeSigningKeyValidUntil: time("2026-08-14T12:04:00.000Z"),
      }),
    ).toBe("2026-08-14T12:02:30.000Z");

    expect(() =>
      computeApplicationAppendPendingExpiresAt({
        snapshot,
        admissionStartedAt: time("2026-08-14T12:02:00.001Z"),
        authoritativeReceivedAt: NOW,
        activeSigningKeyValidUntil: time("2026-08-14T12:04:00.000Z"),
      }),
    ).toThrow(/time bound/i);
    expect(() =>
      computeApplicationAppendPendingExpiresAt({
        snapshot,
        admissionStartedAt: time("2026-08-14T12:01:59.000Z"),
        authoritativeReceivedAt: NOW,
        activeSigningKeyValidUntil: NOW,
      }),
    ).toThrow(/live interval/i);
  });

  it("reserves quota capacity by unique pending ownership and converts it once additively", () => {
    const prior = makeSnapshot();
    const expectation = makeExpectation(prior);
    const decision = evaluateLockedApplicationAppend(prior, expectation, NOW);
    if (decision.status !== "allowed") throw new Error("Expected allowed append.");
    const reservations = bindApplicationAppendQuotaCapacityReservations({
      deltas: decision.quotaCapacityDeltas,
      pendingPreparationDigest: PREPARATION_DIGEST,
      fenceGeneration: uint("1"),
      fenceTokenHash: FENCE_TOKEN_HASH,
    });
    expect(
      validateLockedApplicationAppendQuotaReservationTransition({
        priorSnapshot: prior,
        expectation,
        authoritativeReceivedAt: NOW,
        quotaCapacityReservations: reservations,
        preparedPostReservationQuotas: decision.postReservationQuotas,
      }),
    ).toEqual(decision.postReservationQuotas);

    const finalizedQuotas = decision.postReservationQuotas.map((quota) => ({
      ...quota,
      operationCount: uint("2"),
      byteCount: uint("225"),
      reservedOperationCount: uint("0"),
      reservedByteCount: uint("0"),
      rowVersion: uint("3"),
    }));
    const consumed = reservations.map((reservation) => ({
      ...reservation,
      state: "consumed" as const,
    }));
    expect(
      validateLockedApplicationAppendQuotaFinalizationTransition({
        currentQuotas: decision.postReservationQuotas,
        currentCapacityReservations: reservations,
        pendingPreparationDigest: PREPARATION_DIGEST,
        fenceGeneration: uint("1"),
        fenceTokenHash: FENCE_TOKEN_HASH,
        preparedFinalQuotas: finalizedQuotas,
        preparedFinalReservations: consumed,
      }),
    ).toEqual({ quotas: finalizedQuotas, reservations: consumed });

    expect(() =>
      validateLockedApplicationAppendQuotaFinalizationTransition({
        currentQuotas: finalizedQuotas,
        currentCapacityReservations: consumed,
        pendingPreparationDigest: PREPARATION_DIGEST,
        fenceGeneration: uint("1"),
        fenceTokenHash: FENCE_TOKEN_HASH,
        preparedFinalQuotas: finalizedQuotas,
        preparedFinalReservations: consumed,
      }),
    ).toThrow(/not owned/i);

    const released = reservations.map((reservation) => ({
      ...reservation,
      state: "released" as const,
    }));
    const releasedQuotas = decision.postReservationQuotas.map((quota) => ({
      ...quota,
      reservedOperationCount: uint("0"),
      reservedByteCount: uint("0"),
      rowVersion: uint("3"),
    }));
    expect(
      validateLockedApplicationAppendQuotaReleaseTransition({
        currentQuotas: decision.postReservationQuotas,
        currentCapacityReservations: reservations,
        pendingPreparationDigest: PREPARATION_DIGEST,
        fenceGeneration: uint("1"),
        fenceTokenHash: FENCE_TOKEN_HASH,
        preparedFinalQuotas: releasedQuotas,
        preparedFinalReservations: released,
      }),
    ).toEqual({ quotas: releasedQuotas, reservations: released });

    expect(() =>
      validateLockedApplicationAppendQuotaReleaseTransition({
        currentQuotas: decision.postReservationQuotas,
        currentCapacityReservations: reservations,
        pendingPreparationDigest: hash(99),
        fenceGeneration: uint("1"),
        fenceTokenHash: FENCE_TOKEN_HASH,
        preparedFinalQuotas: releasedQuotas,
        preparedFinalReservations: released,
      }),
    ).toThrow(/not owned/i);
  });

  it("derives fanout only from complete separately committed MLS and routing projections", () => {
    const snapshot = cloneSnapshot(makeSnapshot());
    const mlsRoster: ApplicationAppendMlsRosterProjection[] = [
      {
        conversationId: CONVERSATION_ID,
        conversationGeneration: uint("1"),
        rosterVersion: uint("5"),
        accountId: ACCOUNT_ID,
        installationId: INSTALLATION_ID,
        credentialId: CREDENTIAL_ID,
        credentialFingerprint: CREDENTIAL_FINGERPRINT,
      },
      {
        conversationId: CONVERSATION_ID,
        conversationGeneration: uint("1"),
        rosterVersion: uint("5"),
        accountId: OTHER_ACCOUNT_ID,
        installationId: OTHER_INSTALLATION_ID,
        credentialId: OTHER_CREDENTIAL_ID,
        credentialFingerprint: OTHER_CREDENTIAL_FINGERPRINT,
      },
      {
        conversationId: CONVERSATION_ID,
        conversationGeneration: uint("1"),
        rosterVersion: uint("5"),
        accountId: THIRD_ACCOUNT_ID,
        installationId: THIRD_INSTALLATION_ID,
        credentialId: THIRD_CREDENTIAL_ID,
        credentialFingerprint: THIRD_CREDENTIAL_FINGERPRINT,
      },
    ];
    const routes: ApplicationAppendRecipientProjection[] = mlsRoster.map(
      (member) => ({
        conversationId: member.conversationId,
        conversationGeneration: member.conversationGeneration,
        recipientSetVersion: uint("6"),
        accountId: member.accountId,
        installationId: member.installationId,
        credentialId: member.credentialId,
        credentialFingerprint: member.credentialFingerprint,
        credentialRevocationVersion:
          member.installationId === INSTALLATION_ID
            ? snapshot.membership.credentialRevocationVersion
            : uint("1"),
        credentialState: "active",
        credentialExpiresAt: CREDENTIAL_EXPIRES_AT,
        joinedPosition: uint("1"),
        removedPosition: null,
        installationState: "active",
      }),
    );
    snapshot.conversation.rosterHash = computeApplicationAppendMlsRosterHash(mlsRoster);
    snapshot.conversation.recipientSetHash =
      computeApplicationAppendRecipientSetHash(routes);
    snapshot.conversation.recipientSetVersion = uint("6");
    const plan = deriveApplicationAppendFanoutPlan({
      conversation: snapshot.conversation,
      senderMembership: snapshot.membership,
      position: uint("11"),
      authoritativeReceivedAt: NOW,
      recipientInstallationsMax: uint("2500"),
      mlsRosterProjections: mlsRoster,
      recipientProjections: routes,
    });
    expect(plan.recipientInstallationIds).toEqual(
      [INSTALLATION_ID, OTHER_INSTALLATION_ID, THIRD_INSTALLATION_ID].sort(),
    );

    const revokedRoutes = structuredClone(routes);
    revokedRoutes[2].credentialState = "revoked";
    revokedRoutes[2].credentialRevocationVersion = uint("2");
    snapshot.conversation.recipientSetVersion = uint("7");
    for (const route of revokedRoutes) route.recipientSetVersion = uint("7");
    snapshot.conversation.recipientSetHash =
      computeApplicationAppendRecipientSetHash(revokedRoutes);
    const revokedPlan = deriveApplicationAppendFanoutPlan({
      conversation: snapshot.conversation,
      senderMembership: snapshot.membership,
      position: uint("11"),
      authoritativeReceivedAt: NOW,
      recipientInstallationsMax: uint("2500"),
      mlsRosterProjections: mlsRoster,
      recipientProjections: revokedRoutes,
    });
    expect(revokedPlan.rosterHash).toBe(plan.rosterHash);
    expect(revokedPlan.recipientInstallationIds).not.toContain(
      THIRD_INSTALLATION_ID,
    );

    expect(() =>
      deriveApplicationAppendFanoutPlan({
        conversation: snapshot.conversation,
        senderMembership: snapshot.membership,
        position: uint("11"),
        authoritativeReceivedAt: NOW,
        recipientInstallationsMax: uint("2500"),
        mlsRosterProjections: mlsRoster,
        recipientProjections: revokedRoutes.slice(0, 2),
      }),
    ).toThrow(/incomplete|routing row/i);
  });

  it("accepts only the recomputed single-append transition", () => {
    const prior = makeSnapshot();
    const expectation = makeExpectation(prior);
    const prepared = preparedCommitProjection(prior, expectation);

    const validated = validateLockedApplicationAppendStateTransition({
      priorSnapshot: prior,
      expectation,
      authoritativeReceivedAt: NOW,
      nextHeadHash: NEXT_LOG_HEAD_HASH,
      preparedNextConversation: prepared.conversation,
      preparedNextUsage: prepared.usage,
      quotaCapacityReservations: prepared.quotaCapacityReservations,
    });

    expect(validated).toEqual(prepared);
    expect(validated.conversation.lastPosition).toBe("11");
    expect(validated.conversation.currentLogHeadHash).toBe(NEXT_LOG_HEAD_HASH);
  });

  it("rejects zero heads, rejected priors, and every unauthorized prepared change", () => {
    const prior = makeSnapshot();
    const expectation = makeExpectation(prior);
    const prepared = preparedCommitProjection(prior, expectation);

    expect(() =>
      validateLockedApplicationAppendStateTransition({
        priorSnapshot: prior,
        expectation,
        authoritativeReceivedAt: NOW,
        nextHeadHash: ZERO_HASH32,
        preparedNextConversation: prepared.conversation,
        preparedNextUsage: prepared.usage,
        quotaCapacityReservations: prepared.quotaCapacityReservations,
      }),
    ).toThrow();

    const suspendedPrior = cloneSnapshot(prior);
    suspendedPrior.conversation.state = "suspended";
    expect(() =>
      validateLockedApplicationAppendStateTransition({
        priorSnapshot: suspendedPrior,
        expectation,
        authoritativeReceivedAt: NOW,
        nextHeadHash: NEXT_LOG_HEAD_HASH,
        preparedNextConversation: prepared.conversation,
        preparedNextUsage: prepared.usage,
        quotaCapacityReservations: prepared.quotaCapacityReservations,
      }),
    ).toThrow(/Rejected append/);

    const mutations: Array<
      (projection: DeepMutable<LockedApplicationAppendCommitProjection>) => void
    > = [
      (projection) => {
        projection.conversation.currentLogHeadHash = hash(110);
      },
      (projection) => {
        projection.usage.envelopeBytes = uint("1101");
      },
      (projection) => {
        projection.quotaCapacityReservations[0].reservationId = hash(111);
      },
    ];
    for (const mutate of mutations) {
      const candidate = structuredClone(prepared) as DeepMutable<LockedApplicationAppendCommitProjection>;
      mutate(candidate);
      expect(() =>
        validateLockedApplicationAppendStateTransition({
          priorSnapshot: prior,
          expectation,
          authoritativeReceivedAt: NOW,
          nextHeadHash: NEXT_LOG_HEAD_HASH,
          preparedNextConversation: candidate.conversation,
          preparedNextUsage: candidate.usage,
          quotaCapacityReservations: candidate.quotaCapacityReservations,
        }),
      ).toThrow();
    }
  });
});
