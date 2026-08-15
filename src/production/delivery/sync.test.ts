import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";
import type {
  ConversationLogHeadProofVerificationRequest,
  ConversationPageProofVerificationRequest,
  ConversationPolicyReplayVerificationRequest,
  DeliveryInvariantIncidentPort,
  MlsCommitProjectionVerificationRequest,
  MlsStagedExternalProposalBinding,
} from "./ports";
import { DELIVERY_MANDATORY_PROPOSALS_MAX } from "./ports";
import { DELIVERY_TESTED_CEILINGS, parseDeliveryLimits } from "./limits";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  type EnvelopeLeafInput,
} from "./hashes";
import { computeDeliveryLimitsDigest } from "./state";
import { createUnavailableProductionDeliveryPorts } from "./unavailable";
import {
  CONVERSATION_CURSOR_PROFILE,
  CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  CONVERSATION_LOG_HEAD_HARD_MAX_SERIALIZED_BYTES,
  ConversationCursorExpiredError,
  ConversationCursorInvalidError,
  ConversationHistoryRetentionError,
  ConversationSyncDependencyTimeoutError,
  ConversationSyncDependencyUnavailableError,
  ConversationSyncValidationError,
  computeConversationLogHeadProofEvidenceDigest,
  computeConversationPageProofBundleEvidenceDigest,
  computeConversationVerifiedPrefixEvidenceDigest,
  computeConversationPolicyReplayEvidenceDigest,
  computeDeliveryCheckpointProofEvidenceDigest,
  computeDeliveryWitnessProofEvidenceDigest,
  computeMlsCommitProjectionEvidenceDigest,
  computePolicyMandatoryProposalSetHash,
  parseAndVerifyConversationLogHead,
  parseConversationPageProofEvidence,
  parseConversationPolicyReplayEvidence,
  parseEncodedConversationCursor,
  parseMlsCommitProjectionEvidence,
  parseAndVerifyConversationPageJson,
  type ConversationLogHeadProofEvidence,
  type ConversationLogHeadVerificationInput,
  type ConversationPageVerificationInput,
  type ConversationPolicyReplayEvidence,
  type ConversationSyncVerificationPorts,
  type ConversationVerifiedPrefixEvidenceInput,
  type MlsCommitProjectionEvidence,
} from "./sync";
import {
  DeliveryValidationError,
  UINT63_MAX_STRING,
  ZERO_HASH32,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  parseAccountId,
  parseCanonicalBase64Url,
  parseConversationId,
  parseCredentialId,
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
} from "./valueObjects";

const CONVERSATION_ID = parseConversationId(
  "c99daf46-89d8-4e84-aada-53a04fa111c9",
);
const ACCOUNT_ID = parseAccountId("7f94c690-2af4-4a45-a7cc-9d85ce6cbd26");
const INSTALLATION_ID = parseInstallationId(
  "5ec2d18e-f082-48f0-8b01-55e43fed021c",
);
const CREDENTIAL_ID = parseCredentialId(
  "c3c82f16-bf3c-45e0-8518-ca1bf6ab3b66",
);
const ENVELOPE_ID = parseEnvelopeId("415609f1-9662-49f6-9cda-9ef319abe51d");
const OTHER_ENVELOPE_ID = parseEnvelopeId(
  "525609f1-9662-49f6-9cda-9ef319abe51d",
);
const POLICY_HEAD_ID = parsePolicyHeadId(
  "a4d721f6-8af9-4d82-afbe-e509e9a3fc2f",
);
const WITNESS_CHECKPOINT_ID = parseWitnessCheckpointId(
  "b4d721f6-8af9-4d82-afbe-e509e9a3fc2f",
);
const PROPOSAL_ID = parseProposalId(
  "0198a5d7-4c58-7e31-bbf1-0fd4c09e4acf",
);
const INTENT_ID = parseMembershipIntentId(
  "0198a5d8-4c58-7e31-bbf1-0fd4c09e4acf",
);
const NOW = parseRfc3339Millis("2026-08-14T16:20:45.123Z");
const DEADLINE = parseRfc3339Millis("2026-08-14T16:20:55.123Z");
const RELEASE_PROFILE_ID = parseReleaseProfileId("fictional-release.v1");

function hash(byte: number) {
  return parseHash32(Buffer.alloc(32, byte).toString("base64url"));
}

function policyReplayFixture(options: {
  eventClass?: "application" | "external_proposal" | "mls_commit";
  pageStartSequence?: string;
  pageEndSequence?: string;
  highWaterSequence?: string;
  includeMandatoryTransition?: boolean;
} = {}) {
  const eventClass = options.eventClass ?? "external_proposal";
  const startSequence = parseUint63String(options.pageStartSequence ?? "20");
  const endSequence = parseUint63String(options.pageEndSequence ?? "21");
  const highWaterSequence = parseUint63String(
    options.highWaterSequence ?? "100",
  );
  const mandatory = Object.freeze([
    Object.freeze({ proposalId: PROPOSAL_ID, proposalHash: hash(20) }),
  ]);
  const startPolicy = Object.freeze({
    policyHeadId: POLICY_HEAD_ID,
    policyHeadSequence: startSequence,
    policyHeadHash: hash(21),
    deliveryLogPosition: parseUint63String("5"),
    deliveryLogHeadHash: hash(5),
    mandatoryProposals: Object.freeze([]),
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessEvidenceDigest: hash(22),
  });
  const endPolicy = Object.freeze({
    policyHeadId: parsePolicyHeadId("c4d721f6-8af9-4d82-afbe-e509e9a3fc2f"),
    policyHeadSequence: endSequence,
    policyHeadHash: hash(23),
    deliveryLogPosition: parseUint63String("6"),
    deliveryLogHeadHash: hash(6),
    mandatoryProposals:
      options.includeMandatoryTransition === false
        ? Object.freeze([])
        : mandatory,
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessEvidenceDigest: hash(24),
  });
  const event = Object.freeze({
    position: parseUint63String("6"),
    envelopeId: ENVELOPE_ID,
    envelopeClass: eventClass,
    envelopeSha256: hash(25),
    headHash: hash(6),
  });
  const request: ConversationPolicyReplayVerificationRequest = Object.freeze({
    profile: "conversation-policy-replay.v1",
    realmId: "fictional-lab" as never,
    conversationGeneration: parseUint63String("1"),
    releaseProfileId: RELEASE_PROFILE_ID,
    deliveryLimitsDigest: hash(26),
    releaseTrustRootDigest: hash(27),
    conversationId: CONVERSATION_ID,
    pageStartPosition: parseUint63String("5"),
    pageStartHeadHash: hash(5),
    pageStartPolicy: startPolicy,
    pageEndPosition: parseUint63String("6"),
    pageEndHeadHash: hash(6),
    pageEndPolicy: endPolicy,
    policyLogHighWaterSequence: highWaterSequence,
    policyLogHighWaterHash: hash(100),
    policyLogHighWaterWitnessCheckpointId: WITNESS_CHECKPOINT_ID,
    policyLogHighWaterWitnessEvidenceDigest: hash(28),
    events: Object.freeze([event]),
    verifiedAt: NOW,
    deadline: DEADLINE,
    signal: new AbortController().signal,
  });
  const transitions =
    options.includeMandatoryTransition === false
      ? Object.freeze([])
      : Object.freeze([endPolicy]);
  const base = {
    realmId: request.realmId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    deliveryLimitsDigest: request.deliveryLimitsDigest,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    conversationId: request.conversationId,
    pageStartPosition: request.pageStartPosition,
    pageStartHeadHash: request.pageStartHeadHash,
    pageStartPolicy: request.pageStartPolicy,
    pageEndPosition: request.pageEndPosition,
    pageEndHeadHash: request.pageEndHeadHash,
    pageEndPolicy: request.pageEndPolicy,
    policyLogHighWaterSequence: request.policyLogHighWaterSequence,
    policyLogHighWaterHash: request.policyLogHighWaterHash,
    policyLogHighWaterWitnessCheckpointId:
      request.policyLogHighWaterWitnessCheckpointId,
    policyLogHighWaterWitnessEvidenceDigest:
      request.policyLogHighWaterWitnessEvidenceDigest,
    events: request.events,
    transitions,
    transitionCompactionStatus: "verified-complete" as const,
    transitionRangeProofDigest: hash(29),
    historicalIntervalStatus: "verified" as const,
    applicationCutoffStatus: "verified" as const,
    policyConsistencyStatus: "verified" as const,
    policyConsistencyEvidenceDigest: hash(30),
    verifiedAt: request.verifiedAt,
  } satisfies Omit<
    ConversationPolicyReplayEvidence,
    "profile" | "evidenceDigest"
  >;
  const evidence = Object.freeze({
    status: "verified" as const,
    profile: "conversation-policy-replay.v1" as const,
    ...base,
    evidenceDigest: computeConversationPolicyReplayEvidenceDigest(base),
  });
  return { request, evidence, mandatory };
}

function stagedProposal(): MlsStagedExternalProposalBinding {
  return Object.freeze({
    position: parseUint63String("6"),
    envelopeId: ENVELOPE_ID,
    envelopeSha256: hash(31),
    epoch: parseUint63String("20"),
    proposalId: PROPOSAL_ID,
    proposalHash: hash(20),
    authorizationRecordHash: hash(32),
    membershipIntentId: INTENT_ID,
    membershipIntentHash: hash(33),
    membershipIntentEvidenceDigest: hash(34),
    proposalType: "remove",
    proposalRequirement: "mandatory",
    authorizingPolicyHeadSequence: parseUint63String("21"),
    authorizingPolicyHeadHash: hash(23),
  });
}

function commitFixture() {
  const proposal = stagedProposal();
  const target = Object.freeze({
    accountId: ACCOUNT_ID,
    installationId: INSTALLATION_ID,
    credentialId: CREDENTIAL_ID,
    credentialFingerprint: parseFingerprint32(hash(35)),
  });
  const request: MlsCommitProjectionVerificationRequest = Object.freeze({
    profile: "mls-commit-projection.v1",
    realmId: "fictional-lab" as never,
    conversationGeneration: parseUint63String("1"),
    releaseProfileId: RELEASE_PROFILE_ID,
    releaseTrustRootDigest: hash(27),
    expectedGroupIdHash: hash(36),
    conversationId: CONVERSATION_ID,
    position: parseUint63String("7"),
    envelopeId: OTHER_ENVELOPE_ID,
    envelopeBytes: parseCanonicalBase64Url(
      Buffer.from("exact commit").toString("base64url"),
    ),
    envelopeSha256: hash(37),
    expectedAccountId: ACCOUNT_ID,
    expectedInstallationId: INSTALLATION_ID,
    expectedCredentialId: CREDENTIAL_ID,
    expectedCredentialFingerprint: target.credentialFingerprint,
    expectedCredentialRevocationVersion: parseUint63String("4"),
    expectedSenderGeneration: parseUint63String("2"),
    commitEpoch: parseUint63String("20"),
    commitRosterVersion: parseUint63String("28"),
    previousEpoch: parseUint63String("20"),
    previousRosterVersion: parseUint63String("28"),
    previousConfirmedTranscriptHash: hash(38),
    baseConfirmedTranscriptHash: hash(38),
    resultingConfirmedTranscriptHash: hash(39),
    stagedProposals: Object.freeze([proposal]),
    requiredProposals: Object.freeze([
      Object.freeze({ proposalId: proposal.proposalId, proposalHash: proposal.proposalHash }),
    ]),
    creatorBootstrapTarget: null,
    removalTarget: target,
    deadline: DEADLINE,
    signal: new AbortController().signal,
  });
  const committedIntent = Object.freeze({
    membershipIntentId: proposal.membershipIntentId,
    membershipIntentHash: proposal.membershipIntentHash,
    membershipIntentEvidenceDigest: proposal.membershipIntentEvidenceDigest,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    commitPosition: request.position,
    commitEnvelopeId: request.envelopeId,
    commitEnvelopeSha256: request.envelopeSha256,
  });
  const base = {
    realmId: request.realmId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    expectedGroupIdHash: request.expectedGroupIdHash,
    conversationId: request.conversationId,
    position: request.position,
    envelopeId: request.envelopeId,
    envelopeSha256: request.envelopeSha256,
    expectedAccountId: request.expectedAccountId,
    expectedInstallationId: request.expectedInstallationId,
    expectedCredentialId: request.expectedCredentialId,
    expectedCredentialFingerprint: request.expectedCredentialFingerprint,
    expectedCredentialRevocationVersion:
      request.expectedCredentialRevocationVersion,
    expectedSenderGeneration: request.expectedSenderGeneration,
    authenticatedCredentialId: request.expectedCredentialId,
    authenticatedCredentialFingerprint: request.expectedCredentialFingerprint,
    authenticatedCredentialRevocationVersion:
      request.expectedCredentialRevocationVersion,
    authenticatedSenderGeneration: request.expectedSenderGeneration,
    senderBindingStatus: "verified" as const,
    commitEpoch: request.commitEpoch,
    commitRosterVersion: request.commitRosterVersion,
    previousEpoch: request.previousEpoch,
    previousRosterVersion: request.previousRosterVersion,
    previousConfirmedTranscriptHash: request.previousConfirmedTranscriptHash,
    baseConfirmedTranscriptHash: request.baseConfirmedTranscriptHash,
    resultingConfirmedTranscriptHash: request.resultingConfirmedTranscriptHash,
    commitKind: "membership" as const,
    resultingEpoch: parseUint63String("21"),
    resultingRosterVersion: parseUint63String("29"),
    stagedProposals: request.stagedProposals,
    requiredProposals: request.requiredProposals,
    consumedProposals: request.stagedProposals,
    committedIntents: Object.freeze([committedIntent]),
    proposalConsumptionStatus: "verified" as const,
    intentBindingStatus: "verified" as const,
    creatorBootstrapTarget: null,
    creatorMembershipStatus: "not-applicable" as const,
    removalTarget: target,
    removalProposalId: proposal.proposalId,
    removalProposalHash: proposal.proposalHash,
    removalMembershipStatus: "verified-absent" as const,
    projectionStatus: "verified" as const,
  } satisfies Omit<MlsCommitProjectionEvidence, "profile" | "evidenceDigest">;
  const evidence = Object.freeze({
    status: "verified" as const,
    profile: "mls-commit-projection.v1" as const,
    ...base,
    evidenceDigest: computeMlsCommitProjectionEvidenceDigest(base),
  });
  return { request, evidence, base, committedIntent };
}

function currentTimes(waitMilliseconds = 5_000) {
  const nowMilliseconds = Date.now();
  return {
    now: parseRfc3339Millis(new Date(nowMilliseconds - 1).toISOString()),
    deadline: parseRfc3339Millis(
      new Date(nowMilliseconds + waitMilliseconds).toISOString(),
    ),
  };
}

function prefixFixture(
  senderBindings: ConversationVerifiedPrefixEvidenceInput["mlsCommitSenderBindings"] = [],
) {
  const limits = parseDeliveryLimits({ ...DELIVERY_TESTED_CEILINGS });
  const cursorContext = Object.freeze({
    realmId: "fictional-lab" as never,
    accountId: ACCOUNT_ID,
    installationId: INSTALLATION_ID,
    conversationId: CONVERSATION_ID,
    routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  });
  const membership = Object.freeze({
    bootstrapMode: "creator" as const,
    credentialId: CREDENTIAL_ID,
    credentialFingerprint: parseFingerprint32(hash(35)),
    joinedPosition: parseUint63String("1"),
    removedPosition: null,
  });
  const anchor = Object.freeze({
    position: parseUint63String("0"),
    previousHeadHash: ZERO_HASH32,
    headHash: ZERO_HASH32,
    checkpointReceivedAt: null,
  });
  const trustedWitnessAnchor = Object.freeze({
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessTreeSize: parseUint63String("1"),
    witnessRootHash: hash(50),
    witnessedAt: NOW,
  });
  const trustedPolicyAnchor = Object.freeze({
    policyHeadSequence: parseUint63String("1"),
    policyHeadHash: hash(51),
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessEvidenceDigest: hash(52),
  });
  const mlsProjectionAtAnchor = Object.freeze({
    epoch: parseUint63String("0"),
    rosterVersion: parseUint63String("0"),
    confirmedTranscriptHash: hash(53),
  });
  const policyProjectionAtAnchor = Object.freeze({
    etag: '"e0-r0"' as never,
    policyHeadId: POLICY_HEAD_ID,
    policyRevision: parseUint63String("1"),
    policyMandatoryProposalCount: parseUint63String("0"),
    policyMandatoryProposalSetHash: ZERO_HASH32,
    policyMandatoryProposals: Object.freeze([]),
    policyAuthorizedSendGrantSetHash: hash(54),
    policyAuthorizedQuotaPolicyDigest: hash(55),
    policyHeadSequence: parseUint63String("1"),
    policyHeadHash: hash(51),
    policyDeliveryLogPosition: parseUint63String("0"),
    policyDeliveryLogHeadHash: ZERO_HASH32,
    policyWitnessCheckpointId: WITNESS_CHECKPOINT_ID,
    policyWitnessEvidenceDigest: hash(52),
  });
  const prefix = {
    cursorContext,
    membership,
    anchor,
    trustedWitnessAnchor,
    trustedPolicyAnchor,
    mlsProjectionAtAnchor,
    policyProjectionAtAnchor,
    mlsCommitSenderBindings: senderBindings,
    stagedProposalsAtAnchor: Object.freeze([]),
    conversationGeneration: parseUint63String("1"),
    releaseProfileId: RELEASE_PROFILE_ID,
    deliveryLimitsDigest: computeDeliveryLimitsDigest(limits),
    releaseTrustRootDigest: hash(56),
    expectedGroupIdHash: hash(57),
  } satisfies ConversationVerifiedPrefixEvidenceInput;
  return { limits, prefix };
}

function pageVerificationFixture(
  overrides: Partial<ConversationPageVerificationInput> = {},
): ConversationPageVerificationInput {
  const { limits, prefix } = prefixFixture();
  const times = currentTimes();
  return {
    ...prefix,
    requestedCursor: null,
    requestedLimit: parseUint63String("1"),
    retainedFloor: parseUint63String("1"),
    verifiedPrefixEvidenceDigest:
      computeConversationVerifiedPrefixEvidenceDigest(prefix),
    now: times.now,
    deadline: times.deadline,
    signal: new AbortController().signal,
    limits,
    ...overrides,
  };
}

function unavailableSyncPorts(): ConversationSyncVerificationPorts {
  const production = createUnavailableProductionDeliveryPorts();
  return {
    cursorCodec: production.conversationCursorCodec,
    pageProofVerifier: production.conversationPageProofVerifier,
    policyHeadProofVerifier: production.policyHeadProofVerifier,
    policyReplayVerifier: production.conversationPolicyReplayVerifier,
    mlsCommitProjectionVerifier: production.mlsCommitProjectionVerifier,
    mlsExternalProposalVerifier: production.mlsExternalProposalVerifier,
    invariantIncident: production.invariantIncident,
  };
}

function encodedCursor() {
  return `cc1.${Buffer.alloc(29, 7).toString("base64url")}`;
}

function signature(byte: number) {
  return Buffer.alloc(64, byte).toString("base64url");
}

function joinPageFixture(bootstrapMode: "creator" | "welcome") {
  const baseInput = pageVerificationFixture();
  const membership = Object.freeze({
    ...baseInput.membership,
    bootstrapMode,
  });
  const input = {
    ...baseInput,
    membership,
    verifiedPrefixEvidenceDigest:
      computeConversationVerifiedPrefixEvidenceDigest({
        ...baseInput,
        membership,
      }),
  };
  const envelopeBytes = new TextEncoder().encode("exact creator/join Commit");
  const envelopeSha256 = computeEnvelopeSha256(envelopeBytes);
  const receivedAt = parseRfc3339Millis("2026-08-14T16:20:44.123Z");
  const envelopeBase = {
    conversationId: CONVERSATION_ID,
    position: parseUint63String("1"),
    envelopeId: ENVELOPE_ID,
    envelopeClass: "mls_commit" as const,
    contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
    envelopeBytes: Buffer.from(envelopeBytes).toString("base64url"),
    envelopeSha256,
    epoch: parseUint63String("0"),
    rosterVersion: parseUint63String("0"),
    sender: Object.freeze({
      type: "installation" as const,
      accountId: ACCOUNT_ID,
      installationId: INSTALLATION_ID,
    }),
    receivedAt,
    previousHeadHash: ZERO_HASH32,
    baseConfirmedTranscriptHash:
      input.mlsProjectionAtAnchor.confirmedTranscriptHash,
    resultingConfirmedTranscriptHash: hash(70),
    logSigningKeyId: "delivery-key-1",
    logHeadSignature: signature(1),
  };
  const leafInput = {
    conversationId: envelopeBase.conversationId,
    position: envelopeBase.position,
    envelopeId: envelopeBase.envelopeId,
    envelopeClass: envelopeBase.envelopeClass,
    sender: envelopeBase.sender,
    epoch: envelopeBase.epoch,
    rosterVersion: envelopeBase.rosterVersion,
    contentType: envelopeBase.contentType,
    envelopeSha256: envelopeBase.envelopeSha256,
    receivedAt: envelopeBase.receivedAt,
  } satisfies EnvelopeLeafInput;
  const leafHash = computeEnvelopeLeafHash(leafInput);
  const headHash = computeLogHeadHash(ZERO_HASH32, leafHash);
  const logCheckpointDigest = computeDeliveryLogCheckpointDigest({
    conversationId: CONVERSATION_ID,
    position: envelopeBase.position,
    previousHeadHash: ZERO_HASH32,
    headHash,
    signingKeyId: envelopeBase.logSigningKeyId as never,
  });
  const envelope = {
    ...envelopeBase,
    leafHash,
    headHash,
    logCheckpointDigest,
  };
  const witnessReceipt = {
    conversationId: CONVERSATION_ID,
    position: "1",
    headHash,
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessTreeSize: "2",
    witnessRootHash: hash(71),
    witnessKeyId: "witness-key-1",
    witnessSignature: signature(2),
    witnessedAt: "2026-08-14T16:20:45.000Z",
  };
  const page = {
    events: [envelope],
    nextCursor: encodedCursor(),
    hasMore: false,
    snapshot: {
      conversationId: CONVERSATION_ID,
      generation: "1",
      releaseProfileId: RELEASE_PROFILE_ID,
      deliveryLimitsDigest: input.deliveryLimitsDigest,
      etag: '"e1-r1"',
      epoch: "1",
      rosterVersion: "1",
      confirmedTranscriptHash: envelopeBase.resultingConfirmedTranscriptHash,
      policyHeadId: POLICY_HEAD_ID,
      policyRevision: "1",
      policyMandatoryProposalCount: "0",
      policyMandatoryProposalSetHash: ZERO_HASH32,
      policyMandatoryProposals: [],
      policyAuthorizedSendGrantSetHash: hash(54),
      policyAuthorizedQuotaPolicyDigest: hash(55),
      policyHeadSequence: "2",
      policyHeadHash: hash(72),
      policyDeliveryLogPosition: "1",
      policyDeliveryLogHeadHash: headHash,
      policyWitnessCheckpointId: WITNESS_CHECKPOINT_ID,
      policyWitnessEvidenceDigest: hash(73),
      logHead: {
        position: "1",
        previousHeadHash: ZERO_HASH32,
        headHash,
        signingKeyId: envelopeBase.logSigningKeyId,
        checkpointDigest: logCheckpointDigest,
        signature: envelopeBase.logHeadSignature,
        checkpointReceivedAt: receivedAt,
      },
      witnessReceipt,
    },
  };
  return { input, page };
}

function maxEmptyPageFixture() {
  const original = pageVerificationFixture();
  const anchor = Object.freeze({
    position: UINT63_MAX_STRING,
    previousHeadHash: hash(201),
    headHash: hash(202),
    checkpointReceivedAt: parseRfc3339Millis(
      "2026-08-14T16:20:44.123Z",
    ),
  });
  const membership = Object.freeze({
    ...original.membership,
    removedPosition: UINT63_MAX_STRING,
  });
  const policyProjectionAtAnchor = Object.freeze({
    ...original.policyProjectionAtAnchor,
    policyDeliveryLogPosition: UINT63_MAX_STRING,
    policyDeliveryLogHeadHash: anchor.headHash,
  });
  const prefix = {
    cursorContext: original.cursorContext,
    membership,
    anchor,
    trustedWitnessAnchor: original.trustedWitnessAnchor,
    trustedPolicyAnchor: original.trustedPolicyAnchor,
    mlsProjectionAtAnchor: original.mlsProjectionAtAnchor,
    policyProjectionAtAnchor,
    mlsCommitSenderBindings: original.mlsCommitSenderBindings,
    stagedProposalsAtAnchor: original.stagedProposalsAtAnchor,
    conversationGeneration: original.conversationGeneration,
    releaseProfileId: original.releaseProfileId,
    deliveryLimitsDigest: original.deliveryLimitsDigest,
    releaseTrustRootDigest: original.releaseTrustRootDigest,
    expectedGroupIdHash: original.expectedGroupIdHash,
  } satisfies ConversationVerifiedPrefixEvidenceInput;
  const input: ConversationPageVerificationInput = Object.freeze({
    ...original,
    ...prefix,
    requestedCursor: encodedCursor(),
    verifiedPrefixEvidenceDigest:
      computeConversationVerifiedPrefixEvidenceDigest(prefix),
  });
  const signingKeyId = parseSigningKeyId("delivery-key-1");
  const checkpointDigest = computeDeliveryLogCheckpointDigest({
    conversationId: CONVERSATION_ID,
    position: anchor.position,
    previousHeadHash: anchor.previousHeadHash,
    headHash: anchor.headHash,
    signingKeyId,
  });
  const witnessReceipt = Object.freeze({
    conversationId: CONVERSATION_ID,
    position: anchor.position,
    headHash: anchor.headHash,
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessTreeSize: "2",
    witnessRootHash: hash(203),
    witnessKeyId: "witness-key-1",
    witnessSignature: signature(7),
    witnessedAt: "2026-08-14T16:20:45.000Z",
  });
  const page = Object.freeze({
    events: Object.freeze([]),
    nextCursor: encodedCursor(),
    hasMore: false,
    snapshot: Object.freeze({
      conversationId: CONVERSATION_ID,
      generation: original.conversationGeneration,
      releaseProfileId: original.releaseProfileId,
      deliveryLimitsDigest: original.deliveryLimitsDigest,
      etag: policyProjectionAtAnchor.etag,
      epoch: original.mlsProjectionAtAnchor.epoch,
      rosterVersion: original.mlsProjectionAtAnchor.rosterVersion,
      confirmedTranscriptHash:
        original.mlsProjectionAtAnchor.confirmedTranscriptHash,
      policyHeadId: policyProjectionAtAnchor.policyHeadId,
      policyRevision: policyProjectionAtAnchor.policyRevision,
      policyMandatoryProposalCount:
        policyProjectionAtAnchor.policyMandatoryProposalCount,
      policyMandatoryProposalSetHash:
        policyProjectionAtAnchor.policyMandatoryProposalSetHash,
      policyMandatoryProposals:
        policyProjectionAtAnchor.policyMandatoryProposals,
      policyAuthorizedSendGrantSetHash:
        policyProjectionAtAnchor.policyAuthorizedSendGrantSetHash,
      policyAuthorizedQuotaPolicyDigest:
        policyProjectionAtAnchor.policyAuthorizedQuotaPolicyDigest,
      policyHeadSequence: policyProjectionAtAnchor.policyHeadSequence,
      policyHeadHash: policyProjectionAtAnchor.policyHeadHash,
      policyDeliveryLogPosition:
        policyProjectionAtAnchor.policyDeliveryLogPosition,
      policyDeliveryLogHeadHash:
        policyProjectionAtAnchor.policyDeliveryLogHeadHash,
      policyWitnessCheckpointId:
        policyProjectionAtAnchor.policyWitnessCheckpointId,
      policyWitnessEvidenceDigest:
        policyProjectionAtAnchor.policyWitnessEvidenceDigest,
      logHead: Object.freeze({
        position: anchor.position,
        previousHeadHash: anchor.previousHeadHash,
        headHash: anchor.headHash,
        signingKeyId,
        checkpointDigest,
        signature: signature(8),
        checkpointReceivedAt: anchor.checkpointReceivedAt,
      }),
      witnessReceipt,
    }),
  });
  return { input, page };
}

function pageBytes(page: unknown) {
  return new TextEncoder().encode(JSON.stringify(page));
}

function logHeadProofEvidence(
  request: ConversationLogHeadProofVerificationRequest,
  mutate?: (input: {
    checkpoint: Record<string, unknown>;
    witness: Record<string, unknown>;
  }) => void,
) {
  const checkpointBase = {
    position: request.current.position,
    previousHeadHash: request.current.previousHeadHash,
    headHash: request.current.headHash,
    signingKeyId: request.current.signingKeyId,
    checkpointDigest: request.current.checkpointDigest,
    signatureSha256: computeEnvelopeSha256(
      Buffer.from(request.current.signature, "base64url"),
    ),
    checkpointReceivedAt: request.current.checkpointReceivedAt,
    signatureStatus: "verified" as const,
    keyStatus: "valid-for-checkpoint" as const,
  };
  const checkpoint: Record<string, unknown> = {
    ...checkpointBase,
    evidenceDigest: computeDeliveryCheckpointProofEvidenceDigest({
      conversationId: request.conversationId,
      verifiedAt: request.verifiedAt,
      ...checkpointBase,
    }),
  };
  const witnessBase = {
    position: request.witness.position,
    headHash: request.witness.headHash,
    witnessCheckpointId: request.witness.witnessCheckpointId,
    witnessTreeSize: request.witness.witnessTreeSize,
    witnessRootHash: request.witness.witnessRootHash,
    witnessKeyId: request.witness.witnessKeyId,
    witnessSignatureSha256: computeEnvelopeSha256(
      Buffer.from(request.witness.witnessSignature, "base64url"),
    ),
    witnessedAt: request.witness.witnessedAt,
    priorWitnessCheckpointId: request.priorWitness.witnessCheckpointId,
    priorWitnessTreeSize: request.priorWitness.witnessTreeSize,
    priorWitnessRootHash: request.priorWitness.witnessRootHash,
    signatureStatus: "verified" as const,
    keyStatus: "valid-for-checkpoint" as const,
    inclusionStatus: "verified" as const,
    consistencyStatus: "verified" as const,
    freshnessStatus: "fresh" as const,
  };
  const witness: Record<string, unknown> = {
    ...witnessBase,
    evidenceDigest: computeDeliveryWitnessProofEvidenceDigest({
      conversationId: request.conversationId,
      verifiedAt: request.verifiedAt,
      ...witnessBase,
    }),
  };
  mutate?.({ checkpoint, witness });
  checkpoint.evidenceDigest = computeDeliveryCheckpointProofEvidenceDigest({
    conversationId: request.conversationId,
    verifiedAt: request.verifiedAt,
    ...checkpoint,
  } as Parameters<typeof computeDeliveryCheckpointProofEvidenceDigest>[0]);
  witness.evidenceDigest = computeDeliveryWitnessProofEvidenceDigest({
    conversationId: request.conversationId,
    verifiedAt: request.verifiedAt,
    ...witness,
  } as Parameters<typeof computeDeliveryWitnessProofEvidenceDigest>[0]);
  const base = {
    realmId: request.realmId,
    accountId: request.accountId,
    installationId: request.installationId,
    conversationId: request.conversationId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    verifiedPrefixEvidenceDigest: request.verifiedPrefixEvidenceDigest,
    membershipBootstrapMode: request.membershipBootstrapMode,
    membershipCredentialId: request.membershipCredentialId,
    membershipCredentialFingerprint:
      request.membershipCredentialFingerprint,
    membershipJoinedPosition: request.membershipJoinedPosition,
    membershipRemovedPosition: request.membershipRemovedPosition,
    visibilityStatus:
      request.visibilityMode === "active-high-water"
        ? ("active-high-water" as const)
        : ("removed-exact" as const),
    fromPosition: request.fromPosition,
    fromHeadHash: request.fromHeadHash,
    currentPosition: request.current.position,
    currentHeadHash: request.current.headHash,
    appendOnlyConsistencyStatus: "verified" as const,
    appendOnlyConsistencyEvidenceDigest: hash(80),
    checkpoint,
    witness,
    verifiedAt: request.verifiedAt,
  } as unknown as Omit<
    ConversationLogHeadProofEvidence,
    "profile" | "evidenceDigest"
  >;
  return {
    status: "verified" as const,
    profile: "conversation-log-head-proof.v1" as const,
    ...base,
    evidenceDigest: computeConversationLogHeadProofEvidenceDigest(base),
  };
}

type LogHeadProofEvidenceBase = Omit<
  ConversationLogHeadProofEvidence,
  "profile" | "evidenceDigest"
>;

function substituteLogHeadProofEvidence(
  request: ConversationLogHeadProofVerificationRequest,
  substitute: (base: LogHeadProofEvidenceBase) => LogHeadProofEvidenceBase,
) {
  const original = logHeadProofEvidence(request);
  const {
    status: _status,
    profile: _profile,
    evidenceDigest: _evidenceDigest,
    ...originalBase
  } = original;
  void _status;
  void _profile;
  void _evidenceDigest;
  const substitutedBase = substitute(originalBase);
  return Object.freeze({
    status: "verified" as const,
    profile: "conversation-log-head-proof.v1" as const,
    ...substitutedBase,
    evidenceDigest:
      computeConversationLogHeadProofEvidenceDigest(substitutedBase),
  });
}

function logHeadFixture(mode: "active" | "removed" = "active") {
  const { input: pageInput, page } = joinPageFixture("creator");
  const times = currentTimes();
  const logHead = structuredClone(page.snapshot.logHead);
  const witnessReceipt = {
    ...structuredClone(page.snapshot.witnessReceipt),
    witnessedAt: times.now,
  };
  const membership = Object.freeze({
    ...pageInput.membership,
    removedPosition:
      mode === "removed" ? parseUint63String("1") : null,
  });
  const input: ConversationLogHeadVerificationInput = Object.freeze({
    cursorContext: pageInput.cursorContext,
    membership,
    verifiedPrefixEvidenceDigest: pageInput.verifiedPrefixEvidenceDigest,
    conversationGeneration: pageInput.conversationGeneration,
    releaseProfileId: pageInput.releaseProfileId,
    releaseTrustRootDigest: pageInput.releaseTrustRootDigest,
    fromAnchor: Object.freeze({
      position: parseUint63String(logHead.position),
      previousHeadHash: logHead.previousHeadHash,
      headHash: logHead.headHash,
      checkpointReceivedAt: logHead.checkpointReceivedAt,
    }),
    trustedWitnessAnchor: Object.freeze({
      witnessCheckpointId: witnessReceipt.witnessCheckpointId,
      witnessTreeSize: parseUint63String(witnessReceipt.witnessTreeSize),
      witnessRootHash: witnessReceipt.witnessRootHash,
      witnessedAt: witnessReceipt.witnessedAt,
    }),
    now: times.now,
    deadline: times.deadline,
    signal: new AbortController().signal,
  });
  const response = Object.freeze({
    conversationId: CONVERSATION_ID,
    generation: "1",
    releaseProfileId: RELEASE_PROFILE_ID,
    releaseTrustRootDigest: pageInput.releaseTrustRootDigest,
    visibility:
      mode === "active" ? "active-high-water" : "removed-boundary",
    logHead,
    witnessReceipt,
  });
  return { input, response };
}

function logHeadPorts(
  verify: (
    request: ConversationLogHeadProofVerificationRequest,
  ) => Promise<unknown> = (request) =>
    Promise.resolve(logHeadProofEvidence(request)),
  record: DeliveryInvariantIncidentPort["record"] = vi.fn(() =>
    Promise.resolve({ status: "recorded" }),
  ),
) {
  return {
    logHeadProofVerifier: { verify },
    invariantIncident: { record },
  };
}

function uuidV4(index: number) {
  return `10000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function uuidV7(index: number) {
  return `0198a5d7-0000-7000-8000-${index.toString(16).padStart(12, "0")}`;
}

function pageProofBoundaryFixture() {
  const signingKeyId = parseSigningKeyId("delivery-key-1");
  const proofSignature = parseEd25519Signature(signature(5));
  const checkpointReceivedAt = parseRfc3339Millis(
    "2026-08-14T16:20:44.000Z",
  );
  const checkpoints = Object.freeze(
    Array.from({ length: 501 }, (_, index) => {
      const position = parseUint63String((index + 1).toString(10));
      return Object.freeze({
        conversationId: CONVERSATION_ID,
        position,
        previousHeadHash: index === 0 ? ZERO_HASH32 : hash(90),
        headHash: hash(91),
        signingKeyId,
        checkpointDigest: hash(92),
        signature: proofSignature,
        checkpointReceivedAt,
      });
    }),
  );
  const priorWitness = Object.freeze({
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessTreeSize: parseUint63String("1"),
    witnessRootHash: hash(93),
    witnessedAt: NOW,
  });
  const witness = Object.freeze({
    conversationId: CONVERSATION_ID,
    position: parseUint63String("501"),
    headHash: hash(91),
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessTreeSize: parseUint63String("501"),
    witnessRootHash: hash(94),
    witnessKeyId: parseSigningKeyId("witness-key-1"),
    witnessSignature: parseEd25519Signature(signature(6)),
    witnessedAt: NOW,
  });
  const request: ConversationPageProofVerificationRequest = Object.freeze({
    profile: "conversation-page-proof-bundle.v1",
    realmId: "fictional-lab" as never,
    conversationId: CONVERSATION_ID,
    conversationGeneration: parseUint63String("1"),
    releaseProfileId: RELEASE_PROFILE_ID,
    releaseTrustRootDigest: hash(56),
    checkpoints,
    witness,
    priorWitness,
    witnessTrustMode: "continuity",
    targetWelcome: null,
    verifiedAt: NOW,
    deadline: DEADLINE,
    signal: new AbortController().signal,
  });
  const checkpointEvidence = checkpoints.map((checkpoint) => {
    const base = {
      position: checkpoint.position,
      previousHeadHash: checkpoint.previousHeadHash,
      headHash: checkpoint.headHash,
      signingKeyId: checkpoint.signingKeyId,
      checkpointDigest: checkpoint.checkpointDigest,
      signatureSha256: computeEnvelopeSha256(
        Buffer.from(checkpoint.signature, "base64url"),
      ),
      checkpointReceivedAt: checkpoint.checkpointReceivedAt,
      signatureStatus: "verified" as const,
      keyStatus: "valid-for-checkpoint" as const,
    };
    return Object.freeze({
      ...base,
      evidenceDigest: computeDeliveryCheckpointProofEvidenceDigest({
        conversationId: CONVERSATION_ID,
        verifiedAt: NOW,
        ...base,
      }),
    });
  });
  const witnessBase = {
    position: witness.position,
    headHash: witness.headHash,
    witnessCheckpointId: witness.witnessCheckpointId,
    witnessTreeSize: witness.witnessTreeSize,
    witnessRootHash: witness.witnessRootHash,
    witnessKeyId: witness.witnessKeyId,
    witnessSignatureSha256: computeEnvelopeSha256(
      Buffer.from(witness.witnessSignature, "base64url"),
    ),
    witnessedAt: witness.witnessedAt,
    priorWitnessCheckpointId: priorWitness.witnessCheckpointId,
    priorWitnessTreeSize: priorWitness.witnessTreeSize,
    priorWitnessRootHash: priorWitness.witnessRootHash,
    signatureStatus: "verified" as const,
    keyStatus: "valid-for-checkpoint" as const,
    inclusionStatus: "verified" as const,
    consistencyStatus: "verified" as const,
    freshnessStatus: "fresh" as const,
  };
  const witnessEvidence = Object.freeze({
    ...witnessBase,
    evidenceDigest: computeDeliveryWitnessProofEvidenceDigest({
      conversationId: CONVERSATION_ID,
      verifiedAt: NOW,
      ...witnessBase,
    }),
  });
  const evidence = Object.freeze({
    status: "verified" as const,
    profile: "conversation-page-proof-bundle.v1" as const,
    realmId: request.realmId,
    conversationId: request.conversationId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    verifiedAt: request.verifiedAt,
    checkpoints: Object.freeze(checkpointEvidence),
    witness: witnessEvidence,
    targetWelcome: null,
    bundleEvidenceDigest: computeConversationPageProofBundleEvidenceDigest({
      realmId: request.realmId,
      conversationId: request.conversationId,
      conversationGeneration: request.conversationGeneration,
      releaseProfileId: request.releaseProfileId,
      releaseTrustRootDigest: request.releaseTrustRootDigest,
      verifiedAt: request.verifiedAt,
      checkpointEvidenceDigests: checkpointEvidence.map(
        ({ evidenceDigest }) => evidenceDigest,
      ),
      witnessEvidenceDigest: witnessEvidence.evidenceDigest,
      targetWelcomeEvidenceDigest: null,
    }),
  });
  return { request, evidence };
}

function policyReplayBoundaryFixture() {
  const required = Object.freeze([
    Object.freeze({ proposalId: PROPOSAL_ID, proposalHash: hash(95) }),
  ]);
  const pageStartPolicy = Object.freeze({
    policyHeadId: parsePolicyHeadId(uuidV4(1)),
    policyHeadSequence: parseUint63String("1"),
    policyHeadHash: hash(96),
    deliveryLogPosition: parseUint63String("0"),
    deliveryLogHeadHash: ZERO_HASH32,
    mandatoryProposals: Object.freeze([]),
    witnessCheckpointId: WITNESS_CHECKPOINT_ID,
    witnessEvidenceDigest: hash(97),
  });
  const events = Object.freeze(
    Array.from({ length: 500 }, (_, index) =>
      Object.freeze({
        position: parseUint63String((index + 1).toString(10)),
        envelopeId: parseEnvelopeId(uuidV4(index + 1_000)),
        envelopeClass: "mls_commit" as const,
        envelopeSha256: hash(98),
        headHash: hash((index % 100) + 100),
      }),
    ),
  );
  const transitions = Object.freeze(
    Array.from({ length: 501 }, (_, index) => {
      const deliveryLogPosition = parseUint63String(index.toString(10));
      return Object.freeze({
        policyHeadId: parsePolicyHeadId(uuidV4(index + 2_000)),
        policyHeadSequence: parseUint63String((index + 2).toString(10)),
        policyHeadHash: hash((index % 100) + 120),
        deliveryLogPosition,
        deliveryLogHeadHash:
          index === 0 ? ZERO_HASH32 : events[index - 1]!.headHash,
        mandatoryProposals:
          index % 2 === 0 ? required : Object.freeze([]),
        witnessCheckpointId: WITNESS_CHECKPOINT_ID,
        witnessEvidenceDigest: hash((index % 100) + 140),
      });
    }),
  );
  const pageEndPolicy = transitions.at(-1)!;
  const request: ConversationPolicyReplayVerificationRequest = Object.freeze({
    profile: "conversation-policy-replay.v1",
    realmId: "fictional-lab" as never,
    conversationGeneration: parseUint63String("1"),
    releaseProfileId: RELEASE_PROFILE_ID,
    deliveryLimitsDigest: hash(26),
    releaseTrustRootDigest: hash(27),
    conversationId: CONVERSATION_ID,
    pageStartPosition: parseUint63String("0"),
    pageStartHeadHash: ZERO_HASH32,
    pageStartPolicy,
    pageEndPosition: parseUint63String("500"),
    pageEndHeadHash: events.at(-1)!.headHash,
    pageEndPolicy,
    policyLogHighWaterSequence: pageEndPolicy.policyHeadSequence,
    policyLogHighWaterHash: pageEndPolicy.policyHeadHash,
    policyLogHighWaterWitnessCheckpointId: WITNESS_CHECKPOINT_ID,
    policyLogHighWaterWitnessEvidenceDigest: hash(28),
    events,
    verifiedAt: NOW,
    deadline: DEADLINE,
    signal: new AbortController().signal,
  });
  const base = {
    realmId: request.realmId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    deliveryLimitsDigest: request.deliveryLimitsDigest,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    conversationId: request.conversationId,
    pageStartPosition: request.pageStartPosition,
    pageStartHeadHash: request.pageStartHeadHash,
    pageStartPolicy: request.pageStartPolicy,
    pageEndPosition: request.pageEndPosition,
    pageEndHeadHash: request.pageEndHeadHash,
    pageEndPolicy: request.pageEndPolicy,
    policyLogHighWaterSequence: request.policyLogHighWaterSequence,
    policyLogHighWaterHash: request.policyLogHighWaterHash,
    policyLogHighWaterWitnessCheckpointId:
      request.policyLogHighWaterWitnessCheckpointId,
    policyLogHighWaterWitnessEvidenceDigest:
      request.policyLogHighWaterWitnessEvidenceDigest,
    events: request.events,
    transitions,
    transitionCompactionStatus: "verified-complete" as const,
    transitionRangeProofDigest: hash(29),
    historicalIntervalStatus: "verified" as const,
    applicationCutoffStatus: "verified" as const,
    policyConsistencyStatus: "verified" as const,
    policyConsistencyEvidenceDigest: hash(30),
    verifiedAt: request.verifiedAt,
  } satisfies Omit<
    ConversationPolicyReplayEvidence,
    "profile" | "evidenceDigest"
  >;
  const evidence = Object.freeze({
    status: "verified" as const,
    profile: "conversation-policy-replay.v1" as const,
    ...base,
    evidenceDigest: computeConversationPolicyReplayEvidenceDigest(base),
  });
  return { request, evidence };
}

describe("conversation policy replay evidence", () => {
  it("keeps historical replay valid after a newer persisted policy high-water", () => {
    const { request, evidence } = policyReplayFixture();
    expect(parseConversationPolicyReplayEvidence(evidence, request)).toMatchObject({
      pageEndPolicy: { policyHeadSequence: "21" },
      policyLogHighWaterSequence: "100",
      transitionCompactionStatus: "verified-complete",
    });
  });

  it("rejects an application after a witnessed mandatory cutoff", () => {
    const { request, evidence } = policyReplayFixture();
    const application = Object.freeze({
      position: parseUint63String("7"),
      envelopeId: OTHER_ENVELOPE_ID,
      envelopeClass: "application" as const,
      envelopeSha256: hash(42),
      headHash: hash(7),
    });
    const substitutedRequest = Object.freeze({
      ...request,
      pageEndPosition: application.position,
      pageEndHeadHash: application.headHash,
      events: Object.freeze([...request.events, application]),
    });
    const base = Object.fromEntries(
      Object.entries(evidence).filter(
        ([key]) => !["status", "profile", "evidenceDigest"].includes(key),
      ),
    ) as unknown as Omit<
      ConversationPolicyReplayEvidence,
      "profile" | "evidenceDigest"
    >;
    const substitutedBase = {
      ...base,
      pageEndPosition: substitutedRequest.pageEndPosition,
      pageEndHeadHash: substitutedRequest.pageEndHeadHash,
      events: substitutedRequest.events,
    } satisfies Omit<
      ConversationPolicyReplayEvidence,
      "profile" | "evidenceDigest"
    >;
    const substituted = {
      status: "verified" as const,
      profile: "conversation-policy-replay.v1" as const,
      ...substitutedBase,
      evidenceDigest:
        computeConversationPolicyReplayEvidenceDigest(substitutedBase),
    };
    expect(() =>
      parseConversationPolicyReplayEvidence(substituted, substitutedRequest),
    ).toThrow(
      /application traffic after a cutoff/i,
    );
  });

  it("rejects page-end policy rollback even when mandatory sets are equal", () => {
    const { request, evidence } = policyReplayFixture({
      pageStartSequence: "100",
      pageEndSequence: "50",
      highWaterSequence: "100",
      includeMandatoryTransition: false,
    });
    expect(() => parseConversationPolicyReplayEvidence(evidence, request)).toThrow(
      /rolls back/i,
    );
  });

  it("commits the exact ordered mandatory ID/hash list", () => {
    const first = Object.freeze({ proposalId: PROPOSAL_ID, proposalHash: hash(40) });
    const second = Object.freeze({
      proposalId: parseProposalId("0198a5d9-4c58-7e31-bbf1-0fd4c09e4acf"),
      proposalHash: hash(41),
    });
    expect(computePolicyMandatoryProposalSetHash([])).toBe(ZERO_HASH32);
    expect(computePolicyMandatoryProposalSetHash([first, second])).not.toBe(
      computePolicyMandatoryProposalSetHash([second, first]),
    );
  });

  it("accepts the reviewed page-start plus 500-event transition boundary", () => {
    const { request, evidence } = policyReplayBoundaryFixture();
    expect(parseConversationPolicyReplayEvidence(evidence, request)).toMatchObject({
      events: expect.arrayContaining([expect.objectContaining({ position: "500" })]),
      transitions: expect.arrayContaining([
        expect.objectContaining({ deliveryLogPosition: "500" }),
      ]),
    });
    expect(evidence.events).toHaveLength(500);
    expect(evidence.transitions).toHaveLength(501);
  });

  it("uses a dedicated mandatory queue bound at hashing and replay boundaries", () => {
    const maximum = Array.from(
      { length: DELIVERY_MANDATORY_PROPOSALS_MAX },
      (_, index) => ({
        proposalId: parseProposalId(uuidV7(index + 1)),
        proposalHash: hash((index % 200) + 1),
      }),
    );
    expect(() => computePolicyMandatoryProposalSetHash(maximum)).not.toThrow();
    expect(() =>
      computePolicyMandatoryProposalSetHash([
        ...maximum,
        {
          proposalId: parseProposalId(
            uuidV7(DELIVERY_MANDATORY_PROPOSALS_MAX + 1),
          ),
          proposalHash: hash(250),
        },
      ]),
    ).toThrow(/queue.*bound/i);
  });
});

describe("conversation page proof count boundary", () => {
  it("accepts 500 event checkpoints plus the signed page snapshot", () => {
    const { request, evidence } = pageProofBoundaryFixture();
    expect(parseConversationPageProofEvidence(evidence, request).checkpoints).toHaveLength(
      501,
    );
  });
});

describe("MLS Commit intent and proposal binding", () => {
  it("accepts a one-to-one intent/proposal/Commit binding", () => {
    const { request, evidence } = commitFixture();
    expect(parseMlsCommitProjectionEvidence(evidence, request)).toMatchObject({
      intentBindingStatus: "verified",
      committedIntents: [{ membershipIntentId: INTENT_ID }],
    });
  });

  it("rejects a self-consistent proof that points the intent at another Commit", () => {
    const { request, base, committedIntent } = commitFixture();
    const substitutedBase = {
      ...base,
      committedIntents: Object.freeze([
        Object.freeze({
          ...committedIntent,
          commitEnvelopeId: ENVELOPE_ID,
        }),
      ]),
    } satisfies Omit<MlsCommitProjectionEvidence, "profile" | "evidenceDigest">;
    const substituted = {
      status: "verified" as const,
      profile: "mls-commit-projection.v1" as const,
      ...substitutedBase,
      evidenceDigest:
        computeMlsCommitProjectionEvidenceDigest(substitutedBase),
    };
    expect(() => parseMlsCommitProjectionEvidence(substituted, request)).toThrow(
      /membership target evidence is incomplete/i,
    );
  });

  it("rejects an omitted required proposal even when the verifier says consumed", () => {
    const { request, base } = commitFixture();
    const substitutedRequest = {
      ...request,
      stagedProposals: Object.freeze([]),
    } satisfies MlsCommitProjectionVerificationRequest;
    const substitutedBase = {
      ...base,
      stagedProposals: Object.freeze([]),
      consumedProposals: Object.freeze([]),
      committedIntents: Object.freeze([]),
    } satisfies Omit<MlsCommitProjectionEvidence, "profile" | "evidenceDigest">;
    const substituted = {
      status: "verified" as const,
      profile: "mls-commit-projection.v1" as const,
      ...substitutedBase,
      evidenceDigest:
        computeMlsCommitProjectionEvidenceDigest(substitutedBase),
    };
    expect(() =>
      parseMlsCommitProjectionEvidence(substituted, substitutedRequest),
    ).toThrow(/mandatory proposal set/i);
  });
});

describe("caller-visible conversation log head", () => {
  it("verifies an active high-water and an exact removed-member boundary", async () => {
    const active = logHeadFixture("active");
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(active.response),
        active.input,
        logHeadPorts(),
      ),
    ).resolves.toMatchObject({
      visibility: "active-high-water",
      logHead: { position: "1" },
      proofEvidence: { appendOnlyConsistencyStatus: "verified" },
    });

    const removed = logHeadFixture("removed");
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(removed.response),
        removed.input,
        logHeadPorts(),
      ),
    ).resolves.toMatchObject({
      visibility: "removed-boundary",
      logHead: { position: "1" },
    });
  });

  it("rejects a concealed join or rollback and records only a bounded incident", async () => {
    const concealed = logHeadFixture("active");
    const concealedInput = {
      ...concealed.input,
      membership: Object.freeze({
        ...concealed.input.membership,
        joinedPosition: parseUint63String("2"),
      }),
    };
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(concealed.response),
        concealedInput,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);

    const rollback = logHeadFixture("active");
    let recordedIncident:
      | Parameters<DeliveryInvariantIncidentPort["record"]>[0]
      | undefined;
    const record = vi.fn(
      (incident: Parameters<DeliveryInvariantIncidentPort["record"]>[0]) => {
        recordedIncident = incident;
        return Promise.resolve({ status: "recorded" });
      },
    );
    const rollbackInput = {
      ...rollback.input,
      fromAnchor: Object.freeze({
        position: parseUint63String("2"),
        previousHeadHash: hash(81),
        headHash: hash(82),
        checkpointReceivedAt: rollback.input.fromAnchor.checkpointReceivedAt,
      }),
    };
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(rollback.response),
        rollbackInput,
        logHeadPorts(undefined, record),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    expect(record).toHaveBeenCalledOnce();
    expect(recordedIncident).toMatchObject({
      incidentCode: "conversation-log-fork",
      conversationId: CONVERSATION_ID,
    });
    expect(recordedIncident).not.toHaveProperty("cursor");

    const visibility = logHeadFixture("active");
    const visibilityIncident = vi.fn(
      (input: Parameters<DeliveryInvariantIncidentPort["record"]>[0]) => {
        void input;
        return Promise.resolve({ status: "recorded" });
      },
    );
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes({ ...visibility.response, visibility: "removed-boundary" }),
        visibility.input,
        logHeadPorts(undefined, visibilityIncident),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    expect(visibilityIncident).toHaveBeenCalledWith(
      expect.objectContaining({ incidentCode: "conversation-log-fork" }),
    );
  });

  it("rejects checkpoint and witness substitutions even with recomputed evidence digests", async () => {
    const fixture = logHeadFixture("active");
    const checkpointPorts = logHeadPorts((request) =>
      Promise.resolve(
        logHeadProofEvidence(request, ({ checkpoint }) => {
          checkpoint.signatureSha256 = hash(83);
        }),
      ),
    );
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(fixture.response),
        fixture.input,
        checkpointPorts,
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);

    const witnessPorts = logHeadPorts((request) =>
      Promise.resolve(
        logHeadProofEvidence(request, ({ witness }) => {
          witness.witnessRootHash = hash(84);
        }),
      ),
    );
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(fixture.response),
        fixture.input,
        witnessPorts,
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
  });

  it("fails before invoking a dependency after the absolute deadline", async () => {
    const fixture = logHeadFixture("active");
    const verify = vi.fn(() => Promise.resolve({ status: "verified" }));
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(fixture.response),
        { ...fixture.input, deadline: fixture.input.now },
        logHeadPorts(verify),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    [
      "durable prefix digest",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        verifiedPrefixEvidenceDigest: hash(204),
      }),
    ],
    [
      "account",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        accountId: parseAccountId(
          "8f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
        ),
      }),
    ],
    [
      "installation",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        installationId: parseInstallationId(
          "6ec2d18e-f082-48f0-8b01-55e43fed021c",
        ),
      }),
    ],
    [
      "membership credential",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        membershipCredentialId: parseCredentialId(
          "d3c82f16-bf3c-45e0-8518-ca1bf6ab3b66",
        ),
      }),
    ],
    [
      "joined position",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        membershipJoinedPosition: parseUint63String("2"),
      }),
    ],
    [
      "active/removed boundary",
      (base: LogHeadProofEvidenceBase) => ({
        ...base,
        membershipRemovedPosition: parseUint63String("1"),
      }),
    ],
  ] satisfies readonly (readonly [
    string,
    (base: LogHeadProofEvidenceBase) => LogHeadProofEvidenceBase,
  ])[])("rejects a substituted log-head %s", async (_label, substitute) => {
    const fixture = logHeadFixture("active");
    const ports = logHeadPorts((request) =>
      Promise.resolve(substituteLogHeadProofEvidence(request, substitute)),
    );
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(fixture.response),
        fixture.input,
        ports,
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
  });

  it("accepts only bounded strict JSON bytes and sanitizes fulfilled hostile proof objects", async () => {
    const fixture = logHeadFixture("active");
    await expect(
      parseAndVerifyConversationLogHead(
        fixture.response,
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    await expect(
      parseAndVerifyConversationLogHead(
        new TextEncoder().encode('{"conversationId":"x","conversationId":"y"}'),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    await expect(
      parseAndVerifyConversationLogHead(
        Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    await expect(
      parseAndVerifyConversationLogHead(
        new TextEncoder().encode("{}{}"),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    await expect(
      parseAndVerifyConversationLogHead(
        new Uint8Array(CONVERSATION_LOG_HEAD_HARD_MAX_SERIALIZED_BYTES + 1),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);

    const hostile = new Proxy(Object.create(null) as Record<string, unknown>, {
      ownKeys() {
        throw new DeliveryValidationError("secret proof adapter detail");
      },
    });
    const promise = parseAndVerifyConversationLogHead(
      pageBytes(fixture.response),
      fixture.input,
      logHeadPorts(() => Promise.resolve(hostile)),
    );
    await expect(promise).rejects.toBeInstanceOf(ConversationSyncValidationError);
    await expect(promise).rejects.not.toThrow(/secret proof adapter detail/i);
  });

  it("rejects positive signed heads with zero heads or invalid genesis predecessors", async () => {
    const fixture = logHeadFixture("active");
    const invalidPredecessor = structuredClone(fixture.response);
    invalidPredecessor.logHead.position = "2" as never;
    invalidPredecessor.logHead.previousHeadHash = ZERO_HASH32;
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(invalidPredecessor),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);

    const zeroHead = structuredClone(fixture.response);
    zeroHead.logHead.headHash = ZERO_HASH32;
    zeroHead.logHead.checkpointDigest = computeDeliveryLogCheckpointDigest({
      conversationId: CONVERSATION_ID,
      position: parseUint63String(zeroHead.logHead.position),
      previousHeadHash: zeroHead.logHead.previousHeadHash,
      headHash: ZERO_HASH32,
      signingKeyId: parseSigningKeyId(zeroHead.logHead.signingKeyId),
    });
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(zeroHead),
        fixture.input,
        logHeadPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
  });

  it("caps best-effort incident recording independently of the request deadline", async () => {
    const fixture = logHeadFixture("active");
    const rollbackInput = {
      ...fixture.input,
      fromAnchor: Object.freeze({
        position: parseUint63String("2"),
        previousHeadHash: hash(205),
        headHash: hash(206),
        checkpointReceivedAt: fixture.input.fromAnchor.checkpointReceivedAt,
      }),
    };
    const record = vi.fn(() => new Promise<never>(() => undefined));
    const startedAt = Date.now();
    await expect(
      parseAndVerifyConversationLogHead(
        pageBytes(fixture.response),
        rollbackInput,
        logHeadPorts(undefined, record),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
    expect(record).toHaveBeenCalledOnce();
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });
});

describe("conversation sync boundary hardening", () => {
  it("accepts the 43-character minimum cursor and rejects 42 characters", () => {
    const { limits } = prefixFixture();
    const minimumCursor = `cc1.${Buffer.alloc(29, 9).toString("base64url")}`;
    expect(minimumCursor).toHaveLength(43);
    expect(parseEncodedConversationCursor(minimumCursor, limits)).toBe(
      minimumCursor,
    );
    expect(() =>
      parseEncodedConversationCursor(minimumCursor.slice(0, -1), limits),
    ).toThrow();
  });

  it("allows a terminal empty page at uint63 max without increment overflow", async () => {
    const { input, page } = maxEmptyPageFixture();
    const ports = unavailableSyncPorts();
    let decodeCalls = 0;
    ports.cursorCodec = {
      ...ports.cursorCodec,
      decode: () => {
        decodeCalls += 1;
        if (decodeCalls > 1) {
          return Promise.resolve({
            status: "unavailable",
            reasonCode: "not-configured",
          });
        }
        const now = Date.parse(input.now);
        return Promise.resolve({
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          encodedCursor: input.requestedCursor,
          ...input.cursorContext,
          lastReturnedPosition: UINT63_MAX_STRING,
          issuedAt: new Date(now - 1_000).toISOString(),
          expiresAt: new Date(now + 60_000).toISOString(),
          keyId: "cursor-key-1",
          authenticated: true,
        });
      },
    };
    await expect(
      parseAndVerifyConversationPageJson(pageBytes(page), input, ports),
    ).rejects.toBeInstanceOf(ConversationSyncDependencyUnavailableError);
    expect(decodeCalls).toBe(2);
  });

  it("accepts a creator bootstrap Commit without inventing a Welcome", async () => {
    const { input, page } = joinPageFixture("creator");
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(page),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncDependencyUnavailableError);
  });

  it("requires the exact target Welcome for a non-creator join", async () => {
    const { input, page } = joinPageFixture("welcome");
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(page),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toThrow(/expected target Welcome is missing/i);

    const foreignTarget = structuredClone(page) as unknown as {
      events: Array<Record<string, unknown>>;
    };
    const welcome = Buffer.from("target Welcome");
    foreignTarget.events[0]!.welcome = {
      targetInstallationId: parseInstallationId(
        "6ec2d18e-f082-48f0-8b01-55e43fed021c",
      ),
      welcome: welcome.toString("base64url"),
      welcomeSha256: computeEnvelopeSha256(welcome),
    };
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(foreignTarget),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toThrow(/another installation/i);
  });

  it("rejects a forked predecessor and a detached page-end snapshot", async () => {
    const { input, page } = joinPageFixture("creator");
    const forked = structuredClone(page);
    forked.events[0]!.previousHeadHash = hash(74);
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(forked),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);

    const detached = structuredClone(page);
    detached.snapshot.logHead.checkpointReceivedAt =
      "2026-08-14T16:20:43.123Z" as never;
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(detached),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toThrow(/page-prefix head/i);
  });

  it("rejects reserved zero hashes for positive prefix and snapshot policy heads", async () => {
    const { prefix } = prefixFixture();
    expect(() =>
      computeConversationVerifiedPrefixEvidenceDigest({
        ...prefix,
        policyProjectionAtAnchor: Object.freeze({
          ...prefix.policyProjectionAtAnchor,
          policyHeadHash: ZERO_HASH32,
        }),
      }),
    ).toThrow(/reserved zero hash/i);

    const { input, page } = joinPageFixture("creator");
    const zeroPolicySnapshot = structuredClone(page);
    zeroPolicySnapshot.snapshot.policyHeadHash = ZERO_HASH32;
    await expect(
      parseAndVerifyConversationPageJson(
        pageBytes(zeroPolicySnapshot),
        input,
        unavailableSyncPorts(),
      ),
    ).rejects.toBeInstanceOf(ConversationSyncValidationError);
  });

  it.each([
    ["duplicate key", new TextEncoder().encode('{"events":[],"events":[]}')],
    ["BOM", Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])],
    ["trailing value", new TextEncoder().encode("{}{}")],
  ])("rejects strict JSON %s input before any proof can run", async (_label, raw) => {
    await expect(
      parseAndVerifyConversationPageJson(
        raw,
        pageVerificationFixture(),
        unavailableSyncPorts(),
      ),
    ).rejects.toThrow();
  });

  it("maps authenticated cursor rejection to the non-oracular invalid_cursor type", async () => {
    const ports = unavailableSyncPorts();
    const record = vi.fn(() => Promise.resolve({ status: "recorded" }));
    ports.invariantIncident = { record };
    ports.cursorCodec = {
      ...ports.cursorCodec,
      decode: () =>
        Promise.resolve({
          status: "invalid",
          reasonCode: "authentication-failed",
        }),
    };
    await expect(
      parseAndVerifyConversationPageJson(
        new Uint8Array(),
        pageVerificationFixture({ requestedCursor: encodedCursor() }),
        ports,
      ),
    ).rejects.toBeInstanceOf(ConversationCursorInvalidError);
    expect(record).not.toHaveBeenCalled();
  });

  it("records an authenticated cross-context cursor without exposing the token", async () => {
    const input = pageVerificationFixture({ requestedCursor: encodedCursor() });
    let incident:
      | Parameters<DeliveryInvariantIncidentPort["record"]>[0]
      | undefined;
    const ports = unavailableSyncPorts();
    ports.cursorCodec = {
      ...ports.cursorCodec,
      decode: () => {
        const now = Date.parse(input.now);
        return Promise.resolve({
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          encodedCursor: input.requestedCursor,
          ...input.cursorContext,
          accountId: parseAccountId(
            "8f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
          ),
          lastReturnedPosition: "0",
          issuedAt: new Date(now - 1_000).toISOString(),
          expiresAt: new Date(now + 60_000).toISOString(),
          keyId: "cursor-key-1",
          authenticated: true,
        });
      },
    };
    ports.invariantIncident = {
      record: (value) => {
        incident = value;
        return Promise.resolve({ status: "recorded" });
      },
    };
    await expect(
      parseAndVerifyConversationPageJson(new Uint8Array(), input, ports),
    ).rejects.toBeInstanceOf(ConversationCursorInvalidError);
    expect(incident).toMatchObject({
      incidentCode: "cursor-binding-failure",
      conversationId: CONVERSATION_ID,
    });
    expect(incident).not.toHaveProperty("encodedCursor");
  });

  it("distinguishes an authenticated expired cursor from an invalid tag", async () => {
    const input = pageVerificationFixture({ requestedCursor: encodedCursor() });
    const now = Date.parse(input.now);
    const ports = unavailableSyncPorts();
    ports.cursorCodec = {
      ...ports.cursorCodec,
      decode: () =>
        Promise.resolve({
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          encodedCursor: input.requestedCursor,
          ...input.cursorContext,
          lastReturnedPosition: "0",
          issuedAt: new Date(now - 600_000).toISOString(),
          expiresAt: new Date(now - 60_000).toISOString(),
          keyId: "cursor-key-1",
          authenticated: true,
        }),
    };
    await expect(
      parseAndVerifyConversationPageJson(new Uint8Array(), input, ports),
    ).rejects.toBeInstanceOf(ConversationCursorExpiredError);
  });

  it("does not disclose a post-removal retention floor through cursor expiry", async () => {
    const original = pageVerificationFixture({ requestedCursor: encodedCursor() });
    const membership = Object.freeze({
      ...original.membership,
      removedPosition: parseUint63String("5"),
    });
    const input = {
      ...original,
      membership,
      retainedFloor: parseUint63String("6"),
      verifiedPrefixEvidenceDigest:
        computeConversationVerifiedPrefixEvidenceDigest({
          ...original,
          membership,
        }),
    };
    const now = Date.parse(input.now);
    const ports = unavailableSyncPorts();
    ports.cursorCodec = {
      ...ports.cursorCodec,
      decode: () =>
        Promise.resolve({
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          encodedCursor: input.requestedCursor,
          ...input.cursorContext,
          lastReturnedPosition: "0",
          issuedAt: new Date(now - 600_000).toISOString(),
          expiresAt: new Date(now - 60_000).toISOString(),
          keyId: "cursor-key-1",
          authenticated: true,
        }),
    };
    try {
      await parseAndVerifyConversationPageJson(new Uint8Array(), input, ports);
      throw new Error("expected retention rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(ConversationHistoryRetentionError);
      expect((error as ConversationHistoryRetentionError).nextRequiredPosition).toBe(
        "1",
      );
    }
  });

  it("sanitizes hostile dependency rejections and bounds never-settling ports", async () => {
    const hostilePorts = unavailableSyncPorts();
    hostilePorts.cursorCodec = {
      ...hostilePorts.cursorCodec,
      decode: () => Promise.reject(new Error("secret adapter detail")),
    };
    const hostile = parseAndVerifyConversationPageJson(
      new Uint8Array(),
      pageVerificationFixture({ requestedCursor: encodedCursor() }),
      hostilePorts,
    );
    await expect(hostile).rejects.toBeInstanceOf(
      ConversationSyncDependencyUnavailableError,
    );
    await expect(hostile).rejects.not.toThrow(/secret adapter detail/i);

    const hangingPorts = unavailableSyncPorts();
    hangingPorts.cursorCodec = {
      ...hangingPorts.cursorCodec,
      decode: () => new Promise(() => undefined),
    };
    const times = currentTimes(30);
    await expect(
      parseAndVerifyConversationPageJson(
        new Uint8Array(),
        pageVerificationFixture({
          requestedCursor: encodedCursor(),
          now: times.now,
          deadline: times.deadline,
        }),
        hangingPorts,
      ),
    ).rejects.toBeInstanceOf(ConversationSyncDependencyTimeoutError);
  });

  it("rejects two live sender credentials overlapping at uint63 max", () => {
    const binding = {
      accountId: ACCOUNT_ID,
      installationId: INSTALLATION_ID,
      credentialId: CREDENTIAL_ID,
      credentialFingerprint: parseFingerprint32(hash(60)),
      credentialRevocationVersion: parseUint63String("1"),
      senderGeneration: parseUint63String("1"),
      activeFromPosition: parseUint63String("9223372036854775807"),
      inactiveAtPosition: null,
    };
    const { prefix } = prefixFixture([
      Object.freeze(binding),
      Object.freeze({
        ...binding,
        credentialId: parseCredentialId(
          "d3c82f16-bf3c-45e0-8518-ca1bf6ab3b66",
        ),
        credentialFingerprint: parseFingerprint32(hash(61)),
      }),
    ]);
    expect(() => computeConversationVerifiedPrefixEvidenceDigest(prefix)).toThrow(
      /overlap/i,
    );
  });

  it.each([
    "membershipIntentHash",
    "membershipIntentEvidenceDigest",
  ] as const)("rejects a zero prefix staged-proposal %s", (field) => {
    const { prefix } = prefixFixture();
    const proposal = Object.freeze({
      ...stagedProposal(),
      position: parseUint63String("1"),
      [field]: ZERO_HASH32,
    });
    expect(() =>
      computeConversationVerifiedPrefixEvidenceDigest({
        ...prefix,
        stagedProposalsAtAnchor: Object.freeze([proposal]),
      }),
    ).toThrow(/intent-proved/i);
  });

  it("rejects a positive policy sequence carrying the reserved zero hash", () => {
    const { request, evidence } = policyReplayFixture();
    const pageEndPolicy = Object.freeze({
      ...request.pageEndPolicy,
      policyHeadHash: ZERO_HASH32,
    });
    expect(() =>
      parseConversationPolicyReplayEvidence(
        { ...evidence, pageEndPolicy },
        { ...request, pageEndPolicy },
      ),
    ).toThrow(/reserved zero hash/i);
  });
});
