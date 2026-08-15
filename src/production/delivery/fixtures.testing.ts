import { Buffer } from "node:buffer";
import { computeEnvelopeSha256 } from "./hashes";
import {
  DELIVERY_TESTED_CEILINGS,
  type DeliveryLimits,
} from "./limits";
import {
  computeApplicationAppendQuotaPolicyDigest,
  computeApplicationAppendQuotaScopeHash,
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendRecipientSetHash,
  computeConversationSendGrantEvidenceDigest,
  computeDeliveryLimitsDigest,
  computePolicyHeadProofEvidenceDigest,
} from "./state";
import { APPLICATION_ENVELOPE_APPEND_ROUTE } from "./service";
import {
  API_V1_MEDIA_TYPE,
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  parseAccountId,
  parseConversationId,
  parseCredentialId,
  parseFingerprint32,
  parseHash32,
  parseInstallationId,
  parseRfc3339Millis,
  parseUint63String,
} from "./valueObjects";

export const LAB_CONVERSATION_ID =
  "c99daf46-89d8-4e84-aada-53a04fa111c9";
export const LAB_ACCOUNT_ID = "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26";
export const LAB_INSTALLATION_ID =
  "5ec2d18e-f082-48f0-8b01-55e43fed021c";
export const LAB_RECIPIENT_INSTALLATION_ID =
  "6ec2d18e-f082-48f0-8b01-55e43fed021c";
export const LAB_RECIPIENT_ACCOUNT_ID =
  "8f94c690-2af4-4a45-a7cc-9d85ce6cbd26";
export const LAB_RECIPIENT_CREDENTIAL_ID =
  "d3c82f16-bf3c-45e0-8518-ca1bf6ab3b66";
export const LAB_CREDENTIAL_ID =
  "c3c82f16-bf3c-45e0-8518-ca1bf6ab3b66";
export const LAB_POLICY_HEAD_ID =
  "a4d721f6-8af9-4d82-afbe-e509e9a3fc2f";
export const LAB_WITNESS_CHECKPOINT_ID =
  "b4d721f6-8af9-4d82-afbe-e509e9a3fc2f";
export const LAB_ATTACHMENT_ID =
  "d5e83107-9bf8-4b42-a095-c3b64028e4aa";
export const LAB_ENVELOPE_ID =
  "415609f1-9662-49f6-9cda-9ef319abe51d";
export const LAB_ENVELOPE_ID_2 =
  "525609f1-9662-49f6-9cda-9ef319abe51d";
export const LAB_IDEMPOTENCY_KEY =
  "0198a5d7-4c58-7e31-bbf1-0fd4c09e4acf";
export const LAB_IDEMPOTENCY_KEY_2 =
  "0198a5d8-4c58-7e31-bbf1-0fd4c09e4acf";
export const LAB_NOW = "2026-08-14T16:20:45.123Z";
export const LAB_LATER_NOW = "2026-08-22T16:20:45.123Z";
export const LAB_REALM_ID = "fictional-lab";
export const LAB_RELEASE_PROFILE_ID = "fictional-release.v1";
export const LAB_ETAG = '"e20-r28"';
export const LAB_TRANSCRIPT_HASH = labHash(1);
export const LAB_POLICY_HEAD_HASH = labHash(2);
export const LAB_CREDENTIAL_FINGERPRINT = labHash(3);
export const LAB_GROUP_ID_HASH = labHash(4);
export const LAB_POLICY_SIGNED_BODY_SHA256 = labHash(5);
export const LAB_POLICY_SIGNATURE_SHA256 = labHash(6);
export const LAB_POLICY_WITNESS_EVIDENCE_DIGEST = labHash(7);
export const LAB_RELEASE_TRUST_ROOT_DIGEST = labHash(8);
export const LAB_POLICY_CONSISTENCY_EVIDENCE_DIGEST = labHash(9);
export const LAB_PRIOR_POLICY_HEAD_HASH = labHash(10);
export const LAB_PRIOR_POLICY_WITNESS_EVIDENCE_DIGEST = labHash(11);
export const LAB_BASE_POSITION = "1";
export const LAB_BASE_HEAD_HASH = labHash(12);
export const LAB_ROLE_CREDENTIAL_FINGERPRINT = labHash(13);
export const LAB_SEND_GRANT_INCLUSION_EVIDENCE_DIGEST = labHash(14);
export const LAB_AUTHORIZED_SEND_GRANT_SET_HASH = labHash(15);
export const LAB_RECIPIENT_CREDENTIAL_FINGERPRINT = labHash(16);
export const LAB_PROJECT_SCOPE_ID = "fictional-project";
export const LAB_TENANT_SCOPE_ID = "fictional-tenant";
export const LAB_ROLE_CREDENTIAL_ID =
  "e6f94218-ac09-4c31-b1a6-d4c75139f5bb";
export const LAB_POLICY_SIGNING_KEY_ID = "fictional-policy-lab-2026q3";
export const LAB_LOG_SIGNING_KEY_ID = "fictional-delivery-lab-2026q3";

function fictionalMlsRosterProjections() {
  return [
    {
      conversationId: parseConversationId(LAB_CONVERSATION_ID),
      conversationGeneration: parseUint63String("1"),
      rosterVersion: parseUint63String("28"),
      accountId: parseAccountId(LAB_ACCOUNT_ID),
      installationId: parseInstallationId(LAB_INSTALLATION_ID),
      credentialId: parseCredentialId(LAB_CREDENTIAL_ID),
      credentialFingerprint: parseFingerprint32(LAB_CREDENTIAL_FINGERPRINT),
      credentialRevocationVersion: parseUint63String("4"),
    },
    {
      conversationId: parseConversationId(LAB_CONVERSATION_ID),
      conversationGeneration: parseUint63String("1"),
      rosterVersion: parseUint63String("28"),
      accountId: parseAccountId(LAB_RECIPIENT_ACCOUNT_ID),
      installationId: parseInstallationId(LAB_RECIPIENT_INSTALLATION_ID),
      credentialId: parseCredentialId(LAB_RECIPIENT_CREDENTIAL_ID),
      credentialFingerprint: parseFingerprint32(
        LAB_RECIPIENT_CREDENTIAL_FINGERPRINT,
      ),
      credentialRevocationVersion: parseUint63String("1"),
    },
  ];
}

export const LAB_ROSTER_HASH = computeApplicationAppendMlsRosterHash(
  fictionalMlsRosterProjections(),
);

interface AppendFixtureOptions {
  readonly envelopeId?: string;
  readonly idempotencyKey?: string;
  readonly ciphertextText?: string;
  readonly attachmentIds?: readonly string[];
  readonly ifMatch?: string;
  readonly expectedEpoch?: string;
  readonly expectedRosterVersion?: string;
  readonly expectedConfirmedTranscriptHash?: string;
  readonly policyHeadHash?: string;
}

export function fictionalDeliveryLabSeed(
  deliveryLimits: DeliveryLimits = fictionalDeliveryLimits(),
) {
  const deliveryLimitsDigest = computeDeliveryLimitsDigest(deliveryLimits);
  const quotaSubjects = {
    installation: LAB_INSTALLATION_ID,
    account: LAB_ACCOUNT_ID,
    project: LAB_PROJECT_SCOPE_ID,
    conversation: LAB_CONVERSATION_ID,
    tenant: LAB_TENANT_SCOPE_ID,
  } as const;
  const quotaBindings = (
    ["installation", "account", "project", "conversation", "tenant"] as const
  ).map((scope) => ({
    scope,
    scopeHash: computeApplicationAppendQuotaScopeHash({
      realmId: LAB_REALM_ID,
      scope,
      subjectId: quotaSubjects[scope],
    }),
    quotaName: "application-append",
    windowStartedAt: parseRfc3339Millis("2026-08-14T00:00:00.000Z"),
    windowSeconds: parseUint63String("86400"),
    operationLimit: parseUint63String("1000"),
    byteLimit: parseUint63String("1048576"),
  }));
  const quotaPolicyDigest = computeApplicationAppendQuotaPolicyDigest(
    quotaBindings,
  );
  const sendGrantWithoutDigests: Parameters<
    typeof computeConversationSendGrantEvidenceDigest
  >[0] = {
    conversationId: parseConversationId(LAB_CONVERSATION_ID),
    installationId: parseInstallationId(LAB_INSTALLATION_ID),
    credentialId: parseCredentialId(LAB_CREDENTIAL_ID),
    conversationKind: "purchase_support",
    conversationGeneration: parseUint63String("1"),
    role: "customer",
    roleCredentialId: parseCredentialId(LAB_ROLE_CREDENTIAL_ID),
    roleCredentialFingerprint: parseFingerprint32(
      LAB_ROLE_CREDENTIAL_FINGERPRINT,
    ),
    roleCredentialSubjectAccountId: parseAccountId(LAB_ACCOUNT_ID),
    roleCredentialSubjectInstallationId: parseInstallationId(
      LAB_INSTALLATION_ID,
    ),
    roleCredentialValidFrom: parseRfc3339Millis(
      "2026-08-01T00:00:00.000Z",
    ),
    roleCredentialValidUntil: parseRfc3339Millis(
      "2026-09-14T16:20:45.123Z",
    ),
    capability: "send_application",
    state: "active",
    policyRevision: parseUint63String("12"),
    policyHeadSequence: parseUint63String("81"),
    policyHeadHash: parseHash32(LAB_POLICY_HEAD_HASH),
    expiresAt: parseRfc3339Millis("2026-09-14T16:20:45.123Z"),
  };
  const sendGrantEvidenceDigest = computeConversationSendGrantEvidenceDigest(
    sendGrantWithoutDigests,
  );
  const recipientProjections = [
    {
      conversationId: parseConversationId(LAB_CONVERSATION_ID),
      conversationGeneration: parseUint63String("1"),
      recipientSetVersion: parseUint63String("1"),
      accountId: parseAccountId(LAB_ACCOUNT_ID),
      installationId: parseInstallationId(LAB_INSTALLATION_ID),
      credentialId: parseCredentialId(LAB_CREDENTIAL_ID),
      credentialFingerprint: parseFingerprint32(LAB_CREDENTIAL_FINGERPRINT),
      credentialRevocationVersion: parseUint63String("4"),
      credentialState: "active" as const,
      credentialExpiresAt: parseRfc3339Millis(
        "2026-09-14T16:20:45.123Z",
      ),
      joinedPosition: parseUint63String("1"),
      removedPosition: null,
      installationState: "active" as const,
    },
    {
      conversationId: parseConversationId(LAB_CONVERSATION_ID),
      conversationGeneration: parseUint63String("1"),
      recipientSetVersion: parseUint63String("1"),
      accountId: parseAccountId(LAB_RECIPIENT_ACCOUNT_ID),
      installationId: parseInstallationId(LAB_RECIPIENT_INSTALLATION_ID),
      credentialId: parseCredentialId(LAB_RECIPIENT_CREDENTIAL_ID),
      credentialFingerprint: parseFingerprint32(
        LAB_RECIPIENT_CREDENTIAL_FINGERPRINT,
      ),
      credentialRevocationVersion: parseUint63String("1"),
      credentialState: "active" as const,
      credentialExpiresAt: parseRfc3339Millis(
        "2026-09-14T16:20:45.123Z",
      ),
      joinedPosition: parseUint63String("1"),
      removedPosition: null,
      installationState: "active" as const,
    },
  ];
  const recipientSetHash =
    computeApplicationAppendRecipientSetHash(recipientProjections);
  const mlsRosterProjections = fictionalMlsRosterProjections();
  const rosterHash = computeApplicationAppendMlsRosterHash(
    mlsRosterProjections,
  );
  const policyProofInput = {
    realmId: LAB_REALM_ID,
    conversationGeneration: "1",
    releaseTrustRootDigest: LAB_RELEASE_TRUST_ROOT_DIGEST,
    purpose: "append-authorization",
    releaseProfileId: LAB_RELEASE_PROFILE_ID,
    deliveryLimitsDigest,
    conversationId: LAB_CONVERSATION_ID,
    policyHeadId: LAB_POLICY_HEAD_ID,
    policyHeadSequence: "81",
    policyHeadHash: LAB_POLICY_HEAD_HASH,
    deliveryLogPosition: LAB_BASE_POSITION,
    deliveryLogHeadHash: LAB_BASE_HEAD_HASH,
    evaluationLogPosition: LAB_BASE_POSITION,
    evaluationLogHeadHash: LAB_BASE_HEAD_HASH,
    epoch: "20",
    rosterVersion: "28",
    confirmedTranscriptHash: LAB_TRANSCRIPT_HASH,
    policyRevision: "12",
    mandatoryProposalCount: "0",
    mandatoryProposalSetHash: ZERO_HASH32,
    authorizedSendGrantSetHash: LAB_AUTHORIZED_SEND_GRANT_SET_HASH,
    selectedSendGrantEvidenceDigest: sendGrantEvidenceDigest,
    selectedSendGrantInclusionEvidenceDigest:
      LAB_SEND_GRANT_INCLUSION_EVIDENCE_DIGEST,
    authorizedQuotaPolicyDigest: quotaPolicyDigest,
    priorPolicyHeadSequence: "80",
    priorPolicyHeadHash: LAB_PRIOR_POLICY_HEAD_HASH,
    priorPolicyWitnessCheckpointId: LAB_WITNESS_CHECKPOINT_ID,
    priorPolicyWitnessEvidenceDigest:
      LAB_PRIOR_POLICY_WITNESS_EVIDENCE_DIGEST,
    signedBodySha256: LAB_POLICY_SIGNED_BODY_SHA256,
    signerKeyId: LAB_POLICY_SIGNING_KEY_ID,
    signatureSha256: LAB_POLICY_SIGNATURE_SHA256,
    witnessCheckpointId: LAB_WITNESS_CHECKPOINT_ID,
    witnessedPolicyHeadHash: LAB_POLICY_HEAD_HASH,
    witnessEvidenceDigest: LAB_POLICY_WITNESS_EVIDENCE_DIGEST,
    issuedAt: "2026-08-14T16:20:00.000Z",
    expiresAt: "2026-08-14T16:24:00.000Z",
    verifiedAt: LAB_NOW,
    signatureStatus: "verified",
    keyStatus: "valid-for-checkpoint",
    witnessStatus: "verified",
    freshnessStatus: "fresh",
    currentStatus: "current",
    policyConsistencyStatus: "verified",
    sendGrantInclusionStatus: "verified",
    policyConsistencyEvidenceDigest:
      LAB_POLICY_CONSISTENCY_EVIDENCE_DIGEST,
  } as Parameters<typeof computePolicyHeadProofEvidenceDigest>[0];
  const policyProofEvidenceDigest =
    computePolicyHeadProofEvidenceDigest(policyProofInput);
  return {
    snapshot: {
      conversation: {
        realmId: LAB_REALM_ID,
        conversationId: LAB_CONVERSATION_ID,
        projectScopeId: LAB_PROJECT_SCOPE_ID,
        tenantScopeId: LAB_TENANT_SCOPE_ID,
        kind: "purchase_support",
        generation: "1",
        releaseProfileId: LAB_RELEASE_PROFILE_ID,
        deliveryLimitsDigest,
        releaseTrustRootDigest: LAB_RELEASE_TRUST_ROOT_DIGEST,
        quotaPolicyDigest,
        groupIdHash: LAB_GROUP_ID_HASH,
        state: "active",
        etag: LAB_ETAG,
        epoch: "20",
        rosterVersion: "28",
        rosterHash,
        recipientSetVersion: "1",
        recipientSetHash,
        confirmedTranscriptHash: LAB_TRANSCRIPT_HASH,
        lastPosition: LAB_BASE_POSITION,
        currentLogHeadHash: LAB_BASE_HEAD_HASH,
        currentPolicyHeadSequence: "81",
        currentPolicyHeadHash: LAB_POLICY_HEAD_HASH,
      },
      membership: {
        conversationId: LAB_CONVERSATION_ID,
        accountId: LAB_ACCOUNT_ID,
        installationId: LAB_INSTALLATION_ID,
        credentialId: LAB_CREDENTIAL_ID,
        credentialFingerprint: LAB_CREDENTIAL_FINGERPRINT,
        credentialRevocationVersion: "4",
        installationState: "active",
        credentialState: "active",
        credentialExpiresAt: "2026-09-14T16:20:45.123Z",
        joinedPosition: "1",
        removedPosition: null,
      },
      policyHead: {
        policyHeadId: LAB_POLICY_HEAD_ID,
        conversationId: LAB_CONVERSATION_ID,
        policyHeadSequence: "81",
        policyHeadHash: LAB_POLICY_HEAD_HASH,
        deliveryLogPosition: LAB_BASE_POSITION,
        deliveryLogHeadHash: LAB_BASE_HEAD_HASH,
        evaluationLogPosition: LAB_BASE_POSITION,
        evaluationLogHeadHash: LAB_BASE_HEAD_HASH,
        epoch: "20",
        rosterVersion: "28",
        confirmedTranscriptHash: LAB_TRANSCRIPT_HASH,
        policyRevision: "12",
        signedBodySha256: LAB_POLICY_SIGNED_BODY_SHA256,
        signerKeyId: LAB_POLICY_SIGNING_KEY_ID,
        signatureSha256: LAB_POLICY_SIGNATURE_SHA256,
        witnessEvidenceDigest: LAB_POLICY_WITNESS_EVIDENCE_DIGEST,
        proofEvidenceDigest: policyProofEvidenceDigest,
        policyConsistencyEvidenceDigest:
          LAB_POLICY_CONSISTENCY_EVIDENCE_DIGEST,
        proofVerifiedAt: LAB_NOW,
        issuedAt: "2026-08-14T16:20:00.000Z",
        expiresAt: "2026-08-14T16:24:00.000Z",
        witnessState: "verified",
        witnessCheckpointId: LAB_WITNESS_CHECKPOINT_ID,
        witnessedPolicyHeadHash: LAB_POLICY_HEAD_HASH,
        mandatoryProposalCount: "0",
        mandatoryProposalSetHash: ZERO_HASH32,
        authorizedSendGrantSetHash: LAB_AUTHORIZED_SEND_GRANT_SET_HASH,
        selectedSendGrantEvidenceDigest: sendGrantEvidenceDigest,
        selectedSendGrantInclusionEvidenceDigest:
          LAB_SEND_GRANT_INCLUSION_EVIDENCE_DIGEST,
        authorizedQuotaPolicyDigest: quotaPolicyDigest,
        priorPolicyHeadSequence: "80",
        priorPolicyHeadHash: LAB_PRIOR_POLICY_HEAD_HASH,
        priorPolicyWitnessCheckpointId: LAB_WITNESS_CHECKPOINT_ID,
        priorPolicyWitnessEvidenceDigest:
          LAB_PRIOR_POLICY_WITNESS_EVIDENCE_DIGEST,
      },
      sendGrant: {
        ...sendGrantWithoutDigests,
        grantEvidenceDigest: sendGrantEvidenceDigest,
        grantInclusionEvidenceDigest:
          LAB_SEND_GRANT_INCLUSION_EVIDENCE_DIGEST,
      },
      pendingRemovalCount: "0",
      usage: {
        conversationId: LAB_CONVERSATION_ID,
        envelopeCount: "0",
        envelopeBytes: "0",
        attachmentBytes: "0",
        envelopeCountLimit: "1000",
        envelopeBytesLimit: "1048576",
        attachmentBytesLimit: "1048576",
      },
      quotaBindings,
      quotas: quotaBindings.map((binding) => ({
        ...binding,
        operationCount: "0",
        byteCount: "0",
        reservedOperationCount: "0",
        reservedByteCount: "0",
        rowVersion: "0",
      })),
    },
    basePosition: LAB_BASE_POSITION,
    baseHeadHash: LAB_BASE_HEAD_HASH,
    now: LAB_NOW,
    signingKeyId: LAB_LOG_SIGNING_KEY_ID,
    signingKeyValidFrom: "2026-08-01T00:00:00.000Z",
    signingKeyValidUntil: "2026-09-14T16:20:45.123Z",
    recipientProjections,
    mlsRosterProjections,
    attachments: [
      {
        attachmentId: LAB_ATTACHMENT_ID,
        accountId: LAB_ACCOUNT_ID,
        byteLength: "321",
        state: "finalized",
        boundEnvelopeId: null,
      },
    ],
  };
}

export function fictionalDeliveryTrustContext(
  deliveryLimits: DeliveryLimits = fictionalDeliveryLimits(),
) {
  return Object.freeze({
    realmId: LAB_REALM_ID,
    releaseProfileId: LAB_RELEASE_PROFILE_ID,
    releaseTrustRootDigest: LAB_RELEASE_TRUST_ROOT_DIGEST,
    deliveryLimitsDigest: computeDeliveryLimitsDigest(deliveryLimits),
    deliveryLimits,
  });
}

export function fictionalDeliveryLimits(
  overrides: Partial<DeliveryLimits> = {},
): DeliveryLimits {
  return Object.freeze({
    ...DELIVERY_TESTED_CEILINGS,
    ...overrides,
  });
}

export function fictionalAppendRequest(
  options: AppendFixtureOptions = {},
) {
  const ciphertext = Buffer.from(
    options.ciphertextText ?? "fictional opaque MLS private message",
    "utf8",
  ).toString("base64url");
  const body = {
    envelopeId: options.envelopeId ?? LAB_ENVELOPE_ID,
    policyHeadId: LAB_POLICY_HEAD_ID,
    policyHeadSequence: "81",
    policyHeadHash: options.policyHeadHash ?? LAB_POLICY_HEAD_HASH,
    expectedEpoch: options.expectedEpoch ?? "20",
    expectedRosterVersion: options.expectedRosterVersion ?? "28",
    expectedConfirmedTranscriptHash:
      options.expectedConfirmedTranscriptHash ?? LAB_TRANSCRIPT_HASH,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    ciphertext,
    envelopeSha256: computeEnvelopeSha256(Buffer.from(ciphertext, "base64url")),
    attachmentIds: [...(options.attachmentIds ?? [])],
  };
  const rawBodyBytes = Buffer.from(JSON.stringify(body), "utf8");
  return {
    idempotencyKey: options.idempotencyKey ?? LAB_IDEMPOTENCY_KEY,
    authenticatedSender: {
      type: "installation",
      accountId: LAB_ACCOUNT_ID,
      installationId: LAB_INSTALLATION_ID,
    },
    authenticatedCredentialId: LAB_CREDENTIAL_ID,
    authenticatedCredentialFingerprint: LAB_CREDENTIAL_FINGERPRINT,
    authenticatedCredentialRevocationVersion: "4",
    request: {
      method: "POST",
      routeTemplate: APPLICATION_ENVELOPE_APPEND_ROUTE,
      resourceId: LAB_CONVERSATION_ID,
      mediaType: API_V1_MEDIA_TYPE,
      ifMatch: options.ifMatch ?? LAB_ETAG,
      rawBodyBytes,
      queryString: "",
      contentEncoding: null,
    },
  };
}

function labHash(byte: number): string {
  return Buffer.alloc(32, byte).toString("base64url");
}
