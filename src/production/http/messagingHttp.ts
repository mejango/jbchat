import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign as signNode } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres, { type Sql } from "postgres";
import {
  createEnrollmentStore,
  type DeviceCredentialSignerPort,
  type EnrollmentStore,
} from "../identity/enrollmentStore";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import type { IdentityKeyedCryptoPort } from "../identity/identityKeyedCrypto";
import {
  createUnavailableWalletProofVerifier,
  type WalletProofVerifierPort,
} from "../identity/walletProofVerifier";
import { createHttpJsonRpcTransport } from "../chain/jsonRpc";
import {
  createQuorumWalletProofVerifier,
  type RatifiedChainProfile,
} from "../chain/quorumWalletProofVerifier";
import finalityProfileSet from "../../../config/finality-profiles.v1.json";
import { ensureProjectRef } from "../storage/projectRefProvision";
import {
  createEligibilityStore,
  type EligibilityStore,
} from "../entitlement/eligibilityStore";
import {
  parseSignedDeploymentManifest,
  type DeploymentManifest,
} from "../entitlement/deploymentManifest";
import { createQuorumCanonicalPurchaseVerifier } from "../chain/purchaseVerifier";
import type { ChainTransportRegistry } from "../chain/finalityVerifier";
import type { FinalityPolicy } from "../authority/finality";
import {
  createMembershipIntentStore,
  type MembershipIntentStore,
} from "../storage/membershipIntentStore";
import type { ExternalProposalSigningPort } from "../storage/externalProposalStore";
import {
  createMembershipCommitStore,
  type MembershipCommitStore,
} from "../storage/membershipCommitStore";
import {
  createConversationPlanStore,
  serviceTrustContext,
  type ConversationPlanStore,
} from "../storage/conversationPlanStore";
import {
  createConversationRequestStore,
  type ConversationRequestStore,
} from "../storage/conversationRequestStore";
import {
  createPostgresDeliveryAppendStore,
  type PostgresDeliveryAppendStore,
} from "../storage/postgresDeliveryStore";
import { createKeyedDeliveryCryptoPorts } from "../delivery/deliveryCryptoPorts";
import {
  APPLICATION_ENVELOPE_APPEND_ROUTE,
  createApplicationEnvelopeDeliveryService,
} from "../delivery/service";
import { API_V1_MEDIA_TYPE } from "../delivery/valueObjects";
import {
  runPolicyWitnessSync,
  type PolicyWitnessSubmitPort,
} from "../witness/policyWitnessSync";
import { rotateExternalSenderCredentials } from "../storage/externalSenderRotation";
import { readCallAtFinalized } from "../chain/quorumReads";
import { computeKeyPackageRef } from "../identity/identityCrypto";
import {
  createConversationPageReader,
} from "../storage/conversationPageReader";
import { createPostgresCursorNonceAllocator } from "../storage/cursorNonceAllocator";
import {
  createKeyedConversationCursorCodec,
} from "../delivery/conversationCursorCodec";
import {
  CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  CONVERSATION_CURSOR_PROFILE,
} from "../delivery/sync";
import {
  createInProcessDpopReplayGuard,
  verifyDpopProof,
  type DpopReplayGuard,
} from "./dpop";
import {
  loadMessagingRuntimeConfig,
  type MessagingRuntimeConfig,
} from "./messagingRuntimeConfig";

const MEDIA_TYPE = "application/vnd.juicebox.messaging.v1+json";
const PROBLEM_TYPE = "application/problem+json";
const MAX_BODY_BYTES = 64 * 1024;
const MAX_COMMIT_BODY_BYTES = 1_400 * 1024;
const PAGE_MAX_EVENTS = 100;
const PAGE_MAX_SERIALIZED_BYTES = 512 * 1024;
const CURSOR_TTL_MILLISECONDS = 24 * 60 * 60 * 1_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface MessagingHttpContext {
  readonly loadConfig?: () => MessagingRuntimeConfig;
  readonly connect?: (databaseUrl: string) => Sql;
  readonly now?: () => string;
  readonly walletProofVerifier?: WalletProofVerifierPort;
  readonly credentialSigner?: DeviceCredentialSignerPort;
  readonly logSigner?: ExternalProposalSigningPort;
  readonly logSignerKeyId?: string;
  readonly replayGuard?: DpopReplayGuard;
  readonly chainRegistry?: ChainTransportRegistry;
  readonly deliveryKeys?: {
    readonly privateKey: import("node:crypto").KeyObject;
    readonly publicKey: import("node:crypto").KeyObject;
  };
  readonly policyWitnessSubmit?: PolicyWitnessSubmitPort;
}

export interface MessagingHttpHandlers {
  readonly allocateEnrollment: (request: Request) => Promise<Response>;
  readonly issueChallenges: (
    request: Request,
    enrollmentId: string,
  ) => Promise<Response>;
  readonly completeEnrollment: (
    request: Request,
    enrollmentId: string,
  ) => Promise<Response>;
  readonly readEnrollment: (
    request: Request,
    enrollmentId: string,
  ) => Promise<Response>;
  readonly refreshSession: (request: Request) => Promise<Response>;
  readonly readSession: (request: Request) => Promise<Response>;
  readonly deleteSession: (request: Request) => Promise<Response>;
  readonly createMembershipIntent: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly cancelMembershipIntent: (
    request: Request,
    conversationId: string,
    intentId: string,
  ) => Promise<Response>;
  readonly consumeCommit: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly readConversationEvents: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly createPurchaseClaim: (request: Request) => Promise<Response>;
  readonly createConversationPlan: (request: Request) => Promise<Response>;
  readonly createConversationRequest: (request: Request) => Promise<Response>;
  readonly listConversationRequests: (request: Request) => Promise<Response>;
  readonly acceptConversationRequest: (request: Request) => Promise<Response>;
  readonly activateConversation: (request: Request) => Promise<Response>;
  readonly listConversations: (request: Request) => Promise<Response>;
  readonly registerProjectStaff: (
    request: Request,
    projectRefId: string,
  ) => Promise<Response>;
  readonly publishKeyPackages: (
    request: Request,
    installationId: string,
  ) => Promise<Response>;
  readonly appendEnvelope: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly readConversationDetail: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly readEnvelope: (
    request: Request,
    conversationId: string,
    envelopeId: string,
  ) => Promise<Response>;
  readonly listInstallationWelcomes: (
    request: Request,
    installationId: string,
  ) => Promise<Response>;
  readonly policyWitnessSync: (request: Request) => Promise<Response>;
  readonly externalSenderRotation: (request: Request) => Promise<Response>;
  readonly rpcDiagnostics: (request: Request) => Promise<Response>;
  readonly enrollmentStatus: (request: Request) => Promise<Response>;
  readonly registerPushEndpoint: (
    request: Request,
    installationId: string,
    endpointId: string,
  ) => Promise<Response>;
  readonly deletePushEndpoint: (
    request: Request,
    installationId: string,
    endpointId: string,
  ) => Promise<Response>;
}

interface AuthenticatedSession {
  readonly sessionId: string;
  readonly accountId: string;
  readonly installationId: string;
  readonly tokenFamilyId: string;
}

/**
 * The production messaging HTTP surface (service-api.md sections 2, 3, 7,
 * and 8) over the PostgreSQL stores. An unconfigured deployment serves a
 * uniform 404 from every route, exactly like the witness gate. Enrollment
 * uses the one-time Enrollment capability header; every authenticated
 * route enforces the DPoP session contract (access-token hash lookup,
 * live device credential, RFC 9449 proof bound to the registered key).
 * The wallet-proof verifier defaults to fail-closed unavailable until
 * real chain adapters exist, and the commit/pages lanes gate on their own
 * optional key material. Responses carry no-store cache headers; errors
 * are application/problem+json with stable reason codes only.
 */
export function createMessagingHttpHandlers(
  contextValue: MessagingHttpContext = {},
): MessagingHttpHandlers {
  const loadConfig =
    contextValue.loadConfig ?? (() => loadMessagingRuntimeConfig());
  const now = contextValue.now ?? (() => new Date().toISOString());
  const connect =
    contextValue.connect ??
    ((databaseUrl: string) =>
      postgres(databaseUrl, { max: 8, onnotice: () => {} }));
  const replayGuard =
    contextValue.replayGuard ??
    createInProcessDpopReplayGuard({ nowEpochMilliseconds: () => Date.now() });

  interface Wired {
    readonly key: string;
    readonly sql: Sql;
    readonly crypto: IdentityKeyedCryptoPort;
    readonly enrollment: EnrollmentStore;
    readonly intents: MembershipIntentStore;
    readonly commits: MembershipCommitStore | null;
    readonly cursorCodec: ReturnType<
      typeof createKeyedConversationCursorCodec
    > | null;
    readonly cursorKeyId: string | null;
    readonly pageReader: ReturnType<typeof createConversationPageReader>;
    readonly eligibility: {
      readonly storeFor: (chainNumber: number) => EligibilityStore | null;
      readonly manifestId: string;
      readonly projectsContractFor: (chainNumber: number) => string | null;
    } | null;
    readonly plans: ConversationPlanStore | null;
    readonly requests: ConversationRequestStore;
    readonly provisioningSeed: Buffer | null;
    readonly rpcEndpoints: Readonly<
      Record<string, readonly { providerId: string; url: string }[]>
    > | null;
    readonly chainRegistry: ChainTransportRegistry | null;
    readonly deliveryStore: PostgresDeliveryAppendStore;
    readonly appendKeys: {
      readonly privateKey: import("node:crypto").KeyObject;
      readonly publicKey: import("node:crypto").KeyObject;
      readonly keyId: string;
    } | null;
    readonly trust: ReturnType<typeof serviceTrustContext> | null;
    readonly policyWitnessSubmit: PolicyWitnessSubmitPort | null;
    readonly internalSyncToken: string | null;
  }
  let cached: Wired | null = null;

  const wire = (): Wired | null => {
    const config = loadConfig();
    if (config.status !== "configured") return null;
    const key = `${config.databaseUrl} ${config.identitySecret.toString(
      "base64url",
    )}`;
    if (cached && cached.key === key) return cached;
    const sql = connect(config.databaseUrl);
    const crypto = createKeyedIdentityCrypto(config.identitySecret);
    const credentialSigner =
      contextValue.credentialSigner ??
      createSeededEd25519CredentialSigner(
        config.credentialSignerKeyId,
        config.credentialSignerSeed,
      );
    const walletProofVerifier =
      contextValue.walletProofVerifier ??
      walletVerifierFromEndpoints(config.rpcEndpoints);
    const logSigner =
      contextValue.logSigner ??
      (config.logSigner
        ? createSeededEd25519LogSigner(config.logSigner.seed)
        : null);
    cached = {
      key,
      sql,
      crypto,
      enrollment: createEnrollmentStore({
        sql,
        now: now as never,
        crypto,
        walletProofVerifier,
        credentialSigner,
        allowedChainIds: config.allowedChainIds,
      }),
      intents: createMembershipIntentStore({ sql }),
      commits: logSigner
        ? createMembershipCommitStore({ sql, signer: logSigner })
        : null,
      cursorCodec: config.cursor
        ? createKeyedConversationCursorCodec({
            keyId: config.cursor.keyId,
            key: config.cursor.key,
            nonceAllocator: createPostgresCursorNonceAllocator({
              sql,
              keyId: config.cursor.keyId,
            }),
          })
        : null,
      cursorKeyId: config.cursor?.keyId ?? null,
      pageReader: createConversationPageReader({ sql }),
      eligibility: buildEligibilityLane(
        config,
        sql,
        crypto,
        contextValue.chainRegistry ?? registryFromEndpoints(config.rpcEndpoints),
        now,
      ),
      plans: (() => {
        const keyId = config.logSigner?.keyId ?? contextValue.logSignerKeyId;
        if (!config.provisioningSeed || !logSigner || !keyId) return null;
        return createConversationPlanStore({
          sql,
          provisioningSeed: config.provisioningSeed,
          logSigner,
          logSigningKeyId: keyId,
          hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
        });
      })(),
      requests: createConversationRequestStore({
        sql,
        hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
        now: now as never,
      }),
      chainRegistry:
        contextValue.chainRegistry ?? registryFromEndpoints(config.rpcEndpoints),
      deliveryStore: createPostgresDeliveryAppendStore({
        sql,
        now: now as never,
      }),
      appendKeys: (() => {
        const keyId = config.logSigner?.keyId ?? contextValue.logSignerKeyId;
        if (!keyId) return null;
        if (contextValue.deliveryKeys) {
          return { ...contextValue.deliveryKeys, keyId };
        }
        if (!config.logSigner) return null;
        const privateKey = createPrivateKey({
          key: Buffer.concat([
            Buffer.from("302e020100300506032b657004220420", "hex"),
            config.logSigner.seed,
          ]),
          format: "der",
          type: "pkcs8",
        });
        return { privateKey, publicKey: createPublicKey(privateKey), keyId };
      })(),
      trust: config.provisioningSeed
        ? serviceTrustContext(config.provisioningSeed)
        : null,
      provisioningSeed: config.provisioningSeed ?? null,
      rpcEndpoints: config.rpcEndpoints ?? null,
      policyWitnessSubmit:
        contextValue.policyWitnessSubmit ??
        (process.env.JBM_WITNESS_URL && process.env.JBM_WITNESS_SUBMIT_TOKEN
          ? {
              submitChain: async (submission) => {
                const response = await fetch(
                  `${process.env.JBM_WITNESS_URL}/v1/witness/extensions`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      Authorization: `Bearer ${process.env.JBM_WITNESS_SUBMIT_TOKEN}`,
                    },
                    body: JSON.stringify(submission),
                    signal: AbortSignal.timeout(15_000),
                  },
                );
                return (await response.json()) as never;
              },
            }
          : null),
      internalSyncToken: process.env.JBM_INTERNAL_SYNC_TOKEN ?? null,
    };
    return cached;
  };

  const authenticate = async (
    wired: Wired,
    request: Request,
  ): Promise<AuthenticatedSession | null> => {
    const authorization = request.headers.get("authorization");
    const match = authorization?.match(/^DPoP ([A-Za-z0-9_-]{43})$/);
    if (!match) return null;
    const accessToken = match[1];
    const nowIso = now();
    const rows = await wired.sql`
      SELECT s.session_id, s.account_id, s.installation_id,
             s.token_family_id, s.installation_auth_jkt,
             s.device_credential_revocation_version,
             c.revocation_version, c.status AS credential_status,
             c.expires_at AS credential_expires_at
      FROM auth_sessions s
      JOIN device_credentials c
        ON c.device_credential_id = s.device_credential_id
      WHERE s.access_token_hash = ${wired.crypto.hmacAccessToken(accessToken)}
        AND s.state = 'active'
        AND s.access_expires_at > ${nowIso}::timestamptz`;
    if (rows.length !== 1) return null;
    const row = rows[0];
    if (
      String(row.credential_status) !== "active" ||
      new Date(row.credential_expires_at as Date).toISOString() <= nowIso ||
      String(row.revocation_version) !==
        String(row.device_credential_revocation_version)
    ) {
      return null;
    }
    const verdict = verifyDpopProof({
      proof: request.headers.get("dpop"),
      method: request.method,
      url: externalRequestUrl(request),
      accessToken,
      expectedJkt: Buffer.from(row.installation_auth_jkt as Uint8Array),
      nowEpochMilliseconds: Date.parse(nowIso),
      replayGuard,
    });
    if (!verdict.valid) return null;
    return Object.freeze({
      sessionId: String(row.session_id),
      accountId: String(row.account_id),
      installationId: String(row.installation_id),
      tokenFamilyId: String(row.token_family_id),
    });
  };

  const readBody = async (
    request: Request,
    maxBytes: number,
  ): Promise<unknown | undefined> => {
    if (request.headers.get("content-type") !== MEDIA_TYPE) return undefined;
    const text = await request.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) return undefined;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  };

  const enrollmentHandle = (request: Request): string | null => {
    const match = request.headers
      .get("authorization")
      ?.match(/^Enrollment ([A-Za-z0-9_-]{43})$/);
    return match ? match[1] : null;
  };

  return Object.freeze({
    async allocateEnrollment(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const allocation = await wired.enrollment.allocateEnrollment(body);
      if (allocation.status !== "allocated") {
        return problem(400, allocation.reasonCode);
      }
      return jsonNoStore(201, allocation);
    },

    async issueChallenges(
      request: Request,
      enrollmentId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(enrollmentId)) return notFound();
      const handle = enrollmentHandle(request);
      if (!handle) return problem(401, "enrollment_capability_required");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const challenges = await wired.enrollment.issueChallenges(handle, body);
      if (challenges.status !== "challenges_issued") {
        return problem(
          challenges.reasonCode === "enrollment_expired" ? 410 : 400,
          challenges.reasonCode,
        );
      }
      return jsonNoStore(200, challenges);
    },

    async completeEnrollment(
      request: Request,
      enrollmentId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(enrollmentId)) return notFound();
      const handle = enrollmentHandle(request);
      if (!handle) return problem(401, "enrollment_capability_required");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      const completion = await wired.enrollment.completeEnrollment(handle, {
        walletSignature: (record.walletProof as Record<string, unknown>)
          ?.signature,
        possessionSignature: (
          record.possessionProof as Record<string, unknown>
        )?.signature,
      });
      if (completion.status === "conflict") {
        return problem(409, completion.reasonCode);
      }
      if (completion.status === "unavailable") {
        return problem(503, completion.reasonCode);
      }
      if (completion.status === "invalid") {
        return problem(400, completion.reasonCode);
      }
      const clientRecord = record.client as Record<string, unknown> | undefined;
      const session = await wired.enrollment.issueSession({
        installationId: completion.installationId,
        audience: String(clientRecord?.audience ?? ""),
        clientId: String(clientRecord?.clientId ?? ""),
      });
      if (session.status !== "issued") {
        return problem(503, "session_issue_failed");
      }
      return jsonNoStore(200, {
        tokenType: "DPoP",
        accessToken: session.accessToken,
        accessExpiresAt: session.accessExpiresAt,
        refreshToken: session.refreshToken,
        refreshExpiresAt: session.refreshExpiresAt,
        account: { accountId: completion.accountId },
        installation: {
          installationId: completion.installationId,
          deviceCredentialId: completion.deviceCredentialId,
        },
        walletVerificationMethod: completion.walletVerificationMethod,
      });
    },

    async readEnrollment(
      request: Request,
      enrollmentId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      if (!UUID_PATTERN.test(enrollmentId)) return notFound();
      const handle = enrollmentHandle(request);
      if (!handle) return problem(401, "enrollment_capability_required");
      const result = await wired.enrollment.readEnrollment(handle);
      if (result.status === "unknown") return notFound();
      return jsonNoStore(200, result);
    },

    async refreshSession(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const refreshToken = (body as Record<string, unknown>).refreshToken;
      if (
        typeof refreshToken !== "string" ||
        !HANDLE_PATTERN.test(refreshToken)
      ) {
        return problem(400, "malformed_request");
      }
      // The rotated session inherits the registered key; the DPoP proof is
      // checked against the family's stored JKT before rotation.
      const nowIso = now();
      const sessions = await wired.sql`
        SELECT installation_auth_jkt FROM auth_sessions
        WHERE refresh_token_hash =
              ${wired.crypto.hmacRefreshToken(refreshToken)}`;
      if (sessions.length !== 1) return problem(401, "session_invalid");
      const verdict = verifyDpopProof({
        proof: request.headers.get("dpop"),
        method: request.method,
        url: externalRequestUrl(request),
        accessToken: refreshToken,
        expectedJkt: Buffer.from(
          sessions[0].installation_auth_jkt as Uint8Array,
        ),
        nowEpochMilliseconds: Date.parse(nowIso),
        replayGuard,
      });
      if (!verdict.valid) return problem(401, verdict.reasonCode);
      const rotated = await wired.enrollment.refreshSession(refreshToken);
      if (rotated.status !== "issued") {
        return problem(401, rotated.reasonCode);
      }
      return jsonNoStore(200, {
        tokenType: "DPoP",
        accessToken: rotated.accessToken,
        accessExpiresAt: rotated.accessExpiresAt,
        refreshToken: rotated.refreshToken,
        refreshExpiresAt: rotated.refreshExpiresAt,
      });
    },

    async readSession(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const rows = await wired.sql`
        SELECT s.access_expires_at, s.refresh_expires_at,
               s.device_credential_id, c.status, c.expires_at,
               c.revocation_version
        FROM auth_sessions s
        JOIN device_credentials c
          ON c.device_credential_id = s.device_credential_id
        WHERE s.session_id = ${session.sessionId}`;
      const row = rows[0];
      return jsonNoStore(200, {
        account: { accountId: session.accountId },
        installation: { installationId: session.installationId },
        deviceCredential: {
          deviceCredentialId: String(row.device_credential_id),
          state: String(row.status),
          expiresAt: new Date(row.expires_at as Date).toISOString(),
          revocationVersion: String(row.revocation_version),
        },
        session: {
          accessExpiresAt: new Date(
            row.access_expires_at as Date,
          ).toISOString(),
          refreshExpiresAt: new Date(
            row.refresh_expires_at as Date,
          ).toISOString(),
        },
      });
    },

    async deleteSession(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "DELETE") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      await wired.sql`
        UPDATE auth_sessions SET state = 'revoked',
          revoked_at = ${now()}::timestamptz,
          revoke_reason = 'session_delete'
        WHERE token_family_id = ${session.tokenFamilyId}
          AND state IN ('active', 'rotated')`;
      return new Response(null, { status: 204, headers: noStoreHeaders() });
    },

    async createMembershipIntent(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;

      // ADR 0003: the HTTP layer resolves the one-time claim handle to a
      // grant ID; the store re-validates the grant row relationally.
      let grantId: string | null = null;
      if (record.eligibilityClaimHandle !== undefined) {
        const handle = record.eligibilityClaimHandle;
        if (typeof handle !== "string" || !HANDLE_PATTERN.test(handle)) {
          return problem(403, "grant_invalid");
        }
        const grants = await wired.sql`
          SELECT grant_id, state FROM eligibility_grants
          WHERE claim_handle_hash =
                ${wired.crypto.hmacEligibilityClaimHandle(handle)}`;
        if (grants.length !== 1 || String(grants[0].state) !== "active") {
          return problem(403, "grant_invalid");
        }
        grantId = String(grants[0].grant_id);
      }
      const created = await wired.intents.createIntent({
        operation: record.operation,
        conversationId,
        targetInstallationId: record.targetInstallationId,
        requestedByInstallationId: session.installationId,
        grantId,
      });
      if (created.status === "conflict") {
        return problem(409, created.reasonCode);
      }
      if (created.status === "refused") {
        return problem(
          created.reasonCode === "malformed-request" ? 400 : 403,
          created.reasonCode,
        );
      }
      return jsonNoStore(201, created);
    },

    async cancelMembershipIntent(
      request: Request,
      conversationId: string,
      intentId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "DELETE") return notFound();
      if (!UUID_PATTERN.test(conversationId) || !UUID_PATTERN.test(intentId)) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const cancelled = await wired.intents.cancelIntent(
        intentId,
        session.installationId,
      );
      if (cancelled.status !== "resolved") return notFound();
      return jsonNoStore(200, cancelled);
    },

    async consumeCommit(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.commits) return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_COMMIT_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const result = await wired.commits.consumeCommit({
        ...(body as Record<string, unknown>),
        committerInstallationId: session.installationId,
      });
      if (result.status === "refused") {
        return problem(400, result.reasonCode);
      }
      if (result.status === "cas-failed") {
        return problem(412, result.reasonCode);
      }
      return jsonNoStore(200, result);
    },

    async readConversationEvents(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      if (!wired.cursorCodec || !wired.cursorKeyId) return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");

      const conversations = await wired.sql`
        SELECT realm_id FROM conversations
        WHERE conversation_id = ${conversationId}`;
      if (conversations.length !== 1) return notFound();
      const cursorContext = {
        realmId: String(conversations[0].realm_id),
        accountId: session.accountId,
        installationId: session.installationId,
        conversationId,
        routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
      };
      const nowIso = now();
      const deadline = new Date(Date.parse(nowIso) + 5_000).toISOString();
      const signal = AbortSignal.timeout(5_000);

      let afterPosition: string | null = null;
      const encodedCursor = new URL(request.url).searchParams.get("cursor");
      if (encodedCursor !== null) {
        const claims = (await wired.cursorCodec.decode({
          encodedCursor,
          context: cursorContext as never,
          now: nowIso as never,
          deadline: deadline as never,
          signal,
        })) as Record<string, unknown>;
        if (claims.authenticated !== true) {
          return problem(400, "invalid_cursor");
        }
        if (String(claims.expiresAt) <= nowIso) {
          return problem(400, "cursor_expired");
        }
        afterPosition = String(claims.lastReturnedPosition);
      }

      const page = await wired.pageReader.readPage({
        conversationId,
        installationId: session.installationId,
        afterPosition,
        maxEvents: PAGE_MAX_EVENTS,
        maxSerializedBytes: PAGE_MAX_SERIALIZED_BYTES,
      });
      if (page.status === "not-a-member") return notFound();
      if (page.status === "history-gone") {
        return problem(410, "history_gone");
      }
      const nextCursor = (await wired.cursorCodec.encode({
        plaintext: {
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          realmId: cursorContext.realmId,
          installationId: session.installationId,
          conversationId,
          lastReturnedPosition: page.nextPosition,
          issuedAt: nowIso,
          expiresAt: new Date(
            Date.parse(nowIso) + CURSOR_TTL_MILLISECONDS,
          ).toISOString(),
          keyId: wired.cursorKeyId,
        } as never,
        context: cursorContext as never,
        deadline: deadline as never,
        signal,
      })) as { status: string; encodedCursor: string };
      return jsonNoStore(200, {
        events: page.events,
        hasMore: page.hasMore,
        snapshot: page.snapshot,
        nextCursor: nextCursor.encodedCursor,
      });
    },

    async createPurchaseClaim(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      if (
        typeof record.walletRef !== "string" ||
        typeof record.transactionHash !== "string" ||
        !/^0x[0-9a-f]{64}$/.test(record.transactionHash) ||
        typeof record.payLogIndex !== "number" ||
        !Number.isSafeInteger(record.payLogIndex) ||
        record.payLogIndex < 0 ||
        typeof record.terminal !== "string"
      ) {
        return problem(400, "malformed_request");
      }

      // Resolve the project. A caller may pass a known projectRefId, or
      // (open, on-demand) a chainId + projectId — any project on a
      // manifest-blessed chain is provisioned on first claim. The payment
      // is still verified on-chain below, so opening this is safe.
      let projectRefId: string;
      if (UUID_PATTERN.test(String(record.projectRefId))) {
        projectRefId = String(record.projectRefId);
      } else if (
        typeof record.chainId === "number" &&
        Number.isSafeInteger(record.chainId) &&
        typeof record.projectId === "number" &&
        Number.isSafeInteger(record.projectId) &&
        record.projectId >= 0
      ) {
        if (!wired.eligibility || !wired.provisioningSeed) return notFound();
        const contract = wired.eligibility.projectsContractFor(
          record.chainId,
        );
        if (!contract) return problem(404, "project_unknown");
        projectRefId = await ensureProjectRef(
          wired.sql,
          wired.provisioningSeed,
          now(),
          {
            chainId: record.chainId,
            projectId: record.projectId,
            projectsContract: contract,
          },
        );
      } else {
        return problem(400, "malformed_request");
      }

      const projects = await wired.sql`
        SELECT chain_id, projects_contract, project_id::text AS project_id
        FROM project_refs
        WHERE project_ref_id = ${projectRefId} AND status = 'active'`;
      if (projects.length !== 1) return problem(404, "project_unknown");
      const chainMatch = String(projects[0].chain_id).match(/^eip155:(\d+)$/);
      if (!chainMatch) return problem(404, "project_unknown");
      const chainNumber = Number(chainMatch[1]);
      if (!wired.eligibility) return notFound();
      const store = wired.eligibility.storeFor(chainNumber);
      if (!store) return notFound();

      const policies = await wired.sql`
        SELECT policy_id, policy_revision::int AS policy_revision, policy_hash
        FROM policies
        WHERE project_ref_id = ${projectRefId} AND superseded_at IS NULL
        ORDER BY policy_revision DESC LIMIT 1`;
      if (policies.length !== 1) return problem(404, "project_unknown");

      const walletParts = String(record.walletRef).split(":");
      const walletAddress = walletParts[2]?.toLowerCase() ?? "";
      const claim = {
        kind: "juicebox-v6-payment-beneficiary-claim.v1",
        claimId: randomUUID(),
        project: {
          protocol: "juicebox-v6",
          chainId: chainNumber,
          projectId: Number(String(projects[0].project_id)),
          version: 6,
          deploymentManifestId: wired.eligibility.manifestId,
          projectsContract: `0x${Buffer.from(
            projects[0].projects_contract as Uint8Array,
          ).toString("hex")}`,
        },
        transactionHash: String(record.transactionHash),
        payLogIndex: record.payLogIndex,
        expectedBeneficiary: walletAddress,
        customerSubjectSource: "pay-beneficiary",
      };
      const issued = await store.issuePurchaseGrant({
        projectRefId,
        installationId: session.installationId,
        walletRef: record.walletRef,
        policyId: String(policies[0].policy_id),
        policyRevision: Number(policies[0].policy_revision),
        policyHash: `0x${Buffer.from(
          policies[0].policy_hash as Uint8Array,
        ).toString("hex")}`,
        claim,
        terminal: String(record.terminal).toLowerCase(),
        tierHook: null,
      });
      if (issued.status === "issued") {
        return jsonNoStore(201, issued);
      }
      if (issued.status === "pending-finality") {
        return problem(409, issued.reasonCode);
      }
      if (issued.status === "unavailable") {
        return problem(503, issued.reasonCode);
      }
      return problem(issued.status === "ineligible" ? 403 : 400, issued.reasonCode);
    },

    async createConversationRequest(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const handle = (body as Record<string, unknown>).eligibilityClaimHandle;
      if (typeof handle !== "string") return problem(400, "malformed_request");
      const result = await wired.requests.createRequest({
        requesterAccountId: session.accountId,
        requesterInstallationId: session.installationId,
        eligibilityClaimHandle: handle,
      });
      if (result.status === "refused") {
        return problem(
          result.reasonCode === "conversation_exists" ? 409 : 403,
          result.reasonCode,
        );
      }
      return jsonNoStore(result.status === "created" ? 201 : 200, result);
    },

    async listConversationRequests(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const items = await wired.requests.listForOwnerInstallation(
        session.installationId,
      );
      return jsonNoStore(200, { requests: items });
    },

    async acceptConversationRequest(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.plans) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const requestId = (body as Record<string, unknown>).requestId;
      if (typeof requestId !== "string") return problem(400, "malformed_request");
      const accepted = await wired.plans.acceptRequest({
        requestId,
        ownerAccountId: session.accountId,
        ownerInstallationId: session.installationId,
      });
      if (accepted.status === "created") return jsonNoStore(201, accepted.plan);
      if (accepted.status === "reuse_generation") {
        return jsonNoStore(200, {
          action: "reuse_generation",
          conversationId: accepted.conversationId,
        });
      }
      return problem(
        accepted.reasonCode === "recipient_keys_unavailable"
          ? 409
          : accepted.reasonCode === "not_project_staff"
            ? 403
            : accepted.reasonCode === "request_not_pending"
              ? 404
              : 403,
        accepted.reasonCode,
      );
    },

    async createConversationPlan(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.plans) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const handle = (body as Record<string, unknown>).eligibilityClaimHandle;
      if (typeof handle !== "string") return problem(400, "malformed_request");
      const created = await wired.plans.createPlan({
        creatorAccountId: session.accountId,
        creatorInstallationId: session.installationId,
        eligibilityClaimHandle: handle,
      });
      if (created.status === "created") return jsonNoStore(201, created.plan);
      if (created.status === "reuse_generation") {
        return jsonNoStore(200, {
          action: "reuse_generation",
          conversationId: created.conversationId,
        });
      }
      return problem(
        created.reasonCode === "recipient_keys_unavailable" ? 409 : 403,
        created.reasonCode,
      );
    },

    async activateConversation(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.plans) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_COMMIT_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const planId = String((body as Record<string, unknown>).planId ?? "");
      const ifMatch = request.headers.get("if-match");
      if (ifMatch !== `"plan-${planId}-1"`) {
        return problem(412, "plan_etag_mismatch");
      }
      const result = await wired.plans.activate(body, session.installationId);
      if (result.status !== "activated") {
        return problem(
          result.reasonCode === "malformed_request" ? 400 : 409,
          result.reasonCode,
        );
      }
      return jsonNoStore(201, result);
    },

    async listConversations(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const rows = await wired.sql`
        SELECT c.conversation_id, c.state, c.delivery_purpose,
               c.last_position, c.last_activity_at, c.created_at,
               m.role, m.joined_position, m.removed_position,
               p.chain_id, p.project_id::text AS project_id,
               encode(p.projects_contract, 'hex') AS projects_contract
        FROM memberships m
        JOIN conversations c ON c.conversation_id = m.conversation_id
        JOIN project_refs p ON p.project_ref_id = c.project_ref_id
        WHERE m.installation_id = ${session.installationId}
        ORDER BY c.last_activity_at DESC
        LIMIT 100`;
      return jsonNoStore(200, {
        conversations: rows.map((row) => ({
          conversationId: String(row.conversation_id),
          state: String(row.state),
          deliveryPurpose: String(row.delivery_purpose),
          role: String(row.role),
          lastPosition: String(row.last_position),
          lastActivityAt: new Date(row.last_activity_at as Date).toISOString(),
          createdAt: new Date(row.created_at as Date).toISOString(),
          removedPosition:
            row.removed_position === null
              ? null
              : String(row.removed_position),
          project: {
            chainId: String(row.chain_id),
            projectId: String(row.project_id),
            projectsContract: `0x${String(row.projects_contract)}`,
          },
        })),
      });
    },

    async registerProjectStaff(
      request: Request,
      projectRefId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.chainRegistry) return notFound();
      if (!UUID_PATTERN.test(projectRefId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");

      const projects = await wired.sql`
        SELECT chain_id, project_id::text AS project_id,
               encode(projects_contract, 'hex') AS projects_contract
        FROM project_refs
        WHERE project_ref_id = ${projectRefId} AND status = 'active'`;
      if (projects.length !== 1) return problem(404, "project_unknown");
      const chainMatch = String(projects[0].chain_id).match(/^eip155:(\d+)$/);
      if (!chainMatch) return problem(404, "project_unknown");
      const transports = wired.chainRegistry.transportsFor(
        Number(chainMatch[1]),
      );
      if (!transports) return problem(503, "chain_unavailable");

      // ERC-721 ownerOf(projectId) on the pinned projects contract at the
      // finalized quorum head proves who may register support staff.
      const projectIdHex = BigInt(String(projects[0].project_id))
        .toString(16)
        .padStart(64, "0");
      const call = await readCallAtFinalized(
        transports,
        2,
        `0x${String(projects[0].projects_contract)}`,
        `0x6352211e${projectIdHex}`,
      );
      if (call.status !== "ok" || call.returnData.byteLength !== 32) {
        return problem(503, "chain_unavailable");
      }
      const ownerAddress = `0x${call.returnData.subarray(12).toString("hex")}`;
      const links = await wired.sql`
        SELECT account_id FROM wallet_links
        WHERE wallet_ref_lookup = ${wired.crypto.hmacWalletRefLookup(
          `${String(projects[0].chain_id)}:${ownerAddress}`,
        )} AND status = 'active'`;
      if (
        links.length !== 1 ||
        String(links[0].account_id) !== session.accountId
      ) {
        return problem(403, "not_project_owner");
      }
      await wired.sql`
        INSERT INTO project_staff_registrations (
          project_ref_id, installation_id, account_id,
          registered_by_owner_address, ownership_block,
          ownership_block_hash, state, registered_at
        ) VALUES (
          ${projectRefId}, ${session.installationId}, ${session.accountId},
          ${Buffer.from(ownerAddress.slice(2), "hex")},
          ${String(call.blockNumber ?? 0n)},
          ${Buffer.from(
            String(call.blockHash ?? `0x${"00".repeat(32)}`).slice(2),
            "hex",
          )},
          'active', ${now()}::timestamptz
        ) ON CONFLICT (project_ref_id, installation_id)
        DO UPDATE SET state = 'active', revoked_at = NULL`;
      return jsonNoStore(201, {
        projectRefId,
        installationId: session.installationId,
        ownerAddress,
      });
    },

    async publishKeyPackages(
      request: Request,
      installationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(installationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      if (session.installationId !== installationId) {
        return problem(403, "installation_mismatch");
      }
      const body = await readBody(request, MAX_COMMIT_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const items = (body as Record<string, unknown>).keyPackages;
      if (!Array.isArray(items) || items.length === 0 || items.length > 20) {
        return problem(400, "malformed_request");
      }
      const credentials = await wired.sql`
        SELECT device_credential_id, revocation_version,
               encode(mls_credential_fingerprint, 'base64') AS fingerprint
        FROM device_credentials
        WHERE installation_id = ${installationId} AND status = 'active'`;
      if (credentials.length !== 1) return problem(403, "credential_invalid");
      const nowIso = now();
      const accepted: string[] = [];
      for (const item of items) {
        const record = item as Record<string, unknown>;
        const encoded = record.keyPackage;
        if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
          return problem(400, "malformed_request");
        }
        const bytes = Buffer.from(encoded, "base64url");
        if (bytes.byteLength === 0 || bytes.byteLength > 65536) {
          return problem(400, "malformed_request");
        }
        const ref = computeKeyPackageRef(bytes);
        const expiresAt = new Date(
          Date.parse(nowIso) + 7 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const inserted = await wired.sql`
          INSERT INTO key_packages (
            key_package_ref, installation_id, device_credential_id,
            device_credential_revocation_version, release_profile_id,
            package_bytes, package_sha256, mls_credential_fingerprint,
            state, created_at, expires_at
          ) VALUES (
            ${ref}, ${installationId},
            ${String(credentials[0].device_credential_id)},
            ${String(credentials[0].revocation_version)},
            'delivery-v1-2026q3', ${bytes},
            ${createHash("sha256").update(bytes).digest()},
            ${Buffer.from(String(credentials[0].fingerprint), "base64")},
            'available', ${nowIso}::timestamptz, ${expiresAt}::timestamptz
          ) ON CONFLICT (key_package_ref) DO NOTHING
          RETURNING key_package_ref`;
        if (inserted.length === 1) accepted.push(ref.toString("base64url"));
      }
      return jsonNoStore(201, { accepted });
    },

    async appendEnvelope(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.appendKeys || !wired.trust) return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const idempotencyKey = request.headers.get("idempotency-key");
      const ifMatch = request.headers.get("if-match");
      if (
        !idempotencyKey ||
        !/^[A-Za-z0-9_-]{43,64}$/.test(idempotencyKey) ||
        !ifMatch
      ) {
        return problem(400, "malformed_request");
      }
      if (request.headers.get("content-type") !== MEDIA_TYPE) {
        return problem(400, "malformed_request");
      }
      const rawText = await request.text();
      if (Buffer.byteLength(rawText, "utf8") > 256 * 1024) {
        return problem(400, "malformed_request");
      }

      const grants = await wired.sql`
        SELECT g.credential_id, g.role_credential_id,
               encode(rc.credential_fingerprint, 'base64') AS fingerprint,
               rc.revocation_version
        FROM conversation_send_grants g
        JOIN role_credentials rc ON rc.credential_id = g.role_credential_id
        WHERE g.conversation_id = ${conversationId}
          AND g.installation_id = ${session.installationId}
          AND g.state = 'active'`;
      if (grants.length !== 1) return problem(403, "no_send_grant");

      const keys = wired.appendKeys;
      const validity = await wired.sql`
        SELECT valid_from, valid_until FROM delivery_log_signing_keys
        WHERE key_id = ${keys.keyId} AND state = 'active'`;
      if (validity.length !== 1) return problem(503, "log_key_unavailable");

      const nowIso = now();
      const ports = {
        ...createKeyedDeliveryCryptoPorts({
          now: (() => now()) as never,
          snapshot: () =>
            wired.deliveryStore.loadSnapshot(conversationId as never, {
              installationId: session.installationId,
            }),
          signingKeyId: keys.keyId as never,
          signingKeyValidFrom: new Date(
            validity[0].valid_from as Date,
          ).toISOString() as never,
          signingKeyValidUntil: new Date(
            validity[0].valid_until as Date,
          ).toISOString() as never,
          privateKey: keys.privateKey,
          publicKey: keys.publicKey,
        }),
        mlsCommitProjectionVerifier: {
          verify: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        mlsExternalProposalVerifier: {
          verify: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        conversationPolicyReplayVerifier: {
          verify: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        conversationPageProofVerifier: {
          verify: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        conversationLogHeadProofVerifier: {
          verify: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        applicationAppendPreflight:
          wired.deliveryStore.applicationAppendPreflight,
        atomicPersistence: wired.deliveryStore.atomicPersistence,
        clock: { now: (() => now()) as never },
        conversationCursorCodec: wired.cursorCodec ?? {
          decode: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
          encode: () =>
            Promise.resolve({
              status: "unavailable",
              reasonCode: "not-configured",
            }),
        },
        invariantIncident: {
          record: (incident: unknown) => {
            console.error("DELIVERY INVARIANT INCIDENT", incident);
            return Promise.resolve({ status: "recorded" });
          },
        },
      };
      const service = createApplicationEnvelopeDeliveryService(
        ports as never,
        {
          realmId: wired.trust.realmId,
          releaseProfileId: wired.trust.releaseProfileId,
          releaseTrustRootDigest: wired.trust.releaseTrustRootDigest,
          deliveryLimitsDigest: wired.trust.deliveryLimitsDigest,
          deliveryLimits: wired.trust.deliveryLimits,
        },
      );
      void nowIso;
      const result = await service.appendApplicationEnvelope({
        idempotencyKey,
        authenticatedSender: {
          type: "installation",
          accountId: session.accountId,
          installationId: session.installationId,
        },
        authenticatedCredentialId: String(grants[0].role_credential_id),
        authenticatedCredentialFingerprint: Buffer.from(
          String(grants[0].fingerprint).replace(/\s/g, ""),
          "base64",
        ).toString("base64url"),
        authenticatedCredentialRevocationVersion: String(
          grants[0].revocation_version,
        ),
        request: {
          method: "POST",
          routeTemplate: APPLICATION_ENVELOPE_APPEND_ROUTE,
          resourceId: conversationId,
          mediaType: API_V1_MEDIA_TYPE,
          ifMatch,
          rawBodyBytes: Buffer.from(rawText, "utf8"),
          queryString: "",
          contentEncoding: null,
        },
      } as never);
      if (result.status === "accepted") return jsonNoStore(201, result);
      if (result.status === "conflict") return jsonNoStore(409, result);
      if (result.status === "rejected") return jsonNoStore(422, result);
      return jsonNoStore(503, result);
    },

    async readConversationDetail(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const rows = await wired.sql`
        SELECT c.etag, c.epoch, c.roster_version, c.state, c.last_position,
               encode(c.confirmed_transcript_hash, 'base64') AS transcript,
               encode(c.group_id_hash, 'base64') AS group_id_hash,
               c.release_profile_id,
               a.policy_head_id, a.policy_head_sequence,
               encode(a.policy_head_hash, 'base64') AS policy_head_hash,
               a.witness_state
        FROM memberships m
        JOIN conversations c ON c.conversation_id = m.conversation_id
        LEFT JOIN delivery_policy_head_anchors a
          ON a.conversation_id = c.conversation_id
        WHERE m.conversation_id = ${conversationId}
          AND m.installation_id = ${session.installationId}`;
      if (rows.length !== 1) return notFound();
      const row = rows[0];
      const b64u = (value: unknown) =>
        Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
          "base64url",
        );
      return jsonNoStore(200, {
        conversationId,
        etag: String(row.etag),
        state: String(row.state),
        epoch: String(row.epoch),
        rosterVersion: String(row.roster_version),
        lastPosition: String(row.last_position),
        confirmedTranscriptHash: b64u(row.transcript),
        groupIdHash: b64u(row.group_id_hash),
        releaseProfileId: String(row.release_profile_id),
        policyHead:
          row.policy_head_id === null
            ? null
            : {
                policyHeadId: String(row.policy_head_id),
                policyHeadSequence: String(row.policy_head_sequence),
                policyHeadHash: b64u(row.policy_head_hash),
                witnessState: String(row.witness_state),
              },
      });
    },

    async readEnvelope(
      request: Request,
      conversationId: string,
      envelopeId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      if (!UUID_PATTERN.test(conversationId) || !UUID_PATTERN.test(envelopeId)) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const rows = await wired.sql`
        SELECT e.position, e.envelope_class, e.content_type,
               e.sender_type, e.sender_account_id, e.sender_installation_id,
               encode(e.envelope_bytes, 'base64') AS envelope
        FROM memberships m
        JOIN envelopes e ON e.conversation_id = m.conversation_id
        WHERE m.conversation_id = ${conversationId}
          AND m.installation_id = ${session.installationId}
          AND e.envelope_id = ${envelopeId}`;
      if (rows.length !== 1) return notFound();
      const row = rows[0];
      return jsonNoStore(200, {
        conversationId,
        envelopeId,
        position: String(row.position),
        envelopeClass: String(row.envelope_class),
        contentType: String(row.content_type),
        sender: {
          type: String(row.sender_type),
          accountId:
            row.sender_account_id === null
              ? null
              : String(row.sender_account_id),
          installationId:
            row.sender_installation_id === null
              ? null
              : String(row.sender_installation_id),
        },
        envelope: Buffer.from(
          String(row.envelope).replace(/\s/g, ""),
          "base64",
        ).toString("base64url"),
      });
    },

    async listInstallationWelcomes(
      request: Request,
      installationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      if (!UUID_PATTERN.test(installationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      if (session.installationId !== installationId) {
        return problem(403, "installation_mismatch");
      }
      const rows = await wired.sql`
        SELECT conversation_id, commit_position, commit_envelope_id,
               encode(welcome_bytes, 'base64') AS welcome
        FROM mls_welcomes
        WHERE target_installation_id = ${installationId}
        ORDER BY created_at
        LIMIT 50`;
      return jsonNoStore(200, {
        welcomes: rows.map((row) => ({
          conversationId: String(row.conversation_id),
          commitPosition: String(row.commit_position),
          commitEnvelopeId: String(row.commit_envelope_id),
          welcome: Buffer.from(
            String(row.welcome).replace(/\s/g, ""),
            "base64",
          ).toString("base64url"),
        })),
      });
    },

    async policyWitnessSync(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.policyWitnessSubmit || !wired.internalSyncToken) {
        return notFound();
      }
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      const report = await runPolicyWitnessSync(
        wired.sql,
        wired.policyWitnessSubmit,
      );
      return jsonNoStore(200, report);
    },

    async enrollmentStatus(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.internalSyncToken) return notFound();
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      const [installs, creds, accounts, attempts] = await Promise.all([
        wired.sql`SELECT count(*)::int AS c FROM installations`,
        wired.sql`SELECT count(*)::int AS c FROM device_credentials WHERE status = 'active'`,
        wired.sql`SELECT count(*)::int AS c FROM accounts`,
        wired.sql`SELECT state, count(*)::int AS c FROM device_enrollment_attempts GROUP BY state ORDER BY c DESC`,
      ]);
      return jsonNoStore(200, {
        installations: installs[0].c,
        activeCredentials: creds[0].c,
        accounts: accounts[0].c,
        attemptsByState: attempts.map((row) => ({
          state: String(row.state),
          count: row.c,
        })),
      });
    },

    async rpcDiagnostics(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.internalSyncToken) return notFound();
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      if (!wired.rpcEndpoints) {
        return jsonNoStore(200, { configured: false, chains: [] });
      }
      const readStage = async (
        transport: { providerId: string; request: (m: string, p: readonly unknown[]) => Promise<unknown> },
        method: string,
        params: readonly unknown[],
      ): Promise<{ providerId: string; ok: boolean; value?: string; error?: string }> => {
        try {
          const result = (await transport.request(method, params)) as Record<string, unknown> | string | null;
          const value =
            typeof result === "string"
              ? result
              : result && typeof result === "object"
                ? String((result as Record<string, unknown>).number ?? (result as Record<string, unknown>).hash ?? "")
                : "";
          return { providerId: transport.providerId, ok: true, value };
        } catch (error) {
          return { providerId: transport.providerId, ok: false, error: String(error).slice(0, 120) };
        }
      };
      // Optional: probe eth_getCode for an address to catch a contract /
      // EIP-7702-delegated wallet (non-empty code => "unavailable").
      let probeAddress: string | null = null;
      const body = await request.json().catch(() => null);
      if (body && typeof (body as Record<string, unknown>).address === "string") {
        const candidate = String((body as Record<string, unknown>).address).toLowerCase();
        if (/^0x[0-9a-f]{40}$/.test(candidate)) probeAddress = candidate;
      }
      const chains: unknown[] = [];
      for (const [chainId, endpoints] of Object.entries(wired.rpcEndpoints)) {
        const ratified = finalityProfileSet.profiles.find((profile) => profile.chainId === chainId);
        const transports = endpoints.map((endpoint) =>
          createHttpJsonRpcTransport({ providerId: endpoint.providerId, url: endpoint.url }),
        );
        const heads = await Promise.all(
          transports.map((transport) => readStage(transport, "eth_getBlockByNumber", ["finalized", false])),
        );
        const nums = heads
          .filter((head) => head.ok && /^0x[0-9a-f]+$/i.test(head.value ?? ""))
          .map((head) => BigInt(head.value as string));
        let hashAgree: boolean | null = null;
        let hashes: { providerId: string; ok: boolean; value?: string; error?: string }[] = [];
        if (nums.length === transports.length && nums.length > 0) {
          const lowest = nums.reduce((low, n) => (n < low ? n : low));
          hashes = await Promise.all(
            transports.map((transport) =>
              readStage(transport, "eth_getBlockByNumber", [`0x${lowest.toString(16)}`, false]),
            ),
          );
          const set = new Set(hashes.filter((h) => h.ok).map((h) => h.value));
          hashAgree = hashes.every((h) => h.ok) && set.size === 1;
        }
        let codeProbe: unknown = null;
        if (probeAddress && nums.length === transports.length && nums.length > 0) {
          const lowest = nums.reduce((low, n) => (n < low ? n : low));
          const codes = await Promise.all(
            transports.map((transport) =>
              readStage(transport, "eth_getCode", [probeAddress, `0x${lowest.toString(16)}`]),
            ),
          );
          codeProbe = codes.map((c) => ({
            providerId: c.providerId,
            ok: c.ok,
            error: c.error,
            codeLen: c.ok && typeof c.value === "string" ? (c.value.length - 2) / 2 : null,
            prefix: c.ok && typeof c.value === "string" ? c.value.slice(0, 12) : null,
          }));
        }
        chains.push({
          chainId,
          ratified: Boolean(ratified),
          heads: heads.map((h) => ({ providerId: h.providerId, ok: h.ok, error: h.error })),
          headsAllOk: heads.every((h) => h.ok),
          hashAgree,
          hashErrors: hashes.filter((h) => !h.ok).map((h) => ({ providerId: h.providerId, error: h.error })),
          codeProbe,
        });
      }
      return jsonNoStore(200, { configured: true, chains });
    },

    async externalSenderRotation(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.provisioningSeed || !wired.internalSyncToken) {
        return notFound();
      }
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      const report = await rotateExternalSenderCredentials(
        wired.sql,
        wired.provisioningSeed,
      );
      return jsonNoStore(200, report);
    },

    async registerPushEndpoint(
      request: Request,
      installationId: string,
      endpointId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "PUT") return notFound();
      if (!UUID_PATTERN.test(installationId) || !UUID_PATTERN.test(endpointId)) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      if (session.installationId !== installationId) {
        return problem(403, "installation_mismatch");
      }
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      const keys = record.keys as Record<string, unknown> | undefined;
      if (
        record.provider !== "webpush" ||
        typeof record.endpoint !== "string" ||
        !record.endpoint.startsWith("https://") ||
        typeof keys?.p256dh !== "string" ||
        typeof keys?.auth !== "string"
      ) {
        return problem(400, "malformed_request");
      }
      const sealed = wired.crypto.sealPayload(
        JSON.stringify({
          endpoint: record.endpoint,
          p256dh: keys.p256dh,
          auth: keys.auth,
        }),
      );
      await wired.sql`
        INSERT INTO push_endpoints (
          endpoint_id, installation_id, provider, endpoint_fingerprint,
          encrypted_configuration, kms_key_version, status, created_at
        ) VALUES (
          ${endpointId}, ${installationId}, 'webpush',
          ${createHash("sha256")
            .update(String(record.endpoint), "utf8")
            .digest()},
          ${sealed.ciphertext}, ${sealed.kmsKeyVersion}, 'active',
          ${now()}::timestamptz
        ) ON CONFLICT (endpoint_id) DO UPDATE SET
          encrypted_configuration = EXCLUDED.encrypted_configuration,
          kms_key_version = EXCLUDED.kms_key_version,
          status = 'active'`;
      return new Response(null, { status: 204, headers: noStoreHeaders() });
    },

    async deletePushEndpoint(
      request: Request,
      installationId: string,
      endpointId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "DELETE") return notFound();
      if (!UUID_PATTERN.test(installationId) || !UUID_PATTERN.test(endpointId)) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      if (session.installationId !== installationId) {
        return problem(403, "installation_mismatch");
      }
      await wired.sql`
        UPDATE push_endpoints SET status = 'deleted'
        WHERE endpoint_id = ${endpointId}
          AND installation_id = ${installationId}`;
      return new Response(null, { status: 204, headers: noStoreHeaders() });
    },
  });
}

/**
 * Builds the ADR 0005 quorum wallet verifier for every configured chain
 * whose ratified profile exists in the checked-in canonical set. No
 * endpoints, or a chain without a ratified profile, stays fail-closed
 * unavailable - never a partial or inferred configuration.
 */
/**
 * The eligibility lane exists only when a signed deployment manifest
 * verifies against its trusted signer AND chain transports exist. Per
 * chain, the finality policy is derived from the ratified ADR 0005
 * profile; a chain without a ratified profile has no store and refuses.
 */
function buildEligibilityLane(
  config: Extract<MessagingRuntimeConfig, { status: "configured" }>,
  sql: Sql,
  crypto: IdentityKeyedCryptoPort,
  registry: ChainTransportRegistry | null,
  now: () => string,
): {
  readonly storeFor: (chainNumber: number) => EligibilityStore | null;
  readonly manifestId: string;
  readonly projectsContractFor: (chainNumber: number) => string | null;
} | null {
  if (!config.manifest || !registry) return null;
  let manifest: DeploymentManifest;
  try {
    const raw =
      config.manifest.source.kind === "path"
        ? readFileSync(config.manifest.source.path, "utf8")
        : config.manifest.source.json;
    manifest = parseSignedDeploymentManifest(
      JSON.parse(raw),
      config.manifest.signerPublicKey,
    );
  } catch {
    return null;
  }
  const verifier = createQuorumCanonicalPurchaseVerifier(registry);
  const stores = new Map<number, EligibilityStore | null>();
  const storeFor = (chainNumber: number) => {
    if (stores.has(chainNumber)) return stores.get(chainNumber) ?? null;
    const ratified = finalityProfileSet.profiles.find(
      (profile) => profile.chainId === `eip155:${chainNumber}`,
    );
    const pinned = manifest.chains.some(
      (chain) => chain.chainId === chainNumber,
    );
    if (!ratified || !pinned) {
      stores.set(chainNumber, null);
      return null;
    }
    const store = createEligibilityStore({
      sql,
      now,
      crypto,
      purchaseVerifier: verifier,
      finalityPolicy: {
        kind: "juicebox-finality-policy.v1",
        policyId: ratified.finalityProfileId,
        chainId: chainNumber,
        blockTag: "finalized",
        minimumProviderQuorum: 2,
        requireBlockHashAgreement: true,
        requireArchiveStateAtReceiptBlock: true,
        allowConfirmationFallback: false,
        safeHeadUse: "suspend-existing-authority-only",
        onReorg: "revoke-leases-and-rekey",
      } as unknown as FinalityPolicy,
      manifest,
    });
    stores.set(chainNumber, store);
    return store;
  };
  const projectsContractFor = (chainNumber: number): string | null => {
    const chain = manifest.chains.find((entry) => entry.chainId === chainNumber);
    return chain ? chain.projectsContract : null;
  };
  return Object.freeze({
    storeFor,
    manifestId: manifest.manifestId,
    projectsContractFor,
  });
}

function registryFromEndpoints(
  rpcEndpoints: Readonly<
    Record<string, readonly { providerId: string; url: string }[]>
  > | null,
): ChainTransportRegistry | null {
  if (!rpcEndpoints) return null;
  const cache = new Map<number, readonly ReturnType<typeof createHttpJsonRpcTransport>[]>();
  return {
    transportsFor(chainNumber: number) {
      const existing = cache.get(chainNumber);
      if (existing) return existing;
      const endpoints = rpcEndpoints[`eip155:${chainNumber}`];
      if (!endpoints) return null;
      const transports = endpoints.map((endpoint) =>
        createHttpJsonRpcTransport({
          providerId: endpoint.providerId,
          url: endpoint.url,
        }),
      );
      cache.set(chainNumber, transports);
      return transports;
    },
  };
}

function walletVerifierFromEndpoints(
  rpcEndpoints: Readonly<
    Record<string, readonly { providerId: string; url: string }[]>
  > | null,
): WalletProofVerifierPort {
  if (!rpcEndpoints) return createUnavailableWalletProofVerifier();
  const profiles: RatifiedChainProfile[] = [];
  for (const [chainId, endpoints] of Object.entries(rpcEndpoints)) {
    const ratified = finalityProfileSet.profiles.find(
      (profile) => profile.chainId === chainId,
    );
    if (!ratified) continue;
    profiles.push({
      chainId,
      finalityProfileId: ratified.finalityProfileId,
      finalityProfileRevision: String(ratified.profileRevision),
      finalityProfileHash: createHashOfCanonicalDocument(
        ratified.canonicalDocument,
      ),
      transports: endpoints.map((endpoint) =>
        createHttpJsonRpcTransport({
          providerId: endpoint.providerId,
          url: endpoint.url,
        }),
      ),
      minimumProviderQuorum: 2,
    });
  }
  return profiles.length > 0
    ? createQuorumWalletProofVerifier(profiles)
    : createUnavailableWalletProofVerifier();
}

function createHashOfCanonicalDocument(document: unknown): Buffer {
  return createHash("sha256")
    .update(JSON.stringify(document), "utf8")
    .digest();
}

function createSeededEd25519CredentialSigner(
  signerKeyId: string,
  seed: Buffer,
): DeviceCredentialSignerPort {
  const privateKey = ed25519PrivateKeyFromSeed(seed);
  return Object.freeze({
    signerKeyId,
    sign: (payload: Buffer) => signNode(null, payload, privateKey),
  });
}

function createSeededEd25519LogSigner(
  seed: Buffer,
): ExternalProposalSigningPort {
  const privateKey = ed25519PrivateKeyFromSeed(seed);
  return Object.freeze({
    signCheckpointDigest: async (_signingKeyId: string, digest: string) =>
      signNode(null, Buffer.from(digest, "base64url"), privateKey).toString(
        "base64url",
      ),
  });
}

function ed25519PrivateKeyFromSeed(seed: Buffer) {
  // PKCS#8 wrapping of a raw Ed25519 seed.
  const prefix = Buffer.from(
    "302e020100300506032b657004220420",
    "hex",
  );
  return createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function noStoreHeaders(): Record<string, string> {
  return {
    "Cache-Control": "no-store, private",
    Pragma: "no-cache",
    Vary: "Authorization, DPoP",
  };
}

function jsonNoStore(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": MEDIA_TYPE, ...noStoreHeaders() },
  });
}

function problem(status: number, reasonCode: string): Response {
  return new Response(JSON.stringify({ status, reasonCode }), {
    status,
    headers: { "Content-Type": PROBLEM_TYPE, ...noStoreHeaders() },
  });
}

function notFound(): Response {
  return problem(404, "not_found");
}

/**
 * The externally-visible request URL for DPoP htu binding. Behind a
 * TLS-terminating proxy (Railway) the node server sees the connection as
 * http, so raw request.url carries the wrong scheme/host and never matches
 * the client's htu (built from window.location.origin = https). The
 * security middleware has already 421'd any request whose forwarded origin
 * is not the canonical origin, so the forwarded headers are trustworthy
 * here; fall back to request.url for direct/local requests.
 */
function externalRequestUrl(request: Request): string {
  const url = new URL(request.url);
  const proto = request.headers.get("x-forwarded-proto");
  const host =
    request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (proto && host && !proto.includes(",") && !host.includes(",")) {
    return `${proto}://${host}${url.pathname}`;
  }
  return `${url.protocol}//${url.host}${url.pathname}`;
}
