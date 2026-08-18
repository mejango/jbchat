import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, randomUUID, sign as signNode } from "node:crypto";
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
  readonly replayGuard?: DpopReplayGuard;
  readonly chainRegistry?: ChainTransportRegistry;
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
    } | null;
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
      url: request.url,
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
        url: request.url,
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
        !UUID_PATTERN.test(String(record.projectRefId)) ||
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
      const projectRefId = String(record.projectRefId);

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
  return Object.freeze({ storeFor, manifestId: manifest.manifestId });
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
