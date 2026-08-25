import { Buffer } from "node:buffer";
import { createHash, createHmac, createPrivateKey, createPublicKey, randomUUID, sign as signNode } from "node:crypto";
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
import {
  createExternalProposalStore,
  type ExternalProposalSigningPort,
  type ExternalProposalStore,
} from "../storage/externalProposalStore";
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
  createNotificationChannelStore,
  type ChannelKind,
  type NotificationChannelStore,
} from "../storage/notificationChannelStore";
import {
  createNotificationDispatcher,
  type NotificationDispatcher,
} from "../notify/notificationDispatch";
import {
  sendEmail,
  sendTelegram,
  telegramDeepLink,
} from "../notify/senders";
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
import {
  resolveMlsBridgeFromEnvironment,
  type MlsBridgeClient,
} from "../mls/bridgeClient";
import {
  createRelayInstallationStore,
  type RelayBridgePort,
  type RelayInstallationStore,
} from "../storage/relayInstallationStore";
import { issueRelayGrant } from "../entitlement/eligibilityStore";
import { runRelayDrain } from "../relay/relayDrain";
import {
  conversationTag,
  renderPrompt,
  routeInbound,
  type RelayEnvelopeContext,
} from "../relay/relayFormat";
import { BendystrawDiscoveryAdapter } from "../../integrations/juicebox/discovery.server";
import type { FetchLike } from "../notify/senders";
import { readProjectProvision } from "../storage/appendAuthority";
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
const NOT_CONFIGURED = Object.freeze({
  status: "unavailable" as const,
  reasonCode: "not-configured" as const,
});

/** A UUIDv4-shaped id from 16 digest bytes (the append lane wants v4). */
function uuidV4From(digest: Buffer): string {
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

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
  /** Lab override for the relay provisioner's bridge verbs. */
  readonly mlsBridge?: RelayBridgePort | null;
  /** Lab override for outbound channel HTTP (Telegram sendMessage). */
  readonly fetchImpl?: FetchLike;
  /** Lab override for the best-effort project display name. */
  readonly projectName?: (chainId: string, projectId: string) => Promise<string | null>;
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
  readonly declineConversationRequest: (request: Request) => Promise<Response>;
  readonly listInstallations: (request: Request) => Promise<Response>;
  readonly revokeInstallation: (
    request: Request,
    installationId: string,
  ) => Promise<Response>;
  readonly createNotificationChannel: (request: Request) => Promise<Response>;
  readonly verifyNotificationChannel: (request: Request) => Promise<Response>;
  readonly listNotificationChannels: (request: Request) => Promise<Response>;
  readonly deleteNotificationChannel: (
    request: Request,
    channelId: string,
  ) => Promise<Response>;
  readonly telegramWebhook: (request: Request) => Promise<Response>;
  readonly activateConversation: (request: Request) => Promise<Response>;
  readonly listConversations: (request: Request) => Promise<Response>;
  readonly registerProjectStaff: (
    request: Request,
    projectRefId: string,
  ) => Promise<Response>;
  readonly registerOwnerStaff: (request: Request) => Promise<Response>;
  readonly readKeyPackageShelf: (
    request: Request,
    installationId: string,
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
  /** Internal: records the server's external-sender Add/Remove proposal. */
  readonly recordMembershipProposal: (request: Request) => Promise<Response>;
  /** ADR 0006 consent: compose the Add (POST) / Remove (DELETE) of the caller's relay. */
  readonly enableConversationRelay: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  readonly disableConversationRelay: (
    request: Request,
    conversationId: string,
  ) => Promise<Response>;
  /** Internal (keeper-triggered): ADR 0006 §4 outbound relay drain. */
  readonly relayDrain: (request: Request) => Promise<Response>;
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
    readonly intents: MembershipIntentStore | null;
    readonly commits: MembershipCommitStore | null;
    readonly proposals: ExternalProposalStore | null;
    readonly relays: (RelayInstallationStore & { readonly bridge: RelayBridgePort }) | null;
    readonly fetchImpl: FetchLike;
    readonly projectName: (chainId: string, projectId: string) => Promise<string | null>;
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
    readonly notifications: NotificationChannelStore;
    readonly notificationsConfig: {
      readonly appOrigin: string;
      readonly email: { readonly apiKey: string; readonly from: string } | null;
      readonly telegram: {
        readonly botToken: string;
        readonly botUsername: string;
        readonly webhookSecret: string | null;
      } | null;
    } | null;
    readonly dispatcher: NotificationDispatcher | null;
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
      intents: config.provisioningSeed
        ? createMembershipIntentStore({
            sql,
            provisioningSeed: config.provisioningSeed,
          })
        : null,
      commits:
        logSigner && config.provisioningSeed
          ? createMembershipCommitStore({
              sql,
              signer: logSigner,
              provisioningSeed: config.provisioningSeed,
            })
          : null,
      proposals: logSigner
        ? createExternalProposalStore({ sql, signer: logSigner })
        : null,
      relays: (() => {
        const bridge =
          contextValue.mlsBridge === undefined
            ? environmentRelayBridge()
            : contextValue.mlsBridge;
        return bridge
          ? Object.freeze({
              ...createRelayInstallationStore({ sql, bridge, seal: crypto }),
              bridge,
            })
          : null;
      })(),
      fetchImpl: contextValue.fetchImpl ?? globalThis.fetch,
      projectName: contextValue.projectName ?? bendystrawProjectName,
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
        hmacEligibilitySubject: crypto.hmacEligibilitySubject,
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
      notifications: createNotificationChannelStore({
        sql,
        hmacSecret: (secret: string) =>
          createHmac("sha256", config.identitySecret)
            .update("jbm-notification-channel-secret/v1\n", "utf8")
            .update(secret, "utf8")
            .digest(),
        now: now as never,
      }),
      notificationsConfig: config.notifications,
      dispatcher: config.notifications
        ? createNotificationDispatcher({
            sql,
            config: config.notifications,
            fetchImpl: contextValue.fetchImpl,
          })
        : null,
    };
    return cached;
  };

  // ADR 0006 §3 - the product copy must say exactly this.
  const RELAY_CONFIDENTIALITY_STATEMENT =
    "While this relay is active, this conversation's messages transit the service for your Telegram delivery and live transiently on Telegram's servers. This is a per-conversation downgrade from device-only end-to-end encryption to service-mediated delivery, chosen by you and visible to everyone in the conversation.";

  async function liveMembership(
    wired: Wired,
    conversationId: string,
    session: AuthenticatedSession,
  ): Promise<{ role: string; projectRefId: string } | null> {
    const rows = await wired.sql`
      SELECT m.role, c.project_ref_id
      FROM memberships m
      JOIN conversations c ON c.conversation_id = m.conversation_id
      WHERE m.conversation_id = ${conversationId}
        AND m.installation_id = ${session.installationId}
        AND m.removed_at IS NULL`;
    if (rows.length !== 1) return null;
    return { role: String(rows[0].role), projectRefId: String(rows[0].project_ref_id) };
  }

  async function relayStatusFor(
    wired: Wired,
    conversationId: string,
    accountId: string,
  ): Promise<Record<string, unknown>> {
    const seats = wired.relays
      ? await wired.relays.seatsForConversation(conversationId)
      : [];
    const pending = await wired.sql`
      SELECT r.channel_kind FROM membership_intents mi
      JOIN relay_installations r ON r.relay_installation_id = mi.target_installation_id
      WHERE mi.conversation_id = ${conversationId}
        AND mi.operation = 'add'
        AND mi.state IN ('requested', 'authorized', 'proposed')
        AND r.served_account_id = ${accountId}`;
    const mineTelegram = seats.some(
      (seat) => seat.servedAccountId === accountId && seat.channelKind === "telegram",
    )
      ? "active"
      : pending.some((row) => String(row.channel_kind) === "telegram")
        ? "pending"
        : "none";
    return {
      seats: seats.map((seat) => ({
        installationId: seat.installationId,
        channelKind: seat.channelKind,
        role: seat.role,
        mine: seat.servedAccountId === accountId,
      })),
      mine: { telegram: mineTelegram },
      statement: RELAY_CONFIDENTIALITY_STATEMENT,
    };
  }

  /**
   * The consent lane's server half (ADR 0006 §2): a normal membership intent
   * targeting the relay plus the service's external proposal, recorded
   * in-process. The proposal's PublicMessage is the service's authorization
   * record - the bridge has no external-sender signing verb yet, and the
   * member's device commits a self-authored Add/Remove exactly as activation
   * does - so it is labelled as such rather than dressed up as MLS.
   */
  async function composeRelayIntent(
    wired: Wired,
    input: {
      conversationId: string;
      session: AuthenticatedSession;
      operation: "add" | "remove";
      relayInstallationId: string;
      channelKind: string;
      grantId: string | null;
      projectRefId: string;
    },
  ): Promise<Response> {
    const intents = wired.intents!;
    const proposals = wired.proposals!;
    const created = await intents.createIntent({
      operation: input.operation,
      conversationId: input.conversationId,
      targetInstallationId: input.relayInstallationId,
      requestedByInstallationId: input.session.installationId,
      grantId: input.grantId,
    });
    if (created.status === "conflict") return problem(409, created.reasonCode);
    if (created.status === "refused") {
      return problem(
        created.reasonCode === "malformed-request" ? 400 : 403,
        created.reasonCode,
      );
    }
    const provision = await wired.sql.begin((tx) =>
      readProjectProvision(tx, input.projectRefId),
    );
    if (!provision) {
      await intents.cancelIntent(created.intentId, input.session.installationId);
      return problem(503, "project_not_provisioned");
    }
    const record = Buffer.from(
      JSON.stringify({
        kind:
          input.operation === "add"
            ? "jbm-relay-consent-authorization.v1"
            : "jbm-relay-consent-revocation.v1",
        intentId: created.intentId,
        conversationId: input.conversationId,
        relayInstallationId: input.relayInstallationId,
        servedAccountId: input.session.accountId,
        channelKind: input.channelKind,
        issuedAt: created.expiresAt,
      }),
      "utf8",
    );
    const recorded = await proposals.recordProposal({
      intentId: created.intentId,
      publicMessage: record.toString("base64url"),
      authorizationRecordHash: createHash("sha256")
        .update(record)
        .digest("base64url"),
      signerExternalSenderCredentialId: String(
        provision.current_external_sender_credential_id,
      ),
      transparencyCheckpointId: String(provision.policy_log_checkpoint_id),
    });
    if (recorded.status !== "recorded") {
      await intents.cancelIntent(created.intentId, input.session.installationId);
      return problem(503, recorded.reasonCode);
    }
    const mandatory = await wired.sql`
      SELECT p.proposal_id, p.proposal_hash
      FROM delivery_policy_head_anchors a
      JOIN policy_head_mandatory_proposals p ON p.policy_head_id = a.policy_head_id
      WHERE a.conversation_id = ${input.conversationId}
      ORDER BY p.ordinal`;
    const relayKey = await wired.sql`
      SELECT encode(mls_credential_public, 'base64') AS key FROM installations
      WHERE installation_id = ${input.relayInstallationId}`;
    return jsonNoStore(201, {
      operation: input.operation,
      relayInstallationId: input.relayInstallationId,
      relaySignatureKey: Buffer.from(
        String(relayKey[0]?.key ?? "").replace(/\s/g, ""),
        "base64",
      ).toString("base64url"),
      channelKind: input.channelKind,
      intent: created,
      mandatoryProposals: mandatory.map((row) => ({
        proposalId: String(row.proposal_id),
        proposalHash: Buffer.from(row.proposal_hash as Uint8Array).toString(
          "base64url",
        ),
      })),
      statement: RELAY_CONFIDENTIALITY_STATEMENT,
    });
  }

  /**
   * The append lane below the session: the same ports, service and
   * request commitment for a member's device (appendEnvelope) and for a
   * relay appending in-process (the Telegram webhook, ADR 0006 §5) - send
   * grant, custody fence, quotas and the witness gate are all enforced by
   * the delivery core, so a relay has no bypass surface.
   */
  async function appendForInstallation(
    wired: Wired,
    input: {
      conversationId: string;
      installationId: string;
      accountId: string;
      credential: Record<string, unknown>;
      idempotencyKey: string;
      ifMatch: string;
      rawText: string;
    },
  ): Promise<
    | { status: "log_key_unavailable" }
    | { status: "accepted" | "conflict" | "rejected" | "unavailable"; [key: string]: unknown }
  > {
    const { conversationId } = input;
    const keys = wired.appendKeys!;
    const validity = await wired.sql`
      SELECT valid_from, valid_until FROM delivery_log_signing_keys
      WHERE key_id = ${keys.keyId} AND state = 'active'`;
    if (validity.length !== 1) return { status: "log_key_unavailable" };
    const ports = {
      ...createKeyedDeliveryCryptoPorts({
        now: (() => now()) as never,
        snapshot: () =>
          wired.deliveryStore.loadSnapshot(conversationId as never, {
            installationId: input.installationId,
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
      mlsCommitProjectionVerifier: { verify: () => Promise.resolve(NOT_CONFIGURED) },
      mlsExternalProposalVerifier: { verify: () => Promise.resolve(NOT_CONFIGURED) },
      conversationPolicyReplayVerifier: { verify: () => Promise.resolve(NOT_CONFIGURED) },
      conversationPageProofVerifier: { verify: () => Promise.resolve(NOT_CONFIGURED) },
      conversationLogHeadProofVerifier: { verify: () => Promise.resolve(NOT_CONFIGURED) },
      applicationAppendPreflight: wired.deliveryStore.applicationAppendPreflight,
      atomicPersistence: wired.deliveryStore.atomicPersistence,
      clock: { now: (() => now()) as never },
      conversationCursorCodec: wired.cursorCodec ?? {
        decode: () => Promise.resolve(NOT_CONFIGURED),
        encode: () => Promise.resolve(NOT_CONFIGURED),
      },
      invariantIncident: {
        record: (incident: unknown) => {
          console.error("DELIVERY INVARIANT INCIDENT", incident);
          return Promise.resolve({ status: "recorded" });
        },
      },
    };
    const trust = wired.trust!;
    const service = createApplicationEnvelopeDeliveryService(ports as never, {
      realmId: trust.realmId,
      releaseProfileId: trust.releaseProfileId,
      releaseTrustRootDigest: trust.releaseTrustRootDigest,
      deliveryLimitsDigest: trust.deliveryLimitsDigest,
      deliveryLimits: trust.deliveryLimits,
    });
    const result = await service.appendApplicationEnvelope({
      idempotencyKey: input.idempotencyKey,
      authenticatedSender: {
        type: "installation",
        accountId: input.accountId,
        installationId: input.installationId,
      },
      authenticatedCredentialId: String(input.credential.role_credential_id),
      authenticatedCredentialFingerprint: Buffer.from(
        String(input.credential.fingerprint).replace(/\s/g, ""),
        "base64",
      ).toString("base64url"),
      authenticatedCredentialRevocationVersion: String(
        input.credential.revocation_version,
      ),
      request: {
        method: "POST",
        routeTemplate: APPLICATION_ENVELOPE_APPEND_ROUTE,
        resourceId: conversationId,
        mediaType: API_V1_MEDIA_TYPE,
        ifMatch: input.ifMatch,
        rawBodyBytes: Buffer.from(input.rawText, "utf8"),
        queryString: "",
        contentEncoding: null,
      },
    } as never);
    return result as never;
  }

  /** The active send grant + role credential the append lane binds. */
  async function sendGrantFor(
    wired: Wired,
    conversationId: string,
    installationId: string,
  ): Promise<Record<string, unknown> | null> {
    const grants = await wired.sql`
      SELECT g.credential_id, g.role_credential_id,
             encode(rc.credential_fingerprint, 'base64') AS fingerprint,
             rc.revocation_version
      FROM conversation_send_grants g
      JOIN role_credentials rc ON rc.credential_id = g.role_credential_id
      WHERE g.conversation_id = ${conversationId}
        AND g.installation_id = ${installationId}
        AND g.state = 'active'`;
    return grants.length === 1 ? grants[0] : null;
  }

  /**
   * ADR 0006 §5, the inbound path: a Telegram message from a verified chat
   * maps to the accounts that verified it, to their active relays, to the
   * conversations those relays are seated in; routeInbound picks one (or
   * asks), the relay seals under its row lock and appends through the
   * ordinary lane. Nothing is ever guessed; every refusal is a channel
   * reply, never a silent drop.
   */
  async function relayInbound(
    wired: Wired,
    cfg: { botToken: string },
    update: { updateId: string; chatId: string; text: string },
  ): Promise<void> {
    if (!wired.relays || !wired.appendKeys || !wired.trust) return;
    const accounts = await wired.notifications.accountsForTarget(
      "telegram",
      update.chatId,
    );
    const reply = (text: string) =>
      sendTelegramReply(cfg.botToken, update.chatId, text, wired.fetchImpl);
    const candidates: {
      relayInstallationId: string;
      relayAccountId: string;
      conversationId: string;
      groupId: string;
      context: RelayEnvelopeContext;
    }[] = [];
    for (const accountId of accounts) {
      const relay = await wired.relays.activeFor(accountId, "telegram");
      if (!relay) continue;
      const seats = await wired.sql`
        SELECT f.conversation_id, encode(f.mls_group_id, 'base64') AS group_id,
               m.role, p.chain_id, p.project_id::text AS project_id
        FROM relay_forward_watermarks f
        JOIN memberships m
          ON m.conversation_id = f.conversation_id
         AND m.installation_id = f.relay_installation_id
         AND m.removed_at IS NULL
        JOIN conversations c ON c.conversation_id = f.conversation_id
        JOIN project_refs p ON p.project_ref_id = c.project_ref_id
        WHERE f.relay_installation_id = ${relay.relayInstallationId}
          AND f.mls_group_id IS NOT NULL
          AND c.state = 'active'
        ORDER BY f.updated_at DESC`;
      for (const seat of seats) {
        const conversationId = String(seat.conversation_id);
        candidates.push({
          relayInstallationId: relay.relayInstallationId,
          relayAccountId: relay.relayAccountId,
          conversationId,
          groupId: Buffer.from(
            String(seat.group_id).replace(/\s/g, ""),
            "base64",
          ).toString("base64url"),
          context: {
            projectName: await wired.projectName(
              String(seat.chain_id),
              String(seat.project_id),
            ),
            projectId: String(seat.project_id),
            senderRole: String(seat.role),
            tag: conversationTag(conversationId),
          },
        });
      }
    }
    const route = routeInbound(
      update.text,
      candidates.map((candidate) => ({
        conversationId: candidate.conversationId,
        context: candidate.context,
      })),
    );
    if (route.kind === "ignore") return;
    if (route.kind === "prompt") {
      await reply(renderPrompt(route.options));
      return;
    }
    const chosen = candidates.find(
      (candidate) => candidate.conversationId === route.conversationId,
    )!;
    const credential = await sendGrantFor(
      wired,
      chosen.conversationId,
      chosen.relayInstallationId,
    );
    if (!credential) {
      await reply("This relay can't send here right now. Open the app to reply.");
      return;
    }
    const detail = await wired.sql`
      SELECT c.etag, c.epoch, c.roster_version,
             encode(c.confirmed_transcript_hash, 'base64') AS transcript,
             a.policy_head_id, a.policy_head_sequence,
             encode(a.policy_head_hash, 'base64') AS policy_head_hash,
             a.witness_state
      FROM conversations c
      LEFT JOIN delivery_policy_head_anchors a ON a.conversation_id = c.conversation_id
      WHERE c.conversation_id = ${chosen.conversationId}`;
    const row = detail[0];
    if (!row || row.policy_head_id === null || String(row.witness_state) !== "verified") {
      await reply("The conversation is being co-signed right now. Try again in a moment.");
      return;
    }
    const b64u = (value: unknown) =>
      Buffer.from(String(value).replace(/\s/g, ""), "base64").toString("base64url");
    // Seal under the relay's row lock; the mutated state is resealed there.
    const message = await wired.relays.withState(
      chosen.relayInstallationId,
      async (state) => {
        const sealed = await wired.relays!.bridge.sealApplication(
          state,
          chosen.groupId,
          new TextEncoder().encode(route.text),
        );
        return { state: sealed.state, result: sealed.message };
      },
    );
    const ciphertext = Buffer.from(message, "base64url");
    // One Telegram update is one append: retries replay, edits conflict.
    const updateDigest = createHash("sha256")
      .update(`telegram:${update.updateId}`)
      .digest();
    const envelopeId = uuidV4From(updateDigest);
    const body = JSON.stringify({
      envelopeId,
      policyHeadId: String(row.policy_head_id),
      policyHeadSequence: String(row.policy_head_sequence),
      policyHeadHash: b64u(row.policy_head_hash),
      expectedEpoch: String(row.epoch),
      expectedRosterVersion: String(row.roster_version),
      expectedConfirmedTranscriptHash: b64u(row.transcript),
      contentType: "application/vnd.juicebox.messaging.mls-private-message",
      ciphertext: ciphertext.toString("base64url"),
      envelopeSha256: createHash("sha256").update(ciphertext).digest("base64url"),
      attachmentIds: [],
    });
    const result = await appendForInstallation(wired, {
      conversationId: chosen.conversationId,
      installationId: chosen.relayInstallationId,
      accountId: chosen.relayAccountId,
      credential,
      idempotencyKey: updateDigest.toString("base64url"),
      ifMatch: String(row.etag),
      rawText: body,
    });
    if (result.status === "accepted") {
      if (wired.dispatcher) {
        void notifyConversationPeers(wired, chosen.conversationId, chosen.relayAccountId)
          .catch(() => undefined);
      }
      return;
    }
    console.error("relay inbound append refused", result);
    await reply("Your reply couldn't be delivered. Open the app to send it.");
  }

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

  // Quorum-ownerOf ownership proof + staff upsert, shared by the
  // projectRefId route and the on-demand owner registration.
  const registerStaffForRef = async (
    wired: Wired,
    session: AuthenticatedSession,
    projectRefId: string,
  ): Promise<Response> => {
    if (!wired.chainRegistry) return notFound();
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
      if (!wired.intents) return notFound();
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
      if (!wired.intents) return notFound();
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
      const walletRef = (body as Record<string, unknown>).walletRef;
      const result = await wired.requests.createRequest({
        requesterAccountId: session.accountId,
        requesterInstallationId: session.installationId,
        eligibilityClaimHandle: handle,
        requesterWalletRef:
          typeof walletRef === "string" ? walletRef : undefined,
      });
      if (result.status === "refused") {
        return problem(
          result.reasonCode === "conversation_exists" ? 409 : 403,
          result.reasonCode,
        );
      }
      // A newly-lodged request wakes the project's staff on their channels.
      if (result.status === "created" && wired.dispatcher) {
        void notifyProjectStaff(wired, result.projectRefId).catch(
          () => undefined,
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

    async declineConversationRequest(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const requestId = (body as Record<string, unknown>).requestId;
      if (typeof requestId !== "string" || !UUID_PATTERN.test(requestId)) {
        return problem(400, "malformed_request");
      }
      const result = await wired.requests.declineRequest({
        requestId,
        ownerAccountId: session.accountId,
        ownerInstallationId: session.installationId,
      });
      if (result.status === "refused") {
        return problem(
          result.reasonCode === "request_not_pending" ? 404 : 403,
          result.reasonCode,
        );
      }
      return jsonNoStore(200, { status: "declined" });
    },

    async listInstallations(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const rows = await wired.sql`
        SELECT installation_id, platform, status, created_at, last_seen_at
        FROM installations
        WHERE account_id = ${session.accountId}
          AND status IN ('active', 'suspended')
        ORDER BY created_at`;
      return jsonNoStore(200, {
        installations: rows.map((row) => ({
          installationId: String(row.installation_id),
          platform: String(row.platform),
          status: String(row.status),
          createdAt: new Date(row.created_at as Date).toISOString(),
          lastSeenAt: new Date(row.last_seen_at as Date).toISOString(),
          current: String(row.installation_id) === session.installationId,
        })),
      });
    },

    async revokeInstallation(
      request: Request,
      installationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(installationId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      // A device cannot revoke itself — sign out covers that; requiring a
      // SECOND device to do the revoking keeps a stolen device from
      // locking the owner out of their own account.
      if (installationId === session.installationId) {
        return problem(409, "cannot_revoke_current_device");
      }
      const nowIso = now();
      const revoked = await wired.sql.begin(async (tx) => {
        const target = await tx`
          UPDATE installations
          SET status = 'revoked', revoked_at = ${nowIso}::timestamptz
          WHERE installation_id = ${installationId}
            AND account_id = ${session.accountId}
            AND status IN ('active', 'suspended')
          RETURNING installation_id`;
        if (target.length !== 1) return false;
        // Credentials and sessions die with the device: the auth path
        // re-checks credential status on every call, so this is a full
        // lock-out. The device's MLS seats in existing conversations are
        // left to the roster-removal flow; it can no longer fetch anything.
        await tx`
          UPDATE device_credentials
          SET status = 'revoked', revoked_at = ${nowIso}::timestamptz
          WHERE installation_id = ${installationId} AND status = 'active'`;
        await tx`
          UPDATE auth_sessions
          SET state = 'revoked', revoked_at = ${nowIso}::timestamptz,
              revoke_reason = 'device_revoked'
          WHERE installation_id = ${installationId} AND state = 'active'`;
        // Unclaimed KeyPackages are destroyed so no future plan can
        // welcome the revoked device.
        await tx`
          UPDATE key_packages
          SET state = 'revoked', package_bytes = NULL,
              destroyed_at = ${nowIso}::timestamptz,
              revoked_at = ${nowIso}::timestamptz
          WHERE installation_id = ${installationId} AND state = 'available'`;
        return true;
      });
      if (!revoked) return notFound();
      return jsonNoStore(200, { status: "revoked", installationId });
    },

    async createNotificationChannel(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      const kind = record.kind;
      const target = record.target;
      if (
        (kind !== "email" && kind !== "telegram" && kind !== "whatsapp") ||
        typeof target !== "string"
      ) {
        return problem(400, "malformed_request");
      }
      const cfg = wired.notificationsConfig;
      // Refuse a channel we can't deliver a verification secret for.
      if (kind === "email" && !cfg?.email) {
        return problem(503, "email_unconfigured");
      }
      if (kind === "telegram" && !cfg?.telegram) {
        return problem(503, "telegram_unconfigured");
      }
      const created = await wired.notifications.createChannel({
        accountId: session.accountId,
        kind: kind as ChannelKind,
        target,
      });
      if (created.status === "refused") {
        return problem(
          created.reasonCode === "already_active" ? 409 : 400,
          created.reasonCode,
        );
      }
      if (created.kind === "email" && cfg?.email) {
        void sendVerificationEmail(cfg, target, created.secret).catch(
          () => undefined,
        );
        return jsonNoStore(201, {
          channelId: created.channelId,
          kind: "email",
          verify: "code_sent",
        });
      }
      if (created.kind === "telegram" && cfg?.telegram) {
        return jsonNoStore(201, {
          channelId: created.channelId,
          kind: "telegram",
          verify: "deep_link",
          deepLink: telegramDeepLink(cfg.telegram.botUsername, created.secret),
        });
      }
      // whatsapp: stored pending; no sender wired yet.
      return jsonNoStore(201, {
        channelId: created.channelId,
        kind: created.kind,
        verify: "pending_provider",
      });
    },

    async verifyNotificationChannel(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      if (
        typeof record.channelId !== "string" ||
        typeof record.code !== "string"
      ) {
        return problem(400, "malformed_request");
      }
      const result = await wired.notifications.verifyEmailCode({
        accountId: session.accountId,
        channelId: record.channelId,
        code: record.code,
      });
      if (result.status !== "active") {
        return problem(result.status === "expired" ? 410 : 400, result.status);
      }
      return jsonNoStore(200, { status: "active" });
    },

    async listNotificationChannels(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "GET") return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const channels = await wired.notifications.list(session.accountId);
      return jsonNoStore(200, {
        channels,
        providers: {
          email: Boolean(wired.notificationsConfig?.email),
          telegram: Boolean(wired.notificationsConfig?.telegram),
          whatsapp: false,
        },
      });
    },

    async deleteNotificationChannel(
      request: Request,
      channelId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "DELETE") return notFound();
      if (!UUID_PATTERN.test(channelId)) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const removed = await wired.notifications.disable(
        session.accountId,
        channelId,
      );
      return removed ? new Response(null, { status: 204 }) : notFound();
    },

    async telegramWebhook(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      const cfg = wired.notificationsConfig?.telegram;
      if (!cfg) return notFound();
      // Telegram echoes the secret we set on the webhook; reject anything else.
      if (
        cfg.webhookSecret &&
        request.headers.get("x-telegram-bot-api-secret-token") !==
          cfg.webhookSecret
      ) {
        return problem(401, "unauthorized");
      }
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return new Response(null, { status: 200 });
      const message = (body as Record<string, unknown>).message as
        | Record<string, unknown>
        | undefined;
      const text = message?.text;
      const chat = message?.chat as Record<string, unknown> | undefined;
      const chatId = chat?.id;
      const match =
        typeof text === "string" ? text.match(/^\/start\s+(\S+)/) : null;
      const updateId = (body as Record<string, unknown>).update_id;
      if (
        !match &&
        typeof text === "string" &&
        (typeof chatId === "number" || typeof chatId === "string") &&
        (typeof updateId === "number" || typeof updateId === "string")
      ) {
        // ADR 0006 §5: a relayed reply. Errors are logged, never leaked to
        // Telegram as a non-200 (it would retry forever).
        try {
          await relayInbound(wired, cfg, {
            updateId: String(updateId),
            chatId: String(chatId),
            text,
          });
        } catch (error) {
          console.error("relay inbound failed", String(error));
        }
      }
      if (match && (typeof chatId === "number" || typeof chatId === "string")) {
        const redeemed = await wired.notifications.redeemTelegramToken({
          token: match[1],
          chatId: String(chatId),
        });
        if (redeemed.status === "active") {
          void sendTelegramReply(
            cfg.botToken,
            String(chatId),
            "Connected. You'll get Fruitful notifications here.",
          ).catch(() => undefined);
        }
      }
      // Telegram retries non-200s; always ack.
      return new Response(null, { status: 200 });
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
      return registerStaffForRef(wired, session, projectRefId);
    },

    async registerOwnerStaff(request: Request): Promise<Response> {
      // Open, on-demand owner registration: the dashboard knows only
      // (chainId, projectId) from the indexer. The project_ref is
      // provisioned exactly like the claim path, and ownership is still
      // proven by quorum ownerOf inside registerStaffForRef — so this
      // opens nothing.
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.chainRegistry) return notFound();
      if (!wired.eligibility || !wired.provisioningSeed) return notFound();
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const record = body as Record<string, unknown>;
      if (
        typeof record.chainId !== "number" ||
        !Number.isSafeInteger(record.chainId) ||
        typeof record.projectId !== "number" ||
        !Number.isSafeInteger(record.projectId) ||
        record.projectId < 0
      ) {
        return problem(400, "malformed_request");
      }
      const contract = wired.eligibility.projectsContractFor(record.chainId);
      if (!contract) return problem(404, "project_unknown");
      const projectRefId = await ensureProjectRef(
        wired.sql,
        wired.provisioningSeed,
        now(),
        {
          chainId: record.chainId,
          projectId: record.projectId,
          projectsContract: contract,
        },
      );
      return registerStaffForRef(wired, session, projectRefId);
    },

    async readKeyPackageShelf(
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
        SELECT count(*)::int AS available FROM key_packages
        WHERE installation_id = ${installationId}
          AND state = 'available' AND taken_at IS NULL
          AND expires_at > ${now()}::timestamptz`;
      return jsonNoStore(200, { available: Number(rows[0].available) });
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

      const result = await appendForInstallation(wired, {
        conversationId,
        installationId: session.installationId,
        accountId: session.accountId,
        credential: grants[0],
        idempotencyKey,
        ifMatch,
        rawText,
      });
      if (result.status === "log_key_unavailable") {
        return problem(503, "log_key_unavailable");
      }
      if (result.status === "accepted") {
        // Wake the other participants out-of-band (content stays E2E).
        if (wired.dispatcher) {
          void notifyConversationPeers(
            wired,
            conversationId,
            session.accountId,
          ).catch(() => undefined);
        }
        return jsonNoStore(201, result);
      }
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
      const relay = await relayStatusFor(wired, conversationId, session.accountId);
      return jsonNoStore(200, {
        conversationId,
        relay,
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
        { provisioningSeed: wired.provisioningSeed },
      );
      return jsonNoStore(200, report);
    },

    // The external proposal is the SERVICE acting as the MLS external
    // sender (service-api.md §8.2): a member session must never supply the
    // PublicMessage bytes the log attributes to the entitlement signer, so
    // this rides the internal bearer scheme, not DPoP. The store still
    // proves the intent is live, the signer credential is the project's
    // published one, and the transparency checkpoint exists.
    async recordMembershipProposal(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.proposals || !wired.internalSyncToken) return notFound();
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      // A PublicMessage may be up to 256 KiB decoded; the commit ceiling
      // covers its base64url form with room for the envelope fields.
      const body = await readBody(request, MAX_COMMIT_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const recorded = await wired.proposals.recordProposal(body);
      if (recorded.status === "conflict") {
        return problem(409, recorded.reasonCode);
      }
      if (recorded.status === "refused") {
        if (recorded.reasonCode === "malformed-request") {
          return problem(400, recorded.reasonCode);
        }
        if (recorded.reasonCode === "log-authority-unavailable") {
          return problem(503, recorded.reasonCode);
        }
        return problem(403, recorded.reasonCode);
      }
      return jsonNoStore(201, recorded);
    },

    async enableConversationRelay(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      if (!wired.intents || !wired.proposals || !wired.provisioningSeed) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const body = await readBody(request, MAX_BODY_BYTES);
      if (body === undefined) return problem(400, "malformed_request");
      const channelKind = (body as Record<string, unknown>).channelKind;
      if (channelKind !== "telegram") {
        return problem(400, "unsupported_channel");
      }
      const membership = await liveMembership(wired, conversationId, session);
      if (!membership) return notFound();
      const targets = await wired.notifications.activeTargets(session.accountId);
      if (!targets.some((target) => target.kind === channelKind)) {
        return problem(403, "channel_not_verified");
      }
      if (!wired.relays) return problem(503, "bridge_unavailable");
      const seats = await wired.relays.seatsForConversation(conversationId);
      if (
        seats.some(
          (seat) =>
            seat.servedAccountId === session.accountId &&
            seat.channelKind === channelKind,
        )
      ) {
        return problem(409, "relay_already_member");
      }
      const relay = await wired.relays.provision({
        servedAccountId: session.accountId,
        channelKind,
      });
      const grant = await issueRelayGrant(
        wired.sql,
        wired.crypto,
        {
          projectRefId: membership.projectRefId,
          relayAccountId: relay.relayAccountId,
          relayInstallationId: relay.relayInstallationId,
          servedAccountId: session.accountId,
          channelKind,
        },
        now(),
      );
      if (grant.status !== "issued") return problem(503, grant.reasonCode);
      return composeRelayIntent(wired, {
        conversationId,
        session,
        operation: "add",
        relayInstallationId: relay.relayInstallationId,
        channelKind,
        grantId: grant.grantId,
        projectRefId: membership.projectRefId,
      });
    },

    async disableConversationRelay(
      request: Request,
      conversationId: string,
    ): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "DELETE") return notFound();
      if (!UUID_PATTERN.test(conversationId)) return notFound();
      if (!wired.intents || !wired.proposals || !wired.provisioningSeed) {
        return notFound();
      }
      const session = await authenticate(wired, request);
      if (!session) return problem(401, "session_invalid");
      const membership = await liveMembership(wired, conversationId, session);
      if (!membership) return notFound();
      if (!wired.relays) return problem(503, "bridge_unavailable");
      const seat = (await wired.relays.seatsForConversation(conversationId)).find(
        (candidate) => candidate.servedAccountId === session.accountId,
      );
      if (!seat) return problem(404, "relay_not_active");
      return composeRelayIntent(wired, {
        conversationId,
        session,
        operation: "remove",
        relayInstallationId: seat.installationId,
        channelKind: seat.channelKind,
        grantId: null,
        projectRefId: membership.projectRefId,
      });
    },

    async relayDrain(request: Request): Promise<Response> {
      const wired = wire();
      if (!wired || request.method !== "POST") return notFound();
      if (!wired.internalSyncToken) return notFound();
      const authorization = request.headers.get("authorization");
      if (authorization !== `Bearer ${wired.internalSyncToken}`) {
        return problem(401, "unauthorized");
      }
      if (!wired.relays) return problem(503, "bridge_unavailable");
      const telegram = wired.notificationsConfig?.telegram ?? null;
      const relays = wired.relays;
      const report = await runRelayDrain({
        sql: wired.sql,
        relays,
        bridge: relays.bridge,
        activeTargets: (accountId) => wired.notifications.activeTargets(accountId),
        sendText: async (channelKind, target, text) => {
          if (channelKind !== "telegram" || !telegram) return false;
          return sendTelegram(telegram.botToken, { chatId: target, text }, wired.fetchImpl);
        },
        projectName: wired.projectName,
      });
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
        mlsBridge: await describeMlsBridge(),
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

/** The production relay provisioner's bridge: one pinned subprocess per call. */
function environmentRelayBridge(): RelayBridgePort | null {
  const resolved = resolveMlsBridgeFromEnvironment();
  if (resolved.status !== "ready") return null;
  const withBridge = async <T,>(
    run: (client: MlsBridgeClient) => Promise<T>,
  ): Promise<T> => {
    const client = resolved.open();
    try {
      return await run(client);
    } finally {
      client.close();
    }
  };
  return Object.freeze({
    createIdentity: (label: string) =>
      withBridge((client) => client.createIdentity(label)),
    generateKeyPackage: (state: string) =>
      withBridge((client) => client.generateKeyPackage(state)),
    joinWelcome: (state: string, welcome: string) =>
      withBridge((client) => client.joinWelcome(state, welcome)),
    sealApplication: (state: string, groupId: string, plaintext: Uint8Array) =>
      withBridge((client) => client.sealApplication(state, groupId, plaintext)),
    openApplication: (state: string, groupId: string, message: string) =>
      withBridge((client) => client.openApplication(state, groupId, message)),
    processCommit: (state: string, groupId: string, commit: string) =>
      withBridge((client) => client.processCommit(state, groupId, commit)),
  });
}

// Operator-facing proof that the release-pinned bridge is live: the
// resolution (absent/refused/ready with the pinned digest) plus one
// bridge/describe round trip.
async function describeMlsBridge(): Promise<Record<string, unknown>> {
  const resolved = resolveMlsBridgeFromEnvironment();
  if (resolved.status !== "ready") return resolved;
  const client = resolved.open();
  try {
    const description = await client.describe();
    return {
      status: "ready",
      verification: resolved.verification,
      bridgeProtocol: description.bridgeProtocol,
      ciphersuite: description.ciphersuite,
    };
  } catch (error) {
    return { status: "unresponsive", reason: String(error) };
  } finally {
    client.close();
  }
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
/** Wake a project's active staff on their notification channels. */
async function notifyProjectStaff(
  wired: { sql: Sql; dispatcher: NotificationDispatcher | null },
  projectRefId: string,
): Promise<void> {
  if (!wired.dispatcher) return;
  const rows = await wired.sql`
    SELECT DISTINCT account_id FROM project_staff_registrations
    WHERE project_ref_id = ${projectRefId} AND state = 'active'`;
  await wired.dispatcher.dispatch(
    rows.map((row) => String(row.account_id)),
    "request",
    projectRefId,
  );
}

/** Wake a conversation's other participants (not the sender) on a new message. */
async function notifyConversationPeers(
  wired: { sql: Sql; dispatcher: NotificationDispatcher | null },
  conversationId: string,
  senderAccountId: string,
): Promise<void> {
  if (!wired.dispatcher) return;
  const rows = await wired.sql`
    SELECT DISTINCT account_id FROM memberships
    WHERE conversation_id = ${conversationId}
      AND account_id <> ${senderAccountId}`;
  await wired.dispatcher.dispatch(
    rows.map((row) => String(row.account_id)),
    "message",
    conversationId,
  );
}

async function sendVerificationEmail(
  cfg: { email: { apiKey: string; from: string } | null; appOrigin: string },
  to: string,
  code: string,
): Promise<void> {
  if (!cfg.email) return;
  await sendEmail(cfg.email, {
    to,
    subject: "Your Fruitful verification code",
    text: `Your Fruitful verification code is ${code}. It expires in 15 minutes.`,
  });
}

async function sendTelegramReply(
  botToken: string,
  chatId: string,
  text: string,
  fetchImpl: FetchLike = globalThis.fetch,
): Promise<void> {
  await sendTelegram(botToken, { chatId, text }, fetchImpl);
}

// Best-effort display name from Bendystraw; the relay copy falls back to
// "Project #id" when the lookup fails or the project has no name.
const projectNameCache = new Map<string, { name: string | null; at: number }>();
async function bendystrawProjectName(
  chainId: string,
  projectId: string,
): Promise<string | null> {
  const chainNumber = Number(chainId.replace(/^eip155:/, ""));
  if (!Number.isSafeInteger(chainNumber) || !/^[0-9]+$/.test(projectId)) return null;
  const key = `${chainNumber}:${projectId}`;
  const cached = projectNameCache.get(key);
  if (cached && Date.now() - cached.at < 5 * 60_000) return cached.name;
  try {
    const meta = await new BendystrawDiscoveryAdapter().projectMeta([
      { chainId: chainNumber, projectId: Number(projectId) },
    ]);
    const name = meta[key]?.name ?? null;
    projectNameCache.set(key, { name, at: Date.now() });
    return name;
  } catch {
    return null;
  }
}

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
