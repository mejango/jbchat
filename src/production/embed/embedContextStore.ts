import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import type { EmbedContextCryptoPort } from "./embedContextCrypto";

const CONTEXT_TTL_MILLISECONDS = 2 * 60 * 1_000;
const SESSION_TTL_MILLISECONDS = 10 * 60 * 1_000;
const EMBED_PROTOCOL = "org.juicebox.messaging.embed";
const PURGE_RETENTION_MILLISECONDS = 24 * 60 * 60 * 1_000;

const TENANT_PUBLIC_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const RESOURCE_REF_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const PURPOSES = ["open-secure-messaging"] as const;
const ACTIONS = ["open"] as const;

export interface EmbedContextStoreContext {
  readonly sql: Sql;
  readonly now: () => string;
  readonly crypto: EmbedContextCryptoPort;
}

export type EmbedContextIssueResult =
  | {
      readonly status: "issued";
      readonly embedContextId: string;
      readonly contextHandle: string;
      readonly state: "issued";
      readonly issuedAt: string;
      readonly notBefore: string;
      readonly expiresAt: string;
    }
  | { readonly status: "refused"; readonly reasonCode: "issuance_refused" };

export type EmbedContextRedemptionResult =
  | {
      readonly status: "redeemed";
      readonly state: "authentication_required";
      readonly expiresAt: string;
      readonly sessionToken: string;
      readonly resourceRef: string;
    }
  | { readonly status: "invalid"; readonly reasonCode: "context_invalid" };

export type EmbedSessionReadResult =
  | {
      readonly status: "live";
      readonly state: "authentication_required";
      readonly expiresAt: string;
    }
  | { readonly status: "invalid"; readonly reasonCode: "session_invalid" };

export interface EmbedContextStore {
  readonly issueContext: (input: unknown) => Promise<EmbedContextIssueResult>;
  readonly redeemContext: (
    input: unknown,
  ) => Promise<EmbedContextRedemptionResult>;
  readonly readSession: (
    sessionToken: unknown,
  ) => Promise<EmbedSessionReadResult>;
  readonly revokeSession: (sessionToken: unknown) => Promise<void>;
  readonly revokeParentOrigin: (
    tenantPublicId: unknown,
    canonicalParentOrigin: unknown,
  ) => Promise<void>;
}

interface IssueInput {
  readonly tenantPublicId: string;
  readonly parentOrigin: string;
  readonly frameAudience: string;
  readonly hostClientId: string;
  readonly purpose: (typeof PURPOSES)[number];
  readonly action: (typeof ACTIONS)[number];
  readonly resourceRef: string;
}

interface RedeemInput {
  readonly contextHandle: string;
  readonly tenantPublicId: string;
  readonly parentOrigin: string;
  readonly frameAudience: string;
  readonly channelId: string;
  readonly bootstrapNonce: string;
  readonly parentNonce: string;
  readonly frameNonce: string;
}

/**
 * PostgreSQL adapter for tenant-bound one-use embed contexts, redemptions,
 * and embed sessions (service-api.md section 3.7). Authority is compared
 * against the stored tenant/origin/issuer configuration, never learned from
 * the request; every redemption failure collapses to one context_invalid
 * result; and a failed claim is terminal. OAuth/mTLS caller authentication
 * and cookie/Fetch-Metadata enforcement live in the HTTP layer above this
 * store and must be composed before any endpoint is exposed.
 */
export function createEmbedContextStore(
  context: EmbedContextStoreContext,
): EmbedContextStore {
  const { sql, crypto } = context;

  const nowIso = (): string => {
    const value = context.now();
    if (new Date(value).toISOString() !== value) {
      throw new TypeError("Embed context clock must be canonical UTC ISO time.");
    }
    return value;
  };

  const loadActiveTenantBinding = async (
    tx: TransactionSql,
    input: Pick<
      IssueInput,
      "tenantPublicId" | "parentOrigin" | "frameAudience" | "hostClientId"
    >,
  ) => {
    const rows = await tx`
      SELECT t.tenant_id, t.frame_audience, o.tenant_origin_id,
             c.embed_issuer_client_id, c.allowed_purposes
      FROM tenants t
      JOIN tenant_parent_origins o ON o.tenant_id = t.tenant_id
      JOIN embed_issuer_clients c ON c.tenant_id = t.tenant_id
      WHERE t.tenant_public_id = ${input.tenantPublicId}
        AND t.status = 'active'
        AND t.embed_state = 'active'
        AND t.frame_audience = ${input.frameAudience}
        AND o.environment = 'production'
        AND o.canonical_https_origin = ${input.parentOrigin}
        AND o.state = 'active'
        AND o.verified_at IS NOT NULL
        AND c.client_id = ${input.hostClientId}
        AND c.audience = ${input.frameAudience}
        AND c.state = 'active'`;
    return rows.length === 1 ? rows[0] : null;
  };

  return Object.freeze({
    async issueContext(inputValue: unknown): Promise<EmbedContextIssueResult> {
      let input: IssueInput;
      try {
        input = parseIssueInput(inputValue);
      } catch {
        return refusedIssue();
      }
      const issuedAt = nowIso();
      const expiresAt = new Date(
        Date.parse(issuedAt) + CONTEXT_TTL_MILLISECONDS,
      ).toISOString();
      const purgeAfter = new Date(
        Date.parse(issuedAt) + PURGE_RETENTION_MILLISECONDS,
      ).toISOString();
      const embedContextId = uuidV7(issuedAt);
      const contextHandle = randomBytes(32).toString("base64url");
      const creationNonce = randomBytes(32).toString("base64url");
      const sealed = crypto.sealResourceRef(input.resourceRef);
      const scopeCanonical = {
        purpose: input.purpose,
        action: input.action,
        kind: "opaque-host-resource.v1",
      };
      const issued = await sql.begin(async (tx) => {
        const binding = await loadActiveTenantBinding(tx, input);
        if (!binding) return false;
        const allowedPurposes = canonicalJson(binding.allowed_purposes);
        if (
          !Array.isArray(allowedPurposes) ||
          !allowedPurposes.includes(input.purpose)
        ) {
          return false;
        }
        await tx`
          INSERT INTO embed_contexts (
            embed_context_id, context_handle_hash, tenant_id, tenant_origin_id,
            embed_issuer_client_id, canonical_parent_origin, frame_audience,
            host_client_id, purpose, action, context_kind, scope_canonical,
            scope_hash, resource_ref_lookup, resource_ref_ciphertext,
            resource_ref_kms_key_version, creation_nonce_hash, state,
            issued_at, not_before, expires_at, purge_after
          ) VALUES (
            ${embedContextId}, ${crypto.hmacContextHandle(contextHandle)},
            ${binding.tenant_id}, ${binding.tenant_origin_id},
            ${binding.embed_issuer_client_id}, ${input.parentOrigin},
            ${input.frameAudience}, ${input.hostClientId}, ${input.purpose},
            ${input.action}, 'opaque-host-resource.v1',
            ${JSON.stringify(scopeCanonical)}::jsonb,
            ${sha256Utf8(JSON.stringify(scopeCanonical))},
            ${crypto.hmacResourceRefLookup(input.resourceRef)},
            ${sealed.ciphertext}, ${sealed.kmsKeyVersion},
            ${sha256Utf8(creationNonce)}, 'issued',
            ${issuedAt}::timestamptz, ${issuedAt}::timestamptz,
            ${expiresAt}::timestamptz, ${purgeAfter}::timestamptz
          )`;
        return true;
      });
      if (!issued) return refusedIssue();
      return Object.freeze({
        status: "issued",
        embedContextId,
        contextHandle,
        state: "issued",
        issuedAt,
        notBefore: issuedAt,
        expiresAt,
      });
    },

    async redeemContext(
      inputValue: unknown,
    ): Promise<EmbedContextRedemptionResult> {
      let input: RedeemInput;
      try {
        input = parseRedeemInput(inputValue);
      } catch {
        return contextInvalid();
      }
      const now = nowIso();
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT c.embed_context_id, c.tenant_id, c.tenant_origin_id,
                 c.embed_issuer_client_id, c.canonical_parent_origin,
                 c.frame_audience, c.host_client_id, c.purpose, c.action,
                 c.scope_hash, c.resource_ref_lookup, c.resource_ref_ciphertext,
                 c.resource_ref_kms_key_version, c.state, c.not_before,
                 c.expires_at, c.purge_after, t.tenant_public_id, t.status AS tenant_status,
                 t.embed_state, o.state AS origin_state
          FROM embed_contexts c
          JOIN tenants t ON t.tenant_id = c.tenant_id
          JOIN tenant_parent_origins o ON o.tenant_origin_id = c.tenant_origin_id
          WHERE c.context_handle_hash = ${crypto.hmacContextHandle(
            input.contextHandle,
          )}
          FOR UPDATE OF c`;
        if (rows.length !== 1) return contextInvalid();
        const row = rows[0];
        if (row.state !== "issued") return contextInvalid();
        const redemptionId = uuidV7(now);
        await tx`
          INSERT INTO embed_context_redemptions (
            embed_redemption_id, embed_context_id, request_sha256, protocol,
            protocol_version, channel_id_hash, bootstrap_nonce_hash,
            parent_nonce_hash, frame_nonce_hash, state, claimed_at, purge_after
          ) VALUES (
            ${redemptionId}, ${row.embed_context_id},
            ${sha256Utf8(JSON.stringify(input))}, ${EMBED_PROTOCOL}, 1,
            ${crypto.hmacChannelCommitment("channel-id", input.channelId)},
            ${crypto.hmacChannelCommitment("bootstrap-nonce", input.bootstrapNonce)},
            ${crypto.hmacChannelCommitment("parent-nonce", input.parentNonce)},
            ${crypto.hmacChannelCommitment("frame-nonce", input.frameNonce)},
            'claimed', ${now}::timestamptz, ${row.purge_after}::timestamptz
          )`;
        const claim = await tx`
          UPDATE embed_contexts SET state = 'claimed',
            claimed_at = ${now}::timestamptz,
            claimed_by_redemption_id = ${redemptionId}
          WHERE embed_context_id = ${row.embed_context_id} AND state = 'issued'
          RETURNING embed_context_id`;
        if (claim.length !== 1) return contextInvalid();

        const bindingsMatch =
          row.tenant_public_id === input.tenantPublicId &&
          row.canonical_parent_origin === input.parentOrigin &&
          row.frame_audience === input.frameAudience &&
          row.tenant_status === "active" &&
          row.embed_state === "active" &&
          row.origin_state === "active";
        const timely =
          iso(row.not_before) <= now && now < iso(row.expires_at);
        if (!bindingsMatch || !timely) {
          await tx`
            UPDATE embed_context_redemptions SET state = 'invalid',
              completed_at = ${now}::timestamptz,
              terminal_reason_code = 'binding-or-expiry-mismatch'
            WHERE embed_redemption_id = ${redemptionId}`;
          await tx`
            UPDATE embed_contexts SET state = 'invalid',
              terminal_reason_code = 'binding-or-expiry-mismatch'
            WHERE embed_context_id = ${row.embed_context_id}`;
          return contextInvalid();
        }
        const resourceRef = crypto.openResourceRef(
          Buffer.from(row.resource_ref_ciphertext),
          String(row.resource_ref_kms_key_version),
        );
        const sessionId = randomUuidV4();
        const sessionToken = randomBytes(32).toString("base64url");
        const sessionExpiresAt = new Date(
          Math.min(
            Date.parse(now) + SESSION_TTL_MILLISECONDS,
            Date.parse(iso(row.purge_after)),
          ),
        ).toISOString();
        await tx`
          INSERT INTO embed_sessions (
            embed_session_id, embed_session_token_hash, token_generation,
            embed_context_id, embed_redemption_id, tenant_id, tenant_origin_id,
            embed_issuer_client_id, canonical_parent_origin, frame_audience,
            host_client_id, purpose, action, scope_hash, resource_ref_lookup,
            channel_id_hash, bootstrap_nonce_hash, parent_nonce_hash,
            frame_nonce_hash, cookie_profile, state, issued_at, expires_at,
            purge_after
          ) VALUES (
            ${sessionId}, ${crypto.hmacSessionToken(sessionToken)}, 1,
            ${row.embed_context_id}, ${redemptionId}, ${row.tenant_id},
            ${row.tenant_origin_id}, ${row.embed_issuer_client_id},
            ${row.canonical_parent_origin}, ${row.frame_audience},
            ${row.host_client_id}, ${row.purpose}, ${row.action},
            ${row.scope_hash}, ${row.resource_ref_lookup},
            ${crypto.hmacChannelCommitment("channel-id", input.channelId)},
            ${crypto.hmacChannelCommitment("bootstrap-nonce", input.bootstrapNonce)},
            ${crypto.hmacChannelCommitment("parent-nonce", input.parentNonce)},
            ${crypto.hmacChannelCommitment("frame-nonce", input.frameNonce)},
            '__Host-secure-httponly-samesite-none-partitioned.v1',
            'unauthenticated', ${now}::timestamptz,
            ${sessionExpiresAt}::timestamptz, ${row.purge_after}::timestamptz
          )`;
        await tx`
          UPDATE embed_context_redemptions SET state = 'redeemed',
            completed_at = ${now}::timestamptz, embed_session_id = ${sessionId}
          WHERE embed_redemption_id = ${redemptionId}`;
        await tx`
          UPDATE embed_contexts SET state = 'redeemed',
            redeemed_at = ${now}::timestamptz
          WHERE embed_context_id = ${row.embed_context_id}`;
        return Object.freeze({
          status: "redeemed",
          state: "authentication_required",
          expiresAt: sessionExpiresAt,
          sessionToken,
          resourceRef,
        });
      });
    },

    async readSession(sessionTokenValue: unknown): Promise<EmbedSessionReadResult> {
      if (
        typeof sessionTokenValue !== "string" ||
        !HANDLE_PATTERN.test(sessionTokenValue)
      ) {
        return sessionInvalid();
      }
      const now = nowIso();
      const rows = await sql`
        SELECT state, expires_at FROM embed_sessions
        WHERE embed_session_token_hash = ${crypto.hmacSessionToken(
          sessionTokenValue,
        )}`;
      if (rows.length !== 1) return sessionInvalid();
      if (rows[0].state !== "unauthenticated" || iso(rows[0].expires_at) <= now) {
        return sessionInvalid();
      }
      return Object.freeze({
        status: "live",
        state: "authentication_required",
        expiresAt: iso(rows[0].expires_at),
      });
    },

    async revokeSession(sessionTokenValue: unknown): Promise<void> {
      if (
        typeof sessionTokenValue !== "string" ||
        !HANDLE_PATTERN.test(sessionTokenValue)
      ) {
        return;
      }
      const now = nowIso();
      await sql`
        UPDATE embed_sessions SET state = 'revoked',
          revoked_at = ${now}::timestamptz, revoke_reason = 'explicit-teardown'
        WHERE embed_session_token_hash = ${crypto.hmacSessionToken(
          sessionTokenValue,
        )} AND state IN ('unauthenticated', 'authenticated')`;
    },

    async revokeParentOrigin(
      tenantPublicIdValue: unknown,
      canonicalParentOriginValue: unknown,
    ): Promise<void> {
      const tenantPublicId = String(tenantPublicIdValue);
      const origin = String(canonicalParentOriginValue);
      if (!TENANT_PUBLIC_ID_PATTERN.test(tenantPublicId)) {
        throw new TypeError("Tenant public ID is malformed.");
      }
      assertCanonicalHttpsOrigin(origin);
      const now = nowIso();
      await sql.begin(async (tx) => {
        const origins = await tx`
          UPDATE tenant_parent_origins o SET state = 'revoked',
            revoked_at = ${now}::timestamptz, updated_at = ${now}::timestamptz
          FROM tenants t
          WHERE t.tenant_id = o.tenant_id
            AND t.tenant_public_id = ${tenantPublicId}
            AND o.canonical_https_origin = ${origin}
            AND o.state <> 'revoked'
          RETURNING o.tenant_origin_id`;
        for (const originRow of origins) {
          await tx`
            UPDATE embed_contexts SET state = 'revoked',
              revoked_at = ${now}::timestamptz,
              terminal_reason_code = 'parent-origin-revoked'
            WHERE tenant_origin_id = ${originRow.tenant_origin_id}
              AND state IN ('issued', 'claimed')`;
          await tx`
            UPDATE embed_sessions SET state = 'revoked',
              revoked_at = ${now}::timestamptz,
              revoke_reason = 'parent-origin-revoked'
            WHERE tenant_origin_id = ${originRow.tenant_origin_id}
              AND state IN ('unauthenticated', 'authenticated')`;
        }
      });
    },
  });
}

function parseIssueInput(value: unknown): IssueInput {
  const record = expectRecord(value, [
    "tenantPublicId",
    "parentOrigin",
    "frameAudience",
    "hostClientId",
    "purpose",
    "action",
    "resource",
  ]);
  const resource = expectRecord(record.resource, ["kind", "resourceRef"]);
  if (resource.kind !== "opaque-host-resource.v1") {
    throw new TypeError("Embed resource kind is unsupported.");
  }
  const tenantPublicId = String(record.tenantPublicId);
  const parentOrigin = String(record.parentOrigin);
  const frameAudience = String(record.frameAudience);
  const hostClientId = String(record.hostClientId);
  const resourceRef = String(resource.resourceRef);
  if (
    !TENANT_PUBLIC_ID_PATTERN.test(tenantPublicId) ||
    !CLIENT_ID_PATTERN.test(hostClientId) ||
    !RESOURCE_REF_PATTERN.test(resourceRef) ||
    !PURPOSES.includes(record.purpose as (typeof PURPOSES)[number]) ||
    !ACTIONS.includes(record.action as (typeof ACTIONS)[number])
  ) {
    throw new TypeError("Embed context issuance input is malformed.");
  }
  assertCanonicalHttpsOrigin(parentOrigin);
  assertCanonicalFrameAudience(frameAudience);
  return Object.freeze({
    tenantPublicId,
    parentOrigin,
    frameAudience,
    hostClientId,
    purpose: record.purpose as (typeof PURPOSES)[number],
    action: record.action as (typeof ACTIONS)[number],
    resourceRef,
  });
}

function parseRedeemInput(value: unknown): RedeemInput {
  const record = expectRecord(value, [
    "contextHandle",
    "tenantPublicId",
    "parentOrigin",
    "frameAudience",
    "channel",
  ]);
  const channel = expectRecord(record.channel, [
    "protocol",
    "version",
    "channelId",
    "bootstrapNonce",
    "parentNonce",
    "frameNonce",
  ]);
  if (channel.protocol !== EMBED_PROTOCOL || channel.version !== 1) {
    throw new TypeError("Embed redemption channel is unsupported.");
  }
  const contextHandle = String(record.contextHandle);
  const tenantPublicId = String(record.tenantPublicId);
  const parentOrigin = String(record.parentOrigin);
  const frameAudience = String(record.frameAudience);
  const channelId = String(channel.channelId);
  const bootstrapNonce = String(channel.bootstrapNonce);
  const parentNonce = String(channel.parentNonce);
  const frameNonce = String(channel.frameNonce);
  if (
    !HANDLE_PATTERN.test(contextHandle) ||
    !TENANT_PUBLIC_ID_PATTERN.test(tenantPublicId) ||
    !NONCE_PATTERN.test(channelId) ||
    !NONCE_PATTERN.test(bootstrapNonce) ||
    !NONCE_PATTERN.test(parentNonce) ||
    !NONCE_PATTERN.test(frameNonce)
  ) {
    throw new TypeError("Embed redemption input is malformed.");
  }
  assertCanonicalHttpsOrigin(parentOrigin);
  assertCanonicalFrameAudience(frameAudience);
  return Object.freeze({
    contextHandle,
    tenantPublicId,
    parentOrigin,
    frameAudience,
    channelId,
    bootstrapNonce,
    parentNonce,
    frameNonce,
  });
}

function expectRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Embed input must be a plain record.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new TypeError("Embed input has an unexpected shape.");
  }
  return value as Record<string, unknown>;
}

function assertCanonicalHttpsOrigin(value: string): void {
  const url = new URL(value);
  if (
    url.origin !== value ||
    url.protocol !== "https:" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hostname !== url.hostname.toLowerCase() ||
    !/^[a-z0-9.-]+$/.test(url.hostname) ||
    !url.hostname.includes(".")
  ) {
    throw new TypeError("Origin is not a canonical HTTPS origin.");
  }
}

function assertCanonicalFrameAudience(value: string): void {
  const url = new URL(value);
  assertCanonicalHttpsOrigin(url.origin);
  if (url.search !== "" || url.hash !== "" || `${url.origin}${url.pathname}` !== value) {
    throw new TypeError("Frame audience is not a canonical HTTPS URL path.");
  }
}

function refusedIssue(): EmbedContextIssueResult {
  return Object.freeze({ status: "refused", reasonCode: "issuance_refused" });
}

function contextInvalid(): EmbedContextRedemptionResult {
  return Object.freeze({ status: "invalid", reasonCode: "context_invalid" });
}

function sessionInvalid(): EmbedSessionReadResult {
  return Object.freeze({ status: "invalid", reasonCode: "session_invalid" });
}

function sha256Utf8(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function canonicalJson(value: unknown): unknown {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function iso(value: unknown): string {
  return new Date(value as string | Date).toISOString();
}

function randomUuidV4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return formatUuid(bytes);
}

function uuidV7(nowIsoValue: string): string {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.parse(nowIsoValue));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((milliseconds >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return formatUuid(bytes);
}

function formatUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
