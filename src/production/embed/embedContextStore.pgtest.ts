import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { createKeyedEmbedContextCrypto } from "./embedContextCrypto";
import {
  createEmbedContextStore,
  type EmbedContextStore,
} from "./embedContextStore";
import {
  FIXTURE_EMBED_FRAME_AUDIENCE,
  FIXTURE_EMBED_HOST_CLIENT_ID,
  FIXTURE_EMBED_PARENT_ORIGIN,
  FIXTURE_EMBED_TENANT_PUBLIC_ID,
  seedEmbedTenantFixture,
} from "./embedTenantFixture.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const BASE_NOW = "2026-08-14T17:00:00.000Z";

describeStorage("embed context plane", () => {
  let sql: Sql;
  let store: EmbedContextStore;
  let now = BASE_NOW;

  const issueInput = (resourceRef: string) => ({
    tenantPublicId: FIXTURE_EMBED_TENANT_PUBLIC_ID,
    parentOrigin: FIXTURE_EMBED_PARENT_ORIGIN,
    frameAudience: FIXTURE_EMBED_FRAME_AUDIENCE,
    hostClientId: FIXTURE_EMBED_HOST_CLIENT_ID,
    purpose: "open-secure-messaging",
    action: "open",
    resource: { kind: "opaque-host-resource.v1", resourceRef },
  });

  const channel = () => ({
    protocol: "org.juicebox.messaging.embed",
    version: 1,
    channelId: randomBytes(32).toString("base64url"),
    bootstrapNonce: randomBytes(32).toString("base64url"),
    parentNonce: randomBytes(32).toString("base64url"),
    frameNonce: randomBytes(32).toString("base64url"),
  });

  const redeemInput = (contextHandle: string, overrides = {}) => ({
    contextHandle,
    tenantPublicId: FIXTURE_EMBED_TENANT_PUBLIC_ID,
    parentOrigin: FIXTURE_EMBED_PARENT_ORIGIN,
    frameAudience: FIXTURE_EMBED_FRAME_AUDIENCE,
    channel: channel(),
    ...overrides,
  });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    store = createEmbedContextStore({
      sql,
      now: () => now,
      crypto: createKeyedEmbedContextCrypto(Buffer.alloc(32, 0x5a)),
    });
    await seedEmbedTenantFixture(sql, BASE_NOW);
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("issues a one-use handle and stores only keyed hashes", async () => {
    const resourceRef = randomBytes(32).toString("base64url");
    const issued = await store.issueContext(issueInput(resourceRef));
    expect(issued.status).toBe("issued");
    if (issued.status !== "issued") throw new Error("issuance refused");
    expect(issued.contextHandle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Date.parse(issued.expiresAt) - Date.parse(issued.issuedAt)).toBe(
      120_000,
    );
    const [row] = await sql`
      SELECT state, encode(context_handle_hash, 'hex') AS handle_hash,
             resource_ref_ciphertext
      FROM embed_contexts WHERE embed_context_id = ${issued.embedContextId}`;
    expect(row.state).toBe("issued");
    expect(String(row.handle_hash)).not.toContain(issued.contextHandle);
    expect(
      Buffer.from(row.resource_ref_ciphertext).toString("utf8"),
    ).not.toContain(resourceRef);
  });

  it("refuses issuance for an unknown tenant binding", async () => {
    const refused = await store.issueContext({
      ...issueInput(randomBytes(32).toString("base64url")),
      hostClientId: "unregistered-client",
    });
    expect(refused).toEqual({ status: "refused", reasonCode: "issuance_refused" });
  });

  it("redeems once, opens the sealed resource ref, and burns the handle", async () => {
    const resourceRef = randomBytes(32).toString("base64url");
    const issued = await store.issueContext(issueInput(resourceRef));
    if (issued.status !== "issued") throw new Error("issuance refused");
    const redeemed = await store.redeemContext(redeemInput(issued.contextHandle));
    expect(redeemed.status).toBe("redeemed");
    if (redeemed.status !== "redeemed") throw new Error("redemption failed");
    expect(redeemed.state).toBe("authentication_required");
    expect(redeemed.resourceRef).toBe(resourceRef);
    expect(Date.parse(redeemed.expiresAt) - Date.parse(now)).toBe(600_000);

    const replay = await store.redeemContext(redeemInput(issued.contextHandle));
    expect(replay).toEqual({ status: "invalid", reasonCode: "context_invalid" });

    const session = await store.readSession(redeemed.sessionToken);
    expect(session).toMatchObject({ status: "live", state: "authentication_required" });
    await store.revokeSession(redeemed.sessionToken);
    expect(await store.readSession(redeemed.sessionToken)).toEqual({
      status: "invalid",
      reasonCode: "session_invalid",
    });
  });

  it("terminally burns a claimed handle on any binding mismatch", async () => {
    const issued = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    if (issued.status !== "issued") throw new Error("issuance refused");
    const mismatched = await store.redeemContext(
      redeemInput(issued.contextHandle, {
        parentOrigin: "https://attacker.example",
      }),
    );
    expect(mismatched).toEqual({
      status: "invalid",
      reasonCode: "context_invalid",
    });
    const [row] = await sql`
      SELECT state, terminal_reason_code FROM embed_contexts
      WHERE embed_context_id = ${issued.embedContextId}`;
    expect(row.state).toBe("invalid");
    expect(row.terminal_reason_code).toBe("binding-or-expiry-mismatch");
    const retry = await store.redeemContext(redeemInput(issued.contextHandle));
    expect(retry).toEqual({ status: "invalid", reasonCode: "context_invalid" });
  });

  it("collapses expiry to the same context_invalid outcome", async () => {
    const issued = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    if (issued.status !== "issued") throw new Error("issuance refused");
    now = "2026-08-14T17:05:00.000Z";
    const expired = await store.redeemContext(redeemInput(issued.contextHandle));
    expect(expired).toEqual({ status: "invalid", reasonCode: "context_invalid" });
    now = BASE_NOW;
  });

  it("rejects channel commitment reuse across contexts relationally", async () => {
    const first = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    const second = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    if (first.status !== "issued" || second.status !== "issued") {
      throw new Error("issuance refused");
    }
    const sharedChannel = channel();
    const redeemedFirst = await store.redeemContext(
      redeemInput(first.contextHandle, { channel: sharedChannel }),
    );
    expect(redeemedFirst.status).toBe("redeemed");
    await expect(
      store.redeemContext(
        redeemInput(second.contextHandle, { channel: sharedChannel }),
      ),
    ).rejects.toThrow(/duplicate key/);
  });

  it("revoking a parent origin kills issued contexts and live sessions", async () => {
    const issued = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    if (issued.status !== "issued") throw new Error("issuance refused");
    const live = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    if (live.status !== "issued") throw new Error("issuance refused");
    const redeemed = await store.redeemContext(redeemInput(live.contextHandle));
    if (redeemed.status !== "redeemed") throw new Error("redemption failed");

    await store.revokeParentOrigin(
      FIXTURE_EMBED_TENANT_PUBLIC_ID,
      FIXTURE_EMBED_PARENT_ORIGIN,
    );
    const afterRevocation = await store.redeemContext(
      redeemInput(issued.contextHandle),
    );
    expect(afterRevocation).toEqual({
      status: "invalid",
      reasonCode: "context_invalid",
    });
    expect(await store.readSession(redeemed.sessionToken)).toEqual({
      status: "invalid",
      reasonCode: "session_invalid",
    });
    const refused = await store.issueContext(
      issueInput(randomBytes(32).toString("base64url")),
    );
    expect(refused).toEqual({ status: "refused", reasonCode: "issuance_refused" });
  });
});
