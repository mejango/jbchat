import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { createEmbedBffHandlers, type EmbedBffHandlers } from "./embedBff";
import { createKeyedEmbedContextCrypto } from "./embedContextCrypto";
import {
  createEmbedContextStore,
  type EmbedContextStore,
} from "./embedContextStore";
import {
  FIXTURE_EMBED_FRAME_AUDIENCE,
  FIXTURE_EMBED_HOST_CLIENT_ID,
  FIXTURE_EMBED_PARENT_ORIGIN,
  seedEmbedTenantFixture,
} from "./embedTenantFixture.testing";

const BFF_TENANT_PUBLIC_ID = "fictional-embed-bff-tenant";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const BASE_NOW = "2026-08-14T17:30:00.000Z";
const SECRET = Buffer.alloc(32, 0x5a);
const BFF_ORIGIN = "https://messages.fictional.example";

describeStorage("embed BFF handlers", () => {
  let sql: Sql;
  let store: EmbedContextStore;
  let handlers: EmbedBffHandlers;
  const now = BASE_NOW;

  const issueHandle = async (): Promise<string> => {
    const issued = await store.issueContext({
      tenantPublicId: BFF_TENANT_PUBLIC_ID,
      parentOrigin: FIXTURE_EMBED_PARENT_ORIGIN,
      frameAudience: FIXTURE_EMBED_FRAME_AUDIENCE,
      hostClientId: FIXTURE_EMBED_HOST_CLIENT_ID,
      purpose: "open-secure-messaging",
      action: "open",
      resource: {
        kind: "opaque-host-resource.v1",
        resourceRef: randomBytes(32).toString("base64url"),
      },
    });
    if (issued.status !== "issued") throw new Error("issuance refused");
    return issued.contextHandle;
  };

  const redemptionRequest = (
    contextHandle: string,
    headers: Record<string, string> = {},
    url = `${BFF_ORIGIN}/v1/embed/context-redemptions`,
  ): Request =>
    new Request(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "sec-fetch-site": "same-origin",
        ...headers,
      },
      body: JSON.stringify({
        contextHandle,
        tenantPublicId: BFF_TENANT_PUBLIC_ID,
        parentOrigin: FIXTURE_EMBED_PARENT_ORIGIN,
        frameAudience: FIXTURE_EMBED_FRAME_AUDIENCE,
        channel: {
          protocol: "org.juicebox.messaging.embed",
          version: 1,
          channelId: randomBytes(32).toString("base64url"),
          bootstrapNonce: randomBytes(32).toString("base64url"),
          parentNonce: randomBytes(32).toString("base64url"),
          frameNonce: randomBytes(32).toString("base64url"),
        },
      }),
    });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    await seedEmbedTenantFixture(sql, BASE_NOW, BFF_TENANT_PUBLIC_ID, "b");
    store = createEmbedContextStore({
      sql,
      now: () => now,
      crypto: createKeyedEmbedContextCrypto(SECRET),
    });
    handlers = createEmbedBffHandlers({
      loadConfig: () => ({
        status: "configured",
        databaseUrl: DATABASE_URL!,
        contextSecret: SECRET,
      }),
      now: () => now,
      connect: () => sql,
    });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("redeems over HTTP, sets the partitioned host cookie, and serves the session", async () => {
    const handle = await issueHandle();
    const response = await handlers.redeemContext(redemptionRequest(handle));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const cookie = response.headers.get("set-cookie") ?? "";
    expect(cookie).toContain("__Host-jbm_embed=");
    for (const attribute of ["Secure", "HttpOnly", "SameSite=None", "Partitioned", "Path=/"]) {
      expect(cookie).toContain(attribute);
    }
    expect(await response.json()).toMatchObject({
      state: "authentication_required",
    });

    const token = /__Host-jbm_embed=([A-Za-z0-9_-]{43})/.exec(cookie)![1];
    const session = await handlers.readSession(
      new Request(`${BFF_ORIGIN}/v1/embed/session`, {
        headers: {
          "sec-fetch-site": "same-origin",
          cookie: `__Host-jbm_embed=${token}`,
        },
      }),
    );
    expect(session.status).toBe(200);
    expect(await session.json()).toMatchObject({ state: "authentication_required" });

    const teardown = await handlers.deleteSession(
      new Request(`${BFF_ORIGIN}/v1/embed/session`, {
        method: "DELETE",
        headers: {
          "sec-fetch-site": "same-origin",
          cookie: `__Host-jbm_embed=${token}`,
        },
      }),
    );
    expect(teardown.status).toBe(204);
    expect(teardown.headers.get("set-cookie")).toContain("Max-Age=0");
    const afterTeardown = await handlers.readSession(
      new Request(`${BFF_ORIGIN}/v1/embed/session`, {
        headers: {
          "sec-fetch-site": "same-origin",
          cookie: `__Host-jbm_embed=${token}`,
        },
      }),
    );
    expect(afterTeardown.status).toBe(404);
  });

  it("collapses replay to the generic 404 problem", async () => {
    const handle = await issueHandle();
    expect((await handlers.redeemContext(redemptionRequest(handle))).status).toBe(200);
    const replay = await handlers.redeemContext(redemptionRequest(handle));
    expect(replay.status).toBe(404);
    expect(await replay.json()).toMatchObject({ title: "context_invalid" });
  });

  it("rejects cross-site, queried, and unconfigured calls identically", async () => {
    const handle = await issueHandle();
    const crossSite = await handlers.redeemContext(
      redemptionRequest(handle, { "sec-fetch-site": "cross-site" }),
    );
    expect(crossSite.status).toBe(404);
    const queried = await handlers.redeemContext(
      redemptionRequest(
        handle,
        {},
        `${BFF_ORIGIN}/v1/embed/context-redemptions?probe=1`,
      ),
    );
    expect(queried.status).toBe(404);
    const unconfigured = createEmbedBffHandlers({
      loadConfig: () => ({ status: "unconfigured" }),
      now: () => now,
    });
    const refused = await unconfigured.redeemContext(redemptionRequest(handle));
    expect(refused.status).toBe(404);
    const stillIssued = await handlers.redeemContext(redemptionRequest(handle));
    expect(stillIssued.status).toBe(200);
  });
});
