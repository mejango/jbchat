import postgres, { type Sql } from "postgres";
import { createKeyedEmbedContextCrypto } from "./embedContextCrypto";
import {
  createEmbedContextStore,
  type EmbedContextStore,
} from "./embedContextStore";
import { loadEmbedRuntimeConfig, type EmbedRuntimeConfig } from "./embedRuntimeConfig";

const EMBED_COOKIE_NAME = "__Host-jbm_embed";
const MAX_BODY_BYTES = 8 * 1024;

export interface EmbedBffContext {
  readonly loadConfig: () => EmbedRuntimeConfig;
  readonly now: () => string;
  readonly connect?: (databaseUrl: string) => Sql;
}

export interface EmbedBffHandlers {
  readonly redeemContext: (request: Request) => Promise<Response>;
  readonly readSession: (request: Request) => Promise<Response>;
  readonly deleteSession: (request: Request) => Promise<Response>;
}

/**
 * Same-origin BFF handlers for the embed frame (service-api.md section 3.7).
 * Requests must arrive same-origin with Fetch Metadata and an empty query;
 * every context failure collapses to one 404 context_invalid problem; the
 * embed session travels only as the partitioned __Host cookie; and an
 * unconfigured deployment fails closed without revealing why.
 */
export function createEmbedBffHandlers(
  contextValue: Partial<EmbedBffContext> = {},
): EmbedBffHandlers {
  const loadConfig = contextValue.loadConfig ?? (() => loadEmbedRuntimeConfig());
  const now = contextValue.now ?? (() => new Date().toISOString());
  const connect =
    contextValue.connect ??
    ((databaseUrl: string) =>
      postgres(databaseUrl, { max: 4, onnotice: () => {} }));

  let cached: { readonly key: string; readonly store: EmbedContextStore } | null =
    null;
  const storeFor = (config: EmbedRuntimeConfig): EmbedContextStore | null => {
    if (config.status !== "configured") return null;
    const key = `${config.databaseUrl} ${config.contextSecret.toString("base64url")}`;
    if (cached && cached.key === key) return cached.store;
    cached = {
      key,
      store: createEmbedContextStore({
        sql: connect(config.databaseUrl),
        now,
        crypto: createKeyedEmbedContextCrypto(config.contextSecret),
      }),
    };
    return cached.store;
  };

  const guarded = async (
    request: Request,
    method: string,
    handler: (store: EmbedContextStore) => Promise<Response>,
  ): Promise<Response> => {
    if (request.method !== method) return contextInvalid();
    const url = new URL(request.url);
    if (url.search !== "") return contextInvalid();
    const fetchSite = request.headers.get("sec-fetch-site");
    if (fetchSite !== "same-origin") return contextInvalid();
    const store = storeFor(loadConfig());
    if (!store) return contextInvalid();
    try {
      return await handler(store);
    } catch {
      return contextInvalid();
    }
  };

  return Object.freeze({
    redeemContext: (request: Request) =>
      guarded(request, "POST", async (store) => {
        if (
          (request.headers.get("content-type") ?? "")
            .toLowerCase()
            .split(";")[0]
            .trim() !== "application/json"
        ) {
          return contextInvalid();
        }
        const raw = await request.text();
        if (raw.length > MAX_BODY_BYTES) return contextInvalid();
        let body: unknown;
        try {
          body = JSON.parse(raw);
        } catch {
          return contextInvalid();
        }
        const result = await store.redeemContext(body);
        if (result.status !== "redeemed") return contextInvalid();
        const maxAgeSeconds = Math.max(
          1,
          Math.floor((Date.parse(result.expiresAt) - Date.parse(now())) / 1000),
        );
        return json(
          { state: result.state, expiresAt: result.expiresAt },
          {
            "set-cookie": `${EMBED_COOKIE_NAME}=${result.sessionToken}; Max-Age=${maxAgeSeconds}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned`,
          },
        );
      }),
    readSession: (request: Request) =>
      guarded(request, "GET", async (store) => {
        const token = readEmbedCookie(request);
        if (!token) return contextInvalid();
        const session = await store.readSession(token);
        if (session.status !== "live") return contextInvalid();
        return json({ state: session.state, expiresAt: session.expiresAt });
      }),
    deleteSession: (request: Request) =>
      guarded(request, "DELETE", async (store) => {
        const token = readEmbedCookie(request);
        if (token) await store.revokeSession(token);
        return new Response(null, {
          status: 204,
          headers: {
            "cache-control": "private, no-store",
            "set-cookie": `${EMBED_COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=None; Partitioned`,
          },
        });
      }),
  });
}

function readEmbedCookie(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  const matches = header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${EMBED_COOKIE_NAME}=`))
    .map((part) => part.slice(EMBED_COOKIE_NAME.length + 1));
  if (matches.length !== 1) return null;
  return /^[A-Za-z0-9_-]{43}$/.test(matches[0]) ? matches[0] : null;
}

function contextInvalid(): Response {
  return json(
    { type: "about:blank", title: "context_invalid", status: 404 },
    {},
    404,
  );
}

function json(
  body: unknown,
  headers: Record<string, string> = {},
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "private, no-store",
      ...headers,
    },
  });
}
