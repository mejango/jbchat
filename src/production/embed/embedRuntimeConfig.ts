import { Buffer } from "node:buffer";

/**
 * Runtime configuration for the embed context plane's HTTP layer. Both
 * values are deployment secrets: without them every context/session
 * endpoint fails closed and the tenant route renders the generic
 * unavailable document. There are no defaults and no lab fallback here.
 */
export type EmbedRuntimeConfig =
  | {
      readonly status: "configured";
      readonly databaseUrl: string;
      readonly contextSecret: Buffer;
    }
  | { readonly status: "unconfigured" };

export function loadEmbedRuntimeConfig(
  environment: NodeJS.ProcessEnv = process.env,
): EmbedRuntimeConfig {
  const databaseUrl = environment.JUICEBOX_MESSAGING_EMBED_DATABASE_URL;
  const secretValue = environment.JUICEBOX_MESSAGING_EMBED_CONTEXT_SECRET;
  if (!databaseUrl || !secretValue) {
    return Object.freeze({ status: "unconfigured" });
  }
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) {
    throw new TypeError(
      "JUICEBOX_MESSAGING_EMBED_DATABASE_URL must be a postgres:// URL.",
    );
  }
  if (!/^[A-Za-z0-9_-]{43,}$/.test(secretValue)) {
    throw new TypeError(
      "JUICEBOX_MESSAGING_EMBED_CONTEXT_SECRET must be at least 256 bits of base64url.",
    );
  }
  const contextSecret = Buffer.from(secretValue, "base64url");
  if (contextSecret.byteLength < 32) {
    throw new TypeError(
      "JUICEBOX_MESSAGING_EMBED_CONTEXT_SECRET must decode to at least 32 bytes.",
    );
  }
  return Object.freeze({ status: "configured", databaseUrl, contextSecret });
}
