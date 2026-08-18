import { Buffer } from "node:buffer";

const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CHAIN_ID_PATTERN = /^eip155:[1-9][0-9]*$/;
const PROVIDER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface RpcEndpointConfig {
  readonly providerId: string;
  readonly url: string;
}

export type MessagingRuntimeConfig =
  | {
      readonly status: "configured";
      readonly databaseUrl: string;
      readonly identitySecret: Buffer;
      readonly credentialSignerKeyId: string;
      readonly credentialSignerSeed: Buffer;
      readonly allowedChainIds: readonly string[];
      readonly logSigner: {
        readonly keyId: string;
        readonly seed: Buffer;
      } | null;
      readonly cursor: {
        readonly keyId: string;
        readonly key: Buffer;
      } | null;
      readonly rpcEndpoints: Readonly<
        Record<string, readonly RpcEndpointConfig[]>
      > | null;
      readonly provisioningSeed: Buffer | null;
      readonly manifest: {
        readonly source:
          | { readonly kind: "path"; readonly path: string }
          | { readonly kind: "inline"; readonly json: string };
        readonly signerPublicKey: Buffer;
      } | null;
    }
  | { readonly status: "unconfigured" };

/**
 * Fail-closed environment gate for the messaging HTTP surface. A missing
 * or malformed core variable leaves every route a 404, exactly like the
 * witness deployment gate; the delivery-log signer and cursor lanes are
 * optional and gate only their own routes.
 */
export function loadMessagingRuntimeConfig(
  environment: Record<string, string | undefined> = process.env,
): MessagingRuntimeConfig {
  const databaseUrl = environment.JBM_STORAGE_DATABASE_URL;
  const identitySecret = decodeSecret(environment.JBM_IDENTITY_SECRET);
  const credentialSignerKeyId =
    environment.JBM_DEVICE_CREDENTIAL_SIGNER_KEY_ID;
  const credentialSignerSeed = decodeSecret(
    environment.JBM_DEVICE_CREDENTIAL_SIGNING_SEED,
  );
  const allowedChainIds = (environment.JBM_ALLOWED_CHAIN_IDS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  if (
    !databaseUrl ||
    !identitySecret ||
    !credentialSignerKeyId ||
    !KEY_ID_PATTERN.test(credentialSignerKeyId) ||
    !credentialSignerSeed ||
    allowedChainIds.length === 0 ||
    !allowedChainIds.every((chainId) => CHAIN_ID_PATTERN.test(chainId))
  ) {
    return Object.freeze({ status: "unconfigured" });
  }

  const logSignerKeyId = environment.JBM_DELIVERY_LOG_SIGNING_KEY_ID;
  const logSignerSeed = decodeSecret(
    environment.JBM_DELIVERY_LOG_SIGNING_SEED,
  );
  const logSigner =
    logSignerKeyId && KEY_ID_PATTERN.test(logSignerKeyId) && logSignerSeed
      ? Object.freeze({ keyId: logSignerKeyId, seed: logSignerSeed })
      : null;

  const cursorKeyId = environment.JBM_CURSOR_KEY_ID;
  const cursorKey = decodeSecret(environment.JBM_CURSOR_KEY);
  const cursor =
    cursorKeyId && KEY_ID_PATTERN.test(cursorKeyId) && cursorKey
      ? Object.freeze({ keyId: cursorKeyId, key: cursorKey })
      : null;

  return Object.freeze({
    status: "configured",
    databaseUrl,
    identitySecret,
    credentialSignerKeyId,
    credentialSignerSeed,
    allowedChainIds: Object.freeze(allowedChainIds),
    logSigner,
    cursor,
    rpcEndpoints: parseRpcEndpoints(environment.JBM_RPC_ENDPOINTS),
    provisioningSeed: decodeSecret(environment.JBM_PROVISIONING_SEED),
    manifest: parseManifestConfig(
      environment.JBM_DEPLOYMENT_MANIFEST_PATH,
      environment.JBM_DEPLOYMENT_MANIFEST,
      environment.JBM_MANIFEST_SIGNER_PUBLIC_KEY,
    ),
  });
}

/**
 * ADR 0005 quorum endpoints: JSON of chainId -> [{providerId, url}, ...].
 * A malformed document, a non-allowlisted chain, fewer than two providers,
 * duplicate provider IDs, or a non-HTTPS URL disables the WHOLE lane -
 * chain reads never run on a partially valid configuration.
 */
function parseRpcEndpoints(
  value: string | undefined,
): Readonly<Record<string, readonly RpcEndpointConfig[]>> | null {
  if (!value) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const endpoints: Record<string, readonly RpcEndpointConfig[]> = {};
  for (const [chainId, list] of Object.entries(parsed)) {
    if (!CHAIN_ID_PATTERN.test(chainId) || !Array.isArray(list)) return null;
    if (list.length < 2) return null;
    const providers: RpcEndpointConfig[] = [];
    for (const entry of list) {
      const record = entry as Record<string, unknown>;
      const providerId = record.providerId;
      const url = record.url;
      if (
        typeof providerId !== "string" ||
        !PROVIDER_ID_PATTERN.test(providerId) ||
        typeof url !== "string" ||
        !url.startsWith("https://")
      ) {
        return null;
      }
      providers.push(Object.freeze({ providerId, url }));
    }
    if (new Set(providers.map((p) => p.providerId)).size !== providers.length) {
      return null;
    }
    endpoints[chainId] = Object.freeze(providers);
  }
  return Object.freeze(endpoints);
}

function parseManifestConfig(
  path: string | undefined,
  inlineJson: string | undefined,
  signerPublicKey: string | undefined,
):
  | {
      readonly source:
        | { readonly kind: "path"; readonly path: string }
        | { readonly kind: "inline"; readonly json: string };
      readonly signerPublicKey: Buffer;
    }
  | null {
  const decoded = decodeSecret(signerPublicKey);
  if (!decoded) return null;
  if (path) {
    return Object.freeze({
      source: Object.freeze({ kind: "path" as const, path }),
      signerPublicKey: decoded,
    });
  }
  if (inlineJson) {
    return Object.freeze({
      source: Object.freeze({ kind: "inline" as const, json: inlineJson }),
      signerPublicKey: decoded,
    });
  }
  return null;
}

function decodeSecret(value: string | undefined): Buffer | null {
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === 32 ? decoded : null;
}
