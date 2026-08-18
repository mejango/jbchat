import { Buffer } from "node:buffer";

const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CHAIN_ID_PATTERN = /^eip155:[1-9][0-9]*$/;

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
  });
}

function decodeSecret(value: string | undefined): Buffer | null {
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === 32 ? decoded : null;
}
