import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

/**
 * Keyed derivations for the embed context plane. Production supplies KMS-held
 * keys through this port; nothing in this module invents ambient authority,
 * and every derivation is purpose-separated so a handle HMAC can never be
 * replayed as a channel commitment or lookup key.
 */
export interface EmbedContextCryptoPort {
  readonly hmacContextHandle: (handle: string) => Buffer;
  readonly hmacResourceRefLookup: (resourceRef: string) => Buffer;
  readonly hmacChannelCommitment: (
    kind: "channel-id" | "bootstrap-nonce" | "parent-nonce" | "frame-nonce",
    value: string,
  ) => Buffer;
  readonly hmacSessionToken: (token: string) => Buffer;
  readonly sealResourceRef: (resourceRef: string) => {
    readonly ciphertext: Buffer;
    readonly kmsKeyVersion: string;
  };
  readonly openResourceRef: (
    ciphertext: Buffer,
    kmsKeyVersion: string,
  ) => string;
}

const HANDLE_DOMAIN = "jbm-embed-context-handle/v1";
const LOOKUP_DOMAIN = "jbm-embed-resource-ref-lookup/v1";
const CHANNEL_DOMAIN = "jbm-embed-channel-commitment/v1";
const SESSION_DOMAIN = "jbm-embed-session-token/v1";

/**
 * Deterministic keyed crypto for fictional-data labs. The secret is supplied
 * by the caller; there is no default key, so an unconfigured deployment
 * cannot silently mint or verify anything.
 */
export function createKeyedEmbedContextCrypto(
  secretValue: Buffer,
): EmbedContextCryptoPort {
  if (secretValue.byteLength < 32) {
    throw new TypeError("Embed context crypto requires a 256-bit secret.");
  }
  const secret = Buffer.from(secretValue);
  const keyed = (domain: string, value: string): Buffer =>
    createHmac("sha256", secret).update(domain).update("\u0000").update(value).digest();
  const sealKey = createHmac("sha256", secret)
    .update("jbm-embed-resource-ref-seal-key/v1")
    .digest();
  return Object.freeze({
    hmacContextHandle: (handle: string) => keyed(HANDLE_DOMAIN, handle),
    hmacResourceRefLookup: (resourceRef: string) =>
      keyed(LOOKUP_DOMAIN, resourceRef),
    hmacChannelCommitment: (
      kind: "channel-id" | "bootstrap-nonce" | "parent-nonce" | "frame-nonce",
      value: string,
    ) =>
      keyed(`${CHANNEL_DOMAIN}:${kind}`, value),
    hmacSessionToken: (token: string) => keyed(SESSION_DOMAIN, token),
    sealResourceRef: (resourceRef: string) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", sealKey, iv);
      const sealed = Buffer.concat([
        cipher.update(resourceRef, "utf8"),
        cipher.final(),
      ]);
      return {
        ciphertext: Buffer.concat([iv, cipher.getAuthTag(), sealed]),
        kmsKeyVersion: "keyed-lab-v1",
      };
    },
    openResourceRef: (ciphertext: Buffer, kmsKeyVersion: string) => {
      if (kmsKeyVersion !== "keyed-lab-v1") {
        throw new TypeError("Embed resource-ref key version is unknown.");
      }
      const iv = ciphertext.subarray(0, 12);
      const tag = ciphertext.subarray(12, 28);
      const sealed = ciphertext.subarray(28);
      const decipher = createDecipheriv("aes-256-gcm", sealKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(sealed), decipher.final()]).toString(
        "utf8",
      );
    },
  });
}
