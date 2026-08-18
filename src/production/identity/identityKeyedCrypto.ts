import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

/**
 * Keyed derivations for the enrollment and session plane. Every hash is
 * purpose-separated; there is no default key, so an unconfigured deployment
 * can neither mint nor verify anything.
 */
export interface IdentityKeyedCryptoPort {
  readonly hmacWalletRefLookup: (caip10: string) => Buffer;
  readonly hmacResultHandle: (handle: string) => Buffer;
  readonly hmacChallengeNonce: (nonce: string) => Buffer;
  readonly hmacAccessToken: (token: string) => Buffer;
  readonly hmacRefreshToken: (token: string) => Buffer;
  readonly hmacEligibilityClaimHandle: (handle: string) => Buffer;
  readonly hmacEligibilitySubject: (caip10: string) => Buffer;
  readonly sealPayload: (plaintext: string) => {
    readonly ciphertext: Buffer;
    readonly kmsKeyVersion: string;
  };
  readonly openPayload: (ciphertext: Buffer, kmsKeyVersion: string) => string;
}

const WALLET_REF_DOMAIN = "jbm-identity-wallet-ref-lookup/v1";
const RESULT_HANDLE_DOMAIN = "jbm-identity-enrollment-result-handle/v1";
const CHALLENGE_NONCE_DOMAIN = "jbm-identity-challenge-nonce/v1";
const ACCESS_TOKEN_DOMAIN = "jbm-identity-access-token/v1";
const REFRESH_TOKEN_DOMAIN = "jbm-identity-refresh-token/v1";
const ELIGIBILITY_CLAIM_HANDLE_DOMAIN = "jbm-eligibility-claim-handle/v1";
const ELIGIBILITY_SUBJECT_DOMAIN = "jbm-eligibility-subject/v1";
const SEAL_KEY_DOMAIN = "jbm-identity-payload-seal-key/v1";

export function createKeyedIdentityCrypto(
  secretValue: Buffer,
): IdentityKeyedCryptoPort {
  if (secretValue.byteLength < 32) {
    throw new TypeError("Identity crypto requires a 256-bit secret.");
  }
  const secret = Buffer.from(secretValue);
  const keyed = (domain: string, value: string): Buffer =>
    createHmac("sha256", secret)
      .update(domain)
      .update(":")
      .update(value)
      .digest();
  const sealKey = createHmac("sha256", secret).update(SEAL_KEY_DOMAIN).digest();
  return Object.freeze({
    hmacWalletRefLookup: (caip10: string) => keyed(WALLET_REF_DOMAIN, caip10),
    hmacResultHandle: (handle: string) => keyed(RESULT_HANDLE_DOMAIN, handle),
    hmacChallengeNonce: (nonce: string) => keyed(CHALLENGE_NONCE_DOMAIN, nonce),
    hmacAccessToken: (token: string) => keyed(ACCESS_TOKEN_DOMAIN, token),
    hmacRefreshToken: (token: string) => keyed(REFRESH_TOKEN_DOMAIN, token),
    hmacEligibilityClaimHandle: (handle: string) =>
      keyed(ELIGIBILITY_CLAIM_HANDLE_DOMAIN, handle),
    hmacEligibilitySubject: (caip10: string) =>
      keyed(ELIGIBILITY_SUBJECT_DOMAIN, caip10),
    sealPayload: (plaintext: string) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", sealKey, iv);
      const sealed = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
      ]);
      return {
        ciphertext: Buffer.concat([iv, cipher.getAuthTag(), sealed]),
        kmsKeyVersion: "keyed-lab-v1",
      };
    },
    openPayload: (ciphertext: Buffer, kmsKeyVersion: string) => {
      if (kmsKeyVersion !== "keyed-lab-v1") {
        throw new TypeError("Identity payload key version is unknown.");
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
