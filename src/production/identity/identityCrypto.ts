import { Buffer } from "node:buffer";
import { createHash, createPublicKey, verify as verifyNodeSignature } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const SIWE_PROOF_PROFILE = "siwe-erc4361-v1" as const;
export const ENROLLMENT_PROTOCOL_PROFILE = "device-enrollment.v1" as const;
export const ENROLLMENT_STATEMENT =
  "Authorize this wallet to enroll one Juicebox Messaging device." as const;
const POSSESSION_DIGEST_DOMAIN = "jb-msg-device-possession/v1";
const MLS_FINGERPRINT_DOMAIN = "jb-msg-mls-credential-fingerprint/v1";
const KEY_PACKAGE_REF_DOMAIN = "jb-msg-key-package-ref/v1";
const SECP256K1_HALF_ORDER =
  0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface CanonicalWalletRef {
  readonly caip10: string;
  readonly chainId: string;
  readonly address: string;
}

/** Parses an eip155 CAIP-10 wallet reference into its canonical lowercase form. */
export function parseWalletRef(
  value: unknown,
  allowedChainIds: readonly string[],
): CanonicalWalletRef {
  if (typeof value !== "string") {
    throw new TypeError("The wallet reference must be a CAIP-10 string.");
  }
  const match = /^eip155:(\d{1,10}):(0x[0-9a-fA-F]{40})$/.exec(value);
  if (!match) {
    throw new TypeError("The wallet reference must be an exact eip155 CAIP-10 account.");
  }
  const chainId = `eip155:${match[1]}`;
  if (!allowedChainIds.includes(chainId)) {
    throw new TypeError("The wallet chain is not allowlisted.");
  }
  const address = match[2].toLowerCase();
  return Object.freeze({ caip10: `${chainId}:${address}`, chainId, address });
}

export interface SiweMessageFields {
  readonly domain: string;
  readonly address: string;
  readonly uri: string;
  readonly chainReference: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly notBefore: string;
  readonly expirationTime: string;
  readonly requestId: string;
  readonly resources: SiweEnrollmentResources;
}

export interface SiweEnrollmentResources {
  readonly enrollmentId: string;
  readonly accountId: string;
  readonly installationId: string;
  readonly deviceCredentialId: string;
  readonly audience: string;
  readonly clientId: string;
  readonly scopeDigest: string;
  readonly installationAuthJkt: string;
  readonly mlsCredentialFingerprint: string;
  readonly keyPackageRef: string;
  readonly keyPackageSha256: string;
  readonly protocolProfile: typeof ENROLLMENT_PROTOCOL_PROFILE;
  readonly possessionChallengeId: string;
}

const RESOURCE_ORDER: readonly (readonly [string, keyof SiweEnrollmentResources])[] = [
  ["enrollment-id", "enrollmentId"],
  ["account-id", "accountId"],
  ["installation-id", "installationId"],
  ["device-credential-id", "deviceCredentialId"],
  ["audience", "audience"],
  ["client-id", "clientId"],
  ["scope-digest", "scopeDigest"],
  ["installation-auth-jkt", "installationAuthJkt"],
  ["mls-credential-fingerprint", "mlsCredentialFingerprint"],
  ["key-package-ref", "keyPackageRef"],
  ["key-package-sha256", "keyPackageSha256"],
  ["protocol-profile", "protocolProfile"],
  ["possession-challenge-id", "possessionChallengeId"],
] as const;

/**
 * Builds the exact EIP-4361 message for one enrollment wallet challenge: the
 * fixed statement, the thirteen ordered urn:juicebox:messaging resources,
 * and nothing an integrator can reorder or extend.
 */
export function buildSiweEnrollmentMessage(fields: SiweMessageFields): string {
  const resourceLines = RESOURCE_ORDER.map(
    ([name, key]) => `- urn:juicebox:messaging:${name}:v1:${fields.resources[key]}`,
  );
  return [
    `${fields.domain} wants you to sign in with your Ethereum account:`,
    toChecksumAddress(fields.address),
    "",
    ENROLLMENT_STATEMENT,
    "",
    `URI: ${fields.uri}`,
    "Version: 1",
    `Chain ID: ${fields.chainReference}`,
    `Nonce: ${fields.nonce}`,
    `Issued At: ${fields.issuedAt}`,
    `Expiration Time: ${fields.expirationTime}`,
    `Not Before: ${fields.notBefore}`,
    `Request ID: ${fields.requestId}`,
    "Resources:",
    ...resourceLines,
  ].join("\n");
}

/** EIP-55 checksum encoding for display inside the SIWE message. */
export function toChecksumAddress(address: string): string {
  const bare = address.toLowerCase().replace(/^0x/, "");
  const digest = Buffer.from(keccak_256(Buffer.from(bare, "ascii"))).toString("hex");
  let output = "0x";
  for (let index = 0; index < bare.length; index += 1) {
    output +=
      parseInt(digest[index], 16) >= 8 ? bare[index].toUpperCase() : bare[index];
  }
  return output;
}

/**
 * Verifies an EIP-191 personal-sign signature from an externally owned
 * account: exact prefixed keccak digest, 65-byte recovered form, low-s only,
 * and recovered-address equality. Contract wallets never pass through here.
 */
export function verifyEip191EoaSignature(
  message: string,
  signatureValue: unknown,
  expectedAddress: string,
): boolean {
  if (typeof signatureValue !== "string") return false;
  const match = /^0x([0-9a-fA-F]{130})$/.exec(signatureValue);
  if (!match) return false;
  const bytes = Buffer.from(match[1], "hex");
  const recoveryByte = bytes[64];
  const recovery =
    recoveryByte === 27 || recoveryByte === 28 ? recoveryByte - 27 : recoveryByte;
  if (recovery !== 0 && recovery !== 1) return false;
  const s = BigInt(`0x${bytes.subarray(32, 64).toString("hex")}`);
  if (s === 0n || s > SECP256K1_HALF_ORDER) return false;
  const digest = eip191Digest(message);
  try {
    const recovered = Buffer.concat([Buffer.of(recovery), bytes.subarray(0, 64)]);
    const publicKey = secp256k1.recoverPublicKey(recovered, digest, {
      prehash: false,
    });
    const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
    const address = `0x${Buffer.from(keccak_256(uncompressed.subarray(1)))
      .subarray(-20)
      .toString("hex")}`;
    return address === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
}

export function eip191Digest(message: string): Uint8Array {
  const body = Buffer.from(message, "utf8");
  const prefix = Buffer.from(
    `\u0019Ethereum Signed Message:\n${body.byteLength}`,
    "utf8",
  );
  return keccak_256(Buffer.concat([prefix, body]));
}

export interface P256PublicJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
  readonly use: "sig";
  readonly alg: "ES256";
}

export function parseP256PublicJwk(value: unknown): P256PublicJwk {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("The installation auth key must be a strict P-256 JWK.");
  }
  const keys = Reflect.ownKeys(value);
  const record = value as Record<string, unknown>;
  if (
    keys.length !== 6 ||
    record.kty !== "EC" ||
    record.crv !== "P-256" ||
    record.use !== "sig" ||
    record.alg !== "ES256" ||
    typeof record.x !== "string" ||
    typeof record.y !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(record.x) ||
    !/^[A-Za-z0-9_-]{43}$/.test(record.y)
  ) {
    throw new TypeError("The installation auth key must be a strict P-256 JWK.");
  }
  return Object.freeze({
    kty: "EC",
    crv: "P-256",
    x: record.x,
    y: record.y,
    use: "sig",
    alg: "ES256",
  });
}

/** RFC 7638 thumbprint over the exact required EC members. */
export function computeJwkThumbprint(jwk: P256PublicJwk): Buffer {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical, "utf8").digest();
}

/**
 * Verifies a canonical 64-byte raw r||s ES256 signature over the possession
 * challenge digest: low-S only, exact bound key, no DER acceptance.
 */
export function verifyPossessionSignature(
  jwk: P256PublicJwk,
  challengeDigest: Buffer,
  signatureValue: unknown,
): boolean {
  if (typeof signatureValue !== "string") return false;
  if (!/^[A-Za-z0-9_-]{86}$/.test(signatureValue)) return false;
  const signature = Buffer.from(signatureValue, "base64url");
  if (signature.byteLength !== 64) return false;
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s === 0n || s > P256_ORDER / 2n) return false;
  try {
    const publicKey = createPublicKey({
      key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      format: "jwk",
    });
    return verifyNodeSignature(
      "sha256",
      challengeDigest,
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch {
    return false;
  }
}

export function computeMlsCredentialFingerprint(publicKey: Buffer): Buffer {
  return createHash("sha256")
    .update(MLS_FINGERPRINT_DOMAIN, "utf8")
    .update(publicKey)
    .digest();
}

export function computeKeyPackageRef(packageBytes: Buffer): Buffer {
  return createHash("sha256")
    .update(KEY_PACKAGE_REF_DOMAIN, "utf8")
    .update(packageBytes)
    .digest();
}

export interface PossessionDigestInput {
  readonly walletChallengeId: string;
  readonly walletPayloadDigest: Buffer;
  readonly possessionChallengeId: string;
  readonly serverNonce: string;
  readonly enrollmentId: string;
  readonly accountId: string;
  readonly chainId: string;
  readonly installationId: string;
  readonly deviceCredentialId: string;
  readonly installationAuthJkt: Buffer;
  readonly mlsCredentialFingerprint: Buffer;
  readonly keyPackageRef: Buffer;
  readonly keyPackageSha256: Buffer;
  readonly audience: string;
  readonly clientId: string;
  readonly exactHttpsOrigin: string;
  readonly purpose: string;
  readonly scopeDigest: Buffer;
  readonly notBefore: string;
  readonly expiresAt: string;
}

export function computePossessionChallengeDigest(
  input: PossessionDigestInput,
): Buffer {
  const hash = createHash("sha256").update(POSSESSION_DIGEST_DOMAIN, "utf8");
  const parts: (string | Buffer)[] = [
    input.walletChallengeId,
    input.walletPayloadDigest,
    input.possessionChallengeId,
    input.serverNonce,
    input.enrollmentId,
    input.accountId,
    input.chainId,
    input.installationId,
    input.deviceCredentialId,
    input.installationAuthJkt,
    input.mlsCredentialFingerprint,
    input.keyPackageRef,
    input.keyPackageSha256,
    input.audience,
    input.clientId,
    input.exactHttpsOrigin,
    input.purpose,
    input.scopeDigest,
    ENROLLMENT_PROTOCOL_PROFILE,
    SIWE_PROOF_PROFILE,
    input.notBefore,
    input.expiresAt,
  ];
  for (const part of parts) {
    const bytes = typeof part === "string" ? Buffer.from(part, "utf8") : part;
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}
