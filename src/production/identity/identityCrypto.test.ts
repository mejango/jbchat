import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signNode } from "node:crypto";
import { describe, expect, it } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  ENROLLMENT_STATEMENT,
  buildSiweEnrollmentMessage,
  computeJwkThumbprint,
  computeKeyPackageRef,
  computeMlsCredentialFingerprint,
  computePossessionChallengeDigest,
  eip191Digest,
  parseP256PublicJwk,
  parseWalletRef,
  toChecksumAddress,
  verifyEip191EoaSignature,
  verifyPossessionSignature,
} from "./identityCrypto";

const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function walletKey(): { priv: Buffer; address: string } {
  const priv = Buffer.from(secp256k1.utils.randomSecretKey());
  const uncompressed = secp256k1.getPublicKey(priv, false);
  const address = `0x${Buffer.from(keccak_256(uncompressed.subarray(1)))
    .subarray(-20)
    .toString("hex")}`;
  return { priv, address };
}

function signEip191(message: string, priv: Buffer): string {
  const signature = secp256k1.sign(eip191Digest(message), priv, {
    format: "recovered",
    prehash: false,
  });
  return `0x${Buffer.from(signature.subarray(1)).toString("hex")}${Buffer.of(
    signature[0] + 27,
  ).toString("hex")}`;
}

const SIWE_FIELDS = {
  domain: "messages.fictional.example",
  address: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
  uri: "https://api.fictional.example/v1",
  chainReference: "99999",
  nonce: "aabbccddeeff00112233445566778899",
  issuedAt: "2026-08-18T12:00:00.000Z",
  notBefore: "2026-08-18T12:00:00.000Z",
  expirationTime: "2026-08-18T12:05:00.000Z",
  requestId: "11111111-2222-4333-8444-555555555555",
  resources: {
    enrollmentId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    accountId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    installationId: "cccccccc-dddd-4eee-8fff-000000000000",
    deviceCredentialId: "dddddddd-eeee-4fff-8000-111111111111",
    audience: "https://api.fictional.example/v1",
    clientId: "fictional-messenger",
    scopeDigest: "c2NvcGUtZGlnZXN0LXBsYWNlaG9sZGVyLTMyYnl0ZQ",
    installationAuthJkt: "amt0LXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmctISE",
    mlsCredentialFingerprint: "ZnAtcGxhY2Vob2xkZXItYnl0ZXMtMzItbG9uZy0hISE",
    keyPackageRef: "a3ByLXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmchISE",
    keyPackageSha256: "a3BzLXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmchISE",
    protocolProfile: "device-enrollment.v1" as const,
    possessionChallengeId: "eeeeeeee-ffff-4000-8111-222222222222",
  },
} as const;

describe("identity crypto", () => {
  it("builds the exact EIP-4361 enrollment message", () => {
    const message = buildSiweEnrollmentMessage(SIWE_FIELDS);
    expect(message).toBe(
      [
        "messages.fictional.example wants you to sign in with your Ethereum account:",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "",
        ENROLLMENT_STATEMENT,
        "",
        "URI: https://api.fictional.example/v1",
        "Version: 1",
        "Chain ID: 99999",
        "Nonce: aabbccddeeff00112233445566778899",
        "Issued At: 2026-08-18T12:00:00.000Z",
        "Expiration Time: 2026-08-18T12:05:00.000Z",
        "Not Before: 2026-08-18T12:00:00.000Z",
        "Request ID: 11111111-2222-4333-8444-555555555555",
        "Resources:",
        "- urn:juicebox:messaging:enrollment-id:v1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "- urn:juicebox:messaging:account-id:v1:bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
        "- urn:juicebox:messaging:installation-id:v1:cccccccc-dddd-4eee-8fff-000000000000",
        "- urn:juicebox:messaging:device-credential-id:v1:dddddddd-eeee-4fff-8000-111111111111",
        "- urn:juicebox:messaging:audience:v1:https://api.fictional.example/v1",
        "- urn:juicebox:messaging:client-id:v1:fictional-messenger",
        "- urn:juicebox:messaging:scope-digest:v1:c2NvcGUtZGlnZXN0LXBsYWNlaG9sZGVyLTMyYnl0ZQ",
        "- urn:juicebox:messaging:installation-auth-jkt:v1:amt0LXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmctISE",
        "- urn:juicebox:messaging:mls-credential-fingerprint:v1:ZnAtcGxhY2Vob2xkZXItYnl0ZXMtMzItbG9uZy0hISE",
        "- urn:juicebox:messaging:key-package-ref:v1:a3ByLXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmchISE",
        "- urn:juicebox:messaging:key-package-sha256:v1:a3BzLXBsYWNlaG9sZGVyLWJ5dGVzLTMyLWxvbmchISE",
        "- urn:juicebox:messaging:protocol-profile:v1:device-enrollment.v1",
        "- urn:juicebox:messaging:possession-challenge-id:v1:eeeeeeee-ffff-4000-8111-222222222222",
      ].join("\n"),
    );
  });

  it("checksums addresses per EIP-55", () => {
    expect(toChecksumAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")).toBe(
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    );
    expect(toChecksumAddress("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")).toBe(
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    );
  });

  it("parses only allowlisted eip155 CAIP-10 references", () => {
    const parsed = parseWalletRef(
      "eip155:99999:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
      ["eip155:99999"],
    );
    expect(parsed.address).toBe("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    expect(parsed.caip10).toBe(
      "eip155:99999:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
    );
    expect(() =>
      parseWalletRef("eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", [
        "eip155:99999",
      ]),
    ).toThrow();
    expect(() => parseWalletRef("cosmos:hub:addr", ["eip155:99999"])).toThrow();
  });

  it("accepts a real EIP-191 signature and rejects tampering", () => {
    const { priv, address } = walletKey();
    const message = buildSiweEnrollmentMessage(SIWE_FIELDS);
    const signature = signEip191(message, priv);
    expect(verifyEip191EoaSignature(message, signature, address)).toBe(true);
    expect(verifyEip191EoaSignature(`${message} `, signature, address)).toBe(false);
    expect(
      verifyEip191EoaSignature(message, signature, `0x${"11".repeat(20)}`),
    ).toBe(false);
    expect(verifyEip191EoaSignature(message, signature.slice(0, -2), address)).toBe(
      false,
    );
  });

  it("rejects the high-s form of a valid signature", () => {
    const { priv, address } = walletKey();
    const message = "malleability probe";
    const signature = Buffer.from(signEip191(message, priv).slice(2), "hex");
    const s = BigInt(`0x${signature.subarray(32, 64).toString("hex")}`);
    const highS = Buffer.from(
      (SECP256K1_ORDER - s).toString(16).padStart(64, "0"),
      "hex",
    );
    const flipped = signature[64] === 27 ? 28 : 27;
    const highSignature = `0x${Buffer.concat([
      signature.subarray(0, 32),
      highS,
      Buffer.of(flipped),
    ]).toString("hex")}`;
    expect(verifyEip191EoaSignature(message, highSignature, address)).toBe(false);
  });

  it("computes a deterministic RFC 7638 thumbprint from a strict JWK only", () => {
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      use: "sig",
      alg: "ES256",
    };
    const parsed = parseP256PublicJwk(jwk);
    const thumbprint = computeJwkThumbprint(parsed);
    expect(thumbprint.byteLength).toBe(32);
    expect(computeJwkThumbprint(parseP256PublicJwk({ ...jwk }))).toEqual(
      thumbprint,
    );
    expect(() => parseP256PublicJwk({ ...jwk, d: "secret" })).toThrow();
    expect(() => parseP256PublicJwk({ ...jwk, crv: "P-384" })).toThrow();
  });

  it("verifies a canonical low-S possession signature and nothing else", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const jwkExport = publicKey.export({ format: "jwk" }) as Record<string, string>;
    const jwk = parseP256PublicJwk({
      kty: "EC",
      crv: "P-256",
      x: jwkExport.x,
      y: jwkExport.y,
      use: "sig",
      alg: "ES256",
    });
    const digest = Buffer.alloc(32, 0x42);
    const raw = signNode("sha256", digest, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    const s = BigInt(`0x${raw.subarray(32).toString("hex")}`);
    const lowS =
      s > P256_ORDER / 2n
        ? Buffer.concat([
            raw.subarray(0, 32),
            Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"),
          ])
        : raw;
    const encoded = lowS.toString("base64url");
    expect(verifyPossessionSignature(jwk, digest, encoded)).toBe(true);
    expect(
      verifyPossessionSignature(jwk, Buffer.alloc(32, 0x43), encoded),
    ).toBe(false);
    const sLow = BigInt(`0x${lowS.subarray(32).toString("hex")}`);
    const highEncoded = Buffer.concat([
      lowS.subarray(0, 32),
      Buffer.from((P256_ORDER - sLow).toString(16).padStart(64, "0"), "hex"),
    ]).toString("base64url");
    expect(verifyPossessionSignature(jwk, digest, highEncoded)).toBe(false);
  });

  it("binds every possession digest part with length prefixes", () => {
    const base = {
      walletChallengeId: "w",
      walletPayloadDigest: Buffer.alloc(32, 1),
      possessionChallengeId: "p",
      serverNonce: "ab",
      enrollmentId: "e",
      accountId: "a",
      chainId: "eip155:99999",
      installationId: "i",
      deviceCredentialId: "d",
      installationAuthJkt: Buffer.alloc(32, 2),
      mlsCredentialFingerprint: Buffer.alloc(32, 3),
      keyPackageRef: Buffer.alloc(32, 4),
      keyPackageSha256: Buffer.alloc(32, 5),
      audience: "https://api.fictional.example/v1",
      clientId: "c",
      exactHttpsOrigin: "https://messages.fictional.example",
      purpose: "enroll-messaging-device",
      scopeDigest: Buffer.alloc(32, 6),
      notBefore: "2026-08-18T12:00:00.000Z",
      expiresAt: "2026-08-18T12:05:00.000Z",
    };
    const digest = computePossessionChallengeDigest(base);
    expect(digest.byteLength).toBe(32);
    expect(computePossessionChallengeDigest({ ...base })).toEqual(digest);
    expect(
      computePossessionChallengeDigest({ ...base, serverNonce: "a", enrollmentId: "be" }),
    ).not.toEqual(digest);
    expect(
      computePossessionChallengeDigest({ ...base, purpose: "enroll-messaging-devicE" }),
    ).not.toEqual(digest);
  });

  it("domain-separates fingerprints from key-package refs", () => {
    const bytes = Buffer.alloc(32, 0x7a);
    expect(computeMlsCredentialFingerprint(bytes)).not.toEqual(
      computeKeyPackageRef(bytes),
    );
  });
});
