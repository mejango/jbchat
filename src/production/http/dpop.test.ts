import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, sign as signNode } from "node:crypto";
import { describe, expect, it } from "vitest";
import { computeJwkThumbprint } from "../identity/identityCrypto";
import {
  createInProcessDpopReplayGuard,
  verifyDpopProof,
  type DpopReplayGuard,
} from "./dpop";

const NOW_MS = Date.parse("2026-08-14T16:21:30.000Z");
const URL_UNDER_TEST = "https://api.example.test/v1/auth/session";
const ACCESS_TOKEN = Buffer.alloc(32, 0x11).toString("base64url");
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const keyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = keyPair.publicKey.export({ format: "jwk" }) as {
  x: string;
  y: string;
};
const expectedJkt = computeJwkThumbprint({
  kty: "EC",
  crv: "P-256",
  x: jwk.x,
  y: jwk.y,
  use: "sig",
  alg: "ES256",
});

function buildProof(overrides: {
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  breakSignature?: boolean;
}): string {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    ...overrides.header,
  };
  const payload = {
    htm: "GET",
    htu: URL_UNDER_TEST,
    iat: Math.floor(NOW_MS / 1000),
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    ath: createHash("sha256").update(ACCESS_TOKEN, "ascii").digest("base64url"),
    ...overrides.payload,
  };
  const head = Buffer.from(JSON.stringify(header)).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  let signature = signNode(
    "sha256",
    Buffer.from(`${head}.${body}`, "utf8"),
    { key: keyPair.privateKey, dsaEncoding: "ieee-p1363" },
  );
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s > P256_ORDER / 2n) {
    signature = Buffer.concat([
      signature.subarray(0, 32),
      Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"),
    ]);
  }
  if (overrides.breakSignature) signature[10] ^= 0x01;
  return `${head}.${body}.${signature.toString("base64url")}`;
}

function guard(): DpopReplayGuard {
  return createInProcessDpopReplayGuard({
    nowEpochMilliseconds: () => NOW_MS,
  });
}

function verify(
  proof: string | null,
  extras: Partial<Parameters<typeof verifyDpopProof>[0]> = {},
) {
  return verifyDpopProof({
    proof,
    method: "GET",
    url: `${URL_UNDER_TEST}?cursor=abc`,
    accessToken: ACCESS_TOKEN,
    expectedJkt,
    nowEpochMilliseconds: NOW_MS,
    replayGuard: guard(),
    ...extras,
  });
}

describe("DPoP proof verification", () => {
  it("accepts a canonical proof and strips query from htu", () => {
    expect(verify(buildProof({}))).toEqual({ valid: true });
  });

  it("rejects a missing or malformed proof", () => {
    expect(verify(null)).toMatchObject({ reasonCode: "dpop_proof_missing" });
    expect(verify("only.two")).toMatchObject({
      reasonCode: "dpop_proof_invalid",
    });
  });

  it("rejects a foreign key even with a valid signature", () => {
    const result = verify(buildProof({}), {
      expectedJkt: Buffer.alloc(32, 0x77),
    });
    expect(result).toMatchObject({ reasonCode: "dpop_key_mismatch" });
  });

  it("rejects a broken signature", () => {
    expect(verify(buildProof({ breakSignature: true }))).toMatchObject({
      reasonCode: "dpop_signature_invalid",
    });
  });

  it("rejects htm, htu, and ath mismatches", () => {
    expect(verify(buildProof({ payload: { htm: "POST" } }))).toMatchObject({
      reasonCode: "dpop_binding_mismatch",
    });
    expect(
      verify(buildProof({ payload: { htu: "https://evil.test/v1" } })),
    ).toMatchObject({ reasonCode: "dpop_binding_mismatch" });
    expect(
      verify(buildProof({ payload: { ath: "AAAA" } })),
    ).toMatchObject({ reasonCode: "dpop_binding_mismatch" });
  });

  it("rejects a stale iat and a replayed jti", () => {
    expect(
      verify(
        buildProof({ payload: { iat: Math.floor(NOW_MS / 1000) - 120 } }),
      ),
    ).toMatchObject({ reasonCode: "dpop_proof_stale" });

    const sharedGuard = guard();
    const proof = buildProof({ payload: { jti: "fixed-jti" } });
    expect(verify(proof, { replayGuard: sharedGuard })).toEqual({
      valid: true,
    });
    expect(verify(proof, { replayGuard: sharedGuard })).toMatchObject({
      reasonCode: "dpop_proof_replayed",
    });
  });

  it("rejects wrong typ, alg, and non-P-256 keys", () => {
    expect(verify(buildProof({ header: { typ: "jwt" } }))).toMatchObject({
      reasonCode: "dpop_proof_invalid",
    });
    expect(verify(buildProof({ header: { alg: "ES384" } }))).toMatchObject({
      reasonCode: "dpop_proof_invalid",
    });
    expect(
      verify(
        buildProof({
          header: { jwk: { kty: "EC", crv: "P-384", x: jwk.x, y: jwk.y } },
        }),
      ),
    ).toMatchObject({ reasonCode: "dpop_proof_invalid" });
  });
});
