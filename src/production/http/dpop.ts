import { Buffer } from "node:buffer";
import {
  createHash,
  createPublicKey,
  verify as verifyNodeSignature,
} from "node:crypto";
import { computeJwkThumbprint } from "../identity/identityCrypto";

const IAT_WINDOW_SECONDS = 60;
const MAX_PROOF_BYTES = 4 * 1024;
const MAX_JTI_LENGTH = 128;
const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface DpopReplayGuard {
  /** Returns true when the jti was fresh and is now claimed. */
  readonly claim: (jti: string, expiresAtEpochMs: number) => boolean;
}

export type DpopVerification =
  | { readonly valid: true }
  | { readonly valid: false; readonly reasonCode: string };

export interface DpopVerificationInput {
  readonly proof: string | null;
  readonly method: string;
  readonly url: string;
  readonly accessToken: string;
  readonly expectedJkt: Buffer;
  readonly nowEpochMilliseconds: number;
  readonly replayGuard: DpopReplayGuard;
}

/**
 * RFC 9449 DPoP proof check for the p256-es256-dpop.v1 session profile:
 * exact typ/alg, a strict embedded P-256 JWK whose RFC 7638 thumbprint
 * must equal the session's registered installation JKT, a canonical
 * low-S 64-byte ES256 signature, exact htm, normalized htu (no query or
 * fragment), iat within a sixty-second window, a single-use jti, and the
 * access-token hash binding. Every failure collapses to one refusal with
 * a stable reason code; nothing about the parse is oracular.
 */
export function verifyDpopProof(input: DpopVerificationInput): DpopVerification {
  const refused = (reasonCode: string): DpopVerification =>
    Object.freeze({ valid: false, reasonCode });
  const { proof } = input;
  if (typeof proof !== "string" || proof.length === 0) {
    return refused("dpop_proof_missing");
  }
  if (Buffer.byteLength(proof, "utf8") > MAX_PROOF_BYTES) {
    return refused("dpop_proof_invalid");
  }
  const segments = proof.split(".");
  if (
    segments.length !== 3 ||
    !segments.every((segment) => BASE64URL_SEGMENT.test(segment))
  ) {
    return refused("dpop_proof_invalid");
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(
      Buffer.from(segments[0], "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    payload = JSON.parse(
      Buffer.from(segments[1], "base64url").toString("utf8"),
    ) as Record<string, unknown>;
  } catch {
    return refused("dpop_proof_invalid");
  }
  if (
    !header ||
    typeof header !== "object" ||
    header.typ !== "dpop+jwt" ||
    header.alg !== "ES256"
  ) {
    return refused("dpop_proof_invalid");
  }
  const jwk = header.jwk as Record<string, unknown> | undefined;
  if (
    !jwk ||
    typeof jwk !== "object" ||
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    !BASE64URL_SEGMENT.test(jwk.x) ||
    !BASE64URL_SEGMENT.test(jwk.y) ||
    Buffer.from(jwk.x, "base64url").byteLength !== 32 ||
    Buffer.from(jwk.y, "base64url").byteLength !== 32
  ) {
    return refused("dpop_proof_invalid");
  }
  const thumbprint = computeJwkThumbprint({
    kty: "EC",
    crv: "P-256",
    x: jwk.x,
    y: jwk.y,
    use: "sig",
    alg: "ES256",
  });
  if (!thumbprint.equals(input.expectedJkt)) {
    return refused("dpop_key_mismatch");
  }

  const signature = Buffer.from(segments[2], "base64url");
  if (signature.byteLength !== 64) return refused("dpop_proof_invalid");
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s === 0n || s > P256_ORDER / 2n) return refused("dpop_proof_invalid");
  try {
    const publicKey = createPublicKey({
      key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      format: "jwk",
    });
    const signingInput = Buffer.from(
      `${segments[0]}.${segments[1]}`,
      "utf8",
    );
    if (
      !verifyNodeSignature(
        "sha256",
        signingInput,
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        signature,
      )
    ) {
      return refused("dpop_signature_invalid");
    }
  } catch {
    return refused("dpop_proof_invalid");
  }

  if (payload.htm !== input.method) return refused("dpop_binding_mismatch");
  let normalizedHtu: string;
  try {
    const parsed = new URL(input.url);
    parsed.search = "";
    parsed.hash = "";
    normalizedHtu = parsed.toString();
  } catch {
    return refused("dpop_proof_invalid");
  }
  if (payload.htu !== normalizedHtu) return refused("dpop_binding_mismatch");

  const iat = payload.iat;
  if (typeof iat !== "number" || !Number.isInteger(iat)) {
    return refused("dpop_proof_invalid");
  }
  const nowSeconds = Math.floor(input.nowEpochMilliseconds / 1000);
  if (Math.abs(nowSeconds - iat) > IAT_WINDOW_SECONDS) {
    return refused("dpop_proof_stale");
  }

  const expectedAth = createHash("sha256")
    .update(input.accessToken, "ascii")
    .digest("base64url");
  if (payload.ath !== expectedAth) return refused("dpop_binding_mismatch");

  const jti = payload.jti;
  if (
    typeof jti !== "string" ||
    jti.length === 0 ||
    jti.length > MAX_JTI_LENGTH
  ) {
    return refused("dpop_proof_invalid");
  }
  const replayHorizon =
    input.nowEpochMilliseconds + (IAT_WINDOW_SECONDS + 300) * 1000;
  if (!input.replayGuard.claim(jti, replayHorizon)) {
    return refused("dpop_proof_replayed");
  }
  return Object.freeze({ valid: true });
}

/**
 * Five-minute in-process jti cache. One Railway process serves the beta;
 * a multi-instance deployment must move this to a shared store before the
 * replay guarantee holds across workers.
 */
export function createInProcessDpopReplayGuard(context: {
  readonly nowEpochMilliseconds: () => number;
}): DpopReplayGuard {
  const seen = new Map<string, number>();
  return Object.freeze({
    claim(jti: string, expiresAtEpochMs: number): boolean {
      const now = context.nowEpochMilliseconds();
      if (seen.size > 10_000) {
        for (const [key, expiry] of seen) {
          if (expiry <= now) seen.delete(key);
        }
      }
      const existing = seen.get(jti);
      if (existing !== undefined && existing > now) return false;
      seen.set(jti, expiresAtEpochMs);
      return true;
    },
  });
}
