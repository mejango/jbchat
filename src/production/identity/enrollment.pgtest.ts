import { Buffer } from "node:buffer";
import { generateKeyPairSync, randomBytes, sign as signNode, type KeyObject } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { eip191Digest } from "./identityCrypto";
import { createKeyedIdentityCrypto } from "./identityKeyedCrypto";
import { createFictionalWalletProofVerifier } from "./walletProofVerifier";
import {
  createEnrollmentStore,
  type EnrollmentStore,
} from "./enrollmentStore";
import {
  FIXTURE_CHAIN_ID,
  createFictionalDeviceCredentialSigner,
  fixtureChainState,
  seedIdentityFixture,
} from "./identityFixture.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const BASE_NOW = "2026-08-18T12:00:00.000Z";
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

interface FictionalDevice {
  readonly walletPriv: Buffer;
  readonly walletAddress: string;
  readonly walletRef: string;
  readonly possessionKey: KeyObject;
  readonly binding: Record<string, unknown>;
}

function fictionalDevice(): FictionalDevice {
  const walletPriv = Buffer.from(secp256k1.utils.randomSecretKey());
  const uncompressed = secp256k1.getPublicKey(walletPriv, false);
  const walletAddress = `0x${Buffer.from(keccak_256(uncompressed.subarray(1)))
    .subarray(-20)
    .toString("hex")}`;
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const jwkExport = publicKey.export({ format: "jwk" }) as Record<string, string>;
  return {
    walletPriv,
    walletAddress,
    walletRef: `${FIXTURE_CHAIN_ID}:${walletAddress}`,
    possessionKey: privateKey,
    binding: {
      installationAuthPublicJwk: {
        kty: "EC",
        crv: "P-256",
        x: jwkExport.x,
        y: jwkExport.y,
        use: "sig",
        alg: "ES256",
      },
      mlsCredentialPublic: randomBytes(32).toString("base64url"),
      keyPackage: randomBytes(220).toString("base64url"),
    },
  };
}

function signSiwe(message: string, priv: Buffer): string {
  const signature = secp256k1.sign(eip191Digest(message), priv, {
    format: "recovered",
    prehash: false,
  });
  return `0x${Buffer.from(signature.subarray(1)).toString("hex")}${Buffer.of(
    signature[0] + 27,
  ).toString("hex")}`;
}

function signPossession(digestBase64Url: string, key: KeyObject): string {
  const digest = Buffer.from(digestBase64Url, "base64url");
  const raw = signNode("sha256", digest, { key, dsaEncoding: "ieee-p1363" });
  const s = BigInt(`0x${raw.subarray(32).toString("hex")}`);
  const canonical =
    s > P256_ORDER / 2n
      ? Buffer.concat([
          raw.subarray(0, 32),
          Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"),
        ])
      : raw;
  return canonical.toString("base64url");
}

describeStorage("device enrollment and sessions", () => {
  let sql: Sql;
  let now = BASE_NOW;
  let store: EnrollmentStore;

  const allocateInput = (device: FictionalDevice) => ({
    walletRef: device.walletRef,
    proofProfile: "siwe-erc4361-v1",
    client: {
      clientId: "fictional-messenger",
      origin: "https://messages.fictional.example",
      audience: "https://api.fictional.example/v1",
    },
    purpose: "enroll-messaging-device",
    scope: {
      kind: "wallet-challenge-scope.v1",
      project: "fictional-project",
      action: "enroll-messaging-device",
    },
    installationKind: "native",
    platform: "ios",
  });

  const bindingInput = (device: FictionalDevice) => ({
    walletRef: device.walletRef,
    ...device.binding,
  });

  const enrollToChallenges = async (device: FictionalDevice) => {
    const allocation = await store.allocateEnrollment(allocateInput(device));
    expect(allocation.status).toBe("allocated");
    if (allocation.status !== "allocated") throw new Error("allocation refused");
    const challenges = await store.issueChallenges(
      allocation.enrollmentResultHandle,
      bindingInput(device),
    );
    expect(challenges.status).toBe("challenges_issued");
    if (challenges.status !== "challenges_issued") {
      throw new Error("challenge issuance refused");
    }
    return { allocation, challenges };
  };

  const proofFor = (
    device: FictionalDevice,
    challenges: { siweMessage: string; possessionChallengeDigest: string },
  ) => ({
    walletSignature: signSiwe(challenges.siweMessage, device.walletPriv),
    possessionSignature: signPossession(
      challenges.possessionChallengeDigest,
      device.possessionKey,
    ),
  });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 6, onnotice: () => {} });
    await seedIdentityFixture(sql, BASE_NOW);
    store = createEnrollmentStore({
      sql,
      now: () => now,
      crypto: createKeyedIdentityCrypto(Buffer.alloc(32, 0x6b)),
      walletProofVerifier: createFictionalWalletProofVerifier(fixtureChainState()),
      credentialSigner: createFictionalDeviceCredentialSigner(),
      allowedChainIds: [FIXTURE_CHAIN_ID],
    });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("enrolls a device end-to-end and leaves only derived material at rest", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const { allocation, challenges } = await enrollToChallenges(device);
    expect(challenges.siweMessage).toContain(
      "Authorize this wallet to enroll one Juicebox Messaging device.",
    );
    expect(challenges.siweMessage).toContain(
      `- urn:juicebox:messaging:enrollment-id:v1:${allocation.enrollmentId}`,
    );

    const replay = await store.issueChallenges(
      allocation.enrollmentResultHandle,
      bindingInput(device),
    );
    expect(replay).toEqual(challenges);

    now = "2026-08-18T12:01:00.000Z";
    const proof = proofFor(device, challenges);
    const completion = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      proof,
    );
    expect(completion.status).toBe("issued");
    if (completion.status !== "issued") throw new Error("enrollment not issued");
    expect(completion.walletVerificationMethod).toBe("eoa");

    const [account] = await sql`
      SELECT status FROM accounts WHERE account_id = ${completion.accountId}`;
    expect(account.status).toBe("active");
    const [credential] = await sql`
      SELECT status, signer_key_id FROM device_credentials
      WHERE device_credential_id = ${completion.deviceCredentialId}`;
    expect(credential.status).toBe("active");
    expect(credential.signer_key_id).toBe("fictional-device-credential-signer-1");
    const links = await sql`
      SELECT wl.status FROM wallet_links wl
      JOIN device_credentials dc ON dc.wallet_link_id = wl.wallet_link_id
      WHERE dc.device_credential_id = ${completion.deviceCredentialId}`;
    expect(links).toHaveLength(1);
    expect(links[0].status).toBe("active");
    const plaintextHits = await sql`
      SELECT count(*)::int AS hits FROM enrollment_wallet_challenges
      WHERE position(${device.walletAddress.slice(2)}::bytea in exact_payload_ciphertext) > 0`;
    expect(plaintextHits[0].hits).toBe(0);

    await expect(
      store.readEnrollment(allocation.enrollmentResultHandle),
    ).resolves.toEqual({ status: "issued" });

    const replayCompletion = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      proof,
    );
    expect(replayCompletion.status).toBe("issued");
    const [keyPackage] = await sql`
      SELECT state FROM key_packages
      WHERE device_credential_id = ${completion.deviceCredentialId}`;
    expect(keyPackage.state).toBe("available");
  });

  it("returns idempotency_conflict for a different proof after any claim", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const { allocation, challenges } = await enrollToChallenges(device);
    const proof = proofFor(device, challenges);
    const first = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      proof,
    );
    expect(first.status).toBe("issued");
    const conflicting = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      {
        ...proof,
        possessionSignature: signPossession(
          challenges.possessionChallengeDigest,
          device.possessionKey,
        ),
      },
    );
    expect(conflicting).toEqual({
      status: "conflict",
      reasonCode: "idempotency_conflict",
    });
  });

  it("keeps an invalid-signature claim terminal even against a correct retry", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const stranger = fictionalDevice();
    const { allocation, challenges } = await enrollToChallenges(device);
    const badProof = {
      walletSignature: signSiwe(challenges.siweMessage, stranger.walletPriv),
      possessionSignature: signPossession(
        challenges.possessionChallengeDigest,
        device.possessionKey,
      ),
    };
    const invalid = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      badProof,
    );
    expect(invalid).toEqual({ status: "invalid", reasonCode: "enrollment_invalid" });
    await expect(
      store.readEnrollment(allocation.enrollmentResultHandle),
    ).resolves.toEqual({ status: "invalid" });

    const correctRetry = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      proofFor(device, challenges),
    );
    expect(correctRetry).toEqual({
      status: "conflict",
      reasonCode: "idempotency_conflict",
    });
  });

  it("reports contract wallets unavailable, terminally, without fallback", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const contractStore = createEnrollmentStore({
      sql,
      now: () => now,
      crypto: createKeyedIdentityCrypto(Buffer.alloc(32, 0x6b)),
      walletProofVerifier: createFictionalWalletProofVerifier(
        fixtureChainState([device.walletAddress]),
      ),
      credentialSigner: createFictionalDeviceCredentialSigner(),
      allowedChainIds: [FIXTURE_CHAIN_ID],
    });
    const allocation = await contractStore.allocateEnrollment(allocateInput(device));
    if (allocation.status !== "allocated") throw new Error("allocation refused");
    const challenges = await contractStore.issueChallenges(
      allocation.enrollmentResultHandle,
      bindingInput(device),
    );
    if (challenges.status !== "challenges_issued") {
      throw new Error("challenge issuance refused");
    }
    const proof = proofFor(device, challenges);
    const completion = await contractStore.completeEnrollment(
      allocation.enrollmentResultHandle,
      proof,
    );
    expect(completion).toEqual({
      status: "unavailable",
      reasonCode: "enrollment_verification_unavailable",
    });
    await expect(
      contractStore.readEnrollment(allocation.enrollmentResultHandle),
    ).resolves.toEqual({ status: "unavailable" });
    const retry = await contractStore.completeEnrollment(
      allocation.enrollmentResultHandle,
      proof,
    );
    expect(retry).toEqual({
      status: "unavailable",
      reasonCode: "enrollment_verification_unavailable",
    });
  });

  it("expires the five-minute window fail-closed", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const allocation = await store.allocateEnrollment(allocateInput(device));
    if (allocation.status !== "allocated") throw new Error("allocation refused");
    now = "2026-08-18T12:06:00.000Z";
    const late = await store.issueChallenges(
      allocation.enrollmentResultHandle,
      bindingInput(device),
    );
    expect(late).toEqual({ status: "refused", reasonCode: "enrollment_expired" });
    await expect(
      store.readEnrollment(allocation.enrollmentResultHandle),
    ).resolves.toEqual({ status: "expired" });
    now = BASE_NOW;
  });

  it("admits exactly one claimant under concurrent completion", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const { allocation, challenges } = await enrollToChallenges(device);
    const proof = proofFor(device, challenges);
    const results = await Promise.all([
      store.completeEnrollment(allocation.enrollmentResultHandle, proof),
      store.completeEnrollment(allocation.enrollmentResultHandle, proof),
    ]);
    for (const result of results) expect(result.status).toBe("issued");
    const credentials = await sql`
      SELECT count(*)::int AS total FROM device_credentials
      WHERE enrollment_id = ${allocation.enrollmentId}`;
    expect(credentials[0].total).toBe(1);
    const completions = await sql`
      SELECT count(*)::int AS total FROM enrollment_completion_requests
      WHERE enrollment_id = ${allocation.enrollmentId}`;
    expect(completions[0].total).toBe(1);
  });

  it("rotates refresh tokens and kills the family on reuse", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    const { allocation, challenges } = await enrollToChallenges(device);
    const completion = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      proofFor(device, challenges),
    );
    if (completion.status !== "issued") throw new Error("enrollment not issued");

    const session = await store.issueSession({
      installationId: completion.installationId,
      audience: "https://api.fictional.example/v1",
      clientId: "fictional-messenger",
    });
    expect(session.status).toBe("issued");
    if (session.status !== "issued") throw new Error("session refused");
    expect(
      Date.parse(session.accessExpiresAt) - Date.parse(now),
    ).toBe(15 * 60 * 1_000);

    now = "2026-08-18T12:20:00.000Z";
    const rotated = await store.refreshSession(session.refreshToken);
    expect(rotated.status).toBe("issued");
    if (rotated.status !== "issued") throw new Error("rotation refused");
    expect(rotated.refreshToken).not.toBe(session.refreshToken);

    const reuse = await store.refreshSession(session.refreshToken);
    expect(reuse).toEqual({
      status: "revoked",
      reasonCode: "token_family_revoked",
    });
    const postKill = await store.refreshSession(rotated.refreshToken);
    expect(postKill.status).not.toBe("issued");
    const family = await sql`
      SELECT count(*)::int AS live FROM auth_sessions
      WHERE installation_id = ${completion.installationId} AND state = 'active'`;
    expect(family[0].live).toBe(0);
    now = BASE_NOW;
  });

  it("refuses garbage handles, bindings, and tokens without touching state", async () => {
    now = BASE_NOW;
    const device = fictionalDevice();
    await expect(
      store.allocateEnrollment({ ...allocateInput(device), extra: true }),
    ).resolves.toEqual({ status: "refused", reasonCode: "enrollment_refused" });
    await expect(
      store.allocateEnrollment({
        ...allocateInput(device),
        client: {
          clientId: "fictional-messenger",
          origin: "http://messages.fictional.example",
          audience: "https://api.fictional.example/v1",
        },
      }),
    ).resolves.toEqual({ status: "refused", reasonCode: "enrollment_refused" });
    await expect(
      store.issueChallenges("not-a-handle", bindingInput(device)),
    ).resolves.toEqual({ status: "refused", reasonCode: "enrollment_invalid" });
    await expect(
      store.completeEnrollment(randomBytes(32).toString("base64url"), {
        walletSignature: "0x00",
        possessionSignature: "AA",
      }),
    ).resolves.toEqual({ status: "invalid", reasonCode: "enrollment_invalid" });
    await expect(store.readEnrollment("junk")).resolves.toEqual({
      status: "unknown",
    });
    await expect(
      store.refreshSession(randomBytes(32).toString("base64url")),
    ).resolves.toEqual({ status: "refused", reasonCode: "credential_invalid" });
  });
});
