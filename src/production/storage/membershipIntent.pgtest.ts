import { Buffer } from "node:buffer";
import { generateKeyPairSync, randomBytes, sign as signNode, webcrypto } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { LAB_CONVERSATION_ID, LAB_INSTALLATION_ID } from "../delivery/fixtures.testing";
import { eip191Digest } from "../identity/identityCrypto";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import { createFictionalWalletProofVerifier } from "../identity/walletProofVerifier";
import { createEnrollmentStore } from "../identity/enrollmentStore";
import {
  FIXTURE_CHAIN_ID,
  createFictionalDeviceCredentialSigner,
  fixtureChainState,
} from "../identity/identityFixture.testing";
import {
  createMembershipIntentStore,
  type MembershipIntentStore,
} from "./membershipIntentStore";
import { refreshCustodySnapshotDigest } from "./postgresDeliveryStore";
import { setDeliveryLabClock } from "./postgresDeliveryLab.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-14T16:21:30.000Z";
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

describeStorage("membership intents", () => {
  let sql: Sql;
  let store: MembershipIntentStore;
  let targetInstallationId: string;
  let targetAccountId: string;
  let grantId: string;

  const enrollTargetDevice = async (): Promise<void> => {
    const identityCrypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x5e));
    const enrollment = createEnrollmentStore({
      sql,
      now: () => NOW as never,
      crypto: identityCrypto,
      walletProofVerifier: createFictionalWalletProofVerifier(fixtureChainState()),
      credentialSigner: createFictionalDeviceCredentialSigner(),
      allowedChainIds: [FIXTURE_CHAIN_ID],
    });
    const walletPriv = Buffer.from(secp256k1.utils.randomSecretKey());
    const walletAddress = `0x${Buffer.from(
      keccak_256(secp256k1.getPublicKey(walletPriv, false).subarray(1)),
    )
      .subarray(-20)
      .toString("hex")}`;
    const possession = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = possession.publicKey.export({ format: "jwk" }) as Record<
      string,
      string
    >;
    const allocation = await enrollment.allocateEnrollment({
      walletRef: `${FIXTURE_CHAIN_ID}:${walletAddress}`,
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
    if (allocation.status !== "allocated") throw new Error("allocation refused");
    const challenges = await enrollment.issueChallenges(
      allocation.enrollmentResultHandle,
      {
        walletRef: `${FIXTURE_CHAIN_ID}:${walletAddress}`,
        installationAuthPublicJwk: {
          kty: "EC",
          crv: "P-256",
          x: jwk.x,
          y: jwk.y,
          use: "sig",
          alg: "ES256",
        },
        mlsCredentialPublic: randomBytes(32).toString("base64url"),
        keyPackage: randomBytes(220).toString("base64url"),
      },
    );
    if (challenges.status !== "challenges_issued") {
      throw new Error("challenges refused");
    }
    const walletSig = secp256k1.sign(
      eip191Digest(challenges.siweMessage),
      walletPriv,
      { format: "recovered", prehash: false },
    );
    const digest = Buffer.from(
      challenges.possessionChallengeDigest,
      "base64url",
    );
    const rawSignature = Buffer.from(
      await webcrypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        await webcrypto.subtle.importKey(
          "jwk",
          possession.privateKey.export({ format: "jwk" }),
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"],
        ),
        digest,
      ),
    );
    const s = BigInt(`0x${rawSignature.subarray(32).toString("hex")}`);
    const lowS =
      s > P256_ORDER / 2n
        ? Buffer.concat([
            rawSignature.subarray(0, 32),
            Buffer.from(
              (P256_ORDER - s).toString(16).padStart(64, "0"),
              "hex",
            ),
          ])
        : rawSignature;
    const completion = await enrollment.completeEnrollment(
      allocation.enrollmentResultHandle,
      {
        walletSignature: `0x${Buffer.from(walletSig.subarray(1)).toString(
          "hex",
        )}${Buffer.of(walletSig[0] + 27).toString("hex")}`,
        possessionSignature: lowS.toString("base64url"),
      },
    );
    if (completion.status !== "issued") throw new Error("enrollment refused");
    targetInstallationId = completion.installationId;
    targetAccountId = completion.accountId;
    void signNode;
  };

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 6, onnotice: () => {} });
    await setDeliveryLabClock(sql, NOW);
    store = createMembershipIntentStore({ sql });
    await enrollTargetDevice();

    const [conversation] = await sql`
      SELECT project_ref_id FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    const policyId = "00000000-0000-4000-8000-0000000a0001";
    await sql`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${policyId}, 1, ${String(conversation.project_ref_id)},
        ${"{}"}::jsonb, ${Buffer.alloc(32, 0xa1)}, ${NOW}::timestamptz
      )`;
    grantId = "00000000-0000-4000-8000-0000000a0002";
    await sql`
      INSERT INTO eligibility_grants (
        grant_id, project_ref_id, account_id, installation_id, capability,
        policy_id, policy_revision, policy_hash, subject_hash,
        finality_profile_id, finality_profile_revision, finality_profile_hash,
        finality_evidence_digest, source_chain_id, source_block,
        source_block_hash, finality_status, state, issued_at, valid_until
      ) VALUES (
        ${grantId}, ${String(conversation.project_ref_id)},
        ${targetAccountId}, ${targetInstallationId}, 'purchase-support',
        ${policyId}, 1, ${Buffer.alloc(32, 0xa1)}, ${Buffer.alloc(32, 0xa2)},
        '00000000-0000-4000-8000-0000000000f1', 1, ${Buffer.alloc(32, 0xf1)},
        ${Buffer.alloc(32, 0xa3)}, 'eip155:99999', 1, ${Buffer.alloc(32, 0xa4)},
        'verified-finalized', 'active', ${NOW}::timestamptz,
        ${NOW}::timestamptz + interval '5 minutes'
      )`;
  });

  afterAll(async () => {
    // Restore the shared conversation so later drills can append again; the
    // fence must be rewritten alongside any fenced-field change.
    await sql.begin(async (tx) => {
      await tx`
        UPDATE membership_intents SET state = 'cancelled'
        WHERE conversation_id = ${LAB_CONVERSATION_ID}
          AND state IN ('requested', 'authorized', 'proposed')`;
      await tx`
        UPDATE conversations SET state = 'active'
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      await refreshCustodySnapshotDigest(tx, LAB_CONVERSATION_ID);
    });
    await sql?.end({ timeout: 5 });
  });

  const addInput = (overrides: Record<string, unknown> = {}) => ({
    operation: "add",
    conversationId: LAB_CONVERSATION_ID,
    targetInstallationId,
    requestedByInstallationId: LAB_INSTALLATION_ID,
    grantId,
    ...overrides,
  });

  it("creates an add intent with an irreversible KeyPackage take", async () => {
    const refusedWithoutGrant = await store.createIntent(
      addInput({ grantId: null }),
    );
    expect(refusedWithoutGrant).toEqual({
      status: "refused",
      reasonCode: "grant-required",
    });

    const [custodyBefore] = await sql`
      SELECT row_version, snapshot_digest
      FROM delivery_conversation_authority
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;

    const created = await store.createIntent(addInput());
    expect(created.status).toBe("created");

    // The state flip is a custody-fenced field: the digest must be rewritten
    // in the same transaction or the append lane fails on a stale fence.
    const [custodyAfter] = await sql`
      SELECT row_version, snapshot_digest
      FROM delivery_conversation_authority
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(Number(custodyAfter.row_version)).toBe(
      Number(custodyBefore.row_version) + 1,
    );
    expect(
      Buffer.compare(
        custodyAfter.snapshot_digest as Buffer,
        custodyBefore.snapshot_digest as Buffer,
      ),
    ).not.toBe(0);
    if (created.status !== "created") throw new Error("intent refused");
    expect(created.takenKeyPackage).not.toBeNull();
    expect(created.authorizedCommitterInstallationIds).toEqual([
      LAB_INSTALLATION_ID,
    ]);
    expect(Date.parse(created.expiresAt) - Date.parse(NOW)).toBe(5 * 60 * 1_000);

    const [keyPackage] = await sql`
      SELECT state, taken_by_intent_id FROM key_packages
      WHERE installation_id = ${targetInstallationId}`;
    expect(String(keyPackage.state)).toBe("taken");
    expect(String(keyPackage.taken_by_intent_id)).toBe(created.intentId);
    const [conversation] = await sql`
      SELECT state FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(conversation.state)).toBe("membership_pending");

    // One live intent per target is a schema fact.
    expect(await store.createIntent(addInput())).toEqual({
      status: "conflict",
      reasonCode: "membership_intent_conflict",
    });

    // Cancellation returns the conversation to active but NEVER returns the
    // taken KeyPackage to inventory: the next add finds none.
    const cancelled = await store.cancelIntent(
      created.intentId,
      LAB_INSTALLATION_ID,
    );
    expect(cancelled).toMatchObject({ status: "resolved", state: "cancelled" });
    const [afterCancel] = await sql`
      SELECT state FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(afterCancel.state)).toBe("active");
    const [stillTaken] = await sql`
      SELECT state FROM key_packages
      WHERE installation_id = ${targetInstallationId}`;
    expect(String(stillTaken.state)).toBe("taken");
    expect(await store.createIntent(addInput())).toEqual({
      status: "refused",
      reasonCode: "key-package-unavailable",
    });
  });

  it("creates and expires a removal intent without reopening the lane", async () => {
    const removal = await store.createIntent({
      operation: "remove",
      conversationId: LAB_CONVERSATION_ID,
      targetInstallationId: LAB_INSTALLATION_ID,
      requestedByInstallationId: null,
      grantId: null,
    });
    expect(removal.status).toBe("created");
    if (removal.status !== "created") throw new Error("removal refused");
    expect(removal.takenKeyPackage).toBeNull();
    // The removal target cannot be its own authorized committer.
    expect(removal.authorizedCommitterInstallationIds).toEqual([]);
    const [pending] = await sql`
      SELECT state FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(pending.state)).toBe("membership_pending");

    await setDeliveryLabClock(sql, "2026-08-14T16:27:00.000Z");
    expect(await store.expireIntents()).toBeGreaterThanOrEqual(1);
    await expect(store.readIntent(removal.intentId)).resolves.toMatchObject({
      state: "expired",
    });
    // An expired REMOVAL leaves the conversation pending: the unresolved
    // removal still blocks application sends.
    const [stillPending] = await sql`
      SELECT state FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(stillPending.state)).toBe("membership_pending");
    await setDeliveryLabClock(sql, NOW);
  });

  it("refuses mismatched grants and unknown targets", async () => {
    // The expired removal from the previous test left the conversation
    // pending on purpose; clear it so refusal precedence is observable.
    await sql.begin(async (tx) => {
      await tx`
        UPDATE conversations SET state = 'active'
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      await refreshCustodySnapshotDigest(tx, LAB_CONVERSATION_ID);
    });
    await expect(
      store.createIntent(
        addInput({
          targetInstallationId: "00000000-0000-4000-8000-00000000dead",
        }),
      ),
    ).resolves.toEqual({
      status: "refused",
      reasonCode: "target-not-enrolled",
    });
    await expect(
      store.createIntent({
        operation: "remove",
        conversationId: LAB_CONVERSATION_ID,
        targetInstallationId,
        requestedByInstallationId: null,
        grantId: null,
      }),
    ).resolves.toEqual({
      status: "refused",
      reasonCode: "target-not-a-member",
    });
  });
});
