import { Buffer } from "node:buffer";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as signNode,
  type KeyObject,
} from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql, type TransactionSql } from "postgres";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { eip191Digest } from "../identity/identityCrypto";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import { createFictionalWalletProofVerifier } from "../identity/walletProofVerifier";
import { createFictionalDeviceCredentialSigner } from "../identity/identityFixture.testing";
import { createEnrollmentStore } from "../identity/enrollmentStore";
import { createConversationRequestStore } from "./conversationRequestStore";
import { createConversationPlanStore } from "./conversationPlanStore";
import { ensureProjectRef } from "./projectRefProvision";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-14T12:03:00.000Z";

// Self-contained fixture IDs (d3xx) so this suite shares the lab DB with the
// others without colliding on the entitlement fixture.
const TENANT_ID = "00000000-0000-4000-8000-00000000d301";
const PROJECT_REF_ID = "00000000-0000-4000-8000-00000000d302";
const POLICY_ID = "00000000-0000-4000-8000-00000000d303";
const FINALITY_PROFILE_ID = "00000000-0000-4000-8000-00000000d304";
const CUSTOMER_ACCOUNT_ID = "00000000-0000-4000-8000-00000000d311";
const CUSTOMER_INSTALLATION_ID = "00000000-0000-4000-8000-00000000d312";
const OWNER_ACCOUNT_ID = "00000000-0000-4000-8000-00000000d321";
const OWNER_INSTALLATION_ID = "00000000-0000-4000-8000-00000000d322";
const CLAIM_HANDLE = randomBytes(32).toString("base64url");
const WALLET_REF = "eip155:31337:0x5138a42c3d5065debe950debda10c1f38150a908";
const POLICY_HASH = randomBytes(32);
const PROFILE_HASH = randomBytes(32);

describeStorage("conversation requests", () => {
  let sql: Sql;
  const crypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x7c));
  const store = () =>
    createConversationRequestStore({
      sql,
      hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
      hmacEligibilitySubject: crypto.hmacEligibilitySubject,
      now: () => NOW,
    });
  // The plan store reads the real DB clock (not the injected NOW), so the
  // fixture grant's valid_until is far-future to stay live for acceptRequest.
  const planStore = () =>
    createConversationPlanStore({
      sql,
      provisioningSeed: Buffer.alloc(32, 0x7d),
      logSigner: { signCheckpointDigest: async () => "" },
      logSigningKeyId: "req-lab-log-signer",
      hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
    });

  const seedInstallation = (
    tx: TransactionSql,
    installationId: string,
    accountId: string,
  ) => tx`
    INSERT INTO installations (
      installation_id, account_id, platform, storage_partition_class,
      installation_auth_profile, installation_auth_public_jwk,
      installation_auth_jkt, mls_credential_profile, mls_credential_public,
      mls_credential_fingerprint, status, created_at, last_seen_at
    ) VALUES (
      ${installationId}, ${accountId}, 'web', 'top_level',
      'p256-es256-dpop.v1',
      ${JSON.stringify({ kty: "EC", crv: "P-256", x: "x", y: "y" })}::jsonb,
      ${randomBytes(32)}, 'mls-credential-ed25519-suite-0x0001.v1',
      ${randomBytes(32)}, ${randomBytes(32)}, 'active', ${NOW}::timestamptz,
      ${NOW}::timestamptz
    )`;

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 2, onnotice: () => {} });
    await sql.begin(async (tx) => {
      await tx`
        INSERT INTO tenants (
          tenant_id, tenant_public_id, status, kms_key_ref, created_at, updated_at
        ) VALUES (
          ${TENANT_ID}, 'req-lab', 'active', 'req-lab-kms',
          ${NOW}::timestamptz, ${NOW}::timestamptz
        )`;
      await tx`
        INSERT INTO project_refs (
          project_ref_id, tenant_id, protocol, protocol_version, chain_id,
          projects_contract, project_id, canonical_hash, status, created_at
        ) VALUES (
          ${PROJECT_REF_ID}, ${TENANT_ID}, 'juicebox', '6', 'eip155:31337',
          ${Buffer.alloc(20, 0xd3)}, 42, ${Buffer.alloc(32, 0xd3)}, 'active',
          ${NOW}::timestamptz
        )`;
      await tx`
        INSERT INTO policies (
          policy_id, policy_revision, project_ref_id, canonical_document,
          policy_hash, created_at
        ) VALUES (
          ${POLICY_ID}, 1, ${PROJECT_REF_ID},
          ${JSON.stringify({ profile: "req-lab" })}::jsonb, ${POLICY_HASH},
          ${NOW}::timestamptz
        )`;
      await tx`
        INSERT INTO chain_finality_profiles (
          finality_profile_id, profile_revision, chain_id, canonical_document,
          profile_hash, adapter_release_id, ratification_evidence_ref, state,
          effective_at, created_at
        ) VALUES (
          ${FINALITY_PROFILE_ID}, 1, 'eip155:31337',
          ${JSON.stringify({ profile: "req-finality.v1", quorum: 2 })}::jsonb,
          ${PROFILE_HASH}, 'req-adapter-1.0.0', 'req-ratification', 'active',
          ${NOW}::timestamptz, ${NOW}::timestamptz
        )`;
      await tx`
        INSERT INTO accounts (account_id, status, created_at) VALUES
          (${CUSTOMER_ACCOUNT_ID}, 'active', ${NOW}::timestamptz),
          (${OWNER_ACCOUNT_ID}, 'active', ${NOW}::timestamptz)`;
      await seedInstallation(tx, CUSTOMER_INSTALLATION_ID, CUSTOMER_ACCOUNT_ID);
      await seedInstallation(tx, OWNER_INSTALLATION_ID, OWNER_ACCOUNT_ID);
      await tx`
        INSERT INTO eligibility_grants (
          grant_id, project_ref_id, account_id, installation_id, capability,
          policy_id, policy_revision, policy_hash, subject_hash,
          claim_handle_hash, finality_profile_id, finality_profile_revision,
          finality_profile_hash, finality_evidence_digest, source_chain_id,
          source_block, source_block_hash, finality_status, state, issued_at,
          valid_until
        ) VALUES (
          ${randomUUID()}, ${PROJECT_REF_ID}, ${CUSTOMER_ACCOUNT_ID},
          ${CUSTOMER_INSTALLATION_ID}, 'purchase-support', ${POLICY_ID}, 1,
          ${POLICY_HASH}, ${crypto.hmacEligibilitySubject(WALLET_REF)},
          ${crypto.hmacEligibilityClaimHandle(CLAIM_HANDLE)},
          ${FINALITY_PROFILE_ID}, 1, ${PROFILE_HASH}, ${randomBytes(32)},
          'eip155:31337', 100, ${randomBytes(32)}, 'verified-finalized',
          'active', ${NOW}::timestamptz, '2099-01-01T00:00:00.000Z'
        )`;
      await tx`
        INSERT INTO project_staff_registrations (
          project_ref_id, installation_id, account_id,
          registered_by_owner_address, ownership_block, ownership_block_hash,
          state, registered_at
        ) VALUES (
          ${PROJECT_REF_ID}, ${OWNER_INSTALLATION_ID}, ${OWNER_ACCOUNT_ID},
          ${Buffer.alloc(20, 0xd2)}, 100, ${randomBytes(32)}, 'active',
          ${NOW}::timestamptz
        )`;
    });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("lodges a request, dedupes a second, and shows it to the owner", async () => {
    const created = await store().createRequest({
      requesterAccountId: CUSTOMER_ACCOUNT_ID,
      requesterInstallationId: CUSTOMER_INSTALLATION_ID,
      eligibilityClaimHandle: CLAIM_HANDLE,
      requesterWalletRef: WALLET_REF.toUpperCase().replace("EIP", "eip"),
    });
    expect(created.status).toBe("created");

    const again = await store().createRequest({
      requesterAccountId: CUSTOMER_ACCOUNT_ID,
      requesterInstallationId: CUSTOMER_INSTALLATION_ID,
      eligibilityClaimHandle: CLAIM_HANDLE,
    });
    if (created.status !== "created" || again.status !== "already_pending") {
      throw new Error(`unexpected: ${created.status}/${again.status}`);
    }
    expect(again.requestId).toBe(created.requestId);

    const queue = await store().listForOwnerInstallation(OWNER_INSTALLATION_ID);
    expect(queue.length).toBe(1);
    expect(queue[0].requestId).toBe(created.requestId);
    expect(queue[0].requesterAccountId).toBe(CUSTOMER_ACCOUNT_ID);
    // The wallet display survives only because it HMAC-matched the grant's
    // subject (case-normalized).
    expect(queue[0].requesterWallet).toBe(WALLET_REF);
    expect(queue[0].projectId).toBe("42");
  });

  it("refuses a claim handle that is not the requester's", async () => {
    const wrong = await store().createRequest({
      requesterAccountId: OWNER_ACCOUNT_ID,
      requesterInstallationId: OWNER_INSTALLATION_ID,
      eligibilityClaimHandle: CLAIM_HANDLE,
    });
    expect(wrong.status).toBe("refused");
  });

  it("shows nothing to an installation that owns no projects", async () => {
    const queue = await store().listForOwnerInstallation(
      CUSTOMER_INSTALLATION_ID,
    );
    expect(queue.length).toBe(0);
  });

  it("provisions a project_ref on demand, deterministically and idempotently", async () => {
    const seed = Buffer.alloc(32, 0xef);
    const input = {
      chainId: 8453,
      projectId: 777,
      projectsContract: "0x6017d1fba9dc279bfa0b03fd931c22e242ab3691",
    };
    const first = await ensureProjectRef(sql, seed, NOW, input);
    const second = await ensureProjectRef(sql, seed, NOW, input);
    expect(second).toBe(first);
    const rows = await sql`
      SELECT chain_id, project_id::text AS project_id, status
      FROM project_refs WHERE project_ref_id = ${first}`;
    expect(rows.length).toBe(1);
    expect(rows[0].chain_id).toBe("eip155:8453");
    expect(rows[0].project_id).toBe("777");
    expect(rows[0].status).toBe("active");
    const policies = await sql`
      SELECT count(*)::int AS c FROM policies WHERE project_ref_id = ${first}`;
    expect(policies[0].c).toBe(1);
  });

  // acceptRequest inverts the roster: the owner becomes MLS creator and the
  // waiting customer the welcome target. These cover its owner-auth gates and
  // that it proceeds to reserve the CUSTOMER's KeyPackage.
  it("refuses acceptRequest from an installation that is not project staff", async () => {
    const request = await store().createRequest({
      requesterAccountId: CUSTOMER_ACCOUNT_ID,
      requesterInstallationId: CUSTOMER_INSTALLATION_ID,
      eligibilityClaimHandle: CLAIM_HANDLE,
    });
    if (request.status === "refused") throw new Error(request.reasonCode);
    const result = await planStore().acceptRequest({
      requestId: request.requestId,
      // The customer is not staff on this project.
      ownerAccountId: CUSTOMER_ACCOUNT_ID,
      ownerInstallationId: CUSTOMER_INSTALLATION_ID,
    });
    expect(result).toMatchObject({
      status: "refused",
      reasonCode: "not_project_staff",
    });
  });

  it("refuses acceptRequest for an unknown request", async () => {
    const result = await planStore().acceptRequest({
      requestId: randomUUID(),
      ownerAccountId: OWNER_ACCOUNT_ID,
      ownerInstallationId: OWNER_INSTALLATION_ID,
    });
    expect(result).toMatchObject({
      status: "refused",
      reasonCode: "request_not_pending",
    });
  });

  it("owner-accepts through the auth gates to the customer's KeyPackage take", async () => {
    const request = await store().createRequest({
      requesterAccountId: CUSTOMER_ACCOUNT_ID,
      requesterInstallationId: CUSTOMER_INSTALLATION_ID,
      eligibilityClaimHandle: CLAIM_HANDLE,
    });
    if (request.status === "refused") throw new Error(request.reasonCode);
    // The owner IS active staff and the grant is live, so acceptRequest
    // clears every gate and reaches the welcome-target KeyPackage take —
    // which is the CUSTOMER's. None is stocked, so it stops there.
    const result = await planStore().acceptRequest({
      requestId: request.requestId,
      ownerAccountId: OWNER_ACCOUNT_ID,
      ownerInstallationId: OWNER_INSTALLATION_ID,
    });
    expect(result).toMatchObject({
      status: "refused",
      reasonCode: "recipient_keys_unavailable",
    });
    // Nothing materialized and the request stays pending (safe to retry).
    const plans = await sql`
      SELECT count(*)::int AS c FROM conversation_plans
      WHERE project_ref_id = ${PROJECT_REF_ID}`;
    expect(plans[0].c).toBe(0);
    const stillPending = await sql`
      SELECT status FROM conversation_requests
      WHERE request_id = ${request.requestId}`;
    expect(String(stillPending[0].status)).toBe("pending");
  });
});

// The FULL owner-accept loop over the real enrollment graph: two customer
// devices enrolled with the same wallet (same account), one owner device,
// a verified grant, a queued request — accepted by the owner, activated
// with an MLS-shaped commit, both customer devices welcomed, and the
// queue self-healing. This is the production path end to end at the
// store layer.
describeStorage("owner-accept happy path (real enrollment graph)", () => {
  const logKey = generateKeyPairSync("ed25519");
  const logPublicRaw = (
    logKey.publicKey.export({ format: "der", type: "spki" }) as Buffer
  ).subarray(-32);
  const P256_ORDER =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const CHAIN = "eip155:31337";
  let sql: Sql;
  let nowIso = "2026-08-14T12:10:00.000Z";
  const crypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x7c));
  const claimHandle = randomBytes(32).toString("base64url");

  interface Enrolled {
    accountId: string;
    installationId: string;
    walletRef: string;
  }

  const enroll = async (walletPriv: Buffer): Promise<Enrolled> => {
    const store = createEnrollmentStore({
      sql,
      now: () => nowIso,
      crypto,
      walletProofVerifier: createFictionalWalletProofVerifier({
        finalityProfileId: FINALITY_PROFILE_ID,
        finalityProfileRevision: "1",
        finalityProfileHash: PROFILE_HASH,
        finalizedChainId: CHAIN,
        finalizedBlock: "4242",
        finalizedBlockHash: Buffer.alloc(32, 0x4b),
        providerQuorumHash: Buffer.alloc(32, 0x4c),
      }),
      credentialSigner: createFictionalDeviceCredentialSigner(),
      allowedChainIds: [CHAIN],
    });
    const walletAddress = `0x${Buffer.from(
      keccak_256(secp256k1.getPublicKey(walletPriv, false).subarray(1)),
    )
      .subarray(-20)
      .toString("hex")}`;
    const walletRef = `${CHAIN}:${walletAddress}`;
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;

    const allocation = await store.allocateEnrollment({
      walletRef,
      proofProfile: "siwe-erc4361-v1",
      client: {
        clientId: "req-lab-client",
        origin: "https://req.lab.example",
        audience: "https://req.lab.example/v1",
      },
      purpose: "enroll-messaging-device",
      scope: {
        kind: "wallet-challenge-scope.v1",
        project: "req-lab",
        action: "enroll-messaging-device",
      },
      installationKind: "native",
      platform: "web",
    });
    if (allocation.status !== "allocated") throw new Error("alloc refused");
    const challenges = await store.issueChallenges(
      allocation.enrollmentResultHandle,
      {
        walletRef,
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
    const siweSig = secp256k1.sign(
      eip191Digest(challenges.siweMessage),
      walletPriv,
      { format: "recovered", prehash: false },
    );
    const walletSignature = `0x${Buffer.from(siweSig.subarray(1)).toString(
      "hex",
    )}${Buffer.of(siweSig[0] + 27).toString("hex")}`;
    const possessionRaw = signNode(
      "sha256",
      Buffer.from(challenges.possessionChallengeDigest, "base64url"),
      { key: privateKey as KeyObject, dsaEncoding: "ieee-p1363" },
    );
    const s = BigInt(`0x${possessionRaw.subarray(32).toString("hex")}`);
    const possessionCanonical =
      s > P256_ORDER / 2n
        ? Buffer.concat([
            possessionRaw.subarray(0, 32),
            Buffer.from(
              (P256_ORDER - s).toString(16).padStart(64, "0"),
              "hex",
            ),
          ])
        : possessionRaw;
    const completion = await store.completeEnrollment(
      allocation.enrollmentResultHandle,
      {
        walletSignature,
        possessionSignature: possessionCanonical.toString("base64url"),
      },
    );
    if (completion.status !== "issued") {
      throw new Error(`enroll not issued: ${JSON.stringify(completion)}`);
    }
    return {
      accountId: completion.accountId,
      installationId: completion.installationId,
      walletRef,
    };
  };

  let customerA: Enrolled;
  let customerB: Enrolled;
  let owner: Enrolled;

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    const customerWallet = Buffer.from(secp256k1.utils.randomSecretKey());
    const ownerWallet = Buffer.from(secp256k1.utils.randomSecretKey());
    customerA = await enroll(customerWallet);
    nowIso = "2026-08-14T12:11:00.000Z";
    // Second device, same wallet: the active wallet link binds it to the
    // SAME account.
    customerB = await enroll(customerWallet);
    nowIso = "2026-08-14T12:12:00.000Z";
    owner = await enroll(ownerWallet);
    expect(customerB.accountId).toBe(customerA.accountId);
    expect(customerB.installationId).not.toBe(customerA.installationId);

    // The plan store reads the durable DB clock (real time in this lab),
    // while enrollment stamped 2026-08-14 expiries — push the KeyPackage
    // shelf lifetimes far out so the accept path can take them.
    await sql`
      UPDATE key_packages SET expires_at = '2099-01-01T00:00:00Z'
      WHERE installation_id IN (
        ${customerA.installationId}, ${customerB.installationId},
        ${owner.installationId}
      )`;

    // The activation's position-one commit envelope FKs to a registered
    // delivery-log signing key.
    await sql`
      INSERT INTO delivery_log_signing_keys (
        key_id, public_key, state, valid_from, valid_until, created_at
      ) VALUES (
        'req-lab-log-signer', ${logPublicRaw},
        'active', now() - interval '1 day', now() + interval '30 days', now()
      ) ON CONFLICT (key_id) DO NOTHING`;

    // Grant + staff registration + queued request against the shared
    // req-lab project fixture.
    await sql`
      INSERT INTO eligibility_grants (
        grant_id, project_ref_id, account_id, installation_id, capability,
        policy_id, policy_revision, policy_hash, subject_hash,
        claim_handle_hash, finality_profile_id, finality_profile_revision,
        finality_profile_hash, finality_evidence_digest, source_chain_id,
        source_block, source_block_hash, finality_status, state, issued_at,
        valid_until
      ) VALUES (
        ${randomUUID()}, ${PROJECT_REF_ID}, ${customerA.accountId},
        ${customerA.installationId}, 'purchase-support', ${POLICY_ID}, 1,
        ${POLICY_HASH}, ${crypto.hmacEligibilitySubject(customerA.walletRef)},
        ${crypto.hmacEligibilityClaimHandle(claimHandle)},
        ${FINALITY_PROFILE_ID}, 1, ${PROFILE_HASH}, ${randomBytes(32)},
        ${CHAIN}, 4242, ${randomBytes(32)}, 'verified-finalized',
        'active', ${nowIso}::timestamptz, '2099-01-01T00:00:00.000Z'
      )`;
    await sql`
      INSERT INTO project_staff_registrations (
        project_ref_id, installation_id, account_id,
        registered_by_owner_address, ownership_block, ownership_block_hash,
        state, registered_at
      ) VALUES (
        ${PROJECT_REF_ID}, ${owner.installationId}, ${owner.accountId},
        ${Buffer.alloc(20, 0xd7)}, 4242, ${randomBytes(32)}, 'active',
        ${nowIso}::timestamptz
      )`;
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("accepts and activates: both customer devices welcomed, queue self-heals", async () => {
    const requests = createConversationRequestStore({
      sql,
      hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
      hmacEligibilitySubject: crypto.hmacEligibilitySubject,
      now: () => "2026-08-14T12:15:00.000Z",
    });
    const plans = createConversationPlanStore({
      sql,
      provisioningSeed: Buffer.alloc(32, 0x7d),
      logSigner: {
        signCheckpointDigest: async (_keyId: string, digest: string) =>
          signNode(
            null,
            Buffer.from(digest, "base64url"),
            logKey.privateKey,
          ).toString("base64url"),
      },
      logSigningKeyId: "req-lab-log-signer",
      hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
    });

    const lodged = await requests.createRequest({
      requesterAccountId: customerA.accountId,
      requesterInstallationId: customerA.installationId,
      eligibilityClaimHandle: claimHandle,
      requesterWalletRef: customerA.walletRef,
    });
    if (lodged.status === "refused") throw new Error(lodged.reasonCode);

    const queueBefore = await requests.listForOwnerInstallation(
      owner.installationId,
    );
    expect(
      queueBefore.some((item) => item.requestId === lodged.requestId),
    ).toBe(true);

    const accepted = await plans.acceptRequest({
      requestId: lodged.requestId,
      ownerAccountId: owner.accountId,
      ownerInstallationId: owner.installationId,
    });
    if (accepted.status !== "created") {
      throw new Error(`accept: ${JSON.stringify(accepted)}`);
    }
    const plan = accepted.plan as {
      planId: string;
      conversationId: string;
      rosterHash: string;
      externalSendersHash: string;
      roster: {
        installationId: string;
        role: string;
        bootstrapMode: string;
      }[];
    };
    // Owner creates; BOTH customer devices are welcome targets.
    const creator = plan.roster.find(
      (member) => member.bootstrapMode === "creator",
    );
    expect(creator).toMatchObject({
      installationId: owner.installationId,
      role: "project-staff",
    });
    const welcomes = plan.roster.filter(
      (member) => member.bootstrapMode === "welcome",
    );
    expect(
      welcomes.map((member) => member.installationId).sort(),
    ).toEqual(
      [customerA.installationId, customerB.installationId].sort(),
    );
    expect(welcomes.every((member) => member.role === "customer")).toBe(true);

    // Activate with an MLS-shaped commit, one Welcome per target.
    const commit = Buffer.from("owner-accept-activation-commit", "utf8");
    const welcomeBytes = Buffer.from("owner-accept-welcome", "utf8");
    const activated = await plans.activate(
      {
        planId: plan.planId,
        conversationId: plan.conversationId,
        rosterHash: plan.rosterHash,
        externalSendersHash: plan.externalSendersHash,
        mls: {
          cipherSuite: "0x0001",
          groupId: randomBytes(32).toString("base64url"),
          epoch: "1",
          envelopeId: randomUUID(),
          commit: commit.toString("base64url"),
          envelopeSha256: createHash("sha256")
            .update(commit)
            .digest("base64url"),
          resultingConfirmedTranscriptHash: Buffer.alloc(32, 0xd9).toString(
            "base64url",
          ),
          welcomeByInstallation: welcomes.map((member) => ({
            installationId: member.installationId,
            welcome: welcomeBytes.toString("base64url"),
            welcomeSha256: createHash("sha256")
              .update(welcomeBytes)
              .digest("base64url"),
          })),
        },
      },
      owner.installationId,
    );
    if (activated.status !== "activated") {
      throw new Error(`activate: ${JSON.stringify(activated)}`);
    }

    // The relationship went live for the CUSTOMER account and every
    // device holds a membership.
    const relationship = await sql`
      SELECT active_conversation_id FROM relationships
      WHERE project_ref_id = ${PROJECT_REF_ID}
        AND customer_account_id = ${customerA.accountId}
        AND state = 'active'`;
    expect(String(relationship[0].active_conversation_id)).toBe(
      plan.conversationId,
    );
    const memberships = await sql`
      SELECT installation_id, role FROM memberships
      WHERE conversation_id = ${plan.conversationId}
      ORDER BY role, installation_id`;
    expect(memberships).toHaveLength(3);

    // Each welcome target got its mailbox Welcome.
    const mlsWelcomes = await sql`
      SELECT target_installation_id FROM mls_welcomes
      WHERE conversation_id = ${plan.conversationId}`;
    expect(
      mlsWelcomes.map((row) => String(row.target_installation_id)).sort(),
    ).toEqual(
      [customerA.installationId, customerB.installationId].sort(),
    );

    // The queue self-heals: the accepted request no longer shows.
    const queueAfter = await requests.listForOwnerInstallation(
      owner.installationId,
    );
    expect(
      queueAfter.some((item) => item.requestId === lodged.requestId),
    ).toBe(false);
  });
});
