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
import postgres, { type Sql } from "postgres";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { LAB_CONVERSATION_ID } from "../delivery/fixtures.testing";
import { signFictionalDeliveryCheckpointDigestForTesting } from "../delivery/fictionalCryptoPorts.testing";
import { eip191Digest } from "../identity/identityCrypto";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import { createFictionalWalletProofVerifier } from "../identity/walletProofVerifier";
import {
  FIXTURE_CHAIN_ID,
  fixtureChainState,
} from "../identity/identityFixture.testing";
import { createExternalProposalStore } from "../storage/externalProposalStore";
import {
  refreshCustodySnapshotDigest,
} from "../storage/postgresDeliveryStore";
import { setDeliveryLabClock } from "../storage/postgresDeliveryLab.testing";
import { createInProcessDpopReplayGuard } from "./dpop";
import { createMessagingHttpHandlers } from "./messagingHttp";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-14T16:21:30.000Z";
const NOW_MS = Date.parse(NOW);
const BASE = "https://api.lab.test";
const MEDIA_TYPE = "application/vnd.juicebox.messaging.v1+json";
const POLICY_ID = "00000000-0000-4000-8000-0000000b0001";
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

interface EnrolledDevice {
  readonly installationId: string;
  readonly accountId: string;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly privateKey: KeyObject;
}

describeStorage("messaging HTTP surface", () => {
  let sql: Sql;
  let handlers: ReturnType<typeof createMessagingHttpHandlers>;
  let crypto: ReturnType<typeof createKeyedIdentityCrypto>;
  let committer: EnrolledDevice;
  let target: EnrolledDevice;
  let pre: Record<string, unknown>;

  const lowS = (signature: Buffer): Buffer => {
    const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
    return s > P256_ORDER / 2n
      ? Buffer.concat([
          signature.subarray(0, 32),
          Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"),
        ])
      : signature;
  };

  const dpopProof = (
    device: EnrolledDevice,
    method: string,
    url: string,
    token?: string,
  ): string => {
    const jwk = device.privateKey.export({ format: "jwk" }) as Record<
      string,
      string
    >;
    const normalized = new URL(url);
    normalized.search = "";
    normalized.hash = "";
    const head = Buffer.from(
      JSON.stringify({
        typ: "dpop+jwt",
        alg: "ES256",
        jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      }),
    ).toString("base64url");
    const body = Buffer.from(
      JSON.stringify({
        htm: method,
        htu: normalized.toString(),
        iat: Math.floor(NOW_MS / 1000),
        jti: randomUUID(),
        ath: createHash("sha256")
          .update(token ?? device.accessToken, "ascii")
          .digest("base64url"),
      }),
    ).toString("base64url");
    const signature = lowS(
      signNode("sha256", Buffer.from(`${head}.${body}`, "utf8"), {
        key: device.privateKey,
        dsaEncoding: "ieee-p1363",
      }),
    );
    return `${head}.${body}.${signature.toString("base64url")}`;
  };

  const jsonRequest = (
    method: string,
    path: string,
    body: unknown,
    headers: Record<string, string> = {},
  ): Request =>
    new Request(`${BASE}${path}`, {
      method,
      headers: { "Content-Type": MEDIA_TYPE, ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  const authedRequest = (
    device: EnrolledDevice,
    method: string,
    path: string,
    body?: unknown,
  ): Request => {
    const url = `${BASE}${path}`;
    return jsonRequest(method, path, body, {
      Authorization: `DPoP ${device.accessToken}`,
      DPoP: dpopProof(device, method, url),
    });
  };

  const enrollOverHttp = async (): Promise<EnrolledDevice> => {
    const walletPriv = Buffer.from(secp256k1.utils.randomSecretKey());
    const walletAddress = `0x${Buffer.from(
      keccak_256(secp256k1.getPublicKey(walletPriv, false).subarray(1)),
    )
      .subarray(-20)
      .toString("hex")}`;
    const walletRef = `${FIXTURE_CHAIN_ID}:${walletAddress}`;
    const possession = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = possession.publicKey.export({ format: "jwk" }) as Record<
      string,
      string
    >;

    const allocated = await handlers.allocateEnrollment(
      jsonRequest("POST", "/v1/device-enrollments", {
        walletRef,
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
      }),
    );
    expect(allocated.status).toBe(201);
    const allocation = (await allocated.json()) as Record<string, string>;
    const handleHeader = {
      Authorization: `Enrollment ${allocation.enrollmentResultHandle}`,
    };

    const challenged = await handlers.issueChallenges(
      jsonRequest(
        "POST",
        `/v1/device-enrollments/${allocation.enrollmentId}/challenges`,
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
        handleHeader,
      ),
      allocation.enrollmentId,
    );
    expect(challenged.status).toBe(200);
    const challenges = (await challenged.json()) as Record<string, string>;

    const walletSig = secp256k1.sign(
      eip191Digest(challenges.siweMessage),
      walletPriv,
      { format: "recovered", prehash: false },
    );
    const possessionSignature = lowS(
      signNode(
        "sha256",
        Buffer.from(challenges.possessionChallengeDigest, "base64url"),
        { key: possession.privateKey, dsaEncoding: "ieee-p1363" },
      ),
    ).toString("base64url");

    const completed = await handlers.completeEnrollment(
      jsonRequest(
        "POST",
        `/v1/device-enrollments/${allocation.enrollmentId}/complete`,
        {
          client: {
            clientId: "fictional-messenger",
            audience: "https://api.fictional.example/v1",
          },
          walletProof: {
            signature: `0x${Buffer.from(walletSig.subarray(1)).toString(
              "hex",
            )}${Buffer.of(walletSig[0] + 27).toString("hex")}`,
          },
          possessionProof: { signature: possessionSignature },
        },
        handleHeader,
      ),
      allocation.enrollmentId,
    );
    expect(completed.status).toBe(200);
    const issued = (await completed.json()) as {
      accessToken: string;
      refreshToken: string;
      account: { accountId: string };
      installation: { installationId: string };
    };
    return {
      installationId: issued.installation.installationId,
      accountId: issued.account.accountId,
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      privateKey: possession.privateKey,
    };
  };

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 8, onnotice: () => {} });
    await setDeliveryLabClock(sql, NOW);
    const identitySecret = Buffer.alloc(32, 0x5f);
    crypto = createKeyedIdentityCrypto(identitySecret);
    handlers = createMessagingHttpHandlers({
      loadConfig: () => ({
        status: "configured",
        databaseUrl: DATABASE_URL!,
        identitySecret,
        credentialSignerKeyId: "lab-http-credential-signer",
        credentialSignerSeed: Buffer.alloc(32, 0x60),
        allowedChainIds: [FIXTURE_CHAIN_ID],
        logSigner: null,
        cursor: { keyId: "lab-http-cursor", key: Buffer.alloc(32, 0x61) },
      }),
      connect: () => sql,
      now: () => NOW,
      walletProofVerifier: createFictionalWalletProofVerifier(
        fixtureChainState(),
      ),
      logSigner: {
        signCheckpointDigest: async (_keyId, digest) =>
          signFictionalDeliveryCheckpointDigestForTesting(
            Buffer.from(digest, "base64url"),
          ).toString("base64url"),
      },
      replayGuard: createInProcessDpopReplayGuard({
        nowEpochMilliseconds: () => NOW_MS,
      }),
    });

    const [conversation] = await sql`
      SELECT project_ref_id, epoch, roster_version, roster_hash,
             recipient_set_version, recipient_set_hash,
             confirmed_transcript_hash
      FROM conversations WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    pre = conversation;
    await sql`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${POLICY_ID}, 1, ${String(conversation.project_ref_id)},
        ${"{}"}::jsonb, ${Buffer.alloc(32, 0xb1)}, ${NOW}::timestamptz
      )`;

    committer = await enrollOverHttp();
    target = await enrollOverHttp();

    // The committer joins the conversation at the genesis Commit; the
    // target gets its role credential and eligibility grant.
    for (const [device, credentialByte] of [
      [committer, 0xb2],
      [target, 0xb3],
    ] as const) {
      await sql`
        INSERT INTO role_credentials (
          credential_id, conversation_id, installation_id, account_id,
          policy_id, policy_revision, role, credential_public,
          credential_fingerprint, issued_at, expires_at, revocation_version,
          state
        ) VALUES (
          ${deviceCredentialId(credentialByte)}, ${LAB_CONVERSATION_ID},
          ${device.installationId}, ${device.accountId}, ${POLICY_ID}, 1,
          'customer', ${Buffer.alloc(32, credentialByte)},
          ${Buffer.alloc(32, credentialByte)}, ${NOW}::timestamptz,
          ${NOW}::timestamptz + interval '30 days', 1, 'active'
        )`;
    }
    await sql`
      INSERT INTO memberships (
        conversation_id, installation_id, account_id, credential_id, role,
        delivery_purpose, bootstrap_mode, joined_position, joined_at
      ) VALUES (
        ${LAB_CONVERSATION_ID}, ${committer.installationId},
        ${committer.accountId}, ${deviceCredentialId(0xb2)}, 'customer',
        'purchase_support', 'welcome', 1, ${NOW}::timestamptz
      )`;
  });

  afterAll(async () => {
    await sql.begin(async (tx) => {
      await tx`
        DELETE FROM mls_welcomes
        WHERE conversation_id = ${LAB_CONVERSATION_ID}
          AND target_installation_id = ${target.installationId}`;
      await tx`
        DELETE FROM mailbox_entries
        WHERE installation_id IN (${committer.installationId}, ${target.installationId})`;
      await tx`
        DELETE FROM memberships
        WHERE conversation_id = ${LAB_CONVERSATION_ID}
          AND installation_id IN (${committer.installationId}, ${target.installationId})`;
      await tx`
        DELETE FROM conversation_roster_projections
        WHERE conversation_id = ${LAB_CONVERSATION_ID}
          AND installation_id = ${target.installationId}`;
      await tx`
        DELETE FROM conversation_recipient_projections
        WHERE conversation_id = ${LAB_CONVERSATION_ID}
          AND installation_id = ${target.installationId}`;
      await tx`
        UPDATE conversation_roster_projections
        SET roster_version = ${String(pre.roster_version)}
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      await tx`
        UPDATE conversation_recipient_projections
        SET recipient_set_version = ${String(pre.recipient_set_version)}
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      await tx`
        UPDATE conversations SET
          epoch = ${String(pre.epoch)},
          roster_version = ${String(pre.roster_version)},
          roster_hash = ${pre.roster_hash as Buffer},
          recipient_set_version = ${String(pre.recipient_set_version)},
          recipient_set_hash = ${pre.recipient_set_hash as Buffer},
          confirmed_transcript_hash =
            ${pre.confirmed_transcript_hash as Buffer},
          state = 'active'
        WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
      await refreshCustodySnapshotDigest(tx, LAB_CONVERSATION_ID);
    });
    await sql?.end({ timeout: 5 });
  });

  it("refuses unauthenticated and badly-bound requests", async () => {
    const bare = await handlers.readSession(
      new Request(`${BASE}/v1/auth/session`, { method: "GET" }),
    );
    expect(bare.status).toBe(401);

    // A valid token with a proof signed by the WRONG key is refused.
    const crossed = await handlers.readSession(
      new Request(`${BASE}/v1/auth/session`, {
        method: "GET",
        headers: {
          Authorization: `DPoP ${committer.accessToken}`,
          DPoP: dpopProof(target, "GET", `${BASE}/v1/auth/session`, committer.accessToken),
        },
      }),
    );
    expect(crossed.status).toBe(401);
  });

  it("introspects, refreshes, and revokes DPoP sessions", async () => {
    const read = await handlers.readSession(
      authedRequest(committer, "GET", "/v1/auth/session"),
    );
    expect(read.status).toBe(200);
    const session = (await read.json()) as Record<string, never>;
    expect(session).toMatchObject({
      account: { accountId: committer.accountId },
      installation: { installationId: committer.installationId },
    });
    expect(read.headers.get("cache-control")).toBe("no-store, private");

    const refreshUrl = `${BASE}/v1/auth/refresh`;
    const refreshed = await handlers.refreshSession(
      jsonRequest(
        "POST",
        "/v1/auth/refresh",
        { refreshToken: target.refreshToken },
        {
          DPoP: dpopProof(target, "POST", refreshUrl, target.refreshToken),
        },
      ),
    );
    expect(refreshed.status).toBe(200);
    const rotated = (await refreshed.json()) as {
      accessToken: string;
      refreshToken: string;
    };
    expect(rotated.accessToken).not.toBe(target.accessToken);
    target = {
      ...target,
      accessToken: rotated.accessToken,
      refreshToken: rotated.refreshToken,
    };
    // The rotated session authenticates.
    const reread = await handlers.readSession(
      authedRequest(target, "GET", "/v1/auth/session"),
    );
    expect(reread.status).toBe(200);
  });

  it("runs the membership add lifecycle over HTTP", async () => {
    const claimHandle = randomBytes(32).toString("base64url");
    const grantId = "00000000-0000-4000-8000-0000000b0010";
    await sql`
      INSERT INTO eligibility_grants (
        grant_id, project_ref_id, account_id, installation_id, capability,
        policy_id, policy_revision, policy_hash, subject_hash,
        claim_handle_hash, finality_profile_id, finality_profile_revision,
        finality_profile_hash, finality_evidence_digest, source_chain_id,
        source_block, source_block_hash, finality_status, state, issued_at,
        valid_until
      ) VALUES (
        ${grantId}, ${String(pre.project_ref_id)}, ${target.accountId},
        ${target.installationId}, 'purchase-support', ${POLICY_ID}, 1,
        ${Buffer.alloc(32, 0xb1)}, ${Buffer.alloc(32, 0xb4)},
        ${crypto.hmacEligibilityClaimHandle(claimHandle)},
        '00000000-0000-4000-8000-0000000000f1', 1, ${Buffer.alloc(32, 0xf1)},
        ${Buffer.alloc(32, 0xb5)}, ${FIXTURE_CHAIN_ID}, 1,
        ${Buffer.alloc(32, 0xb6)}, 'verified-finalized', 'active',
        ${NOW}::timestamptz, ${NOW}::timestamptz + interval '5 minutes'
      )`;

    const intentResponse = await handlers.createMembershipIntent(
      authedRequest(
        committer,
        "POST",
        `/v1/conversations/${LAB_CONVERSATION_ID}/membership-intents`,
        {
          operation: "add",
          targetInstallationId: target.installationId,
          eligibilityClaimHandle: claimHandle,
        },
      ),
      LAB_CONVERSATION_ID,
    );
    expect(intentResponse.status).toBe(201);
    const intent = (await intentResponse.json()) as Record<string, string>;
    expect(intent.takenKeyPackage).not.toBeNull();

    // The external proposal is the server's act; recorded via the store.
    const proposals = createExternalProposalStore({
      sql,
      signer: {
        signCheckpointDigest: async (_keyId, digest) =>
          signFictionalDeliveryCheckpointDigestForTesting(
            Buffer.from(digest, "base64url"),
          ).toString("base64url"),
      },
    });
    const checkpointId = "00000000-0000-4000-8000-0000000b0011";
    await sql`
      INSERT INTO policy_log_checkpoints (
        checkpoint_id, tree_size, root_hash, signer_key_id, signature,
        witness_key_id, witness_signature, created_at
      ) VALUES (
        ${checkpointId}, 1, ${Buffer.alloc(32, 0xb7)}, 'lab-policy-signer',
        ${Buffer.from("aa", "hex")}, 'lab-witness', ${Buffer.from("bb", "hex")},
        ${NOW}::timestamptz
      )`;
    // The membership suite already published this project's generation-1
    // external sender credential; the wire format keys on the project.
    const [sender] = await sql`
      SELECT external_sender_credential_id FROM external_sender_credentials
      WHERE project_ref_id = ${String(pre.project_ref_id)}
        AND signer_generation = 1 AND lifecycle_state = 'published'`;
    const senderId = String(sender.external_sender_credential_id);
    const proposed = await proposals.recordProposal({
      intentId: intent.intentId,
      publicMessage: Buffer.from("http-add-proposal", "utf8").toString(
        "base64url",
      ),
      authorizationRecordHash: Buffer.alloc(32, 0xb9).toString("base64url"),
      signerExternalSenderCredentialId: senderId,
      transparencyCheckpointId: checkpointId,
    });
    expect(proposed.status).toBe("recorded");

    const commitBytes = Buffer.from("http-mls-commit", "utf8");
    const commitResponse = await handlers.consumeCommit(
      authedRequest(
        committer,
        "POST",
        `/v1/conversations/${LAB_CONVERSATION_ID}/commits`,
        {
          intentId: intent.intentId,
          expectedEpoch: intent.baseEpoch,
          expectedRosterVersion: intent.baseRosterVersion,
          proposedRosterHash: intent.proposedRosterHash,
          mandatoryProposals: [],
          envelopeId: randomUUID(),
          commit: commitBytes.toString("base64url"),
          envelopeSha256: createHash("sha256")
            .update(commitBytes)
            .digest("base64url"),
          baseConfirmedTranscriptHash: (
            pre.confirmed_transcript_hash as Buffer
          ).toString("base64url"),
          resultingConfirmedTranscriptHash: Buffer.alloc(32, 0xba).toString(
            "base64url",
          ),
          resultingEpoch: String(BigInt(intent.baseEpoch) + 1n),
          welcomeByInstallation: [
            {
              installationId: target.installationId,
              welcome: Buffer.from("http-welcome", "utf8").toString(
                "base64url",
              ),
            },
          ],
          targetCredentialId: deviceCredentialId(0xb3),
        },
      ),
      LAB_CONVERSATION_ID,
    );
    expect(commitResponse.status).toBe(200);
    const committed = (await commitResponse.json()) as Record<string, string>;

    const [conversation] = await sql`
      SELECT state, epoch FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(conversation.state)).toBe("active");
    expect(String(conversation.epoch)).toBe(
      String(BigInt(intent.baseEpoch) + 1n),
    );

    // The added member reads its window through the cursor round trip.
    const path = `/v1/conversations/${LAB_CONVERSATION_ID}/events`;
    const firstPage = await handlers.readConversationEvents(
      authedRequest(target, "GET", path),
      LAB_CONVERSATION_ID,
    );
    expect(firstPage.status).toBe(200);
    const first = (await firstPage.json()) as {
      events: { position: string; envelopeClass: string }[];
      nextCursor: string;
      hasMore: boolean;
    };
    // The target joined at the Commit, so its window starts there.
    expect(first.events.length).toBe(1);
    expect(first.events[0].position).toBe(committed.position);
    expect(first.events[0].envelopeClass).toBe("mls_commit");
    expect(first.nextCursor.startsWith("cc1.")).toBe(true);

    const cursorPath = `${path}?cursor=${encodeURIComponent(first.nextCursor)}`;
    const secondPage = await handlers.readConversationEvents(
      authedRequest(target, "GET", cursorPath),
      LAB_CONVERSATION_ID,
    );
    expect(secondPage.status).toBe(200);
    const second = (await secondPage.json()) as {
      events: unknown[];
      hasMore: boolean;
    };
    expect(second.events.length).toBe(0);
    expect(second.hasMore).toBe(false);

    // A tampered cursor is one authenticated rejection.
    const tampered = `${first.nextCursor.slice(0, -2)}aa`;
    const tamperedResponse = await handlers.readConversationEvents(
      authedRequest(
        target,
        "GET",
        `${path}?cursor=${encodeURIComponent(tampered)}`,
      ),
      LAB_CONVERSATION_ID,
    );
    expect(tamperedResponse.status).toBe(400);

    // The committer's window spans from genesis; the page reader joins the
    // page end to the projections the proposal and Commit stores wrote.
    const committerPage = await handlers.readConversationEvents(
      authedRequest(committer, "GET", path),
      LAB_CONVERSATION_ID,
    );
    expect(committerPage.status).toBe(200);
  });
});

function deviceCredentialId(byte: number): string {
  return `00000000-0000-4000-8000-0000000000${byte.toString(16)}`;
}
