import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signNode } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import {
  computeMandatoryProposalSetHash,
  computePolicyHeadHash,
  computeSendGrantSetHash,
  type PolicyHeadSignerPort,
} from "../delivery/policyHeadIssuance";
import {
  createPolicyHeadIssuanceStore,
  type PolicyHeadIssuanceStore,
} from "./policyHeadIssuanceStore";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-14T16:20:45.123Z";

const TENANT_ID = "00000000-0000-4000-8000-0000000f0001";
const PROJECT_REF_ID = "00000000-0000-4000-8000-0000000f0002";
const ACCOUNT_ID = "00000000-0000-4000-8000-0000000f0003";
const INSTALLATION_ID = "00000000-0000-4000-8000-0000000f0004";
const CONVERSATION_ID = "00000000-0000-4000-8000-0000000f0010";
const DIRECTORY_CHECKPOINT_ID = "00000000-0000-4000-8000-0000000f0011";
const POLICY_LOG_CHECKPOINT_ID = "00000000-0000-4000-8000-0000000f0012";
const EXTERNAL_SENDER_ID = "00000000-0000-4000-8000-0000000f0013";
const INTENT_ID = "00000000-0000-4000-8000-0000000f0014";
const PROPOSAL_ID = "00000000-0000-4000-8000-0000000f0015";
const SIGNER_KEY_ID = "fictional-issuance-policy-head-signer";
const REALM_ID = "fictional-issuance-realm";

function fictionalPolicyHeadSigner(): {
  port: PolicyHeadSignerPort;
  rawPublicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return {
    port: Object.freeze({
      signerKeyId: SIGNER_KEY_ID,
      sign: (hash: Buffer) => signNode(null, hash, privateKey),
    }),
    rawPublicKey: Buffer.from(jwk.x, "base64url"),
  };
}

async function seedIssuanceFixture(sql: Sql, rawPublicKey: Buffer): Promise<void> {
  const h = (byte: number) => Buffer.alloc(32, byte);
  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO tenants (tenant_id, tenant_public_id, status, kms_key_ref, created_at, updated_at)
      VALUES (${TENANT_ID}, 'fictional-issuance-tenant', 'active', 'fictional-kms',
              ${NOW}::timestamptz, ${NOW}::timestamptz)`;
    await tx`
      INSERT INTO project_refs (
        project_ref_id, tenant_id, protocol, protocol_version, chain_id,
        projects_contract, project_id, canonical_hash, status, created_at
      ) VALUES (
        ${PROJECT_REF_ID}, ${TENANT_ID}, 'juicebox', '6', 'eip155:8453',
        ${Buffer.alloc(20, 0xf0)}, 3, ${h(0xf0)}, 'active', ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO delivery_realms (realm_id, tenant_id, created_at)
      VALUES (${REALM_ID}, ${TENANT_ID}, ${NOW}::timestamptz)`;
    await tx`
      INSERT INTO archived_release_profiles (
        release_profile_id, delivery_limits_digest, release_trust_root_digest,
        delivery_limits_canonical, created_at
      ) VALUES (
        'fictional-issuance-release.v1', ${h(0xf1)}, ${h(0xf2)}, ${"{}"}::jsonb,
        ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO quota_policies (quota_policy_digest, canonical_document, created_at)
      VALUES (${h(0xf3)}, ${"{}"}::jsonb, ${NOW}::timestamptz)`;
    await tx`
      INSERT INTO conversations (
        conversation_id, project_ref_id, kind, delivery_purpose, generation,
        state, group_id_hash, release_profile_id, delivery_limits_digest,
        release_trust_root_digest, quota_policy_digest, epoch, roster_version,
        roster_hash, external_senders_hash,
        reader_history_retention_policy_hash, confirmed_transcript_hash,
        last_policy_head_sequence, current_policy_head_hash, last_position,
        current_log_head_hash, retention_policy_version, retention_policy,
        created_at, last_activity_at, expires_at, realm_id, project_scope_id,
        tenant_scope_id, etag, recipient_set_version, recipient_set_hash
      ) VALUES (
        ${CONVERSATION_ID}, ${PROJECT_REF_ID}, 'community_room', 'community',
        1, 'active', ${h(0xf4)}, 'fictional-issuance-release.v1', ${h(0xf1)},
        ${h(0xf2)}, ${h(0xf3)}, 0, 0, ${h(0xf5)}, ${h(0xf6)}, ${h(0xf7)},
        ${h(0xf8)}, 0, ${Buffer.alloc(32)}, 0, ${Buffer.alloc(32)}, 1,
        ${"{}"}::jsonb, ${NOW}::timestamptz, ${NOW}::timestamptz,
        ${NOW}::timestamptz + interval '30 days', ${REALM_ID},
        'fictional-issuance-project', 'fictional-issuance-tenant',
        'issuance-etag', 0, ${h(0xf9)}
      )`;
    await tx`
      INSERT INTO accounts (account_id, status, created_at)
      VALUES (${ACCOUNT_ID}, 'active', ${NOW}::timestamptz)`;
    await tx`
      INSERT INTO installations (
        installation_id, account_id, platform, storage_partition_class,
        installation_auth_profile, installation_auth_public_jwk,
        installation_auth_jkt, mls_credential_profile, mls_credential_public,
        mls_credential_fingerprint, status, created_at, last_seen_at
      ) VALUES (
        ${INSTALLATION_ID}, ${ACCOUNT_ID}, 'web', 'top_level',
        'p256-es256-dpop.v1', ${'{"kty":"EC"}'}::jsonb, ${h(0xfa)},
        'mls-credential-ed25519-suite-0x0001.v1', ${h(0xfb)}, ${h(0xfc)},
        'active', ${NOW}::timestamptz, ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO directory_checkpoints (
        checkpoint_id, tree_size, root_hash, signer_key_id, signature, created_at
      ) VALUES (
        ${DIRECTORY_CHECKPOINT_ID}, 1, ${h(0xd1)}, 'fictional-directory-signer',
        ${Buffer.from("aa", "hex")}, ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO policy_log_checkpoints (
        checkpoint_id, tree_size, root_hash, signer_key_id, signature,
        witness_key_id, witness_signature, created_at
      ) VALUES (
        ${POLICY_LOG_CHECKPOINT_ID}, 1, ${h(0xd2)}, 'fictional-policy-signer',
        ${Buffer.from("aa", "hex")}, 'fictional-witness',
        ${Buffer.from("bb", "hex")}, ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO external_sender_credentials (
        external_sender_credential_id, project_ref_id, signer_generation,
        credential_public, credential_fingerprint, not_before, expires_at,
        created_checkpoint_id, witnessed_at, lifecycle_state
      ) VALUES (
        ${EXTERNAL_SENDER_ID}, ${PROJECT_REF_ID}, 1,
        ${Buffer.from("cc", "hex")}, ${h(0xc3)},
        ${NOW}::timestamptz - interval '1 day',
        ${NOW}::timestamptz + interval '30 days',
        ${POLICY_LOG_CHECKPOINT_ID}, ${NOW}::timestamptz, 'published'
      )`;
    await tx`
      INSERT INTO policy_head_signing_keys (
        policy_head_signing_key_id, project_ref_id, public_key,
        key_fingerprint, not_before, expires_at, lifecycle_state,
        policy_checkpoint_id
      ) VALUES (
        ${SIGNER_KEY_ID}, ${PROJECT_REF_ID}, ${rawPublicKey}, ${h(0xc4)},
        ${NOW}::timestamptz - interval '1 day',
        ${NOW}::timestamptz + interval '30 days', 'active',
        ${POLICY_LOG_CHECKPOINT_ID}
      )`;
    await tx`
      INSERT INTO delivery_log_signing_keys (
        key_id, public_key, state, valid_from, valid_until, created_at
      ) VALUES (
        'fictional-issuance-log-key', ${h(0xc5)}, 'active',
        ${NOW}::timestamptz - interval '1 day',
        ${NOW}::timestamptz + interval '30 days', ${NOW}::timestamptz
      )`;
    await tx`
      INSERT INTO envelopes (
        conversation_id, position, envelope_id, envelope_class, sender_type,
        sender_external_credential_id, sender_external_fingerprint,
        sender_signer_generation, epoch, roster_version, content_type,
        envelope_bytes, envelope_sha256, previous_head_hash, leaf_hash,
        head_hash, log_signing_key_id, log_checkpoint_digest,
        log_head_signature, received_at, expires_at
      ) VALUES (
        ${CONVERSATION_ID}, 1, '00000000-0000-4000-8000-0000000f0016',
        'external_proposal', 'entitlement_signer', ${EXTERNAL_SENDER_ID},
        ${h(0xc3)}, 1, 0, 0,
        'application/vnd.juicebox.messaging.mls-public-message',
        ${Buffer.from("proposal", "utf8")}, ${h(0xdd)}, ${Buffer.alloc(32)},
        ${h(0xd5)}, ${h(0xd6)}, 'fictional-issuance-log-key', ${h(0xd7)},
        ${Buffer.alloc(64, 0x99)},
        date_trunc('milliseconds', ${NOW}::timestamptz),
        ${NOW}::timestamptz + interval '365 days'
      )`;
    await tx`
      INSERT INTO membership_intents (
        intent_id, conversation_id, operation, target_installation_id,
        base_epoch, base_roster_version, base_confirmed_transcript_hash,
        proposed_roster_hash, state, created_at, expires_at
      ) VALUES (
        ${INTENT_ID}, ${CONVERSATION_ID}, 'add', ${INSTALLATION_ID}, 0, 0,
        ${h(0xf8)}, ${h(0xfd)}, 'proposed', ${NOW}::timestamptz,
        ${NOW}::timestamptz + interval '1 day'
      )`;
    await tx`
      INSERT INTO external_proposals (
        proposal_id, proposal_hash, intent_id, conversation_id, envelope_id,
        envelope_position, base_epoch, public_message, public_message_sha256,
        authorization_record_hash, signer_external_sender_credential_id,
        signer_external_sender_fingerprint, signer_generation,
        transparency_checkpoint_id, created_at, expires_at
      ) VALUES (
        ${PROPOSAL_ID}, ${h(0xfe)}, ${INTENT_ID}, ${CONVERSATION_ID},
        '00000000-0000-4000-8000-0000000f0016', 1, 0,
        ${Buffer.from("proposal", "utf8")}, ${h(0xdd)}, ${h(0xde)},
        ${EXTERNAL_SENDER_ID}, ${h(0xc3)}, 1, ${POLICY_LOG_CHECKPOINT_ID},
        ${NOW}::timestamptz, ${NOW}::timestamptz + interval '1 day'
      )`;
  });
}

describeStorage("policy-head issuance", () => {
  let sql: Sql;
  let store: PolicyHeadIssuanceStore;
  let rawPublicKey: Buffer;

  const issuanceInput = (overrides: Record<string, unknown> = {}) => ({
    conversationId: CONVERSATION_ID,
    policyId: "00000000-0000-4000-8000-0000000f0020",
    policyRevision: "1",
    policyHash: Buffer.alloc(32, 0xe0).toString("base64url"),
    authorizedQuotaPolicyDigest: Buffer.alloc(32, 0xf3).toString("base64url"),
    evaluatedChainId: "eip155:8453",
    evaluatedBlock: "123456",
    evaluatedBlockHash: Buffer.alloc(32, 0xe1).toString("base64url"),
    activeExternalSenderCredentialId: EXTERNAL_SENDER_ID,
    activeExternalSenderFingerprint: Buffer.alloc(32, 0xc3).toString("base64url"),
    activeSignerGeneration: "1",
    directoryCheckpointId: DIRECTORY_CHECKPOINT_ID,
    policyLogCheckpointId: POLICY_LOG_CHECKPOINT_ID,
    mandatoryProposals: [],
    sendGrantSetMembers: [
      {
        grantEvidenceDigest: Buffer.alloc(32, 0xe2).toString("base64url"),
        grantInclusionEvidenceDigest: Buffer.alloc(32, 0xe3).toString(
          "base64url",
        ),
        installationId: INSTALLATION_ID,
        credentialId: "00000000-0000-4000-8000-0000000f0021",
        role: "member",
      },
    ],
    ...overrides,
  });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 6, onnotice: () => {} });
    const signer = fictionalPolicyHeadSigner();
    rawPublicKey = signer.rawPublicKey;
    await seedIssuanceFixture(sql, rawPublicKey);
    store = createPolicyHeadIssuanceStore({ sql, signer: signer.port });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("issues head one with the zero previous hash and immutable signed bytes", async () => {
    const issued = await store.issuePolicyHead(issuanceInput());
    expect(issued.policyHeadSequence).toBe("1");
    expect(issued.previousPolicyHeadHash).toBe(
      Buffer.alloc(32).toString("base64url"),
    );
    expect(
      Date.parse(issued.expiresAt) - Date.parse(issued.issuedAt),
    ).toBe(5 * 60 * 1_000);

    const [row] = await sql`
      SELECT canonical_signed_body, canonical_signed_body_sha256,
             policy_head_hash, authorized_send_grant_set_hash,
             mandatory_proposal_count
      FROM policy_heads
      WHERE conversation_id = ${CONVERSATION_ID} AND policy_head_sequence = 1`;
    const canonicalBody = Buffer.from(row.canonical_signed_body as Uint8Array);
    expect(canonicalBody.toString("utf8")).toBe(issued.canonicalSignedBody);
    expect(
      computePolicyHeadHash(canonicalBody).equals(
        Buffer.from(row.policy_head_hash as Uint8Array),
      ),
    ).toBe(true);
    const body = JSON.parse(canonicalBody.toString("utf8")) as Record<
      string,
      string
    >;
    expect(body.policyHeadSequence).toBe("1");
    expect(body.deliveryLogPosition).toBe("0");
    expect(body.signerKeyId).toBe(SIGNER_KEY_ID);
    expect(
      Buffer.from(row.authorized_send_grant_set_hash as Uint8Array).equals(
        computeSendGrantSetHash(issuanceInput().sendGrantSetMembers),
      ),
    ).toBe(true);

    const [conversation] = await sql`
      SELECT last_policy_head_sequence, current_policy_head_hash
      FROM conversations WHERE conversation_id = ${CONVERSATION_ID}`;
    expect(String(conversation.last_policy_head_sequence)).toBe("1");
    expect(
      Buffer.from(conversation.current_policy_head_hash as Uint8Array).toString(
        "base64url",
      ),
    ).toBe(issued.policyHeadHash);

    const [members] = await sql`
      SELECT count(*)::int AS total FROM policy_head_send_grant_set_members
      WHERE policy_head_id = ${issued.policyHeadId}`;
    expect(members.total).toBe(1);
  });

  it("chains head two to head one and stays gap-free under concurrency", async () => {
    const first = await store.readNewestPolicyHead(CONVERSATION_ID);
    if (!first) throw new Error("head one missing");
    const second = await store.issuePolicyHead(issuanceInput());
    expect(second.policyHeadSequence).toBe("2");
    expect(second.previousPolicyHeadHash).toBe(first.policyHeadHash);

    const concurrent = await Promise.all([
      store.issuePolicyHead(issuanceInput()),
      store.issuePolicyHead(issuanceInput()),
      store.issuePolicyHead(issuanceInput()),
      store.issuePolicyHead(issuanceInput()),
    ]);
    const sequences = concurrent
      .map((issued) => Number(issued.policyHeadSequence))
      .sort((left, right) => left - right);
    expect(sequences).toEqual([3, 4, 5, 6]);
    const rows = await sql`
      SELECT policy_head_sequence,
             encode(previous_policy_head_hash, 'base64') AS previous,
             encode(policy_head_hash, 'base64') AS head
      FROM policy_heads
      WHERE conversation_id = ${CONVERSATION_ID}
      ORDER BY policy_head_sequence`;
    for (let index = 1; index < rows.length; index += 1) {
      expect(rows[index].previous).toBe(rows[index - 1].head);
    }
  });

  it("binds an ordered mandatory proposal set with real rows", async () => {
    const proposal = {
      proposalId: PROPOSAL_ID,
      proposalHash: Buffer.alloc(32, 0xfe).toString("base64url"),
    };
    const issued = await store.issuePolicyHead(
      issuanceInput({ mandatoryProposals: [proposal] }),
    );
    const [head] = await sql`
      SELECT mandatory_proposal_count, mandatory_proposal_set_hash
      FROM policy_heads WHERE policy_head_id = ${issued.policyHeadId}`;
    expect(Number(head.mandatory_proposal_count)).toBe(1);
    expect(
      Buffer.from(head.mandatory_proposal_set_hash as Uint8Array).equals(
        computeMandatoryProposalSetHash([proposal]),
      ),
    ).toBe(true);
    const [rowCount] = await sql`
      SELECT count(*)::int AS total FROM policy_head_mandatory_proposals
      WHERE policy_head_id = ${issued.policyHeadId}`;
    expect(rowCount.total).toBe(1);
  });

  it("serves the newest head only by re-deriving its immutable bytes", async () => {
    const served = await store.readNewestPolicyHead(CONVERSATION_ID);
    if (!served) throw new Error("no head served");
    expect(Number(served.policyHeadSequence)).toBeGreaterThanOrEqual(7);

    // Mutable conversation columns are not the source of a served head.
    await sql`
      UPDATE conversations SET epoch = 42
      WHERE conversation_id = ${CONVERSATION_ID}`;
    const afterMutation = await store.readNewestPolicyHead(CONVERSATION_ID);
    expect(afterMutation?.canonicalSignedBody).toBe(served.canonicalSignedBody);
    await sql`
      UPDATE conversations SET epoch = 0
      WHERE conversation_id = ${CONVERSATION_ID}`;

    // Tampering the immutable bytes fails closed on read.
    await sql`
      UPDATE policy_heads
      SET canonical_signed_body = ${Buffer.from("tampered", "utf8")}
      WHERE policy_head_id = ${served.policyHeadId}`;
    await expect(
      store.readNewestPolicyHead(CONVERSATION_ID),
    ).rejects.toThrow(/re-derive/);
    const [restore] = await sql`
      SELECT policy_head_id FROM policy_heads
      WHERE policy_head_id = ${served.policyHeadId}`;
    expect(String(restore.policy_head_id)).toBe(served.policyHeadId);
    await sql`
      UPDATE policy_heads
      SET canonical_signed_body =
        ${Buffer.from(served.canonicalSignedBody, "utf8")}
      WHERE policy_head_id = ${served.policyHeadId}`;
    const healed = await store.readNewestPolicyHead(CONVERSATION_ID);
    expect(healed?.policyHeadHash).toBe(served.policyHeadHash);
  });
});
