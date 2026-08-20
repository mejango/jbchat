import { Buffer } from "node:buffer";
import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql, type TransactionSql } from "postgres";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import { createConversationRequestStore } from "./conversationRequestStore";

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
const POLICY_HASH = randomBytes(32);
const PROFILE_HASH = randomBytes(32);

describeStorage("conversation requests", () => {
  let sql: Sql;
  const crypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x7c));
  const store = () =>
    createConversationRequestStore({
      sql,
      hmacEligibilityClaimHandle: crypto.hmacEligibilityClaimHandle,
      now: () => NOW,
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
          ${POLICY_HASH}, ${randomBytes(32)},
          ${crypto.hmacEligibilityClaimHandle(CLAIM_HANDLE)},
          ${FINALITY_PROFILE_ID}, 1, ${PROFILE_HASH}, ${randomBytes(32)},
          'eip155:31337', 100, ${randomBytes(32)}, 'verified-finalized',
          'active', ${NOW}::timestamptz, ${NOW}::timestamptz + interval '1 day'
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
});
