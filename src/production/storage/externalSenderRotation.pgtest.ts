import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { rotateExternalSenderCredentials } from "./externalSenderRotation";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describePg = DATABASE_URL ? describe : describe.skip;

const TENANT_ID = "00000000-0000-4000-8000-00000000c101";
const PROJECT_REF_ID = "00000000-0000-4000-8000-00000000c102";
const POLICY_ID = "00000000-0000-4000-8000-00000000c103";
const CHECKPOINT_ID = "00000000-0000-4000-8000-00000000c104";
const DIRECTORY_ID = "00000000-0000-4000-8000-00000000c105";
const GEN1_ID = "00000000-0000-4000-8000-00000000c111";
const GEN2_ID = "00000000-0000-4000-8000-00000000c112";
const SEED = Buffer.alloc(32, 0xc1);

describePg("external-sender credential aging", () => {
  let sql: postgres.Sql;

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 2, onnotice: () => {} });
    await sql.begin(async (tx) => {
      await tx`
        INSERT INTO tenants (
          tenant_id, tenant_public_id, status, kms_key_ref, created_at,
          updated_at
        ) VALUES (
          ${TENANT_ID}, 'rotation-lab', 'active', 'rotation-lab-kms',
          delivery_db_now(), delivery_db_now()
        ) ON CONFLICT DO NOTHING`;
      await tx`
        INSERT INTO project_refs (
          project_ref_id, tenant_id, protocol, protocol_version, chain_id,
          projects_contract, project_id, canonical_hash, status, created_at
        ) VALUES (
          ${PROJECT_REF_ID}, ${TENANT_ID}, 'juicebox', '6', 'eip155:8453',
          ${Buffer.alloc(20, 0xc2)}, 77, ${Buffer.alloc(32, 0xc3)},
          'active', delivery_db_now()
        ) ON CONFLICT DO NOTHING`;
      await tx`
        INSERT INTO policies (
          policy_id, policy_revision, project_ref_id, canonical_document,
          policy_hash, created_at
        ) VALUES (
          ${POLICY_ID}, 1, ${PROJECT_REF_ID},
          ${JSON.stringify({ profile: "rotation-lab" })}::jsonb,
          ${Buffer.alloc(32, 0xc4)}, delivery_db_now()
        ) ON CONFLICT DO NOTHING`;
      await tx`
        INSERT INTO policy_log_checkpoints (
          checkpoint_id, tree_size, root_hash, signer_key_id, signature,
          witness_key_id, witness_signature, created_at
        ) VALUES (
          ${CHECKPOINT_ID}, 0, ${Buffer.alloc(32)}, 'rotation-lab',
          ${Buffer.alloc(1)}, 'rotation-lab-witness', ${Buffer.alloc(1)},
          delivery_db_now()
        ) ON CONFLICT DO NOTHING`;
      // Generation 1 is already inside its 14-day overlap window;
      // generation 2 has plenty of runway.
      // Lifetimes must satisfy expires_at <= not_before + 90 days.
      for (const [id, generation, age, expiry, fill] of [
        [GEN1_ID, 1, "79 days", "10 days", 0xc5],
        [GEN2_ID, 2, "9 days", "80 days", 0xc6],
      ] as const) {
        const publicRaw = Buffer.alloc(32, fill);
        await tx`
          INSERT INTO external_sender_credentials (
            external_sender_credential_id, project_ref_id, signer_generation,
            credential_public, credential_fingerprint, not_before, expires_at,
            created_checkpoint_id, witnessed_at, lifecycle_state
          ) VALUES (
            ${id}, ${PROJECT_REF_ID}, ${generation}, ${publicRaw},
            ${createHash("sha256")
              .update("jb-msg-external-sender-fingerprint/v1", "utf8")
              .update(publicRaw)
              .digest()},
            delivery_db_now() - ${age}::interval,
            delivery_db_now() + ${expiry}::interval,
            ${CHECKPOINT_ID}, delivery_db_now() - ${age}::interval,
            'published'
          ) ON CONFLICT DO NOTHING`;
      }
      await tx`
        INSERT INTO project_messaging_provisions (
          project_ref_id, policy_id, policy_revision,
          policy_log_checkpoint_id, directory_checkpoint_id,
          current_external_sender_credential_id,
          staged_external_sender_credential_id, policy_head_signing_key_id,
          provisioned_at
        ) VALUES (
          ${PROJECT_REF_ID}, ${POLICY_ID}, 1, ${CHECKPOINT_ID},
          ${DIRECTORY_ID}, ${GEN1_ID}, ${GEN2_ID}, 'rotation-lab-signer',
          delivery_db_now() - interval '79 days'
        ) ON CONFLICT DO NOTHING`;
    });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("promotes the staged generation inside the overlap and stages the next", async () => {
    const report = await rotateExternalSenderCredentials(sql, SEED);
    expect(report.promoted).toBe(1);

    const provision = await sql`
      SELECT current_external_sender_credential_id AS current_id,
             staged_external_sender_credential_id AS staged_id
      FROM project_messaging_provisions
      WHERE project_ref_id = ${PROJECT_REF_ID}`;
    expect(String(provision[0].current_id)).toBe(GEN2_ID);
    expect(String(provision[0].staged_id)).not.toBe(GEN2_ID);

    const staged = await sql`
      SELECT signer_generation, lifecycle_state,
             expires_at > delivery_db_now() + interval '60 days' AS long_lived
      FROM external_sender_credentials
      WHERE external_sender_credential_id =
            ${String(provision[0].staged_id)}`;
    expect(String(staged[0].signer_generation)).toBe("3");
    expect(String(staged[0].lifecycle_state)).toBe("published");
    expect(staged[0].long_lived).toBe(true);

    // The overlap keeps generation 1 published until it actually expires.
    const gen1 = await sql`
      SELECT lifecycle_state FROM external_sender_credentials
      WHERE external_sender_credential_id = ${GEN1_ID}`;
    expect(String(gen1[0].lifecycle_state)).toBe("published");

    // Non-rollback ledger records the newest staged generation.
    const ref = await sql`
      SELECT last_signer_generation FROM project_refs
      WHERE project_ref_id = ${PROJECT_REF_ID}`;
    expect(String(ref[0].last_signer_generation)).toBe("3");
  });

  it("is idempotent once promoted", async () => {
    const report = await rotateExternalSenderCredentials(sql, SEED);
    expect(report.promoted).toBe(0);
  });

  it("retires a published credential past its expiry", async () => {
    await sql`
      UPDATE external_sender_credentials
      SET expires_at = delivery_db_now() - interval '1 hour'
      WHERE external_sender_credential_id = ${GEN1_ID}`;
    const report = await rotateExternalSenderCredentials(sql, SEED);
    expect(report.retired).toBe(1);
    const gen1 = await sql`
      SELECT lifecycle_state, retired_at FROM external_sender_credentials
      WHERE external_sender_credential_id = ${GEN1_ID}`;
    expect(String(gen1[0].lifecycle_state)).toBe("retired");
    expect(gen1[0].retired_at).not.toBeNull();
  });
});
