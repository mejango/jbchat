import { Buffer } from "node:buffer";
import { createHash, createHmac } from "node:crypto";
import type { Sql } from "postgres";

/**
 * Open, on-demand project provisioning. Any project on a
 * manifest-blessed chain gets a project_ref the first time a customer
 * verifiably paid it — derived deterministically from the project's
 * on-chain identity, so the same project always maps to the same ref and
 * a second customer's claim is a no-op. The signed manifest still bounds
 * WHICH chains and contracts are trusted, and the eligibility claim still
 * proves the payment against finalized chain state, so opening this does
 * not weaken the eligibility guarantee.
 */

const SERVICE_TENANT_ID = "00000000-0000-4000-8000-00000000a001";

function deterministicUuid(
  seed: Buffer,
  purpose: string,
  scope: string,
): string {
  const bytes = createHmac("sha256", seed)
    .update(`uuid:${purpose}\n${scope}`, "utf8")
    .digest()
    .subarray(0, 16);
  const value = Buffer.from(bytes);
  value[6] = (value[6] & 0x0f) | 0x40;
  value[8] = (value[8] & 0x3f) | 0x80;
  const hex = value.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function ensureProjectRef(
  sql: Sql,
  provisioningSeed: Buffer,
  now: string,
  input: {
    readonly chainId: number;
    readonly projectId: number;
    readonly projectsContract: string;
  },
): Promise<string> {
  const contractHex = input.projectsContract.toLowerCase().replace(/^0x/, "");
  const scope = `eip155:${input.chainId}:0x${contractHex}:${input.projectId}`;
  const projectRefId = deterministicUuid(provisioningSeed, "project-ref", scope);
  const policyId = deterministicUuid(provisioningSeed, "project-policy", scope);
  const canonicalHash = createHash("sha256")
    .update(
      JSON.stringify({
        protocol: "juicebox",
        version: 6,
        chainId: input.chainId,
        projectsContract: `0x${contractHex}`,
        projectId: input.projectId,
      }),
      "utf8",
    )
    .digest();
  const policyHash = createHash("sha256")
    .update("jbm-open-support-policy/v1", "utf8")
    .update(scope, "utf8")
    .digest();

  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO tenants (
        tenant_id, tenant_public_id, status, kms_key_ref, created_at, updated_at
      ) VALUES (
        ${SERVICE_TENANT_ID}, 'juicebox-messaging', 'active',
        'jbm-service-tenant-v1', ${now}::timestamptz, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    await tx`
      INSERT INTO project_refs (
        project_ref_id, tenant_id, protocol, protocol_version, chain_id,
        projects_contract, project_id, canonical_hash, status, created_at
      ) VALUES (
        ${projectRefId}, ${SERVICE_TENANT_ID}, 'juicebox', '6',
        ${`eip155:${input.chainId}`}, ${Buffer.from(contractHex, "hex")},
        ${String(input.projectId)}, ${canonicalHash}, 'active',
        ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    await tx`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${policyId}, 1, ${projectRefId},
        ${JSON.stringify({
          profile: "telligence-open-support-v1",
          chainId: input.chainId,
          projectId: input.projectId,
        })}::jsonb,
        ${policyHash}, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
  });

  return projectRefId;
}
