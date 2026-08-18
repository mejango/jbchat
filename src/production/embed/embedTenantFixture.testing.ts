import { Buffer } from "node:buffer";
import type { Sql } from "postgres";

export const FIXTURE_EMBED_TENANT_PUBLIC_ID = "fictional-embed-tenant";
export const FIXTURE_EMBED_PARENT_ORIGIN = "https://fictional-host.example";
export const FIXTURE_EMBED_FRAME_AUDIENCE =
  "https://messages.fictional.example/embed";
export const FIXTURE_EMBED_HOST_CLIENT_ID = "fictional-host-production";
const TENANT_ID = "00000000-0000-4000-8000-000000000a01";
const ORIGIN_ID = "00000000-0000-4000-8000-000000000a02";
const ISSUER_CLIENT_ID = "00000000-0000-4000-8000-000000000a03";

/** Seeds one active, ownership-verified fictional embed tenant. */
export async function seedEmbedTenantFixture(
  sql: Sql,
  now: string,
): Promise<void> {
  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO tenants (
        tenant_id, tenant_public_id, status, embed_state, frame_audience,
        embed_theme_hash, top_level_destinations_hash, kms_key_ref,
        created_at, updated_at
      ) VALUES (
        ${TENANT_ID}, ${FIXTURE_EMBED_TENANT_PUBLIC_ID}, 'active', 'active',
        ${FIXTURE_EMBED_FRAME_AUDIENCE}, ${Buffer.alloc(32, 0xa1)},
        ${Buffer.alloc(32, 0xa2)}, 'fictional-kms', ${now}::timestamptz,
        ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO tenant_parent_origins (
        tenant_origin_id, tenant_id, environment, canonical_https_origin,
        ownership_proof_method, ownership_proof_digest, state, verified_at,
        created_at, updated_at
      ) VALUES (
        ${ORIGIN_ID}, ${TENANT_ID}, 'production',
        ${FIXTURE_EMBED_PARENT_ORIGIN}, 'dns', ${Buffer.alloc(32, 0xa3)},
        'active', ${now}::timestamptz, ${now}::timestamptz, ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO embed_issuer_clients (
        embed_issuer_client_id, tenant_id, client_id, oauth_subject_hash,
        mtls_certificate_thumbprint, audience, allowed_purposes, state,
        created_at
      ) VALUES (
        ${ISSUER_CLIENT_ID}, ${TENANT_ID}, ${FIXTURE_EMBED_HOST_CLIENT_ID},
        ${Buffer.alloc(32, 0xa4)}, ${Buffer.alloc(32, 0xa5)},
        ${FIXTURE_EMBED_FRAME_AUDIENCE},
        ${JSON.stringify(["open-secure-messaging"])}::jsonb, 'active',
        ${now}::timestamptz
      )`;
  });
}
