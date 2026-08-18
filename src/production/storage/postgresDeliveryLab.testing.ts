import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import { sha256Bytes } from "../delivery/hashes";
import { FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW } from "../delivery/fictionalCryptoPorts.testing";
import type { InMemoryDeliveryLabSeed } from "../delivery/inMemoryLabStore.testing";
import type { DeliveryLimits } from "../delivery/limits";
import {
  computeLockedApplicationAppendSnapshotDigest,
  parseApplicationAppendMlsRosterProjections,
  parseApplicationAppendRecipientProjections,
  parseLockedApplicationAppendSnapshot,
} from "../delivery/state";
import { parseRfc3339Millis, parseUint63String } from "../delivery/valueObjects";

const FIXTURE_TENANT_ID = "00000000-0000-4000-8000-000000000901";
const FIXTURE_PROJECT_REF_ID = "00000000-0000-4000-8000-000000000902";
const FIXTURE_RELATIONSHIP_ID = "00000000-0000-4000-8000-000000000903";
const FIXTURE_RELATIONSHIP_SCOPE_ID = "00000000-0000-4000-8000-000000000904";

const KIND_MAP = {
  purchase_support: ["relationship", "purchase_support"],
  announcement: ["relationship", "announcement"],
  community: ["community_room", "community"],
} as const;

/**
 * Seeds the relational fixture graph one fictional delivery conversation
 * needs (tenant, project ref, accounts, installations, relationship,
 * archived release profile, signing key, conversation, usage, mailbox
 * counters, and the authority custody row) so the PostgreSQL append store
 * can run the production delivery service against real schema constraints.
 */
export async function seedPostgresDeliveryLab(
  sql: Sql,
  seedValue: InMemoryDeliveryLabSeed,
  deliveryLimits: DeliveryLimits,
): Promise<void> {
  const snapshot = parseLockedApplicationAppendSnapshot(seedValue.snapshot);
  const now = parseRfc3339Millis(seedValue.now);
  const basePosition = parseUint63String(seedValue.basePosition);
  const signingKeyId = String(seedValue.signingKeyId);
  const signingKeyValidFrom = parseRfc3339Millis(seedValue.signingKeyValidFrom);
  const signingKeyValidUntil = parseRfc3339Millis(seedValue.signingKeyValidUntil);
  const roster = parseApplicationAppendMlsRosterProjections(
    seedValue.mlsRosterProjections,
    parseUint63String(
      String((seedValue.mlsRosterProjections as unknown[]).length),
    ),
  );
  const recipients = parseApplicationAppendRecipientProjections(
    seedValue.recipientProjections,
    parseUint63String(
      String((seedValue.recipientProjections as unknown[]).length),
    ),
  );
  const conversation = snapshot.conversation;
  const [kind, deliveryPurpose] = KIND_MAP[conversation.kind];
  const retentionPolicyHash = Buffer.alloc(32, 0x72);

  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO tenants (tenant_id, tenant_public_id, status, kms_key_ref, created_at, updated_at)
      VALUES (${FIXTURE_TENANT_ID}, 'fictional-tenant-delivery', 'active', 'fictional-kms',
              ${now}::timestamptz, ${now}::timestamptz)`;
    await tx`
      INSERT INTO project_refs (
        project_ref_id, tenant_id, protocol, protocol_version, chain_id,
        projects_contract, project_id, canonical_hash, status, created_at
      ) VALUES (
        ${FIXTURE_PROJECT_REF_ID}, ${FIXTURE_TENANT_ID}, 'juicebox', '6',
        'eip155:8453', ${Buffer.alloc(20, 0x22)}, 2, ${Buffer.alloc(32, 0x71)},
        'active', ${now}::timestamptz
      )`;
    const accountIds = [...new Set(roster.map(({ accountId }) => accountId))];
    for (const accountId of accountIds) {
      await tx`
        INSERT INTO accounts (account_id, status, created_at)
        VALUES (${accountId}, 'active', ${now}::timestamptz)`;
    }
    for (const member of roster) {
      await tx`
        INSERT INTO installations (
          installation_id, account_id, platform, storage_partition_class,
          installation_auth_profile, installation_auth_public_jwk,
          installation_auth_jkt, mls_credential_profile,
          mls_credential_public, mls_credential_fingerprint,
          status, created_at, last_seen_at
        ) VALUES (
          ${member.installationId}, ${member.accountId}, 'web', 'top_level',
          'p256-es256-dpop.v1', ${'{"kty":"EC"}'}::jsonb,
          ${Buffer.from(sha256Bytes(Buffer.from(member.installationId)), "base64url")},
          'mls-credential-ed25519-suite-0x0001.v1',
          ${Buffer.from(member.credentialFingerprint, "base64url")},
          ${Buffer.from(member.credentialFingerprint, "base64url")},
          'active', ${now}::timestamptz, ${now}::timestamptz
        )`;
      await tx`
        INSERT INTO mailbox_counters (installation_id, last_position)
        VALUES (${member.installationId}, 0)`;
    }
    if (kind === "relationship") {
      await tx`
        INSERT INTO relationships (
          relationship_id, relationship_scope_id, project_ref_id,
          customer_account_id, policy_profile_id,
          reader_history_retention_policy,
          reader_history_retention_policy_hash, state, created_at
        ) VALUES (
          ${FIXTURE_RELATIONSHIP_ID}, ${FIXTURE_RELATIONSHIP_SCOPE_ID},
          ${FIXTURE_PROJECT_REF_ID}, ${snapshot.membership.accountId},
          'fictional-policy-profile', ${"{}"}::jsonb, ${retentionPolicyHash},
          'active', ${now}::timestamptz
        )`;
    }
    await tx`
      INSERT INTO archived_release_profiles (
        release_profile_id, delivery_limits_digest, release_trust_root_digest,
        delivery_limits_canonical, created_at
      ) VALUES (
        ${conversation.releaseProfileId},
        ${Buffer.from(conversation.deliveryLimitsDigest, "base64url")},
        ${Buffer.from(conversation.releaseTrustRootDigest, "base64url")},
        ${JSON.stringify(deliveryLimits)}::jsonb, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    await tx`
      INSERT INTO delivery_log_signing_keys (
        key_id, public_key, state, valid_from, valid_until, created_at
      ) VALUES (
        ${signingKeyId}, ${Buffer.from(FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW)},
        'active', ${signingKeyValidFrom}::timestamptz,
        ${signingKeyValidUntil}::timestamptz, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    await tx`
      INSERT INTO conversations (
        conversation_id, relationship_id, relationship_scope_id,
        project_ref_id, kind, delivery_purpose, generation, state,
        group_id_hash, release_profile_id, delivery_limits_digest,
        release_trust_root_digest, quota_policy_digest, epoch,
        roster_version, roster_hash, external_senders_hash,
        reader_history_retention_policy_hash, confirmed_transcript_hash,
        last_policy_head_sequence, current_policy_head_hash, last_position,
        current_log_head_hash, retention_policy_version, retention_policy,
        created_at, last_activity_at, expires_at
      ) VALUES (
        ${conversation.conversationId},
        ${kind === "relationship" ? FIXTURE_RELATIONSHIP_ID : null},
        ${kind === "relationship" ? FIXTURE_RELATIONSHIP_SCOPE_ID : null},
        ${FIXTURE_PROJECT_REF_ID}, ${kind}, ${deliveryPurpose},
        ${conversation.generation}, 'active',
        ${Buffer.from(conversation.groupIdHash, "base64url")},
        ${conversation.releaseProfileId},
        ${Buffer.from(conversation.deliveryLimitsDigest, "base64url")},
        ${Buffer.from(conversation.releaseTrustRootDigest, "base64url")},
        ${Buffer.from(conversation.quotaPolicyDigest, "base64url")},
        ${conversation.epoch}, ${conversation.rosterVersion},
        ${Buffer.from(conversation.rosterHash, "base64url")},
        ${Buffer.alloc(32, 0x73)}, ${retentionPolicyHash},
        ${Buffer.from(conversation.confirmedTranscriptHash, "base64url")},
        ${conversation.currentPolicyHeadSequence},
        ${Buffer.from(conversation.currentPolicyHeadHash, "base64url")},
        ${basePosition},
        ${Buffer.from(conversation.currentLogHeadHash, "base64url")},
        1, ${"{}"}::jsonb, ${now}::timestamptz, ${now}::timestamptz,
        ${now}::timestamptz + interval '365 days'
      )`;
    await tx`
      INSERT INTO conversation_usage (
        conversation_id, envelope_count, envelope_bytes, attachment_bytes, updated_at
      ) VALUES (
        ${conversation.conversationId}, ${snapshot.usage.envelopeCount},
        ${snapshot.usage.envelopeBytes}, ${snapshot.usage.attachmentBytes},
        ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO delivery_conversation_authority (
        conversation_id, conversation_generation, realm_id,
        snapshot_canonical, snapshot_digest, mls_roster_canonical,
        recipient_projections_canonical, active_signing_key_id,
        updated_at
      ) VALUES (
        ${conversation.conversationId}, ${conversation.generation},
        ${conversation.realmId}, ${JSON.stringify(snapshot)}::jsonb,
        ${Buffer.from(
          computeLockedApplicationAppendSnapshotDigest(snapshot),
          "base64url",
        )},
        ${JSON.stringify(roster)}::jsonb, ${JSON.stringify(recipients)}::jsonb,
        ${signingKeyId}, ${now}::timestamptz
      )`;
  });
}
