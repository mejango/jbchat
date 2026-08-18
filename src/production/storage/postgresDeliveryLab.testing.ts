import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import { sha256Bytes } from "../delivery/hashes";
import { FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW } from "../delivery/fictionalCryptoPorts.testing";
import {
  LAB_GENESIS_CHECKPOINT_DIGEST,
  LAB_GENESIS_ENVELOPE_ID,
  LAB_GENESIS_ENVELOPE_SHA256,
  LAB_GENESIS_LEAF_HASH,
  LAB_GENESIS_PREVIOUS_HEAD_HASH,
  LAB_TRANSCRIPT_HASH,
} from "../delivery/fixtures.testing";
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
const FIXTURE_POLICY_ID = "00000000-0000-4000-8000-000000000905";

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
/**
 * Replaces delivery_db_now() with a deterministic lab clock backed by one
 * row, so controlled-time scenarios advance database-authoritative time
 * explicitly instead of via any application clock. Production keeps the
 * migration-pinned clock_timestamp definition.
 */
export async function installDeliveryLabClock(
  sql: Sql,
  now: string,
): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS delivery_lab_clock (
      only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
      now timestamptz NOT NULL
    )`;
  await sql`
    INSERT INTO delivery_lab_clock (now)
    VALUES (${parseRfc3339Millis(now)}::timestamptz)
    ON CONFLICT (only_row) DO UPDATE SET now = excluded.now`;
  await sql.unsafe(
    "CREATE OR REPLACE FUNCTION delivery_db_now() RETURNS timestamptz " +
      "LANGUAGE sql VOLATILE AS $$ " +
      "SELECT date_trunc('milliseconds', (SELECT now FROM delivery_lab_clock)) $$",
  );
}

/** Advances only the database-authoritative lab clock. */
export async function setDeliveryLabClock(sql: Sql, now: string): Promise<void> {
  await sql`
    UPDATE delivery_lab_clock SET now = ${parseRfc3339Millis(now)}::timestamptz`;
}

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
      INSERT INTO delivery_realms (realm_id, tenant_id, created_at)
      VALUES (${conversation.realmId}, ${FIXTURE_TENANT_ID}, ${now}::timestamptz)
      ON CONFLICT DO NOTHING`;
    for (const binding of snapshot.quotaBindings) {
      const subjectId =
        binding.scope === "installation"
          ? snapshot.membership.installationId
          : binding.scope === "account"
            ? snapshot.membership.accountId
            : binding.scope === "project"
              ? conversation.projectScopeId
              : binding.scope === "conversation"
                ? conversation.conversationId
                : conversation.tenantScopeId;
      await tx`
        INSERT INTO quota_scopes (
          scope_type, scope_hash, realm_id, subject_id, created_at
        ) VALUES (
          ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
          ${conversation.realmId}, ${subjectId}, ${now}::timestamptz
        ) ON CONFLICT DO NOTHING`;
    }
    await tx`
      INSERT INTO quota_policies (
        quota_policy_digest, canonical_document, created_at
      ) VALUES (
        ${Buffer.from(conversation.quotaPolicyDigest, "base64url")},
        ${JSON.stringify(snapshot.quotaBindings)}::jsonb, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    for (const quota of snapshot.quotas) {
      await tx`
        INSERT INTO quota_counters (
          scope_type, scope_hash, quota_name, window_started_at,
          window_seconds, operation_count, byte_count,
          reserved_operation_count, reserved_byte_count, row_version,
          updated_at
        ) VALUES (
          ${quota.scope}, ${Buffer.from(quota.scopeHash, "base64url")},
          ${quota.quotaName}, ${quota.windowStartedAt}::timestamptz,
          ${quota.windowSeconds}, ${quota.operationCount}, ${quota.byteCount},
          ${quota.reservedOperationCount}, ${quota.reservedByteCount},
          ${quota.rowVersion}, ${now}::timestamptz
        ) ON CONFLICT DO NOTHING`;
    }
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
        created_at, last_activity_at, expires_at,
        realm_id, project_scope_id, tenant_scope_id,
        etag, recipient_set_version, recipient_set_hash
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
        ${now}::timestamptz + interval '365 days',
        ${conversation.realmId}, ${conversation.projectScopeId},
        ${conversation.tenantScopeId}, ${conversation.etag},
        ${conversation.recipientSetVersion},
        ${Buffer.from(conversation.recipientSetHash, "base64url")}
      )`;
    for (const [ordinal, binding] of snapshot.quotaBindings.entries()) {
      await tx`
        INSERT INTO conversation_quota_bindings (
          conversation_id, quota_policy_digest, scope_type, scope_hash,
          quota_name, window_seconds, operation_limit, byte_limit,
          ordinal, window_started_at
        ) VALUES (
          ${conversation.conversationId},
          ${Buffer.from(conversation.quotaPolicyDigest, "base64url")},
          ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
          ${binding.quotaName}, ${binding.windowSeconds},
          ${binding.operationLimit}, ${binding.byteLimit}, ${ordinal},
          ${binding.windowStartedAt}::timestamptz
        ) ON CONFLICT DO NOTHING`;
    }
    await tx`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${FIXTURE_POLICY_ID}, ${snapshot.sendGrant.policyRevision},
        ${FIXTURE_PROJECT_REF_ID},
        ${JSON.stringify({ policy: "fictional-delivery-policy.v1" })}::jsonb,
        ${Buffer.alloc(32, 0x74)}, ${now}::timestamptz
      )`;
    const membership = snapshot.membership;
    const sendGrant = snapshot.sendGrant;
    await tx`
      INSERT INTO envelopes (
        conversation_id, position, envelope_id, envelope_class, sender_type,
        sender_account_id, sender_installation_id, epoch, roster_version,
        base_confirmed_transcript_hash, resulting_confirmed_transcript_hash,
        content_type, envelope_bytes, envelope_sha256, previous_head_hash,
        leaf_hash, head_hash, log_signing_key_id, log_checkpoint_digest,
        log_head_signature, received_at, expires_at
      ) VALUES (
        ${conversation.conversationId}, 1, ${LAB_GENESIS_ENVELOPE_ID},
        'mls_commit', 'installation', ${membership.accountId},
        ${membership.installationId}, 0, 0,
        ${Buffer.from(LAB_TRANSCRIPT_HASH, "base64url")},
        ${Buffer.from(LAB_TRANSCRIPT_HASH, "base64url")},
        'application/vnd.juicebox.messaging.mls-public-message',
        ${Buffer.from("genesis", "utf8")},
        ${Buffer.from(LAB_GENESIS_ENVELOPE_SHA256, "base64url")},
        ${Buffer.from(LAB_GENESIS_PREVIOUS_HEAD_HASH, "base64url")},
        ${Buffer.from(LAB_GENESIS_LEAF_HASH, "base64url")},
        ${Buffer.from(seedValue.baseHeadHash as string, "base64url")},
        ${signingKeyId},
        ${Buffer.from(LAB_GENESIS_CHECKPOINT_DIGEST, "base64url")},
        ${Buffer.alloc(64, 0x99)}, ${now}::timestamptz,
        ${now}::timestamptz + interval '365 days'
      )`;
    await tx`
      INSERT INTO role_credentials (
        credential_id, conversation_id, installation_id, account_id,
        policy_id, policy_revision, role, credential_public,
        credential_fingerprint, issued_at, expires_at, revocation_version,
        state
      ) VALUES (
        ${membership.credentialId}, ${conversation.conversationId},
        ${membership.installationId}, ${membership.accountId},
        ${FIXTURE_POLICY_ID}, ${sendGrant.policyRevision}, ${sendGrant.role},
        ${Buffer.from(membership.credentialFingerprint, "base64url")},
        ${Buffer.from(membership.credentialFingerprint, "base64url")},
        ${now}::timestamptz, ${membership.credentialExpiresAt}::timestamptz,
        ${membership.credentialRevocationVersion}, ${membership.credentialState}
      )`;
    if (sendGrant.roleCredentialId !== membership.credentialId) {
      await tx`
        INSERT INTO role_credentials (
          credential_id, conversation_id, installation_id, account_id,
          policy_id, policy_revision, role, credential_public,
          credential_fingerprint, issued_at, expires_at, revocation_version,
          state
        ) VALUES (
          ${sendGrant.roleCredentialId}, ${conversation.conversationId},
          ${sendGrant.roleCredentialSubjectInstallationId},
          ${sendGrant.roleCredentialSubjectAccountId}, ${FIXTURE_POLICY_ID},
          ${sendGrant.policyRevision}, ${sendGrant.role},
          ${Buffer.from(sendGrant.roleCredentialFingerprint, "base64url")},
          ${Buffer.from(sendGrant.roleCredentialFingerprint, "base64url")},
          ${sendGrant.roleCredentialValidFrom}::timestamptz,
          ${sendGrant.roleCredentialValidUntil}::timestamptz, 1, 'active'
        )`;
    }
    await tx`
      INSERT INTO memberships (
        conversation_id, installation_id, account_id, credential_id, role,
        delivery_purpose, bootstrap_mode, joined_position, removed_position,
        joined_at, removed_at
      ) VALUES (
        ${conversation.conversationId}, ${membership.installationId},
        ${membership.accountId}, ${membership.credentialId},
        ${sendGrant.role}, ${deliveryPurpose}, 'creator',
        ${membership.joinedPosition}, ${membership.removedPosition},
        ${now}::timestamptz, ${null}
      )`;
    await tx`
      INSERT INTO conversation_send_grants (
        conversation_id, installation_id, credential_id, conversation_kind,
        conversation_generation, role, role_credential_id,
        role_credential_fingerprint, role_credential_subject_account_id,
        role_credential_subject_installation_id, role_credential_valid_from,
        role_credential_valid_until, capability, state, policy_revision,
        policy_head_sequence, policy_head_hash, expires_at,
        grant_evidence_digest, grant_inclusion_evidence_digest
      ) VALUES (
        ${sendGrant.conversationId}, ${sendGrant.installationId},
        ${sendGrant.credentialId}, ${deliveryPurpose},
        ${sendGrant.conversationGeneration}, ${sendGrant.role},
        ${sendGrant.roleCredentialId},
        ${Buffer.from(sendGrant.roleCredentialFingerprint, "base64url")},
        ${sendGrant.roleCredentialSubjectAccountId},
        ${sendGrant.roleCredentialSubjectInstallationId},
        ${sendGrant.roleCredentialValidFrom}::timestamptz,
        ${sendGrant.roleCredentialValidUntil}::timestamptz,
        ${sendGrant.capability}, ${sendGrant.state}, ${sendGrant.policyRevision},
        ${sendGrant.policyHeadSequence},
        ${Buffer.from(sendGrant.policyHeadHash, "base64url")},
        ${sendGrant.expiresAt}::timestamptz,
        ${Buffer.from(sendGrant.grantEvidenceDigest, "base64url")},
        ${Buffer.from(sendGrant.grantInclusionEvidenceDigest, "base64url")}
      )`;
    const head = snapshot.policyHead;
    await tx`
      INSERT INTO delivery_policy_head_anchors (
        conversation_id, policy_head_id, policy_head_sequence,
        policy_head_hash, delivery_log_position, delivery_log_head_hash,
        evaluation_log_position, evaluation_log_head_hash, epoch,
        roster_version, confirmed_transcript_hash, policy_revision,
        signed_body_sha256, signer_key_id, signature_sha256,
        witness_evidence_digest, proof_evidence_digest,
        policy_consistency_evidence_digest, proof_verified_at, issued_at,
        expires_at, witness_state, witness_checkpoint_id,
        witnessed_policy_head_hash, mandatory_proposal_count,
        mandatory_proposal_set_hash, authorized_send_grant_set_hash,
        selected_send_grant_evidence_digest,
        selected_send_grant_inclusion_evidence_digest,
        authorized_quota_policy_digest, prior_policy_head_sequence,
        prior_policy_head_hash, prior_policy_witness_checkpoint_id,
        prior_policy_witness_evidence_digest, updated_at
      ) VALUES (
        ${head.conversationId}, ${head.policyHeadId},
        ${head.policyHeadSequence},
        ${Buffer.from(head.policyHeadHash, "base64url")},
        ${head.deliveryLogPosition},
        ${Buffer.from(head.deliveryLogHeadHash, "base64url")},
        ${head.evaluationLogPosition},
        ${Buffer.from(head.evaluationLogHeadHash, "base64url")},
        ${head.epoch}, ${head.rosterVersion},
        ${Buffer.from(head.confirmedTranscriptHash, "base64url")},
        ${head.policyRevision},
        ${Buffer.from(head.signedBodySha256, "base64url")},
        ${head.signerKeyId}, ${Buffer.from(head.signatureSha256, "base64url")},
        ${Buffer.from(head.witnessEvidenceDigest, "base64url")},
        ${Buffer.from(head.proofEvidenceDigest, "base64url")},
        ${Buffer.from(head.policyConsistencyEvidenceDigest, "base64url")},
        ${head.proofVerifiedAt}::timestamptz, ${head.issuedAt}::timestamptz,
        ${head.expiresAt}::timestamptz, ${head.witnessState},
        ${head.witnessCheckpointId},
        ${
          head.witnessedPolicyHeadHash === null
            ? null
            : Buffer.from(head.witnessedPolicyHeadHash, "base64url")
        },
        ${head.mandatoryProposalCount},
        ${Buffer.from(head.mandatoryProposalSetHash, "base64url")},
        ${Buffer.from(head.authorizedSendGrantSetHash, "base64url")},
        ${Buffer.from(head.selectedSendGrantEvidenceDigest, "base64url")},
        ${Buffer.from(head.selectedSendGrantInclusionEvidenceDigest, "base64url")},
        ${Buffer.from(head.authorizedQuotaPolicyDigest, "base64url")},
        ${head.priorPolicyHeadSequence},
        ${Buffer.from(head.priorPolicyHeadHash, "base64url")},
        ${head.priorPolicyWitnessCheckpointId},
        ${Buffer.from(head.priorPolicyWitnessEvidenceDigest, "base64url")},
        ${now}::timestamptz
      )`;
    for (const [ordinal, member] of roster.entries()) {
      await tx`
        INSERT INTO conversation_roster_projections (
          conversation_id, conversation_generation, roster_version,
          account_id, installation_id, credential_id, credential_fingerprint,
          ordinal
        ) VALUES (
          ${member.conversationId}, ${member.conversationGeneration},
          ${member.rosterVersion}, ${member.accountId},
          ${member.installationId}, ${member.credentialId},
          ${Buffer.from(member.credentialFingerprint, "base64url")}, ${ordinal}
        )`;
    }
    for (const [ordinal, recipient] of recipients.entries()) {
      await tx`
        INSERT INTO conversation_recipient_projections (
          conversation_id, conversation_generation, recipient_set_version,
          account_id, installation_id, credential_id, credential_fingerprint,
          credential_revocation_version, credential_state,
          credential_expires_at, joined_position, removed_position,
          installation_state, ordinal
        ) VALUES (
          ${recipient.conversationId}, ${recipient.conversationGeneration},
          ${recipient.recipientSetVersion}, ${recipient.accountId},
          ${recipient.installationId}, ${recipient.credentialId},
          ${Buffer.from(recipient.credentialFingerprint, "base64url")},
          ${recipient.credentialRevocationVersion}, ${recipient.credentialState},
          ${recipient.credentialExpiresAt}::timestamptz,
          ${recipient.joinedPosition}, ${recipient.removedPosition},
          ${recipient.installationState}, ${ordinal}
        )`;
    }
    await tx`
      INSERT INTO conversation_usage (
        conversation_id, envelope_count, envelope_bytes, attachment_bytes,
        envelope_count_limit, envelope_bytes_limit, attachment_bytes_limit,
        updated_at
      ) VALUES (
        ${conversation.conversationId}, ${snapshot.usage.envelopeCount},
        ${snapshot.usage.envelopeBytes}, ${snapshot.usage.attachmentBytes},
        ${snapshot.usage.envelopeCountLimit},
        ${snapshot.usage.envelopeBytesLimit},
        ${snapshot.usage.attachmentBytesLimit}, ${now}::timestamptz
      )`;
    for (const [index, attachmentValue] of (
      seedValue.attachments as readonly Record<string, unknown>[]
    ).entries()) {
      await tx`
        INSERT INTO attachments (
          attachment_id, conversation_id, owner_installation_id, epoch,
          object_key, ciphertext_bytes, ciphertext_sha256, state,
          created_at, upload_expires_at, finalized_at, expires_at
        ) VALUES (
          ${String(attachmentValue.attachmentId)},
          ${conversation.conversationId}, ${snapshot.membership.installationId},
          ${conversation.epoch}, ${`fictional-object-${index}`},
          ${String(attachmentValue.byteLength)}, ${Buffer.alloc(32, 0x74 + index)},
          'ready', ${now}::timestamptz, ${now}::timestamptz + interval '1 day',
          ${now}::timestamptz, ${now}::timestamptz + interval '365 days'
        )`;
    }
    await tx`
      INSERT INTO delivery_conversation_authority (
        conversation_id, conversation_generation, realm_id, snapshot_digest,
        active_signing_key_id, updated_at
      ) VALUES (
        ${conversation.conversationId}, ${conversation.generation},
        ${conversation.realmId},
        ${Buffer.from(
          computeLockedApplicationAppendSnapshotDigest(snapshot),
          "base64url",
        )},
        ${signingKeyId}, ${now}::timestamptz
      )`;
  });
}
