-- Normative source: docs/production/storage-and-retention.md, section 3 DDL excerpt.
-- This file is the excerpt's SQL verbatim with the two inline prose paragraphs
-- removed. The relational gaps those paragraphs and the section-1 blocker list
-- name are closed by the numbered migrations that follow, not by editing this
-- baseline.

CREATE TABLE tenants (
  tenant_id uuid PRIMARY KEY,
  tenant_public_id text NOT NULL UNIQUE,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'deleting')),
  embed_state text NOT NULL DEFAULT 'unconfigured'
    CHECK (embed_state IN ('unconfigured', 'active', 'suspended', 'revoked')),
  frame_audience text,
  embed_theme_hash bytea CHECK (octet_length(embed_theme_hash) = 32),
  top_level_destinations_hash bytea CHECK (octet_length(top_level_destinations_hash) = 32),
  kms_key_ref text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (tenant_public_id = lower(tenant_public_id)),
  CHECK (
    embed_state <> 'active'
    OR (frame_audience IS NOT NULL AND embed_theme_hash IS NOT NULL
      AND top_level_destinations_hash IS NOT NULL)
  )
);

CREATE TABLE tenant_parent_origins (
  tenant_origin_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'preview', 'development')),
  canonical_https_origin text NOT NULL,
  ownership_proof_method text NOT NULL CHECK (ownership_proof_method IN ('dns', 'https')),
  ownership_proof_digest bytea NOT NULL CHECK (octet_length(ownership_proof_digest) = 32),
  state text NOT NULL CHECK (state IN ('pending_verification', 'active', 'suspended', 'revoked')),
  verified_at timestamptz,
  reverify_after timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id, environment, canonical_https_origin),
  UNIQUE (tenant_origin_id, tenant_id),
  CHECK (state <> 'active' OR (verified_at IS NOT NULL AND revoked_at IS NULL)),
  CHECK (state <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE TABLE embed_issuer_clients (
  embed_issuer_client_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  client_id text NOT NULL,
  oauth_subject_hash bytea NOT NULL CHECK (octet_length(oauth_subject_hash) = 32),
  mtls_certificate_thumbprint bytea NOT NULL CHECK (octet_length(mtls_certificate_thumbprint) = 32),
  audience text NOT NULL,
  allowed_purposes jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'suspended', 'revoked')),
  created_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (tenant_id, client_id),
  UNIQUE (tenant_id, oauth_subject_hash, mtls_certificate_thumbprint),
  UNIQUE (embed_issuer_client_id, tenant_id)
);

CREATE TABLE chain_finality_profiles (
  finality_profile_id uuid NOT NULL,
  profile_revision bigint NOT NULL
    CHECK (profile_revision BETWEEN 1 AND 9223372036854775807),
  chain_id text NOT NULL,
  canonical_document jsonb NOT NULL,
  profile_hash bytea NOT NULL CHECK (octet_length(profile_hash) = 32),
  adapter_release_id text NOT NULL,
  ratification_evidence_ref text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'paused', 'retired')),
  effective_at timestamptz NOT NULL,
  retired_at timestamptz,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (finality_profile_id, profile_revision),
  UNIQUE (finality_profile_id, profile_revision, profile_hash),
  UNIQUE (chain_id, profile_hash),
  CHECK (state <> 'retired' OR retired_at IS NOT NULL)
);
CREATE UNIQUE INDEX chain_finality_one_active_idx
  ON chain_finality_profiles(chain_id) WHERE state = 'active';

CREATE TABLE project_refs (
  project_ref_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  protocol text NOT NULL,
  protocol_version text NOT NULL,
  chain_id text NOT NULL,
  projects_contract bytea NOT NULL CHECK (octet_length(projects_contract) = 20),
  project_id numeric(78,0) NOT NULL CHECK (project_id >= 0),
  canonical_hash bytea NOT NULL CHECK (octet_length(canonical_hash) = 32),
  last_signer_generation bigint NOT NULL DEFAULT 0
    CHECK (last_signer_generation BETWEEN 0 AND 9223372036854775807),
  status text NOT NULL CHECK (status IN ('active', 'paused', 'deleted')),
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, canonical_hash),
  UNIQUE (tenant_id, protocol, protocol_version, chain_id, projects_contract, project_id)
);

CREATE TABLE policies (
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  canonical_document jsonb NOT NULL,
  policy_hash bytea NOT NULL CHECK (octet_length(policy_hash) = 32),
  created_at timestamptz NOT NULL,
  superseded_at timestamptz,
  PRIMARY KEY (policy_id, policy_revision),
  UNIQUE (policy_id, policy_hash)
);

CREATE TABLE accounts (
  account_id uuid PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('pending_enrollment', 'active', 'suspended', 'deleting', 'deleted')),
  created_at timestamptz NOT NULL,
  deletion_requested_at timestamptz,
  deleted_at timestamptz
);

CREATE TABLE wallet_links (
  wallet_link_id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  wallet_ref_lookup bytea NOT NULL UNIQUE CHECK (octet_length(wallet_ref_lookup) = 32),
  wallet_ref_ciphertext bytea NOT NULL,
  kms_key_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'revoked', 'deleted')),
  verified_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (wallet_link_id, account_id)
);
CREATE INDEX wallet_links_account_idx ON wallet_links(account_id, status);

CREATE TABLE device_enrollment_attempts (
  enrollment_id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  preallocated_installation_id uuid NOT NULL UNIQUE,
  preallocated_device_credential_id uuid NOT NULL UNIQUE,
  preallocated_wallet_challenge_id uuid UNIQUE,
  preallocated_possession_challenge_id uuid UNIQUE,
  wallet_ref_lookup bytea NOT NULL CHECK (octet_length(wallet_ref_lookup) = 32),
  chain_id text NOT NULL,
  proof_profile text NOT NULL CHECK (proof_profile IN ('siwe-erc4361-v1', 'eip712-device-enrollment-v1')),
  client_id text NOT NULL,
  exact_https_origin text NOT NULL,
  audience text NOT NULL,
  purpose text NOT NULL,
  scope_canonical jsonb NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  installation_kind text NOT NULL CHECK (installation_kind IN ('native')),
  platform text NOT NULL CHECK (platform IN ('web', 'ios', 'android', 'desktop')),
  storage_partition_class text NOT NULL CHECK (storage_partition_class IN ('top_level', 'embedded')),
  embed_tenant_id uuid REFERENCES tenants(tenant_id),
  embed_tenant_origin_id uuid,
  result_handle_hash bytea NOT NULL UNIQUE CHECK (octet_length(result_handle_hash) = 32),
  device_key_binding_canonical jsonb,
  installation_auth_jkt bytea UNIQUE CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_fingerprint bytea UNIQUE CHECK (octet_length(mls_credential_fingerprint) = 32),
  initial_key_package_ref bytea UNIQUE CHECK (octet_length(initial_key_package_ref) = 32),
  initial_key_package_sha256 bytea CHECK (octet_length(initial_key_package_sha256) = 32),
  state text NOT NULL CHECK (state IN (
    'allocated', 'challenges_issued', 'claimed', 'verifying', 'issued',
    'invalid', 'unavailable', 'expired'
  )),
  terminal_reason_code text,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  completed_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '5 minutes'),
  CHECK (
    (storage_partition_class = 'embedded')
      = (embed_tenant_id IS NOT NULL AND embed_tenant_origin_id IS NOT NULL)
  ),
  CHECK (
    state NOT IN ('challenges_issued', 'claimed', 'verifying', 'issued', 'invalid', 'unavailable')
    OR device_key_binding_canonical IS NOT NULL
  ),
  CHECK (
    state IN ('allocated', 'expired')
    OR (preallocated_wallet_challenge_id IS NOT NULL
      AND preallocated_possession_challenge_id IS NOT NULL)
  ),
  CHECK (
    state NOT IN ('claimed', 'verifying', 'issued', 'invalid', 'unavailable')
    OR claimed_at IS NOT NULL
  ),
  CHECK ((state IN ('issued', 'invalid', 'unavailable', 'expired')) = (terminal_reason_code IS NOT NULL)),
  UNIQUE (enrollment_id, preallocated_installation_id, preallocated_device_credential_id),
  UNIQUE (enrollment_id, preallocated_wallet_challenge_id),
  UNIQUE (
    enrollment_id, preallocated_wallet_challenge_id, preallocated_possession_challenge_id
  ),
  UNIQUE (
    enrollment_id, account_id, chain_id, preallocated_installation_id,
    preallocated_device_credential_id, installation_auth_jkt, mls_credential_fingerprint,
    initial_key_package_ref, initial_key_package_sha256
  ),
  FOREIGN KEY (embed_tenant_origin_id, embed_tenant_id)
    REFERENCES tenant_parent_origins(tenant_origin_id, tenant_id)
);
CREATE INDEX device_enrollment_attempts_expiry_idx
  ON device_enrollment_attempts(expires_at, enrollment_id);

CREATE TABLE enrollment_wallet_challenges (
  challenge_id uuid PRIMARY KEY,
  enrollment_id uuid NOT NULL UNIQUE REFERENCES device_enrollment_attempts(enrollment_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  chain_id text NOT NULL,
  installation_id uuid NOT NULL,
  device_credential_id uuid NOT NULL,
  possession_challenge_id uuid NOT NULL UNIQUE,
  profile text NOT NULL CHECK (profile IN ('siwe-erc4361-v1', 'eip712-device-enrollment-v1')),
  protocol_profile text NOT NULL CHECK (protocol_profile = 'device-enrollment.v1'),
  exact_payload_ciphertext bytea NOT NULL,
  payload_digest bytea NOT NULL UNIQUE CHECK (octet_length(payload_digest) = 32),
  nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(nonce_hash) = 32),
  audience text NOT NULL,
  client_id text NOT NULL,
  exact_https_origin text NOT NULL,
  purpose text NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_fingerprint bytea NOT NULL CHECK (octet_length(mls_credential_fingerprint) = 32),
  key_package_ref bytea NOT NULL CHECK (octet_length(key_package_ref) = 32),
  key_package_sha256 bytea NOT NULL CHECK (octet_length(key_package_sha256) = 32),
  issued_at timestamptz NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('issued', 'claimed', 'expired')),
  claimed_by_completion_id uuid UNIQUE,
  claimed_at timestamptz,
  CHECK (expires_at > not_before),
  CHECK ((state = 'claimed') = (claimed_at IS NOT NULL AND claimed_by_completion_id IS NOT NULL)),
  UNIQUE (challenge_id, enrollment_id),
  UNIQUE (challenge_id, enrollment_id, possession_challenge_id),
  UNIQUE (challenge_id, enrollment_id, payload_digest),
  UNIQUE (challenge_id, enrollment_id, payload_digest, not_before, expires_at),
  UNIQUE (challenge_id, enrollment_id, account_id, chain_id, installation_id, device_credential_id),
  FOREIGN KEY (
    enrollment_id, account_id, chain_id, installation_id, device_credential_id,
    installation_auth_jkt, mls_credential_fingerprint, key_package_ref, key_package_sha256
  ) REFERENCES device_enrollment_attempts(
    enrollment_id, account_id, chain_id, preallocated_installation_id,
    preallocated_device_credential_id, installation_auth_jkt, mls_credential_fingerprint,
    initial_key_package_ref, initial_key_package_sha256
  ),
  FOREIGN KEY (enrollment_id, challenge_id, possession_challenge_id)
    REFERENCES device_enrollment_attempts(
      enrollment_id, preallocated_wallet_challenge_id, preallocated_possession_challenge_id
    )
);

CREATE TABLE device_possession_challenges (
  possession_challenge_id uuid PRIMARY KEY,
  enrollment_id uuid NOT NULL UNIQUE REFERENCES device_enrollment_attempts(enrollment_id),
  wallet_challenge_id uuid NOT NULL UNIQUE REFERENCES enrollment_wallet_challenges(challenge_id),
  wallet_payload_digest bytea NOT NULL CHECK (octet_length(wallet_payload_digest) = 32),
  challenge_digest bytea NOT NULL UNIQUE CHECK (octet_length(challenge_digest) = 32),
  server_nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(server_nonce_hash) = 32),
  installation_id uuid NOT NULL,
  device_credential_id uuid NOT NULL,
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_fingerprint bytea NOT NULL CHECK (octet_length(mls_credential_fingerprint) = 32),
  key_package_ref bytea NOT NULL CHECK (octet_length(key_package_ref) = 32),
  key_package_sha256 bytea NOT NULL CHECK (octet_length(key_package_sha256) = 32),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  chain_id text NOT NULL,
  audience text NOT NULL,
  client_id text NOT NULL,
  exact_https_origin text NOT NULL,
  purpose text NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  issued_at timestamptz NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('issued', 'claimed', 'expired')),
  claimed_by_completion_id uuid UNIQUE,
  claimed_at timestamptz,
  CHECK (not_before >= issued_at),
  CHECK (expires_at > not_before),
  CHECK ((state = 'claimed') = (claimed_at IS NOT NULL AND claimed_by_completion_id IS NOT NULL)),
  UNIQUE (possession_challenge_id, enrollment_id, wallet_challenge_id),
  FOREIGN KEY (wallet_challenge_id, enrollment_id, possession_challenge_id)
    REFERENCES enrollment_wallet_challenges(
      challenge_id, enrollment_id, possession_challenge_id
    ),
  FOREIGN KEY (wallet_challenge_id, enrollment_id, wallet_payload_digest)
    REFERENCES enrollment_wallet_challenges(challenge_id, enrollment_id, payload_digest),
  FOREIGN KEY (
    wallet_challenge_id, enrollment_id, wallet_payload_digest, not_before, expires_at
  ) REFERENCES enrollment_wallet_challenges(
    challenge_id, enrollment_id, payload_digest, not_before, expires_at
  ),
  FOREIGN KEY (wallet_challenge_id, enrollment_id, account_id, chain_id, installation_id, device_credential_id)
    REFERENCES enrollment_wallet_challenges(
      challenge_id, enrollment_id, account_id, chain_id, installation_id, device_credential_id
    ),
  FOREIGN KEY (
    enrollment_id, account_id, chain_id, installation_id, device_credential_id,
    installation_auth_jkt, mls_credential_fingerprint, key_package_ref, key_package_sha256
  ) REFERENCES device_enrollment_attempts(
    enrollment_id, account_id, chain_id, preallocated_installation_id,
    preallocated_device_credential_id, installation_auth_jkt, mls_credential_fingerprint,
    initial_key_package_ref, initial_key_package_sha256
  ),
  FOREIGN KEY (enrollment_id, wallet_challenge_id, possession_challenge_id)
    REFERENCES device_enrollment_attempts(
      enrollment_id, preallocated_wallet_challenge_id, preallocated_possession_challenge_id
    )
);

CREATE TABLE enrollment_completion_requests (
  completion_id uuid PRIMARY KEY,
  enrollment_id uuid NOT NULL UNIQUE REFERENCES device_enrollment_attempts(enrollment_id),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  wallet_challenge_id uuid NOT NULL UNIQUE REFERENCES enrollment_wallet_challenges(challenge_id),
  possession_challenge_id uuid NOT NULL UNIQUE
    REFERENCES device_possession_challenges(possession_challenge_id),
  state text NOT NULL CHECK (state IN ('claimed', 'verifying', 'issued', 'invalid', 'unavailable')),
  wallet_verification_method text CHECK (wallet_verification_method IN ('eoa', 'erc1271', 'erc6492')),
  finality_status text CHECK (finality_status IN (
    'verified-finalized', 'pending-finality', 'orphaned', 'unavailable'
  )),
  finality_profile_id uuid,
  finality_profile_revision bigint
    CHECK (finality_profile_revision BETWEEN 1 AND 9223372036854775807),
  finality_profile_hash bytea CHECK (octet_length(finality_profile_hash) = 32),
  finalized_chain_id text,
  finalized_block numeric(78,0) CHECK (finalized_block >= 0),
  finalized_block_hash bytea CHECK (octet_length(finalized_block_hash) = 32),
  provider_quorum_hash bytea CHECK (octet_length(provider_quorum_hash) = 32),
  wallet_evidence_digest bytea CHECK (octet_length(wallet_evidence_digest) = 32),
  possession_evidence_digest bytea CHECK (octet_length(possession_evidence_digest) = 32),
  result_status integer,
  result_body_ciphertext bytea,
  result_body_sha256 bytea CHECK (octet_length(result_body_sha256) = 32),
  result_kms_key_version text,
  result_purge_after timestamptz,
  claimed_at timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE (completion_id, enrollment_id),
  UNIQUE (completion_id, enrollment_id, wallet_challenge_id),
  UNIQUE (completion_id, enrollment_id, wallet_challenge_id, possession_challenge_id),
  CHECK (state NOT IN ('issued', 'invalid', 'unavailable') OR completed_at IS NOT NULL),
  CHECK (
    state NOT IN ('issued', 'invalid', 'unavailable')
    OR (result_status BETWEEN 200 AND 599 AND result_body_ciphertext IS NOT NULL
      AND result_body_sha256 IS NOT NULL AND result_kms_key_version IS NOT NULL
      AND result_purge_after IS NOT NULL)
  ),
  CHECK (
    state <> 'issued'
    OR (wallet_verification_method IS NOT NULL AND finality_status = 'verified-finalized'
      AND finality_profile_id IS NOT NULL
      AND finality_profile_revision IS NOT NULL AND finality_profile_hash IS NOT NULL
      AND finalized_chain_id IS NOT NULL AND finalized_block IS NOT NULL
      AND finalized_block_hash IS NOT NULL AND provider_quorum_hash IS NOT NULL
      AND wallet_evidence_digest IS NOT NULL
      AND possession_evidence_digest IS NOT NULL)
  ),
  FOREIGN KEY (finality_profile_id, finality_profile_revision, finality_profile_hash)
    REFERENCES chain_finality_profiles(finality_profile_id, profile_revision, profile_hash),
  FOREIGN KEY (wallet_challenge_id, enrollment_id)
    REFERENCES enrollment_wallet_challenges(challenge_id, enrollment_id),
  FOREIGN KEY (possession_challenge_id, enrollment_id, wallet_challenge_id)
    REFERENCES device_possession_challenges(
      possession_challenge_id, enrollment_id, wallet_challenge_id
    )
);
ALTER TABLE enrollment_wallet_challenges ADD CONSTRAINT enrollment_wallet_claim_fk
  FOREIGN KEY (claimed_by_completion_id, enrollment_id, challenge_id)
  REFERENCES enrollment_completion_requests(completion_id, enrollment_id, wallet_challenge_id);
ALTER TABLE device_possession_challenges ADD CONSTRAINT device_possession_claim_fk
  FOREIGN KEY (
    claimed_by_completion_id, enrollment_id, wallet_challenge_id, possession_challenge_id
  ) REFERENCES enrollment_completion_requests(
    completion_id, enrollment_id, wallet_challenge_id, possession_challenge_id
  );

CREATE TABLE installations (
  installation_id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_kind text NOT NULL DEFAULT 'native' CHECK (installation_kind = 'native'),
  platform text NOT NULL CHECK (platform IN ('web', 'ios', 'android', 'desktop')),
  storage_partition_class text NOT NULL CHECK (storage_partition_class IN ('top_level', 'embedded')),
  embed_tenant_id uuid REFERENCES tenants(tenant_id),
  embed_tenant_origin_id uuid,
  installation_auth_profile text NOT NULL CHECK (installation_auth_profile = 'p256-es256-dpop.v1'),
  installation_auth_public_jwk jsonb NOT NULL,
  installation_auth_jkt bytea NOT NULL UNIQUE CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_profile text NOT NULL
    CHECK (mls_credential_profile = 'mls-credential-ed25519-suite-0x0001.v1'),
  mls_credential_public bytea NOT NULL CHECK (octet_length(mls_credential_public) = 32),
  mls_credential_fingerprint bytea NOT NULL UNIQUE
    CHECK (octet_length(mls_credential_fingerprint) = 32),
  active_device_credential_id uuid,
  directory_checkpoint_id uuid,
  revocation_version bigint NOT NULL DEFAULT 1
    CHECK (revocation_version BETWEEN 1 AND 9223372036854775807),
  status text NOT NULL CHECK (status IN (
    'pending_verification', 'active', 'suspended', 'revoked', 'superseded', 'deleted'
  )),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  suspended_at timestamptz,
  revoked_at timestamptz,
  superseded_at timestamptz,
  UNIQUE (installation_id, account_id),
  UNIQUE (
    installation_id, account_id, storage_partition_class,
    embed_tenant_id, embed_tenant_origin_id
  ),
  CHECK (
    (storage_partition_class = 'embedded')
      = (embed_tenant_id IS NOT NULL AND embed_tenant_origin_id IS NOT NULL)
  ),
  CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (status <> 'suspended' OR suspended_at IS NOT NULL),
  FOREIGN KEY (embed_tenant_origin_id, embed_tenant_id)
    REFERENCES tenant_parent_origins(tenant_origin_id, tenant_id),
  CHECK (status <> 'superseded' OR superseded_at IS NOT NULL)
);
CREATE INDEX installations_account_active_idx ON installations(account_id, status);

CREATE TABLE directory_checkpoints (
  checkpoint_id uuid PRIMARY KEY,
  tree_size bigint NOT NULL CHECK (tree_size BETWEEN 0 AND 9223372036854775807),
  root_hash bytea NOT NULL CHECK (octet_length(root_hash) = 32),
  previous_checkpoint_id uuid REFERENCES directory_checkpoints(checkpoint_id),
  signer_key_id text NOT NULL,
  signature bytea NOT NULL,
  witnessed_at timestamptz,
  witness_receipt bytea,
  created_at timestamptz NOT NULL
);
ALTER TABLE installations ADD CONSTRAINT installations_directory_checkpoint_fk
  FOREIGN KEY (directory_checkpoint_id) REFERENCES directory_checkpoints(checkpoint_id);

CREATE TABLE device_credentials (
  device_credential_id uuid PRIMARY KEY,
  enrollment_id uuid NOT NULL UNIQUE REFERENCES device_enrollment_attempts(enrollment_id),
  enrollment_completion_id uuid NOT NULL UNIQUE,
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  wallet_link_id uuid NOT NULL,
  chain_id text NOT NULL,
  credential_profile text NOT NULL CHECK (credential_profile = 'device-credential.v1'),
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_fingerprint bytea NOT NULL CHECK (octet_length(mls_credential_fingerprint) = 32),
  initial_key_package_ref bytea NOT NULL CHECK (octet_length(initial_key_package_ref) = 32),
  initial_key_package_sha256 bytea NOT NULL CHECK (octet_length(initial_key_package_sha256) = 32),
  device_key_binding_canonical jsonb NOT NULL,
  device_key_binding_hash bytea NOT NULL CHECK (octet_length(device_key_binding_hash) = 32),
  wallet_evidence_digest bytea NOT NULL CHECK (octet_length(wallet_evidence_digest) = 32),
  possession_evidence_digest bytea NOT NULL CHECK (octet_length(possession_evidence_digest) = 32),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revocation_version bigint NOT NULL
    CHECK (revocation_version BETWEEN 1 AND 9223372036854775807),
  role_binding jsonb CHECK (role_binding IS NULL),
  signer_key_id text NOT NULL,
  canonical_payload_bytes bytea NOT NULL,
  canonical_payload_digest bytea NOT NULL UNIQUE CHECK (octet_length(canonical_payload_digest) = 32),
  signature bytea NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked', 'superseded', 'expired')),
  supersedes_device_credential_id uuid UNIQUE REFERENCES device_credentials(device_credential_id),
  superseded_by_device_credential_id uuid UNIQUE REFERENCES device_credentials(device_credential_id),
  suspended_at timestamptz,
  revoked_at timestamptz,
  superseded_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (device_credential_id, installation_id),
  UNIQUE (device_credential_id, installation_id, canonical_payload_digest),
  UNIQUE (device_credential_id, installation_id, account_id),
  UNIQUE (
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, revocation_version
  ),
  UNIQUE (
    device_credential_id, installation_id,
    mls_credential_fingerprint, revocation_version
  ),
  UNIQUE (
    device_credential_id, installation_id, account_id, installation_auth_jkt,
    mls_credential_fingerprint, revocation_version
  ),
  UNIQUE (
    device_credential_id, installation_id, account_id, installation_auth_jkt,
    mls_credential_fingerprint, initial_key_package_ref, initial_key_package_sha256,
    expires_at, revocation_version
  ),
  UNIQUE (installation_id, revocation_version),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '30 days'),
  CHECK (status <> 'suspended' OR suspended_at IS NOT NULL),
  CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (
    status <> 'superseded'
    OR (superseded_at IS NOT NULL AND superseded_by_device_credential_id IS NOT NULL)
  ),
  FOREIGN KEY (enrollment_completion_id, enrollment_id)
    REFERENCES enrollment_completion_requests(completion_id, enrollment_id),
  FOREIGN KEY (wallet_link_id, account_id)
    REFERENCES wallet_links(wallet_link_id, account_id)
);
CREATE UNIQUE INDEX device_credentials_one_active_installation_idx
  ON device_credentials(installation_id) WHERE status = 'active';

CREATE TABLE device_directory_entries (
  directory_entry_id uuid PRIMARY KEY,
  directory_entry_sequence bigint NOT NULL UNIQUE
    CHECK (directory_entry_sequence BETWEEN 1 AND 9223372036854775807),
  previous_entry_hash bytea NOT NULL CHECK (octet_length(previous_entry_hash) = 32),
  entry_hash bytea NOT NULL UNIQUE CHECK (octet_length(entry_hash) = 32),
  action text NOT NULL CHECK (action IN ('add', 'renew', 'suspend', 'revoke', 'supersede')),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  device_credential_id uuid NOT NULL REFERENCES device_credentials(device_credential_id),
  device_credential_digest bytea NOT NULL CHECK (octet_length(device_credential_digest) = 32),
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  mls_credential_fingerprint bytea NOT NULL CHECK (octet_length(mls_credential_fingerprint) = 32),
  initial_key_package_ref bytea NOT NULL CHECK (octet_length(initial_key_package_ref) = 32),
  initial_key_package_sha256 bytea NOT NULL CHECK (octet_length(initial_key_package_sha256) = 32),
  credential_expires_at timestamptz NOT NULL,
  revocation_version bigint NOT NULL
    CHECK (revocation_version BETWEEN 1 AND 9223372036854775807),
  checkpoint_id uuid NOT NULL REFERENCES directory_checkpoints(checkpoint_id),
  inclusion_proof bytea NOT NULL,
  consistency_proof bytea NOT NULL,
  witness_receipt_digest bytea NOT NULL CHECK (octet_length(witness_receipt_digest) = 32),
  audit_digest bytea NOT NULL CHECK (octet_length(audit_digest) = 32),
  created_at timestamptz NOT NULL,
  UNIQUE (installation_id, revocation_version),
  FOREIGN KEY (device_credential_id, installation_id)
    REFERENCES device_credentials(device_credential_id, installation_id),
  FOREIGN KEY (device_credential_id, installation_id, device_credential_digest)
    REFERENCES device_credentials(
      device_credential_id, installation_id, canonical_payload_digest
    ),
  FOREIGN KEY (
    device_credential_id, installation_id, account_id, installation_auth_jkt,
    mls_credential_fingerprint, initial_key_package_ref, initial_key_package_sha256,
    credential_expires_at, revocation_version
  ) REFERENCES device_credentials(
    device_credential_id, installation_id, account_id, installation_auth_jkt,
    mls_credential_fingerprint, initial_key_package_ref, initial_key_package_sha256,
    expires_at, revocation_version
  )
);
CREATE INDEX device_directory_installation_idx
  ON device_directory_entries(installation_id, directory_entry_sequence DESC);

ALTER TABLE installations ADD CONSTRAINT installations_active_device_credential_fk
  FOREIGN KEY (
    active_device_credential_id, installation_id, account_id,
    installation_auth_jkt, mls_credential_fingerprint, revocation_version
  ) REFERENCES device_credentials(
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, mls_credential_fingerprint, revocation_version
  );

CREATE TABLE policy_log_checkpoints (
  checkpoint_id uuid PRIMARY KEY,
  tree_size bigint NOT NULL CHECK (tree_size BETWEEN 0 AND 9223372036854775807),
  root_hash bytea NOT NULL CHECK (octet_length(root_hash) = 32),
  previous_checkpoint_id uuid REFERENCES policy_log_checkpoints(checkpoint_id),
  signer_key_id text NOT NULL,
  signature bytea NOT NULL,
  witness_key_id text NOT NULL,
  witness_signature bytea NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE external_sender_credentials (
  external_sender_credential_id uuid PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  signer_generation bigint NOT NULL CHECK (signer_generation BETWEEN 1 AND 9223372036854775807),
  signature_domain text NOT NULL DEFAULT 'mls_external_proposal_v1'
    CHECK (signature_domain = 'mls_external_proposal_v1'),
  credential_public bytea NOT NULL,
  credential_fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(credential_fingerprint) = 32),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  witnessed_at timestamptz NOT NULL,
  lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('published', 'retired', 'revoked')),
  revoked_checkpoint_id uuid REFERENCES policy_log_checkpoints(checkpoint_id),
  retired_at timestamptz,
  revoked_at timestamptz,
  CHECK ((revoked_checkpoint_id IS NULL) = (revoked_at IS NULL)),
  CHECK (expires_at > not_before),
  CHECK (expires_at <= not_before + interval '90 days'),
  CHECK ((lifecycle_state = 'retired') = (retired_at IS NOT NULL)),
  CHECK ((lifecycle_state = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (project_ref_id, signer_generation),
  UNIQUE (external_sender_credential_id, signer_generation),
  UNIQUE (external_sender_credential_id, credential_fingerprint, signer_generation)
);

CREATE TABLE policy_head_signing_keys (
  policy_head_signing_key_id text PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  signature_domain text NOT NULL DEFAULT 'policy_head_v1'
    CHECK (signature_domain = 'policy_head_v1'),
  public_key bytea NOT NULL,
  key_fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(key_fingerprint) = 32),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('active', 'retired', 'revoked')),
  policy_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  CHECK (expires_at > not_before)
);

CREATE TABLE step_up_wallet_challenges (
  challenge_id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  device_credential_id uuid NOT NULL,
  device_credential_revocation_version bigint NOT NULL
    CHECK (device_credential_revocation_version BETWEEN 1 AND 9223372036854775807),
  wallet_ref_lookup bytea NOT NULL CHECK (octet_length(wallet_ref_lookup) = 32),
  proof_profile text NOT NULL CHECK (proof_profile IN ('siwe-erc4361-v1', 'eip712-device-enrollment-v1')),
  client_id text NOT NULL,
  exact_https_origin text NOT NULL,
  audience text NOT NULL,
  purpose text NOT NULL,
  scope_canonical jsonb NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(nonce_hash) = 32),
  exact_payload_ciphertext bytea NOT NULL,
  payload_digest bytea NOT NULL UNIQUE CHECK (octet_length(payload_digest) = 32),
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('issued', 'claimed', 'expired')),
  claimed_by_request_id uuid UNIQUE,
  claimed_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '5 minutes'),
  CHECK ((state = 'claimed') = (claimed_at IS NOT NULL AND claimed_by_request_id IS NOT NULL)),
  FOREIGN KEY (
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, device_credential_revocation_version
  ) REFERENCES device_credentials(
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, revocation_version
  )
);
CREATE INDEX step_up_wallet_challenges_expiry_idx
  ON step_up_wallet_challenges(expires_at, challenge_id);

CREATE TABLE auth_sessions (
  session_id uuid PRIMARY KEY,
  token_family_id uuid NOT NULL,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  device_credential_id uuid NOT NULL,
  installation_auth_jkt bytea NOT NULL CHECK (octet_length(installation_auth_jkt) = 32),
  device_credential_revocation_version bigint NOT NULL
    CHECK (device_credential_revocation_version BETWEEN 1 AND 9223372036854775807),
  audience text NOT NULL,
  client_id text NOT NULL,
  exact_https_origin text,
  session_profile text NOT NULL CHECK (session_profile IN (
    'native_dpop', 'browser_dpop', 'cookie_bff', 'embedded_cookie_bff'
  )),
  embed_tenant_id uuid REFERENCES tenants(tenant_id),
  embed_tenant_origin_id uuid,
  installation_partition_class text NOT NULL CHECK (
    installation_partition_class IN ('top_level', 'embedded')
  ),
  access_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(access_token_hash) = 32),
  refresh_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(refresh_token_hash) = 32),
  csrf_token_hash bytea CHECK (octet_length(csrf_token_hash) = 32),
  refresh_generation bigint NOT NULL CHECK (refresh_generation BETWEEN 0 AND 9223372036854775807),
  state text NOT NULL CHECK (state IN ('active', 'rotated', 'revoked', 'expired')),
  created_at timestamptz NOT NULL,
  access_expires_at timestamptz NOT NULL,
  refresh_expires_at timestamptz NOT NULL,
  rotated_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text,
  CHECK (access_expires_at > created_at),
  CHECK (refresh_expires_at >= access_expires_at),
  UNIQUE (session_id, embed_tenant_id, embed_tenant_origin_id),
  CHECK ((session_profile = 'native_dpop') OR exact_https_origin IS NOT NULL),
  CHECK (
    (session_profile IN ('cookie_bff', 'embedded_cookie_bff')) = (csrf_token_hash IS NOT NULL)
  ),
  CHECK (
    (session_profile = 'embedded_cookie_bff')
      = (embed_tenant_id IS NOT NULL AND embed_tenant_origin_id IS NOT NULL)
  ),
  CHECK (
    (session_profile = 'embedded_cookie_bff')
      = (installation_partition_class = 'embedded')
  ),
  CHECK (state <> 'rotated' OR rotated_at IS NOT NULL),
  CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
  FOREIGN KEY (
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, device_credential_revocation_version
  ) REFERENCES device_credentials(
    device_credential_id, installation_id, account_id,
    installation_auth_jkt, revocation_version
  ),
  FOREIGN KEY (embed_tenant_origin_id, embed_tenant_id)
    REFERENCES tenant_parent_origins(tenant_origin_id, tenant_id),
  FOREIGN KEY (installation_id, account_id)
    REFERENCES installations(installation_id, account_id),
  FOREIGN KEY (
    installation_id, account_id, installation_partition_class,
    embed_tenant_id, embed_tenant_origin_id
  ) REFERENCES installations(
    installation_id, account_id, storage_partition_class,
    embed_tenant_id, embed_tenant_origin_id
  )
);
CREATE INDEX auth_sessions_installation_idx
  ON auth_sessions(installation_id, refresh_expires_at);
CREATE INDEX auth_sessions_family_idx ON auth_sessions(token_family_id);
CREATE INDEX auth_sessions_credential_idx
  ON auth_sessions(device_credential_id, state, refresh_expires_at);

CREATE TABLE embed_contexts (
  embed_context_id uuid PRIMARY KEY,
  context_handle_hash bytea NOT NULL UNIQUE CHECK (octet_length(context_handle_hash) = 32),
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  tenant_origin_id uuid NOT NULL,
  embed_issuer_client_id uuid NOT NULL,
  canonical_parent_origin text NOT NULL,
  frame_audience text NOT NULL,
  host_client_id text NOT NULL,
  purpose text NOT NULL,
  action text NOT NULL,
  context_kind text NOT NULL CHECK (context_kind = 'opaque-host-resource.v1'),
  scope_canonical jsonb NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  resource_ref_lookup bytea NOT NULL CHECK (octet_length(resource_ref_lookup) = 32),
  resource_ref_ciphertext bytea NOT NULL,
  resource_ref_kms_key_version text NOT NULL,
  creation_nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(creation_nonce_hash) = 32),
  state text NOT NULL CHECK (state IN ('issued', 'claimed', 'redeemed', 'invalid', 'expired', 'revoked')),
  claimed_by_redemption_id uuid UNIQUE,
  issued_at timestamptz NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  redeemed_at timestamptz,
  revoked_at timestamptz,
  terminal_reason_code text,
  purge_after timestamptz NOT NULL,
  FOREIGN KEY (tenant_origin_id, tenant_id)
    REFERENCES tenant_parent_origins(tenant_origin_id, tenant_id),
  FOREIGN KEY (embed_issuer_client_id, tenant_id)
    REFERENCES embed_issuer_clients(embed_issuer_client_id, tenant_id),
  CHECK (expires_at > not_before),
  CHECK (expires_at <= issued_at + interval '2 minutes'),
  CHECK ((claimed_by_redemption_id IS NULL) = (claimed_at IS NULL)),
  CHECK (state NOT IN ('claimed', 'redeemed', 'invalid') OR claimed_at IS NOT NULL),
  CHECK (state NOT IN ('issued', 'expired') OR claimed_at IS NULL),
  CHECK (state <> 'redeemed' OR redeemed_at IS NOT NULL),
  CHECK (state NOT IN ('issued', 'claimed', 'invalid', 'expired') OR redeemed_at IS NULL),
  CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (state NOT IN ('invalid', 'expired', 'revoked') OR terminal_reason_code IS NOT NULL),
  UNIQUE (
    embed_context_id, tenant_id, tenant_origin_id, embed_issuer_client_id,
    canonical_parent_origin, frame_audience, host_client_id, purpose, action,
    scope_hash, resource_ref_lookup
  )
);
CREATE INDEX embed_contexts_expiry_idx
  ON embed_contexts(expires_at, embed_context_id) WHERE state = 'issued';
CREATE INDEX embed_contexts_origin_live_idx
  ON embed_contexts(tenant_origin_id, state, expires_at)
  WHERE state IN ('issued', 'claimed', 'redeemed');

CREATE TABLE embed_context_redemptions (
  embed_redemption_id uuid PRIMARY KEY,
  embed_context_id uuid NOT NULL UNIQUE REFERENCES embed_contexts(embed_context_id),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  protocol text NOT NULL CHECK (protocol = 'org.juicebox.messaging.embed'),
  protocol_version integer NOT NULL CHECK (protocol_version = 1),
  channel_id_hash bytea NOT NULL UNIQUE CHECK (octet_length(channel_id_hash) = 32),
  bootstrap_nonce_hash bytea NOT NULL CHECK (octet_length(bootstrap_nonce_hash) = 32),
  parent_nonce_hash bytea NOT NULL CHECK (octet_length(parent_nonce_hash) = 32),
  frame_nonce_hash bytea NOT NULL CHECK (octet_length(frame_nonce_hash) = 32),
  state text NOT NULL CHECK (state IN ('claimed', 'redeemed', 'invalid', 'revoked')),
  embed_session_id uuid UNIQUE,
  claimed_at timestamptz NOT NULL,
  completed_at timestamptz,
  terminal_reason_code text,
  purge_after timestamptz NOT NULL,
  CHECK (state = 'claimed' OR completed_at IS NOT NULL),
  CHECK (state <> 'redeemed' OR embed_session_id IS NOT NULL),
  CHECK (state NOT IN ('claimed', 'invalid') OR embed_session_id IS NULL),
  CHECK (state NOT IN ('invalid', 'revoked') OR terminal_reason_code IS NOT NULL),
  UNIQUE (embed_redemption_id, embed_context_id),
  UNIQUE (
    embed_redemption_id, embed_context_id, channel_id_hash, bootstrap_nonce_hash,
    parent_nonce_hash, frame_nonce_hash
  )
);

CREATE TABLE embed_sessions (
  embed_session_id uuid PRIMARY KEY,
  embed_session_token_hash bytea NOT NULL UNIQUE
    CHECK (octet_length(embed_session_token_hash) = 32),
  previous_embed_session_token_hash bytea UNIQUE
    CHECK (octet_length(previous_embed_session_token_hash) = 32),
  token_generation integer NOT NULL CHECK (token_generation IN (1, 2)),
  embed_context_id uuid NOT NULL UNIQUE REFERENCES embed_contexts(embed_context_id),
  embed_redemption_id uuid NOT NULL UNIQUE
    REFERENCES embed_context_redemptions(embed_redemption_id),
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  tenant_origin_id uuid NOT NULL,
  embed_issuer_client_id uuid NOT NULL,
  authenticated_session_id uuid REFERENCES auth_sessions(session_id),
  canonical_parent_origin text NOT NULL,
  frame_audience text NOT NULL,
  host_client_id text NOT NULL,
  purpose text NOT NULL,
  action text NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  resource_ref_lookup bytea NOT NULL CHECK (octet_length(resource_ref_lookup) = 32),
  channel_id_hash bytea NOT NULL UNIQUE CHECK (octet_length(channel_id_hash) = 32),
  bootstrap_nonce_hash bytea NOT NULL CHECK (octet_length(bootstrap_nonce_hash) = 32),
  parent_nonce_hash bytea NOT NULL CHECK (octet_length(parent_nonce_hash) = 32),
  frame_nonce_hash bytea NOT NULL CHECK (octet_length(frame_nonce_hash) = 32),
  cookie_profile text NOT NULL
    CHECK (cookie_profile = '__Host-secure-httponly-samesite-none-partitioned.v1'),
  state text NOT NULL CHECK (state IN ('unauthenticated', 'authenticated', 'revoked', 'expired')),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  authenticated_at timestamptz,
  token_rotated_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text,
  purge_after timestamptz NOT NULL,
  FOREIGN KEY (tenant_origin_id, tenant_id)
    REFERENCES tenant_parent_origins(tenant_origin_id, tenant_id),
  FOREIGN KEY (embed_issuer_client_id, tenant_id)
    REFERENCES embed_issuer_clients(embed_issuer_client_id, tenant_id),
  FOREIGN KEY (authenticated_session_id, tenant_id, tenant_origin_id)
    REFERENCES auth_sessions(session_id, embed_tenant_id, embed_tenant_origin_id),
  FOREIGN KEY (
    embed_context_id, tenant_id, tenant_origin_id, embed_issuer_client_id,
    canonical_parent_origin, frame_audience, host_client_id, purpose, action,
    scope_hash, resource_ref_lookup
  ) REFERENCES embed_contexts(
    embed_context_id, tenant_id, tenant_origin_id, embed_issuer_client_id,
    canonical_parent_origin, frame_audience, host_client_id, purpose, action,
    scope_hash, resource_ref_lookup
  ),
  FOREIGN KEY (
    embed_redemption_id, embed_context_id, channel_id_hash, bootstrap_nonce_hash,
    parent_nonce_hash, frame_nonce_hash
  ) REFERENCES embed_context_redemptions(
    embed_redemption_id, embed_context_id, channel_id_hash, bootstrap_nonce_hash,
    parent_nonce_hash, frame_nonce_hash
  ),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '10 minutes'),
  CHECK (
    state <> 'unauthenticated'
    OR (authenticated_at IS NULL AND authenticated_session_id IS NULL
      AND token_generation = 1 AND previous_embed_session_token_hash IS NULL
      AND token_rotated_at IS NULL)
  ),
  CHECK (
    state <> 'authenticated'
    OR (authenticated_at IS NOT NULL AND authenticated_session_id IS NOT NULL
      AND token_generation = 2 AND previous_embed_session_token_hash IS NOT NULL
      AND token_rotated_at IS NOT NULL)
  ),
  CHECK (state <> 'revoked' OR revoked_at IS NOT NULL)
);
ALTER TABLE embed_contexts ADD CONSTRAINT embed_context_claim_fk
  FOREIGN KEY (claimed_by_redemption_id, embed_context_id)
  REFERENCES embed_context_redemptions(embed_redemption_id, embed_context_id);
ALTER TABLE embed_context_redemptions ADD CONSTRAINT embed_redemption_session_fk
  FOREIGN KEY (embed_session_id)
  REFERENCES embed_sessions(embed_session_id);
CREATE INDEX embed_sessions_origin_live_idx
  ON embed_sessions(tenant_origin_id, state, expires_at)
  WHERE state IN ('unauthenticated', 'authenticated');
CREATE INDEX embed_sessions_auth_session_idx
  ON embed_sessions(authenticated_session_id, state)
  WHERE authenticated_session_id IS NOT NULL;
CREATE INDEX embed_sessions_previous_token_idx
  ON embed_sessions(previous_embed_session_token_hash)
  WHERE previous_embed_session_token_hash IS NOT NULL;

CREATE TABLE key_packages (
  key_package_ref bytea PRIMARY KEY CHECK (octet_length(key_package_ref) = 32),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  device_credential_id uuid NOT NULL,
  device_credential_revocation_version bigint NOT NULL
    CHECK (device_credential_revocation_version BETWEEN 1 AND 9223372036854775807),
  release_profile_id text NOT NULL,
  package_bytes bytea CHECK (package_bytes IS NULL OR octet_length(package_bytes) <= 262144),
  package_sha256 bytea NOT NULL CHECK (octet_length(package_sha256) = 32),
  mls_credential_fingerprint bytea NOT NULL
    CHECK (octet_length(mls_credential_fingerprint) = 32),
  package_kind text NOT NULL DEFAULT 'ordinary-mls-key-package.v1'
    CHECK (package_kind = 'ordinary-mls-key-package.v1'),
  state text NOT NULL CHECK (state IN ('available', 'taken', 'used', 'destroyed', 'revoked')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  taken_at timestamptz,
  taken_by_plan_id uuid,
  taken_by_intent_id uuid,
  used_at timestamptz,
  destroyed_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (key_package_ref, package_sha256, device_credential_id, installation_id),
  FOREIGN KEY (
    device_credential_id, installation_id,
    mls_credential_fingerprint, device_credential_revocation_version
  ) REFERENCES device_credentials(
    device_credential_id, installation_id,
    mls_credential_fingerprint, revocation_version
  ),
  CHECK (
    (taken_at IS NULL AND taken_by_plan_id IS NULL AND taken_by_intent_id IS NULL)
    OR (taken_at IS NOT NULL AND ((taken_by_plan_id IS NOT NULL) <> (taken_by_intent_id IS NOT NULL)))
  ),
  CHECK (
    (state = 'available' AND package_bytes IS NOT NULL AND taken_at IS NULL
      AND used_at IS NULL AND destroyed_at IS NULL AND revoked_at IS NULL)
    OR (state = 'taken' AND package_bytes IS NOT NULL AND taken_at IS NOT NULL
      AND used_at IS NULL AND destroyed_at IS NULL AND revoked_at IS NULL)
    OR (state = 'used' AND package_bytes IS NOT NULL AND taken_at IS NOT NULL
      AND used_at IS NOT NULL AND destroyed_at IS NULL AND revoked_at IS NULL)
    OR (state = 'destroyed' AND package_bytes IS NULL AND taken_at IS NOT NULL
      AND destroyed_at IS NOT NULL AND revoked_at IS NULL)
    OR (state = 'revoked' AND package_bytes IS NULL AND taken_at IS NULL
      AND used_at IS NULL AND destroyed_at IS NOT NULL AND revoked_at IS NOT NULL)
  )
);
CREATE INDEX key_packages_available_idx
  ON key_packages(installation_id, device_credential_id, expires_at)
  WHERE state = 'available' AND taken_at IS NULL;
ALTER TABLE device_credentials ADD CONSTRAINT device_credentials_initial_key_package_fk
  FOREIGN KEY (
    initial_key_package_ref, initial_key_package_sha256, device_credential_id, installation_id
  ) REFERENCES key_packages(
    key_package_ref, package_sha256, device_credential_id, installation_id
  ) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE eligibility_grants (
  grant_id uuid PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  capability text NOT NULL CHECK (
    capability IN ('purchase-support', 'project-staff', 'token-holder', 'item-set-buyer')
  ),
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  policy_hash bytea NOT NULL CHECK (octet_length(policy_hash) = 32),
  subject_hash bytea NOT NULL CHECK (octet_length(subject_hash) = 32),
  claim_handle_hash bytea UNIQUE CHECK (octet_length(claim_handle_hash) = 32),
  finality_profile_id uuid NOT NULL,
  finality_profile_revision bigint NOT NULL
    CHECK (finality_profile_revision BETWEEN 1 AND 9223372036854775807),
  finality_profile_hash bytea NOT NULL CHECK (octet_length(finality_profile_hash) = 32),
  finality_evidence_digest bytea NOT NULL CHECK (octet_length(finality_evidence_digest) = 32),
  source_chain_id text NOT NULL,
  source_block bigint NOT NULL CHECK (source_block BETWEEN 0 AND 9223372036854775807),
  source_block_hash bytea NOT NULL CHECK (octet_length(source_block_hash) = 32),
  finality_status text NOT NULL CHECK (finality_status IN (
    'verified-finalized', 'unavailable', 'orphaned'
  )),
  state text NOT NULL CHECK (state IN ('active', 'suspended', 'revoked', 'expired')),
  issued_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  suspended_at timestamptz,
  revoked_at timestamptz,
  CHECK (state <> 'active' OR finality_status = 'verified-finalized'),
  CHECK (state <> 'suspended' OR (suspended_at IS NOT NULL AND finality_status = 'unavailable')),
  CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (finality_status <> 'orphaned' OR state = 'revoked'),
  FOREIGN KEY (policy_id, policy_revision) REFERENCES policies(policy_id, policy_revision),
  FOREIGN KEY (finality_profile_id, finality_profile_revision, finality_profile_hash)
    REFERENCES chain_finality_profiles(finality_profile_id, profile_revision, profile_hash)
);
CREATE INDEX eligibility_active_idx
  ON eligibility_grants(account_id, project_ref_id, capability, valid_until)
  WHERE state = 'active';

CREATE TABLE contact_preferences (
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  consent_class text NOT NULL CHECK (consent_class IN ('support', 'transactional', 'community', 'marketing')),
  state text NOT NULL CHECK (state IN ('consented', 'unsubscribed')),
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  changed_at timestamptz NOT NULL,
  PRIMARY KEY (project_ref_id, account_id, consent_class)
);

CREATE TABLE account_blocks (
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  blocked_at timestamptz NOT NULL,
  PRIMARY KEY (project_ref_id, account_id)
);

CREATE TABLE relationships (
  relationship_id uuid PRIMARY KEY,
  relationship_scope_id uuid NOT NULL,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  customer_account_id uuid NOT NULL REFERENCES accounts(account_id),
  policy_profile_id text NOT NULL,
  reader_history_retention_policy jsonb NOT NULL,
  reader_history_retention_policy_hash bytea NOT NULL
    CHECK (octet_length(reader_history_retention_policy_hash) = 32),
  state text NOT NULL CHECK (state IN ('active', 'blocked', 'closed', 'deleting')),
  active_conversation_id uuid,
  created_at timestamptz NOT NULL,
  closed_at timestamptz,
  UNIQUE (project_ref_id, customer_account_id, relationship_scope_id),
  UNIQUE (relationship_id, project_ref_id),
  UNIQUE (relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
);

CREATE TABLE conversation_plans (
  plan_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL UNIQUE,
  relationship_id uuid REFERENCES relationships(relationship_id),
  relationship_scope_id uuid,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  creator_account_id uuid NOT NULL REFERENCES accounts(account_id),
  creator_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  kind text NOT NULL CHECK (kind IN ('relationship', 'community_room')),
  delivery_purpose text NOT NULL
    CHECK (delivery_purpose IN ('purchase_support', 'announcement', 'community')),
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9223372036854775807),
  release_profile_id text NOT NULL,
  delivery_limits_digest bytea NOT NULL CHECK (octet_length(delivery_limits_digest) = 32),
  release_trust_root_digest bytea NOT NULL CHECK (octet_length(release_trust_root_digest) = 32),
  quota_policy_digest bytea NOT NULL CHECK (octet_length(quota_policy_digest) = 32),
  roster_canonical jsonb NOT NULL,
  roster_hash bytea NOT NULL CHECK (octet_length(roster_hash) = 32),
  external_senders_canonical jsonb NOT NULL,
  external_senders_hash bytea NOT NULL CHECK (octet_length(external_senders_hash) = 32),
  reader_history_retention_policy_hash bytea NOT NULL
    CHECK (octet_length(reader_history_retention_policy_hash) = 32),
  plan_version bigint NOT NULL CHECK (plan_version BETWEEN 1 AND 9223372036854775807),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  supersedes_conversation_id uuid,
  migration_reason text CHECK (migration_reason IN ('external_sender_rotation', 'crypto_profile', 'policy_scope')),
  migration_statement_hash bytea CHECK (octet_length(migration_statement_hash) = 32),
  CHECK ((supersedes_conversation_id IS NULL) = (migration_reason IS NULL)),
  CHECK ((supersedes_conversation_id IS NULL) = (migration_statement_hash IS NULL)),
  CHECK ((kind = 'relationship') = (relationship_id IS NOT NULL)),
  CHECK ((kind = 'relationship') = (relationship_scope_id IS NOT NULL)),
  CHECK (
    (kind = 'relationship' AND delivery_purpose IN ('purchase_support', 'announcement'))
    OR (kind = 'community_room' AND delivery_purpose = 'community')
  ),
  FOREIGN KEY (relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
    REFERENCES relationships(relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
);
CREATE INDEX conversation_plans_expiry_idx ON conversation_plans(expires_at);
ALTER TABLE key_packages ADD CONSTRAINT key_packages_taken_plan_fk
  FOREIGN KEY (taken_by_plan_id) REFERENCES conversation_plans(plan_id);


CREATE TABLE conversations (
  conversation_id uuid PRIMARY KEY,
  relationship_id uuid REFERENCES relationships(relationship_id),
  relationship_scope_id uuid,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  kind text NOT NULL CHECK (kind IN ('relationship', 'community_room')),
  delivery_purpose text NOT NULL
    CHECK (delivery_purpose IN ('purchase_support', 'announcement', 'community')),
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9223372036854775807),
  state text NOT NULL CHECK (state IN (
    'provisioning', 'active', 'membership_pending', 'suspended', 'closing', 'closed',
    'retention_expired', 'purged'
  )),
  group_id_hash bytea NOT NULL UNIQUE CHECK (octet_length(group_id_hash) = 32),
  release_profile_id text NOT NULL,
  delivery_limits_digest bytea NOT NULL CHECK (octet_length(delivery_limits_digest) = 32),
  release_trust_root_digest bytea NOT NULL CHECK (octet_length(release_trust_root_digest) = 32),
  quota_policy_digest bytea NOT NULL CHECK (octet_length(quota_policy_digest) = 32),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  roster_version bigint NOT NULL CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  roster_hash bytea NOT NULL CHECK (octet_length(roster_hash) = 32),
  external_senders_hash bytea NOT NULL CHECK (octet_length(external_senders_hash) = 32),
  reader_history_retention_policy_hash bytea NOT NULL
    CHECK (octet_length(reader_history_retention_policy_hash) = 32),
  confirmed_transcript_hash bytea NOT NULL CHECK (octet_length(confirmed_transcript_hash) = 32),
  last_policy_head_sequence bigint NOT NULL DEFAULT 0
    CHECK (last_policy_head_sequence BETWEEN 0 AND 9223372036854775807),
  current_policy_head_hash bytea NOT NULL CHECK (octet_length(current_policy_head_hash) = 32),
  last_position bigint NOT NULL DEFAULT 0 CHECK (last_position BETWEEN 0 AND 9223372036854775807),
  current_log_head_hash bytea NOT NULL CHECK (octet_length(current_log_head_hash) = 32),
  retention_policy_version integer NOT NULL,
  retention_policy jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  last_activity_at timestamptz NOT NULL,
  closed_at timestamptz,
  expires_at timestamptz NOT NULL,
  purge_after timestamptz,
  supersedes_conversation_id uuid REFERENCES conversations(conversation_id),
  migration_reason text CHECK (migration_reason IN ('external_sender_rotation', 'crypto_profile', 'policy_scope')),
  migration_statement_hash bytea CHECK (octet_length(migration_statement_hash) = 32),
  CHECK ((supersedes_conversation_id IS NULL) = (migration_reason IS NULL)),
  CHECK ((supersedes_conversation_id IS NULL) = (migration_statement_hash IS NULL)),
  CHECK ((kind = 'relationship') = (relationship_id IS NOT NULL)),
  CHECK ((kind = 'relationship') = (relationship_scope_id IS NOT NULL)),
  CHECK (
    (kind = 'relationship' AND delivery_purpose IN ('purchase_support', 'announcement'))
    OR (kind = 'community_room' AND delivery_purpose = 'community')
  ),
  UNIQUE (relationship_id, generation),
  UNIQUE (conversation_id, relationship_id, relationship_scope_id, reader_history_retention_policy_hash),
  FOREIGN KEY (relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
    REFERENCES relationships(relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
);
ALTER TABLE relationships ADD CONSTRAINT relationships_active_conversation_fk
  FOREIGN KEY (
    active_conversation_id, relationship_id, relationship_scope_id,
    reader_history_retention_policy_hash
  ) REFERENCES conversations(
    conversation_id, relationship_id, relationship_scope_id,
    reader_history_retention_policy_hash
  );
ALTER TABLE conversation_plans ADD CONSTRAINT conversation_plans_supersedes_fk
  FOREIGN KEY (supersedes_conversation_id) REFERENCES conversations(conversation_id);
CREATE INDEX conversations_project_idx
  ON conversations(project_ref_id, state, last_activity_at DESC);
CREATE INDEX conversations_expiry_idx ON conversations(expires_at, conversation_id);
CREATE UNIQUE INDEX conversations_one_live_generation_per_scope_idx
  ON conversations(relationship_id)
  WHERE kind = 'relationship'
    AND state IN ('provisioning', 'active', 'membership_pending', 'suspended');

-- release_profile_id, delivery_limits_digest, release_trust_root_digest, and quota_policy_digest are
-- immutable for the generation and must reference the archived canonical profile registry in the
-- production migration. last_position/current_log_head_hash describe finalized visible envelopes
-- only; an invisible staged append reservation never advances either column.

CREATE TABLE conversation_external_senders (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  slot text NOT NULL CHECK (slot IN ('current', 'staged_next')),
  external_sender_credential_id uuid NOT NULL
    REFERENCES external_sender_credentials(external_sender_credential_id),
  credential_fingerprint bytea NOT NULL CHECK (octet_length(credential_fingerprint) = 32),
  signer_generation bigint NOT NULL CHECK (signer_generation BETWEEN 1 AND 9223372036854775807),
  extension_ordinal integer NOT NULL CHECK (extension_ordinal >= 0),
  created_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  PRIMARY KEY (conversation_id, slot),
  UNIQUE (conversation_id, external_sender_credential_id),
  UNIQUE (conversation_id, extension_ordinal),
  FOREIGN KEY (external_sender_credential_id, credential_fingerprint, signer_generation)
    REFERENCES external_sender_credentials(
      external_sender_credential_id, credential_fingerprint, signer_generation
    )
);

CREATE TABLE signer_security_ledger (
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  security_ledger_sequence bigint NOT NULL
    CHECK (security_ledger_sequence BETWEEN 1 AND 9223372036854775807),
  previous_entry_hash bytea NOT NULL CHECK (octet_length(previous_entry_hash) = 32),
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  action text NOT NULL CHECK (action IN (
    'published', 'authorized', 'retired', 'revoked', 'migration_scheduled',
    'emergency_frozen', 'cutover_verified', 'migration_complete', 'blocked'
  )),
  external_sender_credential_id uuid REFERENCES external_sender_credentials(external_sender_credential_id),
  signer_generation bigint CHECK (signer_generation BETWEEN 1 AND 9223372036854775807),
  policy_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (project_ref_id, security_ledger_sequence),
  UNIQUE (project_ref_id, security_ledger_sequence, entry_hash),
  UNIQUE (project_ref_id, entry_hash),
  FOREIGN KEY (external_sender_credential_id, signer_generation)
    REFERENCES external_sender_credentials(external_sender_credential_id, signer_generation)
);

CREATE TABLE signer_migrations (
  signer_migration_id uuid PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  relationship_id uuid NOT NULL REFERENCES relationships(relationship_id),
  predecessor_conversation_id uuid NOT NULL UNIQUE REFERENCES conversations(conversation_id),
  successor_plan_id uuid UNIQUE REFERENCES conversation_plans(plan_id),
  successor_conversation_id uuid UNIQUE REFERENCES conversations(conversation_id),
  reason text NOT NULL CHECK (reason IN ('scheduled_rotation', 'emergency_compromise')),
  state text NOT NULL CHECK (state IN (
    'scheduled', 'emergency_frozen', 'successor_provisioning', 'successor_ready',
    'cutover_verified', 'complete', 'blocked'
  )),
  predecessor_current_credential_id uuid NOT NULL,
  predecessor_current_fingerprint bytea NOT NULL CHECK (octet_length(predecessor_current_fingerprint) = 32),
  predecessor_current_signer_generation bigint NOT NULL
    CHECK (predecessor_current_signer_generation BETWEEN 1 AND 9223372036854775807),
  predecessor_staged_credential_id uuid NOT NULL,
  predecessor_staged_fingerprint bytea NOT NULL CHECK (octet_length(predecessor_staged_fingerprint) = 32),
  predecessor_staged_signer_generation bigint NOT NULL
    CHECK (predecessor_staged_signer_generation BETWEEN 1 AND 9223372036854775807),
  successor_current_credential_id uuid NOT NULL,
  successor_current_fingerprint bytea NOT NULL CHECK (octet_length(successor_current_fingerprint) = 32),
  successor_current_signer_generation bigint NOT NULL
    CHECK (successor_current_signer_generation BETWEEN 1 AND 9223372036854775807),
  successor_staged_credential_id uuid NOT NULL,
  successor_staged_fingerprint bytea NOT NULL CHECK (octet_length(successor_staged_fingerprint) = 32),
  successor_staged_signer_generation bigint NOT NULL
    CHECK (successor_staged_signer_generation BETWEEN 1 AND 9223372036854775807),
  source_policy_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  target_policy_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  security_ledger_sequence bigint NOT NULL
    CHECK (security_ledger_sequence BETWEEN 1 AND 9223372036854775807),
  security_ledger_entry_hash bytea NOT NULL CHECK (octet_length(security_ledger_entry_hash) = 32),
  successor_not_before timestamptz NOT NULL,
  dual_overlap_ends_at timestamptz NOT NULL,
  last_authorized_signer_expires_at timestamptz NOT NULL,
  deadline_at timestamptz NOT NULL,
  emergency_decided_at timestamptz,
  emergency_frozen_at timestamptz,
  migration_statement_hash bytea CHECK (octet_length(migration_statement_hash) = 32),
  blocked_reason text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  completed_at timestamptz,
  CHECK (dual_overlap_ends_at >= successor_not_before),
  CHECK (dual_overlap_ends_at <= successor_not_before + interval '14 days'),
  CHECK (deadline_at <= last_authorized_signer_expires_at - interval '30 days'),
  CHECK (predecessor_current_credential_id <> predecessor_staged_credential_id),
  CHECK (successor_current_credential_id <> successor_staged_credential_id),
  CHECK (predecessor_staged_signer_generation > predecessor_current_signer_generation),
  CHECK (successor_current_signer_generation > predecessor_current_signer_generation),
  CHECK (successor_staged_signer_generation > successor_current_signer_generation),
  CHECK ((reason = 'emergency_compromise') = (emergency_decided_at IS NOT NULL)),
  CHECK ((reason = 'emergency_compromise') = (emergency_frozen_at IS NOT NULL)),
  CHECK ((emergency_frozen_at IS NULL) OR
    (emergency_frozen_at <= emergency_decided_at + interval '5 minutes')),
  CHECK ((state = 'complete') = (completed_at IS NOT NULL)),
  CHECK ((state = 'blocked') = (blocked_reason IS NOT NULL)),
  CHECK (state NOT IN ('cutover_verified', 'complete') OR successor_conversation_id IS NOT NULL),
  CHECK (state NOT IN ('scheduled', 'emergency_frozen') OR successor_plan_id IS NULL),
  CHECK (state NOT IN ('successor_provisioning', 'successor_ready', 'cutover_verified', 'complete')
    OR successor_plan_id IS NOT NULL),
  FOREIGN KEY (relationship_id, project_ref_id)
    REFERENCES relationships(relationship_id, project_ref_id),
  FOREIGN KEY (project_ref_id, security_ledger_sequence, security_ledger_entry_hash)
    REFERENCES signer_security_ledger(project_ref_id, security_ledger_sequence, entry_hash),
  FOREIGN KEY (
    predecessor_current_credential_id, predecessor_current_fingerprint,
    predecessor_current_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  ),
  FOREIGN KEY (
    predecessor_staged_credential_id, predecessor_staged_fingerprint,
    predecessor_staged_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  ),
  FOREIGN KEY (
    successor_current_credential_id, successor_current_fingerprint,
    successor_current_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  ),
  FOREIGN KEY (
    successor_staged_credential_id, successor_staged_fingerprint,
    successor_staged_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  )
);
CREATE INDEX signer_migrations_deadline_idx ON signer_migrations(deadline_at, state)
  WHERE state NOT IN ('complete', 'blocked');

CREATE TABLE role_credentials (
  credential_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  role text NOT NULL CHECK (role IN (
    'customer', 'project-staff', 'publisher', 'subscriber', 'member', 'moderator'
  )),
  credential_public bytea NOT NULL,
  credential_fingerprint bytea NOT NULL CHECK (octet_length(credential_fingerprint) = 32),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (conversation_id, installation_id, credential_fingerprint),
  UNIQUE (credential_id, conversation_id, installation_id, account_id, role),
  FOREIGN KEY (installation_id, account_id)
    REFERENCES installations(installation_id, account_id),
  FOREIGN KEY (policy_id, policy_revision) REFERENCES policies(policy_id, policy_revision)
);

CREATE TABLE memberships (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  credential_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN (
    'customer', 'project-staff', 'publisher', 'subscriber', 'member', 'moderator'
  )),
  bootstrap_mode text NOT NULL CHECK (bootstrap_mode IN ('creator', 'welcome')),
  joined_position bigint NOT NULL CHECK (joined_position BETWEEN 1 AND 9223372036854775807),
  joined_envelope_class text NOT NULL DEFAULT 'mls_commit'
    CHECK (joined_envelope_class = 'mls_commit'),
  removed_position bigint CHECK (
    removed_position BETWEEN joined_position AND 9223372036854775807
  ),
  joined_at timestamptz NOT NULL,
  removed_at timestamptz,
  PRIMARY KEY (conversation_id, installation_id),
  UNIQUE (conversation_id, installation_id, joined_position, bootstrap_mode),
  CHECK ((removed_position IS NULL) = (removed_at IS NULL)),
  CHECK (bootstrap_mode <> 'creator' OR joined_position = 1),
  FOREIGN KEY (installation_id, account_id)
    REFERENCES installations(installation_id, account_id),
  FOREIGN KEY (credential_id, conversation_id, installation_id, account_id, role)
    REFERENCES role_credentials(
      credential_id, conversation_id, installation_id, account_id, role
    )
);
CREATE INDEX memberships_installation_idx
  ON memberships(installation_id, removed_at, conversation_id);
CREATE INDEX memberships_active_conversation_idx
  ON memberships(conversation_id, role) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX memberships_one_creator_per_conversation_idx
  ON memberships(conversation_id) WHERE bootstrap_mode = 'creator';

CREATE TABLE policy_heads (
  policy_head_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  policy_head_sequence bigint NOT NULL
    CHECK (policy_head_sequence BETWEEN 1 AND 9223372036854775807),
  previous_policy_head_hash bytea NOT NULL CHECK (octet_length(previous_policy_head_hash) = 32),
  policy_head_hash bytea NOT NULL CHECK (octet_length(policy_head_hash) = 32),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  roster_version bigint NOT NULL CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  roster_hash bytea NOT NULL CHECK (octet_length(roster_hash) = 32),
  confirmed_transcript_hash bytea NOT NULL CHECK (octet_length(confirmed_transcript_hash) = 32),
  delivery_log_position bigint NOT NULL
    CHECK (delivery_log_position BETWEEN 0 AND 9223372036854775807),
  delivery_log_head_hash bytea NOT NULL CHECK (octet_length(delivery_log_head_hash) = 32),
  evaluation_log_position bigint NOT NULL
    CHECK (evaluation_log_position BETWEEN delivery_log_position AND 9223372036854775807),
  evaluation_log_head_hash bytea NOT NULL CHECK (octet_length(evaluation_log_head_hash) = 32),
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  policy_hash bytea NOT NULL CHECK (octet_length(policy_hash) = 32),
  mandatory_proposal_count bigint NOT NULL
    CHECK (mandatory_proposal_count BETWEEN 0 AND 100),
  mandatory_proposal_set_hash bytea NOT NULL
    CHECK (octet_length(mandatory_proposal_set_hash) = 32),
  authorized_send_grant_set_hash bytea NOT NULL
    CHECK (octet_length(authorized_send_grant_set_hash) = 32),
  authorized_quota_policy_digest bytea NOT NULL
    CHECK (octet_length(authorized_quota_policy_digest) = 32),
  evaluated_chain_id text NOT NULL,
  evaluated_block bigint NOT NULL CHECK (evaluated_block BETWEEN 0 AND 9223372036854775807),
  evaluated_block_hash bytea NOT NULL CHECK (octet_length(evaluated_block_hash) = 32),
  directory_checkpoint_id uuid NOT NULL REFERENCES directory_checkpoints(checkpoint_id),
  policy_log_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  active_external_sender_credential_id uuid NOT NULL
    REFERENCES external_sender_credentials(external_sender_credential_id),
  active_external_sender_fingerprint bytea NOT NULL
    CHECK (octet_length(active_external_sender_fingerprint) = 32),
  active_signer_generation bigint NOT NULL
    CHECK (active_signer_generation BETWEEN 1 AND 9223372036854775807),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  policy_head_signing_key_id text NOT NULL
    REFERENCES policy_head_signing_keys(policy_head_signing_key_id),
  canonical_signed_body bytea NOT NULL CHECK (octet_length(canonical_signed_body) <= 65536),
  canonical_signed_body_sha256 bytea NOT NULL
    CHECK (octet_length(canonical_signed_body_sha256) = 32),
  signature bytea NOT NULL,
  UNIQUE (conversation_id, policy_head_sequence),
  UNIQUE (conversation_id, policy_head_hash),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '5 minutes'),
  FOREIGN KEY (
    active_external_sender_credential_id, active_external_sender_fingerprint,
    active_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  )
);

CREATE TABLE membership_intents (
  intent_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  operation text NOT NULL CHECK (operation IN ('add', 'remove', 'replace_installation')),
  target_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  requested_by_installation_id uuid REFERENCES installations(installation_id),
  grant_id uuid REFERENCES eligibility_grants(grant_id),
  key_package_ref bytea REFERENCES key_packages(key_package_ref),
  base_epoch bigint NOT NULL CHECK (base_epoch BETWEEN 0 AND 9223372036854775807),
  base_roster_version bigint NOT NULL CHECK (base_roster_version BETWEEN 0 AND 9223372036854775807),
  base_confirmed_transcript_hash bytea NOT NULL CHECK (octet_length(base_confirmed_transcript_hash) = 32),
  proposed_roster_hash bytea NOT NULL CHECK (octet_length(proposed_roster_hash) = 32),
  state text NOT NULL CHECK (state IN ('requested', 'authorized', 'proposed', 'committed', 'cancelled', 'expired', 'superseded')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  committed_envelope_id uuid,
  committed_envelope_position bigint
    CHECK (committed_envelope_position BETWEEN 1 AND 9223372036854775807),
  CHECK ((committed_envelope_id IS NULL) = (committed_envelope_position IS NULL)),
  CHECK ((state = 'committed') = (committed_envelope_id IS NOT NULL)),
  UNIQUE (conversation_id, committed_envelope_id),
  UNIQUE (conversation_id, committed_envelope_position)
);
CREATE UNIQUE INDEX membership_one_pending_target_idx
  ON membership_intents(conversation_id, target_installation_id)
  WHERE state IN ('requested', 'authorized', 'proposed');
ALTER TABLE key_packages ADD CONSTRAINT key_packages_taken_intent_fk
  FOREIGN KEY (taken_by_intent_id) REFERENCES membership_intents(intent_id);

CREATE TABLE external_proposals (
  proposal_id uuid PRIMARY KEY,
  proposal_hash bytea NOT NULL CHECK (octet_length(proposal_hash) = 32),
  intent_id uuid NOT NULL REFERENCES membership_intents(intent_id),
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  envelope_id uuid NOT NULL,
  envelope_position bigint NOT NULL
    CHECK (envelope_position BETWEEN 1 AND 9223372036854775807),
  base_epoch bigint NOT NULL CHECK (base_epoch BETWEEN 0 AND 9223372036854775807),
  public_message bytea NOT NULL CHECK (octet_length(public_message) <= 262144),
  public_message_sha256 bytea NOT NULL CHECK (octet_length(public_message_sha256) = 32),
  authorization_record_hash bytea NOT NULL CHECK (octet_length(authorization_record_hash) = 32),
  signer_external_sender_credential_id uuid NOT NULL
    REFERENCES external_sender_credentials(external_sender_credential_id),
  signer_external_sender_fingerprint bytea NOT NULL
    CHECK (octet_length(signer_external_sender_fingerprint) = 32),
  signer_generation bigint NOT NULL CHECK (signer_generation BETWEEN 1 AND 9223372036854775807),
  transparency_checkpoint_id uuid NOT NULL REFERENCES policy_log_checkpoints(checkpoint_id),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  committed_at timestamptz,
  UNIQUE (intent_id),
  UNIQUE (conversation_id, proposal_hash),
  UNIQUE (conversation_id, envelope_id),
  UNIQUE (conversation_id, envelope_position),
  UNIQUE (proposal_id, proposal_hash),
  FOREIGN KEY (
    signer_external_sender_credential_id, signer_external_sender_fingerprint, signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  )
);

CREATE TABLE policy_head_mandatory_proposals (
  policy_head_id uuid NOT NULL REFERENCES policy_heads(policy_head_id),
  ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 99),
  proposal_id uuid NOT NULL,
  proposal_hash bytea NOT NULL CHECK (octet_length(proposal_hash) = 32),
  PRIMARY KEY (policy_head_id, ordinal),
  UNIQUE (policy_head_id, proposal_id),
  FOREIGN KEY (proposal_id, proposal_hash)
    REFERENCES external_proposals(proposal_id, proposal_hash)
);

CREATE TABLE envelopes (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  envelope_id uuid NOT NULL,
  envelope_class text NOT NULL CHECK (envelope_class IN ('external_proposal', 'mls_commit', 'application')),
  sender_type text NOT NULL CHECK (sender_type IN ('installation', 'entitlement_signer')),
  sender_account_id uuid REFERENCES accounts(account_id),
  sender_installation_id uuid REFERENCES installations(installation_id),
  sender_external_credential_id uuid,
  sender_external_fingerprint bytea
    CHECK (octet_length(sender_external_fingerprint) = 32),
  sender_signer_generation bigint
    CHECK (sender_signer_generation BETWEEN 1 AND 9223372036854775807),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  roster_version bigint NOT NULL CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  base_confirmed_transcript_hash bytea CHECK (octet_length(base_confirmed_transcript_hash) = 32),
  resulting_confirmed_transcript_hash bytea CHECK (octet_length(resulting_confirmed_transcript_hash) = 32),
  policy_head_id uuid REFERENCES policy_heads(policy_head_id),
  content_type text NOT NULL,
  envelope_bytes bytea NOT NULL CHECK (octet_length(envelope_bytes) <= 524288),
  envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
  previous_head_hash bytea NOT NULL CHECK (octet_length(previous_head_hash) = 32),
  leaf_hash bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  log_signing_key_id text NOT NULL CHECK (
    octet_length(log_signing_key_id) BETWEEN 1 AND 64
    AND log_signing_key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
  ),
  log_checkpoint_digest bytea NOT NULL CHECK (octet_length(log_checkpoint_digest) = 32),
  log_head_signature bytea NOT NULL,
  received_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  purge_state text NOT NULL DEFAULT 'live' CHECK (purge_state IN ('live', 'purge_pending')),
  PRIMARY KEY (conversation_id, position),
  UNIQUE (conversation_id, envelope_id),
  UNIQUE (conversation_id, position, envelope_id),
  UNIQUE (conversation_id, position, envelope_class),
  UNIQUE (conversation_id, head_hash),
  CHECK (
    (sender_type = 'installation'
      AND sender_account_id IS NOT NULL AND sender_installation_id IS NOT NULL
      AND sender_external_credential_id IS NULL AND sender_external_fingerprint IS NULL
      AND sender_signer_generation IS NULL)
    OR (sender_type = 'entitlement_signer'
      AND sender_account_id IS NULL AND sender_installation_id IS NULL
      AND sender_external_credential_id IS NOT NULL AND sender_external_fingerprint IS NOT NULL
      AND sender_signer_generation IS NOT NULL)
  ),
  CHECK ((envelope_class = 'external_proposal') = (sender_type = 'entitlement_signer')),
  CHECK (
    (envelope_class = 'application' AND octet_length(envelope_bytes) <= 65536)
    OR (envelope_class = 'external_proposal' AND octet_length(envelope_bytes) <= 262144)
    OR (envelope_class = 'mls_commit' AND octet_length(envelope_bytes) <= 524288)
  ),
  FOREIGN KEY (
    sender_external_credential_id, sender_external_fingerprint, sender_signer_generation
  ) REFERENCES external_sender_credentials(
    external_sender_credential_id, credential_fingerprint, signer_generation
  )
) PARTITION BY HASH (conversation_id);
-- Initial migration creates 64 hash partitions.
CREATE INDEX envelopes_expiry_idx ON envelopes(expires_at, conversation_id, position);
CREATE INDEX envelopes_id_idx ON envelopes(envelope_id);
ALTER TABLE external_proposals ADD CONSTRAINT external_proposals_envelope_fk
  FOREIGN KEY (conversation_id, envelope_position, envelope_id)
  REFERENCES envelopes(conversation_id, position, envelope_id);
ALTER TABLE membership_intents ADD CONSTRAINT membership_intents_commit_envelope_fk
  FOREIGN KEY (conversation_id, committed_envelope_position, committed_envelope_id)
  REFERENCES envelopes(conversation_id, position, envelope_id);
ALTER TABLE memberships ADD CONSTRAINT memberships_join_commit_envelope_fk
  FOREIGN KEY (conversation_id, joined_position, joined_envelope_class)
  REFERENCES envelopes(conversation_id, position, envelope_class)
  DEFERRABLE INITIALLY DEFERRED;

-- All three envelope classes allocate from conversations.last_position. There is no class-specific
-- sequence or cursor; external proposals, public Commits, and private applications share one
-- gap-free order.

CREATE TABLE log_witness_receipts (
  conversation_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  witness_checkpoint_id text NOT NULL,
  witness_tree_size bigint NOT NULL CHECK (witness_tree_size BETWEEN 0 AND 9223372036854775807),
  witness_root_hash bytea NOT NULL CHECK (octet_length(witness_root_hash) = 32),
  witness_key_id text NOT NULL,
  witness_signature bytea NOT NULL,
  witnessed_at timestamptz NOT NULL,
  PRIMARY KEY (conversation_id, position, witness_key_id),
  FOREIGN KEY (conversation_id, position) REFERENCES envelopes(conversation_id, position)
);

CREATE TABLE mls_welcomes (
  conversation_id uuid NOT NULL,
  commit_position bigint NOT NULL CHECK (commit_position BETWEEN 1 AND 9223372036854775807),
  target_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  target_bootstrap_mode text NOT NULL DEFAULT 'welcome'
    CHECK (target_bootstrap_mode = 'welcome'),
  welcome_bytes bytea NOT NULL CHECK (octet_length(welcome_bytes) <= 262144),
  welcome_sha256 bytea NOT NULL CHECK (octet_length(welcome_sha256) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (conversation_id, commit_position, target_installation_id),
  FOREIGN KEY (conversation_id, commit_position) REFERENCES envelopes(conversation_id, position),
  FOREIGN KEY (
    conversation_id, target_installation_id, commit_position, target_bootstrap_mode
  ) REFERENCES memberships(
    conversation_id, installation_id, joined_position, bootstrap_mode
  ) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE mailbox_counters (
  installation_id uuid PRIMARY KEY REFERENCES installations(installation_id),
  last_position bigint NOT NULL DEFAULT 0 CHECK (last_position BETWEEN 0 AND 9223372036854775807),
  retained_floor bigint NOT NULL DEFAULT 1 CHECK (retained_floor BETWEEN 1 AND 9223372036854775807)
);

CREATE TABLE mailbox_entries (
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  mailbox_position bigint NOT NULL CHECK (mailbox_position BETWEEN 1 AND 9223372036854775807),
  conversation_id uuid NOT NULL,
  envelope_position bigint NOT NULL CHECK (envelope_position BETWEEN 1 AND 9223372036854775807),
  envelope_id uuid NOT NULL,
  delivery_class text NOT NULL CHECK (delivery_class IN ('application', 'proposal', 'commit')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  acknowledged_at timestamptz,
  PRIMARY KEY (installation_id, mailbox_position),
  UNIQUE (installation_id, conversation_id, envelope_position),
  FOREIGN KEY (conversation_id, envelope_position, envelope_id)
    REFERENCES envelopes(conversation_id, position, envelope_id)
) PARTITION BY HASH (installation_id);
-- Initial migration creates 64 hash partitions.
CREATE INDEX mailbox_unacked_idx
  ON mailbox_entries(installation_id, mailbox_position) WHERE acknowledged_at IS NULL;
CREATE INDEX mailbox_expiry_idx
  ON mailbox_entries(expires_at, installation_id, mailbox_position);

-- A target Welcome is resolved from mls_welcomes by the same Commit conversation/position and target
-- installation and augments that one mailbox entry. It never creates a second mailbox entry,
-- delivery_class, envelope ID, or transcript/mailbox position.

CREATE TABLE conversation_usage (
  conversation_id uuid PRIMARY KEY REFERENCES conversations(conversation_id),
  envelope_count bigint NOT NULL DEFAULT 0 CHECK (envelope_count BETWEEN 0 AND 9223372036854775807),
  envelope_bytes bigint NOT NULL DEFAULT 0 CHECK (envelope_bytes BETWEEN 0 AND 9223372036854775807),
  attachment_bytes bigint NOT NULL DEFAULT 0 CHECK (attachment_bytes BETWEEN 0 AND 9223372036854775807),
  updated_at timestamptz NOT NULL
);

CREATE TABLE quota_counters (
  scope_type text NOT NULL CHECK (scope_type IN (
    'installation', 'account', 'project', 'conversation', 'campaign', 'tenant', 'ip_prefix'
  )),
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  quota_name text NOT NULL,
  window_started_at timestamptz NOT NULL,
  window_seconds integer NOT NULL CHECK (window_seconds > 0),
  operation_count bigint NOT NULL DEFAULT 0
    CHECK (operation_count BETWEEN 0 AND 9223372036854775807),
  byte_count bigint NOT NULL DEFAULT 0 CHECK (byte_count BETWEEN 0 AND 9223372036854775807),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (scope_type, scope_hash, quota_name, window_started_at)
);
CREATE INDEX quota_counters_expiry_idx
  ON quota_counters(window_started_at, scope_type, quota_name);

CREATE TABLE attachments (
  attachment_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  owner_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  object_key text NOT NULL UNIQUE,
  upload_id_ciphertext bytea,
  ciphertext_bytes bigint NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 9223372036854775807),
  ciphertext_sha256 bytea NOT NULL CHECK (octet_length(ciphertext_sha256) = 32),
  state text NOT NULL CHECK (state IN ('uploading', 'ready', 'bound', 'purge_pending', 'deleted')),
  bound_envelope_position bigint
    CHECK (bound_envelope_position BETWEEN 1 AND 9223372036854775807),
  created_at timestamptz NOT NULL,
  upload_expires_at timestamptz NOT NULL,
  finalized_at timestamptz,
  cross_region_replication_receipt bytea,
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (conversation_id, bound_envelope_position) REFERENCES envelopes(conversation_id, position)
);
CREATE INDEX attachments_expiry_idx ON attachments(state, expires_at, attachment_id);

CREATE TABLE envelope_attachments (
  conversation_id uuid NOT NULL,
  envelope_position bigint NOT NULL CHECK (envelope_position BETWEEN 1 AND 9223372036854775807),
  ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 9),
  attachment_id uuid NOT NULL UNIQUE REFERENCES attachments(attachment_id),
  PRIMARY KEY (conversation_id, envelope_position, ordinal),
  FOREIGN KEY (conversation_id, envelope_position) REFERENCES envelopes(conversation_id, position)
);

CREATE TABLE campaigns (
  campaign_id uuid PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  creator_account_id uuid NOT NULL REFERENCES accounts(account_id),
  creator_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  policy_hash bytea NOT NULL CHECK (octet_length(policy_hash) = 32),
  consent_class text NOT NULL CHECK (consent_class IN ('support', 'transactional', 'community', 'marketing')),
  relationship_scope_policy_profile_id text NOT NULL,
  audience_snapshot_hash bytea NOT NULL CHECK (octet_length(audience_snapshot_hash) = 32),
  evaluated_block bigint NOT NULL CHECK (evaluated_block BETWEEN 0 AND 9223372036854775807),
  evaluated_block_hash bytea NOT NULL CHECK (octet_length(evaluated_block_hash) = 32),
  state text NOT NULL CHECK (state IN ('audience_snapshotted', 'body_encrypted', 'distributing', 'completed', 'partially_failed', 'cancelled')),
  scheduled_at timestamptz,
  created_at timestamptz NOT NULL,
  cancelled_at timestamptz,
  FOREIGN KEY (policy_id, policy_revision) REFERENCES policies(policy_id, policy_revision)
);

CREATE TABLE campaign_targets (
  campaign_id uuid NOT NULL REFERENCES campaigns(campaign_id),
  target_id uuid NOT NULL,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  encryption_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  scope_selection_algorithm_version integer NOT NULL CHECK (scope_selection_algorithm_version >= 1),
  scope_selection_hash bytea NOT NULL CHECK (octet_length(scope_selection_hash) = 32),
  relationship_id uuid REFERENCES relationships(relationship_id),
  relationship_scope_id uuid,
  reader_history_retention_policy_hash bytea
    CHECK (octet_length(reader_history_retention_policy_hash) = 32),
  conversation_id uuid REFERENCES conversations(conversation_id),
  authorization_hash bytea NOT NULL CHECK (octet_length(authorization_hash) = 32),
  state text NOT NULL CHECK (state IN ('scope_pending', 'pending', 'accepted', 'skipped_policy', 'failed')),
  accepted_envelope_id uuid UNIQUE,
  accepted_envelope_position bigint
    CHECK (accepted_envelope_position BETWEEN 1 AND 9223372036854775807),
  last_error_code text,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (campaign_id, target_id),
  UNIQUE (campaign_id, account_id),
  UNIQUE (conversation_id, accepted_envelope_position),
  CHECK (
    (state = 'scope_pending' AND relationship_id IS NULL
      AND relationship_scope_id IS NULL
      AND reader_history_retention_policy_hash IS NULL
      AND conversation_id IS NULL)
    OR
    (state IN ('pending', 'accepted', 'failed') AND relationship_id IS NOT NULL
      AND relationship_scope_id IS NOT NULL
      AND reader_history_retention_policy_hash IS NOT NULL
      AND conversation_id IS NOT NULL)
    OR
    (state = 'skipped_policy' AND (
      (relationship_id IS NULL AND relationship_scope_id IS NULL
        AND reader_history_retention_policy_hash IS NULL AND conversation_id IS NULL)
      OR
      (relationship_id IS NOT NULL AND relationship_scope_id IS NOT NULL
        AND reader_history_retention_policy_hash IS NOT NULL AND conversation_id IS NOT NULL)
    ))
  ),
  CHECK ((state = 'accepted') = (accepted_envelope_id IS NOT NULL)),
  CHECK ((accepted_envelope_id IS NULL) = (accepted_envelope_position IS NULL)),
  FOREIGN KEY (relationship_id, relationship_scope_id, reader_history_retention_policy_hash)
    REFERENCES relationships(relationship_id, relationship_scope_id, reader_history_retention_policy_hash),
  FOREIGN KEY (conversation_id, accepted_envelope_position, accepted_envelope_id)
    REFERENCES envelopes(conversation_id, position, envelope_id)
);

CREATE TABLE campaign_bodies (
  campaign_id uuid PRIMARY KEY REFERENCES campaigns(campaign_id),
  object_key text NOT NULL UNIQUE,
  ciphertext_bytes bigint NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 9223372036854775807),
  ciphertext_sha256 bytea NOT NULL CHECK (octet_length(ciphertext_sha256) = 32),
  descriptor_hash bytea NOT NULL CHECK (octet_length(descriptor_hash) = 32),
  cross_region_replication_receipt bytea,
  state text NOT NULL CHECK (state IN ('uploading', 'ready', 'purge_pending', 'deleted')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE push_endpoints (
  endpoint_id uuid PRIMARY KEY,
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  provider text NOT NULL CHECK (provider IN ('webpush', 'apns', 'fcm')),
  endpoint_fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(endpoint_fingerprint) = 32),
  encrypted_configuration bytea NOT NULL,
  kms_key_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'invalid', 'deleted')),
  created_at timestamptz NOT NULL,
  last_success_at timestamptz,
  last_failure_at timestamptz
);

CREATE TABLE idempotency_records (
  principal_type text NOT NULL CHECK (principal_type IN (
    'native_installation', 'enrollment_allocator', 'enrollment_attempt',
    'embed_issuer', 'embed_context'
  )),
  principal_scope_hash bytea NOT NULL CHECK (octet_length(principal_scope_hash) = 32),
  account_id uuid REFERENCES accounts(account_id),
  installation_id uuid REFERENCES installations(installation_id),
  enrollment_id uuid REFERENCES device_enrollment_attempts(enrollment_id),
  tenant_id uuid REFERENCES tenants(tenant_id),
  embed_issuer_client_id uuid REFERENCES embed_issuer_clients(embed_issuer_client_id),
  embed_context_id uuid REFERENCES embed_contexts(embed_context_id),
  method text NOT NULL,
  route_template text NOT NULL,
  resource_id text NOT NULL DEFAULT '',
  idempotency_key text NOT NULL,
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 599),
  response_headers jsonb NOT NULL,
  response_body_ciphertext bytea NOT NULL,
  kms_key_version text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (
    principal_type, principal_scope_hash, method, route_template, resource_id, idempotency_key
  ),
  CHECK (
    (principal_type = 'native_installation' AND account_id IS NOT NULL
      AND installation_id IS NOT NULL AND enrollment_id IS NULL AND tenant_id IS NULL
      AND embed_issuer_client_id IS NULL AND embed_context_id IS NULL)
    OR (principal_type = 'enrollment_allocator' AND account_id IS NULL
      AND installation_id IS NULL AND enrollment_id IS NULL AND tenant_id IS NULL
      AND embed_issuer_client_id IS NULL AND embed_context_id IS NULL)
    OR (principal_type = 'enrollment_attempt' AND account_id IS NULL
      AND enrollment_id IS NOT NULL
      AND installation_id IS NULL AND tenant_id IS NULL AND embed_issuer_client_id IS NULL
      AND embed_context_id IS NULL)
    OR (principal_type = 'embed_issuer' AND account_id IS NULL AND tenant_id IS NOT NULL
      AND embed_issuer_client_id IS NOT NULL AND enrollment_id IS NULL
      AND installation_id IS NULL AND embed_context_id IS NULL)
    OR (principal_type = 'embed_context' AND account_id IS NULL AND tenant_id IS NOT NULL
      AND embed_context_id IS NOT NULL AND enrollment_id IS NULL
      AND installation_id IS NULL AND embed_issuer_client_id IS NULL)
  ),
  CHECK (expires_at > created_at)
);
CREATE INDEX idempotency_expiry_idx ON idempotency_records(expires_at);

CREATE TABLE outbox_events (
  outbox_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  aggregate_type text NOT NULL,
  aggregate_id_hash bytea NOT NULL CHECK (octet_length(aggregate_id_hash) = 32),
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  available_at timestamptz NOT NULL,
  claimed_at timestamptz,
  completed_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  last_error_code text
);
CREATE INDEX outbox_ready_idx ON outbox_events(available_at, outbox_id)
  WHERE completed_at IS NULL;

CREATE TABLE audit_events (
  audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  tenant_id uuid,
  actor_type text NOT NULL,
  actor_id_hash bytea,
  installation_id_hash bytea,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id_hash bytea,
  outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error')),
  reason_code text,
  request_id uuid NOT NULL,
  source_ip_prefix_hash bytea,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_time_idx ON audit_events(occurred_at, audit_id);

CREATE TABLE lifecycle_jobs (
  job_id uuid PRIMARY KEY,
  job_type text NOT NULL CHECK (job_type IN (
    'export', 'conversation_purge', 'account_delete', 'attachment_purge', 'campaign_purge'
  )),
  requester_account_id uuid,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('queued', 'running', 'awaiting_object_delete', 'complete', 'failed')),
  encrypted_job_parameters bytea,
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  completed_at timestamptz,
  error_code text
);
CREATE INDEX lifecycle_ready_idx ON lifecycle_jobs(next_attempt_at, job_id)
  WHERE state NOT IN ('complete', 'failed');

CREATE TABLE deletion_ledger (
  deletion_id uuid PRIMARY KEY,
  scope_type text NOT NULL,
  scope_id_hash bytea NOT NULL CHECK (octet_length(scope_id_hash) = 32),
  effective_at timestamptz NOT NULL,
  completed_at timestamptz,
  deletion_generation bigint NOT NULL
    CHECK (deletion_generation BETWEEN 1 AND 9223372036854775807),
  audit_digest bytea NOT NULL CHECK (octet_length(audit_digest) = 32)
);

CREATE TABLE transparency_archives (
  archive_id uuid PRIMARY KEY,
  conversation_scope_hash bytea NOT NULL CHECK (octet_length(conversation_scope_hash) = 32),
  final_position bigint NOT NULL CHECK (final_position BETWEEN 0 AND 9223372036854775807),
  final_head_hash bytea NOT NULL CHECK (octet_length(final_head_hash) = 32),
  delivery_signature bytea NOT NULL,
  witness_checkpoint_id text NOT NULL,
  witness_root_hash bytea NOT NULL CHECK (octet_length(witness_root_hash) = 32),
  witness_signature bytea NOT NULL,
  archived_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX transparency_archives_expiry_idx ON transparency_archives(expires_at, archive_id);
