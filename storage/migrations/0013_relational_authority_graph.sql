-- 0013: The relational authority graph behind the append-lane custody row.
--
-- Every component of the locked append-authority snapshot now has
-- authoritative relational rows: the conversation projection gains its etag
-- and recipient-set commitment columns; sender membership resolves through
-- memberships/role_credentials (which gain state and a revocation fence);
-- the selected send grant, the witnessed policy-head projection, and the
-- MLS roster/recipient routing projections are normalized tables. The
-- custody row is demoted to the lane lock plus a digest-verified cached
-- projection: the store cross-checks every snapshot component against these
-- rows on load and fails closed on any divergence, and finalize advances
-- the relational rows in the same transaction as the cache. Removing the
-- cached JSON copy entirely is the residual G2 integration step.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM role_credentials)
    OR EXISTS (SELECT 1 FROM memberships)
    OR EXISTS (SELECT 1 FROM conversations) THEN
    RAISE EXCEPTION
      'migration 0013 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

ALTER TABLE conversations
  ADD COLUMN etag text NOT NULL CHECK (octet_length(etag) BETWEEN 1 AND 128),
  ADD COLUMN recipient_set_version bigint NOT NULL
    CHECK (recipient_set_version BETWEEN 0 AND 9223372036854775807),
  ADD COLUMN recipient_set_hash bytea NOT NULL
    CHECK (octet_length(recipient_set_hash) = 32);

ALTER TABLE role_credentials
  ADD COLUMN revocation_version bigint NOT NULL DEFAULT 1
    CHECK (revocation_version BETWEEN 1 AND 9223372036854775807),
  ADD COLUMN state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'suspended', 'revoked', 'superseded')),
  ADD CONSTRAINT role_credentials_revoked_state_check
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL));

CREATE TABLE conversation_send_grants (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  credential_id uuid NOT NULL,
  conversation_kind text NOT NULL CHECK (conversation_kind IN (
    'purchase_support', 'announcement', 'community'
  )),
  conversation_generation bigint NOT NULL
    CHECK (conversation_generation BETWEEN 1 AND 9223372036854775807),
  role text NOT NULL CHECK (role IN (
    'customer', 'project-staff', 'publisher', 'subscriber', 'member', 'moderator'
  )),
  role_credential_id uuid NOT NULL REFERENCES role_credentials(credential_id),
  role_credential_fingerprint bytea NOT NULL
    CHECK (octet_length(role_credential_fingerprint) = 32),
  role_credential_subject_account_id uuid NOT NULL
    REFERENCES accounts(account_id),
  role_credential_subject_installation_id uuid NOT NULL
    REFERENCES installations(installation_id),
  role_credential_valid_from timestamptz NOT NULL,
  role_credential_valid_until timestamptz NOT NULL,
  capability text NOT NULL CHECK (capability = 'send_application'),
  state text NOT NULL CHECK (state IN ('active', 'suspended', 'revoked', 'expired')),
  policy_revision bigint NOT NULL
    CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  policy_head_sequence bigint NOT NULL
    CHECK (policy_head_sequence BETWEEN 1 AND 9223372036854775807),
  policy_head_hash bytea NOT NULL CHECK (octet_length(policy_head_hash) = 32),
  expires_at timestamptz NOT NULL,
  grant_evidence_digest bytea NOT NULL
    CHECK (octet_length(grant_evidence_digest) = 32),
  grant_inclusion_evidence_digest bytea NOT NULL
    CHECK (octet_length(grant_inclusion_evidence_digest) = 32),
  PRIMARY KEY (conversation_id, installation_id, credential_id),
  CHECK (role_credential_valid_until > role_credential_valid_from)
);

CREATE TABLE delivery_policy_head_anchors (
  conversation_id uuid PRIMARY KEY REFERENCES conversations(conversation_id),
  policy_head_id uuid NOT NULL,
  policy_head_sequence bigint NOT NULL
    CHECK (policy_head_sequence BETWEEN 1 AND 9223372036854775807),
  policy_head_hash bytea NOT NULL CHECK (octet_length(policy_head_hash) = 32),
  delivery_log_position bigint NOT NULL
    CHECK (delivery_log_position BETWEEN 0 AND 9223372036854775807),
  delivery_log_head_hash bytea NOT NULL
    CHECK (octet_length(delivery_log_head_hash) = 32),
  evaluation_log_position bigint NOT NULL
    CHECK (evaluation_log_position BETWEEN 0 AND 9223372036854775807),
  evaluation_log_head_hash bytea NOT NULL
    CHECK (octet_length(evaluation_log_head_hash) = 32),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  roster_version bigint NOT NULL
    CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  confirmed_transcript_hash bytea NOT NULL
    CHECK (octet_length(confirmed_transcript_hash) = 32),
  policy_revision bigint NOT NULL
    CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  signed_body_sha256 bytea NOT NULL CHECK (octet_length(signed_body_sha256) = 32),
  signer_key_id text NOT NULL,
  signature_sha256 bytea NOT NULL CHECK (octet_length(signature_sha256) = 32),
  witness_evidence_digest bytea NOT NULL
    CHECK (octet_length(witness_evidence_digest) = 32),
  proof_evidence_digest bytea NOT NULL
    CHECK (octet_length(proof_evidence_digest) = 32),
  policy_consistency_evidence_digest bytea NOT NULL
    CHECK (octet_length(policy_consistency_evidence_digest) = 32),
  proof_verified_at timestamptz NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  witness_state text NOT NULL CHECK (witness_state IN (
    'verified', 'missing', 'inconsistent', 'stale'
  )),
  witness_checkpoint_id uuid,
  witnessed_policy_head_hash bytea
    CHECK (witnessed_policy_head_hash IS NULL
      OR octet_length(witnessed_policy_head_hash) = 32),
  mandatory_proposal_count bigint NOT NULL
    CHECK (mandatory_proposal_count BETWEEN 0 AND 100),
  mandatory_proposal_set_hash bytea NOT NULL
    CHECK (octet_length(mandatory_proposal_set_hash) = 32),
  authorized_send_grant_set_hash bytea NOT NULL
    CHECK (octet_length(authorized_send_grant_set_hash) = 32),
  selected_send_grant_evidence_digest bytea NOT NULL
    CHECK (octet_length(selected_send_grant_evidence_digest) = 32),
  selected_send_grant_inclusion_evidence_digest bytea NOT NULL
    CHECK (octet_length(selected_send_grant_inclusion_evidence_digest) = 32),
  authorized_quota_policy_digest bytea NOT NULL
    CHECK (octet_length(authorized_quota_policy_digest) = 32),
  prior_policy_head_sequence bigint NOT NULL
    CHECK (prior_policy_head_sequence BETWEEN 0 AND 9223372036854775807),
  prior_policy_head_hash bytea NOT NULL
    CHECK (octet_length(prior_policy_head_hash) = 32),
  prior_policy_witness_checkpoint_id uuid NOT NULL,
  prior_policy_witness_evidence_digest bytea NOT NULL
    CHECK (octet_length(prior_policy_witness_evidence_digest) = 32),
  updated_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at),
  CHECK ((witness_state = 'verified') = (witness_checkpoint_id IS NOT NULL))
);

CREATE TABLE conversation_roster_projections (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  conversation_generation bigint NOT NULL
    CHECK (conversation_generation BETWEEN 1 AND 9223372036854775807),
  roster_version bigint NOT NULL
    CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  credential_id uuid NOT NULL,
  credential_fingerprint bytea NOT NULL
    CHECK (octet_length(credential_fingerprint) = 32),
  PRIMARY KEY (conversation_id, installation_id)
);

CREATE TABLE conversation_recipient_projections (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  conversation_generation bigint NOT NULL
    CHECK (conversation_generation BETWEEN 1 AND 9223372036854775807),
  recipient_set_version bigint NOT NULL
    CHECK (recipient_set_version BETWEEN 0 AND 9223372036854775807),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  credential_id uuid NOT NULL,
  credential_fingerprint bytea NOT NULL
    CHECK (octet_length(credential_fingerprint) = 32),
  credential_revocation_version bigint NOT NULL
    CHECK (credential_revocation_version BETWEEN 1 AND 9223372036854775807),
  credential_state text NOT NULL CHECK (credential_state IN (
    'active', 'suspended', 'revoked', 'superseded'
  )),
  credential_expires_at timestamptz NOT NULL,
  joined_position bigint NOT NULL
    CHECK (joined_position BETWEEN 1 AND 9223372036854775807),
  removed_position bigint CHECK (
    removed_position BETWEEN joined_position AND 9223372036854775807
  ),
  installation_state text NOT NULL CHECK (installation_state IN (
    'active', 'suspended', 'revoked'
  )),
  PRIMARY KEY (conversation_id, installation_id)
);
