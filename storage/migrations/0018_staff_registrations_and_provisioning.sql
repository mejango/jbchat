-- Conversation planning support: which installations answer a project's
-- support conversations, proven by on-chain project ownership at
-- registration time (ADR 0005 quorum eth_call), and the per-project
-- messaging provisioning marker for lazily minted external-sender
-- credentials and policy-head signing keys. Both tables are additive and
-- empty pre-production.

CREATE TABLE project_staff_registrations (
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  registered_by_owner_address bytea NOT NULL
    CHECK (octet_length(registered_by_owner_address) = 20),
  ownership_block bigint NOT NULL
    CHECK (ownership_block BETWEEN 0 AND 9223372036854775807),
  ownership_block_hash bytea NOT NULL
    CHECK (octet_length(ownership_block_hash) = 32),
  state text NOT NULL CHECK (state IN ('active', 'revoked')),
  registered_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (project_ref_id, installation_id),
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  FOREIGN KEY (installation_id, account_id)
    REFERENCES installations(installation_id, account_id)
);

CREATE TABLE project_messaging_provisions (
  project_ref_id uuid PRIMARY KEY REFERENCES project_refs(project_ref_id),
  policy_id uuid NOT NULL,
  policy_revision bigint NOT NULL,
  policy_log_checkpoint_id uuid NOT NULL,
  directory_checkpoint_id uuid NOT NULL,
  current_external_sender_credential_id uuid NOT NULL,
  staged_external_sender_credential_id uuid NOT NULL,
  policy_head_signing_key_id text NOT NULL,
  provisioned_at timestamptz NOT NULL,
  FOREIGN KEY (policy_id, policy_revision)
    REFERENCES policies(policy_id, policy_revision)
);

-- The service tenant and realm for top-level (non-embedded) conversations
-- are provisioned lazily by the plan store with fixed identities; no rows
-- are inserted by this migration.
