-- The global policy-log leaf sequence: every issued policy head appends
-- one leaf, checkpoints commit the RFC 6962 root over the prefix, and the
-- witness cosigns checkpoints through the policy namespace. Empty
-- pre-production.

CREATE TABLE policy_log_leaves (
  leaf_index bigint PRIMARY KEY CHECK (leaf_index >= 0),
  policy_head_id uuid NOT NULL UNIQUE,
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  created_at timestamptz NOT NULL
);
