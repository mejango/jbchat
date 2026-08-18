-- Witness baseline (ADR 0002). This schema lives in the witness service's
-- OWN database: the delivery service holds no write credential here, and
-- the witness holds none against the delivery database. Three RFC 6962
-- append-only logs share one table keyed by namespace; per-conversation
-- delivery continuity and per-namespace chain heads make equivocation a
-- constraint violation the service converts into a typed SEV-0 rejection.

CREATE FUNCTION witness_db_now() RETURNS timestamptz
LANGUAGE sql VOLATILE
AS $$ SELECT date_trunc('milliseconds', clock_timestamp()) $$;

CREATE TABLE witness_leaves (
  namespace text NOT NULL CHECK (namespace IN ('delivery', 'policy', 'directory')),
  tree_index bigint NOT NULL CHECK (tree_index BETWEEN 0 AND 9223372036854775807),
  leaf_payload bytea NOT NULL CHECK (octet_length(leaf_payload) <= 4096),
  leaf_hash bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  appended_at timestamptz NOT NULL,
  PRIMARY KEY (namespace, tree_index)
);

CREATE TABLE witness_checkpoints (
  checkpoint_id uuid PRIMARY KEY,
  namespace text NOT NULL CHECK (namespace IN ('delivery', 'policy', 'directory')),
  tree_size bigint NOT NULL CHECK (tree_size BETWEEN 1 AND 9223372036854775807),
  root_hash bytea NOT NULL CHECK (octet_length(root_hash) = 32),
  witness_key_id text NOT NULL CHECK (octet_length(witness_key_id) BETWEEN 1 AND 64),
  witness_signature bytea NOT NULL CHECK (octet_length(witness_signature) = 64),
  witnessed_at timestamptz NOT NULL,
  -- same size, same namespace, one root: equivocation cannot be stored.
  UNIQUE (namespace, tree_size)
);

-- Per-conversation delivery continuity: exactly-next positions, one head
-- per position, forever.
CREATE TABLE witness_delivery_heads (
  conversation_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  tree_index bigint NOT NULL,
  PRIMARY KEY (conversation_id, position)
);

-- Per-namespace serialization row plus the last accepted upstream
-- checkpoint reference for policy/directory chain extension.
CREATE TABLE witness_chain_heads (
  namespace text PRIMARY KEY CHECK (namespace IN ('delivery', 'policy', 'directory')),
  last_upstream_checkpoint_id uuid,
  updated_at timestamptz NOT NULL
);
INSERT INTO witness_chain_heads (namespace, updated_at)
VALUES ('delivery', now()), ('policy', now()), ('directory', now());

-- Keys the witness accepts submissions from (the delivery/policy/directory
-- signers' PUBLIC halves only).
CREATE TABLE witness_submitter_keys (
  key_id text PRIMARY KEY CHECK (octet_length(key_id) BETWEEN 1 AND 64),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  CHECK (valid_until > valid_from)
);

-- Client-gossiped observations; a mismatch against the tree is a split
-- view and must alert within the five-minute SLO.
CREATE TABLE witness_gossip_reports (
  report_id uuid PRIMARY KEY,
  conversation_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  witness_checkpoint_id uuid NOT NULL,
  split_view boolean NOT NULL,
  received_at timestamptz NOT NULL
);
CREATE INDEX witness_gossip_split_view_idx
  ON witness_gossip_reports(received_at) WHERE split_view;
