-- storage-and-retention.md section 1: durable realm-scoped accepted replay
-- identity, invisible pending-intent/signing-fence state, and final
-- acceptance linkage with no pre-finalize visibility, position reuse, or
-- duplicate fanout. Shapes follow the TypeScript port contract
-- (src/production/delivery/ports.ts, service.ts): canonical documents are
-- stored verbatim and re-parsed digest-first on every read, while the
-- indexed columns carry the relational fences.

-- Monotonic durable lane generation per conversation; a fence generation is
-- never reused even across retirements.
CREATE TABLE application_append_lanes (
  conversation_id uuid PRIMARY KEY REFERENCES conversations(conversation_id),
  lane_generation bigint NOT NULL DEFAULT 0
    CHECK (lane_generation BETWEEN 0 AND 9223372036854775807)
);

-- Interim custody of the locked append-authority projection (membership,
-- policy head, send grant, quota bindings/counters, roster and routing
-- projections) pinned per conversation generation. The digest is recomputed
-- by the reading service, so a mutated document fails closed. The full
-- relational authority graph (policy-head anchors, send-grant provenance,
-- scope mappings) replaces this custody row during G2 integration.
CREATE TABLE delivery_conversation_authority (
  conversation_id uuid PRIMARY KEY REFERENCES conversations(conversation_id),
  conversation_generation bigint NOT NULL
    CHECK (conversation_generation BETWEEN 1 AND 9223372036854775807),
  realm_id text NOT NULL CHECK (octet_length(realm_id) BETWEEN 1 AND 64),
  snapshot_canonical jsonb NOT NULL,
  snapshot_digest bytea NOT NULL CHECK (octet_length(snapshot_digest) = 32),
  mls_roster_canonical jsonb NOT NULL,
  recipient_projections_canonical jsonb NOT NULL,
  active_signing_key_id text NOT NULL
    REFERENCES delivery_log_signing_keys(key_id),
  row_version bigint NOT NULL DEFAULT 1
    CHECK (row_version BETWEEN 1 AND 9223372036854775807),
  updated_at timestamptz NOT NULL
);

-- Exactly one live pending intent may fence a conversation lane, and a
-- pending position stays invisible: nothing references this table, and the
-- envelope row exists only after finalization. The canonical document
-- includes the live bearer fence token, which never appears in acceptances,
-- receipts, or incidents.
CREATE TABLE application_append_pendings (
  conversation_id uuid PRIMARY KEY REFERENCES conversations(conversation_id),
  realm_id text NOT NULL CHECK (octet_length(realm_id) BETWEEN 1 AND 64),
  intent_digest bytea NOT NULL UNIQUE CHECK (octet_length(intent_digest) = 32),
  admission_command_digest bytea NOT NULL
    CHECK (octet_length(admission_command_digest) = 32),
  request_commitment bytea NOT NULL CHECK (octet_length(request_commitment) = 32),
  http_scope_hash bytea NOT NULL CHECK (octet_length(http_scope_hash) = 32),
  envelope_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  expected_snapshot_digest bytea NOT NULL
    CHECK (octet_length(expected_snapshot_digest) = 32),
  fence_generation bigint NOT NULL
    CHECK (fence_generation BETWEEN 1 AND 9223372036854775807),
  fence_token_hash bytea NOT NULL CHECK (octet_length(fence_token_hash) = 32),
  pending_canonical jsonb NOT NULL,
  reserved_at timestamptz NOT NULL,
  pending_expires_at timestamptz NOT NULL,
  UNIQUE (conversation_id, position),
  UNIQUE (realm_id, conversation_id, envelope_id),
  CHECK (pending_expires_at > reserved_at)
);

-- Durable realm-scoped accepted replay identity plus final acceptance
-- linkage: the acceptance binds the exact finalized envelope row, a position
-- can never be accepted twice, and the stored canonical document is
-- bearer-free.
CREATE TABLE application_append_acceptances (
  realm_id text NOT NULL CHECK (octet_length(realm_id) BETWEEN 1 AND 64),
  conversation_id uuid NOT NULL,
  envelope_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  intent_digest bytea NOT NULL UNIQUE CHECK (octet_length(intent_digest) = 32),
  admission_command_digest bytea NOT NULL
    CHECK (octet_length(admission_command_digest) = 32),
  semantic_identity_digest bytea NOT NULL
    CHECK (octet_length(semantic_identity_digest) = 32),
  acceptance_canonical jsonb NOT NULL,
  finalized_at timestamptz NOT NULL,
  PRIMARY KEY (realm_id, conversation_id, envelope_id),
  UNIQUE (conversation_id, position),
  FOREIGN KEY (conversation_id, position, envelope_id)
    REFERENCES envelopes(conversation_id, position, envelope_id)
);

CREATE TABLE application_append_http_idempotency (
  http_scope_hash bytea PRIMARY KEY CHECK (octet_length(http_scope_hash) = 32),
  request_commitment bytea NOT NULL CHECK (octet_length(request_commitment) = 32),
  realm_id text NOT NULL,
  conversation_id uuid NOT NULL,
  envelope_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (realm_id, conversation_id, envelope_id)
    REFERENCES application_append_acceptances(realm_id, conversation_id, envelope_id)
);
CREATE INDEX application_append_http_idempotency_expiry_idx
  ON application_append_http_idempotency(expires_at);

-- Immutable retirement tombstones: an expired, signer-cancelled pending is
-- released exactly once and replays as retired forever.
CREATE TABLE application_append_retirements (
  intent_digest bytea PRIMARY KEY CHECK (octet_length(intent_digest) = 32),
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  fence_generation bigint NOT NULL
    CHECK (fence_generation BETWEEN 1 AND 9223372036854775807),
  fence_token_hash bytea NOT NULL CHECK (octet_length(fence_token_hash) = 32),
  retired_at timestamptz NOT NULL
);
