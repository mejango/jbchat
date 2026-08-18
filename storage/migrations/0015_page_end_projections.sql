-- 0015: Historical page-end projections and policy-transition range rows.
--
-- Every accepted delivery position gets an immutable exact historical
-- projection of the conversation/policy state at that position, written in
-- the same finalize transaction as the envelope, so any later page end (or
-- empty-page anchor) replays the authenticated historical snapshot instead
-- of substituting current mutable state. conversation_policy_transitions
-- records, append-only, the position at which each policy-head sequence
-- first took effect on the delivery log - the ordered interval rows behind
-- policy-transition range evidence. Both tables are append-only by trigger;
-- a removal cutoff cannot be hidden by later rewriting the projection at an
-- earlier page end. The succinct coalesced range PROOF over these rows
-- still requires the independent policy log's consistency machinery and
-- remains launch work, as do the five release-pinned page verifier
-- adapters the client kernel consumes.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM envelopes) THEN
    RAISE EXCEPTION
      'migration 0015 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

CREATE TABLE conversation_page_end_projections (
  conversation_id uuid NOT NULL,
  position bigint NOT NULL CHECK (position BETWEEN 1 AND 9223372036854775807),
  generation bigint NOT NULL
    CHECK (generation BETWEEN 1 AND 9223372036854775807),
  release_profile_id text NOT NULL,
  delivery_limits_digest bytea NOT NULL
    CHECK (octet_length(delivery_limits_digest) = 32),
  etag text NOT NULL CHECK (octet_length(etag) BETWEEN 1 AND 128),
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND 9223372036854775807),
  roster_version bigint NOT NULL
    CHECK (roster_version BETWEEN 0 AND 9223372036854775807),
  confirmed_transcript_hash bytea NOT NULL
    CHECK (octet_length(confirmed_transcript_hash) = 32),
  policy_head_id uuid NOT NULL,
  policy_revision bigint NOT NULL
    CHECK (policy_revision BETWEEN 1 AND 9223372036854775807),
  policy_mandatory_proposal_count bigint NOT NULL
    CHECK (policy_mandatory_proposal_count BETWEEN 0 AND 100),
  policy_mandatory_proposal_set_hash bytea NOT NULL
    CHECK (octet_length(policy_mandatory_proposal_set_hash) = 32),
  policy_authorized_send_grant_set_hash bytea NOT NULL
    CHECK (octet_length(policy_authorized_send_grant_set_hash) = 32),
  policy_authorized_quota_policy_digest bytea NOT NULL
    CHECK (octet_length(policy_authorized_quota_policy_digest) = 32),
  policy_head_sequence bigint NOT NULL
    CHECK (policy_head_sequence BETWEEN 1 AND 9223372036854775807),
  policy_head_hash bytea NOT NULL
    CHECK (octet_length(policy_head_hash) = 32),
  policy_delivery_log_position bigint NOT NULL
    CHECK (policy_delivery_log_position BETWEEN 0 AND 9223372036854775807),
  policy_delivery_log_head_hash bytea NOT NULL
    CHECK (octet_length(policy_delivery_log_head_hash) = 32),
  policy_witness_checkpoint_id uuid,
  policy_witness_evidence_digest bytea NOT NULL
    CHECK (octet_length(policy_witness_evidence_digest) = 32),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (conversation_id, position),
  FOREIGN KEY (conversation_id, position)
    REFERENCES envelopes (conversation_id, position)
);

CREATE TABLE conversation_policy_transitions (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  policy_head_sequence bigint NOT NULL
    CHECK (policy_head_sequence BETWEEN 1 AND 9223372036854775807),
  policy_head_id uuid NOT NULL,
  policy_head_hash bytea NOT NULL
    CHECK (octet_length(policy_head_hash) = 32),
  effective_from_position bigint NOT NULL
    CHECK (effective_from_position BETWEEN 1 AND 9223372036854775807),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (conversation_id, policy_head_sequence)
);

CREATE FUNCTION historical_projection_rows_are_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'historical projection rows are immutable';
END $$;

CREATE TRIGGER conversation_page_end_projections_immutable_trigger
  BEFORE UPDATE OR DELETE ON conversation_page_end_projections
  FOR EACH ROW EXECUTE FUNCTION historical_projection_rows_are_immutable();
CREATE TRIGGER conversation_policy_transitions_immutable_trigger
  BEFORE UPDATE OR DELETE ON conversation_policy_transitions
  FOR EACH ROW EXECUTE FUNCTION historical_projection_rows_are_immutable();
