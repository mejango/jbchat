-- 0012: Signed quota-policy/scoped-quota anchors and policy-head
-- completeness assertions.
--
-- Quota half: quota_counters gains reserved capacity and a monotonic row
-- fence so append reservations are relational compare-and-swap operations,
-- not JSON bookkeeping; quota_policies anchors every conversation's
-- quota_policy_digest to its canonical document; conversation_quota_bindings
-- materializes the scoped bindings under that anchor; and
-- application_append_quota_reservations is the durable per-append
-- reservation ledger (live -> consumed | released) that survives pending
-- deletion as evidence. While the custody row remains, the JSON snapshot
-- and these rows advance in lockstep and the store fails closed on any
-- divergence.
--
-- Policy-head half: the deferred completeness assertion the storage spec
-- demands - a policy head cannot commit unless its ordered mandatory
-- proposal rows match its declared count - plus the per-grant membership
-- table behind authorized_send_grant_set_hash, so the set root has leaves
-- once the policy-head issuance flow writes them.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM quota_counters)
    OR EXISTS (SELECT 1 FROM policy_heads) THEN
    RAISE EXCEPTION
      'migration 0012 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

ALTER TABLE quota_counters
  ADD COLUMN reserved_operation_count bigint NOT NULL DEFAULT 0
    CHECK (reserved_operation_count BETWEEN 0 AND 9223372036854775807),
  ADD COLUMN reserved_byte_count bigint NOT NULL DEFAULT 0
    CHECK (reserved_byte_count BETWEEN 0 AND 9223372036854775807),
  ADD COLUMN row_version bigint NOT NULL DEFAULT 0
    CHECK (row_version BETWEEN 0 AND 9223372036854775807);

CREATE TABLE quota_policies (
  quota_policy_digest bytea PRIMARY KEY
    CHECK (octet_length(quota_policy_digest) = 32),
  canonical_document jsonb NOT NULL,
  created_at timestamptz NOT NULL
);

ALTER TABLE conversations
  ADD CONSTRAINT conversations_quota_policy_fk
    FOREIGN KEY (quota_policy_digest)
    REFERENCES quota_policies(quota_policy_digest);

CREATE TABLE conversation_quota_bindings (
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  quota_policy_digest bytea NOT NULL
    REFERENCES quota_policies(quota_policy_digest),
  scope_type text NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  quota_name text NOT NULL,
  window_seconds integer NOT NULL CHECK (window_seconds > 0),
  operation_limit bigint NOT NULL
    CHECK (operation_limit BETWEEN 0 AND 9223372036854775807),
  byte_limit bigint NOT NULL CHECK (byte_limit BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY (conversation_id, scope_type, scope_hash, quota_name),
  FOREIGN KEY (scope_type, scope_hash)
    REFERENCES quota_scopes(scope_type, scope_hash)
);

CREATE TABLE application_append_quota_reservations (
  reservation_id bytea PRIMARY KEY CHECK (octet_length(reservation_id) = 32),
  pending_intent_digest bytea NOT NULL
    CHECK (octet_length(pending_intent_digest) = 32),
  scope_type text NOT NULL,
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  quota_name text NOT NULL,
  window_started_at timestamptz NOT NULL,
  reservation_operation_count bigint NOT NULL
    CHECK (reservation_operation_count BETWEEN 0 AND 9223372036854775807),
  reservation_byte_count bigint NOT NULL
    CHECK (reservation_byte_count BETWEEN 0 AND 9223372036854775807),
  fence_generation bigint NOT NULL
    CHECK (fence_generation BETWEEN 0 AND 9223372036854775807),
  fence_token_hash bytea NOT NULL CHECK (octet_length(fence_token_hash) = 32),
  state text NOT NULL CHECK (state IN ('live', 'consumed', 'released')),
  row_version_before bigint NOT NULL
    CHECK (row_version_before BETWEEN 0 AND 9223372036854775807),
  row_version_after bigint NOT NULL
    CHECK (row_version_after BETWEEN 1 AND 9223372036854775807),
  created_at timestamptz NOT NULL,
  resolved_at timestamptz,
  CHECK ((state = 'live') = (resolved_at IS NULL)),
  FOREIGN KEY (scope_type, scope_hash, quota_name, window_started_at)
    REFERENCES quota_counters(scope_type, scope_hash, quota_name, window_started_at)
);
CREATE INDEX application_append_quota_reservations_pending_idx
  ON application_append_quota_reservations(pending_intent_digest)
  WHERE state = 'live';

CREATE TABLE policy_head_send_grant_set_members (
  policy_head_id uuid NOT NULL REFERENCES policy_heads(policy_head_id),
  grant_evidence_digest bytea NOT NULL
    CHECK (octet_length(grant_evidence_digest) = 32),
  grant_inclusion_evidence_digest bytea NOT NULL
    CHECK (octet_length(grant_inclusion_evidence_digest) = 32),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  credential_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN (
    'customer', 'project-staff', 'publisher', 'subscriber', 'member', 'moderator'
  )),
  PRIMARY KEY (policy_head_id, grant_evidence_digest)
);

CREATE FUNCTION policy_head_mandatory_proposals_are_complete()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  head_id uuid;
  declared bigint;
  actual bigint;
BEGIN
  head_id := COALESCE(NEW.policy_head_id, OLD.policy_head_id);
  SELECT mandatory_proposal_count INTO declared
    FROM policy_heads WHERE policy_head_id = head_id;
  IF declared IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT count(*) INTO actual
    FROM policy_head_mandatory_proposals WHERE policy_head_id = head_id;
  IF actual <> declared THEN
    RAISE EXCEPTION
      'policy head % has % mandatory proposal rows but declares %',
      head_id, actual, declared;
  END IF;
  RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER policy_heads_mandatory_completeness_trigger
  AFTER INSERT OR UPDATE ON policy_heads
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION policy_head_mandatory_proposals_are_complete();
CREATE CONSTRAINT TRIGGER policy_head_proposals_completeness_trigger
  AFTER INSERT OR UPDATE OR DELETE ON policy_head_mandatory_proposals
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION policy_head_mandatory_proposals_are_complete();
