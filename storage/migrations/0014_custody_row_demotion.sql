-- 0014: Demote the custody row - relational rows ARE the authority snapshot.
--
-- The cached JSON copies (snapshot_canonical, mls_roster_canonical,
-- recipient_projections_canonical) are deleted. The store now reconstructs
-- the locked append-authority snapshot from the relational graph on every
-- load and verifies the reconstruction against the persisted snapshot
-- digest, which remains as the lane's compare-and-swap fence and tamper
-- check. To make reconstruction byte-exact the order-sensitive projections
-- gain ordinals, quota bindings gain their window anchor and ordering, and
-- conversation usage carries its limits relationally.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM conversations) THEN
    RAISE EXCEPTION
      'migration 0014 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

ALTER TABLE conversation_roster_projections
  ADD COLUMN ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
  ADD CONSTRAINT conversation_roster_projections_ordinal_key
    UNIQUE (conversation_id, ordinal);

ALTER TABLE conversation_recipient_projections
  ADD COLUMN ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
  ADD CONSTRAINT conversation_recipient_projections_ordinal_key
    UNIQUE (conversation_id, ordinal);

ALTER TABLE conversation_quota_bindings
  ADD COLUMN ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
  ADD COLUMN window_started_at timestamptz NOT NULL,
  ADD CONSTRAINT conversation_quota_bindings_ordinal_key
    UNIQUE (conversation_id, ordinal);

ALTER TABLE conversation_usage
  ADD COLUMN envelope_count_limit bigint NOT NULL
    CHECK (envelope_count_limit BETWEEN 0 AND 9223372036854775807),
  ADD COLUMN envelope_bytes_limit bigint NOT NULL
    CHECK (envelope_bytes_limit BETWEEN 0 AND 9223372036854775807),
  ADD COLUMN attachment_bytes_limit bigint NOT NULL
    CHECK (attachment_bytes_limit BETWEEN 0 AND 9223372036854775807);

ALTER TABLE delivery_conversation_authority
  DROP COLUMN snapshot_canonical,
  DROP COLUMN mls_roster_canonical,
  DROP COLUMN recipient_projections_canonical;
