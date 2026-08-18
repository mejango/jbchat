-- Per-sender custody fences: the locked append snapshot embeds the
-- SENDER's send grant, so one conversation-wide digest could only ever
-- fence a single sender. Each (conversation, installation) send grant now
-- carries its own byte-exact snapshot digest; the legacy column on
-- delivery_conversation_authority remains as the creator's fence for
-- compatibility and the custody row keeps the lane lock and signing-key
-- pointer. Both tables are empty or single-sender pre-production, so the
-- new table backfills trivially at next refresh.

CREATE TABLE delivery_sender_fences (
  conversation_id uuid NOT NULL,
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  snapshot_digest bytea NOT NULL CHECK (octet_length(snapshot_digest) = 32),
  row_version bigint NOT NULL DEFAULT 1
    CHECK (row_version BETWEEN 1 AND 9223372036854775807),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (conversation_id, installation_id),
  FOREIGN KEY (conversation_id)
    REFERENCES delivery_conversation_authority(conversation_id)
);
