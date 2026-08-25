-- 0026: what the relay must remember per conversation (ADR 0006 phases 3-4).
--
-- The relay's MLS group id is only ever returned by the bridge's
-- join-welcome verb (conversations store a hash of it), and the drain must
-- fold every later Commit into the sealed state exactly once. One row per
-- (relay, conversation), created at join: the group id, the last envelope
-- position folded into the state, and the existing forward watermark.
ALTER TABLE relay_forward_watermarks
  ADD COLUMN mls_group_id bytea
    CHECK (mls_group_id IS NULL OR octet_length(mls_group_id) BETWEEN 1 AND 64),
  ADD COLUMN processed_position numeric(78,0) NOT NULL DEFAULT 0
    CHECK (processed_position >= 0);

-- Inbound: a Telegram chat id resolves to the accounts that verified it.
CREATE INDEX notification_channels_active_target_idx
  ON notification_channels (kind, target)
  WHERE state = 'active' AND target IS NOT NULL;
