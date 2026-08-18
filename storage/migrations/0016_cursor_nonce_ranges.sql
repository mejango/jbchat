-- 0016: Fenced RPO-0 cursor nonce ranges.
--
-- The cc1 cursor codec's 96-bit nonces are allocated from per-key ranges
-- whose monotonic fence and high-water mark are durably committed BEFORE
-- any nonce from the range is used. Lease loss, restart, rollback, or
-- ambiguous allocation burns the unused remainder: the next holder bumps
-- the fence and continues strictly above the previous high water, so a
-- nonce is never random-only, repeated, or reassigned under one key.
CREATE TABLE cursor_nonce_ranges (
  key_id text PRIMARY KEY CHECK (octet_length(key_id) BETWEEN 1 AND 64),
  fence bigint NOT NULL DEFAULT 0 CHECK (fence BETWEEN 0 AND 9223372036854775807),
  high_water bigint NOT NULL DEFAULT 0
    CHECK (high_water BETWEEN 0 AND 9223372036854775807),
  updated_at timestamptz NOT NULL
);
