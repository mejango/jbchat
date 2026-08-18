-- 0010: DB-authoritative delivery time.
--
-- delivery_db_now() is the single authoritative clock for durable
-- delivery-lane timestamps (reserved_at, finalized_at, retired_at, the
-- signed envelope received_at, and HTTP idempotency expiry) and for the
-- pending-expiry retirement gate the ports contract calls "authoritative
-- DB now". The value is millisecond-truncated so it satisfies the
-- envelopes received_at millisecond CHECK and the canonical RFC 3339
-- millisecond form the service round-trips. The throwaway storage lab MAY
-- substitute a deterministic implementation for controlled-time scenarios;
-- production runs this definition, and the checksummed migration runner
-- pins this file.
CREATE FUNCTION delivery_db_now() RETURNS timestamptz
LANGUAGE sql VOLATILE
AS $$ SELECT date_trunc('milliseconds', clock_timestamp()) $$;
