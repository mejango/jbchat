-- storage-and-retention.md section 4: envelopes and mailbox_entries are HASH
-- partitioned with exactly 64 partitions each; changing the count requires
-- online table replacement, never in-place repartitioning.
DO $partitions$
DECLARE
  remainder integer;
BEGIN
  FOR remainder IN 0..63 LOOP
    EXECUTE format(
      'CREATE TABLE envelopes_h%s PARTITION OF envelopes FOR VALUES WITH (MODULUS 64, REMAINDER %s)',
      lpad(remainder::text, 2, '0'),
      remainder
    );
    EXECUTE format(
      'CREATE TABLE mailbox_entries_h%s PARTITION OF mailbox_entries FOR VALUES WITH (MODULUS 64, REMAINDER %s)',
      lpad(remainder::text, 2, '0'),
      remainder
    );
  END LOOP;
END
$partitions$;
