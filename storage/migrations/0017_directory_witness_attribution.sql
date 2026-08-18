-- 0017: Attributable directory witness receipts.
--
-- ADR 0002 makes witness transfer an overlap of concurrently valid witness
-- keys, which requires every receipt to name its signer. The device
-- directory previously stored an unattributed opaque receipt; it now
-- carries the witness key ID with paired nullability, so a receipt from
-- one operator is structurally distinguishable from another's.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM directory_checkpoints) THEN
    RAISE EXCEPTION
      'migration 0017 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

ALTER TABLE directory_checkpoints
  ADD COLUMN witness_key_id text
    CHECK (witness_key_id IS NULL OR octet_length(witness_key_id) BETWEEN 1 AND 64),
  ADD CONSTRAINT directory_checkpoints_witness_pairing_check CHECK (
    (witnessed_at IS NULL) = (witness_receipt IS NULL)
    AND (witnessed_at IS NULL) = (witness_key_id IS NULL)
  );
