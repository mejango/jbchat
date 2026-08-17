-- storage-and-retention.md section 1: relationally enforce the envelope
-- class/content-type pairing, the permitted/null transcript-hash shape, the
-- 64-byte plain-Ed25519 delivery signature, the canonical-millisecond
-- received_at used by the signed digest, and witness receipt identity
-- against (conversation_id, position, head_hash) rather than position alone.

ALTER TABLE envelopes ADD CONSTRAINT envelopes_class_content_type_check CHECK (
  (envelope_class = 'application'
    AND content_type = 'application/vnd.juicebox.messaging.mls-private-message')
  OR (envelope_class IN ('external_proposal', 'mls_commit')
    AND content_type = 'application/vnd.juicebox.messaging.mls-public-message')
);

ALTER TABLE envelopes ADD CONSTRAINT envelopes_transcript_shape_check CHECK (
  (envelope_class = 'mls_commit'
    AND base_confirmed_transcript_hash IS NOT NULL
    AND resulting_confirmed_transcript_hash IS NOT NULL)
  OR (envelope_class <> 'mls_commit'
    AND base_confirmed_transcript_hash IS NULL
    AND resulting_confirmed_transcript_hash IS NULL)
);

ALTER TABLE envelopes ADD CONSTRAINT envelopes_ed25519_signature_check
  CHECK (octet_length(log_head_signature) = 64);

ALTER TABLE envelopes ADD CONSTRAINT envelopes_received_at_millisecond_check
  CHECK (date_trunc('milliseconds', received_at) = received_at);

ALTER TABLE envelopes ADD CONSTRAINT envelopes_position_head_hash_key
  UNIQUE (conversation_id, position, head_hash);

ALTER TABLE log_witness_receipts ADD CONSTRAINT log_witness_receipts_ed25519_signature_check
  CHECK (octet_length(witness_signature) = 64);

ALTER TABLE log_witness_receipts ADD CONSTRAINT log_witness_receipts_head_identity_fk
  FOREIGN KEY (conversation_id, position, head_hash)
  REFERENCES envelopes(conversation_id, position, head_hash);

ALTER TABLE transparency_archives ADD CONSTRAINT transparency_archives_delivery_signature_check
  CHECK (octet_length(delivery_signature) = 64);

ALTER TABLE transparency_archives ADD CONSTRAINT transparency_archives_witness_signature_check
  CHECK (octet_length(witness_signature) = 64);
