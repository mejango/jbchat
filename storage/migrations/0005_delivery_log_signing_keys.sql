-- storage-and-retention.md section 1: a bounded active/retired delivery
-- signing-key registry with a foreign key from each checkpoint, so an
-- envelope can never cite a signing key the service does not own.

CREATE TABLE delivery_log_signing_keys (
  key_id text PRIMARY KEY CHECK (
    octet_length(key_id) BETWEEN 1 AND 64
    AND key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
  ),
  key_profile text NOT NULL DEFAULT 'delivery-log-ed25519.v1'
    CHECK (key_profile = 'delivery-log-ed25519.v1'),
  public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
  state text NOT NULL CHECK (state IN ('active', 'retired')),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  retired_at timestamptz,
  CHECK (valid_until > valid_from),
  CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);

ALTER TABLE envelopes ADD CONSTRAINT envelopes_log_signing_key_fk
  FOREIGN KEY (log_signing_key_id) REFERENCES delivery_log_signing_keys(key_id);
