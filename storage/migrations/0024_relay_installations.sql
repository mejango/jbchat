-- ADR 0006 relay members: one service-operated installation per
-- (served account, channel kind). The relay is a REAL installation row
-- (its MLS credential and KeyPackages live in the normal tables); this
-- table adds the service-side facts: whom it serves, which channel it
-- forwards to, and its sealed MLS client state. The state blob is the
-- bridge's exported client state, AES-GCM sealed with the identity
-- secret; every mutation happens under FOR UPDATE of this row so the
-- outbound drain (keeper) and inbound webhook (app) serialize.
CREATE TABLE relay_installations (
  relay_installation_id uuid PRIMARY KEY
    REFERENCES installations(installation_id),
  served_account_id uuid NOT NULL REFERENCES accounts(account_id),
  channel_kind text NOT NULL CHECK (channel_kind IN ('telegram', 'email', 'whatsapp')),
  mls_state_ciphertext bytea,
  kms_key_version text,
  state text NOT NULL CHECK (state IN ('active', 'revoked')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK ((mls_state_ciphertext IS NULL) = (kms_key_version IS NULL))
);

-- One live relay per (member, channel).
CREATE UNIQUE INDEX relay_installations_one_active
  ON relay_installations (served_account_id, channel_kind)
  WHERE state = 'active';

-- Outbound drain: the relay installations' mailboxes are polled by the
-- keeper; this finds the relay rows fast.
CREATE INDEX relay_installations_active
  ON relay_installations (state)
  WHERE state = 'active';

-- Delivery watermark for the outbound drain: the last mailbox position
-- forwarded per relay, so restarts never re-send.
CREATE TABLE relay_forward_watermarks (
  relay_installation_id uuid NOT NULL
    REFERENCES relay_installations(relay_installation_id),
  conversation_id uuid NOT NULL REFERENCES conversations(conversation_id),
  forwarded_position numeric(78,0) NOT NULL CHECK (forwarded_position >= 0),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (relay_installation_id, conversation_id)
);
