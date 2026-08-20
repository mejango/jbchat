-- Per-account out-of-band notification channels (email, Telegram, and
-- WhatsApp). Browser web-push stays in push_endpoints because it is
-- per-installation; these are per-account. A channel is created 'pending'
-- and becomes 'active' once its target is verified — an emailed code, or a
-- Telegram deep-link /start that captures the chat id. Only "you have
-- activity" wakeups are ever sent through these (never message content),
-- so nothing leaves the end-to-end boundary; they are also the hook for a
-- future two-way relay to these channels.
CREATE TABLE notification_channels (
  channel_id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  kind text NOT NULL CHECK (kind IN ('email', 'telegram', 'whatsapp')),
  -- Delivery target, normalized per kind: lowercased email, Telegram chat
  -- id (numeric string, NULL until /start lands), E.164 phone for WhatsApp.
  target text,
  -- What the user entered, for display (their email, @handle hint, phone).
  display text NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'active', 'disabled')),
  -- HMAC of the verification secret (email code / Telegram link token);
  -- the raw secret is never stored.
  verification_hash bytea,
  verification_expires_at timestamptz,
  verification_attempts integer NOT NULL DEFAULT 0
    CHECK (verification_attempts >= 0),
  created_at timestamptz NOT NULL,
  verified_at timestamptz,
  -- Active implies verified (a disabled channel keeps its verified_at).
  CHECK (state <> 'active' OR verified_at IS NOT NULL),
  CHECK (state <> 'active' OR target IS NOT NULL)
);

-- One active channel per (account, kind, target) — no duplicate emails.
CREATE UNIQUE INDEX notification_channels_unique_active
  ON notification_channels (account_id, kind, target)
  WHERE state = 'active' AND target IS NOT NULL;

-- Dispatch read: active channels for an account.
CREATE INDEX notification_channels_active
  ON notification_channels (account_id)
  WHERE state = 'active';

-- Verification correlation (email code lookup, Telegram /start token).
CREATE INDEX notification_channels_pending_verification
  ON notification_channels (verification_hash)
  WHERE state = 'pending' AND verification_hash IS NOT NULL;
