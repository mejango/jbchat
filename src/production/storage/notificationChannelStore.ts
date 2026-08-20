import { randomBytes, randomInt, randomUUID } from "node:crypto";
import type { Sql } from "postgres";

/**
 * Per-account out-of-band notification channels (email / Telegram /
 * WhatsApp). A channel is created 'pending' and becomes 'active' once its
 * target is verified: email by a 6-digit code, Telegram by a deep-link
 * /start that carries a one-time token the bot webhook redeems. WhatsApp is
 * accepted and stored pending until a sender is wired. Only wakeups (never
 * message content) are ever delivered through these — the verified target
 * is also the hook for a future two-way relay.
 */

export type ChannelKind = "email" | "telegram" | "whatsapp";

const CODE_TTL_MS = 15 * 60 * 1000;
const TOKEN_TTL_MS = 60 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 5;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const E164 = /^\+[1-9]\d{6,14}$/;

export interface NotificationChannel {
  readonly channelId: string;
  readonly kind: ChannelKind;
  readonly display: string;
  readonly state: "pending" | "active" | "disabled";
  readonly createdAt: string;
}

export interface NotificationChannelStoreContext {
  readonly sql: Sql;
  /** Keyed HMAC over the verification secret; the raw secret is never stored. */
  readonly hmacSecret: (secret: string) => Buffer;
  readonly now: () => string;
}

export type CreateChannelResult =
  | {
      readonly status: "created";
      readonly channelId: string;
      /** Email 6-digit code or Telegram link token; the caller delivers it. */
      readonly secret: string;
      readonly kind: ChannelKind;
    }
  | { readonly status: "refused"; readonly reasonCode: string };

export type VerifyResult =
  | { readonly status: "active" }
  | { readonly status: "invalid" }
  | { readonly status: "expired" };

export interface NotificationChannelStore {
  readonly createChannel: (input: {
    accountId: string;
    kind: ChannelKind;
    target: string;
  }) => Promise<CreateChannelResult>;
  readonly verifyEmailCode: (input: {
    accountId: string;
    channelId: string;
    code: string;
  }) => Promise<VerifyResult>;
  readonly redeemTelegramToken: (input: {
    token: string;
    chatId: string;
  }) => Promise<{ status: "active"; accountId: string } | { status: "not_found" }>;
  readonly list: (accountId: string) => Promise<readonly NotificationChannel[]>;
  readonly disable: (accountId: string, channelId: string) => Promise<boolean>;
  /** Active out-of-band targets for dispatch. */
  readonly activeTargets: (
    accountId: string,
  ) => Promise<readonly { kind: ChannelKind; target: string }[]>;
}

export function createNotificationChannelStore(
  context: NotificationChannelStoreContext,
): NotificationChannelStore {
  const { sql } = context;

  return Object.freeze({
    async createChannel(input: {
      accountId: string;
      kind: ChannelKind;
      target: string;
    }): Promise<CreateChannelResult> {
      const now = context.now();
      const kind = input.kind;
      const raw = input.target.trim();

      // Normalize + validate per kind. Telegram's target (chat id) is not
      // known until /start; the user supplies nothing but the intent.
      let normalizedTarget: string | null = null;
      let display: string;
      if (kind === "email") {
        const email = raw.toLowerCase();
        if (!EMAIL.test(email)) {
          return refused("invalid_email");
        }
        normalizedTarget = email;
        display = email;
      } else if (kind === "whatsapp") {
        const phone = raw.replace(/[\s()-]/g, "");
        if (!E164.test(phone)) {
          return refused("invalid_phone");
        }
        normalizedTarget = phone;
        display = phone;
      } else {
        // telegram: no target yet.
        display = "Telegram";
      }

      return sql.begin(async (tx) => {
        if (normalizedTarget !== null) {
          const active = await tx`
            SELECT channel_id FROM notification_channels
            WHERE account_id = ${input.accountId} AND kind = ${kind}
              AND target = ${normalizedTarget} AND state = 'active'`;
          if (active.length > 0) {
            return refused("already_active");
          }
        }

        const channelId = randomUUID();
        // Email: 6-digit code. Telegram: URL-safe link token. WhatsApp has
        // no sender yet, so it holds pending with no deliverable secret.
        const secret =
          kind === "email"
            ? String(randomInt(0, 1_000_000)).padStart(6, "0")
            : kind === "telegram"
              ? randomBytes(24).toString("base64url")
              : "";
        const ttl = kind === "telegram" ? TOKEN_TTL_MS : CODE_TTL_MS;
        const verificationHash = secret ? context.hmacSecret(secret) : null;
        const expiresAt = secret
          ? new Date(Date.parse(now) + ttl).toISOString()
          : null;

        await tx`
          INSERT INTO notification_channels (
            channel_id, account_id, kind, target, display, state,
            verification_hash, verification_expires_at, verification_attempts,
            created_at
          ) VALUES (
            ${channelId}, ${input.accountId}, ${kind}, ${normalizedTarget},
            ${display}, 'pending', ${verificationHash},
            ${expiresAt}, 0, ${now}::timestamptz
          )`;
        return Object.freeze({
          status: "created" as const,
          channelId,
          secret,
          kind,
        });
      });
    },

    async verifyEmailCode(input: {
      accountId: string;
      channelId: string;
      code: string;
    }): Promise<VerifyResult> {
      const now = context.now();
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT verification_hash, verification_expires_at,
                 verification_attempts
          FROM notification_channels
          WHERE channel_id = ${input.channelId}
            AND account_id = ${input.accountId}
            AND kind = 'email' AND state = 'pending'
          FOR UPDATE`;
        if (rows.length !== 1 || rows[0].verification_hash === null) {
          return Object.freeze({ status: "invalid" as const });
        }
        if (
          new Date(rows[0].verification_expires_at as Date).toISOString() <= now
        ) {
          return Object.freeze({ status: "expired" as const });
        }
        if (Number(rows[0].verification_attempts) >= MAX_VERIFY_ATTEMPTS) {
          return Object.freeze({ status: "expired" as const });
        }
        const expected = Buffer.from(rows[0].verification_hash as Uint8Array);
        const given = context.hmacSecret(input.code.trim());
        if (expected.length !== given.length || !expected.equals(given)) {
          await tx`
            UPDATE notification_channels
            SET verification_attempts = verification_attempts + 1
            WHERE channel_id = ${input.channelId}`;
          return Object.freeze({ status: "invalid" as const });
        }
        await tx`
          UPDATE notification_channels
          SET state = 'active', verified_at = ${now}::timestamptz,
              verification_hash = NULL, verification_expires_at = NULL
          WHERE channel_id = ${input.channelId}`;
        return Object.freeze({ status: "active" as const });
      });
    },

    async redeemTelegramToken(input: {
      token: string;
      chatId: string;
    }): Promise<
      { status: "active"; accountId: string } | { status: "not_found" }
    > {
      const now = context.now();
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT channel_id, account_id, verification_expires_at
          FROM notification_channels
          WHERE kind = 'telegram' AND state = 'pending'
            AND verification_hash = ${context.hmacSecret(input.token.trim())}
          FOR UPDATE`;
        if (
          rows.length !== 1 ||
          new Date(rows[0].verification_expires_at as Date).toISOString() <= now
        ) {
          return Object.freeze({ status: "not_found" as const });
        }
        await tx`
          UPDATE notification_channels
          SET state = 'active', target = ${input.chatId},
              verified_at = ${now}::timestamptz, verification_hash = NULL,
              verification_expires_at = NULL
          WHERE channel_id = ${String(rows[0].channel_id)}`;
        return Object.freeze({
          status: "active" as const,
          accountId: String(rows[0].account_id),
        });
      });
    },

    async list(accountId: string): Promise<readonly NotificationChannel[]> {
      const rows = await sql`
        SELECT channel_id, kind, display, state, created_at
        FROM notification_channels
        WHERE account_id = ${accountId} AND state <> 'disabled'
        ORDER BY created_at`;
      return rows.map((row) => ({
        channelId: String(row.channel_id),
        kind: String(row.kind) as ChannelKind,
        display: String(row.display),
        state: String(row.state) as "pending" | "active" | "disabled",
        createdAt: new Date(row.created_at as Date).toISOString(),
      }));
    },

    async disable(accountId: string, channelId: string): Promise<boolean> {
      const rows = await sql`
        UPDATE notification_channels SET state = 'disabled'
        WHERE channel_id = ${channelId} AND account_id = ${accountId}
          AND state <> 'disabled'
        RETURNING channel_id`;
      return rows.length === 1;
    },

    async activeTargets(
      accountId: string,
    ): Promise<readonly { kind: ChannelKind; target: string }[]> {
      const rows = await sql`
        SELECT kind, target FROM notification_channels
        WHERE account_id = ${accountId} AND state = 'active'
          AND target IS NOT NULL`;
      return rows.map((row) => ({
        kind: String(row.kind) as ChannelKind,
        target: String(row.target),
      }));
    },
  });
}

function refused(reasonCode: string): CreateChannelResult {
  return Object.freeze({ status: "refused" as const, reasonCode });
}
