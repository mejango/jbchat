import type { Sql } from "postgres";
import {
  sendEmail,
  sendTelegram,
  type EmailConfig,
  type FetchLike,
} from "./senders";

/**
 * Best-effort out-of-band wakeups to a set of accounts' active channels
 * (email / Telegram). Browser web-push already fires from the keeper's
 * mailbox poll, so it is not repeated here. Only a "you have activity"
 * wakeup is sent — never message content — so nothing leaves the E2E
 * boundary. Every send is fail-soft: dispatch never throws into the
 * caller's request path.
 */

export type NotifyReason = "message" | "request";

export interface NotificationsConfig {
  readonly appOrigin: string;
  readonly email: EmailConfig | null;
  readonly telegram: { readonly botToken: string; readonly botUsername: string } | null;
}

export interface NotificationDispatcher {
  readonly dispatch: (
    accountIds: readonly string[],
    reason: NotifyReason,
    /** Scope for the cooldown, e.g. the conversation or project id. */
    dedupeKey?: string,
  ) => Promise<void>;
}

// One wakeup per (scope, recipient) per window: a burst chat must not
// become an email per message. ponytail: in-memory cooldown — a restart or
// second instance just means one extra wakeup, which is harmless for a
// best-effort channel; move to a table if instances multiply.
const COOLDOWN_MS = 15 * 60 * 1000;

function copyFor(
  reason: NotifyReason,
  appOrigin: string,
): { subject: string; text: string } {
  if (reason === "request") {
    return {
      subject: "Someone wants to reach you on Fruitful",
      text: `A customer requested a chat with your project. Open ${appOrigin} to accept it.`,
    };
  }
  return {
    subject: "New message on Fruitful",
    text: `You have a new message in one of your Fruitful chats. Open ${appOrigin} to read it.`,
  };
}

export function createNotificationDispatcher(context: {
  readonly sql: Sql;
  readonly config: NotificationsConfig;
  readonly fetchImpl?: FetchLike;
}): NotificationDispatcher {
  const { sql, config } = context;
  const fetchImpl = context.fetchImpl ?? globalThis.fetch;
  const lastSentAt = new Map<string, number>();

  return Object.freeze({
    async dispatch(
      accountIds: readonly string[],
      reason: NotifyReason,
      dedupeKey?: string,
    ): Promise<void> {
      const nowMs = Date.now();
      const unique = [...new Set(accountIds)].filter(Boolean).filter((id) => {
        if (!dedupeKey) return true;
        const key = `${dedupeKey}:${id}`;
        const last = lastSentAt.get(key) ?? 0;
        if (nowMs - last < COOLDOWN_MS) return false;
        lastSentAt.set(key, nowMs);
        return true;
      });
      if (lastSentAt.size > 10_000) {
        for (const [key, at] of lastSentAt) {
          if (nowMs - at >= COOLDOWN_MS) lastSentAt.delete(key);
        }
      }
      if (unique.length === 0) return;
      if (!config.email && !config.telegram) return;

      let rows: { account_id: unknown; kind: unknown; target: unknown }[];
      try {
        rows = await sql`
          SELECT account_id, kind, target FROM notification_channels
          WHERE account_id IN ${sql(unique)}
            AND state = 'active' AND target IS NOT NULL`;
      } catch {
        return;
      }

      const { subject, text } = copyFor(reason, config.appOrigin);
      await Promise.allSettled(
        rows.map((row) => {
          const kind = String(row.kind);
          const target = String(row.target);
          if (kind === "email" && config.email) {
            return sendEmail(config.email, { to: target, subject, text }, fetchImpl);
          }
          if (kind === "telegram" && config.telegram) {
            return sendTelegram(
              config.telegram.botToken,
              { chatId: target, text: `${subject}\n${text}` },
              fetchImpl,
            );
          }
          return Promise.resolve(false);
        }),
      );
    },
  });
}
