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
  ) => Promise<void>;
}

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

  return Object.freeze({
    async dispatch(
      accountIds: readonly string[],
      reason: NotifyReason,
    ): Promise<void> {
      const unique = [...new Set(accountIds)].filter(Boolean);
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
