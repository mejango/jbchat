/**
 * Out-of-band notification senders. Each is a thin, fail-soft wrapper over a
 * provider HTTP API: a send never throws into the caller's request path (a
 * notification is best-effort), it returns ok/failure. WhatsApp is present
 * as a declared-but-unwired adapter until a Business API provider is chosen.
 */

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

const TIMEOUT_MS = 8000;

async function post(
  fetchImpl: FetchLike,
  url: string,
  headers: Record<string, string>,
  body: unknown,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export interface EmailConfig {
  readonly apiKey: string;
  /** e.g. "Fruitful <notifications@fruitful.chat>". */
  readonly from: string;
}

/** Send a transactional email via Resend. */
export async function sendEmail(
  config: EmailConfig,
  message: { to: string; subject: string; text: string },
  fetchImpl: FetchLike = globalThis.fetch,
): Promise<boolean> {
  return post(
    fetchImpl,
    "https://api.resend.com/emails",
    { Authorization: `Bearer ${config.apiKey}` },
    {
      from: config.from,
      to: [message.to],
      subject: message.subject,
      text: message.text,
    },
  );
}

/** Send a Telegram message via the Bot API. */
export async function sendTelegram(
  botToken: string,
  message: { chatId: string; text: string },
  fetchImpl: FetchLike = globalThis.fetch,
): Promise<boolean> {
  return post(
    fetchImpl,
    `https://api.telegram.org/bot${botToken}/sendMessage`,
    {},
    { chat_id: message.chatId, text: message.text, disable_web_page_preview: true },
  );
}

/** The deep link a user taps to bind their Telegram chat to a channel. */
export function telegramDeepLink(botUsername: string, token: string): string {
  const handle = botUsername.replace(/^@/, "");
  return `https://t.me/${handle}?start=${token}`;
}

/** WhatsApp is declared but unwired; sends are a no-op until a provider is set. */
export async function sendWhatsApp(): Promise<boolean> {
  return false;
}
