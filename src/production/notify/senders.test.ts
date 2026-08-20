import { describe, expect, it } from "vitest";
import {
  sendEmail,
  sendTelegram,
  sendWhatsApp,
  telegramDeepLink,
  type FetchLike,
} from "./senders";

function capturingFetch(ok: boolean): {
  fetch: FetchLike;
  calls: { url: string; body: unknown; headers: Record<string, string> }[];
} {
  const calls: { url: string; body: unknown; headers: Record<string, string> }[] =
    [];
  const fetch: FetchLike = async (input, init) => {
    calls.push({
      url: String(input),
      body: JSON.parse(String(init?.body ?? "{}")),
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    return new Response(null, { status: ok ? 200 : 500 });
  };
  return { fetch, calls };
}

describe("notification senders", () => {
  it("posts a Resend email with the configured from + bearer key", async () => {
    const { fetch, calls } = capturingFetch(true);
    const ok = await sendEmail(
      { apiKey: "re_test", from: "Fruitful <n@fruitful.chat>" },
      { to: "user@example.com", subject: "New message", text: "You have activity." },
      fetch,
    );
    expect(ok).toBe(true);
    expect(calls[0].url).toBe("https://api.resend.com/emails");
    expect(calls[0].headers.Authorization).toBe("Bearer re_test");
    expect(calls[0].body).toMatchObject({
      from: "Fruitful <n@fruitful.chat>",
      to: ["user@example.com"],
      subject: "New message",
    });
  });

  it("posts a Telegram message to the bot sendMessage endpoint", async () => {
    const { fetch, calls } = capturingFetch(true);
    const ok = await sendTelegram(
      "123:abc",
      { chatId: "555", text: "hi" },
      fetch,
    );
    expect(ok).toBe(true);
    expect(calls[0].url).toBe("https://api.telegram.org/bot123:abc/sendMessage");
    expect(calls[0].body).toMatchObject({ chat_id: "555", text: "hi" });
  });

  it("fails soft (returns false, never throws) on a provider error", async () => {
    const { fetch } = capturingFetch(false);
    await expect(
      sendEmail({ apiKey: "k", from: "f" }, { to: "a@b.c", subject: "s", text: "t" }, fetch),
    ).resolves.toBe(false);
  });

  it("builds a Telegram deep link, stripping a leading @", () => {
    expect(telegramDeepLink("@FruitfulBot", "tok123")).toBe(
      "https://t.me/FruitfulBot?start=tok123",
    );
  });

  it("whatsapp is unwired (no-op false)", async () => {
    await expect(sendWhatsApp()).resolves.toBe(false);
  });
});
