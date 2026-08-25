import { Buffer } from "node:buffer";
import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { createNotificationChannelStore } from "./notificationChannelStore";
import { createNotificationDispatcher } from "../notify/notificationDispatch";
import type { FetchLike } from "../notify/senders";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-20T12:00:00.000Z";

// Self-contained fixture ids (a4xx) so this shares the lab DB cleanly.
const ACCOUNT_A = "00000000-0000-4000-8000-00000000a401";
const ACCOUNT_B = "00000000-0000-4000-8000-00000000a402";

describeStorage("notification channels", () => {
  let sql: Sql;
  const hmacSecret = (secret: string) =>
    createHmac("sha256", Buffer.alloc(32, 0x9a)).update(secret).digest();
  const store = () =>
    createNotificationChannelStore({ sql, hmacSecret, now: () => NOW });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 2, onnotice: () => {} });
    await sql`
      INSERT INTO accounts (account_id, status, created_at) VALUES
        (${ACCOUNT_A}, 'active', ${NOW}::timestamptz),
        (${ACCOUNT_B}, 'active', ${NOW}::timestamptz)`;
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("creates an email channel, rejects a wrong code, verifies the right one", async () => {
    const created = await store().createChannel({
      accountId: ACCOUNT_A,
      kind: "email",
      target: "Owner@Example.com",
    });
    if (created.status !== "created") throw new Error(created.reasonCode);
    expect(created.secret).toMatch(/^\d{6}$/);

    const wrong = await store().verifyEmailCode({
      accountId: ACCOUNT_A,
      channelId: created.channelId,
      code: "000000",
    });
    expect(wrong.status).toBe("invalid");

    const right = await store().verifyEmailCode({
      accountId: ACCOUNT_A,
      channelId: created.channelId,
      code: created.secret,
    });
    expect(right.status).toBe("active");

    const channels = await store().list(ACCOUNT_A);
    const email = channels.find((c) => c.kind === "email");
    expect(email).toMatchObject({ state: "active", display: "owner@example.com" });

    const targets = await store().activeTargets(ACCOUNT_A);
    expect(targets).toContainEqual({ kind: "email", target: "owner@example.com" });
  });

  it("refuses a duplicate active email", async () => {
    const dup = await store().createChannel({
      accountId: ACCOUNT_A,
      kind: "email",
      target: "owner@example.com",
    });
    expect(dup).toMatchObject({ status: "refused", reasonCode: "already_active" });
  });

  it("links Telegram by redeeming the /start token", async () => {
    const created = await store().createChannel({
      accountId: ACCOUNT_B,
      kind: "telegram",
      target: "telegram",
    });
    if (created.status !== "created") throw new Error(created.reasonCode);

    const bad = await store().redeemTelegramToken({
      token: "not-the-token",
      chatId: "999",
    });
    expect(bad.status).toBe("not_found");

    const ok = await store().redeemTelegramToken({
      token: created.secret,
      chatId: "555123",
    });
    expect(ok).toEqual({ status: "active", accountId: ACCOUNT_B });

    const targets = await store().activeTargets(ACCOUNT_B);
    expect(targets).toContainEqual({ kind: "telegram", target: "555123" });
  });

  it("disables a channel and drops it from the active set", async () => {
    const channels = await store().list(ACCOUNT_B);
    const telegram = channels.find((c) => c.kind === "telegram")!;
    expect(await store().disable(ACCOUNT_B, telegram.channelId)).toBe(true);
    const after = await store().activeTargets(ACCOUNT_B);
    expect(after.some((t) => t.kind === "telegram")).toBe(false);
  });

  it("dispatches to an account's active channels (email + telegram)", async () => {
    // ACCOUNT_A has an active email; give it an active telegram too.
    const created = await store().createChannel({
      accountId: ACCOUNT_A,
      kind: "telegram",
      target: "telegram",
    });
    if (created.status !== "created") throw new Error(created.reasonCode);
    await store().redeemTelegramToken({ token: created.secret, chatId: "777" });

    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      calls.push(String(url));
      return new Response(null, { status: 200 });
    };
    const dispatcher = createNotificationDispatcher({
      sql,
      config: {
        appOrigin: "https://fruitful.chat",
        email: { apiKey: "k", from: "Fruitful <n@fruitful.chat>" },
        telegram: { botToken: "123:abc", botUsername: "FruitfulBot" },
      },
      fetchImpl,
    });
    await dispatcher.dispatch([ACCOUNT_A], "message", "conv-1");
    expect(calls).toContain("https://api.resend.com/emails");
    expect(calls).toContain("https://api.telegram.org/bot123:abc/sendMessage");

    // Same scope inside the cooldown window: no second wakeup.
    const sent = calls.length;
    await dispatcher.dispatch([ACCOUNT_A], "message", "conv-1");
    expect(calls.length).toBe(sent);
    // A different scope still notifies.
    await dispatcher.dispatch([ACCOUNT_A], "message", "conv-2");
    expect(calls.length).toBeGreaterThan(sent);
  });
});
