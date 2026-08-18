import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { createPostgresCursorNonceAllocator } from "./cursorNonceAllocator";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const KEY_ID = "fictional-cursor-key-2026q3";

describeStorage("fenced cursor nonce allocation", () => {
  let sql: Sql;

  beforeAll(() => {
    sql = postgres(DATABASE_URL!, { max: 6, onnotice: () => {} });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("hands out unique nonces and burns the remainder on a new holder", async () => {
    const first = createPostgresCursorNonceAllocator({
      sql,
      keyId: KEY_ID,
      rangeSize: 8,
    });
    const seen = new Set<string>();
    for (let index = 0; index < 12; index += 1) {
      seen.add((await first.allocate()).toString("hex"));
    }
    expect(seen.size).toBe(12);

    // A new holder (restart / lease change) must burn the prior remainder:
    // its whole fenced range sits strictly above the durable high water.
    const second = createPostgresCursorNonceAllocator({
      sql,
      keyId: KEY_ID,
      rangeSize: 8,
    });
    for (let index = 0; index < 12; index += 1) {
      const nonce = (await second.allocate()).toString("hex");
      expect(seen.has(nonce)).toBe(false);
      seen.add(nonce);
    }
    expect(seen.size).toBe(24);

    const concurrent = await Promise.all(
      Array.from({ length: 40 }, () => second.allocate()),
    );
    for (const nonce of concurrent) {
      expect(seen.has(nonce.toString("hex"))).toBe(false);
      seen.add(nonce.toString("hex"));
    }
    expect(seen.size).toBe(64);

    const [range] = await sql`
      SELECT fence, high_water FROM cursor_nonce_ranges
      WHERE key_id = ${KEY_ID}`;
    expect(Number(range.fence)).toBeGreaterThanOrEqual(2);
    expect(Number(range.high_water) % 8).toBe(0);
  });
});
