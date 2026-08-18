import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import type { CursorNonceAllocatorPort } from "../delivery/conversationCursorCodec";

const DEFAULT_RANGE_SIZE = 1_024;

/**
 * Fenced RPO-0 nonce allocation over cursor_nonce_ranges: each refill
 * durably commits a bumped fence and advanced high-water mark before any
 * nonce from the new range is handed out, and every allocator instance
 * (process restart, lease change) starts a fresh fenced range strictly
 * above the previous high water, burning whatever the prior holder left
 * unused. The 96-bit nonce is fence || counter, so even a duplicated
 * counter under an impossible fence collision cannot repeat bytes.
 */
export function createPostgresCursorNonceAllocator(context: {
  readonly sql: Sql;
  readonly keyId: string;
  readonly rangeSize?: number;
}): CursorNonceAllocatorPort {
  const rangeSize = context.rangeSize ?? DEFAULT_RANGE_SIZE;
  if (!Number.isSafeInteger(rangeSize) || rangeSize < 1) {
    throw new TypeError("The nonce range size must be a positive integer.");
  }
  let fence = 0n;
  let next = 0n;
  let ceiling = 0n;
  let refilling: Promise<void> | null = null;

  const refill = async (): Promise<void> => {
    const rows = await context.sql`
      INSERT INTO cursor_nonce_ranges (key_id, fence, high_water, updated_at)
      VALUES (${context.keyId}, 1, ${rangeSize}, delivery_db_now())
      ON CONFLICT (key_id) DO UPDATE SET
        fence = cursor_nonce_ranges.fence + 1,
        high_water = cursor_nonce_ranges.high_water + ${rangeSize},
        updated_at = delivery_db_now()
      RETURNING fence, high_water`;
    const row = rows[0];
    fence = BigInt(String(row.fence));
    ceiling = BigInt(String(row.high_water));
    next = ceiling - BigInt(rangeSize);
  };

  return Object.freeze({
    allocate: async (): Promise<Buffer> => {
      while (next >= ceiling) {
        refilling ??= refill().finally(() => {
          refilling = null;
        });
        await refilling;
      }
      const counter = next;
      next += 1n;
      const nonce = Buffer.alloc(12);
      nonce.writeUInt32BE(Number(fence & 0xffffffffn));
      nonce.writeBigUInt64BE(counter, 4);
      return nonce;
    },
  });
}
