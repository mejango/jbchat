import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  createInMemoryCursorNonceAllocatorForTesting,
  createKeyedConversationCursorCodec,
} from "./conversationCursorCodec";
import { fictionalDeliveryLimits } from "./fixtures.testing";
import {
  CONVERSATION_CURSOR_PROFILE,
  CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  parseConversationCursorClaims,
  type ConversationCursorContext,
  type ConversationCursorPlaintext,
} from "./sync";
import { parseRfc3339Millis } from "./valueObjects";

const KEY_ID = "cursor-key-2026q3";
const KEY = Buffer.alloc(32, 0x4d);
const NOW = parseRfc3339Millis("2026-08-14T16:21:00.000Z");
const CONTEXT = {
  realmId: "fictional-lab",
  accountId: "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
  installationId: "5ec2d18e-f082-48f0-8b01-55e43fed021c",
  conversationId: "0f5f0d0a-95a5-4c7e-b3a5-b64ec91b0f96",
  routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
} as unknown as ConversationCursorContext;

const PLAINTEXT = {
  kind: "conversation-cursor-claims.v1",
  profile: CONVERSATION_CURSOR_PROFILE,
  realmId: CONTEXT.realmId,
  installationId: CONTEXT.installationId,
  conversationId: CONTEXT.conversationId,
  lastReturnedPosition: "7",
  issuedAt: "2026-08-14T16:20:45.123Z",
  expiresAt: "2026-08-15T16:20:45.123Z",
  keyId: KEY_ID,
} as unknown as ConversationCursorPlaintext;

function codec() {
  return createKeyedConversationCursorCodec({
    keyId: KEY_ID,
    key: KEY,
    nonceAllocator: createInMemoryCursorNonceAllocatorForTesting(),
  });
}

function invocation() {
  return {
    deadline: parseRfc3339Millis("2026-08-14T16:22:00.000Z"),
    signal: new AbortController().signal,
  };
}

async function encodeToken(): Promise<string> {
  const encoded = (await codec().encode({
    plaintext: PLAINTEXT,
    context: CONTEXT,
    ...invocation(),
  })) as { status: string; encodedCursor: string };
  expect(encoded.status).toBe("encoded");
  return encoded.encodedCursor;
}

describe("cc1 conversation cursor codec", () => {
  it("round-trips through the sync kernel's strict claims parser", async () => {
    const token = await encodeToken();
    expect(token.startsWith("cc1.")).toBe(true);
    expect(token.length).toBeGreaterThanOrEqual(43);
    const raw = await codec().decode({
      encodedCursor: token,
      context: CONTEXT,
      now: NOW,
      ...invocation(),
    });
    const claims = parseConversationCursorClaims(raw, {
      encodedCursor: token,
      context: CONTEXT,
      now: NOW,
      limits: fictionalDeliveryLimits(),
    });
    expect(claims.lastReturnedPosition).toBe("7");
    expect(claims.accountId).toBe(CONTEXT.accountId);
    expect(claims.keyId).toBe(KEY_ID);
    expect(claims.authenticated).toBe(true);
  });

  it("collapses every grammar, tag, and binding failure to one rejection", async () => {
    const token = await encodeToken();
    const rejection = { status: "invalid", reasonCode: "authentication-failed" };
    const attempt = (encodedCursor: string, context = CONTEXT) =>
      codec().decode({ encodedCursor, context, now: NOW, ...invocation() });

    expect(await attempt("cc2." + token.slice(4))).toEqual(rejection);
    expect(await attempt(token.slice(0, -2))).toEqual(rejection);
    expect(
      await attempt(token.slice(0, -1) + (token.endsWith("A") ? "B" : "A")),
    ).toEqual(rejection);
    expect(await attempt(`${token}==`)).toEqual(rejection);
    expect(
      await attempt(token, {
        ...CONTEXT,
        conversationId: "1f5f0d0a-95a5-4c7e-b3a5-b64ec91b0f96",
      } as unknown as ConversationCursorContext),
    ).toEqual(rejection);
    expect(
      await attempt(token, {
        ...CONTEXT,
        accountId: "8f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
      } as unknown as ConversationCursorContext),
    ).toEqual(rejection);
  });

  it("returns authenticated claims for an expired token so 410 stays distinguishable", async () => {
    const token = await encodeToken();
    const raw = await codec().decode({
      encodedCursor: token,
      context: CONTEXT,
      now: parseRfc3339Millis("2026-08-16T16:21:00.000Z"),
      ...invocation(),
    });
    expect((raw as { authenticated?: boolean }).authenticated).toBe(true);
    expect(() =>
      parseConversationCursorClaims(raw, {
        encodedCursor: token,
        context: CONTEXT,
        now: parseRfc3339Millis("2026-08-16T16:21:00.000Z"),
        limits: fictionalDeliveryLimits(),
      }),
    ).toThrow();
  });

  it("never repeats a nonce across encodes under one key", async () => {
    const shared = codec();
    const tokens = new Set<string>();
    const nonces = new Set<string>();
    for (let index = 0; index < 32; index += 1) {
      const encoded = (await shared.encode({
        plaintext: PLAINTEXT,
        context: CONTEXT,
        ...invocation(),
      })) as { encodedCursor: string };
      tokens.add(encoded.encodedCursor);
      const blob = Buffer.from(encoded.encodedCursor.slice(4), "base64url");
      nonces.add(blob.subarray(2 + KEY_ID.length, 2 + KEY_ID.length + 12).toString("hex"));
    }
    expect(tokens.size).toBe(32);
    expect(nonces.size).toBe(32);
  });
});
