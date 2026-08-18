import { Buffer } from "node:buffer";
import { createCipheriv, createDecipheriv } from "node:crypto";
import type { ConversationCursorCodecPort } from "./ports";
import {
  CONVERSATION_CURSOR_PROFILE,
  CONVERSATION_EVENTS_ROUTE_TEMPLATE,
  parseConversationCursorContext,
  type ConversationCursorContext,
  type ConversationCursorPlaintext,
} from "./sync";

const CURSOR_AAD_DOMAIN = "jb-msg-conversation-cursor-aad/v1";
const CURSOR_PREFIX = "cc1.";
const CURSOR_MAX_CHARACTERS = 1_024;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const AUTHENTICATION_FAILED = Object.freeze({
  status: "invalid",
  reasonCode: "authentication-failed",
});

/**
 * Fenced RPO-0 nonce allocation: the returned 96-bit nonce must come from a
 * range whose fence and high-water mark were durably committed before use.
 * Restart, rollback, or ambiguity burns the unused remainder; a nonce is
 * never random-only, repeated, or reassigned under one key.
 */
export interface CursorNonceAllocatorPort {
  readonly allocate: () => Promise<Buffer>;
}

/**
 * The exact cc1 conversation-cursor codec (service-api.md cursor grammar):
 * AES-256-GCM over the length-prefixed plaintext with the route, realm,
 * authenticated account, installation, conversation, and key ID bound as
 * associated data. Decode output stays untrusted - the sync kernel's strict
 * claims parser re-validates every field - and every grammar, key, tag, or
 * binding failure collapses to one authenticated-rejection shape so the
 * error channel is non-oracular. An expired-but-authentic token still
 * returns its claims so the caller can distinguish cursor_expired from
 * invalid_cursor.
 */
export function createKeyedConversationCursorCodec(context: {
  readonly keyId: string;
  readonly key: Buffer;
  readonly nonceAllocator: CursorNonceAllocatorPort;
}): ConversationCursorCodecPort {
  if (!KEY_ID_PATTERN.test(context.keyId)) {
    throw new TypeError("The cursor key ID is not canonical.");
  }
  if (context.key.byteLength !== 32) {
    throw new TypeError("The cursor key must be 32 bytes.");
  }
  const keyIdBytes = Buffer.from(context.keyId, "ascii");

  const aadFor = (cursorContext: ConversationCursorContext): Buffer =>
    Buffer.concat([
      Buffer.from(CURSOR_AAD_DOMAIN, "ascii"),
      lengthPrefixed(cursorContext.realmId),
      lengthPrefixed(cursorContext.accountId),
      lengthPrefixed(cursorContext.installationId),
      lengthPrefixed(cursorContext.conversationId),
      lengthPrefixed(`GET ${CONVERSATION_EVENTS_ROUTE_TEMPLATE}`),
      lengthPrefixed(context.keyId),
    ]);

  return Object.freeze({
    async encode(input: {
      plaintext: ConversationCursorPlaintext;
      context: ConversationCursorContext;
      deadline: string;
      signal: AbortSignal;
    }): Promise<unknown> {
      const cursorContext = parseConversationCursorContext(input.context);
      const plaintext = input.plaintext;
      if (
        plaintext.keyId !== context.keyId ||
        plaintext.realmId !== cursorContext.realmId ||
        plaintext.installationId !== cursorContext.installationId ||
        plaintext.conversationId !== cursorContext.conversationId
      ) {
        throw new TypeError("Cursor plaintext does not bind its context.");
      }
      const body = Buffer.concat([
        Buffer.of(1),
        lengthPrefixed(plaintext.realmId),
        lengthPrefixed(plaintext.conversationId),
        lengthPrefixed(plaintext.installationId),
        u64be(BigInt(plaintext.lastReturnedPosition)),
        u64be(BigInt(Date.parse(plaintext.issuedAt))),
        u64be(BigInt(Date.parse(plaintext.expiresAt))),
        lengthPrefixed(plaintext.keyId),
      ]);
      const nonce = await context.nonceAllocator.allocate();
      if (nonce.byteLength !== 12) {
        throw new TypeError("The cursor nonce must be 96 bits.");
      }
      const cipher = createCipheriv("aes-256-gcm", context.key, nonce);
      cipher.setAAD(aadFor(cursorContext));
      const ciphertext = Buffer.concat([cipher.update(body), cipher.final()]);
      const blob = Buffer.concat([
        Buffer.of(1),
        Buffer.of(keyIdBytes.byteLength),
        keyIdBytes,
        nonce,
        ciphertext,
        cipher.getAuthTag(),
      ]);
      const encodedCursor = `${CURSOR_PREFIX}${blob.toString("base64url")}`;
      if (encodedCursor.length > CURSOR_MAX_CHARACTERS) {
        throw new TypeError("The encoded cursor exceeds its ceiling.");
      }
      return Object.freeze({ status: "encoded", encodedCursor });
    },

    async decode(input: {
      encodedCursor: string;
      context: ConversationCursorContext;
      now: string;
      deadline: string;
      signal: AbortSignal;
    }): Promise<unknown> {
      const cursorContext = parseConversationCursorContext(input.context);
      const token = input.encodedCursor;
      if (
        typeof token !== "string" ||
        token.length > CURSOR_MAX_CHARACTERS ||
        !token.startsWith(CURSOR_PREFIX)
      ) {
        return AUTHENTICATION_FAILED;
      }
      const encodedBlob = token.slice(CURSOR_PREFIX.length);
      if (!/^[A-Za-z0-9_-]+$/.test(encodedBlob)) {
        return AUTHENTICATION_FAILED;
      }
      const blob = Buffer.from(encodedBlob, "base64url");
      if (blob.toString("base64url") !== encodedBlob) {
        return AUTHENTICATION_FAILED;
      }
      if (blob.byteLength < 2 + 1 + 12 + 16) return AUTHENTICATION_FAILED;
      if (blob[0] !== 1) return AUTHENTICATION_FAILED;
      const keyIdLength = blob[1];
      if (
        keyIdLength < 1 ||
        keyIdLength > 64 ||
        blob.byteLength < 2 + keyIdLength + 12 + 16
      ) {
        return AUTHENTICATION_FAILED;
      }
      const clearKeyId = blob.subarray(2, 2 + keyIdLength).toString("ascii");
      if (clearKeyId !== context.keyId) return AUTHENTICATION_FAILED;
      const nonce = blob.subarray(2 + keyIdLength, 2 + keyIdLength + 12);
      const tag = blob.subarray(blob.byteLength - 16);
      const ciphertext = blob.subarray(2 + keyIdLength + 12, blob.byteLength - 16);
      let body: Buffer;
      try {
        const decipher = createDecipheriv("aes-256-gcm", context.key, nonce);
        decipher.setAAD(aadFor(cursorContext));
        decipher.setAuthTag(tag);
        body = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        return AUTHENTICATION_FAILED;
      }
      const reader = new ByteReader(body);
      try {
        if (reader.u8() !== 1) return AUTHENTICATION_FAILED;
        const realmId = reader.lengthPrefixedAscii();
        const conversationId = reader.lengthPrefixedAscii();
        const installationId = reader.lengthPrefixedAscii();
        const lastReturnedPosition = reader.u64be();
        const issuedAtMilliseconds = reader.u64be();
        const expiresAtMilliseconds = reader.u64be();
        const encryptedKeyId = reader.lengthPrefixedAscii();
        reader.expectExhausted();
        if (
          realmId !== cursorContext.realmId ||
          conversationId !== cursorContext.conversationId ||
          installationId !== cursorContext.installationId ||
          encryptedKeyId !== clearKeyId
        ) {
          return AUTHENTICATION_FAILED;
        }
        return Object.freeze({
          kind: "conversation-cursor-claims.v1",
          profile: CONVERSATION_CURSOR_PROFILE,
          encodedCursor: token,
          realmId,
          accountId: cursorContext.accountId,
          installationId,
          conversationId,
          routeTemplate: CONVERSATION_EVENTS_ROUTE_TEMPLATE,
          lastReturnedPosition: String(lastReturnedPosition),
          issuedAt: new Date(Number(issuedAtMilliseconds)).toISOString(),
          expiresAt: new Date(Number(expiresAtMilliseconds)).toISOString(),
          keyId: encryptedKeyId,
          authenticated: true,
        });
      } catch {
        return AUTHENTICATION_FAILED;
      }
    },
  });
}

/** In-memory fenced counter for offline tests only - not RPO-0 durable. */
export function createInMemoryCursorNonceAllocatorForTesting(
  start = 1n,
): CursorNonceAllocatorPort {
  let next = start;
  return Object.freeze({
    allocate: async () => {
      const nonce = Buffer.alloc(12);
      nonce.writeBigUInt64BE(next, 4);
      next += 1n;
      return nonce;
    },
  });
}

function lengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

function u64be(value: bigint): Buffer {
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new TypeError("Value is outside the unsigned 64-bit range.");
  }
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(value);
  return bytes;
}

class ByteReader {
  private offset = 0;
  constructor(private readonly bytes: Buffer) {}

  u8(): number {
    if (this.offset + 1 > this.bytes.byteLength) throw new RangeError("short");
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value;
  }

  u64be(): bigint {
    if (this.offset + 8 > this.bytes.byteLength) throw new RangeError("short");
    const value = this.bytes.readBigUInt64BE(this.offset);
    this.offset += 8;
    return value;
  }

  lengthPrefixedAscii(): string {
    if (this.offset + 4 > this.bytes.byteLength) throw new RangeError("short");
    const length = this.bytes.readUInt32BE(this.offset);
    this.offset += 4;
    if (this.offset + length > this.bytes.byteLength) {
      throw new RangeError("short");
    }
    const value = this.bytes
      .subarray(this.offset, this.offset + length)
      .toString("ascii");
    this.offset += length;
    return value;
  }

  expectExhausted(): void {
    if (this.offset !== this.bytes.byteLength) {
      throw new RangeError("trailing bytes");
    }
  }
}
