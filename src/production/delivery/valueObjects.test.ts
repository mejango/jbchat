import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  DELIVERY_CURSOR_MIN_CHARACTERS,
  DELIVERY_EVENT_JSON_METADATA_OVERHEAD_BYTES,
  DELIVERY_PAGE_JSON_FIXED_OVERHEAD_BYTES,
  DELIVERY_TESTED_CEILINGS,
  canonicalBase64UrlEncodedLength,
  minimumSerializedDeliveryPageBytes,
  parseDeliveryLimits,
} from "./limits";
import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  UINT63_MAX_VALUE,
  UINT63_MAX_STRING,
  ZERO_HASH32,
  copyBytes,
  decodeHash32,
  expectExactRecord,
  formatConversationEtag,
  parseAccountId,
  parseAttachmentId,
  parseCanonicalBase64Url,
  parseCanonicalBase64UrlBytes,
  parseConversationEtag,
  parseConversationId,
  parseCredentialId,
  parseEd25519Signature,
  parseEnvelopeClass,
  parseEnvelopeContentType,
  parseEnvelopeId,
  parseEnvelopeSender,
  parseFingerprint32,
  parseHash32,
  parseIdempotencyKey,
  parseInstallationId,
  parseMembershipIntentId,
  parsePolicyHeadId,
  parsePositiveUint63String,
  parseProposalId,
  parseRaw32,
  parseReleaseProfileId,
  parseRequestId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63BigInt,
  parseUint63String,
  parseUuidV4,
  parseUuidV7,
  parseWitnessCheckpointId,
  uint63FromBigInt,
  uint63ToBigInt,
} from "./valueObjects";

const UUID_V4 = "123e4567-e89b-42d3-a456-426614174000";
const UUID_V4_B = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const UUID_V7 = "0195e5c1-a7d0-7d6a-a521-256e257df384";
const RAW32 = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString(
  "base64url",
);
const RAW64 = Buffer.alloc(64, 0xa5).toString("base64url");

describe("Delivery Service value objects", () => {
  it("requires exact lowercase RFC-variant UUIDv4 and UUIDv7 classes", () => {
    expect(parseUuidV4(UUID_V4)).toBe(UUID_V4);
    expect(parseUuidV7(UUID_V7)).toBe(UUID_V7);

    for (const parse of [
      parseAccountId,
      parseAttachmentId,
      parseConversationId,
      parseCredentialId,
      parseEnvelopeId,
      parseInstallationId,
      parsePolicyHeadId,
      parseWitnessCheckpointId,
    ]) {
      expect(parse(UUID_V4)).toBe(UUID_V4);
      expect(() => parse(UUID_V7)).toThrow();
    }
    for (const parse of [
      parseMembershipIntentId,
      parseProposalId,
      parseRequestId,
    ]) {
      expect(parse(UUID_V7)).toBe(UUID_V7);
      expect(() => parse(UUID_V4)).toThrow();
    }

    for (const value of [
      UUID_V4.toUpperCase(),
      ` ${UUID_V4}`,
      UUID_V4.replace("-4", "-6"),
      UUID_V4.replace("-a", "-7"),
      "00000000-0000-0000-0000-000000000000",
    ]) {
      expect(() => parseUuidV4(value)).toThrow();
    }
    for (const value of [
      UUID_V7.toUpperCase(),
      UUID_V7.replace("-7", "-4"),
      UUID_V7.replace("-a521-", "-f521-"),
      `${UUID_V7}\n`,
    ]) {
      expect(() => parseUuidV7(value)).toThrow();
    }
  });

  it("does not reinterpret a wrong-version UUID as an entropic idempotency key", () => {
    expect(parseIdempotencyKey(UUID_V7)).toBe(UUID_V7);
    expect(parseIdempotencyKey(Buffer.alloc(16, 0x5a).toString("base64url"))).toBe(
      Buffer.alloc(16, 0x5a).toString("base64url"),
    );
    for (const value of [
      UUID_V4,
      UUID_V7.toUpperCase(),
      UUID_V7.replace("-7", "-6"),
      Buffer.alloc(15).toString("base64url"),
      `${Buffer.alloc(16).toString("base64url")}=`,
    ]) {
      expect(() => parseIdempotencyKey(value)).toThrow();
    }
  });

  it("keeps service counters canonical and outside JavaScript number APIs", () => {
    expect(parseUint63String("0")).toBe("0");
    expect(parseUint63String(UINT63_MAX_STRING)).toBe(UINT63_MAX_STRING);
    expect(parseUint63String("7", "counter", { minimum: 7n, maximum: 7n })).toBe(
      "7",
    );
    expect(parsePositiveUint63String("1")).toBe("1");
    expect(parseUint63BigInt(UINT63_MAX_VALUE)).toBe(UINT63_MAX_VALUE);
    expect(uint63ToBigInt(UINT63_MAX_STRING)).toBe(UINT63_MAX_VALUE);
    expect(uint63FromBigInt(UINT63_MAX_VALUE)).toBe(UINT63_MAX_STRING);

    for (const value of [
      "",
      "00",
      "01",
      "+1",
      "-1",
      "1.0",
      "1e3",
      " 1",
      1,
      1n,
      (UINT63_MAX_VALUE + 1n).toString(),
    ]) {
      expect(() => parseUint63String(value)).toThrow();
    }
    expect(() => parsePositiveUint63String("0")).toThrow();
    expect(() => parseUint63String("6", "counter", { minimum: 7n })).toThrow();
    expect(() =>
      parseUint63String("1", "counter", {
        minimum: 2n,
        maximum: 1n,
      }),
    ).toThrow();
    expect(() => parseUint63BigInt(1)).toThrow();
  });

  it("requires real UTC RFC3339 instants at exact millisecond precision", () => {
    expect(parseRfc3339Millis("2024-02-29T00:00:00.000Z")).toBe(
      "2024-02-29T00:00:00.000Z",
    );
    for (const value of [
      "2023-02-29T00:00:00.000Z",
      "2026-08-14T12:00:00Z",
      "2026-08-14T12:00:00.000z",
      "2026-08-14T12:00:00.000+00:00",
      "2026-08-14T12:00:00.0000Z",
      " 2026-08-14T12:00:00.000Z",
      new Date("2026-08-14T12:00:00.000Z"),
    ]) {
      expect(() => parseRfc3339Millis(value)).toThrow();
    }
  });

  it("parses only exact strong conversation ETags with uint63 components", () => {
    expect(parseConversationEtag('"e0-r0"')).toBe('"e0-r0"');
    expect(
      parseConversationEtag(`"e${UINT63_MAX_STRING}-r${UINT63_MAX_STRING}"`),
    ).toBe(`"e${UINT63_MAX_STRING}-r${UINT63_MAX_STRING}"`);
    expect(
      formatConversationEtag(
        parseUint63String("19"),
        parseUint63String("27"),
      ),
    ).toBe('"e19-r27"');

    for (const value of [
      "e19-r27",
      'W/"e19-r27"',
      '"e019-r27"',
      '"e19-r027"',
      `"e${UINT63_MAX_VALUE + 1n}-r0"`,
      '"e19-r27" ',
      19,
    ]) {
      expect(() => parseConversationEtag(value)).toThrow();
    }
  });

  it("strictly validates raw32 values, fingerprints, signatures, and tail bits", () => {
    expect(parseHash32(RAW32)).toBe(RAW32);
    expect(parseFingerprint32(RAW32)).toBe(RAW32);
    expect(parseRaw32(RAW32)).toBe(RAW32);
    expect(parseEd25519Signature(RAW64)).toBe(RAW64);
    expect(parseHash32(ZERO_HASH32)).toBe(ZERO_HASH32);

    for (const value of [
      `${RAW32}=`,
      ` ${RAW32}`,
      `${RAW32.slice(0, -1)}+`,
      Buffer.alloc(31).toString("base64url"),
      Buffer.alloc(33).toString("base64url"),
      `${"A".repeat(42)}B`,
    ]) {
      expect(() => parseHash32(value)).toThrow();
    }
    expect(() => parseEd25519Signature(RAW32)).toThrow();
  });

  it("returns owned byte copies while retaining immutable canonical wire strings", () => {
    const first = parseCanonicalBase64UrlBytes(RAW32, "bytes", {
      minBytes: 32,
      maxBytes: 32,
    });
    const second = decodeHash32(parseHash32(RAW32));
    first[0] = 0xff;
    expect(second[0]).toBe(0);
    expect(decodeHash32(parseHash32(RAW32))[0]).toBe(0);

    const source = Uint8Array.of(1, 2, 3);
    const copied = copyBytes(source);
    source[0] = 9;
    copied[1] = 8;
    expect([...copied]).toEqual([1, 8, 3]);
    expect([...source]).toEqual([9, 2, 3]);
    expect(parseCanonicalBase64Url("AQID", "bytes")).toBe("AQID");
    expect(() => parseCanonicalBase64Url("AQI=", "bytes")).toThrow();

    const buffer = Buffer.from([4, 5, 6]);
    const copiedBuffer = copyBytes(buffer);
    buffer[0] = 9;
    expect([...copiedBuffer]).toEqual([4, 5, 6]);
    expect(Object.getPrototypeOf(copiedBuffer)).toBe(Uint8Array.prototype);
  });

  it("copies with typed-array internal slots and rejects iterator/proxy/view tricks", () => {
    let iteratorCalled = false;
    const customIterator = Uint8Array.of(1);
    Object.defineProperty(customIterator, Symbol.iterator, {
      configurable: true,
      value: function* iterator(): Generator<number> {
        iteratorCalled = true;
        for (let index = 0; index < 100_000; index += 1) yield 0xff;
      },
    });
    expect(() => copyBytes(customIterator, "custom iterator", 1)).toThrow();
    expect(iteratorCalled).toBe(false);

    class ByteSubclass extends Uint8Array {}
    expect(() => copyBytes(new ByteSubclass(1))).toThrow();
    const proxyTrapCalls = {
      get: 0,
      getOwnPropertyDescriptor: 0,
      getPrototypeOf: 0,
    };
    const proxied = new Proxy(Uint8Array.of(1), {
      get() {
        proxyTrapCalls.get += 1;
        return undefined;
      },
      getOwnPropertyDescriptor() {
        proxyTrapCalls.getOwnPropertyDescriptor += 1;
        return undefined;
      },
      getPrototypeOf() {
        proxyTrapCalls.getPrototypeOf += 1;
        return Uint8Array.prototype;
      },
    });
    expect(() => copyBytes(proxied)).toThrow();
    expect(proxyTrapCalls).toEqual({
      get: 0,
      getOwnPropertyDescriptor: 0,
      getPrototypeOf: 0,
    });

    const spoofedLength = Uint8Array.of(1, 2);
    let lengthAccessorCalled = false;
    Object.defineProperty(spoofedLength, "byteLength", {
      configurable: true,
      get() {
        lengthAccessorCalled = true;
        return 0;
      },
    });
    expect(() => copyBytes(spoofedLength)).toThrow();
    expect(lengthAccessorCalled).toBe(false);

    expect(() =>
      copyBytes(new Uint8Array(new SharedArrayBuffer(1))),
    ).toThrow();

    const ResizableArrayBuffer = ArrayBuffer as unknown as new (
      byteLength: number,
      options: { readonly maxByteLength: number },
    ) => ArrayBuffer;
    const resizable = new ResizableArrayBuffer(1, { maxByteLength: 2 });
    expect(Reflect.get(resizable, "resizable")).toBe(true);
    expect(() => copyBytes(new Uint8Array(resizable))).toThrow();

    const detachedView = Uint8Array.of(1, 2, 3);
    structuredClone(detachedView.buffer, { transfer: [detachedView.buffer] });
    expect(Reflect.get(detachedView.buffer, "detached")).toBe(true);
    expect(() => copyBytes(detachedView)).toThrow();
  });

  it("rejects unknown, inherited, hidden, symbol, undefined, and accessor fields", () => {
    expect(expectExactRecord({ a: 1 }, ["a"], "fixture")).toEqual({ a: 1 });
    const inherited = Object.create({ a: 1 }) as Record<string, unknown>;
    inherited.a = 1;
    expect(() => expectExactRecord(inherited, ["a"], "fixture")).toThrow();
    expect(() => expectExactRecord({ a: 1, b: 2 }, ["a"], "fixture")).toThrow();
    expect(() => expectExactRecord({ a: undefined }, ["a"], "fixture")).toThrow();

    const hidden = { a: 1 };
    Object.defineProperty(hidden, "hidden", { value: true });
    expect(() => expectExactRecord(hidden, ["a"], "fixture")).toThrow();
    const hiddenRequired = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(hiddenRequired, "a", { value: 1 });
    expect(() =>
      expectExactRecord(hiddenRequired, ["a"], "fixture"),
    ).toThrow();
    const symbol = { a: 1, [Symbol("hidden")]: true };
    expect(() => expectExactRecord(symbol, ["a"], "fixture")).toThrow();

    let accessed = false;
    const accessor = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessor, "a", {
      enumerable: true,
      get() {
        accessed = true;
        return 1;
      },
    });
    expect(() => expectExactRecord(accessor, ["a"], "fixture")).toThrow();
    expect(accessed).toBe(false);
  });

  it("parses and freezes the exact tagged sender variants", () => {
    const installation = parseEnvelopeSender({
      type: "installation",
      accountId: UUID_V4,
      installationId: UUID_V4_B,
    });
    expect(installation).toEqual({
      type: "installation",
      accountId: UUID_V4,
      installationId: UUID_V4_B,
    });
    expect(Object.isFrozen(installation)).toBe(true);

    const signer = parseEnvelopeSender({
      type: "entitlement_signer",
      credentialId: UUID_V4,
      fingerprint: RAW32,
      signerGeneration: "1",
    });
    expect(signer.type).toBe("entitlement_signer");
    expect(Object.isFrozen(signer)).toBe(true);

    for (const value of [
      {
        type: "installation",
        accountId: UUID_V4,
        installationId: UUID_V4_B,
        role: "owner",
      },
      {
        type: "installation",
        accountId: UUID_V4,
        credentialId: UUID_V4_B,
      },
      {
        type: "entitlement_signer",
        credentialId: UUID_V4,
        fingerprint: RAW32,
        signerGeneration: "0",
      },
      { type: "server" },
      Object.create({ type: "installation" }),
    ]) {
      expect(() => parseEnvelopeSender(value)).toThrow();
    }

    let accessed = false;
    const accessor = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessor, "type", {
      enumerable: true,
      get() {
        accessed = true;
        return "installation";
      },
    });
    expect(() => parseEnvelopeSender(accessor)).toThrow();
    expect(accessed).toBe(false);
  });

  it("allowlists envelope classes and exact parameter-free media types", () => {
    for (const value of ["external_proposal", "mls_commit", "application"] as const) {
      expect(parseEnvelopeClass(value)).toBe(value);
    }
    expect(parseEnvelopeContentType(MLS_PUBLIC_MESSAGE_MEDIA_TYPE)).toBe(
      MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
    );
    expect(parseEnvelopeContentType(MLS_PRIVATE_MESSAGE_MEDIA_TYPE)).toBe(
      MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    );
    for (const value of [
      "proposal",
      "commit",
      "Application",
      `${MLS_PRIVATE_MESSAGE_MEDIA_TYPE}; charset=utf-8`,
      "application/octet-stream",
    ]) {
      expect(() => parseEnvelopeClass(value)).toThrow();
      expect(() => parseEnvelopeContentType(value)).toThrow();
    }
  });

  it("bounds lowercase signing and release-profile identifiers", () => {
    expect(parseSigningKeyId("delivery-log-2026q3")).toBe(
      "delivery-log-2026q3",
    );
    expect(parseReleaseProfileId("ds.v1_release-2026q3")).toBe(
      "ds.v1_release-2026q3",
    );
    for (const value of [
      "",
      "Delivery-log",
      "delivery:log",
      "delivery/log",
      " delivery-log",
      "a".repeat(65),
      1,
    ]) {
      expect(() => parseSigningKeyId(value)).toThrow();
      expect(() => parseReleaseProfileId(value)).toThrow();
    }
  });
});

describe("signed Delivery Service manifest limits", () => {
  function limits(): Record<string, string> {
    return { ...DELIVERY_TESTED_CEILINGS };
  }

  it("requires all reviewed values as canonical decimal strings with no defaults", () => {
    const parsed = parseDeliveryLimits(limits());
    expect(parsed).toEqual(DELIVERY_TESTED_CEILINGS);
    expect(Object.isFrozen(parsed)).toBe(true);

    for (const key of Object.keys(DELIVERY_TESTED_CEILINGS)) {
      const missing = limits();
      delete missing[key];
      expect(() => parseDeliveryLimits(missing)).toThrow();
    }
    expect(() => parseDeliveryLimits({ ...limits(), extra: "1" })).toThrow();
    expect(() => parseDeliveryLimits(Object.assign(Object.create({}), limits()))).toThrow();
  });

  it("rejects coercion, values over reviewed ceilings, and incoherent page limits", () => {
    expect(() =>
      parseDeliveryLimits({
        ...limits(),
        applicationCiphertextDecodedMaxBytes: 65536,
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...limits(),
        applicationCiphertextDecodedMaxBytes: "065536",
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...limits(),
        conversationEventsMaxPerPage: "501",
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...limits(),
        mlsCommitDecodedMaxBytes: "400000",
        welcomeDecodedMaxBytes: "200000",
        pageDecodedArtifactsMaxBytes: "500000",
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...limits(),
        pageDecodedArtifactsMaxBytes: "4194304",
        pageSerializedResponseMaxBytes: "4194303",
      }),
    ).toThrow();
  });

  it("allows a coherent deployment to lower reviewed hard ceilings", () => {
    const parsed = parseDeliveryLimits({
      applicationCiphertextDecodedMaxBytes: "32768",
      externalProposalDecodedMaxBytes: "131072",
      mlsCommitDecodedMaxBytes: "262144",
      welcomeDecodedMaxBytes: "131072",
      pageDecodedArtifactsMaxBytes: "1048576",
      pageSerializedResponseMaxBytes: "2500000",
      conversationEventsMaxPerPage: "250",
      mailboxEntriesMaxPerPage: "50",
      conversationRecipientInstallationsMax: "1250",
      cursorMaxCharacters: "512",
      attachmentsMaxPerEnvelope: "0",
    });
    expect(parsed.attachmentsMaxPerEnvelope).toBe("0");
  });

  it("accepts explicit zero artifact ceilings as signed feature disables", () => {
    const parsed = parseDeliveryLimits({
      applicationCiphertextDecodedMaxBytes: "0",
      externalProposalDecodedMaxBytes: "0",
      mlsCommitDecodedMaxBytes: "0",
      welcomeDecodedMaxBytes: "0",
      pageDecodedArtifactsMaxBytes: "1",
      pageSerializedResponseMaxBytes: "8194",
      conversationEventsMaxPerPage: "1",
      mailboxEntriesMaxPerPage: "1",
      conversationRecipientInstallationsMax: "1",
      cursorMaxCharacters: "43",
      attachmentsMaxPerEnvelope: "0",
    });
    expect(parsed).toMatchObject({
      applicationCiphertextDecodedMaxBytes: "0",
      externalProposalDecodedMaxBytes: "0",
      mlsCommitDecodedMaxBytes: "0",
      welcomeDecodedMaxBytes: "0",
      attachmentsMaxPerEnvelope: "0",
    });
    for (const key of [
      "pageDecodedArtifactsMaxBytes",
      "pageSerializedResponseMaxBytes",
      "conversationEventsMaxPerPage",
      "mailboxEntriesMaxPerPage",
      "conversationRecipientInstallationsMax",
    ]) {
      expect(() =>
        parseDeliveryLimits({ ...parsed, [key]: "0" }),
      ).toThrow();
    }
  });

  it("covers page-wide canonical base64url expansion and bounded JSON metadata", () => {
    expect(DELIVERY_EVENT_JSON_METADATA_OVERHEAD_BYTES).toBe(4096n);
    expect(DELIVERY_PAGE_JSON_FIXED_OVERHEAD_BYTES).toBe(4096n);
    expect(canonicalBase64UrlEncodedLength(0n)).toBe(0n);
    expect(canonicalBase64UrlEncodedLength(1n)).toBe(2n);
    expect(canonicalBase64UrlEncodedLength(2n)).toBe(3n);
    expect(canonicalBase64UrlEncodedLength(3n)).toBe(4n);
    expect(canonicalBase64UrlEncodedLength(4n)).toBe(6n);
    expect(minimumSerializedDeliveryPageBytes(4_194_304n, 500n)).toBe(
      7_644_502n,
    );

    const boundary = {
      applicationCiphertextDecodedMaxBytes: "0",
      externalProposalDecodedMaxBytes: "0",
      mlsCommitDecodedMaxBytes: "0",
      welcomeDecodedMaxBytes: "0",
      pageDecodedArtifactsMaxBytes: "1",
      pageSerializedResponseMaxBytes: "8194",
      conversationEventsMaxPerPage: "1",
      mailboxEntriesMaxPerPage: "1",
      conversationRecipientInstallationsMax: "1",
      cursorMaxCharacters: "43",
      attachmentsMaxPerEnvelope: "0",
    };
    expect(parseDeliveryLimits(boundary).pageSerializedResponseMaxBytes).toBe(
      "8194",
    );
    expect(DELIVERY_CURSOR_MIN_CHARACTERS).toBe(43n);
    expect(parseDeliveryLimits(boundary).cursorMaxCharacters).toBe("43");
    expect(() =>
      parseDeliveryLimits({ ...boundary, cursorMaxCharacters: "42" }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...boundary,
        conversationRecipientInstallationsMax: "2501",
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLimits({
        ...boundary,
        pageSerializedResponseMaxBytes: "8193",
      }),
    ).toThrow();
    expect(() => canonicalBase64UrlEncodedLength(-1n)).toThrow();
    expect(() => canonicalBase64UrlEncodedLength(UINT63_MAX_VALUE)).toThrow();
    expect(() =>
      minimumSerializedDeliveryPageBytes(UINT63_MAX_VALUE, UINT63_MAX_VALUE),
    ).toThrow();
    expect(() =>
      minimumSerializedDeliveryPageBytes(1 as unknown as bigint, 1n),
    ).toThrow();
  });

  it("rejects accessors without invoking them", () => {
    let accessed = false;
    const input = limits();
    Object.defineProperty(input, "cursorMaxCharacters", {
      enumerable: true,
      get() {
        accessed = true;
        return "1024";
      },
    });
    expect(() => parseDeliveryLimits(input)).toThrow();
    expect(accessed).toBe(false);
  });
});
