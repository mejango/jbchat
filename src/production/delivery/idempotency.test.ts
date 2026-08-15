import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  MAX_IDEMPOTENCY_RAW_BODY_BYTES,
  SERVICE_JSON_MEDIA_TYPE,
  classifyHttpIdempotencyCommitment,
  computeIdempotencyRequestCommitment,
  parseCanonicalResourceId,
  parseIdempotencyKeyHeader,
  parseIdempotencyRequestCommitmentInput,
  parseMutationMethod,
  parseRouteTemplate,
} from "./idempotency";

const CONVERSATION_ID = "c99daf46-89d8-4e84-aada-53a04fa111c9";
const OTHER_CONVERSATION_ID = "cd5d7c41-e111-4389-84ba-8f7fdcd5a574";
const UUID_V7 = "0195e5c1-a7d0-7d6a-a521-256e257df384";
const ROUTE = "/v1/conversations/{conversationId}/envelopes";
const ETAG = '"e20-r28"';
const ORACLE_DOMAIN = "jb-msg-idempotency-request/v1";
const CANONICAL_REQUEST_KAT =
  "BxTPTi1nRLaI9IUjfGOB2VOkR5os24ooXR1mZeYZvmA";
const encoder = new TextEncoder();

function request(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    method: "POST",
    routeTemplate: ROUTE,
    resourceId: CONVERSATION_ID,
    mediaType: SERVICE_JSON_MEDIA_TYPE,
    ifMatch: ETAG,
    rawBodyBytes: encoder.encode('{"ciphertext":"AQID"}'),
    queryString: "",
    contentEncoding: null,
    ...overrides,
  };
}

function u32be(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

function lp(value: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + value.length);
  result.set(u32be(value.length), 0);
  result.set(value, 4);
  return result;
}

function expectedCommitment(input: Record<string, unknown>): string {
  const body = input.rawBodyBytes as Uint8Array;
  return createHash("sha256")
    .update(encoder.encode(ORACLE_DOMAIN))
    .update(lp(encoder.encode(input.method as string)))
    .update(lp(encoder.encode(input.routeTemplate as string)))
    .update(lp(encoder.encode(input.resourceId as string)))
    .update(lp(encoder.encode(input.mediaType as string)))
    .update(lp(encoder.encode(input.ifMatch as string)))
    .update(lp(body))
    .digest("base64url");
}

describe("raw mutation request idempotency commitment", () => {
  it("matches the frozen domain and exact length-prefixed field order", () => {
    const input = request();
    expect(computeIdempotencyRequestCommitment(input)).toBe(
      expectedCommitment(input),
    );
    expect(computeIdempotencyRequestCommitment(input)).toBe(
      CANONICAL_REQUEST_KAT,
    );
  });

  it("binds valid substitutions of every committed field", () => {
    const baseline = computeIdempotencyRequestCommitment(request());
    const substitutions = [
      { method: "PUT" },
      { routeTemplate: "/v1/conversations/{conversationId}/commits" },
      { resourceId: OTHER_CONVERSATION_ID },
      { ifMatch: '"e21-r28"' },
      { rawBodyBytes: encoder.encode('{"ciphertext":"BAUG"}') },
    ];
    for (const substitution of substitutions) {
      expect(
        computeIdempotencyRequestCommitment(request(substitution)),
      ).not.toBe(baseline);
    }
    expect(
      computeIdempotencyRequestCommitment(
        request({ resourceId: "", ifMatch: "" }),
      ),
    ).not.toBe(baseline);
  });

  it("treats JSON whitespace and member order as different exact requests", () => {
    const compact = computeIdempotencyRequestCommitment(
      request({ rawBodyBytes: encoder.encode('{"a":1,"b":2}') }),
    );
    const whitespace = computeIdempotencyRequestCommitment(
      request({ rawBodyBytes: encoder.encode('{ "a": 1, "b": 2 }') }),
    );
    const reordered = computeIdempotencyRequestCommitment(
      request({ rawBodyBytes: encoder.encode('{"b":2,"a":1}') }),
    );
    expect(new Set([compact, whitespace, reordered]).size).toBe(3);
    expect(classifyHttpIdempotencyCommitment(compact, compact)).toEqual({
      kind: "exact_replay",
    });
    expect(classifyHttpIdempotencyCommitment(compact, whitespace)).toEqual({
      kind: "conflict",
    });
    expect(classifyHttpIdempotencyCommitment(undefined, compact)).toEqual({
      kind: "miss",
    });
  });

  it("rejects noncanonical method, route, resource, media type, and If-Match headers", () => {
    for (const mutation of [
      { method: "post" },
      { method: "GET" },
      { method: "POST " },
      { routeTemplate: `${ROUTE}?cursor=x` },
      { routeTemplate: `${ROUTE}#fragment` },
      { routeTemplate: `${ROUTE}\n` },
      { routeTemplate: "/v1//envelopes" },
      { routeTemplate: "/v1/conversations/../envelopes" },
      { routeTemplate: "/v1/conversations/%7BconversationId%7D/envelopes" },
      { routeTemplate: "/v1/conversations/{ConversationId}/envelopes" },
      { routeTemplate: `/v1/${"a".repeat(260)}` },
      { resourceId: CONVERSATION_ID.toUpperCase() },
      { resourceId: `${CONVERSATION_ID}\n` },
      { resourceId: CONVERSATION_ID.replace("-4", "-6") },
      { resourceId: "not-a-resource" },
      { mediaType: "application/json" },
      { mediaType: `${SERVICE_JSON_MEDIA_TYPE}; charset=utf-8` },
      { mediaType: SERVICE_JSON_MEDIA_TYPE.toUpperCase() },
      { ifMatch: "e20-r28" },
      { ifMatch: 'W/"e20-r28"' },
      { ifMatch: '"e020-r28"' },
      { ifMatch: '"e20-r9223372036854775808"' },
    ]) {
      expect(() =>
        computeIdempotencyRequestCommitment(request(mutation)),
      ).toThrow();
    }
  });

  it("rejects any query string or Content-Encoding before hashing", () => {
    for (const mutation of [
      { queryString: "?retry=1" },
      { queryString: "?" },
      { queryString: null },
      { contentEncoding: "gzip" },
      { contentEncoding: "identity" },
      { contentEncoding: "" },
    ]) {
      expect(() =>
        computeIdempotencyRequestCommitment(request(mutation)),
      ).toThrow();
    }
  });

  it("accepts only bounded Uint8Array body bytes and snapshots them", () => {
    const source = encoder.encode("exact bytes");
    const parsed = parseIdempotencyRequestCommitmentInput(
      request({ rawBodyBytes: source }),
    );
    source.fill(0);
    expect(new TextDecoder().decode(parsed.rawBodyBytes)).toBe("exact bytes");

    for (const rawBodyBytes of [
      "exact bytes",
      new ArrayBuffer(2),
      new Uint8Array(MAX_IDEMPOTENCY_RAW_BODY_BYTES + 1),
    ]) {
      expect(() =>
        computeIdempotencyRequestCommitment(request({ rawBodyBytes })),
      ).toThrow();
    }

    const hostileIterator = encoder.encode("small");
    let iteratorCalls = 0;
    Object.defineProperty(hostileIterator, Symbol.iterator, {
      configurable: true,
      value: function* expandForever() {
        iteratorCalls += 1;
        while (true) yield 0x41;
      },
    });
    expect(() =>
      parseIdempotencyRequestCommitmentInput(
        request({ rawBodyBytes: hostileIterator }),
      ),
    ).toThrow();
    expect(iteratorCalls).toBe(0);

    class ByteSubclass extends Uint8Array {}
    expect(() =>
      parseIdempotencyRequestCommitmentInput(
        request({ rawBodyBytes: new ByteSubclass(8) }),
      ),
    ).toThrow();
    let proxyReads = 0;
    const proxied = new Proxy(new Uint8Array(8), {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    expect(() =>
      parseIdempotencyRequestCommitmentInput(
        request({ rawBodyBytes: proxied }),
      ),
    ).toThrow();
    expect(proxyReads).toBe(0);
    expect(() =>
      parseIdempotencyRequestCommitmentInput(
        request({
          rawBodyBytes: new Uint8Array(new SharedArrayBuffer(8)),
        }),
      ),
    ).toThrow();

    const ResizableArrayBuffer = ArrayBuffer as unknown as new (
      length: number,
      options: { maxByteLength: number },
    ) => ArrayBuffer;
    const resizable = new ResizableArrayBuffer(8, { maxByteLength: 16 });
    if (
      "resizable" in resizable &&
      (resizable as ArrayBuffer & { readonly resizable: boolean }).resizable
    ) {
      expect(() =>
        parseIdempotencyRequestCommitmentInput(
          request({ rawBodyBytes: new Uint8Array(resizable) }),
        ),
      ).toThrow();
    }

    const detachedBuffer = new ArrayBuffer(8);
    const detached = new Uint8Array(detachedBuffer);
    structuredClone(detachedBuffer, { transfer: [detachedBuffer] });
    expect(() =>
      parseIdempotencyRequestCommitmentInput(
        request({ rawBodyBytes: detached }),
      ),
    ).toThrow();
  });

  it("has no path for auth, cookies, DPoP, origin, request IDs, or arbitrary headers", () => {
    for (const forbidden of [
      "authorization",
      "cookie",
      "dpop",
      "origin",
      "xRequestId",
      "forwarded",
      "headers",
    ]) {
      expect(() =>
        computeIdempotencyRequestCommitment(
          request({ [forbidden]: "secret-that-must-not-enter-a-digest" }),
        ),
      ).toThrow();
    }
  });

  it("rejects prototype, symbol, and accessor confusion without invoking accessors", () => {
    expect(() =>
      computeIdempotencyRequestCommitment(Object.create(request())),
    ).toThrow();
    const withSymbol = request();
    Object.defineProperty(withSymbol, Symbol("cookie"), {
      value: "secret",
      enumerable: true,
    });
    expect(() => computeIdempotencyRequestCommitment(withSymbol)).toThrow();

    const withAccessor = request();
    let calls = 0;
    Object.defineProperty(withAccessor, "rawBodyBytes", {
      enumerable: true,
      get() {
        calls += 1;
        return encoder.encode("replacement");
      },
    });
    expect(() => computeIdempotencyRequestCommitment(withAccessor)).toThrow();
    expect(calls).toBe(0);
  });

  it("strictly validates helpers instead of trimming or normalizing", () => {
    expect(parseMutationMethod("DELETE")).toBe("DELETE");
    expect(parseRouteTemplate(ROUTE)).toBe(ROUTE);
    expect(parseCanonicalResourceId(CONVERSATION_ID)).toBe(CONVERSATION_ID);
    expect(parseCanonicalResourceId(UUID_V7)).toBe(UUID_V7);
    expect(parseCanonicalResourceId("")).toBe("");
    for (const value of [" POST", "post", "OPTIONS", null])
      expect(() => parseMutationMethod(value)).toThrow();
    for (const value of ["", "/v2/items", `${ROUTE}/`, ` ${ROUTE}`])
      expect(() => parseRouteTemplate(value)).toThrow();
    for (const value of [" id", UUID_V7.toUpperCase(), 1, null])
      expect(() => parseCanonicalResourceId(value)).toThrow();
  });

  it("rejects malformed stored/candidate commitments instead of classifying them", () => {
    const valid = computeIdempotencyRequestCommitment(request());
    for (const malformed of ["", "AA", `${valid}=`, valid.slice(0, -1), null]) {
      expect(() => classifyHttpIdempotencyCommitment(malformed, valid)).toThrow();
      expect(() => classifyHttpIdempotencyCommitment(valid, malformed)).toThrow();
    }
  });
});

describe("Idempotency-Key syntax", () => {
  it("accepts canonical UUIDv7 or bounded canonical base64url with at least 128 bits", () => {
    const random128 = Buffer.alloc(16, 0x5a).toString("base64url");
    expect(parseIdempotencyKeyHeader(UUID_V7)).toBe(UUID_V7);
    expect(parseIdempotencyKeyHeader(random128)).toBe(random128);
  });

  it("rejects UUID lookalikes, insufficient bytes, noncanonical base64url, and excess", () => {
    for (const value of [
      "415609f1-9662-49f6-9cda-9ef319abe51d",
      UUID_V7.toUpperCase(),
      UUID_V7.replace("-7", "-6"),
      Buffer.alloc(15, 0x5a).toString("base64url"),
      `${Buffer.alloc(16, 0x5a).toString("base64url")}=`,
      ` ${Buffer.alloc(16, 0x5a).toString("base64url")}`,
      "AB",
      "A".repeat(1024),
      "",
      null,
    ]) {
      expect(() => parseIdempotencyKeyHeader(value)).toThrow();
    }
  });
});
