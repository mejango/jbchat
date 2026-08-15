import {
  API_V1_MEDIA_TYPE,
  copyBytes,
  expectExactRecord,
  parseConversationEtag,
  parseHash32,
  parseIdempotencyKey,
  type ConversationEtag,
  type Hash32,
  type IdempotencyKey,
} from "./valueObjects";
import { canonicalLengthPrefixed, sha256Bytes } from "./hashes";

export const IDEMPOTENCY_REQUEST_COMMITMENT_DOMAIN =
  "jb-msg-idempotency-request/v1";
export const SERVICE_JSON_MEDIA_TYPE =
  API_V1_MEDIA_TYPE;
export const MAX_IDEMPOTENCY_RAW_BODY_BYTES = 1024 * 1024;

const ROUTE_TEMPLATE =
  /^\/v1(?:\/(?:[a-z0-9][a-z0-9-]*|\{[a-z][A-Za-z0-9]*\}))*$/;
const CANONICAL_UUID =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-(?:4[0-9a-f]{3}|7[0-9a-f]{3})-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const encoder = new TextEncoder();

declare const idempotencyBrand: unique symbol;
export type MutationMethod = "POST" | "PUT" | "PATCH" | "DELETE";
export type RouteTemplate = string & {
  readonly [idempotencyBrand]: "RouteTemplate";
};
export type CanonicalResourceId = string & {
  readonly [idempotencyBrand]: "CanonicalResourceId";
};

export class IdempotencyValidationError extends Error {
  readonly code = "invalid_idempotency_input";

  constructor(message: string) {
    super(message);
    this.name = "IdempotencyValidationError";
  }
}

/**
 * Deliberately selected, already-normalized request data. Authentication,
 * cookies, DPoP, Origin, request IDs, forwarding headers, and arbitrary HTTP
 * headers have no representation here and therefore cannot enter the digest.
 */
export interface IdempotencyRequestCommitmentInput {
  readonly method: MutationMethod;
  readonly routeTemplate: RouteTemplate;
  readonly resourceId: CanonicalResourceId;
  readonly mediaType: typeof SERVICE_JSON_MEDIA_TYPE;
  /** Exact header value, or the empty string when this route has no If-Match. */
  readonly ifMatch: ConversationEtag | "";
  readonly rawBodyBytes: Uint8Array;
  /** Must be empty. Mutation query strings are outside the v1 contract. */
  readonly queryString: "";
  /** Must be null. Content-Encoding is rejected, including `identity`. */
  readonly contentEncoding: null;
}

export interface ParsedIdempotencyRequestCommitmentInput
  extends IdempotencyRequestCommitmentInput {
  /** Owned snapshot; later caller mutation cannot change a stored commitment. */
  readonly rawBodyBytes: Uint8Array;
}

export type HttpIdempotencyClassification =
  | { readonly kind: "miss" }
  | { readonly kind: "exact_replay" }
  | { readonly kind: "conflict" };

export function parseIdempotencyKeyHeader(value: unknown): IdempotencyKey {
  return parseIdempotencyKey(value, "Idempotency-Key");
}

export function parseIdempotencyRequestCommitmentInput(
  value: unknown,
): ParsedIdempotencyRequestCommitmentInput {
  const record = expectExactRecord(
    value,
    [
      "method",
      "routeTemplate",
      "resourceId",
      "mediaType",
      "ifMatch",
      "rawBodyBytes",
      "queryString",
      "contentEncoding",
    ],
    "idempotency request commitment input",
  );
  const method = parseMutationMethod(record.method);
  const routeTemplate = parseRouteTemplate(record.routeTemplate);
  const resourceId = parseCanonicalResourceId(record.resourceId);
  if (record.mediaType !== SERVICE_JSON_MEDIA_TYPE) {
    throw invalid("Request media type must be the exact version-1 service JSON type.");
  }
  const ifMatch =
    record.ifMatch === ""
      ? ""
      : parseConversationEtag(record.ifMatch, "If-Match");
  if (record.queryString !== "") {
    throw invalid("Mutation query strings are not eligible for idempotency commitment.");
  }
  if (record.contentEncoding !== null) {
    throw invalid("Content-Encoding is not accepted on committed mutation requests.");
  }
  const rawBodyBytes = copyBytes(
    record.rawBodyBytes,
    "rawBodyBytes",
    MAX_IDEMPOTENCY_RAW_BODY_BYTES,
  );
  return Object.freeze({
    method,
    routeTemplate,
    resourceId,
    mediaType: SERVICE_JSON_MEDIA_TYPE,
    ifMatch,
    rawBodyBytes,
    queryString: "",
    contentEncoding: null,
  });
}

/**
 * SHA-256(
 *   ASCII("jb-msg-idempotency-request/v1") ||
 *   LP(uppercase method) || LP(exact route template) ||
 *   LP(canonical resource ID) || LP(exact media type) ||
 *   LP(exact If-Match or empty) || LP(exact raw body bytes)
 * )
 */
export function computeIdempotencyRequestCommitment(value: unknown): Hash32 {
  const parsed = parseIdempotencyRequestCommitmentInput(value);
  return sha256Bytes(
    encoder.encode(IDEMPOTENCY_REQUEST_COMMITMENT_DOMAIN),
    canonicalLengthPrefixed(
      encoder.encode(parsed.method),
      encoder.encode(parsed.routeTemplate),
      encoder.encode(parsed.resourceId),
      encoder.encode(parsed.mediaType),
      encoder.encode(parsed.ifMatch),
      parsed.rawBodyBytes,
    ),
  );
}

export function classifyHttpIdempotencyCommitment(
  storedCommitment: unknown | undefined,
  candidateCommitment: unknown,
): HttpIdempotencyClassification {
  const candidate = parseHash32(
    candidateCommitment,
    "candidate request commitment",
  );
  if (storedCommitment === undefined) {
    return Object.freeze({ kind: "miss" });
  }
  const stored = parseHash32(storedCommitment, "stored request commitment");
  return stored === candidate
    ? Object.freeze({ kind: "exact_replay" })
    : Object.freeze({ kind: "conflict" });
}

export function parseMutationMethod(value: unknown): MutationMethod {
  if (
    value !== "POST" &&
    value !== "PUT" &&
    value !== "PATCH" &&
    value !== "DELETE"
  ) {
    throw invalid("Mutation method must be an exact uppercase allowlisted method.");
  }
  return value;
}

export function parseRouteTemplate(value: unknown): RouteTemplate {
  if (
    typeof value !== "string" ||
    value.length < 4 ||
    value.length > 256 ||
    !matchesEntire(ROUTE_TEMPLATE, value)
  ) {
    throw invalid("Route template must be canonical, bounded, and query-free.");
  }
  return value as RouteTemplate;
}

/** Empty denotes a collection route; otherwise v1 accepts canonical UUIDv4/v7. */
export function parseCanonicalResourceId(value: unknown): CanonicalResourceId {
  if (
    typeof value !== "string" ||
    (value !== "" && !matchesEntire(CANONICAL_UUID, value))
  ) {
    throw invalid("Resource ID must be empty or a canonical lowercase UUIDv4/v7.");
  }
  return value as CanonicalResourceId;
}

function matchesEntire(pattern: RegExp, value: string): boolean {
  return pattern.exec(value)?.[0] === value;
}

function invalid(message: string): IdempotencyValidationError {
  return new IdempotencyValidationError(message);
}
