import { Buffer } from "node:buffer";

declare const deliveryValueBrand: unique symbol;

type Brand<Name extends string> = {
  readonly [deliveryValueBrand]: Name;
};

export type UuidV4 = string & Brand<"UuidV4">;
export type UuidV7 = string & Brand<"UuidV7">;

export type AccountId = string & Brand<"AccountId:UuidV4">;
export type AttachmentId = string & Brand<"AttachmentId:UuidV4">;
export type ConversationId = string & Brand<"ConversationId:UuidV4">;
export type CredentialId = string & Brand<"CredentialId:UuidV4">;
export type EnvelopeId = string & Brand<"EnvelopeId:UuidV4">;
export type InstallationId = string & Brand<"InstallationId:UuidV4">;
export type PolicyHeadId = string & Brand<"PolicyHeadId:UuidV4">;
export type WitnessCheckpointId = string & Brand<"WitnessCheckpointId:UuidV4">;

export type MembershipIntentId = string & Brand<"MembershipIntentId:UuidV7">;
export type ProposalId = string & Brand<"ProposalId:UuidV7">;
export type RequestId = string & Brand<"RequestId:UuidV7">;

export type CanonicalBase64Url = string & Brand<"CanonicalBase64Url">;
export type IdempotencyKey = string & Brand<"IdempotencyKey">;
export type Hash32 = string & Brand<"Hash32:Base64UrlRaw32">;
export type Fingerprint32 = string & Brand<"Fingerprint32:Base64UrlRaw32">;
export type Raw32 = string & Brand<"Raw32:Base64UrlRaw32">;
export type Ed25519Signature = string &
  Brand<"Ed25519Signature:Base64UrlRaw64">;
export type Uint63String = string & Brand<"Uint63String">;
export type Rfc3339Millis = string & Brand<"Rfc3339Millis">;
export type ConversationEtag = string & Brand<"ConversationEtag">;
export type SigningKeyId = string & Brand<"SigningKeyId">;
export type ReleaseProfileId = string & Brand<"ReleaseProfileId">;

export const API_V1_MEDIA_TYPE =
  "application/vnd.juicebox.messaging.v1+json" as const;
export const PROBLEM_JSON_MEDIA_TYPE = "application/problem+json" as const;
export const MLS_PUBLIC_MESSAGE_MEDIA_TYPE =
  "application/vnd.juicebox.messaging.mls-public-message" as const;
export const MLS_PRIVATE_MESSAGE_MEDIA_TYPE =
  "application/vnd.juicebox.messaging.mls-private-message" as const;

export type EnvelopeClass =
  | "external_proposal"
  | "mls_commit"
  | "application";
export type EnvelopeContentType =
  | typeof MLS_PUBLIC_MESSAGE_MEDIA_TYPE
  | typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;

export interface InstallationEnvelopeSender {
  readonly type: "installation";
  readonly accountId: AccountId;
  readonly installationId: InstallationId;
}

export interface EntitlementSignerEnvelopeSender {
  readonly type: "entitlement_signer";
  readonly credentialId: CredentialId;
  readonly fingerprint: Fingerprint32;
  readonly signerGeneration: Uint63String;
}

export type EnvelopeSender =
  | InstallationEnvelopeSender
  | EntitlementSignerEnvelopeSender;

const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID_SHAPED =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/i;
const UINT63 = /^(0|[1-9][0-9]*)$(?![\s\S])/;
const UINT63_MAX = (1n << 63n) - 1n;
const RFC3339_MILLISECONDS =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$(?![\s\S])/;
const CONVERSATION_ETAG =
  /^"e(0|[1-9][0-9]*)-r(0|[1-9][0-9]*)"$(?![\s\S])/;
const SIGNING_KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$(?![\s\S])/;
const RELEASE_PROFILE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$(?![\s\S])/;
const BASE64URL = /^[A-Za-z0-9_-]+$(?![\s\S])/;
const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DEFAULT_MAX_BASE64URL_BYTES = 8 * 1024 * 1024;
const MAX_INTRINSIC_COPY_BYTES = 0xffff_ffff;
const INTRINSIC_UINT8_ARRAY = Uint8Array;
const INTRINSIC_UINT8_ARRAY_PROTOTYPE = Uint8Array.prototype;
const INTRINSIC_BUFFER_PROTOTYPE = Buffer.prototype;
const INTRINSIC_OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR =
  Object.getOwnPropertyDescriptor;
const INTRINSIC_OBJECT_HAS_OWN = Object.hasOwn;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_TYPED_ARRAY_PROTOTYPE = INTRINSIC_OBJECT_GET_PROTOTYPE_OF(
  Uint8Array.prototype,
) as object;
const INTRINSIC_TYPED_ARRAY_BUFFER = captureIntrinsicGetter(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  "buffer",
);
const INTRINSIC_TYPED_ARRAY_BYTE_LENGTH = captureIntrinsicGetter(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  "byteLength",
);
const INTRINSIC_TYPED_ARRAY_BYTE_OFFSET = captureIntrinsicGetter(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  "byteOffset",
);
const INTRINSIC_TYPED_ARRAY_LENGTH = captureIntrinsicGetter(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  "length",
);
const INTRINSIC_TYPED_ARRAY_SET = captureIntrinsicMethod(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  "set",
);
const INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH = captureIntrinsicGetter(
  ArrayBuffer.prototype,
  "byteLength",
);
const INTRINSIC_ARRAY_BUFFER_RESIZABLE = captureOptionalIntrinsicGetter(
  ArrayBuffer.prototype,
  "resizable",
);
const INTRINSIC_ARRAY_BUFFER_DETACHED = captureOptionalIntrinsicGetter(
  ArrayBuffer.prototype,
  "detached",
);
const INTRINSIC_SHARED_ARRAY_BUFFER_BYTE_LENGTH =
  typeof SharedArrayBuffer === "undefined"
    ? null
    : captureIntrinsicGetter(SharedArrayBuffer.prototype, "byteLength");

export const UINT63_MAX_VALUE = UINT63_MAX;
export const UINT63_MAX_STRING =
  "9223372036854775807" as Uint63String;
export const ZERO_HASH32 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" as Hash32;

export interface Uint63StringOptions {
  readonly minimum?: bigint;
  readonly maximum?: bigint;
}

export class DeliveryValidationError extends Error {
  readonly code = "invalid_delivery_input";

  constructor(message: string) {
    super(message);
    this.name = "DeliveryValidationError";
  }
}

/**
 * Accepts only an own-property data record with the exact named fields.
 * Accessors are rejected before a value is read, including non-enumerable and
 * symbol properties that ordinary JSON enumeration would otherwise hide.
 */
export function expectExactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${label} must be a plain data record.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalid(`${label} must be a plain data record.`);
  }

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string" || !keys.includes(key)) ||
    keys.some((key) => !ownKeys.includes(key))
  ) {
    throw invalid(`${label} has an unexpected shape.`);
  }

  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      descriptor.value === undefined
    ) {
      throw invalid(`${label} must contain only defined data properties.`);
    }
  }

  return value as Record<string, unknown>;
}

export function parseUuidV4(value: unknown, label = "UUIDv4"): UuidV4 {
  return parseUuid(value, UUID_V4, "UUIDv4", label) as UuidV4;
}

export function parseUuidV7(value: unknown, label = "UUIDv7"): UuidV7 {
  return parseUuid(value, UUID_V7, "UUIDv7", label) as UuidV7;
}

export function parseAccountId(value: unknown, label = "accountId"): AccountId {
  return parseUuidV4(value, label) as string as AccountId;
}

export function parseAttachmentId(
  value: unknown,
  label = "attachmentId",
): AttachmentId {
  return parseUuidV4(value, label) as string as AttachmentId;
}

export function parseConversationId(
  value: unknown,
  label = "conversationId",
): ConversationId {
  return parseUuidV4(value, label) as string as ConversationId;
}

export function parseCredentialId(
  value: unknown,
  label = "credentialId",
): CredentialId {
  return parseUuidV4(value, label) as string as CredentialId;
}

export function parseEnvelopeId(
  value: unknown,
  label = "envelopeId",
): EnvelopeId {
  return parseUuidV4(value, label) as string as EnvelopeId;
}

export function parseInstallationId(
  value: unknown,
  label = "installationId",
): InstallationId {
  return parseUuidV4(value, label) as string as InstallationId;
}

export function parsePolicyHeadId(
  value: unknown,
  label = "policyHeadId",
): PolicyHeadId {
  return parseUuidV4(value, label) as string as PolicyHeadId;
}

export function parseWitnessCheckpointId(
  value: unknown,
  label = "witnessCheckpointId",
): WitnessCheckpointId {
  return parseUuidV4(value, label) as string as WitnessCheckpointId;
}

export function parseMembershipIntentId(
  value: unknown,
  label = "membershipIntentId",
): MembershipIntentId {
  return parseUuidV7(value, label) as string as MembershipIntentId;
}

export function parseProposalId(
  value: unknown,
  label = "proposalId",
): ProposalId {
  return parseUuidV7(value, label) as string as ProposalId;
}

export function parseRequestId(value: unknown, label = "requestId"): RequestId {
  return parseUuidV7(value, label) as string as RequestId;
}

/**
 * Mutating APIs allow either a UUIDv7 or a canonical unpadded token carrying
 * at least 128 bits. The returned string is immutable and remains the exact
 * caller representation; it is never normalized or converted to a number.
 */
export function parseIdempotencyKey(
  value: unknown,
  label = "Idempotency-Key",
): IdempotencyKey {
  if (typeof value === "string" && UUID_V7.test(value)) {
    return value as IdempotencyKey;
  }
  if (typeof value === "string" && UUID_SHAPED.test(value)) {
    throw invalid(`${label} UUID form must be a lowercase canonical UUIDv7.`);
  }
  const parsed = parseCanonicalBase64Url(value, label, {
    minBytes: 16,
    maxBytes: 64,
  });
  return parsed as string as IdempotencyKey;
}

export function parseUint63String(
  value: unknown,
  label = "counter",
  options: Uint63StringOptions = {},
): Uint63String {
  if (typeof value !== "string" || !UINT63.test(value)) {
    throw invalid(`${label} must be a canonical uint63 decimal string.`);
  }
  if (value.length > UINT63_MAX_STRING.length || BigInt(value) > UINT63_MAX) {
    throw invalid(`${label} exceeds the version 1 uint63 ceiling.`);
  }
  const parsed = BigInt(value);
  const minimum = options.minimum ?? 0n;
  const maximum = options.maximum ?? UINT63_MAX;
  if (
    typeof minimum !== "bigint" ||
    typeof maximum !== "bigint" ||
    minimum < 0n ||
    maximum > UINT63_MAX ||
    maximum < minimum
  ) {
    throw invalid(`${label} has invalid uint63 bounds.`);
  }
  if (parsed < minimum || parsed > maximum) {
    throw invalid(`${label} is outside its permitted uint63 range.`);
  }
  return value as Uint63String;
}

export function parsePositiveUint63String(
  value: unknown,
  label = "counter",
): Uint63String {
  const parsed = parseUint63String(value, label);
  if (parsed === "0") {
    throw invalid(`${label} must be greater than zero.`);
  }
  return parsed;
}

export function parseUint63BigInt(
  value: unknown,
  label = "counter",
): bigint {
  if (typeof value !== "bigint" || value < 0n || value > UINT63_MAX) {
    throw invalid(`${label} must be a uint63 bigint.`);
  }
  return value;
}

export function uint63ToBigInt(value: Uint63String): bigint {
  return BigInt(parseUint63String(value));
}

export function uint63FromBigInt(value: bigint, label = "counter"): Uint63String {
  return parseUint63BigInt(value, label).toString() as Uint63String;
}

export function parseRfc3339Millis(
  value: unknown,
  label = "timestamp",
): Rfc3339Millis {
  if (typeof value !== "string" || !RFC3339_MILLISECONDS.test(value)) {
    throw invalid(`${label} must be UTC RFC 3339 with exactly milliseconds.`);
  }
  const instant = new Date(value);
  if (!Number.isFinite(instant.getTime()) || instant.toISOString() !== value) {
    throw invalid(`${label} must be a real canonical UTC instant.`);
  }
  return value as Rfc3339Millis;
}

export function parseConversationEtag(
  value: unknown,
  label = "ETag",
): ConversationEtag {
  if (typeof value !== "string") {
    throw invalid(`${label} must be a canonical conversation ETag.`);
  }
  const match = CONVERSATION_ETAG.exec(value);
  if (!match) {
    throw invalid(`${label} must be exactly \"e<epoch>-r<rosterVersion>\".`);
  }
  parseUint63String(match[1], `${label} epoch`);
  parseUint63String(match[2], `${label} roster version`);
  return value as ConversationEtag;
}

export function formatConversationEtag(
  epoch: Uint63String,
  rosterVersion: Uint63String,
): ConversationEtag {
  return `"e${parseUint63String(epoch, "epoch")}-r${parseUint63String(
    rosterVersion,
    "rosterVersion",
  )}"` as ConversationEtag;
}

export function parseSigningKeyId(
  value: unknown,
  label = "signingKeyId",
): SigningKeyId {
  if (typeof value !== "string" || !SIGNING_KEY_ID.test(value)) {
    throw invalid(
      `${label} must be 1-64 lowercase ASCII letters, digits, dot, underscore, or hyphen.`,
    );
  }
  return value as SigningKeyId;
}

export function parseReleaseProfileId(
  value: unknown,
  label = "releaseProfileId",
): ReleaseProfileId {
  if (typeof value !== "string" || !RELEASE_PROFILE_ID.test(value)) {
    throw invalid(
      `${label} must be 1-64 lowercase ASCII letters, digits, dot, underscore, or hyphen.`,
    );
  }
  return value as ReleaseProfileId;
}

export function parseEnvelopeClass(
  value: unknown,
  label = "envelopeClass",
): EnvelopeClass {
  if (
    value !== "external_proposal" &&
    value !== "mls_commit" &&
    value !== "application"
  ) {
    throw invalid(`${label} is not a supported envelope class.`);
  }
  return value;
}

export function parseEnvelopeContentType(
  value: unknown,
  label = "contentType",
): EnvelopeContentType {
  if (
    value !== MLS_PUBLIC_MESSAGE_MEDIA_TYPE &&
    value !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE
  ) {
    throw invalid(`${label} is not a supported MLS media type.`);
  }
  return value;
}

export function parseEnvelopeSender(
  value: unknown,
  label = "sender",
): EnvelopeSender {
  const discriminated = expectPlainDataRecord(value, label);
  const type = discriminated.type;
  if (type === "installation") {
    const record = expectExactRecord(
      value,
      ["type", "accountId", "installationId"],
      label,
    );
    return Object.freeze({
      type,
      accountId: parseAccountId(record.accountId, `${label}.accountId`),
      installationId: parseInstallationId(
        record.installationId,
        `${label}.installationId`,
      ),
    });
  }
  if (type === "entitlement_signer") {
    const record = expectExactRecord(
      value,
      ["type", "credentialId", "fingerprint", "signerGeneration"],
      label,
    );
    const signerGeneration = parsePositiveUint63String(
      record.signerGeneration,
      `${label}.signerGeneration`,
    );
    return Object.freeze({
      type,
      credentialId: parseCredentialId(
        record.credentialId,
        `${label}.credentialId`,
      ),
      fingerprint: parseFingerprint32(
        record.fingerprint,
        `${label}.fingerprint`,
      ),
      signerGeneration,
    });
  }
  throw invalid(`${label}.type is not a supported sender tag.`);
}

export interface CanonicalBase64UrlOptions {
  readonly minBytes: number;
  readonly maxBytes: number;
}

export function parseCanonicalBase64Url(
  value: unknown,
  label = "base64url",
  options: CanonicalBase64UrlOptions = {
    minBytes: 1,
    maxBytes: DEFAULT_MAX_BASE64URL_BYTES,
  },
): CanonicalBase64Url {
  validateByteBounds(options, label);
  if (typeof value !== "string" || !BASE64URL.test(value)) {
    throw invalid(`${label} must be unpadded canonical base64url.`);
  }

  const remainder = value.length % 4;
  const lastValue = BASE64URL_ALPHABET.indexOf(value.at(-1) ?? "");
  if (
    remainder === 1 ||
    (remainder === 2 && (lastValue & 0b1111) !== 0) ||
    (remainder === 3 && (lastValue & 0b11) !== 0)
  ) {
    throw invalid(`${label} has non-canonical base64url tail bits.`);
  }

  const maximumEncodedLength = Math.ceil((options.maxBytes * 4) / 3);
  if (value.length > maximumEncodedLength) {
    throw invalid(`${label} exceeds its decoded byte limit.`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength < options.minBytes ||
    decoded.byteLength > options.maxBytes ||
    decoded.toString("base64url") !== value
  ) {
    throw invalid(`${label} is not canonical base64url within the byte bounds.`);
  }
  return value as CanonicalBase64Url;
}

/** Returns a newly owned byte array; no mutable view of parser state is shared. */
export function parseCanonicalBase64UrlBytes(
  value: unknown,
  label = "base64url",
  options: CanonicalBase64UrlOptions = {
    minBytes: 1,
    maxBytes: DEFAULT_MAX_BASE64URL_BYTES,
  },
): Uint8Array {
  const parsed = parseCanonicalBase64Url(value, label, options);
  return copyBytes(Buffer.from(parsed, "base64url"), label, options.maxBytes);
}

/** Returns a fresh copy and revalidates a possibly forged compile-time brand. */
export function decodeCanonicalBase64Url(
  value: CanonicalBase64Url,
  label = "base64url",
): Uint8Array {
  return parseCanonicalBase64UrlBytes(value, label, {
    minBytes: 1,
    maxBytes: DEFAULT_MAX_BASE64URL_BYTES,
  });
}

export function parseHash32(value: unknown, label = "hash"): Hash32 {
  return parseCanonicalBase64Url(value, label, {
    minBytes: 32,
    maxBytes: 32,
  }) as string as Hash32;
}

export function parseFingerprint32(
  value: unknown,
  label = "fingerprint",
): Fingerprint32 {
  return parseCanonicalBase64Url(value, label, {
    minBytes: 32,
    maxBytes: 32,
  }) as string as Fingerprint32;
}

export function parseRaw32(value: unknown, label = "raw32"): Raw32 {
  return parseCanonicalBase64Url(value, label, {
    minBytes: 32,
    maxBytes: 32,
  }) as string as Raw32;
}

export function parseEd25519Signature(
  value: unknown,
  label = "signature",
): Ed25519Signature {
  return parseCanonicalBase64Url(value, label, {
    minBytes: 64,
    maxBytes: 64,
  }) as string as Ed25519Signature;
}

export function decodeHash32(value: Hash32, label = "hash"): Uint8Array {
  return parseCanonicalBase64UrlBytes(value, label, {
    minBytes: 32,
    maxBytes: 32,
  });
}

export function decodeFingerprint32(
  value: Fingerprint32,
  label = "fingerprint",
): Uint8Array {
  return parseCanonicalBase64UrlBytes(value, label, {
    minBytes: 32,
    maxBytes: 32,
  });
}

export function copyBytes(
  value: unknown,
  label = "bytes",
  maxBytes = DEFAULT_MAX_BASE64URL_BYTES,
): Uint8Array {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0 ||
    maxBytes > MAX_INTRINSIC_COPY_BYTES
  ) {
    throw invalid(`${label} must be a bounded byte array.`);
  }
  try {
    if (!value || typeof value !== "object") {
      throw new TypeError("not an object");
    }
    // Validate the TypedArray internal slots before any abstract object
    // operation. Intrinsic getters reject a Proxy without executing its traps.
    const source = inspectFixedArrayBufferView(value);
    const prototype = INTRINSIC_OBJECT_GET_PROTOTYPE_OF(value);
    if (
      prototype !== INTRINSIC_UINT8_ARRAY_PROTOTYPE &&
      prototype !== INTRINSIC_BUFFER_PROTOTYPE
    ) {
      throw new TypeError("unsupported byte prototype");
    }
    for (const key of [
      Symbol.iterator,
      "buffer",
      "byteLength",
      "byteOffset",
      "length",
      "set",
    ] as const) {
      if (INTRINSIC_OBJECT_HAS_OWN(value, key)) {
        throw new TypeError("overridden byte intrinsic");
      }
    }

    if (source.byteLength > maxBytes) {
      throw new RangeError("byte limit exceeded");
    }

    const copied = new INTRINSIC_UINT8_ARRAY(source.byteLength);
    INTRINSIC_REFLECT_APPLY(INTRINSIC_TYPED_ARRAY_SET, copied, [value, 0]);

    const sourceAfterCopy = inspectFixedArrayBufferView(value);
    const copiedLength = readSafeIntegerIntrinsic(
      INTRINSIC_TYPED_ARRAY_BYTE_LENGTH,
      copied,
    );
    if (
      sourceAfterCopy.buffer !== source.buffer ||
      sourceAfterCopy.byteLength !== source.byteLength ||
      sourceAfterCopy.byteOffset !== source.byteOffset ||
      sourceAfterCopy.length !== source.length ||
      sourceAfterCopy.backingByteLength !== source.backingByteLength ||
      copiedLength !== source.byteLength
    ) {
      throw new TypeError("byte source changed during copy");
    }
    return copied;
  } catch {
    throw invalid(`${label} must be an intrinsic, fixed, owned byte array.`);
  }
}

interface FixedArrayBufferViewInspection {
  readonly buffer: object;
  readonly byteLength: number;
  readonly byteOffset: number;
  readonly length: number;
  readonly backingByteLength: number;
}

function inspectFixedArrayBufferView(
  value: object,
): FixedArrayBufferViewInspection {
  const byteLength = readSafeIntegerIntrinsic(
    INTRINSIC_TYPED_ARRAY_BYTE_LENGTH,
    value,
  );
  const byteOffset = readSafeIntegerIntrinsic(
    INTRINSIC_TYPED_ARRAY_BYTE_OFFSET,
    value,
  );
  const length = readSafeIntegerIntrinsic(INTRINSIC_TYPED_ARRAY_LENGTH, value);
  const buffer = callIntrinsicGetter(INTRINSIC_TYPED_ARRAY_BUFFER, value);
  if (!buffer || typeof buffer !== "object") {
    throw new TypeError("invalid backing buffer");
  }

  const arrayBufferLength = tryIntrinsicGetter(
    INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH,
    buffer,
  );
  if (!arrayBufferLength.ok) {
    const sharedLength =
      INTRINSIC_SHARED_ARRAY_BUFFER_BYTE_LENGTH === null
        ? { ok: false as const }
        : tryIntrinsicGetter(INTRINSIC_SHARED_ARRAY_BUFFER_BYTE_LENGTH, buffer);
    if (sharedLength.ok) {
      throw new TypeError("shared backing buffer");
    }
    throw new TypeError("invalid backing buffer");
  }
  const backingByteLength = expectSafeInteger(arrayBufferLength.value);
  if (
    INTRINSIC_ARRAY_BUFFER_RESIZABLE !== null &&
    callIntrinsicGetter(INTRINSIC_ARRAY_BUFFER_RESIZABLE, buffer) === true
  ) {
    throw new TypeError("resizable backing buffer");
  }
  if (
    INTRINSIC_ARRAY_BUFFER_DETACHED !== null &&
    callIntrinsicGetter(INTRINSIC_ARRAY_BUFFER_DETACHED, buffer) === true
  ) {
    throw new TypeError("detached backing buffer");
  }

  // Constructing even a zero-length view performs the spec's detached-buffer
  // internal-slot check when the optional `detached` getter is unavailable.
  new INTRINSIC_UINT8_ARRAY(buffer as ArrayBuffer, 0, 0);
  if (
    length !== byteLength ||
    byteOffset + byteLength > backingByteLength
  ) {
    throw new TypeError("inconsistent byte view");
  }
  return Object.freeze({
    buffer,
    byteLength,
    byteOffset,
    length,
    backingByteLength,
  });
}

type IntrinsicGetter = (this: unknown) => unknown;
type IntrinsicMethod = (this: unknown, ...values: unknown[]) => unknown;

function captureIntrinsicGetter(
  prototype: object,
  key: PropertyKey,
): IntrinsicGetter {
  const getter = INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    prototype,
    key,
  )?.get;
  if (typeof getter !== "function") {
    throw new Error(`Missing required intrinsic getter: ${String(key)}`);
  }
  return getter;
}

function captureOptionalIntrinsicGetter(
  prototype: object,
  key: PropertyKey,
): IntrinsicGetter | null {
  const getter = INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    prototype,
    key,
  )?.get;
  return typeof getter === "function" ? getter : null;
}

function captureIntrinsicMethod(
  prototype: object,
  key: PropertyKey,
): IntrinsicMethod {
  const method = INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    prototype,
    key,
  )?.value;
  if (typeof method !== "function") {
    throw new Error(`Missing required intrinsic method: ${String(key)}`);
  }
  return method as IntrinsicMethod;
}

function callIntrinsicGetter(
  getter: IntrinsicGetter,
  receiver: unknown,
): unknown {
  return INTRINSIC_REFLECT_APPLY(getter, receiver, []);
}

function tryIntrinsicGetter(
  getter: IntrinsicGetter,
  receiver: unknown,
): { readonly ok: true; readonly value: unknown } | { readonly ok: false } {
  try {
    return { ok: true, value: callIntrinsicGetter(getter, receiver) };
  } catch {
    return { ok: false };
  }
}

function readSafeIntegerIntrinsic(
  getter: IntrinsicGetter,
  receiver: unknown,
): number {
  return expectSafeInteger(callIntrinsicGetter(getter, receiver));
}

function expectSafeInteger(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new TypeError("invalid intrinsic length");
  }
  return value;
}

function parseUuid(
  value: unknown,
  pattern: RegExp,
  version: "UUIDv4" | "UUIDv7",
  label: string,
): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw invalid(`${label} must be a lowercase canonical ${version}.`);
  }
  return value;
}

function expectPlainDataRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${label} must be a plain data record.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalid(`${label} must be a plain data record.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw invalid(`${label} must not contain symbol properties.`);
    }
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw invalid(`${label} must contain only enumerable data properties.`);
    }
  }
  return value as Record<string, unknown>;
}

function validateByteBounds(
  options: CanonicalBase64UrlOptions,
  label: string,
): void {
  if (
    !Number.isSafeInteger(options.minBytes) ||
    !Number.isSafeInteger(options.maxBytes) ||
    options.minBytes < 0 ||
    options.maxBytes < options.minBytes ||
    options.maxBytes > DEFAULT_MAX_BASE64URL_BYTES
  ) {
    throw invalid(`${label} byte bounds are invalid.`);
  }
}

function invalid(message: string): DeliveryValidationError {
  return new DeliveryValidationError(message);
}
