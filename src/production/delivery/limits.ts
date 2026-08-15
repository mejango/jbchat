import {
  DeliveryValidationError,
  UINT63_MAX_VALUE,
  expectExactRecord,
  parseUint63String,
  type Uint63String,
} from "./valueObjects";

export const DELIVERY_EVENT_JSON_METADATA_OVERHEAD_BYTES = 4096n;
export const DELIVERY_PAGE_JSON_FIXED_OVERHEAD_BYTES = 4096n;
export const DELIVERY_CURSOR_MIN_CHARACTERS = 43n;

export const DELIVERY_LIMIT_KEYS = Object.freeze([
  "applicationCiphertextDecodedMaxBytes",
  "externalProposalDecodedMaxBytes",
  "mlsCommitDecodedMaxBytes",
  "welcomeDecodedMaxBytes",
  "pageDecodedArtifactsMaxBytes",
  "pageSerializedResponseMaxBytes",
  "conversationEventsMaxPerPage",
  "mailboxEntriesMaxPerPage",
  "conversationRecipientInstallationsMax",
  "cursorMaxCharacters",
  "attachmentsMaxPerEnvelope",
] as const);

export type DeliveryLimitKey = (typeof DELIVERY_LIMIT_KEYS)[number];

/**
 * Values copied from an authenticated release manifest. Every wire value
 * remains a canonical decimal string; callers opt in to bigint conversion at
 * arithmetic boundaries rather than risking JSON/JavaScript number coercion.
 */
export interface DeliveryLimits {
  readonly applicationCiphertextDecodedMaxBytes: Uint63String;
  readonly externalProposalDecodedMaxBytes: Uint63String;
  readonly mlsCommitDecodedMaxBytes: Uint63String;
  readonly welcomeDecodedMaxBytes: Uint63String;
  readonly pageDecodedArtifactsMaxBytes: Uint63String;
  readonly pageSerializedResponseMaxBytes: Uint63String;
  readonly conversationEventsMaxPerPage: Uint63String;
  readonly mailboxEntriesMaxPerPage: Uint63String;
  readonly conversationRecipientInstallationsMax: Uint63String;
  readonly cursorMaxCharacters: Uint63String;
  readonly attachmentsMaxPerEnvelope: Uint63String;
}

/** Reviewed ceilings. A signed deployment may lower, but never raise, them. */
export const DELIVERY_TESTED_CEILINGS: Readonly<
  Record<DeliveryLimitKey, Uint63String>
> = Object.freeze({
  applicationCiphertextDecodedMaxBytes: "65536" as Uint63String,
  externalProposalDecodedMaxBytes: "262144" as Uint63String,
  mlsCommitDecodedMaxBytes: "524288" as Uint63String,
  welcomeDecodedMaxBytes: "262144" as Uint63String,
  pageDecodedArtifactsMaxBytes: "4194304" as Uint63String,
  pageSerializedResponseMaxBytes: "8388608" as Uint63String,
  conversationEventsMaxPerPage: "500" as Uint63String,
  mailboxEntriesMaxPerPage: "100" as Uint63String,
  conversationRecipientInstallationsMax: "2500" as Uint63String,
  cursorMaxCharacters: "1024" as Uint63String,
  attachmentsMaxPerEnvelope: "10" as Uint63String,
});

/**
 * Parses the exact Delivery Service subsection of the signed manifest.
 * There are deliberately no defaults: omission, an unknown field, a number,
 * or a value above its reviewed ceiling prevents startup.
 */
export function parseDeliveryLimits(value: unknown): DeliveryLimits {
  const record = expectExactRecord(value, DELIVERY_LIMIT_KEYS, "deliveryLimits");
  const parsed = {} as Record<DeliveryLimitKey, Uint63String>;

  for (const key of DELIVERY_LIMIT_KEYS) {
    const limit = parseUint63String(record[key], `deliveryLimits.${key}`);
    if (BigInt(limit) > BigInt(DELIVERY_TESTED_CEILINGS[key])) {
      throw invalid(`deliveryLimits.${key} exceeds its reviewed ceiling.`);
    }
    parsed[key] = limit;
  }

  // Zero is an explicit signed-manifest disable for each artifact class.
  requirePositive(
    parsed.pageDecodedArtifactsMaxBytes,
    "pageDecodedArtifactsMaxBytes",
  );
  requirePositive(
    parsed.pageSerializedResponseMaxBytes,
    "pageSerializedResponseMaxBytes",
  );
  requirePositive(
    parsed.conversationEventsMaxPerPage,
    "conversationEventsMaxPerPage",
  );
  requirePositive(
    parsed.mailboxEntriesMaxPerPage,
    "mailboxEntriesMaxPerPage",
  );
  requirePositive(
    parsed.conversationRecipientInstallationsMax,
    "conversationRecipientInstallationsMax",
  );
  if (BigInt(parsed.cursorMaxCharacters) < DELIVERY_CURSOR_MIN_CHARACTERS) {
    throw invalid(
      "deliveryLimits.cursorMaxCharacters cannot hold a canonical cc1 cursor.",
    );
  }

  const decodedPage = BigInt(parsed.pageDecodedArtifactsMaxBytes);
  const largestSingleArtifact = maxBigInt(
    BigInt(parsed.applicationCiphertextDecodedMaxBytes),
    BigInt(parsed.externalProposalDecodedMaxBytes),
    BigInt(parsed.mlsCommitDecodedMaxBytes) +
      BigInt(parsed.welcomeDecodedMaxBytes),
  );
  if (decodedPage < largestSingleArtifact) {
    throw invalid(
      "deliveryLimits.pageDecodedArtifactsMaxBytes cannot contain one accepted artifact.",
    );
  }
  const maximumPageItems = maxTwoBigInts(
    BigInt(parsed.conversationEventsMaxPerPage),
    BigInt(parsed.mailboxEntriesMaxPerPage),
  );
  const minimumSerializedPageBytes = minimumSerializedDeliveryPageBytes(
    decodedPage,
    maximumPageItems,
  );
  if (
    BigInt(parsed.pageSerializedResponseMaxBytes) < minimumSerializedPageBytes
  ) {
    throw invalid(
      "deliveryLimits.pageSerializedResponseMaxBytes cannot encode a maximum bounded page.",
    );
  }

  return Object.freeze({
    applicationCiphertextDecodedMaxBytes:
      parsed.applicationCiphertextDecodedMaxBytes,
    externalProposalDecodedMaxBytes: parsed.externalProposalDecodedMaxBytes,
    mlsCommitDecodedMaxBytes: parsed.mlsCommitDecodedMaxBytes,
    welcomeDecodedMaxBytes: parsed.welcomeDecodedMaxBytes,
    pageDecodedArtifactsMaxBytes: parsed.pageDecodedArtifactsMaxBytes,
    pageSerializedResponseMaxBytes: parsed.pageSerializedResponseMaxBytes,
    conversationEventsMaxPerPage: parsed.conversationEventsMaxPerPage,
    mailboxEntriesMaxPerPage: parsed.mailboxEntriesMaxPerPage,
    conversationRecipientInstallationsMax:
      parsed.conversationRecipientInstallationsMax,
    cursorMaxCharacters: parsed.cursorMaxCharacters,
    attachmentsMaxPerEnvelope: parsed.attachmentsMaxPerEnvelope,
  });
}

/** Canonical unpadded base64url length: ceil(decodedBytes * 4 / 3). */
export function canonicalBase64UrlEncodedLength(
  decodedBytes: bigint,
): bigint {
  assertUint63BigInt(decodedBytes, "decoded artifact byte ceiling");
  const encoded = (decodedBytes * 4n + 2n) / 3n;
  if (encoded > UINT63_MAX_VALUE) {
    throw invalid("Canonical base64url length exceeds uint63.");
  }
  return encoded;
}

/**
 * Conservative final UTF-8 JSON bound for either conversation or mailbox
 * pages. It covers base64url expansion of the entire decoded-artifact budget,
 * fixed response framing, and one bounded metadata allowance per item.
 */
export function minimumSerializedDeliveryPageBytes(
  decodedArtifactBytes: bigint,
  maximumPageItems: bigint,
): bigint {
  assertUint63BigInt(decodedArtifactBytes, "decoded page byte ceiling");
  assertUint63BigInt(maximumPageItems, "page item ceiling");
  const result =
    canonicalBase64UrlEncodedLength(decodedArtifactBytes) +
    DELIVERY_PAGE_JSON_FIXED_OVERHEAD_BYTES +
    DELIVERY_EVENT_JSON_METADATA_OVERHEAD_BYTES * maximumPageItems;
  if (result > UINT63_MAX_VALUE) {
    throw invalid("Serialized page requirement exceeds uint63.");
  }
  return result;
}

function requirePositive(value: Uint63String, key: DeliveryLimitKey): void {
  if (value === "0") {
    throw invalid(`deliveryLimits.${key} must be greater than zero.`);
  }
}

function maxBigInt(first: bigint, second: bigint, third: bigint): bigint {
  return first > second
    ? first > third
      ? first
      : third
    : second > third
      ? second
      : third;
}

function maxTwoBigInts(first: bigint, second: bigint): bigint {
  return first > second ? first : second;
}

function assertUint63BigInt(value: bigint, label: string): void {
  if (typeof value !== "bigint" || value < 0n || value > UINT63_MAX_VALUE) {
    throw invalid(`${label} must be a uint63 bigint.`);
  }
}

function invalid(message: string): DeliveryValidationError {
  return new DeliveryValidationError(message);
}
