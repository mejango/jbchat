import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  DeliveryValidationError,
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  copyBytes,
  decodeFingerprint32,
  decodeHash32,
  expectExactRecord,
  parseConversationId,
  parseCredentialId,
  parseEnvelopeClass,
  parseEnvelopeContentType,
  parseEnvelopeId,
  parseEnvelopeSender,
  parseHash32,
  parsePositiveUint63String,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  type ConversationId,
  type CredentialId,
  type EnvelopeClass,
  type EnvelopeContentType,
  type EnvelopeId,
  type EnvelopeSender,
  type Fingerprint32,
  type Hash32,
  type Rfc3339Millis,
  type SigningKeyId,
  type Uint63String,
} from "./valueObjects";

export const ENVELOPE_LEAF_HASH_DOMAIN = "jb-msg-envelope-leaf/v1" as const;
export const LOG_HEAD_HASH_DOMAIN = "jb-msg-log-head/v1" as const;
export const DELIVERY_LOG_CHECKPOINT_DIGEST_DOMAIN =
  "jb-msg-delivery-log-checkpoint/v1" as const;
export const EXTERNAL_PROPOSAL_HASH_DOMAIN =
  "jb-msg-external-proposal/v1" as const;

const U32_MAX = 0xffff_ffffn;

export interface EnvelopeLeafInput {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly envelopeId: EnvelopeId;
  readonly envelopeClass: EnvelopeClass;
  readonly sender: EnvelopeSender;
  readonly epoch: Uint63String;
  readonly rosterVersion: Uint63String;
  readonly contentType: EnvelopeContentType;
  readonly envelopeSha256: Hash32;
  readonly receivedAt: Rfc3339Millis;
}

export interface DeliveryLogCheckpointInput {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly previousHeadHash: Hash32;
  readonly headHash: Hash32;
  readonly signingKeyId: SigningKeyId;
}

/** Encodes only a bigint. Protocol integers must never cross this API as numbers. */
export function encodeU32Be(value: bigint): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value > U32_MAX) {
    throw invalid("length must be a u32 bigint.");
  }
  return Uint8Array.of(
    Number((value >> 24n) & 0xffn),
    Number((value >> 16n) & 0xffn),
    Number((value >> 8n) & 0xffn),
    Number(value & 0xffn),
  );
}

/** Returns u32be(byteLength) followed by a newly owned copy of the bytes. */
export function lengthPrefix(value: Uint8Array): Uint8Array {
  const bytes = copyBytes(value, "length-prefixed bytes");
  return concatenateBytes(encodeU32Be(BigInt(bytes.byteLength)), bytes);
}

/** Applies an independent u32be length prefix to each supplied byte string. */
export function canonicalLengthPrefixed(
  ...values: readonly Uint8Array[]
): Uint8Array {
  return concatenateBytes(...values.map((value) => lengthPrefix(value)));
}

/** The only primitive used here is Node's SHA-256 over exact caller-owned copies. */
export function sha256Bytes(...values: readonly Uint8Array[]): Hash32 {
  const digest = createHash("sha256");
  for (const value of values) {
    digest.update(copyBytes(value, "SHA-256 input"));
  }
  return parseHash32(digest.digest("base64url"), "SHA-256 digest");
}

export function computeEnvelopeSha256(envelopeBytes: Uint8Array): Hash32 {
  return sha256Bytes(copyBytes(envelopeBytes, "envelopeBytes"));
}

export function parseEnvelopeLeafInput(value: unknown): EnvelopeLeafInput {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "position",
      "envelopeId",
      "envelopeClass",
      "sender",
      "epoch",
      "rosterVersion",
      "contentType",
      "envelopeSha256",
      "receivedAt",
    ],
    "envelope leaf input",
  );
  const envelopeClass = parseEnvelopeClass(record.envelopeClass);
  const contentType = parseEnvelopeContentType(record.contentType);
  const sender = parseEnvelopeSender(record.sender);
  requireClassSenderAndMediaType(envelopeClass, sender, contentType);

  return Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    position: parsePositiveUint63String(record.position, "position"),
    envelopeId: parseEnvelopeId(record.envelopeId),
    envelopeClass,
    sender,
    epoch: parseUint63String(record.epoch, "epoch"),
    rosterVersion: parseUint63String(record.rosterVersion, "rosterVersion"),
    contentType,
    envelopeSha256: parseHash32(record.envelopeSha256, "envelopeSha256"),
    receivedAt: parseRfc3339Millis(record.receivedAt, "receivedAt"),
  });
}

/**
 * SHA-256(domain || LP(conversation) || ... || LP(receivedAt)). The
 * senderFields item is itself LP(inner), while inner independently prefixes
 * every variant field. This nested boundary prevents null/empty/tag aliases.
 */
export function computeEnvelopeLeafHash(input: EnvelopeLeafInput): Hash32 {
  const parsed = parseEnvelopeLeafInput(input);
  return sha256Bytes(
    utf8(ENVELOPE_LEAF_HASH_DOMAIN),
    canonicalLengthPrefixed(
      utf8(parsed.conversationId),
      utf8(parsed.position),
      utf8(parsed.envelopeId),
      utf8(parsed.envelopeClass),
      utf8(parsed.sender.type),
      encodeEnvelopeSenderFields(parsed.sender),
      utf8(parsed.epoch),
      utf8(parsed.rosterVersion),
      utf8(parsed.contentType),
      decodeHash32(parsed.envelopeSha256, "envelopeSha256"),
      utf8(parsed.receivedAt),
    ),
  );
}

/**
 * SHA-256(domain || u32be-LP(publicMessage) || authorizationRecordHash raw32).
 * The exact grammar sync's verifier recomputes; the write path and the
 * verifier must never drift apart.
 */
export function computeExternalProposalHash(
  publicMessage: Uint8Array,
  authorizationRecordHash: Hash32,
): Hash32 {
  return sha256Bytes(
    utf8(EXTERNAL_PROPOSAL_HASH_DOMAIN),
    lengthPrefix(copyBytes(publicMessage, "publicMessage")),
    decodeHash32(
      parseHash32(authorizationRecordHash, "authorizationRecordHash"),
      "authorizationRecordHash",
    ),
  );
}

/** SHA-256(domain || previous raw32 || leaf raw32). */
export function computeLogHeadHash(
  previousHeadHash: Hash32,
  leafHash: Hash32,
): Hash32 {
  const previous = parseHash32(previousHeadHash, "previousHeadHash");
  const leaf = parseHash32(leafHash, "leafHash");
  return sha256Bytes(
    utf8(LOG_HEAD_HASH_DOMAIN),
    decodeHash32(previous, "previousHeadHash"),
    decodeHash32(leaf, "leafHash"),
  );
}

export function parseDeliveryLogCheckpointInput(
  value: unknown,
): DeliveryLogCheckpointInput {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "position",
      "previousHeadHash",
      "headHash",
      "signingKeyId",
    ],
    "delivery log checkpoint input",
  );
  const parsed = Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    position: parsePositiveUint63String(record.position, "position"),
    previousHeadHash: parseHash32(
      record.previousHeadHash,
      "previousHeadHash",
    ),
    headHash: parseHash32(record.headHash, "headHash"),
    signingKeyId: parseSigningKeyId(record.signingKeyId),
  });
  if (parsed.position === "1" && parsed.previousHeadHash !== ZERO_HASH32) {
    throw invalid("position one must bind the all-zero previous head hash.");
  }
  if (parsed.position !== "1" && parsed.previousHeadHash === ZERO_HASH32) {
    throw invalid("only position one may bind the all-zero previous head hash.");
  }
  return parsed;
}

/**
 * Produces the exact digest a later Ed25519 signer will sign. This module does
 * not own a key, perform signing, or verify a signature.
 */
export function computeDeliveryLogCheckpointDigest(
  input: DeliveryLogCheckpointInput,
): Hash32 {
  const parsed = parseDeliveryLogCheckpointInput(input);
  return sha256Bytes(
    utf8(DELIVERY_LOG_CHECKPOINT_DIGEST_DOMAIN),
    canonicalLengthPrefixed(
      utf8(parsed.conversationId),
      utf8(parsed.position),
      decodeHash32(parsed.previousHeadHash, "previousHeadHash"),
      decodeHash32(parsed.headHash, "headHash"),
      utf8(parsed.signingKeyId),
    ),
  );
}

/** Returns the variant's inner encoding; the leaf adds its outer LP. */
export function encodeEnvelopeSenderFields(sender: EnvelopeSender): Uint8Array {
  const parsed = parseEnvelopeSender(sender);
  if (parsed.type === "installation") {
    return canonicalLengthPrefixed(
      utf8(parsed.accountId),
      utf8(parsed.installationId),
    );
  }
  return encodeEntitlementSignerFields(
    parsed.credentialId,
    parsed.fingerprint,
    parsed.signerGeneration,
  );
}

function encodeEntitlementSignerFields(
  credentialId: CredentialId,
  fingerprint: Fingerprint32,
  signerGeneration: Uint63String,
): Uint8Array {
  return canonicalLengthPrefixed(
    utf8(parseCredentialId(credentialId)),
    decodeFingerprint32(fingerprint),
    utf8(parsePositiveUint63String(signerGeneration, "signerGeneration")),
  );
}

function requireClassSenderAndMediaType(
  envelopeClass: EnvelopeClass,
  sender: EnvelopeSender,
  contentType: EnvelopeContentType,
): void {
  if (envelopeClass === "external_proposal") {
    if (
      sender.type !== "entitlement_signer" ||
      contentType !== MLS_PUBLIC_MESSAGE_MEDIA_TYPE
    ) {
      throw invalid(
        "external_proposal requires an entitlement signer and public MLS media type.",
      );
    }
    return;
  }
  if (envelopeClass === "mls_commit") {
    if (
      sender.type !== "installation" ||
      contentType !== MLS_PUBLIC_MESSAGE_MEDIA_TYPE
    ) {
      throw invalid(
        "mls_commit requires an installation sender and public MLS media type.",
      );
    }
    return;
  }
  if (
    sender.type !== "installation" ||
    contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE
  ) {
    throw invalid(
      "application requires an installation sender and private MLS media type.",
    );
  }
}

function utf8(value: string): Uint8Array {
  return copyBytes(Buffer.from(value, "utf8"));
}

function concatenateBytes(...values: readonly Uint8Array[]): Uint8Array {
  const copies = values.map((value) =>
    copyBytes(value, "canonical bytes", Number(U32_MAX)),
  );
  const totalLength = copies.reduce(
    (total, value) => total + value.byteLength,
    0,
  );
  if (!Number.isSafeInteger(totalLength) || BigInt(totalLength) > U32_MAX) {
    throw invalid("canonical byte encoding exceeds u32 length capacity.");
  }
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const value of copies) {
    combined.set(value, offset);
    offset += value.byteLength;
  }
  return combined;
}

function invalid(message: string): DeliveryValidationError {
  return new DeliveryValidationError(message);
}
