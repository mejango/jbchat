import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  copyBytes,
  expectExactRecord,
  parseAttachmentId,
  parseCanonicalBase64Url,
  parseCanonicalBase64UrlBytes,
  parseConversationEtag,
  parseConversationId,
  parseEd25519Signature,
  parseEnvelopeContentType,
  parseEnvelopeId,
  parseEnvelopeSender,
  parseHash32,
  parsePolicyHeadId,
  parsePositiveUint63String,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  type AttachmentId,
  type CanonicalBase64Url,
  type ConversationEtag,
  type ConversationId,
  type Ed25519Signature,
  type EntitlementSignerEnvelopeSender,
  type EnvelopeClass,
  type EnvelopeContentType,
  type EnvelopeId,
  type EnvelopeSender,
  type Hash32,
  type InstallationEnvelopeSender,
  type PolicyHeadId,
  type Rfc3339Millis,
  type SigningKeyId,
  type Uint63String,
} from "./valueObjects";
import { parseDeliveryLimits, type DeliveryLimits } from "./limits";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
} from "./hashes";

export const MAX_APPLICATION_ENVELOPE_BYTES = 64 * 1024;
export const MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES = 256 * 1024;
export const MAX_MLS_COMMIT_ENVELOPE_BYTES = 512 * 1024;
export const MAX_APPLICATION_ATTACHMENTS = 10;
export const MAX_APPLICATION_APPEND_JSON_BYTES = 96 * 1024;

const APPLICATION_APPEND_KEYS = [
  "envelopeId",
  "policyHeadId",
  "policyHeadSequence",
  "policyHeadHash",
  "expectedEpoch",
  "expectedRosterVersion",
  "expectedConfirmedTranscriptHash",
  "contentType",
  "ciphertext",
  "envelopeSha256",
  "attachmentIds",
] as const;

const STORED_ENVELOPE_COMMON_KEYS = [
  "conversationId",
  "position",
  "envelopeId",
  "envelopeClass",
  "contentType",
  "envelopeBytes",
  "envelopeSha256",
  "epoch",
  "rosterVersion",
  "sender",
  "receivedAt",
  "leafHash",
  "previousHeadHash",
  "headHash",
  "logSigningKeyId",
  "logCheckpointDigest",
  "logHeadSignature",
] as const;

const COMMIT_TRANSCRIPT_KEYS = [
  ...STORED_ENVELOPE_COMMON_KEYS,
  "baseConfirmedTranscriptHash",
  "resultingConfirmedTranscriptHash",
] as const;

export class DeliveryEnvelopeValidationError extends Error {
  readonly code = "invalid_delivery_envelope";

  constructor(message: string) {
    super(message);
    this.name = "DeliveryEnvelopeValidationError";
  }
}

export interface ApplicationAppendBody {
  readonly envelopeId: EnvelopeId;
  readonly policyHeadId: PolicyHeadId;
  readonly policyHeadSequence: Uint63String;
  readonly policyHeadHash: Hash32;
  readonly expectedEpoch: Uint63String;
  readonly expectedRosterVersion: Uint63String;
  readonly expectedConfirmedTranscriptHash: Hash32;
  readonly contentType: typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;
  readonly ciphertext: CanonicalBase64Url;
  readonly envelopeSha256: Hash32;
  readonly attachmentIds: readonly AttachmentId[];
}

export interface ParsedApplicationAppendJson {
  /** An owned copy of the exact bytes used by HTTP idempotency. */
  readonly rawBodyBytes: Uint8Array;
  readonly body: ApplicationAppendBody;
}

interface StoredEnvelopeCommon {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly envelopeId: EnvelopeId;
  readonly envelopeClass: EnvelopeClass;
  readonly contentType: EnvelopeContentType;
  /** Canonical wire representation. Decode only through the bounded parser. */
  readonly envelopeBytes: CanonicalBase64Url;
  readonly envelopeSha256: Hash32;
  readonly epoch: Uint63String;
  readonly rosterVersion: Uint63String;
  readonly sender: EnvelopeSender;
  readonly receivedAt: Rfc3339Millis;
  readonly leafHash: Hash32;
  readonly previousHeadHash: Hash32;
  readonly headHash: Hash32;
  readonly logSigningKeyId: SigningKeyId;
  readonly logCheckpointDigest: Hash32;
  readonly logHeadSignature: Ed25519Signature;
}

export interface StoredExternalProposalEnvelope extends StoredEnvelopeCommon {
  readonly envelopeClass: "external_proposal";
  readonly contentType: typeof MLS_PUBLIC_MESSAGE_MEDIA_TYPE;
  readonly sender: EntitlementSignerEnvelopeSender;
}

export interface StoredMlsCommitEnvelope extends StoredEnvelopeCommon {
  readonly envelopeClass: "mls_commit";
  readonly contentType: typeof MLS_PUBLIC_MESSAGE_MEDIA_TYPE;
  readonly sender: InstallationEnvelopeSender;
  readonly baseConfirmedTranscriptHash: Hash32;
  readonly resultingConfirmedTranscriptHash: Hash32;
}

export interface StoredApplicationEnvelope extends StoredEnvelopeCommon {
  readonly envelopeClass: "application";
  readonly contentType: typeof MLS_PRIVATE_MESSAGE_MEDIA_TYPE;
  readonly sender: InstallationEnvelopeSender;
}

/**
 * Exact section-10 transcript projection. Application append-only metadata such
 * as policyHeadId and attachmentIds deliberately does not enter this wire union.
 */
export type StoredEnvelope =
  | StoredExternalProposalEnvelope
  | StoredMlsCommitEnvelope
  | StoredApplicationEnvelope;

export interface ApplicationEnvelopeSemanticIdentity {
  readonly conversationId: ConversationId;
  readonly ifMatch: ConversationEtag;
  readonly authenticatedSender: InstallationEnvelopeSender;
  readonly append: ApplicationAppendBody;
}

export interface AcceptedApplicationEnvelope<Receipt> {
  readonly identity: ApplicationEnvelopeSemanticIdentity;
  readonly receipt: Receipt;
}

export type ApplicationEnvelopeReplayClassification<Receipt> =
  | { readonly kind: "new" }
  | { readonly kind: "exact_replay"; readonly receipt: Receipt }
  | { readonly kind: "conflict" };

/**
 * Parse the only caller-controlled envelope body accepted by the application
 * append route. Sender, role, time, position, class, and receipt are absent by
 * construction and any attempt to add them is an unknown-field failure.
 */
export function parseApplicationAppendBody(
  value: unknown,
): ApplicationAppendBody {
  const record = expectExactRecord(
    value,
    APPLICATION_APPEND_KEYS,
    "application append body",
  );
  const attachmentValues = expectExactArray(
    record.attachmentIds,
    MAX_APPLICATION_ATTACHMENTS,
    "attachmentIds",
  );
  const attachmentIds = attachmentValues.map((attachmentId, index) =>
    parseAttachmentId(attachmentId, `attachmentIds[${index}]`),
  );
  if (new Set(attachmentIds).size !== attachmentIds.length) {
    throw invalid("attachmentIds must not contain duplicates.");
  }
  if (record.contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE) {
    throw invalid("Application data must use the MLS PrivateMessage media type.");
  }
  const ciphertextBytes = parseCanonicalBase64UrlBytes(
    record.ciphertext,
    "ciphertext",
    {
      minBytes: 1,
      maxBytes: MAX_APPLICATION_ENVELOPE_BYTES,
    },
  );
  const envelopeSha256 = parseHash32(
    record.envelopeSha256,
    "envelopeSha256",
  );
  if (computeEnvelopeSha256(ciphertextBytes) !== envelopeSha256) {
    throw invalid("envelopeSha256 does not match the exact ciphertext bytes.");
  }

  return Object.freeze({
    envelopeId: parseEnvelopeId(record.envelopeId),
    policyHeadId: parsePolicyHeadId(record.policyHeadId),
    policyHeadSequence: parsePositiveUint63String(
      record.policyHeadSequence,
      "policyHeadSequence",
    ),
    policyHeadHash: parseHash32(record.policyHeadHash, "policyHeadHash"),
    expectedEpoch: parseUint63String(record.expectedEpoch, "expectedEpoch"),
    expectedRosterVersion: parseUint63String(
      record.expectedRosterVersion,
      "expectedRosterVersion",
    ),
    expectedConfirmedTranscriptHash: parseHash32(
      record.expectedConfirmedTranscriptHash,
      "expectedConfirmedTranscriptHash",
    ),
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    ciphertext: parseCanonicalBase64Url(record.ciphertext, "ciphertext", {
      minBytes: 1,
      maxBytes: MAX_APPLICATION_ENVELOPE_BYTES,
    }),
    envelopeSha256,
    attachmentIds: Object.freeze(attachmentIds),
  });
}

/**
 * Admission-only policy. Call this only after HTTP and durable envelope-ID
 * replay both miss; canonical parsing intentionally remains readable under a
 * later, lower manifest so an exact historical retry can replay its receipt.
 */
export function enforceApplicationAppendDeliveryLimits(
  value: unknown,
  limits: DeliveryLimits,
): ApplicationAppendBody {
  const parsed = parseApplicationAppendBody(value);
  const parsedLimits = parseDeliveryLimits(limits);
  const ciphertextBytes = parseCanonicalBase64UrlBytes(
    parsed.ciphertext,
    "ciphertext",
    { minBytes: 1, maxBytes: MAX_APPLICATION_ENVELOPE_BYTES },
  );
  if (
    BigInt(ciphertextBytes.byteLength) >
    BigInt(parsedLimits.applicationCiphertextDecodedMaxBytes)
  ) {
    throw invalid("Ciphertext exceeds the authenticated manifest limit.");
  }
  if (
    BigInt(parsed.attachmentIds.length) >
    BigInt(parsedLimits.attachmentsMaxPerEnvelope)
  ) {
    throw invalid("Attachment count exceeds the authenticated manifest limit.");
  }
  return parsed;
}

/** Parse strict UTF-8 JSON while retaining an owned copy of the exact bytes. */
export function parseApplicationAppendJson(
  rawBody: unknown,
): ParsedApplicationAppendJson {
  const rawBodyBytes = copyBytes(
    rawBody,
    "application append JSON",
    MAX_APPLICATION_APPEND_JSON_BYTES,
  );
  if (
    rawBodyBytes.length >= 3 &&
    rawBodyBytes[0] === 0xef &&
    rawBodyBytes[1] === 0xbb &&
    rawBodyBytes[2] === 0xbf
  ) {
    throw invalid("Application append JSON must not contain a UTF-8 BOM.");
  }
  let json: string;
  try {
    json = new TextDecoder("utf-8", { fatal: true }).decode(rawBodyBytes);
  } catch {
    throw invalid("Application append JSON must be valid UTF-8.");
  }
  const decoded = parseJsonWithoutDuplicateObjectKeys(json);
  return Object.freeze({
    rawBodyBytes,
    body: parseApplicationAppendBody(decoded),
  });
}

export function parseStoredEnvelope(value: unknown): StoredEnvelope {
  const envelopeClass = readDataDiscriminator(value, "envelopeClass");
  if (
    envelopeClass !== "external_proposal" &&
    envelopeClass !== "mls_commit" &&
    envelopeClass !== "application"
  ) {
    throw invalid("Envelope class is unsupported.");
  }
  const record = expectExactRecord(
    value,
    envelopeClass === "mls_commit"
      ? COMMIT_TRANSCRIPT_KEYS
      : STORED_ENVELOPE_COMMON_KEYS,
    `${envelopeClass} envelope`,
  );
  const parsed = parseStoredCommon(record, envelopeClass);

  if (envelopeClass === "external_proposal") {
    if (
      parsed.contentType !== MLS_PUBLIC_MESSAGE_MEDIA_TYPE ||
      parsed.sender.type !== "entitlement_signer"
    ) {
      throw invalid(
        "External proposals must be public and authenticated by the entitlement signer.",
      );
    }
    return Object.freeze({
      ...parsed,
      envelopeClass,
      contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
      sender: parsed.sender,
    });
  }
  if (envelopeClass === "mls_commit") {
    if (
      parsed.contentType !== MLS_PUBLIC_MESSAGE_MEDIA_TYPE ||
      parsed.sender.type !== "installation"
    ) {
      throw invalid("MLS Commits must be public and authenticated by an installation.");
    }
    return Object.freeze({
      ...parsed,
      envelopeClass,
      contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
      sender: parsed.sender,
      baseConfirmedTranscriptHash: parseHash32(
        record.baseConfirmedTranscriptHash,
        "baseConfirmedTranscriptHash",
      ),
      resultingConfirmedTranscriptHash: parseHash32(
        record.resultingConfirmedTranscriptHash,
        "resultingConfirmedTranscriptHash",
      ),
    });
  }
  if (
    parsed.contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE ||
    parsed.sender.type !== "installation"
  ) {
    throw invalid("Applications must be private and authenticated by an installation.");
  }
  return Object.freeze({
    ...parsed,
    envelopeClass,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    sender: parsed.sender,
  });
}

/** Admission-only class ceiling; never apply current limits to history sync. */
export function enforceStoredEnvelopeDeliveryLimits(
  value: unknown,
  limits: DeliveryLimits,
): StoredEnvelope {
  const parsed = parseStoredEnvelope(value);
  const parsedLimits = parseDeliveryLimits(limits);
  const configuredMaximum =
    parsed.envelopeClass === "application"
      ? parsedLimits.applicationCiphertextDecodedMaxBytes
      : parsed.envelopeClass === "external_proposal"
        ? parsedLimits.externalProposalDecodedMaxBytes
        : parsedLimits.mlsCommitDecodedMaxBytes;
  const hardMaximum =
    parsed.envelopeClass === "application"
      ? MAX_APPLICATION_ENVELOPE_BYTES
      : parsed.envelopeClass === "external_proposal"
        ? MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES
        : MAX_MLS_COMMIT_ENVELOPE_BYTES;
  const envelopeBytes = parseCanonicalBase64UrlBytes(
    parsed.envelopeBytes,
    "envelopeBytes",
    { minBytes: 1, maxBytes: hardMaximum },
  );
  if (BigInt(envelopeBytes.byteLength) > BigInt(configuredMaximum)) {
    throw invalid("Envelope exceeds the authenticated manifest class limit.");
  }
  return parsed;
}

export function parseApplicationEnvelopeSemanticIdentity(
  value: unknown,
): ApplicationEnvelopeSemanticIdentity {
  const record = expectExactRecord(
    value,
    ["conversationId", "ifMatch", "authenticatedSender", "append"],
    "application envelope semantic identity",
  );
  const sender = parseEnvelopeSender(record.authenticatedSender);
  if (sender.type !== "installation") {
    throw invalid("An application append must be authenticated by an installation.");
  }
  return Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    ifMatch: parseConversationEtag(record.ifMatch),
    authenticatedSender: sender,
    append: parseApplicationAppendBody(record.append),
  });
}

/**
 * Secondary replay protection after the seven-day HTTP-idempotency row expires.
 * The database lookup key is (conversationId, envelopeId); exact semantic replay
 * returns the original immutable receipt, while any relabel or byte change is a
 * permanent conflict.
 */
export function classifyImmutableApplicationEnvelopeReplay<Receipt>(
  accepted: AcceptedApplicationEnvelope<Receipt> | undefined,
  candidate: unknown,
): ApplicationEnvelopeReplayClassification<Receipt> {
  const parsedCandidate = parseApplicationEnvelopeSemanticIdentity(candidate);
  if (!accepted) return Object.freeze({ kind: "new" });
  const parsedAccepted = parseApplicationEnvelopeSemanticIdentity(
    accepted.identity,
  );
  if (!sameParsedApplicationIdentity(parsedAccepted, parsedCandidate)) {
    return Object.freeze({ kind: "conflict" });
  }
  return Object.freeze({ kind: "exact_replay", receipt: accepted.receipt });
}

export function applicationEnvelopeSemanticallyEqual(
  left: unknown,
  right: unknown,
): boolean {
  return sameParsedApplicationIdentity(
    parseApplicationEnvelopeSemanticIdentity(left),
    parseApplicationEnvelopeSemanticIdentity(right),
  );
}

function parseStoredCommon(
  record: Record<string, unknown>,
  envelopeClass: EnvelopeClass,
): StoredEnvelopeCommon {
  const maximumBytes =
    envelopeClass === "application"
      ? MAX_APPLICATION_ENVELOPE_BYTES
      : envelopeClass === "external_proposal"
        ? MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES
        : MAX_MLS_COMMIT_ENVELOPE_BYTES;
  const envelopeBytes = parseCanonicalBase64UrlBytes(
    record.envelopeBytes,
    "envelopeBytes",
    { minBytes: 1, maxBytes: maximumBytes },
  );
  const envelopeSha256 = parseHash32(
    record.envelopeSha256,
    "envelopeSha256",
  );
  if (computeEnvelopeSha256(envelopeBytes) !== envelopeSha256) {
    throw invalid("envelopeSha256 does not match the exact stored envelope bytes.");
  }
  const parsed = {
    conversationId: parseConversationId(record.conversationId),
    position: parsePositiveUint63String(record.position, "position"),
    envelopeId: parseEnvelopeId(record.envelopeId),
    envelopeClass,
    contentType: parseEnvelopeContentType(record.contentType),
    envelopeBytes: parseCanonicalBase64Url(
      record.envelopeBytes,
      "envelopeBytes",
      { minBytes: 1, maxBytes: maximumBytes },
    ),
    envelopeSha256,
    epoch: parseUint63String(record.epoch, "epoch"),
    rosterVersion: parseUint63String(record.rosterVersion, "rosterVersion"),
    sender: parseEnvelopeSender(record.sender),
    receivedAt: parseRfc3339Millis(record.receivedAt),
    leafHash: parseHash32(record.leafHash, "leafHash"),
    previousHeadHash: parseHash32(record.previousHeadHash, "previousHeadHash"),
    headHash: parseHash32(record.headHash, "headHash"),
    logSigningKeyId: parseSigningKeyId(record.logSigningKeyId),
    logCheckpointDigest: parseHash32(
      record.logCheckpointDigest,
      "logCheckpointDigest",
    ),
    logHeadSignature: parseEd25519Signature(
      record.logHeadSignature,
      "logHeadSignature",
    ),
  };
  if (
    (parsed.position === "1") !==
    (parsed.previousHeadHash === ZERO_HASH32)
  ) {
    throw invalid(
      "Only position one may use the all-zero previous head hash, and it must do so.",
    );
  }
  const expectedLeafHash = computeEnvelopeLeafHash({
    conversationId: parsed.conversationId,
    position: parsed.position,
    envelopeId: parsed.envelopeId,
    envelopeClass: parsed.envelopeClass,
    sender: parsed.sender,
    epoch: parsed.epoch,
    rosterVersion: parsed.rosterVersion,
    contentType: parsed.contentType,
    envelopeSha256: parsed.envelopeSha256,
    receivedAt: parsed.receivedAt,
  });
  if (parsed.leafHash !== expectedLeafHash) {
    throw invalid("leafHash does not match the exact stored envelope metadata.");
  }
  if (
    parsed.headHash !==
    computeLogHeadHash(parsed.previousHeadHash, parsed.leafHash)
  ) {
    throw invalid("headHash does not extend previousHeadHash with this leafHash.");
  }
  if (
    parsed.logCheckpointDigest !==
    computeDeliveryLogCheckpointDigest({
      conversationId: parsed.conversationId,
      position: parsed.position,
      previousHeadHash: parsed.previousHeadHash,
      headHash: parsed.headHash,
      signingKeyId: parsed.logSigningKeyId,
    })
  ) {
    throw invalid(
      "logCheckpointDigest does not match the exact stored checkpoint fields.",
    );
  }
  return parsed;
}

function sameParsedApplicationIdentity(
  left: ApplicationEnvelopeSemanticIdentity,
  right: ApplicationEnvelopeSemanticIdentity,
): boolean {
  const a = left.append;
  const b = right.append;
  return (
    left.conversationId === right.conversationId &&
    left.ifMatch === right.ifMatch &&
    left.authenticatedSender.type === right.authenticatedSender.type &&
    left.authenticatedSender.accountId === right.authenticatedSender.accountId &&
    left.authenticatedSender.installationId ===
      right.authenticatedSender.installationId &&
    a.envelopeId === b.envelopeId &&
    a.policyHeadId === b.policyHeadId &&
    a.policyHeadSequence === b.policyHeadSequence &&
    a.policyHeadHash === b.policyHeadHash &&
    a.expectedEpoch === b.expectedEpoch &&
    a.expectedRosterVersion === b.expectedRosterVersion &&
    a.expectedConfirmedTranscriptHash === b.expectedConfirmedTranscriptHash &&
    a.contentType === b.contentType &&
    a.ciphertext === b.ciphertext &&
    a.envelopeSha256 === b.envelopeSha256 &&
    sameOrderedStrings(a.attachmentIds, b.attachmentIds)
  );
}

function sameOrderedStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function expectExactArray(
  value: unknown,
  maximumLength: number,
  label: string,
): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw invalid(`${label} must be an array.`);
  }
  if (value.length > maximumLength) {
    throw invalid(`${label} exceeds its maximum length.`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== value.length + 1 ||
    ownKeys.at(-1) !== "length"
  ) {
    throw invalid(`${label} must be a dense data-only array.`);
  }
  const parsed: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw invalid(`${label} must be a dense data-only array.`);
    }
    parsed.push(descriptor.value);
  }
  return parsed;
}

function readDataDiscriminator(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid("Envelope must be a plain object.");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalid("Envelope must be a plain object.");
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    throw invalid(`Envelope ${key} must be an own data property.`);
  }
  return descriptor.value;
}

/**
 * JSON.parse silently accepts duplicate member names. The delivery boundary
 * does not: this small bounded parser preserves ordinary JSON whitespace/order
 * while rejecting duplicate keys before an object can be security-validated.
 */
function parseJsonWithoutDuplicateObjectKeys(source: string): unknown {
  let offset = 0;
  let nodes = 0;

  function fail(): never {
    throw invalid("Application append body must be strict JSON without duplicate keys.");
  }

  function skipWhitespace(): void {
    while (
      source[offset] === " " ||
      source[offset] === "\n" ||
      source[offset] === "\r" ||
      source[offset] === "\t"
    ) {
      offset += 1;
    }
  }

  function parseString(): string {
    if (source[offset] !== '"') fail();
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const code = source.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        try {
          return JSON.parse(source.slice(start, offset)) as string;
        } catch {
          fail();
        }
      }
      if (code < 0x20) fail();
      if (code === 0x5c) {
        offset += 1;
        const escaped = source[offset];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(offset + 1, offset + 5))) {
            fail();
          }
          offset += 5;
          continue;
        }
        if (!escaped || !'"\\/bfnrt'.includes(escaped)) fail();
      }
      offset += 1;
    }
    fail();
  }

  function parseNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      source.slice(offset),
    );
    if (!match) fail();
    offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail();
    return value;
  }

  function parseValue(depth: number): unknown {
    if (depth > 16 || ++nodes > 256) fail();
    skipWhitespace();
    const current = source[offset];
    if (current === '"') return parseString();
    if (current === "{") return parseObject(depth + 1);
    if (current === "[") return parseArray(depth + 1);
    if (source.startsWith("true", offset)) {
      offset += 4;
      return true;
    }
    if (source.startsWith("false", offset)) {
      offset += 5;
      return false;
    }
    if (source.startsWith("null", offset)) {
      offset += 4;
      return null;
    }
    return parseNumber();
  }

  function parseObject(depth: number): Record<string, unknown> {
    offset += 1;
    skipWhitespace();
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    if (source[offset] === "}") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      skipWhitespace();
      if (source[offset] !== ":") fail();
      offset += 1;
      const value = parseValue(depth);
      Object.defineProperty(result, key, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      skipWhitespace();
      if (source[offset] === "}") {
        offset += 1;
        return result;
      }
      if (source[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  }

  function parseArray(depth: number): unknown[] {
    offset += 1;
    skipWhitespace();
    const result: unknown[] = [];
    if (source[offset] === "]") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      result.push(parseValue(depth));
      skipWhitespace();
      if (source[offset] === "]") {
        offset += 1;
        return result;
      }
      if (source[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  }

  const result = parseValue(0);
  skipWhitespace();
  if (offset !== source.length) fail();
  return result;
}

function invalid(message: string): DeliveryEnvelopeValidationError {
  return new DeliveryEnvelopeValidationError(message);
}
