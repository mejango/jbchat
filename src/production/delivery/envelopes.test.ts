import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  MAX_APPLICATION_ENVELOPE_BYTES,
  MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES,
  MAX_MLS_COMMIT_ENVELOPE_BYTES,
  applicationEnvelopeSemanticallyEqual as applicationEnvelopeSemanticallyEqualContract,
  classifyImmutableApplicationEnvelopeReplay as classifyImmutableApplicationEnvelopeReplayContract,
  enforceApplicationAppendDeliveryLimits,
  enforceStoredEnvelopeDeliveryLimits,
  parseApplicationAppendBody as parseApplicationAppendBodyContract,
  parseApplicationAppendJson as parseApplicationAppendJsonContract,
  parseApplicationEnvelopeSemanticIdentity as parseApplicationEnvelopeSemanticIdentityContract,
  parseStoredEnvelope as parseStoredEnvelopeContract,
} from "./envelopes";
import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
} from "./valueObjects";
import {
  DELIVERY_TESTED_CEILINGS,
  parseDeliveryLimits,
  type DeliveryLimits,
} from "./limits";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeLogHeadHash,
  type EnvelopeLeafInput,
} from "./hashes";

const CONVERSATION_ID = "c99daf46-89d8-4e84-aada-53a04fa111c9";
const ENVELOPE_ID = "415609f1-9662-49f6-9cda-9ef319abe51d";
const POLICY_HEAD_ID = "a4d721f6-8af9-4d82-afbe-e509e9a3fc2f";
const ACCOUNT_ID = "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26";
const INSTALLATION_ID = "5ec2d18e-f082-48f8-8b01-55e43fed021c";
const OTHER_INSTALLATION_ID = "c28ef6a2-93fc-4f88-97be-fb246f50c519";
const CREDENTIAL_ID = "61114b21-bec2-4c77-9250-fc99789a17aa";
const ATTACHMENT_A = "d6cf349c-047c-46ef-87e9-41ddf4d41871";
const ATTACHMENT_B = "a6739e58-ea34-4f75-8213-434a1f359ecb";
const ETAG = '"e20-r28"';
const HASH_A = hash(bytes("hash-a"));
const HASH_B = hash(bytes("hash-b"));
const HASH_C = hash(bytes("hash-c"));
const HASH_D = hash(bytes("hash-d"));
const LIMITS = parseDeliveryLimits({ ...DELIVERY_TESTED_CEILINGS });

function deliveryLimits(
  overrides: Partial<Record<keyof DeliveryLimits, string>> = {},
): DeliveryLimits {
  return parseDeliveryLimits({ ...DELIVERY_TESTED_CEILINGS, ...overrides });
}

function parseApplicationAppendBody(
  value: unknown,
) {
  return parseApplicationAppendBodyContract(value);
}

function parseApplicationAppendJson(
  value: unknown,
) {
  return parseApplicationAppendJsonContract(value);
}

function parseApplicationEnvelopeSemanticIdentity(
  value: unknown,
) {
  return parseApplicationEnvelopeSemanticIdentityContract(value);
}

function parseStoredEnvelope(
  value: unknown,
) {
  return parseStoredEnvelopeContract(value);
}

function classifyImmutableApplicationEnvelopeReplay<Receipt>(
  accepted: Parameters<
    typeof classifyImmutableApplicationEnvelopeReplayContract<Receipt>
  >[0],
  candidate: unknown,
) {
  return classifyImmutableApplicationEnvelopeReplayContract(
    accepted,
    candidate,
  );
}

function applicationEnvelopeSemanticallyEqual(
  left: unknown,
  right: unknown,
) {
  return applicationEnvelopeSemanticallyEqualContract(left, right);
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function encoded(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function hash(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

function applicationBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const ciphertext = bytes("private MLS application ciphertext");
  return {
    envelopeId: ENVELOPE_ID,
    policyHeadId: POLICY_HEAD_ID,
    policyHeadSequence: "81",
    policyHeadHash: HASH_A,
    expectedEpoch: "20",
    expectedRosterVersion: "28",
    expectedConfirmedTranscriptHash: HASH_B,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    ciphertext: encoded(ciphertext),
    envelopeSha256: hash(ciphertext),
    attachmentIds: [ATTACHMENT_A, ATTACHMENT_B],
    ...overrides,
  };
}

function installationSender(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: "installation",
    accountId: ACCOUNT_ID,
    installationId: INSTALLATION_ID,
    ...overrides,
  };
}

function signerSender(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: "entitlement_signer",
    credentialId: CREDENTIAL_ID,
    fingerprint: HASH_C,
    signerGeneration: "14",
    ...overrides,
  };
}

function semanticIdentity(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    conversationId: CONVERSATION_ID,
    ifMatch: ETAG,
    authenticatedSender: installationSender(),
    append: applicationBody(),
    ...overrides,
  };
}

function storedEnvelope(
  envelopeClass: "external_proposal" | "mls_commit" | "application",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const wire = bytes(`${envelopeClass} exact MLS bytes`);
  const common: Record<string, unknown> = {
    conversationId: CONVERSATION_ID,
    position: "492",
    envelopeId: ENVELOPE_ID,
    envelopeClass,
    contentType:
      envelopeClass === "application"
        ? MLS_PRIVATE_MESSAGE_MEDIA_TYPE
        : MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
    envelopeBytes: encoded(wire),
    envelopeSha256: hash(wire),
    epoch: "20",
    rosterVersion: "28",
    sender:
      envelopeClass === "external_proposal"
        ? signerSender()
        : installationSender(),
    receivedAt: "2026-08-14T16:20:45.123Z",
    previousHeadHash: HASH_B,
    logSigningKeyId: "delivery-log-2026q3",
    logHeadSignature: encoded(new Uint8Array(64).fill(7)),
  };
  if (envelopeClass === "mls_commit") {
    common.baseConfirmedTranscriptHash = HASH_C;
    common.resultingConfirmedTranscriptHash = HASH_D;
  }
  return { ...rehashStoredEnvelope(common), ...overrides };
}

function rehashStoredEnvelope(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const leafHash = computeEnvelopeLeafHash({
    conversationId: value.conversationId,
    position: value.position,
    envelopeId: value.envelopeId,
    envelopeClass: value.envelopeClass,
    sender: value.sender,
    epoch: value.epoch,
    rosterVersion: value.rosterVersion,
    contentType: value.contentType,
    envelopeSha256: value.envelopeSha256,
    receivedAt: value.receivedAt,
  } as EnvelopeLeafInput);
  return {
    ...value,
    leafHash,
    ...checkpointFields(value, leafHash),
  };
}

function checkpointFields(
  value: Record<string, unknown>,
  leafHash: string,
): Record<string, unknown> {
  const headHash = computeLogHeadHash(
    value.previousHeadHash as never,
    leafHash as never,
  );
  const checkpoint = {
    conversationId: value.conversationId,
    position: value.position,
    previousHeadHash: value.previousHeadHash,
    headHash,
    signingKeyId: value.logSigningKeyId,
  };
  return {
    headHash,
    logCheckpointDigest: computeDeliveryLogCheckpointDigest(
      checkpoint as never,
    ),
  };
}

describe("application envelope append parsing", () => {
  it("accepts only the exact private append body and returns immutable normalized data", () => {
    const parsed = parseApplicationAppendBody(applicationBody());
    expect(parsed).toEqual(applicationBody());
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.attachmentIds)).toBe(true);
  });

  it("retains exact raw JSON bytes while allowing ordinary whitespace and key order", () => {
    const body = applicationBody();
    const raw = Buffer.from(`\n ${JSON.stringify(body, null, 2)} \t`, "utf8");
    const parsed = parseApplicationAppendJson(raw);
    expect(Buffer.from(parsed.rawBodyBytes).equals(raw)).toBe(true);
    expect(parsed.body).toEqual(body);

    raw.fill(0);
    expect(new TextDecoder().decode(parsed.rawBodyBytes)).toContain("envelopeId");
  });

  it("copies raw bytes without consulting hostile iterators or mutable backing modes", () => {
    const valid = Uint8Array.from(
      Buffer.from(JSON.stringify(applicationBody()), "utf8"),
    );
    let iteratorCalls = 0;
    Object.defineProperty(valid, Symbol.iterator, {
      configurable: true,
      value: function* hostileIterator() {
        iteratorCalls += 1;
        while (true) yield 0x20;
      },
    });
    expect(() => parseApplicationAppendJson(valid)).toThrow();
    expect(iteratorCalls).toBe(0);

    class ByteSubclass extends Uint8Array {}
    expect(() =>
      parseApplicationAppendJson(
        new ByteSubclass(Buffer.from(JSON.stringify(applicationBody()))),
      ),
    ).toThrow();

    let proxyReads = 0;
    const proxied = new Proxy(
      Uint8Array.from(Buffer.from(JSON.stringify(applicationBody()))),
      {
        get(target, property, receiver) {
          proxyReads += 1;
          return Reflect.get(target, property, receiver);
        },
      },
    );
    expect(() => parseApplicationAppendJson(proxied)).toThrow();
    expect(proxyReads).toBe(0);

    expect(() =>
      parseApplicationAppendJson(new Uint8Array(new SharedArrayBuffer(8))),
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
        parseApplicationAppendJson(new Uint8Array(resizable)),
      ).toThrow();
    }

    const detachedBuffer = new ArrayBuffer(8);
    const detached = new Uint8Array(detachedBuffer);
    structuredClone(detachedBuffer, { transfer: [detachedBuffer] });
    expect(() => parseApplicationAppendJson(detached)).toThrow();
  });

  it("rejects duplicate JSON keys, malformed UTF-8, BOMs, trailing data, and excessive JSON", () => {
    const body = applicationBody();
    const duplicate = JSON.stringify(body).replace(
      `"envelopeId":"${ENVELOPE_ID}"`,
      `"envelopeId":"${ENVELOPE_ID}","envelopeId":"${ENVELOPE_ID}"`,
    );
    for (const raw of [
      Buffer.from(duplicate),
      Uint8Array.from([0xff]),
      Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
      Buffer.from(`${JSON.stringify(body)} true`),
      new Uint8Array(96 * 1024 + 1),
      "not bytes",
    ]) {
      expect(() => parseApplicationAppendJson(raw)).toThrow();
    }
  });

  it("rejects every caller attempt to stamp trusted metadata", () => {
    for (const forbidden of [
      "sender",
      "role",
      "timestamp",
      "receivedAt",
      "position",
      "envelopeClass",
      "class",
      "receipt",
      "logHead",
    ]) {
      expect(() =>
        parseApplicationAppendBody(
          applicationBody({ [forbidden]: forbidden === "position" ? "1" : {} }),
        ),
      ).toThrow();
    }
  });

  it("rejects unknown fields, prototypes, symbols, and accessors without invoking them", () => {
    expect(() => parseApplicationAppendBody(applicationBody({ unknown: true }))).toThrow();
    expect(() =>
      parseApplicationAppendBody(Object.create(applicationBody())),
    ).toThrow();

    const symbolBody = applicationBody();
    Object.defineProperty(symbolBody, Symbol("hidden"), {
      value: true,
      enumerable: true,
    });
    expect(() => parseApplicationAppendBody(symbolBody)).toThrow();

    let getterCalls = 0;
    const accessorBody = applicationBody();
    Object.defineProperty(accessorBody, "ciphertext", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "AA";
      },
    });
    expect(() => parseApplicationAppendBody(accessorBody)).toThrow();
    expect(getterCalls).toBe(0);

    const hiddenBody = applicationBody();
    Object.defineProperty(hiddenBody, "ciphertext", {
      value: hiddenBody.ciphertext,
      enumerable: false,
    });
    expect(() => parseApplicationAppendBody(hiddenBody)).toThrow();
  });

  it("requires dense, ordered, unique, bounded attachment UUIDs", () => {
    expect(
      parseApplicationAppendBody(applicationBody({ attachmentIds: [] }))
        .attachmentIds,
    ).toEqual([]);
    for (const attachmentIds of [
      [ATTACHMENT_A, ATTACHMENT_A],
      Array.from({ length: 11 }, () => ATTACHMENT_A),
      [ATTACHMENT_A.toUpperCase()],
      [ENVELOPE_ID.replace("-4", "-7")],
      "not-an-array",
    ]) {
      expect(() =>
        parseApplicationAppendBody(applicationBody({ attachmentIds })),
      ).toThrow();
    }

    const sparse = [ATTACHMENT_A, ATTACHMENT_B];
    delete sparse[0];
    expect(() =>
      parseApplicationAppendBody(applicationBody({ attachmentIds: sparse })),
    ).toThrow();

    const accessor = [ATTACHMENT_A];
    let calls = 0;
    Object.defineProperty(accessor, "0", {
      enumerable: true,
      get() {
        calls += 1;
        return ATTACHMENT_A;
      },
    });
    expect(() =>
      parseApplicationAppendBody(applicationBody({ attachmentIds: accessor })),
    ).toThrow();
    expect(calls).toBe(0);
  });

  it("rejects noncanonical IDs and every unsafe counter form", () => {
    for (const mutation of [
      { envelopeId: ENVELOPE_ID.toUpperCase() },
      { envelopeId: ENVELOPE_ID.replace("-4", "-7") },
      { policyHeadId: POLICY_HEAD_ID.toUpperCase() },
      { policyHeadId: POLICY_HEAD_ID.replace("-4", "-7") },
    ]) {
      expect(() => parseApplicationAppendBody(applicationBody(mutation))).toThrow();
    }
    for (const field of [
      "policyHeadSequence",
      "expectedEpoch",
      "expectedRosterVersion",
    ]) {
      for (const value of [
        1,
        1n,
        "",
        "00",
        "01",
        "+1",
        "-1",
        "1.0",
        "1e3",
        "9223372036854775808",
      ]) {
        expect(() =>
          parseApplicationAppendBody(applicationBody({ [field]: value })),
        ).toThrow();
      }
    }
    expect(() =>
      parseApplicationAppendBody(applicationBody({ policyHeadSequence: "0" })),
    ).toThrow();
  });

  it("requires canonical bounded base64url bytes, the private media type, and the exact SHA-256", () => {
    const tooLarge = new Uint8Array(MAX_APPLICATION_ENVELOPE_BYTES + 1);
    for (const mutation of [
      { contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE },
      { contentType: `${MLS_PRIVATE_MESSAGE_MEDIA_TYPE}; charset=utf-8` },
      { ciphertext: "" },
      { ciphertext: "AA==" },
      { ciphertext: "AA+_" },
      { ciphertext: "AA/_" },
      { ciphertext: " AA" },
      { ciphertext: "AB", envelopeSha256: hash(Uint8Array.of(0)) },
      { envelopeSha256: HASH_D },
      { ciphertext: encoded(tooLarge), envelopeSha256: hash(tooLarge) },
    ]) {
      expect(() => parseApplicationAppendBody(applicationBody(mutation))).toThrow();
    }
  });

  it("applies lowered or zero manifest ceilings only at new-admission time", () => {
    const body = applicationBody();
    const ciphertextBytes = Buffer.from(body.ciphertext as string, "base64url");
    const zeroApplicationLimits = deliveryLimits({
      applicationCiphertextDecodedMaxBytes: "0",
    });
    expect(zeroApplicationLimits.applicationCiphertextDecodedMaxBytes).toBe(
      "0",
    );
    expect(() =>
      enforceApplicationAppendDeliveryLimits(
        body,
        deliveryLimits({
          applicationCiphertextDecodedMaxBytes: String(
            ciphertextBytes.byteLength,
          ),
        }),
      ),
    ).not.toThrow();
    expect(() =>
      enforceApplicationAppendDeliveryLimits(
        body,
        deliveryLimits({
          applicationCiphertextDecodedMaxBytes: String(
            ciphertextBytes.byteLength - 1,
          ),
        }),
      ),
    ).toThrow();
    expect(() =>
      enforceApplicationAppendDeliveryLimits(
        body,
        zeroApplicationLimits,
      ),
    ).toThrow();
    expect(() =>
      enforceApplicationAppendDeliveryLimits(
        body,
        deliveryLimits({ attachmentsMaxPerEnvelope: "1" }),
      ),
    ).toThrow();
    expect(() =>
      enforceApplicationAppendDeliveryLimits(
        applicationBody({ attachmentIds: [] }),
        deliveryLimits({ attachmentsMaxPerEnvelope: "0" }),
      ),
    ).not.toThrow();
    expect(() =>
      enforceApplicationAppendDeliveryLimits(body, undefined as never),
    ).toThrow();

    // Canonical hard-cap parsing remains independent of the current profile so
    // an old accepted envelope is still identifiable after limits are lowered.
    expect(() => parseApplicationAppendBody(body)).not.toThrow();
  });
});

describe("strict stored ordered-envelope union", () => {
  it("accepts each exact class and preserves the class-specific transcript fields", () => {
    const proposal = parseStoredEnvelope(storedEnvelope("external_proposal"));
    const commit = parseStoredEnvelope(storedEnvelope("mls_commit"));
    const application = parseStoredEnvelope(storedEnvelope("application"));

    expect(proposal.envelopeClass).toBe("external_proposal");
    expect(proposal.sender.type).toBe("entitlement_signer");
    expect(commit.envelopeClass).toBe("mls_commit");
    if (commit.envelopeClass !== "mls_commit") {
      throw new Error("fixture did not parse as an MLS Commit");
    }
    expect(commit.baseConfirmedTranscriptHash).toBe(HASH_C);
    expect(commit.resultingConfirmedTranscriptHash).toBe(HASH_D);
    expect(application.envelopeClass).toBe("application");
    expect(application.contentType).toBe(MLS_PRIVATE_MESSAGE_MEDIA_TYPE);
  });

  it("rejects every class, media-type, and authenticated-sender relabel", () => {
    for (const value of [
      storedEnvelope("external_proposal", {
        contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
      }),
      storedEnvelope("external_proposal", { sender: installationSender() }),
      storedEnvelope("mls_commit", { contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE }),
      storedEnvelope("mls_commit", { sender: signerSender() }),
      storedEnvelope("application", { contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE }),
      storedEnvelope("application", { sender: signerSender() }),
      { ...storedEnvelope("application"), envelopeClass: "unknown" },
    ]) {
      expect(() => parseStoredEnvelope(value)).toThrow();
    }
  });

  it("allows transcript hashes only on Commits and requires both", () => {
    const commit = storedEnvelope("mls_commit");
    const missingBase = { ...commit };
    delete missingBase.baseConfirmedTranscriptHash;
    const missingResult = { ...commit };
    delete missingResult.resultingConfirmedTranscriptHash;
    for (const value of [
      missingBase,
      missingResult,
      {
        ...storedEnvelope("application"),
        baseConfirmedTranscriptHash: HASH_A,
        resultingConfirmedTranscriptHash: HASH_B,
      },
      { ...storedEnvelope("external_proposal"), baseConfirmedTranscriptHash: HASH_A },
    ]) {
      expect(() => parseStoredEnvelope(value)).toThrow();
    }
  });

  it("checks exact bytes/hash and class-specific size ceilings", () => {
    for (const [envelopeClass, maximum] of [
      ["application", MAX_APPLICATION_ENVELOPE_BYTES],
      ["external_proposal", MAX_EXTERNAL_PROPOSAL_ENVELOPE_BYTES],
      ["mls_commit", MAX_MLS_COMMIT_ENVELOPE_BYTES],
    ] as const) {
      const atLimit = new Uint8Array(maximum);
      expect(() =>
        parseStoredEnvelope(
          rehashStoredEnvelope(
            storedEnvelope(envelopeClass, {
              envelopeBytes: encoded(atLimit),
              envelopeSha256: hash(atLimit),
            }),
          ),
        ),
      ).not.toThrow();
      const over = new Uint8Array(maximum + 1);
      expect(() =>
        parseStoredEnvelope(
          storedEnvelope(envelopeClass, {
            envelopeBytes: encoded(over),
            envelopeSha256: hash(over),
          }),
        ),
      ).toThrow();
    }
    expect(() =>
      parseStoredEnvelope(
        storedEnvelope("application", { envelopeSha256: HASH_D }),
      ),
    ).toThrow();
  });

  it("enforces the authenticated per-class manifest byte ceilings on stored items", () => {
    const cases = [
      ["application", "applicationCiphertextDecodedMaxBytes"],
      ["external_proposal", "externalProposalDecodedMaxBytes"],
      ["mls_commit", "mlsCommitDecodedMaxBytes"],
    ] as const;
    for (const [envelopeClass, limitKey] of cases) {
      const item = storedEnvelope(envelopeClass);
      const byteLength = Buffer.from(
        item.envelopeBytes as string,
        "base64url",
      ).byteLength;
      expect(() =>
        enforceStoredEnvelopeDeliveryLimits(
          item,
          deliveryLimits({ [limitKey]: String(byteLength) }),
        ),
      ).not.toThrow();
      expect(() =>
        enforceStoredEnvelopeDeliveryLimits(
          item,
          deliveryLimits({ [limitKey]: String(byteLength - 1) }),
        ),
      ).toThrow();
      const zeroLimits = deliveryLimits({ [limitKey]: "0" });
      expect(zeroLimits[limitKey]).toBe("0");
      expect(() => enforceStoredEnvelopeDeliveryLimits(item, zeroLimits)).toThrow();
      expect(() => parseStoredEnvelope(item)).not.toThrow();
    }
  });

  it("recomputes the leaf/head chain and enforces the position-one sentinel", () => {
    const first = rehashStoredEnvelope(
      storedEnvelope("application", {
        position: "1",
        previousHeadHash: ZERO_HASH32,
      }),
    );
    expect(() => parseStoredEnvelope(first)).not.toThrow();
    const wrongSentinel = {
      ...first,
      previousHeadHash: HASH_B,
      headHash: HASH_C,
      logCheckpointDigest: HASH_D,
    };
    expect(() => parseStoredEnvelope(wrongSentinel)).toThrow();

    const lateZeroSentinel = storedEnvelope("application", {
      position: "2",
      previousHeadHash: ZERO_HASH32,
    });
    expect(() => parseStoredEnvelope(lateZeroSentinel)).toThrow();

    const baseline = storedEnvelope("application");
    expect(() =>
      parseStoredEnvelope({ ...baseline, leafHash: HASH_A }),
    ).toThrow();
    expect(() =>
      parseStoredEnvelope({ ...baseline, headHash: HASH_D }),
    ).toThrow();
  });

  it("rejects malformed receipt-chain fields, counters, IDs, signatures, and time", () => {
    for (const mutation of [
      { position: "0" },
      { position: "01" },
      { epoch: 20 },
      { rosterVersion: "9223372036854775808" },
      { conversationId: CONVERSATION_ID.toUpperCase() },
      { envelopeId: ENVELOPE_ID.replace("-4", "-7") },
      { leafHash: "AA" },
      { previousHeadHash: HASH_B.slice(0, -1) },
      { headHash: `${HASH_C}=` },
      { receivedAt: "2026-08-14T16:20:45Z" },
      { receivedAt: "2026-08-14T16:20:45.123+00:00" },
      { logSigningKeyId: " delivery-log" },
      { logCheckpointDigest: HASH_D },
      { logHeadSignature: encoded(new Uint8Array(63)) },
      { logHeadSignature: encoded(new Uint8Array(65)) },
      { role: "project_owner" },
    ]) {
      expect(() =>
        parseStoredEnvelope(storedEnvelope("application", mutation)),
      ).toThrow();
    }
  });

  it("rejects prototype and accessor confusion before invoking accessors", () => {
    expect(() =>
      parseStoredEnvelope(Object.create(storedEnvelope("application"))),
    ).toThrow();
    const value = storedEnvelope("application");
    let calls = 0;
    Object.defineProperty(value, "envelopeClass", {
      enumerable: true,
      get() {
        calls += 1;
        return "application";
      },
    });
    expect(() => parseStoredEnvelope(value)).toThrow();
    expect(calls).toBe(0);
  });
});

describe("immutable envelope-ID semantic replay", () => {
  it("returns new on a miss and the same original receipt on an exact replay", () => {
    const identity = parseApplicationEnvelopeSemanticIdentity(semanticIdentity());
    const receipt = Object.freeze({ position: "492", headHash: HASH_C });
    expect(
      classifyImmutableApplicationEnvelopeReplay(undefined, identity),
    ).toEqual({ kind: "new" });
    const replay = classifyImmutableApplicationEnvelopeReplay(
      { identity, receipt },
      semanticIdentity(),
    );
    expect(replay).toEqual({ kind: "exact_replay", receipt });
    if (replay.kind === "exact_replay") expect(replay.receipt).toBe(receipt);
    expect(applicationEnvelopeSemanticallyEqual(identity, semanticIdentity())).toBe(
      true,
    );
  });

  it("replays an accepted envelope after limits lower but rejects changed or new oversized admissions", () => {
    const original = semanticIdentity();
    const identity = parseApplicationEnvelopeSemanticIdentity(original);
    const receipt = Object.freeze({ position: "492", headHash: HASH_C });
    expect(() =>
      enforceApplicationAppendDeliveryLimits(identity.append, LIMITS),
    ).not.toThrow();

    const lowered = deliveryLimits({
      applicationCiphertextDecodedMaxBytes: "1",
      attachmentsMaxPerEnvelope: "0",
    });
    const exactReplay = classifyImmutableApplicationEnvelopeReplay(
      { identity, receipt },
      semanticIdentity(),
    );
    expect(exactReplay).toEqual({ kind: "exact_replay", receipt });
    expect(() =>
      enforceApplicationAppendDeliveryLimits(identity.append, lowered),
    ).toThrow();

    const changedBytes = bytes("changed ciphertext still below the hard cap");
    const changed = semanticIdentity({
      append: applicationBody({
        ciphertext: encoded(changedBytes),
        envelopeSha256: hash(changedBytes),
      }),
    });
    expect(
      classifyImmutableApplicationEnvelopeReplay(
        { identity, receipt },
        changed,
      ),
    ).toEqual({ kind: "conflict" });

    const newEnvelope = semanticIdentity({
      append: applicationBody({
        envelopeId: "c74427fd-5f76-49b4-b6d3-01ab6bbd91f2",
      }),
    });
    expect(
      classifyImmutableApplicationEnvelopeReplay(undefined, newEnvelope),
    ).toEqual({ kind: "new" });
    const parsedNew = parseApplicationEnvelopeSemanticIdentity(newEnvelope);
    expect(() =>
      enforceApplicationAppendDeliveryLimits(parsedNew.append, lowered),
    ).toThrow();
  });

  it("conflicts on every valid scope, state, byte, attachment-order, or sender substitution", () => {
    const identity = parseApplicationEnvelopeSemanticIdentity(semanticIdentity());
    const accepted = { identity, receipt: { position: "492" } };
    const changedCiphertext = bytes("different exact ciphertext");
    const candidates = [
      semanticIdentity({
        conversationId: "cd5d7c41-e111-4389-84ba-8f7fdcd5a574",
      }),
      semanticIdentity({ ifMatch: '"e21-r28"' }),
      semanticIdentity({
        authenticatedSender: installationSender({
          installationId: OTHER_INSTALLATION_ID,
        }),
      }),
      semanticIdentity({
        authenticatedSender: installationSender({
          accountId: "7fd58f8d-f10e-43ae-b150-2835488d2dba",
        }),
      }),
      semanticIdentity({
        append: applicationBody({
          envelopeId: "c74427fd-5f76-49b4-b6d3-01ab6bbd91f2",
        }),
      }),
      semanticIdentity({
        append: applicationBody({
          policyHeadId: "ed2404ef-f51e-493d-9f63-11b634320a5c",
        }),
      }),
      semanticIdentity({
        append: applicationBody({ policyHeadSequence: "82" }),
      }),
      semanticIdentity({ append: applicationBody({ policyHeadHash: HASH_D }) }),
      semanticIdentity({ append: applicationBody({ expectedEpoch: "21" }) }),
      semanticIdentity({
        append: applicationBody({ expectedRosterVersion: "29" }),
      }),
      semanticIdentity({
        append: applicationBody({ expectedConfirmedTranscriptHash: HASH_D }),
      }),
      semanticIdentity({
        append: applicationBody({
          ciphertext: encoded(changedCiphertext),
          envelopeSha256: hash(changedCiphertext),
        }),
      }),
      semanticIdentity({
        append: applicationBody({ attachmentIds: [ATTACHMENT_B, ATTACHMENT_A] }),
      }),
      semanticIdentity({
        append: applicationBody({ attachmentIds: [ATTACHMENT_A] }),
      }),
    ];
    for (const candidate of candidates) {
      expect(
        classifyImmutableApplicationEnvelopeReplay(accepted, candidate),
      ).toEqual({ kind: "conflict" });
    }
  });

  it("does not admit an entitlement signer, role, or caller receipt into semantic identity", () => {
    expect(() =>
      parseApplicationEnvelopeSemanticIdentity(
        semanticIdentity({ authenticatedSender: signerSender() }),
      ),
    ).toThrow();
    expect(() =>
      parseApplicationEnvelopeSemanticIdentity(
        semanticIdentity({ authenticatedSender: installationSender({ role: "owner" }) }),
      ),
    ).toThrow();
    expect(() =>
      parseApplicationEnvelopeSemanticIdentity(
        semanticIdentity({ receipt: { position: "1" } }),
      ),
    ).toThrow();
  });
});
