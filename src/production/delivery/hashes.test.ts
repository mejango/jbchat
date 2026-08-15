import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  DELIVERY_LOG_CHECKPOINT_DIGEST_DOMAIN,
  ENVELOPE_LEAF_HASH_DOMAIN,
  LOG_HEAD_HASH_DOMAIN,
  canonicalLengthPrefixed,
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  encodeEnvelopeSenderFields,
  encodeU32Be,
  lengthPrefix,
  parseDeliveryLogCheckpointInput,
  parseEnvelopeLeafInput,
  sha256Bytes,
  type DeliveryLogCheckpointInput,
  type EnvelopeLeafInput,
} from "./hashes";
import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  parseConversationId,
  parseEnvelopeId,
  parseEnvelopeSender,
  parseHash32,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
} from "./valueObjects";

const CONVERSATION_ID = parseConversationId(
  "c99daf46-89d8-4e84-aada-53a04fa111c9",
);
const ACCOUNT_ID = "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26";
const INSTALLATION_ID = "5ec2d18e-f082-48fa-8b01-55e43fed021c";
const CREDENTIAL_ID = "2e6c1a5a-968a-4419-8569-4b3db779f951";
const FINGERPRINT = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const SIGNING_KEY_ID = parseSigningKeyId("delivery-log-2026q3");

const INSTALLATION_SENDER = parseEnvelopeSender({
  type: "installation",
  accountId: ACCOUNT_ID,
  installationId: INSTALLATION_ID,
});
const ENTITLEMENT_SENDER = parseEnvelopeSender({
  type: "entitlement_signer",
  credentialId: CREDENTIAL_ID,
  fingerprint: FINGERPRINT,
  signerGeneration: "7",
});

const VECTORS: readonly {
  readonly input: EnvelopeLeafInput;
  readonly expectedLeafHash: string;
  readonly previousHeadHash: string;
  readonly expectedHeadHash: string;
  readonly expectedCheckpointDigest: string;
}[] = [
  {
    input: {
      conversationId: CONVERSATION_ID,
      position: parseUint63String("1"),
      envelopeId: parseEnvelopeId("415609f1-9662-49f6-9cda-9ef319abe51d"),
      envelopeClass: "external_proposal",
      sender: ENTITLEMENT_SENDER,
      epoch: parseUint63String("19"),
      rosterVersion: parseUint63String("27"),
      contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
      envelopeSha256: parseHash32(
        "ERERERERERERERERERERERERERERERERERERERERERE",
      ),
      receivedAt: parseRfc3339Millis("2026-08-14T16:20:45.123Z"),
    },
    expectedLeafHash: "isvD8D9hWnAhIGl7nvYXPfG4UgHeZnvKGHWFqPOOaQo",
    previousHeadHash: ZERO_HASH32,
    expectedHeadHash: "c66VTo9Yz52vnl6uP_XLBepbITcZU9kNIjz0VaMZAmI",
    expectedCheckpointDigest: "C5xHbARhgSmJVLw2uMXFqJMHp7MXc3LbgIT8qdZ7LJo",
  },
  {
    input: {
      conversationId: CONVERSATION_ID,
      position: parseUint63String("2"),
      envelopeId: parseEnvelopeId("c74427fd-5f76-49b4-b6d3-01ab6bbd91f2"),
      envelopeClass: "mls_commit",
      sender: INSTALLATION_SENDER,
      epoch: parseUint63String("20"),
      rosterVersion: parseUint63String("28"),
      contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE,
      envelopeSha256: parseHash32(
        "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
      ),
      receivedAt: parseRfc3339Millis("2026-08-14T16:20:46.234Z"),
    },
    expectedLeafHash: "iEo8PnQkkUJ-JRfA1BM_AH53GZc3QMxwklMzN0xWm-8",
    previousHeadHash: "c66VTo9Yz52vnl6uP_XLBepbITcZU9kNIjz0VaMZAmI",
    expectedHeadHash: "bfouCKttdQ68yzkUumIso3NiUYUJe_uT5yycC1PI4W8",
    expectedCheckpointDigest: "2rc3NjukdJFrEqHHlLB2LaeCNKekZMImja_mv-EWh_I",
  },
  {
    input: {
      conversationId: CONVERSATION_ID,
      position: parseUint63String("3"),
      envelopeId: parseEnvelopeId("787a0328-ae6c-42c8-86be-00910fb94f6d"),
      envelopeClass: "application",
      sender: INSTALLATION_SENDER,
      epoch: parseUint63String("20"),
      rosterVersion: parseUint63String("28"),
      contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
      envelopeSha256: parseHash32(
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM",
      ),
      receivedAt: parseRfc3339Millis("2026-08-14T16:20:47.345Z"),
    },
    expectedLeafHash: "LDvvtPrQFh3B7PFuG5LkLUpPX5FVHAzRg5cqA6D5Nmg",
    previousHeadHash: "bfouCKttdQ68yzkUumIso3NiUYUJe_uT5yycC1PI4W8",
    expectedHeadHash: "ER1G9xzjgUiYi1sAi69xl6WHX89oHA5KxZR4t9AuDi0",
    expectedCheckpointDigest: "xKlFQSFgrGpNQE5mGwCU7z5mnYxYroQTOBO3Y2kaZtQ",
  },
] as const;

describe("Delivery Service canonical SHA-256 commitments", () => {
  it("pins every domain and encodes u32be length boundaries", () => {
    expect(ENVELOPE_LEAF_HASH_DOMAIN).toBe("jb-msg-envelope-leaf/v1");
    expect(LOG_HEAD_HASH_DOMAIN).toBe("jb-msg-log-head/v1");
    expect(DELIVERY_LOG_CHECKPOINT_DIGEST_DOMAIN).toBe(
      "jb-msg-delivery-log-checkpoint/v1",
    );
    expect(hex(encodeU32Be(0n))).toBe("00000000");
    expect(hex(encodeU32Be(1n))).toBe("00000001");
    expect(hex(encodeU32Be(0x01020304n))).toBe("01020304");
    expect(hex(encodeU32Be(0xffff_ffffn))).toBe("ffffffff");
    expect(() => encodeU32Be(-1n)).toThrow();
    expect(() => encodeU32Be(0x1_0000_0000n)).toThrow();
    expect(() => encodeU32Be(1 as unknown as bigint)).toThrow();

    expect(hex(lengthPrefix(Uint8Array.of(0xaa, 0xbb)))).toBe(
      "00000002aabb",
    );
    expect(
      hex(canonicalLengthPrefixed(new Uint8Array(), Uint8Array.of(0x7f))),
    ).toBe("00000000000000017f");
  });

  it("copies length-prefixed inputs and hashes exact immutable envelope bytes", () => {
    const source = Uint8Array.of(0xaa, 0xbb);
    const encoded = lengthPrefix(source);
    source[0] = 0;
    expect(hex(encoded)).toBe("00000002aabb");
    encoded[4] = 0;
    expect(source[0]).toBe(0);

    const envelope = Uint8Array.of(0, 1, 2, 3, 254, 255);
    expect(computeEnvelopeSha256(envelope)).toBe(
      "fqZGlYcV7Wh6qawvXXhf6xqTQR9PJf3Wx_zGqwf98OM",
    );
    expect(sha256Bytes(envelope)).toBe(
      "fqZGlYcV7Wh6qawvXXhf6xqTQR9PJf3Wx_zGqwf98OM",
    );
    envelope[0] = 1;
    expect(computeEnvelopeSha256(envelope)).not.toBe(
      "fqZGlYcV7Wh6qawvXXhf6xqTQR9PJf3Wx_zGqwf98OM",
    );
  });

  it("pins the nested senderFields encoding for both tagged variants", () => {
    expect(hex(encodeEnvelopeSenderFields(INSTALLATION_SENDER))).toBe(
      "0000002437663934633639302d326166342d346134352d613763632d396438356365366362643236" +
        "0000002435656332643138652d663038322d343866612d386230312d353565343366656430323163",
    );
    expect(hex(encodeEnvelopeSenderFields(ENTITLEMENT_SENDER))).toBe(
      "0000002432653663316135612d393638612d343431392d383536392d346233646237373966393531" +
        "00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "0000000137",
    );
  });

  it("matches fixed vectors for all three envelope classes and both sender tags", () => {
    for (const vector of VECTORS) {
      const leaf = computeEnvelopeLeafHash(vector.input);
      expect(leaf).toBe(vector.expectedLeafHash);
      const head = computeLogHeadHash(
        parseHash32(vector.previousHeadHash),
        leaf,
      );
      expect(head).toBe(vector.expectedHeadHash);
      expect(
        computeDeliveryLogCheckpointDigest({
          conversationId: vector.input.conversationId,
          position: vector.input.position,
          previousHeadHash: parseHash32(vector.previousHeadHash),
          headHash: head,
          signingKeyId: SIGNING_KEY_ID,
        }),
      ).toBe(vector.expectedCheckpointDigest);
    }
  });

  it("changes the leaf for every routing field and sender subfield", () => {
    const baseline = VECTORS[2].input;
    const baselineHash = computeEnvelopeLeafHash(baseline);
    const alternateId = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const mutations: readonly EnvelopeLeafInput[] = [
      { ...baseline, conversationId: parseConversationId(alternateId) },
      { ...baseline, position: parseUint63String("4") },
      { ...baseline, envelopeId: parseEnvelopeId(alternateId) },
      {
        ...baseline,
        sender: parseEnvelopeSender({
          type: "installation",
          accountId: alternateId,
          installationId: INSTALLATION_ID,
        }),
      },
      {
        ...baseline,
        sender: parseEnvelopeSender({
          type: "installation",
          accountId: ACCOUNT_ID,
          installationId: alternateId,
        }),
      },
      { ...baseline, epoch: parseUint63String("21") },
      { ...baseline, rosterVersion: parseUint63String("29") },
      {
        ...baseline,
        envelopeSha256: parseHash32(
          "REREREREREREREREREREREREREREREREREREREREREQ",
        ),
      },
      {
        ...baseline,
        receivedAt: parseRfc3339Millis("2026-08-14T16:20:47.346Z"),
      },
    ];
    for (const mutation of mutations) {
      expect(computeEnvelopeLeafHash(mutation)).not.toBe(baselineHash);
    }
    expect(computeEnvelopeLeafHash(VECTORS[0].input)).not.toBe(baselineHash);
    expect(computeEnvelopeLeafHash(VECTORS[1].input)).not.toBe(baselineHash);

    const signerBaseline = VECTORS[0].input;
    for (const sender of [
      parseEnvelopeSender({
        type: "entitlement_signer",
        credentialId: alternateId,
        fingerprint: FINGERPRINT,
        signerGeneration: "7",
      }),
      parseEnvelopeSender({
        type: "entitlement_signer",
        credentialId: CREDENTIAL_ID,
        fingerprint: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        signerGeneration: "7",
      }),
      parseEnvelopeSender({
        type: "entitlement_signer",
        credentialId: CREDENTIAL_ID,
        fingerprint: FINGERPRINT,
        signerGeneration: "8",
      }),
    ]) {
      expect(computeEnvelopeLeafHash({ ...signerBaseline, sender })).not.toBe(
        computeEnvelopeLeafHash(signerBaseline),
      );
    }
  });

  it("rejects class/sender/media substitutions before hashing", () => {
    const external = VECTORS[0].input;
    const commit = VECTORS[1].input;
    const application = VECTORS[2].input;
    for (const input of [
      { ...external, sender: INSTALLATION_SENDER },
      { ...external, contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE },
      { ...commit, sender: ENTITLEMENT_SENDER },
      { ...commit, contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE },
      { ...application, sender: ENTITLEMENT_SENDER },
      { ...application, contentType: MLS_PUBLIC_MESSAGE_MEDIA_TYPE },
    ]) {
      expect(() =>
        computeEnvelopeLeafHash(input as unknown as EnvelopeLeafInput),
      ).toThrow();
    }
  });

  it("rejects unknown fields, prototypes, accessors, zero position, and forged brands", () => {
    const baseline = VECTORS[2].input;
    expect(() => parseEnvelopeLeafInput({ ...baseline, extra: true })).toThrow();
    expect(() =>
      parseEnvelopeLeafInput(Object.assign(Object.create({}), baseline)),
    ).toThrow();
    expect(() => parseEnvelopeLeafInput({ ...baseline, position: "0" })).toThrow();
    expect(() =>
      parseEnvelopeLeafInput({
        ...baseline,
        envelopeSha256: `${baseline.envelopeSha256}=`,
      }),
    ).toThrow();

    let accessed = false;
    const accessor = { ...baseline } as Record<string, unknown>;
    Object.defineProperty(accessor, "position", {
      enumerable: true,
      get() {
        accessed = true;
        return "3";
      },
    });
    expect(() => parseEnvelopeLeafInput(accessor)).toThrow();
    expect(accessed).toBe(false);
  });

  it("binds previous/head/key in checkpoint digests and reserves the zero sentinel", () => {
    const first = VECTORS[0];
    const valid: DeliveryLogCheckpointInput = {
      conversationId: first.input.conversationId,
      position: first.input.position,
      previousHeadHash: parseHash32(first.previousHeadHash),
      headHash: parseHash32(first.expectedHeadHash),
      signingKeyId: SIGNING_KEY_ID,
    };
    expect(parseDeliveryLogCheckpointInput(valid)).toEqual(valid);

    const mutations: readonly DeliveryLogCheckpointInput[] = [
      { ...valid, conversationId: parseConversationId(CREDENTIAL_ID) },
      {
        ...valid,
        headHash: parseHash32(VECTORS[1].expectedHeadHash),
      },
      { ...valid, signingKeyId: parseSigningKeyId("delivery-log-2026q4") },
    ];
    const baseline = computeDeliveryLogCheckpointDigest(valid);
    for (const mutation of mutations) {
      expect(computeDeliveryLogCheckpointDigest(mutation)).not.toBe(baseline);
    }

    expect(() =>
      parseDeliveryLogCheckpointInput({
        ...valid,
        previousHeadHash: parseHash32(VECTORS[1].expectedHeadHash),
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLogCheckpointInput({
        ...valid,
        position: parseUint63String("2"),
        previousHeadHash: ZERO_HASH32,
      }),
    ).toThrow();
    expect(() =>
      parseDeliveryLogCheckpointInput({ ...valid, extra: true }),
    ).toThrow();
  });
});

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
