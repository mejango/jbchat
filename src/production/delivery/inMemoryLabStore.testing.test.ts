import { Buffer } from "node:buffer";
import { createPublicKey, verify as verifyEd25519 } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  LAB_ATTACHMENT_ID,
  LAB_BASE_HEAD_HASH,
  LAB_BASE_POSITION,
  LAB_CONVERSATION_ID,
  LAB_ENVELOPE_ID,
  LAB_ENVELOPE_ID_2,
  LAB_IDEMPOTENCY_KEY_2,
  LAB_LATER_NOW,
  LAB_NOW,
  LAB_RECIPIENT_INSTALLATION_ID,
  fictionalAppendRequest,
  fictionalDeliveryLabSeed,
  fictionalDeliveryLimits,
  fictionalDeliveryTrustContext,
} from "./fixtures.testing";
import {
  computeDeliveryLogCheckpointDigest,
} from "./hashes";
import {
  DELIVERY_LAB_FAILPOINTS,
  FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL,
  InMemoryDeliveryLabStore,
  type DeliveryLabFailpoint,
  verifyFictionalDeliveryLabReceiptSignatureForTesting,
} from "./inMemoryLabStore.testing";
import { createApplicationEnvelopeDeliveryService } from "./service";
import {
  ZERO_HASH32,
  parseHash32,
  parseRfc3339Millis,
  parseUint63String,
} from "./valueObjects";

const MALFORMED = {
  status: "unavailable",
  reasonCode: "malformed-dependency-response",
} as const;

const RESERVATION_ROLLBACK_FAILPOINTS = [
  "before-reservation-prepare",
  "after-reservation-prepare",
  "before-reservation-commit",
] as const satisfies readonly DeliveryLabFailpoint[];

const FINALIZATION_ROLLBACK_FAILPOINTS = [
  "after-state-write",
  "after-envelope-write",
  "after-mailbox-write",
  "after-outbox-write",
  "after-secondary-write",
  "after-idempotency-write",
  "before-finalization-commit",
] as const satisfies readonly DeliveryLabFailpoint[];

const ACTIVE_REMOVED_INSTALLATION_ID =
  "7ec2d18e-f082-48f0-8b01-55e43fed021c";
const PREJOIN_INSTALLATION_ID =
  "8ec2d18e-f082-48f0-8b01-55e43fed021c";
const SUSPENDED_INSTALLATION_ID =
  "9ec2d18e-f082-48f0-8b01-55e43fed021c";

describe("fictional pre-G1 in-memory delivery lab", () => {
  it("appends one gap-free signed application suffix from a verified base anchor", async () => {
    const { store, service } = lab();
    const result = await service.appendApplicationEnvelope(
      fictionalAppendRequest({ attachmentIds: [LAB_ATTACHMENT_ID] }),
    );

    expect(result).toMatchObject({
      status: "accepted",
      replay: "none",
      receipt: {
        envelopeId: LAB_ENVELOPE_ID,
        position: "2",
        logHead: { previousHeadHash: LAB_BASE_HEAD_HASH },
      },
    });
    if (result.status !== "accepted") throw new Error("append was not accepted");
    const state = store.inspectForTesting();
    expect(state).toMatchObject({
      basePosition: LAB_BASE_POSITION,
      baseHeadHash: LAB_BASE_HEAD_HASH,
      snapshot: {
        conversation: { lastPosition: "2" },
        usage: { envelopeCount: "1", attachmentBytes: "321" },
      },
      envelopes: [{ position: "2", previousHeadHash: LAB_BASE_HEAD_HASH }],
      outbox: [{ position: "2", envelopeId: LAB_ENVELOPE_ID }],
      secondaryEnvelopeRecordCount: 1,
      boundAttachmentCount: 1,
    });
    expect(state.pendingIntentDigest).toBeNull();
    expect(state.mailboxes.map(({ entries }) => entries.length)).toEqual([1, 1]);
    expect(result.receipt.logHead.checkpointDigest).toBe(
      computeDeliveryLogCheckpointDigest({
        conversationId: result.receipt.conversationId,
        position: result.receipt.position,
        previousHeadHash: result.receipt.logHead.previousHeadHash,
        headHash: result.receipt.logHead.headHash,
        signingKeyId: result.receipt.logHead.signingKeyId,
      }),
    );
    expect(verifyFictionalDeliveryLabReceiptSignatureForTesting(result.receipt)).toBe(
      true,
    );
    const publicKey = createPublicKey({
      key: Buffer.from(
        FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL,
        "base64url",
      ),
      format: "der",
      type: "spki",
    });
    expect(
      verifyEd25519(
        null,
        Buffer.from(result.receipt.logHead.checkpointDigest, "base64url"),
        publicKey,
        Buffer.from(result.receipt.logHead.signature, "base64url"),
      ),
    ).toBe(true);
  });

  it("returns the exact original receipt for HTTP replay and conflicts on reuse", async () => {
    const { store, service } = lab();
    const first = await service.appendApplicationEnvelope(fictionalAppendRequest());
    const replay = await service.appendApplicationEnvelope(fictionalAppendRequest());
    const conflict = await service.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: LAB_ENVELOPE_ID_2,
        ciphertextText: "conflicting exact HTTP body",
      }),
    );

    expect(first).toMatchObject({ status: "accepted", replay: "none" });
    expect(replay).toMatchObject({ status: "accepted", replay: "http" });
    if (first.status === "accepted" && replay.status === "accepted") {
      expect(JSON.stringify(replay.receipt)).toBe(JSON.stringify(first.receipt));
    }
    expect(conflict).toEqual({
      status: "conflict",
      reasonCode: "idempotency-conflict",
    });
    expectCommittedOnce(store);
  });

  it("replays historical acceptance before current limits and rejects mutation/new admission", async () => {
    const { store, service } = lab();
    const first = await service.appendApplicationEnvelope(fictionalAppendRequest());
    store.setNowForTesting(LAB_LATER_NOW);
    const disabled = fictionalDeliveryLimits({
      applicationCiphertextDecodedMaxBytes: parseUint63String("0"),
      attachmentsMaxPerEnvelope: parseUint63String("0"),
    });
    const lowerService = serviceFor(store, disabled);
    const replay = await lowerService.appendApplicationEnvelope(
      fictionalAppendRequest({ idempotencyKey: LAB_IDEMPOTENCY_KEY_2 }),
    );
    const mutation = await lowerService.appendApplicationEnvelope(
      fictionalAppendRequest({
        idempotencyKey: "0198a5d9-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "mutated historical envelope",
      }),
    );
    const fresh = await lowerService.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: LAB_ENVELOPE_ID_2,
        idempotencyKey: "0198a5da-4c58-7e31-bbf1-0fd4c09e4acf",
      }),
    );

    expect(replay).toMatchObject({ status: "accepted", replay: "envelope" });
    if (first.status === "accepted" && replay.status === "accepted") {
      expect(JSON.stringify(replay.receipt)).toBe(JSON.stringify(first.receipt));
    }
    expect(mutation).toEqual({
      status: "conflict",
      reasonCode: "idempotency-conflict",
    });
    expect(fresh.status).toBe("rejected");
    expectCommittedOnce(store);
  });

  it.each([
    ["application bytes", { applicationCiphertextDecodedMaxBytes: "0" }, []],
    ["attachments", { attachmentsMaxPerEnvelope: "0" }, [LAB_ATTACHMENT_ID]],
  ] as const)("honors a signed zero %s limit for a true miss", async (_name, overrides, attachmentIds) => {
    const limits = fictionalDeliveryLimits(
      Object.fromEntries(
        Object.entries(overrides).map(([key, value]) => [
          key,
          parseUint63String(value),
        ]),
      ),
    );
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed(limits));
    const result = await serviceFor(store, limits).appendApplicationEnvelope(
      fictionalAppendRequest({ attachmentIds }),
    );
    expect(result).toEqual({
      status: "rejected",
      reasonCode: "delivery-limit-exceeded",
    });
    expectBaselineOnly(store);
  });

  it.each([
    ["ETag", { ifMatch: '"e21-r28"' }, "conversation-state-changed"],
    ["epoch", { expectedEpoch: "21" }, "conversation-state-changed"],
    ["policy", { policyHeadHash: hash(40) }, "policy-head-not-current"],
  ] as const)("rejects stale %s state without reserving", async (_name, options, reason) => {
    const { store, service } = lab();
    const result = await service.appendApplicationEnvelope(
      fictionalAppendRequest(options),
    );
    expect(result).toEqual({ status: "rejected", reasonCode: reason });
    expectBaselineOnly(store);
  });

  it("enforces HTTP credential freshness separately from public MLS framing", async () => {
    const { store, service } = lab();
    const result = await service.appendApplicationEnvelope({
      ...fictionalAppendRequest(),
      authenticatedCredentialRevocationVersion: "5",
    });
    expect(result).toEqual({
      status: "rejected",
      reasonCode: "sender-credential-mismatch",
    });
    expectBaselineOnly(store);
  });

  it("linearizes distinct concurrent requests into consecutive suffix positions", async () => {
    const { store, service } = lab();
    const results = await Promise.all([
      service.appendApplicationEnvelope(fictionalAppendRequest()),
      service.appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: LAB_ENVELOPE_ID_2,
          idempotencyKey: LAB_IDEMPOTENCY_KEY_2,
          ciphertextText: "second concurrent application",
        }),
      ),
    ]);
    const positions = results
      .filter((result) => result.status === "accepted")
      .map((result) => result.receipt.position)
      .sort();
    expect(positions).toEqual(["2", "3"]);
    expect(store.inspectForTesting().envelopes.map(({ position }) => position)).toEqual([
      "2",
      "3",
    ]);
  });

  it("mutates once for concurrent exact reuse and conflicts for changed reuse", async () => {
    const exactLab = lab();
    const exact = await Promise.all([
      exactLab.service.appendApplicationEnvelope(fictionalAppendRequest()),
      exactLab.service.appendApplicationEnvelope(fictionalAppendRequest()),
    ]);
    expect(exact.every(({ status }) => status === "accepted")).toBe(true);
    expect(
      exact.map((result) => result.status === "accepted" && result.replay).sort(),
    ).toEqual(["http", "none"]);
    expectCommittedOnce(exactLab.store);

    const conflictLab = lab();
    const conflicting = await Promise.all([
      conflictLab.service.appendApplicationEnvelope(fictionalAppendRequest()),
      conflictLab.service.appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: LAB_ENVELOPE_ID_2,
          ciphertextText: "same key, changed semantics",
        }),
      ),
    ]);
    expect(conflicting.map(({ status }) => status).sort()).toEqual([
      "accepted",
      "conflict",
    ]);
    expectCommittedOnce(conflictLab.store);
  });

  it.each(RESERVATION_ROLLBACK_FAILPOINTS)(
    "rolls Tx-A back completely at %s",
    async (failpoint) => {
      const { store, service } = lab();
      store.setFailpointForTesting(failpoint);
      await expect(
        service.appendApplicationEnvelope(
          fictionalAppendRequest({ attachmentIds: [LAB_ATTACHMENT_ID] }),
        ),
      ).resolves.toEqual(MALFORMED);
      expectBaselineOnly(store);

      const retry = await serviceFor(store).appendApplicationEnvelope(
        fictionalAppendRequest({ attachmentIds: [LAB_ATTACHMENT_ID] }),
      );
      expect(retry).toMatchObject({ status: "accepted", receipt: { position: "2" } });
      expectCommittedOnce(store, true);
    },
  );

  it("recovers the same durable intent after a lost Tx-A commit response", async () => {
    const { store, service } = lab();
    store.setFailpointForTesting("after-reservation-commit-before-response");
    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual(MALFORMED);
    const pendingDigest = store.inspectForTesting().pendingIntentDigest;
    expectPendingOnly(store);
    expect(store.inspectForTesting().signerHistory).toHaveLength(0);

    store.setNowForTesting("2026-08-14T16:20:47.123Z");
    const retry = await serviceFor(store).appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    expect(retry).toMatchObject({
      status: "accepted",
      receipt: { position: "2", receivedAt: LAB_NOW },
    });
    expect(pendingDigest).not.toBeNull();
    expectCommittedOnce(store);
  });

  it.each([
    "before-signer-call",
    "after-signer-call",
    "before-signature-verifier-call",
    "after-signature-verifier-call",
  ] as const satisfies readonly DeliveryLabFailpoint[])(
    "recovers a fenced signature without visible mutation at %s",
    async (failpoint) => {
      const { store, service } = lab();
      store.setFailpointForTesting(failpoint);
      await expect(
        service.appendApplicationEnvelope(fictionalAppendRequest()),
      ).resolves.toEqual(MALFORMED);
      expectPendingOnly(store);
      const before = store.inspectForTesting().signerHistory;
      expect(before).toHaveLength(failpoint === "before-signer-call" ? 0 : 1);

      const retry = await serviceFor(store).appendApplicationEnvelope(
        fictionalAppendRequest(),
      );
      expect(retry).toMatchObject({ status: "accepted", receipt: { position: "2" } });
      const after = store.inspectForTesting().signerHistory;
      expect(after).toHaveLength(1);
      if (before[0]) {
        expect(after[0]?.checkpointDigest).toBe(before[0].checkpointDigest);
        expect(after[0]?.signature).toBe(before[0].signature);
      }
      expectCommittedOnce(store);
    },
  );

  it.each(FINALIZATION_ROLLBACK_FAILPOINTS)(
    "rolls every Tx-B projection back at %s",
    async (failpoint) => {
      const { store, service } = lab();
      store.setFailpointForTesting(failpoint);
      await expect(
        service.appendApplicationEnvelope(
          fictionalAppendRequest({ attachmentIds: [LAB_ATTACHMENT_ID] }),
        ),
      ).resolves.toEqual(MALFORMED);
      expectPendingOnly(store);

      const retry = await serviceFor(store).appendApplicationEnvelope(
        fictionalAppendRequest({ attachmentIds: [LAB_ATTACHMENT_ID] }),
      );
      expect(retry).toMatchObject({ status: "accepted", receipt: { position: "2" } });
      expectCommittedOnce(store, true);
    },
  );

  it("recovers an original receipt without duplicate fanout after lost Tx-B response", async () => {
    const { store, service } = lab();
    store.setFailpointForTesting("after-finalization-commit-before-response");
    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual(MALFORMED);
    expectCommittedOnce(store);
    const signature = store.inspectForTesting().signerHistory[0]?.signature;

    const retry = await serviceFor(store).appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    expect(retry).toMatchObject({ status: "accepted", replay: "http" });
    expectCommittedOnce(store);
    expect(store.inspectForTesting().signerHistory).toHaveLength(1);
    expect(store.inspectForTesting().signerHistory[0]?.signature).toBe(signature);
  });

  it("fences one digest and signature for each conversation position", async () => {
    const { store, service } = lab();
    const accepted = await service.appendApplicationEnvelope(fictionalAppendRequest());
    if (accepted.status !== "accepted") throw new Error("append was not accepted");
    const differentHead = parseHash32(hash(50));
    const differentDigest = computeDeliveryLogCheckpointDigest({
      conversationId: accepted.receipt.conversationId,
      position: accepted.receipt.position,
      previousHeadHash: accepted.receipt.logHead.previousHeadHash,
      headHash: differentHead,
      signingKeyId: accepted.receipt.logHead.signingKeyId,
    });
    const controller = new AbortController();
    const result = await store.productionPorts.checkpointSigner.sign({
      profile: "delivery-log-checkpoint.v1",
      conversationId: accepted.receipt.conversationId,
      position: accepted.receipt.position,
      previousHeadHash: accepted.receipt.logHead.previousHeadHash,
      headHash: differentHead,
      signingKeyId: accepted.receipt.logHead.signingKeyId,
      checkpointDigest: differentDigest,
      deadline: parseRfc3339Millis("2026-08-14T16:21:00.000Z"),
      signal: controller.signal,
    });
    expect(result).toEqual(MALFORMED);
    expect(store.inspectForTesting().signerHistory).toHaveLength(1);
  });

  it("rejects checkpoint, head, and canonical signature mutations", async () => {
    const { service } = lab();
    const accepted = await service.appendApplicationEnvelope(fictionalAppendRequest());
    if (accepted.status !== "accepted") throw new Error("append was not accepted");
    const receipt = accepted.receipt;
    expect(
      verifyFictionalDeliveryLabReceiptSignatureForTesting({
        ...receipt,
        logHead: { ...receipt.logHead, checkpointDigest: ZERO_HASH32 },
      }),
    ).toBe(false);
    expect(
      verifyFictionalDeliveryLabReceiptSignatureForTesting({
        ...receipt,
        logHead: {
          ...receipt.logHead,
          signature: Buffer.alloc(64, 0).toString("base64url"),
        },
      }),
    ).toBe(false);
    const changedHead = parseHash32(hash(51));
    expect(
      verifyFictionalDeliveryLabReceiptSignatureForTesting({
        ...receipt,
        logHead: {
          ...receipt.logHead,
          headHash: changedHead,
          checkpointDigest: computeDeliveryLogCheckpointDigest({
            conversationId: receipt.conversationId,
            position: receipt.position,
            previousHeadHash: receipt.logHead.previousHeadHash,
            headHash: changedHead,
            signingKeyId: receipt.logHead.signingKeyId,
          }),
        },
      }),
    ).toBe(false);
  });

  it("fans out only within authoritative recipient windows and syncs private mailboxes", async () => {
    const baseSeed = fictionalDeliveryLabSeed();
    const sender = baseSeed.recipientProjections[0]!;
    const always = baseSeed.recipientProjections[1]!;
    const store = new InMemoryDeliveryLabStore({
      ...baseSeed,
      recipientProjections: [
        sender,
        always,
        recipient(ACTIVE_REMOVED_INSTALLATION_ID, "active", "1", "2"),
        recipient(PREJOIN_INSTALLATION_ID, "active", "3", null),
        recipient(SUSPENDED_INSTALLATION_ID, "suspended", "1", null),
      ],
    });
    const service = serviceFor(store);
    await service.appendApplicationEnvelope(fictionalAppendRequest());
    await service.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: LAB_ENVELOPE_ID_2,
        idempotencyKey: LAB_IDEMPOTENCY_KEY_2,
        ciphertextText: "position three application",
      }),
    );

    expect(mailboxPositions(store, ACTIVE_REMOVED_INSTALLATION_ID)).toEqual(["2"]);
    expect(mailboxPositions(store, PREJOIN_INSTALLATION_ID)).toEqual(["3"]);
    expect(mailboxPositions(store, SUSPENDED_INSTALLATION_ID)).toEqual([]);
    expect(mailboxPositions(store, LAB_RECIPIENT_INSTALLATION_ID)).toEqual([
      "2",
      "3",
    ]);
    expect(
      store.syncConversationForInstallation(
        LAB_CONVERSATION_ID,
        ACTIVE_REMOVED_INSTALLATION_ID,
        LAB_BASE_POSITION,
        "10",
      ),
    ).toMatchObject({ events: [{ position: "2" }], hasMore: false });
    expect(store.readGlobalTranscriptForTesting().map(({ position }) => position)).toEqual([
      "2",
      "3",
    ]);
  });

  it.each(["missing", "stale", "suspended", "removed"] as const)(
    "rejects a %s sender recipient projection seed",
    (kind) => {
      const seed = fictionalDeliveryLabSeed();
      const sender = seed.recipientProjections[0]!;
      const replacement =
        kind === "stale"
          ? { ...sender, rosterVersion: "27" }
          : kind === "suspended"
            ? { ...sender, installationState: "suspended" }
            : { ...sender, removedPosition: "2" };
      const recipientProjections =
        kind === "missing"
          ? seed.recipientProjections.slice(1)
          : [replacement, ...seed.recipientProjections.slice(1)];
      expect(
        () => new InMemoryDeliveryLabStore({ ...seed, recipientProjections }),
      ).toThrow(/recipient roster|sender membership/i);
    },
  );

  it("declares every exercised failpoint in the lab contract", () => {
    expect(new Set(DELIVERY_LAB_FAILPOINTS).size).toBe(
      DELIVERY_LAB_FAILPOINTS.length,
    );
  });
});

function lab() {
  const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
  return { store, service: serviceFor(store) };
}

function serviceFor(
  store: InMemoryDeliveryLabStore,
  limits = fictionalDeliveryLimits(),
) {
  return createApplicationEnvelopeDeliveryService(
    store.productionPorts,
    fictionalDeliveryTrustContext(limits),
  );
}

function expectBaselineOnly(store: InMemoryDeliveryLabStore): void {
  const state = store.inspectForTesting();
  expect(state.snapshot.conversation).toMatchObject({
    lastPosition: LAB_BASE_POSITION,
    currentLogHeadHash: LAB_BASE_HEAD_HASH,
  });
  expect(state.snapshot.usage).toEqual(state.baseUsage);
  expect(state.pendingIntentDigest).toBeNull();
  expect(state.envelopes).toHaveLength(0);
  expect(state.mailboxes.every(({ entries }) => entries.length === 0)).toBe(true);
  expect(state.outbox).toHaveLength(0);
  expect(state.httpIdempotencyRecordCount).toBe(0);
  expect(state.secondaryEnvelopeRecordCount).toBe(0);
  expect(state.boundAttachmentCount).toBe(0);
  expect(state.signerHistory).toHaveLength(0);
}

function expectPendingOnly(store: InMemoryDeliveryLabStore): void {
  const state = store.inspectForTesting();
  expect(state.snapshot.conversation.lastPosition).toBe(LAB_BASE_POSITION);
  expect(state.snapshot.usage).toEqual(state.baseUsage);
  expect(state.pendingIntentDigest).not.toBeNull();
  expect(state.envelopes).toHaveLength(0);
  expect(state.mailboxes.every(({ entries }) => entries.length === 0)).toBe(true);
  expect(state.outbox).toHaveLength(0);
  expect(state.httpIdempotencyRecordCount).toBe(0);
  expect(state.secondaryEnvelopeRecordCount).toBe(0);
  expect(state.boundAttachmentCount).toBe(0);
}

function expectCommittedOnce(
  store: InMemoryDeliveryLabStore,
  attachmentBound = false,
): void {
  const state = store.inspectForTesting();
  expect(state.snapshot.conversation.lastPosition).toBe("2");
  expect(state.pendingIntentDigest).toBeNull();
  expect(state.envelopes).toHaveLength(1);
  expect(state.outbox).toHaveLength(1);
  expect(state.httpIdempotencyRecordCount).toBe(1);
  expect(state.secondaryEnvelopeRecordCount).toBe(1);
  expect(state.mailboxes.map(({ entries }) => entries.length)).toEqual([1, 1]);
  expect(state.boundAttachmentCount).toBe(attachmentBound ? 1 : 0);
}

function recipient(
  installationId: string,
  installationState: "active" | "suspended" | "revoked",
  joinedPosition: string,
  removedPosition: string | null,
) {
  return {
    conversationId: LAB_CONVERSATION_ID,
    installationId,
    rosterVersion: "28",
    installationState,
    joinedPosition,
    removedPosition,
  };
}

function mailboxPositions(
  store: InMemoryDeliveryLabStore,
  installationId: string,
): string[] {
  return store
    .inspectForTesting()
    .mailboxes.find((mailbox) => mailbox.installationId === installationId)!
    .entries.map(({ envelope }) => envelope.position);
}

function hash(byte: number): string {
  return Buffer.alloc(32, byte).toString("base64url");
}
