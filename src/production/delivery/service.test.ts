import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  LAB_CONVERSATION_ID,
  LAB_ENVELOPE_ID,
  fictionalAppendRequest,
  fictionalDeliveryLabSeed,
  fictionalDeliveryTrustContext,
} from "./fixtures.testing";
import {
  computeEnvelopeSha256,
  sha256Bytes,
} from "./hashes";
import { InMemoryDeliveryLabStore } from "./inMemoryLabStore.testing";
import type {
  DeliveryCheckpointSignatureVerificationRequest,
  MlsWireInspectionRequest,
  ProductionDeliveryPorts,
} from "./ports";
import {
  DeliveryServiceValidationError,
  computeMlsApplicationWireInspectionEvidenceDigest,
  createApplicationEnvelopeDeliveryService,
  parseAppendApplicationEnvelopeRequest,
  parseApplicationEnvelopeDeliveryTrustContext,
  parsePreparedApplicationAppend,
} from "./service";
import {
  computeDeliveryCheckpointSignatureEvidenceDigest,
} from "./sync";
import { createUnavailableProductionDeliveryPorts } from "./unavailable";
import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
  ZERO_HASH32,
  parseRfc3339Millis,
} from "./valueObjects";

describe("application-envelope delivery service boundary", () => {
  it("strictly parses caller input and the authenticated release trust context", () => {
    const parsed = parseAppendApplicationEnvelopeRequest(
      fictionalAppendRequest(),
    );
    expect(parsed.semanticIdentity.conversationId).toBe(
      parsed.request.resourceId,
    );
    expect(parsed.semanticIdentity.append.envelopeId).toBe(LAB_ENVELOPE_ID);

    expect(() =>
      parseAppendApplicationEnvelopeRequest({
        ...fictionalAppendRequest(),
        callerRole: "admin",
      }),
    ).toThrow(/unexpected shape/i);
    expect(() =>
      parseAppendApplicationEnvelopeRequest({
        ...fictionalAppendRequest(),
        request: {
          ...fictionalAppendRequest().request,
          queryString: "?unsafe=true",
        },
      }),
    ).toThrow(/query strings/i);

    const trust = fictionalDeliveryTrustContext();
    expect(parseApplicationEnvelopeDeliveryTrustContext(trust)).toEqual(trust);
    expect(() =>
      parseApplicationEnvelopeDeliveryTrustContext({
        ...trust,
        deliveryLimitsDigest: ZERO_HASH32,
      }),
    ).toThrow(/limits digest/i);
    expect(() =>
      parseApplicationEnvelopeDeliveryTrustContext({ ...trust, tenant: "x" }),
    ).toThrow(/unexpected shape/i);
  });

  it("keeps the production-unavailable default fail closed", async () => {
    const service = createApplicationEnvelopeDeliveryService(
      createUnavailableProductionDeliveryPorts(),
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "not-configured",
    });
  });

  it("keeps caller validation errors distinct from dependency failures", async () => {
    const { service } = lab();
    await expect(
      service.appendApplicationEnvelope({
        ...fictionalAppendRequest(),
        authenticatedCredentialRevocationVersion: 4,
      }),
    ).rejects.toBeInstanceOf(DeliveryServiceValidationError);
  });

  it.each([
    ["preflight", "backdated", "2026-08-14T00:00:00.000Z"],
    ["preflight", "future", "2026-08-14T16:20:45.124Z"],
    ["reservation", "backdated", "2026-08-14T00:00:00.000Z"],
    ["reservation", "future", "2026-08-14T16:20:45.124Z"],
  ] as const)(
    "rejects a %s timestamp that is %s",
    async (phase, _direction, substitutedTime) => {
      const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
      const base = store.productionPorts;
      const ports: ProductionDeliveryPorts =
        phase === "preflight"
          ? {
              ...base,
              applicationAppendPreflight: {
                async read(...args) {
                  const result = await base.applicationAppendPreflight.read(...args);
                  return {
                    ...(result as object),
                    observedAt: substitutedTime,
                  };
                },
              },
            }
          : {
              ...base,
              atomicPersistence: {
                reserveApplicationAppendAtomically(
                  reservation,
                  prepareUnsigned,
                  invocation,
                ) {
                  return base.atomicPersistence.reserveApplicationAppendAtomically(
                    reservation,
                    (context) =>
                      prepareUnsigned({
                        ...context,
                        authoritativeReceivedAt: substitutedTime,
                      }),
                    invocation,
                  );
                },
                finalizeApplicationAppendAtomically: (...args) =>
                  base.atomicPersistence.finalizeApplicationAppendAtomically(...args),
                retireExpiredApplicationAppendAtomically: (...args) =>
                  base.atomicPersistence.retireExpiredApplicationAppendAtomically(...args),
              },
            };
      const service = createApplicationEnvelopeDeliveryService(
        ports,
        fictionalDeliveryTrustContext(),
      );

      await expect(
        service.appendApplicationEnvelope(fictionalAppendRequest()),
      ).resolves.toEqual({
        status: "unavailable",
        reasonCode: "malformed-dependency-response",
      });
      expectNoAcceptedWrites(store);
    },
  );

  it.each(dependencyFailureCases)(
    "maps a %s dependency failure to a closed malformed response",
    async (_phase, override) => {
      const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
      const service = createApplicationEnvelopeDeliveryService(
        override(store.productionPorts),
        fictionalDeliveryTrustContext(),
      );

      await expect(
        service.appendApplicationEnvelope(fictionalAppendRequest()),
      ).resolves.toEqual({
        status: "unavailable",
        reasonCode: "malformed-dependency-response",
      });
      expectNoAcceptedWrites(store);
    },
  );

  it("reports a redacted atomic ambiguity without blocking on the incident sink", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    let incident:
      | Parameters<ProductionDeliveryPorts["invariantIncident"]["record"]>[0]
      | undefined;
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        applicationAppendPreflight: {
          read: () => Promise.resolve({ malformed: true }),
        },
        invariantIncident: {
          record: (input) => {
            incident = input;
            return new Promise<unknown>(() => {});
          },
        },
      },
      fictionalDeliveryTrustContext(),
    );
    const startedAt = Date.now();

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "malformed-dependency-response",
    });
    expect(Date.now() - startedAt).toBeLessThan(500);
    const recorded = incident;
    if (!recorded) throw new Error("incident was not recorded");
    expect(Object.keys(recorded).sort()).toEqual([
      "conversationId",
      "deadline",
      "detectedAt",
      "evidenceDigest",
      "incidentCode",
      "signal",
    ]);
    expect(recorded).toMatchObject({
      incidentCode: "atomic-persistence-ambiguity",
      conversationId: LAB_CONVERSATION_ID,
    });
    expect(recorded.signal.aborted).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(recorded.signal.aborted).toBe(true);
    expectNoAcceptedWrites(store);
  });

  it("reports checkpoint substitution evidence from an untrusted verifier", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    const incidentCodes: string[] = [];
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        checkpointSignatureVerifier: {
          verify: () => Promise.resolve({ malformed: true }),
        },
        invariantIncident: {
          record: (input) => {
            incidentCodes.push(input.incidentCode);
            return Promise.resolve({ status: "recorded" });
          },
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "malformed-dependency-response",
    });
    expect(incidentCodes).toEqual(["checkpoint-substitution"]);
    expectNoAcceptedWrites(store);
    expect(store.inspectForTesting().pendingIntentDigest).not.toBeNull();
  });

  it.each(["preflight", "signer"] as const)(
    "hard-times out a never-settling %s port without committing",
    async (phase) => {
      const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
      const never = () => new Promise<unknown>(() => {});
      const ports: ProductionDeliveryPorts =
        phase === "preflight"
          ? {
              ...store.productionPorts,
              applicationAppendPreflight: { read: never },
            }
          : {
              ...store.productionPorts,
              checkpointSigner: {
                signExact: never,
                resolveOrCancelIfUnsigned: never,
              },
            };
      const service = createApplicationEnvelopeDeliveryService(
        ports,
        fictionalDeliveryTrustContext(),
      );

      await expect(
        service.appendApplicationEnvelope(fictionalAppendRequest()),
      ).resolves.toEqual({ status: "unavailable", reasonCode: "timeout" });
      expectNoAcceptedWrites(store);
    },
    3_000,
  );

  it("bounds an adapter that returns immediate retry forever", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    let calls = 0;
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        applicationAppendPreflight: {
          read: () => {
            calls += 1;
            return Promise.resolve({
              status: "retry",
              reasonCode: "snapshot-changed",
            });
          },
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({ status: "unavailable", reasonCode: "timeout" });
    expect(calls).toBe(64);
    expectNoAcceptedWrites(store);
  });

  it("keeps MLS/policy and KMS verification outside the two atomic boundaries", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    const base = store.productionPorts;
    const trace: string[] = [];
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...base,
        mlsWireInspector: {
          inspect: (...args) => {
            trace.push("mls");
            return base.mlsWireInspector.inspect(...args);
          },
        },
        policyHeadProofVerifier: {
          verify: (...args) => {
            trace.push("policy");
            return base.policyHeadProofVerifier.verify(...args);
          },
        },
        atomicPersistence: {
          reserveApplicationAppendAtomically: (...args) => {
            trace.push("reserve");
            return base.atomicPersistence.reserveApplicationAppendAtomically(...args);
          },
          finalizeApplicationAppendAtomically: (...args) => {
            trace.push("finalize");
            return base.atomicPersistence.finalizeApplicationAppendAtomically(...args);
          },
          retireExpiredApplicationAppendAtomically: (...args) => {
            trace.push("retire");
            return base.atomicPersistence.retireExpiredApplicationAppendAtomically(...args);
          },
        },
        checkpointSigner: {
          signExact: (...args) => {
            trace.push("sign");
            return base.checkpointSigner.signExact(...args);
          },
          resolveOrCancelIfUnsigned: (...args) => {
            trace.push("resolve-or-cancel");
            return base.checkpointSigner.resolveOrCancelIfUnsigned(...args);
          },
        },
        checkpointSignatureVerifier: {
          verify: (...args) => {
            trace.push("verify-signature");
            return base.checkpointSignatureVerifier.verify(...args);
          },
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toMatchObject({ status: "accepted" });
    expect(trace.indexOf("mls")).toBeLessThan(trace.indexOf("reserve"));
    expect(trace.indexOf("policy")).toBeLessThan(trace.indexOf("reserve"));
    expect(trace).toEqual(
      expect.arrayContaining([
        "reserve",
        "sign",
        "verify-signature",
        "finalize",
      ]),
    );
    expect(trace.indexOf("reserve")).toBeLessThan(trace.indexOf("sign"));
    expect(trace.indexOf("sign")).toBeLessThan(trace.indexOf("verify-signature"));
    expect(trace.indexOf("verify-signature")).toBeLessThan(trace.indexOf("finalize"));
  });

  it.each([
    ["cross-group", { expectedGroupIdHash: hash(61) }],
    ["old-epoch", { expectedEpoch: "19" }],
  ] as const)("rejects internally valid %s MLS evidence substitution", async (_name, patch) => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        mlsWireInspector: {
          inspect: (request) => Promise.resolve(maliciousWireEvidence(request, patch)),
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "malformed-dependency-response",
    });
    expectNoAcceptedWrites(store);
  });

  it("rejects a signature proof whose valid key window excludes receivedAt", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        checkpointSignatureVerifier: {
          verify: (request) => Promise.resolve(invalidKeyWindowEvidence(request)),
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "malformed-dependency-response",
    });
    expectNoAcceptedWrites(store);
    expect(store.inspectForTesting().pendingIntentDigest).not.toBeNull();
  });

  it("requires the unknown accepted result to echo the current command digest", async () => {
    const { store, service } = lab();
    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toMatchObject({ status: "accepted" });
    const base = store.productionPorts.applicationAppendPreflight;
    const substituting = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        applicationAppendPreflight: {
          async read(command, invocation) {
            const raw = await base.read(command, invocation);
            return { ...(raw as object), invocationCommandDigest: ZERO_HASH32 };
          },
        },
      },
      fictionalDeliveryTrustContext(),
    );

    await expect(
      substituting.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "unavailable",
      reasonCode: "malformed-dependency-response",
    });
    expect(store.inspectForTesting().envelopes).toHaveLength(1);
  });

  it("strictly rejects leaf, checkpoint, and next-state substitutions in a reserved plan", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    let rawReservation: unknown;
    const atomic = store.productionPorts.atomicPersistence;
    const service = createApplicationEnvelopeDeliveryService(
      {
        ...store.productionPorts,
        atomicPersistence: {
          async reserveApplicationAppendAtomically(...args) {
            rawReservation =
              await atomic.reserveApplicationAppendAtomically(...args);
            return rawReservation;
          },
          finalizeApplicationAppendAtomically:
            atomic.finalizeApplicationAppendAtomically.bind(atomic),
          retireExpiredApplicationAppendAtomically:
            atomic.retireExpiredApplicationAppendAtomically.bind(atomic),
        },
        checkpointSigner: {
          signExact: () =>
            Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
          resolveOrCancelIfUnsigned: () =>
            Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
        },
      },
      fictionalDeliveryTrustContext(),
    );
    await service.appendApplicationEnvelope(fictionalAppendRequest());
    const pending = (rawReservation as { pendingIntent: unknown }).pendingIntent;
    const valid = parsePreparedApplicationAppend({ status: "ready", pendingIntent: pending });
    if (valid.status !== "ready") throw new Error("fixture plan was not ready");

    for (const mutated of [
      {
        ...valid,
        pendingIntent: {
          ...valid.pendingIntent,
          envelope: { ...valid.pendingIntent.envelope, leafHash: ZERO_HASH32 },
        },
      },
      {
        ...valid,
        pendingIntent: {
          ...valid.pendingIntent,
          envelope: {
            ...valid.pendingIntent.envelope,
            logCheckpointDigest: ZERO_HASH32,
          },
        },
      },
      {
        ...valid,
        pendingIntent: {
          ...valid.pendingIntent,
          commitProjection: {
            ...valid.pendingIntent.commitProjection,
            conversation: {
              ...valid.pendingIntent.commitProjection.conversation,
              currentLogHeadHash: ZERO_HASH32,
            },
          },
        },
      },
    ]) {
      expect(() => parsePreparedApplicationAppend(mutated)).toThrow();
    }
  });

  it("rejects a new admission under a cross-realm trust context", async () => {
    const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
    const trust = fictionalDeliveryTrustContext();
    const service = createApplicationEnvelopeDeliveryService(
      store.productionPorts,
      { ...trust, realmId: "another-fictional-realm" },
    );
    await expect(
      service.appendApplicationEnvelope(fictionalAppendRequest()),
    ).resolves.toEqual({
      status: "rejected",
      reasonCode: "conversation-state-changed",
    });
    expectNoAcceptedWrites(store);
  });
});

const dependencyFailureCases: readonly [
  string,
  (base: ProductionDeliveryPorts) => ProductionDeliveryPorts,
][] = [
  [
    "resolved-malformed preflight",
    (base) => ({
      ...base,
      applicationAppendPreflight: { read: () => Promise.resolve({ nope: true }) },
    }),
  ],
  [
    "rejected MLS inspection",
    (base) => ({
      ...base,
      mlsWireInspector: { inspect: () => Promise.reject(new Error("mls")) },
    }),
  ],
  [
    "synchronously thrown policy proof",
    (base) => ({
      ...base,
      policyHeadProofVerifier: { verify: () => { throw new Error("policy"); } },
    }),
  ],
  [
    "resolved-malformed reservation",
    (base) => ({
      ...base,
      atomicPersistence: {
        reserveApplicationAppendAtomically: () => Promise.resolve({ nope: true }),
        finalizeApplicationAppendAtomically: (...args) =>
          base.atomicPersistence.finalizeApplicationAppendAtomically(...args),
        retireExpiredApplicationAppendAtomically: (...args) =>
          base.atomicPersistence.retireExpiredApplicationAppendAtomically(...args),
      },
    }),
  ],
  [
    "resolved-malformed signer",
    (base) => ({
      ...base,
      checkpointSigner: {
        signExact: () => Promise.resolve({ signed: false }),
        resolveOrCancelIfUnsigned: () => Promise.resolve({ signed: false }),
      },
    }),
  ],
  [
    "rejected signature verifier",
    (base) => ({
      ...base,
      checkpointSignatureVerifier: {
        verify: () => Promise.reject(new Error("verifier")),
      },
    }),
  ],
  [
    "resolved-malformed finalization",
    (base) => ({
      ...base,
      atomicPersistence: {
        reserveApplicationAppendAtomically: (...args) =>
          base.atomicPersistence.reserveApplicationAppendAtomically(...args),
        finalizeApplicationAppendAtomically: () => Promise.resolve({ nope: true }),
        retireExpiredApplicationAppendAtomically: (...args) =>
          base.atomicPersistence.retireExpiredApplicationAppendAtomically(...args),
      },
    }),
  ],
];

function lab() {
  const store = new InMemoryDeliveryLabStore(fictionalDeliveryLabSeed());
  return {
    store,
    service: createApplicationEnvelopeDeliveryService(
      store.productionPorts,
      fictionalDeliveryTrustContext(),
    ),
  };
}

function expectNoAcceptedWrites(store: InMemoryDeliveryLabStore): void {
  const state = store.inspectForTesting();
  expect(state.envelopes).toHaveLength(0);
  expect(state.outbox).toHaveLength(0);
  expect(state.mailboxes.every(({ entries }) => entries.length === 0)).toBe(true);
  expect(state.secondaryEnvelopeRecordCount).toBe(0);
}

function maliciousWireEvidence(
  request: MlsWireInspectionRequest,
  patch: Readonly<Record<string, unknown>>,
) {
  const evidence = {
    releaseProfileId: request.releaseProfileId,
    expectedGroupIdHash: request.expectedGroupIdHash,
    expectedEpoch: request.expectedEpoch,
    wireKind: "private-application" as const,
    contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
    envelopeSha256: computeEnvelopeSha256(request.envelopeBytes),
    inspectionStatus: "verified" as const,
    ...patch,
  } as Parameters<typeof computeMlsApplicationWireInspectionEvidenceDigest>[0];
  return Object.freeze({
    status: "verified",
    profile: "mls-application-wire-inspection.v1",
    ...evidence,
    evidenceDigest: computeMlsApplicationWireInspectionEvidenceDigest(evidence),
  });
}

function invalidKeyWindowEvidence(
  request: DeliveryCheckpointSignatureVerificationRequest,
) {
  const evidence = {
    realmId: request.realmId,
    conversationId: request.conversationId,
    conversationGeneration: request.conversationGeneration,
    releaseProfileId: request.releaseProfileId,
    releaseTrustRootDigest: request.releaseTrustRootDigest,
    position: request.position,
    previousHeadHash: request.previousHeadHash,
    headHash: request.headHash,
    signingKeyId: request.signingKeyId,
    checkpointDigest: request.checkpointDigest,
    signatureSha256: sha256Bytes(Buffer.from(request.signature, "base64url")),
    checkpointReceivedAt: request.checkpointReceivedAt,
    verifiedAt: request.verifiedAt,
    keyState: "active" as const,
    validFrom: parseRfc3339Millis("2026-08-14T16:21:00.000Z"),
    validUntil: parseRfc3339Millis("2026-09-14T16:20:45.123Z"),
  };
  return Object.freeze({
    status: "verified",
    profile: "delivery-log-checkpoint.v1",
    ...evidence,
    evidenceDigest:
      computeDeliveryCheckpointSignatureEvidenceDigest(evidence),
  });
}

function hash(byte: number): string {
  return Buffer.alloc(32, byte).toString("base64url");
}
