import { describe, expect, it, vi } from "vitest";
import { createUnavailableProductionDeliveryPorts } from "./unavailable";

const NOT_CONFIGURED = Object.freeze({
  status: "unavailable",
  reasonCode: "not-configured",
});

describe("unconfigured production delivery ports", () => {
  it("fails every external, persistence, codec, and incident boundary closed", async () => {
    const ports = createUnavailableProductionDeliveryPorts();
    const never = undefined as never;

    const results = await Promise.all([
      ports.mlsWireInspector.inspect(never),
      ports.mlsCommitProjectionVerifier.verify(never),
      ports.mlsExternalProposalVerifier.verify(never),
      ports.conversationPolicyReplayVerifier.verify(never),
      ports.policyHeadProofVerifier.verify(never),
      ports.checkpointSigner.signExact(never),
      ports.checkpointSigner.resolveOrCancelIfUnsigned(never),
      ports.signerFenceEvidenceVerifier.verify(never),
      ports.checkpointSignatureVerifier.verify(never),
      ports.conversationPageProofVerifier.verify(never),
      ports.conversationLogHeadProofVerifier.verify(never),
      ports.applicationAppendPreflight.read(never, never),
      ports.atomicPersistence.finalizeApplicationAppendAtomically(never, never),
      ports.atomicPersistence.retireExpiredApplicationAppendAtomically(never, never),
      ports.conversationCursorCodec.decode(never),
      ports.conversationCursorCodec.encode(never),
      ports.invariantIncident.record(never),
    ]);

    for (const result of results) {
      expect(result).toEqual(NOT_CONFIGURED);
    }
    expect(ports.clock.now()).toEqual(NOT_CONFIGURED);
  });

  it("never invokes the unsigned reservation callback or fabricates an intent", async () => {
    const ports = createUnavailableProductionDeliveryPorts();
    const prepareUnsigned = vi.fn(() => ({ fabricated: true }));

    await expect(
      ports.atomicPersistence.reserveApplicationAppendAtomically(
        undefined as never,
        prepareUnsigned,
        undefined as never,
      ),
    ).resolves.toEqual(NOT_CONFIGURED);
    expect(prepareUnsigned).not.toHaveBeenCalled();
  });
});
