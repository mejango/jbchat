import type {
  DeliveryPortUnavailable,
  ProductionDeliveryPorts,
} from "./ports";

const NOT_CONFIGURED: DeliveryPortUnavailable = Object.freeze({
  status: "unavailable",
  reasonCode: "not-configured",
});

/**
 * Safe production default. It inspects, witnesses, signs, persists, encodes,
 * decodes, and records nothing. In particular, it never fabricates an accepted
 * position, checkpoint signature, cursor, durability receipt, or incident ID.
 */
export function createUnavailableProductionDeliveryPorts(): ProductionDeliveryPorts {
  return {
    mlsWireInspector: {
      inspect: () => Promise.resolve(NOT_CONFIGURED),
    },
    mlsCommitProjectionVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    mlsExternalProposalVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    conversationPolicyReplayVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    policyHeadProofVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    checkpointSigner: {
      signExact: () => Promise.resolve(NOT_CONFIGURED),
      resolveOrCancelIfUnsigned: () => Promise.resolve(NOT_CONFIGURED),
    },
    signerFenceEvidenceVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    checkpointSignatureVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    conversationPageProofVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    conversationLogHeadProofVerifier: {
      verify: () => Promise.resolve(NOT_CONFIGURED),
    },
    applicationAppendPreflight: {
      read: () => Promise.resolve(NOT_CONFIGURED),
    },
    atomicPersistence: {
      reserveApplicationAppendAtomically: () =>
        Promise.resolve(NOT_CONFIGURED),
      finalizeApplicationAppendAtomically: () =>
        Promise.resolve(NOT_CONFIGURED),
      retireExpiredApplicationAppendAtomically: () =>
        Promise.resolve(NOT_CONFIGURED),
    },
    clock: {
      now: () => NOT_CONFIGURED,
    },
    conversationCursorCodec: {
      decode: () => Promise.resolve(NOT_CONFIGURED),
      encode: () => Promise.resolve(NOT_CONFIGURED),
    },
    invariantIncident: {
      record: () => Promise.resolve(NOT_CONFIGURED),
    },
  };
}
