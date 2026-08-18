import type { ChainFinalityVerifierPort } from "../authority/ports";
import type { CanonicalInstant, Hash32, JuiceboxV6ChainId } from "../authority/valueObjects";
import type { FinalityPolicy } from "../authority/finality";
import type { CanonicalityResult } from "../authority/finality";
import type { JsonRpcTransport } from "./jsonRpc";
import { readFinalizedReceipt } from "./quorumReads";

export interface ChainTransportRegistry {
  readonly transportsFor: (
    chainId: number,
  ) => readonly JsonRpcTransport[] | null;
}

/**
 * ADR 0005 receipt-canonicality verifier: the receipt must exist
 * identically at every configured provider, sit at or below the lowest
 * finalized head any provider reports, and match the canonical block
 * hash at its height. A receipt no provider knows cannot be
 * distinguished from a pruned view without a prior anchor, so it reports
 * unavailable here; the eligibility sweeps hold the anchor and own the
 * orphaned-versus-missing distinction.
 */
export function createQuorumChainFinalityVerifier(
  registry: ChainTransportRegistry,
): ChainFinalityVerifierPort {
  return Object.freeze({
    async verifyReceiptCanonicality(input: {
      chainId: JuiceboxV6ChainId;
      transactionHash: Hash32;
      policy: FinalityPolicy;
      now: CanonicalInstant;
    }): Promise<CanonicalityResult> {
      const { chainId, transactionHash, policy, now } = input;
      const unavailable = (
        reasonCode:
          | "finality-verifier-not-configured"
          | "rpc-unavailable"
          | "provider-disagreement"
          | "archive-state-unavailable",
      ): CanonicalityResult =>
        Object.freeze({
          status: "unavailable",
          transactionHash,
          chainId,
          reasonCode,
        }) as CanonicalityResult;

      if (chainId !== policy.chainId) {
        return unavailable("finality-verifier-not-configured");
      }
      const transports = registry.transportsFor(chainId);
      if (!transports || transports.length < policy.minimumProviderQuorum) {
        return unavailable("finality-verifier-not-configured");
      }
      const view = await readFinalizedReceipt(
        transports,
        policy.minimumProviderQuorum,
        transactionHash,
      );
      if (view.status === "disagreement") {
        return unavailable("provider-disagreement");
      }
      if (view.status === "unavailable" || view.status === "not-found") {
        return unavailable("rpc-unavailable");
      }
      if (view.status === "above-finalized") {
        return Object.freeze({
          status: "pending-finality",
          transactionHash,
          chainId,
          candidateBlockNumber: view.candidateBlockNumber.toString(10),
          candidateBlockHash: view.candidateBlockHash,
          reasonCode: "receipt-above-finalized-head",
        }) as CanonicalityResult;
      }
      if (view.status === "not-canonical") {
        return Object.freeze({
          status: "orphaned",
          transactionHash,
          chainId,
          formerBlockNumber: view.receiptBlockNumber.toString(10),
          formerBlockHash: view.receiptBlockHash,
          reasonCode: "block-hash-mismatch",
          requiredAction: "revoke-leases-and-rekey",
        }) as CanonicalityResult;
      }
      return Object.freeze({
        status: "verified-finalized",
        transactionHash,
        anchor: {
          kind: "finalized-block.v1",
          chainId,
          blockNumber: view.blockNumber.toString(10),
          blockHash: view.blockHash,
          finalizedAt: now,
          providerIds: view.agreedProviderIds,
        },
      }) as CanonicalityResult;
    },
  });
}
