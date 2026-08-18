import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import type { CanonicalPurchaseVerifierPort } from "../authority/ports";
import type { FinalityPolicy } from "../authority/finality";
import type { CanonicalPurchaseVerificationExpectation } from "../authority/purchases";
import {
  JUICEBOX_V6_EVENT_TOPICS,
  computeCanonicalPurchaseEvidenceId,
} from "../authority/purchases";
import {
  readCodeAtBlock,
  readFinalizedReceipt,
  type QuorumReceiptLog,
  type QuorumReceiptView,
} from "./quorumReads";
import type { ChainTransportRegistry } from "./finalityVerifier";

const ADAPTER_REVISION = "jbm-evm-adapter.1";

/**
 * ADR 0005 canonical purchase verifier, payment-beneficiary path: the
 * receipt is proven finalized-canonical by quorum, the Pay log at the
 * server-claimed index is decoded against the exact nana-core v6 event
 * layout, the emitter must be the release-pinned terminal whose deployed
 * code hash at the receipt's block matches the manifest, and the decoded
 * beneficiary must equal the claim's expected beneficiary. The output is
 * untrusted by contract - parseCanonicalPurchaseVerificationResult
 * re-validates every binding and digest. The tier-purchase path needs
 * trace correlation against archive nodes and reports not-configured.
 */
export function createQuorumCanonicalPurchaseVerifier(
  registry: ChainTransportRegistry,
): CanonicalPurchaseVerifierPort {
  return Object.freeze({
    async verify(input: {
      expectation: CanonicalPurchaseVerificationExpectation;
      policy: FinalityPolicy;
    }): Promise<unknown> {
      const { expectation, policy } = input;
      const claim = expectation.claim;
      const claimId = claim.claimId;
      const ineligible = (reasonCode: string): unknown =>
        Object.freeze({ status: "ineligible", claimId, reasonCode });
      const unavailable = (reasonCode: string): unknown =>
        Object.freeze({ status: "unavailable", claimId, reasonCode });

      if (claim.kind !== "juicebox-v6-payment-beneficiary-claim.v1") {
        return unavailable("not-configured");
      }
      const transports = registry.transportsFor(policy.chainId);
      if (!transports || transports.length < policy.minimumProviderQuorum) {
        return unavailable("not-configured");
      }

      const view = await readFinalizedReceipt(
        transports,
        policy.minimumProviderQuorum,
        claim.transactionHash,
      );
      if (view.status === "disagreement") return unavailable("rpc-unavailable");
      if (view.status === "unavailable") return unavailable("rpc-unavailable");
      if (view.status === "not-found") {
        return ineligible("receipt-or-log-not-found");
      }
      if (view.status === "above-finalized") {
        return Object.freeze({
          status: "pending-finality",
          claimId,
          reasonCode: "receipt-above-finalized-head",
        });
      }
      if (view.status === "not-canonical") {
        return ineligible("canonical-evidence-orphaned");
      }
      if (view.receiptStatus !== 1) return ineligible("receipt-failed");

      const log = view.logs.find(
        (candidate) => candidate.logIndex === claim.payLogIndex,
      );
      if (!log) return ineligible("receipt-or-log-not-found");
      if (
        log.topics.length !== 4 ||
        log.topics[0] !== JUICEBOX_V6_EVENT_TOPICS.pay
      ) {
        return ineligible("wrong-event-or-emitter");
      }
      if (log.address !== expectation.deployment.terminal.address) {
        return ineligible("wrong-event-or-emitter");
      }
      let decoded: DecodedPayEvent;
      try {
        decoded = decodePayEvent(log);
      } catch {
        return unavailable("malformed-chain-response");
      }
      if (String(decoded.projectId) !== String(claim.project.projectId)) {
        return ineligible("project-or-ruleset-mismatch");
      }
      if (decoded.beneficiary !== claim.expectedBeneficiary.toLowerCase()) {
        return ineligible("beneficiary-mismatch");
      }

      const code = await readCodeAtBlock(
        transports,
        policy.minimumProviderQuorum,
        expectation.deployment.terminal.address,
        view.blockNumber,
      );
      if (code.status !== "ok") return unavailable("rpc-unavailable");
      const codeHash = `0x${Buffer.from(keccak_256(code.code)).toString(
        "hex",
      )}`;
      if (codeHash !== expectation.deployment.terminal.implementationCodeHash) {
        return ineligible("terminal-not-canonical");
      }

      const anchor = Object.freeze({
        kind: "finalized-block.v1",
        chainId: policy.chainId,
        blockNumber: view.blockNumber.toString(10),
        blockHash: view.blockHash,
        finalizedAt: expectation.now,
        providerIds: view.agreedProviderIds,
      });
      const receiptEvidenceId = `receipt:${policy.chainId}:${view.transactionHash}`;
      const receipt = Object.freeze({
        kind: "canonical-finalized-receipt.v1",
        receiptEvidenceId,
        chainId: policy.chainId,
        transactionHash: view.transactionHash,
        transactionIndex: view.transactionIndex,
        block: anchor,
        status: 1,
        receiptDigest: receiptDigest(view),
        finalityPolicyId: policy.policyId,
        deploymentManifestId: expectation.deployment.deploymentManifestId,
        adapterRevision: ADAPTER_REVISION,
        canonicalityCheckedAt: expectation.now,
      });
      const evidence = Object.freeze({
        kind: "juicebox-v6-payment-beneficiary-evidence.v1",
        evidenceId: computeCanonicalPurchaseEvidenceId(claim),
        receipt,
        pay: Object.freeze({
          kind: "juicebox-v6-pay-log.v1",
          log: Object.freeze({
            receiptEvidenceId,
            transactionHash: view.transactionHash,
            blockHash: view.blockHash,
            logIndex: log.logIndex,
            emitter: log.address,
            topic0: log.topics[0],
            abiDigest: expectation.deployment.abiDigests.pay,
            adapterRevision: ADAPTER_REVISION,
            topicsDigest: domainDigest(
              "jb-msg-log-topics/v1",
              Buffer.concat(
                log.topics.map((topic) => Buffer.from(topic.slice(2), "hex")),
              ),
            ),
            dataDigest: domainDigest(
              "jb-msg-log-data/v1",
              Buffer.from(log.data.slice(2), "hex"),
            ),
            removed: false,
          }),
          project: claim.project,
          rulesetId: decoded.rulesetId.toString(10),
          rulesetCycleNumber: decoded.rulesetCycleNumber.toString(10),
          payer: decoded.payer,
          beneficiary: decoded.beneficiary,
          amount: decoded.amount.toString(10),
          newlyIssuedTokenCount: decoded.newlyIssuedTokenCount.toString(10),
          memoDigest: domainDigest("jb-msg-pay-memo/v1", decoded.memo),
          metadataDigest: domainDigest(
            "jb-msg-pay-metadata/v1",
            decoded.metadata,
          ),
          caller: decoded.caller,
          accountingContext: "not-contained-in-pay-event",
        }),
        terminal: Object.freeze({
          kind: "canonical-v6-terminal-at-block.v1",
          evidenceId: `terminal:${policy.chainId}:${expectation.deployment.terminal.address}`,
          project: claim.project,
          terminal: expectation.deployment.terminal.address,
          implementationCodeHash:
            expectation.deployment.terminal.implementationCodeHash,
          deploymentManifestId: expectation.deployment.deploymentManifestId,
          isTerminalOfProject: true,
          block: anchor,
        }),
        project: claim.project,
        customerAccount: decoded.beneficiary,
        customerSubjectSource: "pay-beneficiary",
        payerAttribution: "not-evaluated",
        transactionSenderAttribution: "never-inferred",
        callerAttribution: "never-inferred",
        refundStatus: "not-evaluated",
      });
      return Object.freeze({ status: "verified", claimId, evidence });
    },
  });
}

interface DecodedPayEvent {
  readonly rulesetId: bigint;
  readonly rulesetCycleNumber: bigint;
  readonly projectId: bigint;
  readonly payer: string;
  readonly beneficiary: string;
  readonly amount: bigint;
  readonly newlyIssuedTokenCount: bigint;
  readonly memo: Buffer;
  readonly metadata: Buffer;
  readonly caller: string;
}

/**
 * Strict decoder for the exact nana-core v6 Pay event:
 * Pay(uint256 indexed rulesetId, uint256 indexed rulesetCycleNumber,
 * uint256 indexed projectId, address payer, address beneficiary,
 * uint256 amount, uint256 newlyIssuedTokenCount, string memo,
 * bytes metadata, address caller).
 */
function decodePayEvent(log: QuorumReceiptLog): DecodedPayEvent {
  const data = Buffer.from(log.data.slice(2), "hex");
  if (data.byteLength < 7 * 32) throw new Error("Pay data head is short.");
  const word = (slot: number): Buffer => data.subarray(slot * 32, slot * 32 + 32);
  const uint = (slot: number): bigint => BigInt(`0x${word(slot).toString("hex")}`);
  const address = (slot: number): string => {
    const slotBytes = word(slot);
    if (!slotBytes.subarray(0, 12).every((byte) => byte === 0)) {
      throw new Error("Address slot has non-zero padding.");
    }
    return `0x${slotBytes.subarray(12).toString("hex")}`;
  };
  const dynamic = (slot: number): Buffer => {
    const offset = Number(uint(slot));
    if (offset % 32 !== 0 || offset + 32 > data.byteLength) {
      throw new Error("Dynamic field offset is out of bounds.");
    }
    const length = Number(
      BigInt(`0x${data.subarray(offset, offset + 32).toString("hex")}`),
    );
    if (offset + 32 + length > data.byteLength) {
      throw new Error("Dynamic field length is out of bounds.");
    }
    return data.subarray(offset + 32, offset + 32 + length);
  };
  return {
    rulesetId: BigInt(log.topics[1]),
    rulesetCycleNumber: BigInt(log.topics[2]),
    projectId: BigInt(log.topics[3]),
    payer: address(0),
    beneficiary: address(1),
    amount: uint(2),
    newlyIssuedTokenCount: uint(3),
    memo: dynamic(4),
    metadata: dynamic(5),
    caller: address(6),
  };
}

function receiptDigest(view: QuorumReceiptView): string {
  const identity = {
    blockHash: view.blockHash,
    blockNumber: `0x${view.blockNumber.toString(16)}`,
    status: "0x1",
    transactionHash: view.transactionHash,
    transactionIndex: `0x${view.transactionIndex.toString(16)}`,
  };
  return `0x${createHash("sha256")
    .update("jb-msg-receipt/v1", "utf8")
    .update(JSON.stringify(identity), "utf8")
    .digest("hex")}`;
}

function domainDigest(domain: string, bytes: Buffer): string {
  return `0x${createHash("sha256")
    .update(domain, "utf8")
    .update(bytes)
    .digest("hex")}`;
}
