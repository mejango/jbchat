import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  JUICEBOX_V6_EVENT_TOPICS,
  parseCanonicalPurchaseVerificationResult,
} from "../authority/purchases";
import type { FinalityPolicy } from "../authority/finality";
import { eip191Digest } from "../identity/identityCrypto";
import type { JsonRpcTransport } from "./jsonRpc";
import { createQuorumChainFinalityVerifier } from "./finalityVerifier";
import { createQuorumCanonicalPurchaseVerifier } from "./purchaseVerifier";
import { createQuorumWalletProofVerifier } from "./quorumWalletProofVerifier";

const NOW = "2026-08-14T16:21:30.000Z";
const CHAIN_NUMBER = 8453;
const TX_HASH = `0x${"ab".repeat(32)}`;
const BLOCK_HASH = `0x${"cd".repeat(32)}`;
const RECEIPT_HEIGHT = 0x1000n;
const TERMINAL_CODE = Buffer.from("60806040fe", "hex");
const TERMINAL = `0x${"11".repeat(20)}`;
const BENEFICIARY = `0x${"22".repeat(20)}`;
const PAYER = `0x${"33".repeat(20)}`;
const CALLER = `0x${"44".repeat(20)}`;
const PROJECTS_CONTRACT = `0x${"55".repeat(20)}`;

const POLICY = {
  kind: "juicebox-finality-policy.v1",
  policyId: "finality-policy-base-1",
  chainId: CHAIN_NUMBER,
  blockTag: "finalized",
  minimumProviderQuorum: 2,
  requireBlockHashAgreement: true,
  requireArchiveStateAtReceiptBlock: true,
  allowConfirmationFallback: false,
  safeHeadUse: "suspend-existing-authority-only",
  onReorg: "revoke-leases-and-rekey",
} as unknown as FinalityPolicy;

function encodePayData(memo: string, metadata: Buffer): string {
  const word = (value: bigint): Buffer => {
    const buffer = Buffer.alloc(32);
    let remaining = value;
    for (let index = 31; index >= 0 && remaining > 0n; index -= 1) {
      buffer[index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    return buffer;
  };
  const addressWord = (address: string): Buffer =>
    Buffer.concat([Buffer.alloc(12), Buffer.from(address.slice(2), "hex")]);
  const padded = (bytes: Buffer): Buffer => {
    const padLength = (32 - (bytes.byteLength % 32)) % 32;
    return Buffer.concat([
      word(BigInt(bytes.byteLength)),
      bytes,
      Buffer.alloc(padLength),
    ]);
  };
  const memoBytes = Buffer.from(memo, "utf8");
  const memoTail = padded(memoBytes);
  const head = [
    addressWord(PAYER),
    addressWord(BENEFICIARY),
    word(1_000_000n),
    word(5_000n),
    word(BigInt(7 * 32)),
    word(BigInt(7 * 32 + memoTail.byteLength)),
    addressWord(CALLER),
  ];
  return `0x${Buffer.concat([...head, memoTail, padded(metadata)]).toString(
    "hex",
  )}`;
}

function scriptedTransport(
  providerId: string,
  overrides: Partial<{
    receipt: unknown;
    finalizedNumber: bigint;
    blockHashAtHeight: string;
    code: string;
    fail: boolean;
  }> = {},
): JsonRpcTransport {
  const receipt =
    overrides.receipt !== undefined
      ? overrides.receipt
      : {
          transactionHash: TX_HASH,
          transactionIndex: "0x2",
          status: "0x1",
          blockNumber: `0x${RECEIPT_HEIGHT.toString(16)}`,
          blockHash: BLOCK_HASH,
          logs: [
            {
              logIndex: "0x5",
              address: TERMINAL,
              topics: [
                JUICEBOX_V6_EVENT_TOPICS.pay,
                `0x${"01".repeat(32)}`,
                `0x${(3n).toString(16).padStart(64, "0")}`,
                `0x${(42n).toString(16).padStart(64, "0")}`,
              ],
              data: encodePayData("thanks", Buffer.from("aa55", "hex")),
            },
          ],
        };
  const finalizedNumber = overrides.finalizedNumber ?? RECEIPT_HEIGHT + 5n;
  const blockHashAtHeight = overrides.blockHashAtHeight ?? BLOCK_HASH;
  const code = overrides.code ?? `0x${TERMINAL_CODE.toString("hex")}`;
  return Object.freeze({
    providerId,
    async request(method: string, params: readonly unknown[]) {
      if (overrides.fail) throw new Error("provider down");
      if (method === "eth_getTransactionReceipt") return receipt;
      if (method === "eth_getBlockByNumber") {
        if (params[0] === "finalized") {
          return { number: `0x${finalizedNumber.toString(16)}` };
        }
        return { number: params[0], hash: blockHashAtHeight };
      }
      if (method === "eth_getCode") return code;
      throw new Error(`unexpected method ${method}`);
    },
  });
}

function registryOf(...transports: JsonRpcTransport[]) {
  return {
    transportsFor: (chainId: number) =>
      chainId === CHAIN_NUMBER ? transports : null,
  };
}

describe("quorum chain finality verifier", () => {
  const input = {
    chainId: CHAIN_NUMBER,
    transactionHash: TX_HASH,
    policy: POLICY,
    now: NOW,
  } as unknown as Parameters<
    ReturnType<
      typeof createQuorumChainFinalityVerifier
    >["verifyReceiptCanonicality"]
  >[0];

  it("verifies a finalized canonical receipt under the lowest head", async () => {
    const verifier = createQuorumChainFinalityVerifier(
      registryOf(scriptedTransport("prov-b"), scriptedTransport("prov-a")),
    );
    const result = await verifier.verifyReceiptCanonicality(input);
    expect(result).toMatchObject({
      status: "verified-finalized",
      anchor: {
        blockNumber: RECEIPT_HEIGHT.toString(10),
        blockHash: BLOCK_HASH,
        providerIds: ["prov-a", "prov-b"],
      },
    });
  });

  it("reports pending, orphaned, disagreement, and unavailable", async () => {
    const pending = await createQuorumChainFinalityVerifier(
      registryOf(
        scriptedTransport("a", { finalizedNumber: RECEIPT_HEIGHT - 1n }),
        scriptedTransport("b"),
      ),
    ).verifyReceiptCanonicality(input);
    expect(pending).toMatchObject({ status: "pending-finality" });

    const orphaned = await createQuorumChainFinalityVerifier(
      registryOf(
        scriptedTransport("a", { blockHashAtHeight: `0x${"ef".repeat(32)}` }),
        scriptedTransport("b", { blockHashAtHeight: `0x${"ef".repeat(32)}` }),
      ),
    ).verifyReceiptCanonicality(input);
    expect(orphaned).toMatchObject({
      status: "orphaned",
      reasonCode: "block-hash-mismatch",
    });

    const disagreement = await createQuorumChainFinalityVerifier(
      registryOf(
        scriptedTransport("a"),
        scriptedTransport("b", { blockHashAtHeight: `0x${"ef".repeat(32)}` }),
      ),
    ).verifyReceiptCanonicality(input);
    expect(disagreement).toMatchObject({
      status: "unavailable",
      reasonCode: "provider-disagreement",
    });

    const down = await createQuorumChainFinalityVerifier(
      registryOf(scriptedTransport("a"), scriptedTransport("b", { fail: true })),
    ).verifyReceiptCanonicality(input);
    expect(down).toMatchObject({
      status: "unavailable",
      reasonCode: "rpc-unavailable",
    });

    const single = await createQuorumChainFinalityVerifier(
      registryOf(scriptedTransport("a")),
    ).verifyReceiptCanonicality(input);
    expect(single).toMatchObject({
      status: "unavailable",
      reasonCode: "finality-verifier-not-configured",
    });
  });
});

describe("quorum canonical purchase verifier", () => {
  const expectation = {
    claim: {
      kind: "juicebox-v6-payment-beneficiary-claim.v1",
      claimId: "claim-1",
      project: {
        protocol: "juicebox-v6",
        chainId: CHAIN_NUMBER,
        projectId: 42,
        version: 6,
        deploymentManifestId: "manifest-1",
        projectsContract: PROJECTS_CONTRACT,
      },
      transactionHash: TX_HASH,
      payLogIndex: 5,
      expectedBeneficiary: BENEFICIARY,
      customerSubjectSource: "pay-beneficiary",
    },
    deployment: {
      deploymentManifestId: "manifest-1",
      projectsContract: PROJECTS_CONTRACT,
      adapterRevision: "jbm-evm-adapter.1",
      abiDigests: {
        pay: `0x${"a1".repeat(32)}`,
        hookAfterRecordPay: `0x${"a2".repeat(32)}`,
        tierMint: `0x${"a3".repeat(32)}`,
      },
      terminal: {
        address: TERMINAL,
        implementationCodeHash: `0x${Buffer.from(
          keccak_256(TERMINAL_CODE),
        ).toString("hex")}`,
      },
      tierHook: null,
    },
    now: NOW,
  } as never;

  it("produces evidence the strict kernel accepts end to end", async () => {
    const verifier = createQuorumCanonicalPurchaseVerifier(
      registryOf(scriptedTransport("prov-a"), scriptedTransport("prov-b")),
    );
    const raw = await verifier.verify({ expectation, policy: POLICY });
    const parsed = parseCanonicalPurchaseVerificationResult(
      raw,
      POLICY,
      expectation,
    );
    expect(parsed.status).toBe("verified");
    if (parsed.status !== "verified") throw new Error("not verified");
    expect(parsed.evidence.kind).toBe(
      "juicebox-v6-payment-beneficiary-evidence.v1",
    );
    expect(parsed.evidence.customerAccount).toBe(BENEFICIARY);
    expect(parsed.evidence.pay.amount).toBe("1000000");
    expect(parsed.evidence.pay.rulesetCycleNumber).toBe("3");
    expect(parsed.evidence.receipt.block.blockHash).toBe(BLOCK_HASH);
  });

  it("refuses mismatched beneficiaries, emitters, and code hashes", async () => {
    const wrongBeneficiary = {
      ...(expectation as Record<string, unknown>),
      claim: {
        ...(expectation as { claim: Record<string, unknown> }).claim,
        expectedBeneficiary: `0x${"99".repeat(20)}`,
      },
    } as never;
    const verifier = createQuorumCanonicalPurchaseVerifier(
      registryOf(scriptedTransport("a"), scriptedTransport("b")),
    );
    await expect(
      verifier.verify({ expectation: wrongBeneficiary, policy: POLICY }),
    ).resolves.toMatchObject({
      status: "ineligible",
      reasonCode: "beneficiary-mismatch",
    });

    const wrongCode = createQuorumCanonicalPurchaseVerifier(
      registryOf(
        scriptedTransport("a", { code: "0xdeadbeef" }),
        scriptedTransport("b", { code: "0xdeadbeef" }),
      ),
    );
    await expect(
      wrongCode.verify({ expectation, policy: POLICY }),
    ).resolves.toMatchObject({
      status: "ineligible",
      reasonCode: "terminal-not-canonical",
    });

    const tierClaim = {
      ...(expectation as Record<string, unknown>),
      claim: {
        ...(expectation as { claim: Record<string, unknown> }).claim,
        kind: "juicebox-v6-tier-purchase-claim.v1",
      },
    } as never;
    await expect(
      verifier.verify({ expectation: tierClaim, policy: POLICY }),
    ).resolves.toMatchObject({
      status: "unavailable",
      reasonCode: "not-configured",
    });
  });
});

describe("quorum wallet proof verifier", () => {
  const walletPriv = Buffer.from(secp256k1.utils.randomSecretKey());
  const walletAddress = `0x${Buffer.from(
    keccak_256(secp256k1.getPublicKey(walletPriv, false).subarray(1)),
  )
    .subarray(-20)
    .toString("hex")}`;
  const MESSAGE = "authorize this fictional enrollment";
  const signature = (() => {
    const recovered = secp256k1.sign(eip191Digest(MESSAGE), walletPriv, {
      format: "recovered",
      prehash: false,
    });
    return `0x${Buffer.from(recovered.subarray(1)).toString("hex")}${Buffer.of(
      recovered[0] + 27,
    ).toString("hex")}`;
  })();

  const profileWith = (...transports: JsonRpcTransport[]) => [
    {
      chainId: "eip155:8453",
      finalityProfileId: "00000000-0000-4000-8000-0000000000f2",
      finalityProfileRevision: "1",
      finalityProfileHash: Buffer.alloc(32, 0xf2),
      transports,
      minimumProviderQuorum: 2,
    },
  ];

  it("verifies an EOA wallet against the finalized quorum state", async () => {
    const verifier = createQuorumWalletProofVerifier(
      profileWith(
        scriptedTransport("prov-a", { code: "0x" }),
        scriptedTransport("prov-b", { code: "0x" }),
      ),
    );
    const verdict = await verifier.verify({
      chainId: "eip155:8453",
      address: walletAddress,
      message: MESSAGE,
      signature,
    });
    expect(verdict).toMatchObject({
      status: "verified",
      method: "eoa",
      finality: { finalizedChainId: "eip155:8453" },
    });
    if (verdict.status !== "verified") throw new Error("not verified");
    expect(verdict.finality.finalizedBlock).toBe(
      (RECEIPT_HEIGHT + 5n).toString(10),
    );
  });

  it("fails closed for contract wallets, unknown chains, and bad signatures", async () => {
    const contractWallet = createQuorumWalletProofVerifier(
      profileWith(
        scriptedTransport("a", { code: "0x60806040" }),
        scriptedTransport("b", { code: "0x60806040" }),
      ),
    );
    await expect(
      contractWallet.verify({
        chainId: "eip155:8453",
        address: walletAddress,
        message: MESSAGE,
        signature,
      }),
    ).resolves.toEqual({ status: "unavailable" });

    const verifier = createQuorumWalletProofVerifier(
      profileWith(
        scriptedTransport("a", { code: "0x" }),
        scriptedTransport("b", { code: "0x" }),
      ),
    );
    await expect(
      verifier.verify({
        chainId: "eip155:1",
        address: walletAddress,
        message: MESSAGE,
        signature,
      }),
    ).resolves.toEqual({ status: "unavailable" });
    await expect(
      verifier.verify({
        chainId: "eip155:8453",
        address: walletAddress,
        message: "a different message",
        signature,
      }),
    ).resolves.toEqual({ status: "invalid" });
  });
});
