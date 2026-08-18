import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { JsonRpcTransport } from "./jsonRpc";

const HEX_QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const HEX_HASH = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;

export interface QuorumReceiptLog {
  readonly logIndex: number;
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export interface QuorumReceiptView {
  readonly status: "ok";
  readonly transactionHash: string;
  readonly transactionIndex: number;
  readonly receiptStatus: number;
  readonly blockNumber: bigint;
  readonly blockHash: string;
  readonly logs: readonly QuorumReceiptLog[];
  readonly lowestFinalizedNumber: bigint;
  readonly canonicalBlockHashAtHeight: string;
  readonly agreedProviderIds: readonly string[];
}

export type QuorumReceiptResult =
  | QuorumReceiptView
  | { readonly status: "not-found" }
  | {
      readonly status: "above-finalized";
      readonly candidateBlockNumber: bigint;
      readonly candidateBlockHash: string;
    }
  | { readonly status: "not-canonical"; readonly canonicalBlockHashAtHeight: string; readonly receiptBlockHash: string; readonly receiptBlockNumber: bigint }
  | { readonly status: "disagreement" }
  | { readonly status: "unavailable" };

/**
 * ADR 0005 quorum read: every configured provider must answer, providers
 * must agree byte-for-byte on the receipt's identity and logs, canonical
 * containment is proven by the block hash AT the receipt's height, and
 * every conclusion holds under the LOWEST finalized head any provider
 * reports. Any provider failure is unavailable - never a smaller quorum.
 */
export async function readFinalizedReceipt(
  transports: readonly JsonRpcTransport[],
  minimumQuorum: number,
  transactionHash: string,
): Promise<QuorumReceiptResult> {
  if (transports.length < minimumQuorum) {
    return Object.freeze({ status: "unavailable" });
  }
  interface ProviderView {
    readonly providerId: string;
    readonly receipt: Record<string, unknown> | null;
    readonly finalizedNumber: bigint;
  }
  let views: ProviderView[];
  try {
    views = await Promise.all(
      transports.map(async (transport) => {
        const [receipt, finalized] = await Promise.all([
          transport.request("eth_getTransactionReceipt", [transactionHash]),
          transport.request("eth_getBlockByNumber", ["finalized", false]),
        ]);
        const finalizedRecord = expectBlock(finalized);
        return {
          providerId: transport.providerId,
          receipt:
            receipt === null ? null : (receipt as Record<string, unknown>),
          finalizedNumber: hexQuantity(
            finalizedRecord.number,
            "finalized number",
          ),
        };
      }),
    );
  } catch {
    return Object.freeze({ status: "unavailable" });
  }

  const receiptDigests = new Set(
    views.map((view) =>
      view.receipt === null ? "null" : receiptIdentityDigest(view.receipt),
    ),
  );
  if (receiptDigests.size !== 1) {
    return Object.freeze({ status: "disagreement" });
  }
  if (views[0].receipt === null) {
    return Object.freeze({ status: "not-found" });
  }

  let parsed: {
    transactionIndex: number;
    receiptStatus: number;
    blockNumber: bigint;
    blockHash: string;
    logs: QuorumReceiptLog[];
  };
  try {
    parsed = parseReceipt(views[0].receipt, transactionHash);
  } catch {
    return Object.freeze({ status: "unavailable" });
  }

  const lowestFinalizedNumber = views.reduce(
    (lowest, view) =>
      view.finalizedNumber < lowest ? view.finalizedNumber : lowest,
    views[0].finalizedNumber,
  );
  if (parsed.blockNumber > lowestFinalizedNumber) {
    return Object.freeze({
      status: "above-finalized",
      candidateBlockNumber: parsed.blockNumber,
      candidateBlockHash: parsed.blockHash,
    });
  }

  let hashesAtHeight: string[];
  try {
    hashesAtHeight = await Promise.all(
      transports.map(async (transport) => {
        const block = expectBlock(
          await transport.request("eth_getBlockByNumber", [
            `0x${parsed.blockNumber.toString(16)}`,
            false,
          ]),
        );
        return hexHash(block.hash, "block hash at height");
      }),
    );
  } catch {
    return Object.freeze({ status: "unavailable" });
  }
  if (new Set(hashesAtHeight).size !== 1) {
    return Object.freeze({ status: "disagreement" });
  }
  const canonicalBlockHashAtHeight = hashesAtHeight[0];
  if (canonicalBlockHashAtHeight !== parsed.blockHash) {
    return Object.freeze({
      status: "not-canonical",
      canonicalBlockHashAtHeight,
      receiptBlockHash: parsed.blockHash,
      receiptBlockNumber: parsed.blockNumber,
    });
  }

  return Object.freeze({
    status: "ok",
    transactionHash: transactionHash.toLowerCase(),
    transactionIndex: parsed.transactionIndex,
    receiptStatus: parsed.receiptStatus,
    blockNumber: parsed.blockNumber,
    blockHash: parsed.blockHash,
    logs: Object.freeze(parsed.logs),
    lowestFinalizedNumber,
    canonicalBlockHashAtHeight,
    agreedProviderIds: Object.freeze(
      views.map((view) => view.providerId).sort(),
    ),
  });
}

export type QuorumCodeResult =
  | { readonly status: "ok"; readonly code: Buffer }
  | { readonly status: "disagreement" }
  | { readonly status: "unavailable" };

/** Quorum eth_getCode at an exact block height; providers must agree. */
export async function readCodeAtBlock(
  transports: readonly JsonRpcTransport[],
  minimumQuorum: number,
  address: string,
  blockNumber: bigint,
): Promise<QuorumCodeResult> {
  if (transports.length < minimumQuorum) {
    return Object.freeze({ status: "unavailable" });
  }
  let codes: string[];
  try {
    codes = await Promise.all(
      transports.map(async (transport) => {
        const code = await transport.request("eth_getCode", [
          address,
          `0x${blockNumber.toString(16)}`,
        ]);
        if (typeof code !== "string" || !HEX_DATA.test(code.toLowerCase())) {
          throw new Error("Malformed code response.");
        }
        return code.toLowerCase();
      }),
    );
  } catch {
    return Object.freeze({ status: "unavailable" });
  }
  if (new Set(codes).size !== 1) {
    return Object.freeze({ status: "disagreement" });
  }
  return Object.freeze({
    status: "ok",
    code: Buffer.from(codes[0].slice(2), "hex"),
  });
}

export function providerQuorumHash(providerIds: readonly string[]): Buffer {
  return createHash("sha256")
    .update("jb-msg-provider-quorum/v1", "utf8")
    .update([...providerIds].sort().join("\n"), "utf8")
    .digest();
}

function receiptIdentityDigest(receipt: Record<string, unknown>): string {
  const logs = Array.isArray(receipt.logs) ? receipt.logs : [];
  const identity = {
    blockHash: lower(receipt.blockHash),
    blockNumber: lower(receipt.blockNumber),
    status: lower(receipt.status),
    transactionIndex: lower(receipt.transactionIndex),
    logs: logs.map((log) => {
      const record = log as Record<string, unknown>;
      return {
        address: lower(record.address),
        data: lower(record.data),
        logIndex: lower(record.logIndex),
        topics: Array.isArray(record.topics)
          ? record.topics.map((topic) => lower(topic))
          : [],
      };
    }),
  };
  return createHash("sha256")
    .update(JSON.stringify(identity), "utf8")
    .digest("hex");
}

function parseReceipt(
  receipt: Record<string, unknown>,
  transactionHash: string,
): {
  transactionIndex: number;
  receiptStatus: number;
  blockNumber: bigint;
  blockHash: string;
  logs: QuorumReceiptLog[];
} {
  if (lower(receipt.transactionHash) !== transactionHash.toLowerCase()) {
    throw new Error("Receipt names another transaction.");
  }
  const logs = (Array.isArray(receipt.logs) ? receipt.logs : []).map((log) => {
    const record = log as Record<string, unknown>;
    const topics = Array.isArray(record.topics) ? record.topics : [];
    return Object.freeze({
      logIndex: Number(hexQuantity(record.logIndex, "log index")),
      address: hexAddress(record.address),
      topics: Object.freeze(
        topics.map((topic) => hexHash(topic, "log topic")),
      ),
      data: hexData(record.data),
    });
  });
  return {
    transactionIndex: Number(
      hexQuantity(receipt.transactionIndex, "transaction index"),
    ),
    receiptStatus: Number(hexQuantity(receipt.status, "receipt status")),
    blockNumber: hexQuantity(receipt.blockNumber, "receipt block number"),
    blockHash: hexHash(receipt.blockHash, "receipt block hash"),
    logs,
  };
}

function expectBlock(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Malformed block response.");
  }
  return value as Record<string, unknown>;
}

function lower(value: unknown): string {
  return String(value).toLowerCase();
}

function hexQuantity(value: unknown, label: string): bigint {
  const text = lower(value);
  if (!HEX_QUANTITY.test(text)) {
    throw new Error(`${label} is not a canonical hex quantity.`);
  }
  return BigInt(text);
}

function hexHash(value: unknown, label: string): string {
  const text = lower(value);
  if (!HEX_HASH.test(text)) {
    throw new Error(`${label} is not a 32-byte hex value.`);
  }
  return text;
}

function hexAddress(value: unknown): string {
  const text = lower(value);
  if (!/^0x[0-9a-f]{40}$/.test(text)) {
    throw new Error("Log emitter is not a 20-byte hex address.");
  }
  return text;
}

function hexData(value: unknown): string {
  const text = lower(value);
  if (!HEX_DATA.test(text)) {
    throw new Error("Log data is not canonical hex.");
  }
  return text;
}
