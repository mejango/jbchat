import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, sign as signNode } from "node:crypto";
import type { JsonRpcTransport } from "../chain/jsonRpc";
import { readCodeAtBlock } from "../chain/quorumReads";
import type { DeploymentManifest } from "./deploymentManifest";

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const ABI_DIGEST_DOMAIN = "jb-msg-abi/v1";
const HEX_QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;

/**
 * The exact nana-core v6 event signatures the jbm-evm-adapter.1 decoder
 * implements; the manifest's ABI digests commit to these strings.
 */
export const ADAPTER_EVENT_SIGNATURES = {
  pay: "Pay(uint256,uint256,uint256,address,address,uint256,uint256,string,bytes,address)",
  hookAfterRecordPay:
    "AfterRecordPay(uint256,(uint256,uint256,uint256,address,(address,uint8,uint32),(address,uint8,uint32),address,uint256,uint256,string,bytes),uint256,address)",
  tierMint: "Mint(uint256,uint256,address,uint256,address)",
} as const;

export function abiDigestFor(signature: string): string {
  return `0x${createHash("sha256")
    .update(ABI_DIGEST_DOMAIN, "utf8")
    .update(signature, "utf8")
    .digest("hex")}`;
}

export interface ManifestSourceChain {
  readonly chainId: number;
  readonly projectsContract: string;
  readonly terminals: readonly string[];
  readonly tierHooks: readonly string[];
}

export interface ManifestSource {
  readonly kind: "jbm-deployment-manifest-source.v1";
  readonly manifestId: string;
  readonly adapterRevision: string;
  readonly chains: readonly ManifestSourceChain[];
}

/**
 * Composes an unsigned deployment manifest from the checked-in source by
 * reading every pinned contract's deployed code at each chain's current
 * finalized head through the ADR 0005 quorum. Empty code at a pinned
 * address is a hard error - a manifest must never pin a contract that is
 * not deployed. Signing is a separate explicit step.
 */
export async function composeDeploymentManifest(
  source: ManifestSource,
  transportsFor: (chainId: number) => readonly JsonRpcTransport[],
): Promise<DeploymentManifest> {
  if (source.kind !== "jbm-deployment-manifest-source.v1") {
    throw new Error("Unexpected manifest source kind.");
  }
  const chains = [];
  for (const chain of source.chains) {
    const transports = transportsFor(chain.chainId);
    if (transports.length < 2) {
      throw new Error(
        `Chain ${chain.chainId} needs two providers to compose a manifest.`,
      );
    }
    const finalized = await lowestFinalizedNumber(transports);
    const pin = async (address: string) => {
      const normalized = address.toLowerCase();
      if (!ADDRESS_PATTERN.test(normalized)) {
        throw new Error(`Address ${address} is malformed.`);
      }
      const code = await readCodeAtBlock(transports, 2, normalized, finalized);
      if (code.status !== "ok") {
        throw new Error(
          `Code read for ${normalized} on ${chain.chainId} was ${code.status}.`,
        );
      }
      if (code.code.byteLength === 0) {
        throw new Error(
          `No code at pinned address ${normalized} on ${chain.chainId}.`,
        );
      }
      const { keccak_256 } = await import("@noble/hashes/sha3.js");
      return {
        address: normalized,
        implementationCodeHash: `0x${Buffer.from(
          keccak_256(code.code),
        ).toString("hex")}`,
      };
    };
    chains.push({
      chainId: chain.chainId,
      projectsContract: chain.projectsContract.toLowerCase(),
      abiDigests: {
        pay: abiDigestFor(ADAPTER_EVENT_SIGNATURES.pay),
        hookAfterRecordPay: abiDigestFor(
          ADAPTER_EVENT_SIGNATURES.hookAfterRecordPay,
        ),
        tierMint: abiDigestFor(ADAPTER_EVENT_SIGNATURES.tierMint),
      },
      terminals: await Promise.all(chain.terminals.map(pin)),
      tierHooks: await Promise.all(chain.tierHooks.map(pin)),
    });
  }
  return Object.freeze({
    kind: "juicebox-deployment-manifest.v1",
    manifestId: source.manifestId,
    adapterRevision: source.adapterRevision,
    chains: Object.freeze(chains),
  }) as DeploymentManifest;
}

/** Ed25519-signs the manifest body into the envelope the parser accepts. */
export function signDeploymentManifest(
  manifest: DeploymentManifest,
  signerKeyId: string,
  seed: Buffer,
): unknown {
  if (seed.byteLength !== 32) {
    throw new Error("The manifest signing seed must be 32 bytes.");
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const signature = signNode(
    null,
    Buffer.from(JSON.stringify(manifest), "utf8"),
    privateKey,
  );
  return Object.freeze({
    manifest,
    signature: Object.freeze({
      algorithm: "ed25519",
      signerKeyId,
      signature: signature.toString("base64url"),
    }),
  });
}

async function lowestFinalizedNumber(
  transports: readonly JsonRpcTransport[],
): Promise<bigint> {
  const numbers = await Promise.all(
    transports.map(async (transport) => {
      const block = (await transport.request("eth_getBlockByNumber", [
        "finalized",
        false,
      ])) as Record<string, unknown> | null;
      const number = String(block?.number).toLowerCase();
      if (!HEX_QUANTITY.test(number)) {
        throw new Error("Malformed finalized head while composing manifest.");
      }
      return BigInt(number);
    }),
  );
  return numbers.reduce((lowest, number) =>
    number < lowest ? number : lowest,
  );
}
