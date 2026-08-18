import { Buffer } from "node:buffer";
import { createHash, createPublicKey, verify as verifyNodeSignature } from "node:crypto";
import type { CanonicalPurchaseDeploymentExpectation } from "../authority/purchases";
import {
  parseAuthorityId,
  parseEthereumAddress,
  parseHash32,
} from "../authority/valueObjects";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MANIFEST_KIND = "juicebox-deployment-manifest.v1";
const ID_PATTERN = /^[a-z0-9][a-z0-9.-]{0,62}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const CHAIN_IDS = new Set([
  1, 10, 8453, 42161, 11155111, 11155420, 84532, 421614,
]);

export interface DeploymentManifestChain {
  readonly chainId: number;
  readonly projectsContract: string;
  readonly abiDigests: {
    readonly pay: string;
    readonly hookAfterRecordPay: string;
    readonly tierMint: string;
  };
  readonly terminals: readonly {
    readonly address: string;
    readonly implementationCodeHash: string;
  }[];
  readonly tierHooks: readonly {
    readonly address: string;
    readonly implementationCodeHash: string;
  }[];
}

export interface DeploymentManifest {
  readonly kind: typeof MANIFEST_KIND;
  readonly manifestId: string;
  readonly adapterRevision: string;
  readonly chains: readonly DeploymentManifestChain[];
}

/**
 * Parses and signature-verifies a signed deployment manifest
 * (identity-and-entitlement.md section 2): the ratified artifact pinning
 * every chain, contract address, ABI digest, and implementation code hash a
 * receipt interpretation may trust. The local source tree is never
 * deployment authority; an unsigned, tampered, or unknown-signer document
 * yields no manifest and therefore no eligibility.
 */
export function parseSignedDeploymentManifest(
  value: unknown,
  trustedSignerPublicKey: Buffer,
): DeploymentManifest {
  if (trustedSignerPublicKey.byteLength !== 32) {
    throw new TypeError("The manifest signer key must be 32 raw Ed25519 bytes.");
  }
  const envelope = expectExactRecord(value, ["manifest", "signature"]);
  const signature = expectExactRecord(envelope.signature, [
    "algorithm",
    "signerKeyId",
    "signature",
  ]);
  if (
    signature.algorithm !== "ed25519" ||
    typeof signature.signerKeyId !== "string" ||
    !ID_PATTERN.test(signature.signerKeyId) ||
    typeof signature.signature !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(signature.signature)
  ) {
    throw new TypeError("The manifest signature envelope is malformed.");
  }
  const manifest = parseManifestBody(envelope.manifest);
  const canonical = Buffer.from(JSON.stringify(manifest), "utf8");
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, trustedSignerPublicKey]),
    format: "der",
    type: "spki",
  });
  const verified = verifyNodeSignature(
    null,
    canonical,
    publicKey,
    Buffer.from(signature.signature, "base64url"),
  );
  if (!verified) {
    throw new TypeError("The manifest signature does not verify.");
  }
  return manifest;
}

/** Digest binding a resolved expectation back to its ratified document. */
export function deploymentManifestDigest(manifest: DeploymentManifest): Buffer {
  return createHash("sha256")
    .update(JSON.stringify(manifest), "utf8")
    .digest();
}

/**
 * Resolves the pinned deployment expectation for one purchase interpretation.
 * An unknown chain, terminal, or tier hook resolves to null — never to a
 * best-effort expectation.
 */
export function resolvePurchaseDeployment(
  manifest: DeploymentManifest,
  query: {
    readonly chainId: number;
    readonly terminal: string;
    readonly tierHook: string | null;
  },
): CanonicalPurchaseDeploymentExpectation | null {
  const chain = manifest.chains.find((entry) => entry.chainId === query.chainId);
  if (!chain) return null;
  const terminal = chain.terminals.find(
    (entry) => entry.address === query.terminal.toLowerCase(),
  );
  if (!terminal) return null;
  let tierHook: CanonicalPurchaseDeploymentExpectation["tierHook"] = null;
  if (query.tierHook !== null) {
    const hook = chain.tierHooks.find(
      (entry) => entry.address === query.tierHook?.toLowerCase(),
    );
    if (!hook) return null;
    tierHook = {
      address: parseEthereumAddress(hook.address, "tier hook address"),
      implementationCodeHash: parseHash32(
        hook.implementationCodeHash,
        "tier hook code hash",
      ),
    };
  }
  return {
    deploymentManifestId: parseAuthorityId(manifest.manifestId, "manifest id"),
    projectsContract: parseEthereumAddress(
      chain.projectsContract,
      "projects contract",
    ),
    adapterRevision: parseAuthorityId(manifest.adapterRevision, "adapter revision"),
    abiDigests: {
      pay: parseHash32(chain.abiDigests.pay, "pay abi digest"),
      hookAfterRecordPay: parseHash32(
        chain.abiDigests.hookAfterRecordPay,
        "hook abi digest",
      ),
      tierMint: parseHash32(chain.abiDigests.tierMint, "mint abi digest"),
    },
    terminal: {
      address: parseEthereumAddress(terminal.address, "terminal address"),
      implementationCodeHash: parseHash32(
        terminal.implementationCodeHash,
        "terminal code hash",
      ),
    },
    tierHook,
  };
}

function parseManifestBody(value: unknown): DeploymentManifest {
  const record = expectExactRecord(value, [
    "kind",
    "manifestId",
    "adapterRevision",
    "chains",
  ]);
  if (
    record.kind !== MANIFEST_KIND ||
    typeof record.manifestId !== "string" ||
    !ID_PATTERN.test(record.manifestId) ||
    typeof record.adapterRevision !== "string" ||
    !ID_PATTERN.test(record.adapterRevision) ||
    !Array.isArray(record.chains) ||
    record.chains.length === 0
  ) {
    throw new TypeError("The deployment manifest body is malformed.");
  }
  const chains = record.chains.map(parseManifestChain);
  const chainIds = new Set(chains.map((chain) => chain.chainId));
  if (chainIds.size !== chains.length) {
    throw new TypeError("The deployment manifest repeats a chain.");
  }
  return Object.freeze({
    kind: MANIFEST_KIND,
    manifestId: record.manifestId,
    adapterRevision: record.adapterRevision,
    chains: Object.freeze(chains),
  });
}

function parseManifestChain(value: unknown): DeploymentManifestChain {
  const record = expectExactRecord(value, [
    "chainId",
    "projectsContract",
    "abiDigests",
    "terminals",
    "tierHooks",
  ]);
  if (
    typeof record.chainId !== "number" ||
    !CHAIN_IDS.has(record.chainId) ||
    !isAddress(record.projectsContract) ||
    !Array.isArray(record.terminals) ||
    record.terminals.length === 0 ||
    !Array.isArray(record.tierHooks)
  ) {
    throw new TypeError("A deployment manifest chain entry is malformed.");
  }
  const abiDigests = expectExactRecord(record.abiDigests, [
    "pay",
    "hookAfterRecordPay",
    "tierMint",
  ]);
  if (
    !isHash(abiDigests.pay) ||
    !isHash(abiDigests.hookAfterRecordPay) ||
    !isHash(abiDigests.tierMint)
  ) {
    throw new TypeError("A deployment manifest ABI digest is malformed.");
  }
  const terminals = record.terminals.map(parsePinnedContract);
  const tierHooks = record.tierHooks.map(parsePinnedContract);
  assertUniqueAddresses([...terminals, ...tierHooks]);
  return Object.freeze({
    chainId: record.chainId,
    projectsContract: record.projectsContract as string,
    abiDigests: Object.freeze({
      pay: abiDigests.pay as string,
      hookAfterRecordPay: abiDigests.hookAfterRecordPay as string,
      tierMint: abiDigests.tierMint as string,
    }),
    terminals: Object.freeze(terminals),
    tierHooks: Object.freeze(tierHooks),
  });
}

function parsePinnedContract(value: unknown): {
  address: string;
  implementationCodeHash: string;
} {
  const record = expectExactRecord(value, ["address", "implementationCodeHash"]);
  if (!isAddress(record.address) || !isHash(record.implementationCodeHash)) {
    throw new TypeError("A pinned contract entry is malformed.");
  }
  return Object.freeze({
    address: record.address as string,
    implementationCodeHash: record.implementationCodeHash as string,
  });
}

function assertUniqueAddresses(
  contracts: readonly { address: string }[],
): void {
  const addresses = new Set(contracts.map((contract) => contract.address));
  if (addresses.size !== contracts.length) {
    throw new TypeError("A deployment manifest pins one address twice.");
  }
}

function isAddress(value: unknown): boolean {
  return typeof value === "string" && ADDRESS_PATTERN.test(value);
}

function isHash(value: unknown): boolean {
  return typeof value === "string" && HASH_PATTERN.test(value);
}

function expectExactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Deployment manifest input must be a plain record.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new TypeError("Deployment manifest input has an unexpected shape.");
  }
  return value as Record<string, unknown>;
}
