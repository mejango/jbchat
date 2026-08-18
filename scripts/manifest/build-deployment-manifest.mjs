#!/usr/bin/env node
// Composes and signs the production deployment manifest from the
// checked-in source: reads every pinned contract's deployed code hash at
// each chain's finalized head through the ADR 0005 two-provider quorum,
// then Ed25519-signs the body. Self-contained JS mirror of
// src/production/entitlement/manifestTooling.ts - both sides are policed
// by parseSignedDeploymentManifest, which the lab exercises.
// Requires:
//   JBM_RPC_ENDPOINTS         - {"eip155:1":[{providerId,url},...], ...}
//   JBM_MANIFEST_SIGNING_SEED - 32 bytes base64url
//   JBM_MANIFEST_SIGNER_KEY_ID
// Writes the signed envelope to argv[2]
// (default config/deployment-manifest.signed.json - NOT committed).
import { createHash, createPrivateKey, sign as signNode } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { keccak_256 } from "@noble/hashes/sha3.js";

const ABI_DIGEST_DOMAIN = "jb-msg-abi/v1";
// Keep byte-identical with manifestTooling.ts ADAPTER_EVENT_SIGNATURES.
const EVENT_SIGNATURES = {
  pay: "Pay(uint256,uint256,uint256,address,address,uint256,uint256,string,bytes,address)",
  hookAfterRecordPay:
    "AfterRecordPay(uint256,(uint256,uint256,uint256,address,(address,uint8,uint32),(address,uint8,uint32),address,uint256,uint256,string,bytes),uint256,address)",
  tierMint: "Mint(uint256,uint256,address,uint256,address)",
};

const endpointsRaw = process.env.JBM_RPC_ENDPOINTS;
const seedRaw = process.env.JBM_MANIFEST_SIGNING_SEED;
const signerKeyId = process.env.JBM_MANIFEST_SIGNER_KEY_ID;
if (!endpointsRaw || !seedRaw || !signerKeyId) {
  console.error(
    "JBM_RPC_ENDPOINTS, JBM_MANIFEST_SIGNING_SEED, and JBM_MANIFEST_SIGNER_KEY_ID are required.",
  );
  process.exit(1);
}
const endpoints = JSON.parse(endpointsRaw);
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const source = JSON.parse(
  readFileSync(join(root, "config", "deployment-manifest.source.json"), "utf8"),
);
if (source.kind !== "jbm-deployment-manifest-source.v1") {
  console.error("Unexpected manifest source kind.");
  process.exit(1);
}

let rpcId = 0;
async function rpc(url, method, params) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await rpcOnce(url, method, params);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
    }
  }
  throw lastError;
}

async function rpcOnce(url, method, params) {
  rpcId += 1;
  const id = rpcId;
  const response = await fetch(url, {
    method: "POST",
    headers: {
          "Content-Type": "application/json",
          "User-Agent": "jbm-evm-adapter/1",
        },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${new URL(url).host}`);
  const parsed = await response.json();
  if (parsed.id !== id || parsed.error || !("result" in parsed)) {
    throw new Error(`RPC error from ${new URL(url).host}`);
  }
  return parsed.result;
}

function abiDigest(signature) {
  return `0x${createHash("sha256")
    .update(ABI_DIGEST_DOMAIN, "utf8")
    .update(signature, "utf8")
    .digest("hex")}`;
}

const chains = [];
for (const chain of source.chains) {
  const providers = endpoints[`eip155:${chain.chainId}`] ?? [];
  if (providers.length < 2) {
    console.error(`Chain ${chain.chainId} needs two providers; skipping refused.`);
    process.exit(1);
  }
  const heads = await Promise.all(
    providers.map(async (provider) => {
      const block = await rpc(provider.url, "eth_getBlockByNumber", ["finalized", false]);
      return BigInt(block.number);
    }),
  );
  const finalized = heads.reduce((low, n) => (n < low ? n : low));
  const pin = async (address) => {
    const normalized = address.toLowerCase();
    const codes = await Promise.all(
      providers.map((provider) =>
        rpc(provider.url, "eth_getCode", [normalized, `0x${finalized.toString(16)}`]),
      ),
    );
    if (new Set(codes.map((code) => code.toLowerCase())).size !== 1) {
      throw new Error(`Provider disagreement on code for ${normalized} @ ${chain.chainId}`);
    }
    const code = Buffer.from(codes[0].slice(2), "hex");
    if (code.byteLength === 0) {
      throw new Error(`No code at pinned address ${normalized} on ${chain.chainId}`);
    }
    return {
      address: normalized,
      implementationCodeHash: `0x${Buffer.from(keccak_256(code)).toString("hex")}`,
    };
  };
  chains.push({
    chainId: chain.chainId,
    projectsContract: chain.projectsContract.toLowerCase(),
    abiDigests: {
      pay: abiDigest(EVENT_SIGNATURES.pay),
      hookAfterRecordPay: abiDigest(EVENT_SIGNATURES.hookAfterRecordPay),
      tierMint: abiDigest(EVENT_SIGNATURES.tierMint),
    },
    terminals: await Promise.all(chain.terminals.map(pin)),
    tierHooks: await Promise.all(chain.tierHooks.map(pin)),
  });
  console.error(`Pinned chain ${chain.chainId} at finalized ${finalized}.`);
}

const manifest = {
  kind: "juicebox-deployment-manifest.v1",
  manifestId: source.manifestId,
  adapterRevision: source.adapterRevision,
  chains,
};
const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedRaw, "base64url"),
  ]),
  format: "der",
  type: "pkcs8",
});
const signature = signNode(null, Buffer.from(JSON.stringify(manifest), "utf8"), privateKey);
const envelope = {
  manifest,
  signature: {
    algorithm: "ed25519",
    signerKeyId,
    signature: signature.toString("base64url"),
  },
};
const outPath = process.argv[2] ?? join(root, "config", "deployment-manifest.signed.json");
writeFileSync(outPath, `${JSON.stringify(envelope, null, 2)}\n`);
console.error(`Signed deployment manifest written to ${outPath}`);
