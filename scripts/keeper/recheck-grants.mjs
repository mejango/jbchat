#!/usr/bin/env node
// ADR 0005 section 3: rechecks every live eligibility grant's finality
// anchor through the two-provider quorum. A finalized block hash that no
// longer matches its stored anchor revokes that anchor's grants
// (orphaned); provider failure or disagreement suspends the chain's
// grants (fail-closed, stricter than the two-interval allowance); expired
// grants sweep to terminal. The SQL transitions mirror the exported
// store functions in src/production/entitlement/eligibilityStore.ts.
// Run on a 60-second cadence (Railway cron or the keeper loop).
import postgres from "postgres";

const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
const endpointsRaw = process.env.JBM_RPC_ENDPOINTS;
if (!databaseUrl || !endpointsRaw) {
  console.error("JBM_STORAGE_DATABASE_URL and JBM_RPC_ENDPOINTS are required.");
  process.exit(1);
}
const endpoints = JSON.parse(endpointsRaw);
const sql = postgres(databaseUrl, { max: 2, onnotice: () => {} });
const loopSeconds = Number(process.env.JBM_KEEPER_LOOP_SECONDS ?? "0");

let rpcId = 0;
async function blockHashAt(url, heightHex) {
  rpcId += 1;
  const id = rpcId;
  const response = await fetch(url, {
    method: "POST",
    headers: {
          "Content-Type": "application/json",
          "User-Agent": "jbm-evm-adapter/1",
        },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "eth_getBlockByNumber",
      params: [heightHex, false],
    }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const parsed = await response.json();
  if (parsed.id !== id || parsed.error || !parsed.result?.hash) {
    throw new Error("Malformed block response.");
  }
  return String(parsed.result.hash).toLowerCase();
}

async function pass() {
  const anchors = await sql`
    SELECT DISTINCT source_chain_id, source_block,
           encode(source_block_hash, 'hex') AS source_block_hash
    FROM eligibility_grants WHERE state = 'active'`;
  const suspendedChains = new Set();
  let revoked = 0;
  for (const anchor of anchors) {
    const chainId = String(anchor.source_chain_id);
    if (suspendedChains.has(chainId)) continue;
    const providers = endpoints[chainId] ?? [];
    if (providers.length < 2) {
      suspendedChains.add(chainId);
      continue;
    }
    const heightHex = `0x${BigInt(String(anchor.source_block)).toString(16)}`;
    let hashes;
    try {
      hashes = await Promise.all(
        providers.map((provider) => blockHashAt(provider.url, heightHex)),
      );
    } catch {
      suspendedChains.add(chainId);
      continue;
    }
    if (new Set(hashes).size !== 1) {
      suspendedChains.add(chainId);
      continue;
    }
    const stored = `0x${String(anchor.source_block_hash)}`;
    if (hashes[0] !== stored) {
      const rows = await sql`
        UPDATE eligibility_grants
        SET state = 'revoked', finality_status = 'orphaned',
            revoked_at = now()
        WHERE source_chain_id = ${chainId}
          AND source_block_hash = ${Buffer.from(String(anchor.source_block_hash), "hex")}
          AND state IN ('active', 'suspended')
        RETURNING grant_id`;
      revoked += rows.length;
      console.error(
        `REORG OF FINALIZED STATE on ${chainId} at block ${anchor.source_block}: revoked ${rows.length} grants. Pause the profile and re-ratify per ADR 0005.`,
      );
    }
  }
  let suspended = 0;
  for (const chainId of suspendedChains) {
    const rows = await sql`
      UPDATE eligibility_grants
      SET state = 'suspended', finality_status = 'unavailable',
          suspended_at = now()
      WHERE source_chain_id = ${chainId} AND state = 'active'
      RETURNING grant_id`;
    suspended += rows.length;
  }
  const expired = await sql`
    UPDATE eligibility_grants SET state = 'expired'
    WHERE state = 'active' AND valid_until <= now()
    RETURNING grant_id`;
  console.error(
    `Recheck: ${anchors.length} anchors, ${revoked} revoked, ${suspended} suspended, ${expired.length} expired.`,
  );
}

try {
  if (loopSeconds > 0) {
    for (;;) {
      try {
        await pass();
      } catch (error) {
        console.error("Recheck pass failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, loopSeconds * 1000));
    }
  } else {
    await pass();
  }
} finally {
  await sql.end({ timeout: 5 });
}
