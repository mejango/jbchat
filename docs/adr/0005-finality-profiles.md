# ADR 0005 — ENG-004 finality profiles for the eight launch chains

Status: ratified 2026-08-18 by project-owner delegation, closing the
engineering half of ENG-004 (chain-specific finality thresholds,
canonicality recheck cadence, RPC quorum, and pause rules). Per-chain
G3/G4/G5 admission still requires the operational sign-off the
decision-log row names; nothing here waives a gate.

## 1. One rule, three families

Every launch chain uses the **`finalized` block tag and nothing else**.
No `safe` head, no confirmation-depth heuristic, no elapsed-time
heuristic may create or extend authority — exactly the
architecture.md:440 rule. The three finality families differ in how
`finalized` is produced, not in how this service consumes it:

| Family | Chains | `finalized` means |
|---|---|---|
| Ethereum L1 | `eip155:1`, `eip155:11155111` (Sepolia) | Two-epoch Casper FFG finality (~13 min) |
| OP-stack | `eip155:10`, `eip155:8453`, `eip155:11155420`, `eip155:84532` | L2 blocks whose batch data is in a finalized L1 block |
| Arbitrum | `eip155:42161`, `eip155:421614` | L2 blocks whose data is in a finalized L1 block |

All three families serve `eth_getBlockByNumber("finalized")` on modern
nodes; a provider that cannot is not an eligible provider.

## 2. RPC quorum

- `minimumProviderQuorum: 2`. Two **independent** providers (different
  operators, not two URLs of one service) must answer every read.
- `requireBlockHashAgreement: true`: providers must agree on the
  receipt's block hash, the block hash at the receipt's height, and the
  finalized head they report may differ in HEIGHT (providers lag each
  other) but every canonicality conclusion must hold under the LOWEST
  finalized head any provider reports. Hash disagreement at the same
  height is `provider-disagreement` and fails closed.
- Any provider error, timeout, malformed response, or missing archive
  state is `unavailable`. There is no single-provider fallback.

## 3. Canonicality recheck cadence and pause rules

- Live eligibility grants are rechecked against their finality anchor at
  least every 60 seconds while a lease is open; a recheck that cannot
  complete within two consecutive intervals suspends the chain's grants
  (`suspendGrantsForFinalityLoss`).
- A finalized-block hash mismatch against a stored anchor is a reorg of
  finalized state — operationally an emergency: revoke the chain's
  grants (`revokeGrantsForOrphanedAnchor`), pause the profile row
  (`state = 'paused'`), and require manual re-ratification.
- Pausing a profile makes the chain's routes fail closed immediately;
  existing conversations continue (message authority never depends on
  chain state), only new chain-derived authority stops.

## 4. Adapter digest conventions (adapter revision `jbm-evm-adapter.1`)

The strict parsers treat these as opaque 32-byte commitments; this ADR
fixes how the adapter computes them so evidence is reproducible:

- `receiptDigest` = SHA-256 of `jb-msg-receipt/v1 ||` the canonical JSON
  of `{blockHash, blockNumber, status, transactionHash,
  transactionIndex}` exactly as returned (lowercase hex strings).
- `topicsDigest` = SHA-256 of `jb-msg-log-topics/v1 ||` the
  concatenated raw 32-byte topics in order.
- `dataDigest` = SHA-256 of `jb-msg-log-data/v1 ||` the raw data bytes.
- `memoDigest` = SHA-256 of `jb-msg-pay-memo/v1 ||` the UTF-8 memo.
- `metadataDigest` = SHA-256 of `jb-msg-pay-metadata/v1 ||` the raw
  metadata bytes.
- `providerQuorumHash` = SHA-256 of `jb-msg-provider-quorum/v1 ||` the
  newline-joined sorted provider IDs that agreed.

## 5. Profile rows

`config/finality-profiles.v1.json` is the checked-in canonical document
set; `scripts/storage/seed-finality-profiles.mjs` inserts the
`chain_finality_profiles` rows idempotently (profile hash = SHA-256 of
the canonical JSON document). Each row's `adapter_release_id` is
`jbm-evm-adapter.1` and `ratification_evidence_ref` is this ADR's path.
The wallet-proof and purchase verifiers refuse chains whose profile
identity is not supplied to them explicitly — configuration is
per-chain and fail-closed, never inferred.

## 6. What stays open

Bounded ERC-1271/ERC-6492 execution (contract wallets report
`unavailable`), the tier-purchase trace correlation path (needs
`debug_traceTransaction` against archive nodes and stays
`not-configured`), and payer attribution. Each lights up behind the
same ports without revisiting this decision.
