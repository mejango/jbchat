# JBChat: engineering workload toward production readiness

Honest boundary: gates requiring independent audit, human sign-off, staffed ops,
or external infrastructure (G3+ review/fuzz-attestation, KT witness, DNS/CDN
verification, testnet beta) cannot be closed here. This plan drives every
codeable item.

## Phase 1 — repo green (unfinished Delivery refactor)
- [x] Migrate `fixtures.testing.ts` to new MLS roster-projection shape
- [x] Migrate `inMemoryLabStore.testing.ts` to new ApplicationAppend contract
      (retireExpiredApplicationAppendAtomically, signerFenceEvidenceVerifier,
      acceptance fields, prepared-next split, signExact/resolveOrCancel fence
      signer, fence-evidence verifier, quota capacity conversion)
- [x] Migrate `service.test.ts` + `inMemoryLabStore.testing.test.ts`
- [x] Remove the 8 dead imports in `service.ts`
- [x] Complete the service main loop's conflict/rejected/unavailable phase
      passthrough (preflight + reservation handlers; finalize already had it)
- [x] Regenerate evidence template (3-line digest refresh)
- [x] `npm run check` green under Node 22.23.1 (583/583 unit tests)
- [x] `npm run check:all` green (e2e, production-security, shared)
- [x] Committed as 07d452a

## Phase 2 — G2 storage layer (biggest open engineering block)
- [x] Unit 1: checked-in migrations (spec baseline DDL verbatim, 64+64 hash
      partitions, conversation_plan_members with deferred exactly-one-creator),
      checksummed advisory-locked runner (`npm run storage:migrate`), and a
      throwaway-cluster lab (`npm run test:storage`, 8 probes green on PG14).
      Kept out of `npm run check` so it stays offline/database-free.
- [x] Unit 2: migrations 0004-0008 (envelope class/content-type +
      transcript-hash shape + 64-byte signature + ms-canonical received_at,
      witness head-hash identity, delivery signing-key registry,
      Welcome/Commit class binding, immutable release-profile registry,
      purpose-to-role matrix + immutable purpose) with 11 new probes incl.
      concurrent position-fencing and concurrent migration runners (19 total).
      Deferred to the repository unit: pending-intent/fence tables, replay
      identity, page-end projections, policy-head/quota anchors, scope
      mappings (their shape follows the TS port contract). `postgres`
      (porsager) approved as the driver.
- [x] Unit 3: PostgreSQL repository (migration 0009 + postgresDeliveryStore.ts
      on the pinned `postgres` driver) implementing the preflight +
      atomic-persistence ports; delivery service runs end-to-end against it in
      the storage lab (5 pgtest scenarios incl. concurrency and retirement).
      Shared appendPersistence helpers + extracted fictional crypto ports keep
      the in-memory lab and PG store on one contract. Remaining in-lane:
      attachments support, DB-authoritative timestamps, full relational
      authority graph replacing the custody row.
- [x] Unit 4 (037d168): section-11.2 restore drill in the lab — physical
      pg_basebackup + WAL into an isolated cluster, checksum/hash-chain/
      mailbox/acceptance verification from relational rows, identical
      client-visible receipt, staged pending survives + drains. Cross-region
      standby/WAL-archive/KMS/failover remain operational launch work.
- [x] Unit 5 (ae83cdc): attachment measure/bind through the PG adapter with
      reuse rejection proven.
- [x] Unit 6 (4b38eac): embed context plane (issuance/redemption/session +
      origin revocation) on the baseline embed tables, 7 pgtest scenarios.
      OAuth/mTLS + cookie/Fetch-Metadata enforcement live in the HTTP layer.

## Phase 3 — production web surface
- [x] Unit 7: `/embed/{tenantPublicId}` production route + `/v1/embed/*`
      same-origin BFF + EmbedProductionFrame handshake document. The
      production-security release test now proves: 200 + nonce hydration +
      bounded theme materialization + full authenticated postMessage
      handshake under an allowed ancestor + browser-enforced refusal under
      an unlisted ancestor + fail-closed context-invalid redemption when the
      context plane is unconfigured. Unknown tenants and query-bearing
      requests remain the class-based 404. The BFF's redeemed path (cookie,
      session read/delete, replay collapse) is proven against PostgreSQL in
      the storage lab's embedBff suite. Remaining for a real integration:
      run the redeemed path in a deployed browser with a configured plane.
- [ ] Host SDK stub + launcher contract per embed-contract.md

## Phase 4 — identity & chain authority
- [ ] SIWE device sessions against production stores + signature verifiers
- [ ] Finalized Juicebox receipt verification over pinned deployments

## Phase 5 — Candidate B (XMTP) harness
- [ ] Run the provider-neutral G1 harness against XMTP SDK; record comparative
      evidence (selection/approval itself stays with Protocol Security)

## Review notes
(append as phases complete)
