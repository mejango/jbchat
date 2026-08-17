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
- [ ] `npm run check:all` green (e2e, production-security, shared)
- [ ] Commit

## Phase 2 — G2 storage layer (biggest open engineering block)
- [ ] PostgreSQL migrations implementing the documented logical DDL
- [ ] Repository implementing AtomicDeliveryPersistencePort against Postgres
- [ ] Restore/concurrency/partition tests per storage-and-retention.md

## Phase 3 — production web surface
- [ ] `/embed/{tenantPublicId}` route with one-use context issuance/redemption
- [ ] Host SDK stub + launcher contract per embed-contract.md

## Phase 4 — identity & chain authority
- [ ] SIWE device sessions against production stores + signature verifiers
- [ ] Finalized Juicebox receipt verification over pinned deployments

## Phase 5 — Candidate B (XMTP) harness
- [ ] Run the provider-neutral G1 harness against XMTP SDK; record comparative
      evidence (selection/approval itself stays with Protocol Security)

## Review notes
(append as phases complete)
