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
- [x] Unit 8 (c3834e0): supported host SDK (createEmbedHost) — fixed
      sandbox iframe construction, listener-before-frame, exact-origin
      postMessage, one-use handle custody, fail-closed channel; 6 behavioral
      unit tests through the real protocol gates.

## Phase 4 — identity & chain authority
- [x] SIWE device sessions + signature verifiers: `src/production/identity/`
      — identityCrypto (exact EIP-4361 message with 13 ordered urn resources,
      EIP-191 EOA recovery low-s only via pinned @noble/curves 2.3.0,
      RFC 7638 JKT, ES256 possession verify, length-prefixed possession
      digest), identityKeyedCrypto (purpose-separated HMACs + sealed
      payloads), walletProofVerifier (fail-closed dispatch; contract wallets
      unavailable without bounded 1271/6492 execution), enrollmentStore (PG
      paired-claim state machine: allocate → challenges → one-tx terminal
      claim → verify outside tx → issue/invalid/unavailable; wallet_links +
      installations + device_credentials + initial key_packages row;
      auth_sessions token families with rotation + reuse-kills-family).
      9 offline crypto tests (incl. known priv-1 address vector) + 8 pgtest
      scenarios in the storage lab. ERC-1271/6492 verification and DPoP/HTTP
      enforcement remain launch work needing real chain adapters.
- [x] Finalized Juicebox receipt verification over pinned deployments
      (d08d31a): `src/production/entitlement/` — signed Ed25519 deployment
      manifest (strict parse + exact-signature verify + fail-closed
      resolution into CanonicalPurchaseDeploymentExpectation) and the
      eligibility_grants transaction per storage-and-retention §eligibility:
      verified-parsed receipt + locked project ref/policy/wallet link/active
      installation/ratified active finality profile → five-minute lease with
      finality anchor + evidence digest; claim handles HMAC-only at rest;
      suspend-on-finality-loss, revoke-on-orphaned-anchor, terminal expiry
      sweep. Every non-verified outcome writes no row. Real RPC quorum
      adapters (ChainFinalityVerifierPort / CanonicalPurchaseVerifierPort)
      stay fail-closed unavailable until finality profiles are ratified
      (ENG-004) and a production manifest is signed — launch work, not code.

## Phase 5 — provider-neutral G1 harness (reframed after assessment)
Assessment finding: no provider-neutral harness exists to "run against XMTP".
launch-gates.md:65-68 mandates a common domain API + synthetic harness on
both candidates, but crypto/ leaks OpenMLS types (MlsGroup, KeyPackage,
MlsMessageIn) across client-core's public boundary (its own README:111-113
flags this), and the G1-required rejection corpus + fuzz smoke (CRY-05/06)
do not exist for Candidate A either.
- [x] 5a (7071c4a): harness::CandidateLabClient trait + harness::scenarios
      (16 neutral scenarios incl. PRO-07/PRO-10-shaped scaled loops);
      LabClient is the first impl; native_flow keeps OpenMLS-specific
      probes; checked-in rejection corpus (12 entries × 4 ingresses, all
      rejected without consuming state) + seeded deterministic mutation
      smoke; scale knobs JBM_G1_REPLAY_COUNT / JBM_G1_KILLS_PER_FAILPOINT /
      JBM_G1_FUZZ_MUTATIONS, verified once at spec scale (100k replays,
      1k kills/point, 5k mutations — all passing, ~42 min release run).
      Coverage-guided cargo-fuzz smoke stays launch work (nightly
      toolchain); §3.4's multi-worker seed gate belongs to the PG lane.
- [x] 5b RESOLVED without an XMTP run: ADR 0001 (owner-delegated,
      2026-08-18) closes ENG-001 selecting Candidate A under the default
      rule + frozen-profile fail rule (verified ciphersuite conflict) and
      ratifies the frozen v1 profile. XMTP execution is moot for v1;
      reopening conditions are in the ADR.

## Production decisions (owner, 2026-08-18)
- Witness operating model: self-operated at first in a SEPARATE Railway
  project with its own access boundary and audit stream, transfer-ready
  (state export + key handover documented); independent operator still
  required before G3 — self-operation satisfies the G2 design gate only.
- Production infrastructure: Railway (app + PostgreSQL + witness as
  distinct services/projects). Failover/restore acceptance = re-running
  the lab drills against the Railway Postgres.

## Phase 6 — remaining codeable hardening
Storage-lane follow-ups deferred from Phase 2, executed (1)→(4)→(3)→(2):
- [x] 6a-1 (ae7c336) DB-authoritative timestamps: migration 0010's
      delivery_db_now() feeds every durable timestamp and the retirement
      expiry gate; the lab installs a deterministic one-row clock and
      proves an advanced app clock alone cannot retire a live pending.
- [x] 6a-4 (a77baec) Scope mappings: migration 0011 — delivery_realms,
      conversations.realm/project/tenant scope columns, composite
      (conversation_id, realm_id) FKs on every 0009 lane table,
      quota_scopes resolving each counter hash to its realm-bound subject.
- [x] 6a-3 (9a06e32) Policy-head/quota anchors: migration 0012 —
      quota_counters reserved capacity + row fence driven by relational
      CAS at reserve/finalize/retire (release-conversion defect fixed),
      quota_policies + conversation_quota_bindings + durable reservation
      ledger, policy-head mandatory-proposal completeness trigger (probe-
      proven) + send-grant set member table for the issuance flow.
- [x] 6a-2 (390304a) Relational authority graph: migration 0013 — every
      snapshot component has authoritative rows (conversation projection,
      memberships/role_credentials with state + revocation fence, send
      grants, policy-head anchor, roster/recipient projections, genesis
      join-Commit envelope anchoring the chain from position one);
      loadAuthority cross-checks all of it fail-closed and finalize
      advances the graph in lockstep.

## Phase 6b — the remainder that could be coded (all shipped)
- [x] (24946c7) Custody demotion: migration 0014 deletes the cached JSON
      snapshot; loadAuthority reconstructs the locked snapshot from
      relational rows (sender-selected via the command) and verifies it
      against the persisted digest fence; ordinals/window/limits columns
      make reconstruction byte-exact.
- [x] (47321a6) Replica-failover drill: streaming standby via
      pg_basebackup -R, primary killed without notice, standby promoted;
      pre-failover receipt replays byte-identically and a fresh append
      continues the chain — zero committed-write loss in the lab.
- [x] (608ba9f) Policy-head issuance flow: RFC 8785 JCS canonical bodies,
      jb-msg-policy-head/v1 domain hash, real Ed25519 signer registered in
      policy_head_signing_keys, gap-free chained sequences under
      concurrency, ordered mandatory-proposal rows satisfying the deferred
      completeness trigger, send-grant set-member leaves behind the
      recomputed root, serving that re-derives from immutable bytes and
      fails closed on tampering. Heads stay unwitnessed (no policy log).
- [x] (58e0029) Page-end projections: migration 0015 — immutable exact
      historical projections at every accepted position written in
      finalize, append-only policy-transition rows, immutability triggers
      probe-proven.
- [x] (6bf2adb) cc1 cursor codec: exact grammar, AAD-bound context,
      non-oracular single rejection shape, expired-yet-authentic claims,
      proven against the sync kernel's own claims parser; fenced RPO-0
      nonce ranges (migration 0016) burning remainders across holders.
- [x] (bc7e407) Relational page reader: membership-window-scoped
      position-ordered scan, byte accounting without splitting, empty-
      anchor replay byte-identical, typed history-gone on purged
      projections.

NOT codeable here (unchanged): the independent policy log/witness service,
succinct coalesced range proofs, the five release-pinned verifier adapters
and production sync route (spec-mandated unconfigured), real KMS custody,
chain adapters/ratified finality profiles, XMTP execution (5b), and every
human sign-off gate.
- [x] Written Candidate-B (XMTP) evaluation (1fb5883):
      docs/xmtp-candidate-b-evaluation.md — verified ciphersuite conflict
      (XMTP pins ChaCha20-Poly1305; frozen profile mandates 0x0001
      AES128GCM), flagged last-resort-KeyPackage and external-proposal
      conflicts pending source re-verification, and four provider-gate
      bullets without written production evidence today. ENG-001 closure
      itself stays with Protocol Security.

## Review notes
(append as phases complete)
