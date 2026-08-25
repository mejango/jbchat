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
- Launch chains: ALL EIGHT pinned chain IDs — purchases happen on every
  v6 chain (mainnet, OP, Base, Arbitrum One + their four testnets), so
  eligibility must cover all of them from launch. That means eight
  ratified finality profiles in three semantic families (L1 finalized;
  OP-stack derived-from-finalized-L1 for OP/Base; Arbitrum assertion
  semantics), one provider pair covering all eight endpoints, and the
  orphan-response drill run once per family.
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

## Production build-out (post-decisions, 2026-08-18)
- [x] CI workflow (8b5496b): all four gates on every push.
- [x] ADR 0001 (276321a): ENG-001 closed, v1 profile frozen.
- [x] ADR 0002 + witness (3246179, c5f17bb, HTTP unit): RFC 6962 witness
      core over its own database + migrations, cosigning with submitter
      verification and typed equivocation, verifiable inclusion/
      consistency proofs, gossip split-view detection; witness HTTP
      routes active only on the witness deployment (env-gated fail-closed
      404 elsewhere); Railway runbook at docs/deploy/railway.md with the
      overlap-based transfer procedure. Self-operation satisfies the G2
      design gate only — G3 still requires the independent operator.
- [x] Membership-change storage flow, lab-proven end to end (three commits):
      ADR 0003 (resolve-and-bind claim handles; derived committer set) +
      membershipIntentStore (irreversible KeyPackage take, one-live-intent
      conflict precedence, capability-purpose admission, role-credential
      roster projection, membership_pending CAS); custody-fence refactor
      (reconstructAuthoritySnapshot shared by loadAuthority and the new
      refreshCustodySnapshotDigest — EVERY writer that touches fenced
      fields must call it in-transaction); externalProposalStore (chained
      entitlement_signer envelope append, shared
      computeExternalProposalHash in hashes.ts, sync.ts now imports it);
      membershipCommitStore (full spec CAS, Welcome + mailbox fan-out,
      roster/recipient projection rewrite proving the intent's proposed
      hash, outbox event). Lab suite runs the full add lifecycle and
      restores the shared conversation's counters afterward so the drills
      keep admitting fixture appends.
- [x] Unit D — ADR 0004: stdio JSONL subprocess bridge (not napi; SBOM =
      lockfile, crash isolation, npm-only Railway builds, latency moot).
      crates/service-bridge (jbm-mls-bridge: bridge/describe,
      key-package/validate, lab-only synthetic generation) + TS client
      src/production/mls/bridgeClient.ts (fail-closed on unset
      JBM_MLS_BRIDGE_BINARY, protocol-major refusal). npm run mls:lab
      builds the locked binary and drives it from Node; CI crypto job
      runs it. Future verbs: commit projection once server-side group
      state custody is designed.
- [x] HTTP surface v1: RFC 9449 DPoP verification + in-process jti cache
      (shared store needed before multi-instance);
      createMessagingHttpHandlers behind the witness-style fail-closed
      env gate (JBM_IDENTITY_SECRET, credential signer seed/key,
      JBM_ALLOWED_CHAIN_IDS; commit lane: delivery-log seed/key; pages
      lane: cursor key). Routes: device-enrollments (allocate/
      challenges/complete/status over the Enrollment header), auth
      refresh/session (DPoP), membership-intents create/cancel (HTTP
      resolves claim handles per ADR 0003), commits, events page (cc1
      cursor over the fenced PG nonce allocator). Proposal/Commit
      stores now write page-end projections (any newest envelope is a
      page end). Lab suite four: full lifecycle over real Requests with
      real SIWE/possession/DPoP crypto. Wallet verification stays 503
      unavailable until chain adapters ship.
- [x] ENG-004 + chain adapters: ADR 0005 ratifies finality profiles for
      all eight chains (finalized-tag only, 2-provider quorum with hash
      agreement under the LOWEST head, 60s recheck, reorg pauses the
      profile, jbm-evm-adapter.1 digest conventions);
      config/finality-profiles.v1.json + seed script. Adapters in
      src/production/chain/: finality canonicality verifier, canonical
      purchase verifier (payment-beneficiary path proven end to end
      against the strict kernel parser; tier path not-configured), and
      the quorum wallet-proof verifier (EOA only; contract wallets
      unavailable). JBM_RPC_ENDPOINTS wires EOA enrollment live.
- [x] Eligibility lane live end to end: manifest tooling (compose from
      live finalized quorum reads + Ed25519 sign; real omnichain v6
      addresses in config/deployment-manifest.source.json), POST
      /v1/eligibility/purchase-claims (server-issued claims, one-time
      handles), grant-recheck keeper script, lifecycle transitions
      exported standalone. Lab proves purchase receipt -> grant ->
      support-chat admission in one HTTP flow.
- [x] DEPLOYED: jbm-delivery (app-production-bbdd.up.railway.app) +
      jbm-witness (witness-production-3164.up.railway.app), both green:
      migrations, seeded profiles, registered log key, all lanes
      configured (RPC quorum Dwellir+drpc/Tenderly/base-official,
      signed manifest inline). Operational facts in
      docs/deploy/railway.md.
- [x] Keeper service LIVE on Railway (no manual steps left): one
      long-running process = grant recheck (60s) + delivery->witness
      submission (15s); runDeliverySubmissionPass lab-proven against the
      real witness core (in-order drain, per-conversation blocking,
      idempotent passes); delivery submitter PUBLIC key registered in
      the witness DB. Keeper start command set per-service via GraphQL
      (railway.json carries no startCommand on purpose).
- [x] Push wakeups (keeper child, payload-free VAPID webpush) +
      KeyPackage publication + planning/activation routes + staff
      registration by on-chain ownership: all lab-proven and deployed.
- [x] PRODUCTION FRONTEND replaces the prototype: juicebox.money-family
      UI (ported tokens/fonts), wallet stack = injected + Coinbase +
      WalletConnect + Para (env-gated key), real enrollment ceremony
      (WebCrypto P-256 + Ed25519, SIWE, quorum-verified), DPoP sessions,
      purchase claiming, real inbox + transcript views, View-as toggle +
      /account/[address]. Prototype demo moved to src/shared, /shared +
      /projects 404 in production. Build on webpack with JBM's alias
      set. LIVE at app-production-bbdd.up.railway.app.
- [x] APPEND LANE OPEN (e14e73c): per-sender custody fences (0019),
      global policy log (0020: leaf per issued head + RFC 6962
      checkpoint), keeper-triggered /v1/internal/policy-witness-sync
      submits checkpoints to the witness policy namespace and flips
      anchors missing->verified (equivocation = SEV-0 verbatim stop).
      Grants re-anchor at the issued head hash post-issuance; locked
      proof evidence digest derived per sender (fence-bound). POST
      /v1/conversations/:id/envelopes = full atomic append (DPoP +
      If-Match + idempotency); GET detail serves etag/epoch/policy-head
      state. E2e: plan -> activation -> witness -> both-way sends ->
      events read back. Deployed app+keeper with sync/witness env.
- [x] BROWSER MLS CORE + LIVE SEND UI (805af3f): crypto wasm-client
      crate (client core -> wasm32, state snapshot in IDB, native
      round-trip test), real MLS KeyPackages at enrollment + 3 spares,
      on-device claim->plan->group+Commit+Welcome->activate, welcome
      sync + decrypt-once-cached transcript, live thread UI with
      composer. New reads: envelope body + installation welcomes
      (lab-covered incl. cross-installation 403). Ceilings: single
      welcome-target activation; post-genesis commits not yet
      client-processed.
- [x] PUSH SUBSCRIBE UI (ba893b4): sw push/notificationclick handlers
      (payload-free; still no cache handler), PushManager subscribe w/
      NEXT_PUBLIC_VAPID_PUBLIC_KEY, endpoint register/delete, inbox
      toggle.
- [x] DEPLOYED (2026-08-18 night): app + keeper redeployed with all
      three lanes; prod DB at 20 migrations; /v1/internal/policy-witness-
      sync live (401 unauth, clean report with token), new welcome +
      envelope reads 401-gated, keeper sync trigger looping silently
      (logs only on failure). Railway incident stalled builds for hours;
      app moved to plain us-east4 (GCP builder pool) - eqdc* Metal
      regions were the ones wedging.
- [x] MULTI-DEVICE STAFF + FOLLOWER COMMITS (237bbfa, deployed): core
      add_members plural (one Commit, one Welcome for all invitees;
      3-member native test), activation welcomes every staff
      installation, group map tracks the processed commit position and
      the transcript loop merges later commits in order before opening
      newer ciphertexts (unmergeable commit stops rendering).
- [x] EXTERNAL-SENDER AGING (01cccbd): keeper-driven rotation per ADR
      0001 item 9 - promote staged into the 14-day overlap, stage the
      next generation, retire expired, non-rollback generation ledger;
      plans/heads read real generations. POST
      /v1/internal/external-sender-rotation, keeper cadence 6h.
      Lab-proven (promote/idempotent/retire).
- [ ] Then: custom domains + GitHub auto-deploys (both wait on owner:
      domain names, repo push); independent witness operation (G3).
      Client niceties when wanted: KeyPackage restock trigger,
      multi-conversation welcome batching.

NOT codeable here (unchanged): succinct coalesced range proofs beyond the
witness's consistency proofs, the independent OPERATION of the witness,
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

## Relay phase 1 — added-member authority path (2026-08-25)

- [x] Extract appendAuthority.ts (issueConversationPolicyHead, ensureMemberQuotaBindings, provisionProjectMessaging); activate() uses it
- [x] Role-credential issuer in membershipIntentStore.createIntent (+ targetCredentialId in result)
- [x] membershipCommitStore: quota bindings + head re-issue + grants + etag for add
- [x] Internal HTTP route POST /v1/internal/membership-proposals (bearer JBM_INTERNAL_SYNC_TOKEN)
- [x] Wire provisioningSeed/proposals in messagingHttp.ts
- [x] Tests: LAB restore helper, existing add-lifecycle suites, third-member acceptance suite
- [x] npm run check; storage lab green (run 6, 7)
- [ ] railway up; memory update

### Review
- consumeCommit never rewrote conversations.etag (latent: any append after a membership Commit failed conversation-state-invalid) — fixed.
- Unwitnessed head → the proof verifier returns 503, not the 422 policy-head-not-witnessed ladder (pre-existing).
- Policy heads carry a 5-minute expires_at and nothing refreshes the anchor; lab clocks are frozen so tests never see it. Reported, not fixed.
