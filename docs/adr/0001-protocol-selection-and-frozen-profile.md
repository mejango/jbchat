# ADR 0001 — Protocol selection (ENG-001) and the frozen v1 profile

Status: ratified 2026-08-18 by project-owner delegation (recorded in the
engineering session log). Supersedes the "open" state of ENG-001 in
`docs/production/decision-log.md`. Reopening conditions are listed at the
end; absent one of them, this document is the selection and the profile.

## Decision 1 — ENG-001 closes: Candidate A (owned Delivery Service + pinned OpenMLS)

launch-gates.md section 3.1 sets the default rule: "Candidate A is then
selected unless Candidate B passes every common and provider-specific hard
gate without weakening architecture.md," and section 3.2 sets the fail
rule: "Any candidate unable to express the frozen profile fails rather
than silently adapting the profile to provider defaults."

Candidate B (XMTP) triggers the fail rule on a verified fact: XMTP pins
ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
(docs.xmtp.org/protocol/security, verified 2026-08-18), while this profile
freezes RFC 9420 `0x0001` (AES-128-GCM). The suite is not application-
configurable in libxmtp; adopting XMTP's suite to cure the conflict is
exactly the profile-adaptation section 3.2 prohibits. Two further
conflicts are recorded at high confidence in
`docs/xmtp-candidate-b-evaluation.md` (last-resort KeyPackages; the
external-proposal/entitlement-head surface), and four provider-specific
gate bullets of section 3.13 have no written production evidence today
(mainnet cutover incomplete; export contract, SLA/exit terms, and
gateway-failure testing unpublished). Under the default rule no Candidate-B
harness run is required to select Candidate A; the provider-neutral
harness (`crypto/crates/lab-store/src/harness.rs`) remains available if a
future challenger materializes.

Owned means owned services over unmodified audited MLS — never a fork and
never home-grown cryptography.

## Decision 2 — The frozen v1 profile

Per launch-gates.md section 3.2, the following are frozen for version 1.
Where an item is already normative in `docs/production/*`, this ADR pins
the reference rather than restating it.

1. **Cryptographic core.** RFC 9420 ciphersuite `0x0001`
   (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). Libraries: `openmls`
   `0.9.0-rc.2` with `openmls_rust_crypto`, `openmls_traits`, and
   `openmls_memory_storage` `0.6.0-rc.2`, exact checksums per
   `crypto/Cargo.lock`; upgrades are a new adapter revision and re-run the
   G1 evidence. 32-byte confirmed-transcript representation; the synthetic
   lab credential is replaced 1:1 by the production credential profile of
   identity-and-entitlement.md at integration. Wire-format policy:
   application messages are `PrivateMessage` only, Commits and external
   proposals are `PublicMessage` only (enforced in `client-core` and by
   the envelopes class/content-type constraint, migration 0004). Required
   capabilities and allowed extensions are exactly
   `client-core::profile_capabilities()`; anything else is
   `UnsupportedCapability`. Past-epoch secrets are deleted immediately
   (`MaxEpochs(0)`); there is no out-of-epoch decryption window.
2. **Canonical encodings.** Domain-separated SHA-256 hashes with the
   `jb-msg-*/v1` domain strings as implemented in
   `src/production/delivery/hashes.ts`, `state.ts`, and
   `policyHeadIssuance.ts`; unsigned-64 wire values are canonical decimal
   strings with the `2^63-1` service/storage ceiling; unknown fields are
   rejected everywhere (`expectExactRecord`); the content-type registry is
   the two MLS media types plus the attachment registry of service-api.md.
3. **Release profile.** Immutable per-generation archived release profiles
   (migration 0007) carrying the full ordered `DeliveryLimits` value and
   digest and the release trust root; zero-disable semantics per
   launch-gates.md; per-conversation recipient-installation limit 2,500;
   the reviewed ceilings of `src/production/delivery/limits.ts` bound
   every ratified value. Production `DeliveryLimits` values are ratified
   with the G2 release-evidence run.
4. **Identifier registry.** UUIDv4 for domain objects and client-generated
   case/event/envelope IDs; UUIDv7 for operational records (timestamp
   leakage disclosed); 256-bit bearer capabilities stored only as
   purpose-separated keyed hashes, as implemented across the identity,
   embed, and eligibility stores.
5. **KeyPackages.** 30-day lifetime, single-use take with permanent
   consumption (key_packages DDL semantics; the 10,000-race exclusivity
   gate is a G2 evidence item). Version 1 last-resort KeyPackages are
   disabled and negatively tested
   (`off_profile_and_last_resort_key_packages_are_rejected`).
6. **Proposal surface.** Public external Add/Remove proposals authorized
   by the entitlement signer with mandatory-next-Commit semantics.
   External PSK, ReInit, GroupContextExtensions, external Commit, and all
   unsupported proposal types are disabled (client-core validation plus
   pending-proposal contamination tests).
7. **Topology.** 250-account community design point; announcement fan-out
   through campaigns; the closed delivery-purpose/role send matrix of
   migration 0008.
8. **Commit CAS and append fencing.** As specified in service-api.md and
   implemented in the append lane: conversation generation, base epoch,
   base roster version, ETag, membership intent, and base
   confirmed-transcript checkpoint; invalid-commit quarantine; idempotent
   replay by request digest; `cc1.` cursors with fenced RPO-0 nonce
   ranges (migration 0016); retirement/recovery rules per the ports
   contract with database-authoritative time (migration 0010).
9. **Policy heads and signers.** The signed head schema of service-api.md
   as persisted by the issuance flow; five-minute freshness; monotonic
   gap-free sequence; external-signer lifecycle exactly per
   storage-and-retention.md (at-most-90-day credentials, staged-next
   published 30 days early, 14-day overlap, monotonic generations,
   five-minute emergency freeze, non-rollback ledger).
10. **Key Transparency / policy-log witness.** Design approved for G2: a
    witnessed append-only policy log whose witness runs as an isolated
    service with exportable state and a documented key-handover procedure.
    Operating model: initially operated by the project itself in a
    separate Railway project with its own access boundary and audit
    stream; that self-operation is transfer-ready by construction and is
    explicitly NOT sufficient for G3 — an independently operated witness
    remains a hard G3 requirement, and the handover procedure is the
    transfer path.
11. **One-writer rule.** Shared-worker fencing with one writing
    installation per browser profile, per architecture.md.
12. **Recovery.** Device/account recovery never restores live MLS state;
    the history-archive feature ships disabled in v1.
13. **Chain parameters.** Per-chain ratified finality profiles are
    separate governance documents (chain_finality_profiles rows); v1
    launch chains are decided in the launch-chain decision, and every
    authorization adapter uses only ratified `active` profiles.
14. **Metadata.** The metadata inventory, logging allowlist, padding
    choice, and retention schedule of security-invariants.md and
    storage-and-retention.md are frozen as written; no new telemetry
    field ships without amending this ADR.

## Consequences

- The MLS integration path is fixed: the Rust workbench graduates behind
  the provider-neutral trait into the release-pinned wire
  inspector/commit verifier adapters; no provider negotiation code ships.
- All XMTP-specific gates in launch-gates.md section 3.13 become moot for
  v1; the written evaluation is retained as the ENG-001 record.
- The G1 evidence set (rejection corpus, deterministic mutation smoke,
  spec-scale replay/failpoint runs) already targets exactly this profile;
  the outstanding G1 items are the coverage-guided fuzz smoke and the
  official RFC 9420 vector run.

## Reopening conditions

ENG-001 may be reopened only if (a) XMTP or another provider ships
configurable ciphersuite `0x0001` with single-use KeyPackages and an
external-proposal surface expressible without forking, and a sponsor
funds the full Candidate-B harness run; or (b) the security reference
model changes such that the frozen suite is deprecated by the IETF or the
auditor. Profile items 1–14 may be amended only by a successor ADR that
re-runs the affected gate evidence.
