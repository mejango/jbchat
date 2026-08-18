# Candidate B (XMTP) written evaluation — ENG-001 decision support

Status: analysis only. This document supports, and cannot close, ENG-001;
selection stays with Protocol Security (decision-log.md). It evaluates XMTP
against the provider-specific hard gate (launch-gates.md §3.13) and the
frozen-profile gate (§3.2) using facts verified against public XMTP
documentation on 2026-08-18, with every unverified item flagged. It is
deliberately outside `docs/production/` so it carries no ratified-spec
authority and does not perturb the evidence-template digests.

The governing rules restated from launch-gates.md:

- §3.1: "Candidate A is then selected unless Candidate B passes every common
  and provider-specific hard gate without weakening architecture.md."
- §3.2: "Any candidate unable to express the frozen profile fails rather
  than silently adapting the profile to provider defaults."
- §3.13: "Any hard product limit or unavailable API that changes the
  security profile is a fail, not an item deferred to after selection."

## 1. Verified hard conflicts with the frozen profile

### 1.1 Ciphersuite (frozen-profile bullet 1) — CONFLICT, verified

The frozen profile mandates RFC 9420 ciphersuite `0x0001`
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). XMTP's security
documentation states: "XMTP messaging uses the ciphersuite
`MLS_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519`" (docs.xmtp.org/protocol/security,
fetched 2026-08-18). The suite is fixed by libxmtp, not
application-configurable. This is not an interoperability nuance: the
Candidate-A workbench's own negative test
(`unsupported_suite_and_capability_are_rejected_without_fallback`,
crypto/crates/lab-store/tests/native_flow.rs) uses XMTP's exact suite as the
canonical `UnsupportedCiphersuite` rejection. Under §3.2's fail rule,
Candidate B cannot express the frozen profile as written.

The only cure is for the (not-yet-ratified) frozen-profile ADR to freeze
ChaCha20-Poly1305 instead — a decision that would have to be made for
provider-compatibility reasons, which is exactly the "adapting the profile
to provider defaults" that §3.2 prohibits.

### 1.2 Last-resort KeyPackages (frozen-profile bullet, launch-gates.md:99) — CONFLICT, high confidence, verify against current libxmtp

The frozen profile requires "Version 1 last-resort KeyPackages disabled in
client/server capabilities and negative tests," and the profile's KeyPackage
model is single-use reservation/consumption with a 10,000-race exclusivity
gate. libxmtp's design uses long-lived last-resort KeyPackages so that
offline mobile installations remain addable without replenishment. If that
remains true of the selected SDK versions, it is a second independent §3.2
fail. Confidence: high from libxmtp's documented design history; the exact
current behavior per SDK release MUST be re-verified from libxmtp source
before this line is cited in the ENG-001 record.

### 1.3 External proposal surface (frozen-profile bullet, launch-gates.md:101; §3.13 bullet 2) — CONFLICT, high confidence, verify against current SDK

The profile requires public external Add/Remove proposal authorization with
mandatory-next-Commit semantics and an independent entitlement-head
validation flow, while external PSK, ReInit, GroupContextExtensions, and
external Commit are disabled. XMTP SDKs expose membership mutation as
`addMembers`/`removeMembers` on a member/admin client and do not expose an
application hook for injecting externally authorized MLS proposals, nor a
client-side commit-validation extension point bound to an independent
entitlement head. §3.13 requires this "without forking/protocol bypass."
Absent a fork, the flow appears inexpressible. MUST be re-verified against
the current libxmtp/SDK release notes before citation.

## 2. §3.13 bullet-by-bullet status

1. **Mainnet compatibility + DB migration per SDK.** XMTP's decentralized
   mainnet was still in Stage 2 (testnet validation) as of February 2026,
   with v1 mainnet targeted at "7 independent nodes" and "approximately 30
   minutes of downtime" at cutover (blog.xmtp.org decentralization update,
   Jan 2026). Written production evidence of mainnet compatibility cannot
   exist before that cutover completes and the selected SDKs migrate. Status:
   not satisfiable today; re-check post-cutover.
2. **External Add/Remove + entitlement-head flow without forking.** See §1.3.
3. **250-account community and device topology within group/inbox limits.**
   Verified: "Each inbox has a maximum of 10 installations" (docs.xmtp.org
   FAQ). With the spec's per-conversation recipient-installation ceiling of
   2,500 and 250 accounts, a community fits only if average installations
   per account stay ≤10 — exactly at XMTP's inbox cap, so the topology is
   boundary-tight. XMTP's own group-member cap and cumulative
   identity-rotation constraints were not confirmed in the public docs
   fetched; unverified.
4. **10,000-recipient announcement within write limits and fees without a
   server-held campaign key.** Verified fee model: all fees in USDC,
   estimated "$5 per 100,000 chat messages," composed of base, storage
   (per-byte-day), and congestion fees (docs.xmtp.org fee docs). Writes flow
   through an application-funded gateway signing with the payer wallet key —
   which is a server-held spend key on the announcement path even though it
   is not a message-content key. Whether a 10,000-recipient fan-out fits
   documented rate limits is undocumented publicly; unverified.
5. **Complete ciphertext/identity/membership/consent/history export plus
   successor-group migration.** Not documented in the public materials
   fetched; no export contract of that scope is part of the public SDK
   surface. Unverified, presumed unavailable pending vendor confirmation.
6. **Documented retention, outage behavior, Gateway/payer dependency,
   fee/spend controls, rate-limit exceptions, abuse response, data regions,
   SLA, incident notification, exit terms.** Partially documented: gateway
   dependency and fees are public; retention appears only as "pre-seeding
   the network with all non-expired messages"; gateway failure behavior,
   SLA, regions, incident terms are not published. Not satisfied by
   public documentation today.
7. **Network functions under tested failure of the hosted Gateway path.**
   Gateways are mandatory, application-funded write infrastructure
   ("Applications will need to maintain funded gateways"); community
   alternatives (e.g. GatewayHost.dev) exist, but no published test of
   gateway-failure behavior exists. Additionally, v1 mainnet nodes require
   "proof of authority from the XMTP Security Council" (7 permissioned
   nodes), which bounds the "claimed to be decentralized" premise itself.
   Unverified/not satisfied by public documentation.

## 3. Conclusion offered to Protocol Security

One §3.2 conflict is verified outright (ciphersuite), two more are high
confidence pending source-level re-verification (last-resort KeyPackages,
external proposal surface), and at least four §3.13 bullets cannot be
satisfied by written production evidence today (mainnet cutover incomplete;
export contract, SLA/exit terms, and gateway-failure testing unpublished).
Under §3.1's default rule, ENG-001 can be closed by selecting Candidate A
without commissioning a Candidate-B harness run, citing §3.2's fail rule and
this document's verified items — or, if Protocol Security contests the
analysis, by commissioning the run after the two flagged items are
re-verified against the then-current libxmtp release. The provider-neutral
harness (crypto/crates/lab-store/src/harness.rs) exists either way; an XMTP
adapter binds `CandidateLabClient` and runs the identical scenarios if the
run is commissioned.

What this document is not: it is not a ratified decision, not part of the
frozen profile, and not evidence of Candidate A's own completion of its
remaining pre-G1 blockers (coverage-guided fuzz smoke, RFC 9420 official
vectors, the frozen-profile ADR itself).

Sources verified 2026-08-18: docs.xmtp.org/protocol/security,
docs.xmtp.org/agents/get-started/faq, blog.xmtp.org
"XMTP's Decentralization Update (Jan 2026)", docs.xmtp.org fee and
decentralization pages (via search excerpts).
