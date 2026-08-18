# Native MLS pre-G1 workbench

This directory is a bounded native Rust workbench for the first cryptographic
implementation gate. It uses real MLS client-to-client encryption with
synthetic identities while the existing web/LAN demo remains simulated.

It is **not production-ready**, is **not a G1 result**, and must not carry real
messages, shipping addresses, wallet identifiers, or other personal data. It
has no browser binding, wallet or chain admission, Delivery Service, durable
database, Key Transparency, recovery, external signer, entropy-failure
injection, cross-implementation harness, fuzz campaign, or independent audit.
The memory-only copy-on-write store models atomicity for tests; it does not
survive a process or machine failure.

## Frozen workbench profile

- Rust `1.91.0`, edition 2021, Cargo resolver 2.
- `openmls = 0.9.0-rc.2`, `openmls_traits = 0.6.0-rc.2`,
  `openmls_rust_crypto = 0.6.0-rc.2`,
  `openmls_basic_credential = 0.6.0-rc.2`, and lab-only
  `openmls_memory_storage = 0.6.0-rc.2`, all exact direct pins with default
  features disabled. `tls_codec = 0.5.0` is also exact and direct, with default
  features disabled and only `std` plus `mls` requested.
- OpenMLS upstream commit
  [`831ea9e8f7699887ca101740c34a58f4013b0218`](https://github.com/openmls/openmls/commit/831ea9e8f7699887ca101740c34a58f4013b0218),
  as recorded in every pinned RC2 crate's `.cargo_vcs_info.json`.
- RFC 9420 MLS 1.0 ciphersuite `0x0001` only:
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- Basic credentials with Ed25519 signing keys only.
- Credential contents must use the visibly synthetic, bounded
  `jbm-pre-g1-synthetic:v1:<label>` namespace. Incoming leaf nodes are checked
  for that namespace and the 32-byte Ed25519 public-key encoding.
- Private application messages and public Add/Update/Remove Commit
  handshakes. Standalone proposal ingress is not exposed by this bounded API.
- The standard RatchetTree delivery extension is explicitly enabled so a
  Welcome can carry the public tree. KeyPackage, leaf, and initial GroupContext
  extension sets are otherwise empty; unknown capability inputs are rejected.
- Past-epoch retention is explicitly `MaxEpochs(0)` for both create and join;
  no previous epoch is retained for out-of-order application delivery.
- No last-resort KeyPackages, provider-default capability negotiation,
  custom/draft/PQ suites, draft extensions, private fork, SQLite or OpenMLS
  libcrux provider, test utilities, migration compatibility, crypto-debug, or
  content-debug features.
- Ordinary KeyPackages expire after seven days (with the library's explicit
  one-hour not-before clock-skew margin); longer ranges are rejected.
- Strict complete TLS decoding; trailing input is rejected.
- Decode allocation is preceded by the frozen per-artifact ceiling: 64 KiB
  application ciphertext and KeyPackage, 256 KiB targeted Welcome, and 512 KiB
  public Commit.
- Closed, sanitized wrapper errors; dependency diagnostics do not cross the
  client-core boundary.
- Incoming Commits admit only member-authored, by-value Add, Update, and Remove
  proposals. External/new-member senders, referenced proposals, PSKs, ReInit,
  external init, self-remove, custom proposals, and GroupContext extension
  changes are rejected. Outgoing operations reject a non-empty proposal store
  instead of silently consuming it.
- A Welcome admits no PSKs and exactly one Welcome-only GroupInfo extension:
  the RatchetTree used by this lab profile.

RC2's RustCrypto crate unconditionally includes its own memory-store dependency
and pre-standard algorithm implementation packages in the resolved dependency
graph even when the corresponding OpenMLS draft/PQ features are disabled. The
effective RC2 graph also carries `hpke-rs` experimental/hazmat features. The lab
neither advertises nor invokes those extra suites. Their presence still expands
the artifact review/SBOM surface and is evidence for the eventual ENG-001
provider decision—not something this workbench hides or treats as approved.
Disabling defaults on the direct declarations does not erase features enabled
by RC2's transitive dependencies; the audit freezes and reports the effective
host graph separately.

The suite clones Bob's *current retained state* after an Update and proves that
it cannot decrypt an unprocessed pre-Update ciphertext under the configured
zero-past-epoch schedule. This is useful CRY-09 workbench evidence, but it is
not memory-forensics or secret-zeroization evidence and does not establish that
the compiler, allocator, swap, crash dump, or platform erased every old secret.
CRY-09 therefore remains a promotion blocker pending the frozen provider/build,
storage review, and independent evidence. Pre-join history denial is tested
separately and is not described as forward secrecy.

`client-core` composes the exported `RustCrypto` crypto/RNG implementation with
caller-owned storage. It never instantiates `OpenMlsRustCrypto` or treats the
provider's bundled memory storage as a production boundary. `lab-store` is the
only crate that directly uses `openmls_memory_storage`. RustCrypto owns its
OS-backed entropy path; the workbench neither injects deterministic entropy nor
claims entropy-source failure evidence.

## Explicitly deferred boundaries

This workbench intentionally does not claim the complete Delivery Service or
application event model. In particular:

- The copy-on-write operation treats its one outbox append as canonical
  acceptance and merges the local Commit in the same transaction. It does not
  yet model competing epoch-N candidates, a losing CAS, candidate rejection,
  or the rule that a losing Add's Welcome must never be delivered.
- Replay evidence binds a successfully processed transport envelope ID to its
  exact MLS bytes. There is no authenticated, encrypted application `event_id`
  yet, so a newly encrypted duplicate logical event is not deduplicated.
- A malformed incoming envelope is rolled back rather than persisted as an
  immutable rejected/quarantined hash. Production canonical-envelope binding
  and quarantine are not implemented here.
- Envelope IDs are bounded synthetic lab strings, not production UUIDv4 IDs,
  and the workbench does not implement the frozen Delivery Service counters.
- `LabClient` deliberately supports one group only. Wallet identity, device
  fan-out, multiple groups, recovery, and durable secret storage remain later
  gates.
- OpenMLS's `StagedWelcome` does not expose every staged member leaf before
  `into_group()` persists. The lab's whole-state transaction rolls back a
  later profile rejection; an arbitrary storage implementation used directly
  with `client-core` is not promised generic fail-atomic rejection.
- `ProfileProvider` and the upstream `MlsGroup` type remain public in this
  native evidence crate. Production must expose an opaque policy-preserving
  boundary so downstream callers cannot bypass the checked wrapper functions.
  At the lab layer that boundary now exists: the provider-neutral
  `harness::CandidateLabClient` trait (launch-gates.md §3.1) is the common
  domain API, and `harness::scenarios` holds the shared synthetic scenarios a
  Candidate B adapter must pass byte-for-byte. `client-core` itself still
  exposes OpenMLS internals for this candidate's own adversarial probes.

These are promotion blockers, not implied features of the pre-G1 lab.

## Provider-neutral harness, rejection corpus, and scale knobs

- `lab-store/src/harness.rs` defines `CandidateLabClient` and the common
  scenario set; `tests/native_flow.rs` binds every scenario to the native
  OpenMLS candidate and keeps the OpenMLS-specific wire-format and
  off-profile probes as candidate-local tests.
- `crypto/corpus/{application,commit,key-package,welcome}/` is the
  checked-in rejection corpus (CRY-05/CRY-06). Every entry must be rejected
  by its ingress without consuming state. Regenerate with
  `cargo test -p juicebox-messaging-mls-lab-store --test rejection_corpus
  regenerate_rejection_corpus -- --ignored --exact` and commit the files.
- `tests/rejection_corpus.rs` also runs a seeded deterministic mutation
  smoke each check. Coverage-guided sanitizer/fuzz smoke on the exact
  release artifact still requires the nightly cargo-fuzz toolchain and
  remains a pre-G1 blocker; the deterministic smoke is its offline floor.
- Scale knobs for evidence runs (checks stay fast at the defaults):
  `JBM_G1_REPLAY_COUNT` (default 1,000; PRO-07 evidence uses 100,000),
  `JBM_G1_KILLS_PER_FAILPOINT` (default 100; PRO-10 evidence uses 1,000),
  `JBM_G1_FUZZ_MUTATIONS` (default 500 per ingress).

## Dependency evidence

`scripts/audit-features.sh` uses POSIX shell, `awk`, `grep`, `sed`, and Cargo. It
checks the exact root declarations, disabled direct defaults, exact crates.io
source and pinned lockfile checksums, absence of git/path substitution and
Cargo patch/replace sections, prohibited crates/features, and an allowlist for
the effective features on the six frozen direct dependencies.

The feature graph check covers the active host graph. A reproducible
`--target all` audit was not completed because target-specific crates were not
available in the frozen local cache; cross-target fetching and review remain a
pre-G1 blocker rather than being silently omitted.

A local RustSec database scan on 2026-08-14 reported zero known
vulnerabilities and one unsuppressed unmaintained-package warning:
[`RUSTSEC-2026-0173`](https://rustsec.org/advisories/RUSTSEC-2026-0173) for
`proc-macro-error2 2.0.1`, retained through the target-specific hax/libcrux
transitive lock surface. That warning remains tracked; the lab does not waive
or hide it.

## Run

```sh
cargo fmt --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo run --locked -p juicebox-messaging-mls-lab-cli
cargo tree --locked -e features
sh scripts/audit-features.sh
sh scripts/check.sh
cargo audit --no-fetch --file Cargo.lock
```

The integration scenario covers Alice group creation, Bob ordinary KeyPackage,
Add plus Welcome, bidirectional private application messages, Update, Remove,
post-removal and pre-join history denial, replay, strict trailing-byte
rejection, unsupported suite/capability rejection, exact outbox retry, and
copy-on-write crash rollback. It also checks each ingress size ceiling,
complete decoding across all four ingress artifacts, exact group configuration
on reload, pending-proposal rejection, exact compound Commit-plus-Welcome
retry, and failpoint rollback across KeyPackage, Welcome, Commit, Update, and
Remove mutations. This is engineering evidence for the pre-G1 workbench only;
the remaining requirements in
[`../docs/production/verification.md`](../docs/production/verification.md)
remain release blockers.

An Add produces distinct MLS Commit and Welcome wire bytes, but the lab models
the frozen Delivery Service boundary correctly: the targeted Welcome is
attached to the single Commit outbox record and has no second envelope ID or
conversation-log position.
