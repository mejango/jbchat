# ADR 0004 — MLS core bridge transport

Status: ratified 2026-08-18 by project-owner delegation ("you do this, you
know it better than me, make a good decision with production in mind").
Decides how the TypeScript service reaches the Rust MLS core (the
`crypto/` workspace pinned by ADR 0001).

## Decision: a release-pinned stdio subprocess, not an in-process addon

The service spawns the bridge binary and speaks one JSON object per line
over stdin/stdout. Binary fields are lowercase hex. Every request carries
a caller-chosen `id`; every response echoes it with either `ok: true` and
a `result` or `ok: false` and the core's stable `mls.*` error code.
Nothing else crosses the boundary: no dependency diagnostics, no secret
material, no timestamps.

Why not napi/N-API (in-process native addon):

1. **SBOM integrity.** launch-gates.md requires the SBOM to cover
   generated bindings. A napi build injects generated glue (per-platform
   `.node` artifacts, binding code emitted at build time) that must be
   tracked as its own supply-chain surface. A plain cargo binary's SBOM
   is exactly its lockfile; `forbid(unsafe_code)` stays meaningful
   because no FFI layer reintroduces unsafe.
2. **Crash and resource isolation.** An MLS-core panic or memory spike
   kills a subprocess the supervisor restarts, not the Next.js process
   serving every route.
3. **Build and deploy simplicity.** Railway builds the web app with npm
   only; the bridge ships as a separately built, release-pinned binary
   whose hash enters the release trust manifest. No per-platform prebuild
   matrix inside the JS toolchain.
4. **Latency is irrelevant at this call rate.** The server-side core
   validates KeyPackages and projects membership commits - per-membership
   -operation work, not per-message work. Milliseconds of process I/O do
   not matter; application payloads never transit the bridge (they are
   E2E-encrypted and opaque to the server).

## Boundaries

- The bridge exposes only deterministic, stateless verbs over the frozen
  v1 profile (`bridge/describe`, `key-package/validate`, and future
  projection verbs). Group-state custody stays in the client cores;
  the server bridge never holds long-lived MLS group secrets.
- The TypeScript client fails closed: an unset `JBM_MLS_BRIDGE_BINARY`
  means the capability is absent, never a fallback implementation.
- Protocol versioning: `bridge/describe` reports `bridgeProtocol: 1`;
  the client refuses to operate on an unknown major version.
- The lab gate builds the binary from the locked workspace and drives it
  end to end from Node; production promotion additionally requires the
  release-pinned hash in the trust manifest (G1/G5 lanes, unchanged).
