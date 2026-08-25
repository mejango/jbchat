# ADR 0006 — Two-way channel relay (Telegram / email / WhatsApp)

Status: ratified 2026-08-25 by project owner ("signed off"). Decides how
a conversation participant can
read AND answer their end-to-end encrypted chats from an out-of-band
channel (Telegram first; email and WhatsApp follow the same shape), and
what that costs in confidentiality. Implementation is sequenced after
this design is ratified; the notification-channel plumbing shipped in
migrations 0022/0023 is the substrate.

## The problem

Wakeup notifications (shipped) tell a user "you have activity" but the
content stays end-to-end encrypted to their enrolled devices. Real
support conversations die when answering requires opening a browser.
The product goal is: an owner sees the customer's message IN Telegram
and replies FROM Telegram, without silently breaking the encryption
story for everyone else.

## Decision: an explicit per-conversation relay member, not a backdoor

A relay is a SERVICE-OPERATED MLS MEMBER — a real installation with a
real KeyPackage, holding a real roster seat, visibly listed in the
conversation roster. It is never a passive decryption capability, and it
is never added by default.

1. **Identity.** One relay installation per (account, channel kind),
   owned by a service account (`platform: 'desktop'`). The relay joins
   with the SAME role as the member it serves (`customer` or
   `project-staff`) — the role enums are closed in four schema CHECKs
   plus the 0008 purpose→role matrix, and a distinct `relay` role would
   buy nothing the roster banner does not already disclose. Its MLS
   state lives server-side in the delivery database, sealed with the
   identity secret, and is driven through the ADR 0004 stdio bridge via
   the `client/*` state-threading verbs (phase 0 below): a snapshot
   rides in with each request and the mutated snapshot rides back, so
   the bridge itself stays stateless and never holds group secrets
   between requests — the ADR 0004 custody boundary is preserved, with
   custody moving to the sealed DB row rather than into the bridge.
2. **Consent.** The relay joins a conversation only after the OWNING
   member explicitly enables "Relay to Telegram" for that conversation
   in the UI. Enabling composes a normal membership intent (ADR 0003)
   targeting the relay installation; the member's own device commits the
   Add. The OTHER side sees a roster event and a persistent banner:
   "<display>'s Telegram relay can read this conversation." Disabling
   composes the Remove the same way; MLS forward secrecy then seals
   everything after the removal epoch.
3. **Confidentiality statement (the honest one).** While a relay seat is
   active, conversation plaintext transits the service for THAT member's
   channel delivery, and lives transiently in the channel provider
   (Telegram/Meta/email servers). This is a deliberate, per-conversation
   downgrade from device-only E2E to service-mediated delivery, chosen
   by the member it serves, visible to everyone in the roster. The
   product copy must say exactly this; anything softer is a lie.
4. **Outbound path.** Delivery fan-out already writes the relay
   installation's mailbox entries. A keeper loop drains them: bridge
   decrypt → channel send (senders.ts) with the sender's display name
   and the project name. Message content in the channel is the SAME
   plaintext the member would see in the app — no quoting of other
   conversations, attachments deferred (link back into the app).
5. **Inbound path.** The channel webhook (Telegram `message`, email
   inbound-parse, WhatsApp webhook) maps sender → verified
   notification_channel → relay installation → conversation. The relay
   encrypts via the bridge and appends through the SAME append lane as
   any member (DPoP-equivalent service auth, send grant, custody fence,
   quotas) — the relay is a member, so no bypass surface exists. A
   channel message that cannot be attributed to exactly one active
   relayed conversation is answered with a channel-side prompt to pick
   ("reply to [1] Project A / [2] Project B"), never guessed.
6. **Blast-radius bounds.** The relay's send grant carries the standard
   per-installation quotas. Compromise of the relay's sealed state
   exposes only conversations with an ACTIVE relay seat — never the
   accounts' other conversations — and revoking the relay installation
   (device-revoke lane, shipped) cuts everything at once.

## Rejected alternatives

- **Server-side silent decryption key escrow** — destroys the E2E claim
  globally to serve one member's convenience; unacceptable.
- **Channel-side end-to-end (Telegram secret chats / Signal-style)** —
  not available to bots on any target channel; would also make the
  relay a second E2E system to govern.
- **Client-relay (the member's own browser forwards)** — no availability
  (browser must be open, at which point the app is usable anyway).

## Sequencing (corrected 2026-08-25 after a full subsystem audit)

0. **Bridge client verbs — SHIPPED.** `client/create-identity`,
   `client/generate-key-package`, `client/join-welcome`,
   `client/seal-application`, `client/open-application`,
   `client/process-commit` on `jbm-mls-bridge`, state-threading, same
   snapshot envelope as the wasm client. Proven by a Rust round-trip
   test (member device on the core, relay purely over the verbs) and
   the TS bridge lab. Prerequisite discovered: the binary does NOT ship
   to Railway today (nixpacks is npm-only) — production needs either a
   nixpacks Rust phase or a release-pinned vendored linux binary whose
   hash enters the trust manifest (ADR 0004's stated intent).
1. **Complete the added-member authority path - SHIPPED.** The audit
   found the membership-Add lane created memberships/welcomes/projections
   for an added member but NO role_credentials issuer, NO
   conversation_send_grants row, NO per-member quota bindings, and no
   HTTP surface for the external-proposal step - so no added member
   (relay or human) could append. Now: intent creation issues the
   target's conversation role credential under the role its grant
   capability admits (`purchase-support` -> customer, `project-staff` ->
   project-staff; other purposes refuse) and returns
   `targetCredentialId`; the Commit transaction appends the target's
   installation/account quota bindings, re-issues the policy head
   (sequence N+1) over the full send-grant set through the same
   zero-anchor-then-re-anchor order as genesis (`appendAuthority.ts`,
   shared with activation), rewrites every grant at the new head, drops
   the anchor to `witness_state='missing'` (appends close for everyone
   until the keeper's policy-witness sync cosigns the new checkpoint),
   and rewrites the etag and custody fences. The external proposal is
   the service acting as MLS external sender, so it rides an internal
   route - `POST /v1/internal/membership-proposals`, bearer
   `JBM_INTERNAL_SYNC_TOKEN` - never a member session. Proven by the
   storage-lab suites (intent lifecycle, HTTP add lifecycle, and a third
   member added to an activated conversation who reads and appends while
   the original members keep appending).
2. **Relay provisioning + consent lane - SHIPPED.** Two decisions
   recorded at implementation (owner, 2026-08-25): (a) relay-shaped rows
   by migration 0025 rather than a fabricated enrollment chain - a
   `key_packages` row of kind `relay-mls-key-package.v1` carries no device
   credential, and an `eligibility_grants` row of capability
   `channel-relay` carries no finality anchor
   (`finality_status = 'not-applicable'`; the finality sweepers skip it);
   (b) the external proposal recorded for a consent Add/Remove is the
   service's authorization record (`jbm-relay-consent-authorization.v1` /
   `-revocation.v1`), NOT an MLS PublicMessage - the bridge has no
   external-sender signing verb yet, and the member's device commits a
   self-authored Add/Remove exactly as activation does. The provisioner
   (`relayInstallationStore.provision`) mints one relay per (served
   account, channel): its own service account, an `installations` row
   (`platform='desktop'`, a discarded DPoP key), the bridge identity +
   KeyPackage, and the sealed post-KeyPackage snapshot; it tops the shelf
   up on reuse. `POST /v1/conversations/{id}/relay` (served member's
   session; verified Telegram channel required; bridge required) mints
   the grant, composes the Add intent + proposal in-process and returns
   the intent, the relay's taken KeyPackage and the anchor's mandatory
   proposals; `DELETE` composes the Remove (the wasm client gained
   `removeMember`; the commit lane now revokes the removed grant and
   re-issues the head). The relay joins with the served member's role;
   only the served member may compose its Add/Remove (`relay-not-yours`).
   Conversation detail carries `relay.seats` for every member plus the
   §3 statement; the `RelayPanel` shows it verbatim.
3. **Outbound - SHIPPED.** The drain runs in the app (it holds the
   pinned bridge and the channel credentials); the keeper ticks
   `POST /v1/internal/relay-drain` every 15 s exactly like the witness
   sync. Per active relay, under `FOR UPDATE` of its row
   (`relayInstallationStore.withState`): join every Welcome addressed to
   it (`mls_welcomes` → `client/join-welcome`; the group id and the
   processed position land in `relay_forward_watermarks`, migration
   0026), then fold every envelope after the processed position - Commits
   via `client/process-commit`, application messages via
   `client/open-application` → `renderOutbound` → Telegram `sendMessage`
   to the served member's verified chat - and advance the watermarks. The
   relay's own appends are never echoed. A failed channel send after the
   message was opened is logged and counted (MLS has ratcheted; the
   plaintext is never persisted; the app still has the message).
4. **Inbound - SHIPPED.** The Telegram webhook maps `chat.id` →
   verified `notification_channels` (index in 0026) → the account's
   active relay → the conversations that relay is seated in;
   `routeInbound` picks one by tag or uniqueness, or replies with
   `renderPrompt` - never a guess. The relay seals under its row lock
   (`client/seal-application`) and appends through `appendForInstallation`
   - the SAME service, ports and request commitment the member's device
   uses below the DPoP session, so send grant, custody fence, quotas and
   the witness gate apply unchanged. `Idempotency-Key` and the envelope id
   derive from Telegram's `update_id`: a retried update replays, an edited
   one conflicts. Refusals are channel replies; the webhook always acks 200.
5. Email (Resend inbound) and WhatsApp (provider TBD) reuse 0–4.
6. **Bridge shipping to Railway - SHIPPED.** The bridge ships vendored,
   exactly as ADR 0004 intended: `npm run mls:bridge:build` builds
   `bin/mls-bridge/linux-x64/jbm-mls-bridge` (static musl, linux/amd64)
   inside the pinned `rust:<toolchain>-alpine` image from the locked
   workspace and writes `bin/mls-bridge/manifest.json` with the binary's
   SHA-256 and the SHA-256 of `crypto/Cargo.lock` (its SBOM).
   `npm run mls:bridge:check` (inside `npm run check`) fails when the
   committed bytes or the lockfile drift from the manifest. At runtime
   `resolveMlsBridgeFromEnvironment` refuses to spawn any binary whose
   digest is not in the manifest; only the lab may opt out
   (`JBM_MLS_BRIDGE_ALLOW_UNPINNED=1`). Both Railway services carry
   `JBM_MLS_BRIDGE_BINARY=/app/bin/mls-bridge/linux-x64/jbm-mls-bridge`;
   `POST /v1/internal/enrollment-status` reports `mlsBridge` (resolution
   + a `bridge/describe` round trip) as the operator's proof.

The notification channel (migration 0022) remains verification + wakeup
only until every item above ships; there is no partial "read-only relay"
state that skips the consent Add.
