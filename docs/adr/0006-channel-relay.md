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
2. **Relay provisioning + consent lane.** A service provisioner mints
   the relay installation (installations + device_credentials +
   KeyPackages need a dedicated service path — enrollment's wallet-proof
   lane cannot make one), and the consent endpoint mints the Add's
   eligibility grant. Decision recorded: a new grant capability
   `channel-relay`, issued ONLY by the consent endpoint under the served
   member's authenticated session, bound to the relay's service account
   (requires extending the grants capability CHECK and the intent's
   admitted-capability list by migration). The intent/commit lane itself
   is unchanged — the member's device still commits the Add.
3. **Outbound:** keeper drain (env-gated child, `send-push-wakeups`
   pattern) — mailbox entries for relay installations → FOR UPDATE on
   the sealed state row → `client/open-application` → channel send with
   the relayFormat rendering + `relay_forward_watermarks`.
4. **Inbound:** Telegram webhook reply path — chat id → verified
   channel → relay → `routeInbound` (tag / single / prompt) →
   `client/seal-application` → the ORDINARY append lane under the
   relay's send grant.
5. Email (Resend inbound) and WhatsApp (provider TBD) reuse 0–4.

The notification channel (migration 0022) remains verification + wakeup
only until every item above ships; there is no partial "read-only relay"
state that skips the consent Add.
