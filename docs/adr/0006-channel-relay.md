# ADR 0006 — Two-way channel relay (Telegram / email / WhatsApp)

Status: proposed 2026-08-25. Decides how a conversation participant can
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
   owned by a service account (`platform: 'desktop'`, a dedicated
   `relay` storage partition class is NOT needed — the roster entry's
   credential is service-signed and its role is `relay`). Its MLS state
   lives server-side in the delivery database, sealed with the identity
   secret, and is driven through the ADR 0004 stdio bridge (the
   `jbm-mls-bridge` binary already speaks create/join/encrypt/decrypt).
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

## Sequencing

1. Relay service identity + sealed bridge-backed MLS state store.
2. Outbound: keeper drain → Telegram sendMessage (member's conversations
   with relay enabled).
3. Consent UI + membership-intent wiring + roster banner copy.
4. Inbound: Telegram webhook reply path with the disambiguation prompt.
5. Email (Resend inbound) and WhatsApp (provider TBD) reuse 1–4.

The notification channel (migration 0022) remains verification + wakeup
only until every item above ships; there is no partial "read-only relay"
state that skips the consent Add.
