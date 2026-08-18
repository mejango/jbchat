# ADR 0003 — Membership-intent gap decisions

Status: ratified 2026-08-18 by project-owner delegation. Closes two
normative gaps the membership-change specification leaves open; recorded
here so the implementation codifies a decision rather than an accident.

## Gap 1 — eligibility claim-handle consumption at intent creation

The specs define the one-time-returned, HMAC-stored claim handle and
require it for `purchase-support`/`item-set-buyer` admission, but no
sentence states whether intent creation burns it.

**Decision: resolve-and-bind, not burn.** Presenting a claim handle at
intent creation resolves it (via the existing keyed-hash lookup) to an
ACTIVE, unexpired eligibility grant whose account owns the target
installation and whose capability admits the conversation's purpose; the
intent row stores `grant_id`. The handle itself is not invalidated:
grants are deliberately short five-minute leases, and the one-live-intent
index already prevents duplicate admission attempts, so burning would add
a second expiry mechanism without adding safety. Grant expiry, suspension,
or revocation between intent creation and Commit still blocks the Commit,
because the Commit path re-checks the referenced grant's state - the
lease, not the handle, is the authority.

## Gap 2 — where the "authorized committer" set lives

The intent response must bind "authorized committer installation IDs",
but no table or column stores such a set.

**Decision: derive, never store.** The authorized committer set is
computed at read time as: active memberships of the conversation whose
role may append under the closed purpose/role send matrix
(`purchase_support` -> customer, project-staff; `community` -> member,
moderator; `announcement` -> publisher), minus the removal target for a
`remove` intent, minus installations with a pending removal intent.
Storing the set would create a second mutable authority that could drift
from the membership rows the Commit CAS actually checks; deriving keeps
one source of truth. The set in the response is advisory routing
information - the Commit transaction re-derives it under lock.

## Consequences

- `membership_intents.grant_id` remains a plain nullable FK (null exactly
  for server-originated removes), matching the existing DDL unchanged.
- The HTTP layer resolves handles through the eligibility store's
  existing `readGrantByClaimHandle`; the intent store receives a resolved
  `grantId` and re-validates the grant row relationally in-transaction.
- No schema change is required by either decision.
