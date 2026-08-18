# PostgreSQL storage migrations

This directory turns the logical contract in
[`docs/production/storage-and-retention.md`](../docs/production/storage-and-retention.md)
into real, checksummed, monotonically numbered PostgreSQL migrations.

- `migrations/0001_spec_baseline.sql` is the specification's section-3 DDL
  excerpt verbatim, with its two inline prose paragraphs removed.
- `migrations/0002_envelope_and_mailbox_hash_partitions.sql` creates the 64
  envelope and 64 mailbox hash partitions the excerpt only declares.
- `migrations/0003_conversation_plan_members.sql` normalizes plan rosters into
  relational members with the creator/welcome shape, plan-bound KeyPackage
  takes, and the composite deferred exactly-one-creator constraint.
- `migrations/0004_envelope_and_witness_integrity.sql` binds envelope class to
  its exact MLS content type, enforces the per-class transcript-hash shape,
  the 64-byte Ed25519 delivery signature, the canonical-millisecond
  `received_at`, and witness receipt identity against
  `(conversation_id, position, head_hash)`.
- `migrations/0005_delivery_log_signing_keys.sql` adds the active/retired
  delivery signing-key registry with a foreign key from every checkpoint.
- `migrations/0006_welcome_commit_binding.sql` binds every Welcome to the
  exact Commit envelope identity and the `mls_commit` class.
- `migrations/0007_archived_release_profiles.sql` adds the immutable archived
  release-profile/DeliveryLimits registry with digest/trust-root foreign keys
  from plans and conversation generations.
- `migrations/0008_membership_purpose_role_matrix.sql` makes delivery purpose
  immutable and enforces the purpose-to-role membership matrix, including
  read-only `subscriber`.
- `migrations/0009_application_append_state.sql` adds the durable
  application-append lane state: monotonic fence-lane generations, the
  interim authority custody row, invisible pending intents (exactly one per
  lane), realm-scoped acceptances bound to the finalized envelope row, HTTP
  idempotency scopes, and immutable retirement tombstones.

## PostgreSQL repository

`src/production/storage/postgresDeliveryStore.ts` implements the
`applicationAppendPreflight` and `atomicPersistence` ports against this
schema with the `postgres` driver: every canonical document is re-parsed and
digest-verified on read, lanes serialize on the locked authority row, and a
finalize commits the envelope, mailbox fanout, usage, outbox event,
acceptance, and idempotency rows in one transaction. The storage lab runs the
real delivery service against it (`src/production/storage/*.pgtest.ts`),
covering accept, HTTP/envelope replay across process boundaries, idempotency
conflict, concurrent distinct appends, attachment measure/bind with reuse
rejection, and expired-pending retirement with fenced position reuse. Durable
timestamps (reserved_at, finalized_at, retired_at, the signed received_at,
idempotency expiry) and the pending-expiry retirement gate come from the
database clock `delivery_db_now()` (migration 0010); the injected clock
remains only for invocation-deadline control-plane reads, and the lab proves
an advanced application clock alone cannot retire a live fenced pending. The
authority custody row is an explicit interim stand-in for the full
relational authority graph.

`npm run storage:migrate` applies pending migrations to the exact database in
`JBM_STORAGE_DATABASE_URL`; it never infers a target, refuses checksum drift,
and serializes runners with an advisory transaction lock. It is an operator or
lab job — production pods never self-migrate.

`npm run test:storage` provisions a throwaway local PostgreSQL cluster with
the host's `initdb`/`pg_ctl`/`psql`, applies the migrations, and proves the
first tranche of section-1 blocker constraints with fictional data. It needs
PostgreSQL 14 or newer installed locally and is intentionally not part of
`npm run check`, which stays offline and database-free.

## Boundary

Passing the storage lab is necessary but not sufficient G2 evidence.
Lab-proven: the pending-intent/fence/acceptance linkage (0009), the
section-11.2 restore drill and the streaming-replication failover drill,
DB-authoritative time (0010), realm/quota-scope mappings (0011), quota
anchors with relational capacity CAS plus the policy-head completeness
assertion (0012), the relational authority graph with fail-closed
reconstruction from rows after the custody JSON was deleted (0013/0014),
immutable page-end projections and policy-transition rows with the
relational page reader (0015), the policy-head issuance flow with signed
immutable bodies and set-member provenance, and the cc1 cursor codec with
fenced RPO-0 nonce ranges (0016). Still open, per the specification's own
gate language: the independent policy log/witness service (so issued heads
stay unwitnessed and historical-page proofs cannot be produced), the
succinct coalesced policy-transition range proof, the five release-pinned
page verifier adapters and the production sync route the spec itself
leaves unconfigured, real KMS custody for the signer domains, and
cross-region operational failover beyond the lab drill.
