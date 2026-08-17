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

Passing the storage lab is necessary but not sufficient G2 evidence. Still
open, per the specification's own gate language: the remaining section-1
blocker constraints (envelope class/content-type and transcript-hash shape
probes, witness receipt identity, Welcome/Commit binding, signing-key registry
coverage under writes, archived release-profile registry use, replay/fence
invisibility, historical page-end projections, policy-head set anchors, and
authoritative scope mappings), the production repository that implements
`AtomicDeliveryPersistencePort` against this schema, migration tests under
concurrent writes, the section-11.2 restore drill, and replica failover.
