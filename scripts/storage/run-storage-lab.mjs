#!/usr/bin/env node
// Provisions a throwaway local PostgreSQL cluster, applies the storage
// migrations, and proves the first tranche of relational constraints from
// storage-and-retention.md section 1. This is a fictional-data lab harness;
// passing it is necessary but never sufficient G2 evidence (the production
// repository, restore, and failover drills remain separate gates).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { migrateStorage, readMigrationFiles } from "./migrate.mjs";

const REQUIRED_BINARIES = ["initdb", "pg_ctl", "createdb", "psql"];
const LAB_USER = "jbm_storage_lab";
const LAB_DATABASE = "jbm_storage_lab";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) {
    throw new Error(`${command} could not be executed: ${result.error.message}`);
  }
  return result;
}

function requireBinaries() {
  for (const binary of REQUIRED_BINARIES) {
    const probe = run(binary === "psql" ? binary : binary, ["--version"]);
    if (probe.status !== 0) {
      console.error(
        `The storage lab needs local PostgreSQL tooling; ${binary} is unavailable. ` +
          "Install PostgreSQL 14 or newer and re-run npm run test:storage.",
      );
      process.exit(2);
    }
  }
}

function freeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
    server.on("error", reject);
  });
}

function sql(databaseUrl, statement, { expectFailure = false } = {}) {
  const result = run("psql", [
    "-X",
    "-q",
    "-v",
    "ON_ERROR_STOP=1",
    "-tA",
    "-F",
    "\t",
    "-c",
    statement,
    databaseUrl,
  ]);
  if (expectFailure) {
    if (result.status === 0) {
      throw new Error(`Statement unexpectedly succeeded:\n${statement}`);
    }
    return result.stderr.trim();
  }
  if (result.status !== 0) {
    throw new Error(`Statement failed:\n${statement}\n${result.stderr.trim()}`);
  }
  return result.stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => line.split("\t"));
}

const HEX32 = (byte) => `decode(repeat('${byte}', 32), 'hex')`;
const FIXTURE_SQL = `
INSERT INTO tenants (tenant_id, tenant_public_id, status, kms_key_ref, created_at, updated_at)
VALUES ('00000000-0000-4000-8000-000000000001', 'fictional-tenant', 'active', 'fictional-kms', now(), now());
INSERT INTO project_refs (
  project_ref_id, tenant_id, protocol, protocol_version, chain_id,
  projects_contract, project_id, canonical_hash, status, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001',
  'juicebox', '6', 'eip155:8453', decode(repeat('22', 20), 'hex'), 1,
  ${HEX32("31")}, 'active', now()
);
INSERT INTO accounts (account_id, status, created_at)
VALUES ('00000000-0000-4000-8000-000000000003', 'active', now());
INSERT INTO installations (
  installation_id, account_id, platform, storage_partition_class,
  installation_auth_profile, installation_auth_public_jwk, installation_auth_jkt, mls_credential_profile,
  mls_credential_public, mls_credential_fingerprint, status, created_at, last_seen_at
) VALUES (
  '00000000-0000-4000-8000-000000000004', '00000000-0000-4000-8000-000000000003',
  'web', 'top_level', 'p256-es256-dpop.v1', '{"kty":"EC"}'::jsonb, ${HEX32("41")},
  'mls-credential-ed25519-suite-0x0001.v1', ${HEX32("42")}, ${HEX32("43")}, 'active', now(), now()
);
`;

function planInsert(planId, conversationId, memberRows) {
  return `
BEGIN;
INSERT INTO conversation_plans (
  plan_id, conversation_id, project_ref_id, creator_account_id,
  creator_installation_id, kind, delivery_purpose, generation,
  release_profile_id, delivery_limits_digest, release_trust_root_digest,
  quota_policy_digest, roster_canonical, roster_hash,
  external_senders_canonical, external_senders_hash,
  reader_history_retention_policy_hash, plan_version, created_at, expires_at
) VALUES (
  '${planId}', '${conversationId}', '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004',
  'community_room', 'community', 1,
  'fictional-release.v1', ${HEX32("51")}, ${HEX32("52")}, ${HEX32("53")},
  '[]'::jsonb, ${HEX32("54")}, '[]'::jsonb, ${HEX32("55")}, ${HEX32("56")},
  1, now(), now() + interval '2 minutes'
);
${memberRows}
COMMIT;`;
}

const CREATOR_MEMBER = (planId) => `
INSERT INTO conversation_plan_members (
  plan_id, installation_id, account_id, role, bootstrap_mode,
  mls_credential_fingerprint, key_package_ref
) VALUES (
  '${planId}', '00000000-0000-4000-8000-000000000004',
  '00000000-0000-4000-8000-000000000003', 'moderator', 'creator',
  ${HEX32("43")}, NULL
);`;

async function main() {
  requireBinaries();
  const labDirectory = mkdtempSync(join(tmpdir(), "jbm-storage-lab-"));
  const dataDirectory = join(labDirectory, "data");
  let serverStarted = false;
  try {
    const initdb = run("initdb", [
      "-D",
      dataDirectory,
      "--auth=trust",
      `--username=${LAB_USER}`,
      "-E",
      "UTF8",
    ]);
    assert.equal(initdb.status, 0, `initdb failed: ${initdb.stderr}`);
    const port = await freeLoopbackPort();
    const start = run("pg_ctl", [
      "-D",
      dataDirectory,
      "-o",
      `-c listen_addresses=127.0.0.1 -c port=${port} -c unix_socket_directories='' -c fsync=off`,
      "-l",
      join(labDirectory, "postgres.log"),
      "-w",
      "start",
    ]);
    assert.equal(start.status, 0, `pg_ctl start failed: ${start.stderr}`);
    serverStarted = true;
    const created = run("createdb", ["-h", "127.0.0.1", "-p", String(port), "-U", LAB_USER, LAB_DATABASE]);
    assert.equal(created.status, 0, `createdb failed: ${created.stderr}`);
    const databaseUrl = `postgresql://${LAB_USER}@127.0.0.1:${port}/${LAB_DATABASE}`;

    const firstRun = migrateStorage(databaseUrl);
    assert.ok(firstRun.applied >= 3, "expected the initial migrations to apply");
    console.error(`ok - ${firstRun.applied} migrations applied to a fresh cluster`);

    const secondRun = migrateStorage(databaseUrl);
    assert.equal(secondRun.applied, 0, "a second run must be a no-op");
    console.error("ok - migration runner is idempotent");

    sql(databaseUrl, `UPDATE storage_schema_migrations SET checksum_sha256 = repeat('0', 64) WHERE version = '0001'`);
    assert.throws(
      () => migrateStorage(databaseUrl, undefined, () => {}),
      /checksum/,
      "checksum drift must refuse to migrate",
    );
    sql(databaseUrl, `DELETE FROM storage_schema_migrations WHERE version = '0001'`);
    assert.throws(
      () => migrateStorage(databaseUrl, undefined, () => {}),
      /failed/,
      "a missing ledger row over an applied schema must fail loudly, not re-apply",
    );
    const [baseline] = readMigrationFiles();
    sql(
      databaseUrl,
      `INSERT INTO storage_schema_migrations (version, checksum_sha256)
       VALUES ('0001', '${baseline.checksum}')`,
    );
    console.error("ok - checksummed ledger discipline is enforced");

    for (const table of ["envelopes", "mailbox_entries"]) {
      const [[count]] = sql(
        databaseUrl,
        `SELECT count(*) FROM pg_inherits WHERE inhparent = '${table}'::regclass`,
      );
      assert.equal(count, "64", `${table} must have exactly 64 hash partitions`);
      const [[bound]] = sql(
        databaseUrl,
        `SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = '${table}_h07'`,
      );
      assert.match(bound, /modulus 64, remainder 7/i, `${table}_h07 must carry the declared hash bound`);
      const [[childIndexes]] = sql(
        databaseUrl,
        `SELECT count(*) FROM pg_indexes WHERE tablename = '${table}_h07'`,
      );
      const [[parentIndexes]] = sql(
        databaseUrl,
        `SELECT count(*) FROM pg_indexes WHERE tablename = '${table}'`,
      );
      assert.ok(
        Number(childIndexes) >= Number(parentIndexes) && Number(parentIndexes) > 0,
        `${table} partitions must inherit the parent's partitioned indexes`,
      );
    }
    console.error("ok - 64 envelope and 64 mailbox hash partitions exist with inherited indexes");

    sql(databaseUrl, FIXTURE_SQL);
    sql(
      databaseUrl,
      planInsert(
        "00000000-0000-7000-8000-000000000101",
        "00000000-0000-4000-8000-000000000201",
        CREATOR_MEMBER("00000000-0000-7000-8000-000000000101"),
      ),
    );
    console.error("ok - a plan with exactly one creator member commits");

    const missingCreator = sql(
      databaseUrl,
      planInsert("00000000-0000-7000-8000-000000000102", "00000000-0000-4000-8000-000000000202", ""),
      { expectFailure: true },
    );
    assert.match(missingCreator, /conversation_plans_exactly_one_creator_member_fk/);
    console.error("ok - a plan without its creator member row cannot commit");

    sql(
      databaseUrl,
      `INSERT INTO installations (
         installation_id, account_id, platform, storage_partition_class,
         installation_auth_profile, installation_auth_public_jwk, installation_auth_jkt, mls_credential_profile,
         mls_credential_public, mls_credential_fingerprint, status, created_at, last_seen_at
       ) VALUES (
         '00000000-0000-4000-8000-000000000005', '00000000-0000-4000-8000-000000000003',
         'web', 'top_level', 'p256-es256-dpop.v1', '{"kty":"EC"}'::jsonb, decode(repeat('61', 32), 'hex'),
         'mls-credential-ed25519-suite-0x0001.v1', decode(repeat('62', 32), 'hex'), decode(repeat('63', 32), 'hex'), 'active', now(), now()
       )`,
    );
    const duplicateCreator = sql(
      databaseUrl,
      `INSERT INTO conversation_plan_members (
         plan_id, installation_id, account_id, role, bootstrap_mode,
         mls_credential_fingerprint, key_package_ref
       ) VALUES (
         '00000000-0000-7000-8000-000000000101', '00000000-0000-4000-8000-000000000005',
         '00000000-0000-4000-8000-000000000003', 'moderator', 'creator',
         decode(repeat('63', 32), 'hex'), NULL
       )`,
      { expectFailure: true },
    );
    assert.match(duplicateCreator, /conversation_plan_members_one_creator_idx/);
    console.error("ok - a second creator member row is rejected");

    const welcomeWithoutPackage = sql(
      databaseUrl,
      `INSERT INTO conversation_plan_members (
         plan_id, installation_id, account_id, role, bootstrap_mode,
         mls_credential_fingerprint, key_package_ref
       ) VALUES (
         '00000000-0000-7000-8000-000000000101', '00000000-0000-4000-8000-000000000005',
         '00000000-0000-4000-8000-000000000003', 'member', 'welcome',
         decode(repeat('63', 32), 'hex'), NULL
       )`,
      { expectFailure: true },
    );
    assert.match(welcomeWithoutPackage, /violates check constraint/);
    console.error("ok - a welcome member without a KeyPackage take is rejected");

    const foreignPlanPackage = sql(
      databaseUrl,
      `INSERT INTO conversation_plan_members (
         plan_id, installation_id, account_id, role, bootstrap_mode,
         mls_credential_fingerprint, key_package_ref
       ) VALUES (
         '00000000-0000-7000-8000-000000000101', '00000000-0000-4000-8000-000000000005',
         '00000000-0000-4000-8000-000000000003', 'member', 'welcome',
         decode(repeat('63', 32), 'hex'), decode(repeat('71', 32), 'hex')
       )`,
      { expectFailure: true },
    );
    assert.match(foreignPlanPackage, /conversation_plan_members_key_package_ref_plan_id_fkey/);
    console.error("ok - a welcome KeyPackage take must be bound to this exact plan");

    console.error("Storage lab passed. This is lab evidence only; G2 remains open.");
  } finally {
    if (serverStarted) {
      run("pg_ctl", ["-D", dataDirectory, "-m", "immediate", "stop"]);
    }
    rmSync(labDirectory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exit(1);
});
