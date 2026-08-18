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
INSERT INTO archived_release_profiles (
  release_profile_id, delivery_limits_digest, release_trust_root_digest,
  delivery_limits_canonical, created_at
) VALUES (
  'fictional-release.v1', ${HEX32("51")}, ${HEX32("52")}, '{}'::jsonb, now()
);
INSERT INTO delivery_log_signing_keys (
  key_id, public_key, state, valid_from, valid_until, created_at
) VALUES (
  'fictional-storage-probe-2026q3', ${HEX32("81")}, 'active',
  now() - interval '1 day', now() + interval '30 days', now()
);
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

const CONVERSATION_FIXTURE_SQL = `
INSERT INTO delivery_realms (realm_id, tenant_id, created_at)
VALUES ('fictional-probe-realm', '00000000-0000-4000-8000-000000000001', now())
ON CONFLICT DO NOTHING;
INSERT INTO quota_policies (quota_policy_digest, canonical_document, created_at)
VALUES (${HEX32("53")}, '{}'::jsonb, now())
ON CONFLICT DO NOTHING;
INSERT INTO conversations (
  conversation_id, project_ref_id, kind, delivery_purpose, generation, state,
  group_id_hash, release_profile_id, delivery_limits_digest,
  release_trust_root_digest, quota_policy_digest, epoch, roster_version,
  roster_hash, external_senders_hash, reader_history_retention_policy_hash,
  confirmed_transcript_hash, current_policy_head_hash, current_log_head_hash,
  retention_policy_version, retention_policy, created_at, last_activity_at,
  expires_at, realm_id, project_scope_id, tenant_scope_id,
  etag, recipient_set_version, recipient_set_hash
) VALUES (
  '00000000-0000-4000-8000-000000000301', '00000000-0000-4000-8000-000000000002',
  'community_room', 'community', 1, 'active',
  ${HEX32("91")}, 'fictional-release.v1', ${HEX32("51")}, ${HEX32("52")},
  ${HEX32("53")}, 0, 0, ${HEX32("92")}, ${HEX32("93")}, ${HEX32("94")},
  ${HEX32("95")}, ${HEX32("96")}, ${HEX32("97")},
  1, '{}'::jsonb, now(), now(), now() + interval '30 days',
  'fictional-probe-realm', 'fictional-probe-project', 'fictional-probe-tenant',
  'fictional-probe-etag', 0, ${HEX32("98")}
);
`;

function envelopeInsert({
  position = "2",
  envelopeId = "00000000-0000-4000-8000-000000000402",
  headByte = "a2",
  contentType = "application/vnd.juicebox.messaging.mls-private-message",
  transcripts = "NULL, NULL",
  signature = "decode(repeat('99', 64), 'hex')",
  receivedAt = "date_trunc('milliseconds', now())",
  signingKeyId = "fictional-storage-probe-2026q3",
}) {
  return `
INSERT INTO envelopes (
  conversation_id, position, envelope_id, envelope_class, sender_type,
  sender_account_id, sender_installation_id, epoch, roster_version,
  base_confirmed_transcript_hash, resulting_confirmed_transcript_hash,
  content_type, envelope_bytes, envelope_sha256, previous_head_hash,
  leaf_hash, head_hash, log_signing_key_id, log_checkpoint_digest,
  log_head_signature, received_at, expires_at
) VALUES (
  '00000000-0000-4000-8000-000000000301', ${position}, '${envelopeId}',
  'application', 'installation', '00000000-0000-4000-8000-000000000003',
  '00000000-0000-4000-8000-000000000004', 0, 0, ${transcripts},
  '${contentType}', decode('ab', 'hex'), ${HEX32("e1")}, ${HEX32("e2")},
  ${HEX32("e3")}, decode(repeat('${headByte}', 32), 'hex'), '${signingKeyId}',
  ${HEX32("e4")}, ${signature}, ${receivedAt}, now() + interval '30 days'
)`;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function proveConcurrentPositionFencing(databaseUrl) {
  const { spawn } = await import("node:child_process");
  const holderSql = `BEGIN;
${envelopeInsert({ position: "5", envelopeId: "00000000-0000-4000-8000-000000000501", headByte: "f1" })};
SELECT pg_sleep(1.5);
COMMIT;`;
  const holder = spawn(
    "psql",
    ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", holderSql, databaseUrl],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  const holderExit = new Promise((resolve) => holder.on("close", resolve));
  await sleep(500);
  const contender = sql(
    databaseUrl,
    envelopeInsert({
      position: "5",
      envelopeId: "00000000-0000-4000-8000-000000000502",
      headByte: "f2",
    }),
    { expectFailure: true },
  );
  assert.match(contender, /duplicate key/);
  assert.equal(await holderExit, 0, "the first writer must commit its fenced position");
  const [[survivors]] = sql(
    databaseUrl,
    `SELECT count(*) FROM envelopes
     WHERE conversation_id = '00000000-0000-4000-8000-000000000301' AND position = 5`,
  );
  assert.equal(survivors, "1", "exactly one envelope may claim a position under concurrency");
  console.error("ok - concurrent writers cannot double-claim an envelope position");
}

async function runRestoreDrill(labDirectory, livePort, liveUrl) {
  const statePath = join(labDirectory, "restore-drill-state.json");
  const drillFile = "src/production/storage/postgresRestoreDrill.pgtest.ts";
  const prepare = run(
    "npx",
    ["vitest", "run", "--config", "vitest.storage.config.ts", drillFile],
    {
      env: {
        ...process.env,
        JBM_STORAGE_DATABASE_URL: liveUrl,
        JBM_RESTORE_DRILL_PHASE: "prepare",
        JBM_RESTORE_DRILL_STATE: statePath,
      },
      stdio: ["ignore", "inherit", "inherit"],
      encoding: undefined,
    },
  );
  assert.equal(prepare.status, 0, "the restore drill prepare phase must pass");

  const restoreDirectory = join(labDirectory, "restored-data");
  const backup = run("pg_basebackup", [
    "-h",
    "127.0.0.1",
    "-p",
    String(livePort),
    "-U",
    LAB_USER,
    "-D",
    restoreDirectory,
    "-X",
    "stream",
    "--checkpoint=fast",
  ]);
  assert.equal(backup.status, 0, `pg_basebackup failed: ${backup.stderr}`);
  const restoredPort = await freeLoopbackPort();
  const startRestored = run("pg_ctl", [
    "-D",
    restoreDirectory,
    "-o",
    `-c listen_addresses=127.0.0.1 -c port=${restoredPort} -c unix_socket_directories='' -c fsync=off`,
    "-l",
    join(labDirectory, "restored-postgres.log"),
    "-w",
    "start",
  ]);
  assert.equal(startRestored.status, 0, `restored pg_ctl start failed: ${startRestored.stderr}`);
  try {
    const restoredUrl = `postgresql://${LAB_USER}@127.0.0.1:${restoredPort}/${LAB_DATABASE}`;
    const verify = run(
      "npx",
      ["vitest", "run", "--config", "vitest.storage.config.ts", drillFile],
      {
        env: {
          ...process.env,
          JBM_STORAGE_DATABASE_URL: restoredUrl,
          JBM_RESTORE_DRILL_PHASE: "verify",
          JBM_RESTORE_DRILL_STATE: statePath,
        },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(verify.status, 0, "the restore drill verify phase must pass");
    console.error(
      "ok - restore drill: isolated basebackup restore verified, receipt identical, staged pending drained",
    );
  } finally {
    run("pg_ctl", ["-D", restoreDirectory, "-m", "immediate", "stop"]);
  }
}

async function runFailoverDrill(labDirectory, primaryDataDirectory, primaryPort, primaryUrl) {
  const statePath = join(labDirectory, "failover-drill-state.json");
  const drillFile = "src/production/storage/postgresFailoverDrill.pgtest.ts";
  const prepare = run(
    "npx",
    ["vitest", "run", "--config", "vitest.storage.config.ts", drillFile],
    {
      env: {
        ...process.env,
        JBM_STORAGE_DATABASE_URL: primaryUrl,
        JBM_FAILOVER_DRILL_PHASE: "prepare",
        JBM_FAILOVER_DRILL_STATE: statePath,
      },
      stdio: ["ignore", "inherit", "inherit"],
      encoding: undefined,
    },
  );
  assert.equal(prepare.status, 0, "the failover drill prepare phase must pass");

  const standbyDirectory = join(labDirectory, "standby-data");
  const backup = run("pg_basebackup", [
    "-h",
    "127.0.0.1",
    "-p",
    String(primaryPort),
    "-U",
    LAB_USER,
    "-D",
    standbyDirectory,
    "-X",
    "stream",
    "--checkpoint=fast",
    "-R",
  ]);
  assert.equal(backup.status, 0, `standby pg_basebackup failed: ${backup.stderr}`);
  const standbyPort = await freeLoopbackPort();
  const startStandby = run("pg_ctl", [
    "-D",
    standbyDirectory,
    "-o",
    `-c listen_addresses=127.0.0.1 -c port=${standbyPort} -c unix_socket_directories='' -c fsync=off`,
    "-l",
    join(labDirectory, "standby-postgres.log"),
    "-w",
    "start",
  ]);
  assert.equal(startStandby.status, 0, `standby pg_ctl start failed: ${startStandby.stderr}`);
  const standbyUrl = `postgresql://${LAB_USER}@127.0.0.1:${standbyPort}/${LAB_DATABASE}`;
  try {
    let replicated = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const rows = run("psql", [
        "-X",
        "-q",
        "-tA",
        "-c",
        "SELECT count(*) FROM application_append_acceptances WHERE envelope_id = '6d5609f1-9662-49f6-9cda-9ef319abe51d'",
        standbyUrl,
      ]);
      if (rows.status === 0 && rows.stdout.trim() === "1") {
        replicated = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    assert.ok(replicated, "the standby must replay the primary's committed append");

    // The primary dies without notice; only the streamed WAL survives.
    run("pg_ctl", ["-D", primaryDataDirectory, "-m", "immediate", "stop"]);
    const promote = run("pg_ctl", ["-D", standbyDirectory, "-w", "promote"]);
    assert.equal(promote.status, 0, `standby promotion failed: ${promote.stderr}`);

    const verify = run(
      "npx",
      ["vitest", "run", "--config", "vitest.storage.config.ts", drillFile],
      {
        env: {
          ...process.env,
          JBM_STORAGE_DATABASE_URL: standbyUrl,
          JBM_FAILOVER_DRILL_PHASE: "verify",
          JBM_FAILOVER_DRILL_STATE: statePath,
        },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(verify.status, 0, "the failover drill verify phase must pass");
    console.error(
      "ok - failover drill: streamed standby promoted after primary loss, receipt identical, fresh append continues the chain",
    );
  } finally {
    run("pg_ctl", ["-D", standbyDirectory, "-m", "immediate", "stop"]);
  }
}

async function proveConcurrentMigrationRunners(port) {
  const { spawn } = await import("node:child_process");
  const created = run("createdb", ["-h", "127.0.0.1", "-p", String(port), "-U", LAB_USER, "jbm_storage_lab_race"]);
  assert.equal(created.status, 0, `createdb for the race database failed: ${created.stderr}`);
  const raceUrl = `postgresql://${LAB_USER}@127.0.0.1:${port}/jbm_storage_lab_race`;
  const runnerPath = new URL("./migrate.mjs", import.meta.url).pathname;
  const startRunner = () =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [runnerPath], {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: raceUrl },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("close", (code) => resolve({ code, stderr }));
    });
  const [first, second] = await Promise.all([startRunner(), startRunner()]);
  const exitCodes = [first.code, second.code].sort();
  assert.equal(exitCodes[0], 0, `at least one concurrent runner must succeed: ${first.stderr} ${second.stderr}`);
  if (exitCodes[1] !== 0) {
    assert.match(
      `${first.stderr}${second.stderr}`,
      /duplicate key|failed/,
      "a losing concurrent runner must abort cleanly on the ledger fence",
    );
  }
  const migrations = readMigrationFiles();
  const [[ledgerCount]] = sql(raceUrl, `SELECT count(*) FROM storage_schema_migrations`);
  assert.equal(ledgerCount, String(migrations.length), "the race must apply every migration exactly once");
  const settle = migrateStorage(raceUrl, undefined, () => {});
  assert.equal(settle.applied, 0, "a follow-up run after the race must be a no-op");
  console.error("ok - concurrent migration runners serialize on the ledger fence");
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

    const unregisteredProfile = sql(
      databaseUrl,
      planInsert(
        "00000000-0000-7000-8000-000000000103",
        "00000000-0000-4000-8000-000000000203",
        CREATOR_MEMBER("00000000-0000-7000-8000-000000000103"),
      ).replace(HEX32("52"), HEX32("59")),
      { expectFailure: true },
    );
    assert.match(unregisteredProfile, /conversation_plans_release_profile_fk/);
    const immutableProfile = sql(
      databaseUrl,
      `UPDATE archived_release_profiles SET delivery_limits_canonical = '{"x":1}'::jsonb`,
      { expectFailure: true },
    );
    assert.match(immutableProfile, /immutable/);
    console.error("ok - release profiles are a registry: unregistered pins fail, rows are immutable");

    sql(databaseUrl, CONVERSATION_FIXTURE_SQL);
    sql(databaseUrl, envelopeInsert({}));
    console.error("ok - a canonical application envelope commits");

    const badContentType = sql(
      databaseUrl,
      envelopeInsert({
        position: "3",
        envelopeId: "00000000-0000-4000-8000-000000000403",
        headByte: "a3",
        contentType: "application/vnd.juicebox.messaging.mls-public-message",
      }),
      { expectFailure: true },
    );
    assert.match(badContentType, /envelopes_class_content_type_check/);
    const applicationWithTranscripts = sql(
      databaseUrl,
      envelopeInsert({
        position: "3",
        envelopeId: "00000000-0000-4000-8000-000000000403",
        headByte: "a3",
        transcripts: `${HEX32("b1")}, ${HEX32("b2")}`,
      }),
      { expectFailure: true },
    );
    assert.match(applicationWithTranscripts, /envelopes_transcript_shape_check/);
    const shortSignature = sql(
      databaseUrl,
      envelopeInsert({
        position: "3",
        envelopeId: "00000000-0000-4000-8000-000000000403",
        headByte: "a3",
        signature: "decode(repeat('99', 63), 'hex')",
      }),
      { expectFailure: true },
    );
    assert.match(shortSignature, /envelopes_ed25519_signature_check/);
    const subMillisecondReceipt = sql(
      databaseUrl,
      envelopeInsert({
        position: "3",
        envelopeId: "00000000-0000-4000-8000-000000000403",
        headByte: "a3",
        receivedAt: "timestamptz '2026-08-14 16:20:45.123456+00'",
      }),
      { expectFailure: true },
    );
    assert.match(subMillisecondReceipt, /envelopes_received_at_millisecond_check/);
    const unknownSigningKey = sql(
      databaseUrl,
      envelopeInsert({
        position: "3",
        envelopeId: "00000000-0000-4000-8000-000000000403",
        headByte: "a3",
        signingKeyId: "unregistered-key",
      }),
      { expectFailure: true },
    );
    assert.match(unknownSigningKey, /envelopes_log_signing_key_fk/);
    console.error(
      "ok - envelope class/content-type, transcript shape, signature length, canonical receipt time, and signing-key registry are relational",
    );

    sql(
      databaseUrl,
      `INSERT INTO log_witness_receipts (
         conversation_id, position, head_hash, witness_checkpoint_id,
         witness_tree_size, witness_root_hash, witness_key_id,
         witness_signature, witnessed_at
       ) VALUES (
         '00000000-0000-4000-8000-000000000301', 2, decode(repeat('a2', 32), 'hex'),
         'fictional-witness-checkpoint', 1, decode(repeat('c1', 32), 'hex'),
         'fictional-witness-key', decode(repeat('c2', 64), 'hex'), now()
       )`,
    );
    const forgedWitnessHead = sql(
      databaseUrl,
      `INSERT INTO log_witness_receipts (
         conversation_id, position, head_hash, witness_checkpoint_id,
         witness_tree_size, witness_root_hash, witness_key_id,
         witness_signature, witnessed_at
       ) VALUES (
         '00000000-0000-4000-8000-000000000301', 2, decode(repeat('ff', 32), 'hex'),
         'fictional-witness-checkpoint', 1, decode(repeat('c1', 32), 'hex'),
         'another-fictional-witness-key', decode(repeat('c2', 64), 'hex'), now()
       )`,
      { expectFailure: true },
    );
    assert.match(forgedWitnessHead, /log_witness_receipts_head_identity_fk/);
    console.error("ok - witness receipts bind the exact (conversation, position, head hash) identity");

    const welcomeOnApplication = sql(
      databaseUrl,
      `INSERT INTO mls_welcomes (
         conversation_id, commit_position, target_installation_id,
         commit_envelope_id, welcome_bytes, welcome_sha256, created_at, expires_at
       ) VALUES (
         '00000000-0000-4000-8000-000000000301', 2, '00000000-0000-4000-8000-000000000004',
         '00000000-0000-4000-8000-000000000402', decode('aa', 'hex'),
         decode(repeat('d1', 32), 'hex'), now(), now() + interval '1 day'
       )`,
      { expectFailure: true },
    );
    assert.match(welcomeOnApplication, /mls_welcomes_commit_class_fk/);
    console.error("ok - a Welcome cannot bind to a non-Commit envelope");

    const matrixClause = sql(
      databaseUrl,
      `SELECT pg_get_constraintdef(oid) FROM pg_constraint
       WHERE conname = 'memberships_purpose_role_matrix_check'`,
    );
    assert.match(matrixClause[0][0], /purchase_support/);
    assert.match(matrixClause[0][0], /subscriber/);
    const mutatedPurpose = sql(
      databaseUrl,
      `UPDATE conversations SET delivery_purpose = 'announcement'
       WHERE conversation_id = '00000000-0000-4000-8000-000000000301'`,
      { expectFailure: true },
    );
    assert.match(mutatedPurpose, /immutable/);
    console.error("ok - the purpose-to-role matrix is declared and delivery purpose is immutable");

    sql(
      databaseUrl,
      `INSERT INTO directory_checkpoints (
         checkpoint_id, tree_size, root_hash, signer_key_id, signature, created_at
       ) VALUES (
         '00000000-0000-4000-8000-00000000d001', 1, ${HEX32("d1")},
         'fictional-directory-signer', decode('aa', 'hex'), now()
       );
       INSERT INTO policy_log_checkpoints (
         checkpoint_id, tree_size, root_hash, signer_key_id, signature,
         witness_key_id, witness_signature, created_at
       ) VALUES (
         '00000000-0000-4000-8000-00000000d002', 1, ${HEX32("d2")},
         'fictional-policy-signer', decode('aa', 'hex'),
         'fictional-witness', decode('bb', 'hex'), now()
       );
       INSERT INTO external_sender_credentials (
         external_sender_credential_id, project_ref_id, signer_generation,
         credential_public, credential_fingerprint, not_before, expires_at,
         created_checkpoint_id, witnessed_at, lifecycle_state
       ) VALUES (
         '00000000-0000-4000-8000-00000000d003',
         '00000000-0000-4000-8000-000000000002', 1, decode('cc', 'hex'),
         ${HEX32("d3")}, now() - interval '1 day', now() + interval '30 days',
         '00000000-0000-4000-8000-00000000d002', now(), 'published'
       );
       INSERT INTO policy_head_signing_keys (
         policy_head_signing_key_id, project_ref_id, public_key,
         key_fingerprint, not_before, expires_at, lifecycle_state,
         policy_checkpoint_id
       ) VALUES (
         'fictional-policy-head-signer', '00000000-0000-4000-8000-000000000002',
         decode('dd', 'hex'), ${HEX32("d4")}, now() - interval '1 day',
         now() + interval '30 days', 'active',
         '00000000-0000-4000-8000-00000000d002'
       )`,
    );
    const policyHeadInsert = (headId, count) => `
      INSERT INTO policy_heads (
        policy_head_id, conversation_id, policy_head_sequence,
        previous_policy_head_hash, policy_head_hash, epoch, roster_version,
        roster_hash, confirmed_transcript_hash, delivery_log_position,
        delivery_log_head_hash, evaluation_log_position,
        evaluation_log_head_hash, policy_id, policy_revision, policy_hash,
        mandatory_proposal_count, mandatory_proposal_set_hash,
        authorized_send_grant_set_hash, authorized_quota_policy_digest,
        evaluated_chain_id, evaluated_block, evaluated_block_hash,
        directory_checkpoint_id, policy_log_checkpoint_id,
        active_external_sender_credential_id, active_external_sender_fingerprint,
        active_signer_generation, issued_at, expires_at,
        policy_head_signing_key_id, canonical_signed_body,
        canonical_signed_body_sha256, signature
      ) VALUES (
        '${headId}', '00000000-0000-4000-8000-000000000301',
        (SELECT coalesce(max(policy_head_sequence), 0) + 1 FROM policy_heads),
        ${HEX32("d5")}, decode(md5('${headId}') || md5('${headId}'), 'hex'),
        0, 0, ${HEX32("92")}, ${HEX32("95")}, 0, ${HEX32("d6")}, 0,
        ${HEX32("d7")}, '00000000-0000-4000-8000-00000000d004', 1,
        ${HEX32("d8")}, ${count}, ${HEX32("d9")}, ${HEX32("da")},
        ${HEX32("53")}, 'eip155:8453', 1, ${HEX32("db")},
        '00000000-0000-4000-8000-00000000d001',
        '00000000-0000-4000-8000-00000000d002',
        '00000000-0000-4000-8000-00000000d003', ${HEX32("d3")}, 1,
        now(), now() + interval '4 minutes', 'fictional-policy-head-signer',
        decode('ee', 'hex'), ${HEX32("dc")}, decode('ff', 'hex')
      )`;
    const incompleteHead = sql(
      databaseUrl,
      `BEGIN;
       ${policyHeadInsert("00000000-0000-4000-8000-00000000d101", 1)};
       COMMIT;`,
      { expectFailure: true },
    );
    assert.match(incompleteHead, /mandatory proposal rows/);
    sql(
      databaseUrl,
      `BEGIN;
       ${policyHeadInsert("00000000-0000-4000-8000-00000000d102", 0)};
       COMMIT;`,
    );
    const driftedCount = sql(
      databaseUrl,
      `BEGIN;
       UPDATE policy_heads SET mandatory_proposal_count = 1
       WHERE policy_head_id = '00000000-0000-4000-8000-00000000d102';
       COMMIT;`,
      { expectFailure: true },
    );
    assert.match(driftedCount, /mandatory proposal rows/);
    console.error(
      "ok - a policy head cannot commit unless its mandatory-proposal rows match its declared count",
    );

    await proveConcurrentPositionFencing(databaseUrl);
    await proveConcurrentMigrationRunners(port);

    console.error("Running the PostgreSQL repository suite...");
    const repositorySuite = run(
      "npx",
      [
        "vitest",
        "run",
        "--config",
        "vitest.storage.config.ts",
        "src/production/storage/postgresDeliveryStore.pgtest.ts",
      ],
      {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: databaseUrl },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(
      repositorySuite.status,
      0,
      "the PostgreSQL repository suite must pass",
    );

    console.error("Running the embed context plane suite...");
    const embedSuite = run(
      "npx",
      [
        "vitest",
        "run",
        "--config",
        "vitest.storage.config.ts",
        "src/production/embed/embedContextStore.pgtest.ts",
        "src/production/embed/embedBff.pgtest.ts",
      ],
      {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: databaseUrl },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(embedSuite.status, 0, "the embed context plane suite must pass");

    console.error("Running the device enrollment and session suite...");
    const identitySuite = run(
      "npx",
      [
        "vitest",
        "run",
        "--config",
        "vitest.storage.config.ts",
        "src/production/identity/enrollment.pgtest.ts",
        "src/production/entitlement/eligibility.pgtest.ts",
        "src/production/storage/policyHeadIssuance.pgtest.ts",
        "src/production/storage/cursorNonceAllocator.pgtest.ts",
        "src/production/witness/witnessCore.pgtest.ts",
      ],
      {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: databaseUrl },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(
      identitySuite.status,
      0,
      "the device enrollment and session suite must pass",
    );

    // Runs alone: it flips the shared conversation through membership_pending
    // and must not race any suite that reconstructs the append snapshot.
    console.error("Running the membership intent suite...");
    const membershipSuite = run(
      "npx",
      [
        "vitest",
        "run",
        "--config",
        "vitest.storage.config.ts",
        "src/production/storage/membershipIntent.pgtest.ts",
      ],
      {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: databaseUrl },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(
      membershipSuite.status,
      0,
      "the membership intent suite must pass",
    );

    // Runs alone for the same reason as the membership suite: the full
    // HTTP lifecycle flips the shared conversation through
    // membership_pending and back.
    console.error("Running the messaging HTTP suite...");
    const httpSuite = run(
      "npx",
      [
        "vitest",
        "run",
        "--config",
        "vitest.storage.config.ts",
        "src/production/http/messagingHttp.pgtest.ts",
      ],
      {
        env: { ...process.env, JBM_STORAGE_DATABASE_URL: databaseUrl },
        stdio: ["ignore", "inherit", "inherit"],
        encoding: undefined,
      },
    );
    assert.equal(httpSuite.status, 0, "the messaging HTTP suite must pass");

    await runRestoreDrill(labDirectory, port, databaseUrl);
    await runFailoverDrill(labDirectory, dataDirectory, port, databaseUrl);

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
