#!/usr/bin/env node
// Applies storage/migrations in order against one explicitly named PostgreSQL
// database. Each migration runs in one transaction that first takes the
// advisory migration lock and records the checksummed version row, so a
// concurrent runner aborts cleanly instead of double-applying DDL. This is a
// migration job for operators and the storage lab; production pods never
// self-migrate (storage-and-retention.md section 10).
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";

const MIGRATIONS_DIRECTORY = new URL("../../storage/migrations/", import.meta.url).pathname;
const LEDGER_TABLE = "storage_schema_migrations";
const ADVISORY_LOCK_KEY = "hashtextextended('juicebox-messaging-storage-migrations', 0)";

export function readMigrationFiles(directory = MIGRATIONS_DIRECTORY) {
  const names = readdirSync(directory)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  if (names.length === 0) {
    throw new Error("No storage migrations were found.");
  }
  return names.map((name, index) => {
    const match = /^(\d{4})_[a-z0-9_]+\.sql$/.exec(name);
    if (!match) {
      throw new Error(`Migration name is not NNNN_snake_case.sql: ${name}`);
    }
    const expected = String(index + 1).padStart(4, "0");
    if (match[1] !== expected) {
      throw new Error(
        `Migration numbering must be monotonic from 0001 with no gaps; expected ${expected}, found ${name}.`,
      );
    }
    const sql = readFileSync(join(directory, name), "utf8");
    return {
      version: match[1],
      name,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    };
  });
}

function runPsql(databaseUrl, args, { input } = {}) {
  const result = spawnSync(
    "psql",
    ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...args, databaseUrl],
    { encoding: "utf8", input },
  );
  if (result.error) {
    throw new Error(`psql could not be executed: ${result.error.message}`);
  }
  return result;
}

function queryCsv(databaseUrl, sql) {
  const result = runPsql(databaseUrl, ["-tA", "-F", "\t", "-c", sql]);
  if (result.status !== 0) {
    throw new Error(`Storage query failed: ${result.stderr.trim()}`);
  }
  return result.stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => line.split("	"));
}

export function migrateStorage(databaseUrl, directory = MIGRATIONS_DIRECTORY, log = console.error) {
  const migrations = readMigrationFiles(directory);
  const ledgerDdl = `CREATE TABLE IF NOT EXISTS ${LEDGER_TABLE} (
    version text PRIMARY KEY,
    checksum_sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  );`;
  const bootstrap = runPsql(databaseUrl, ["-c", ledgerDdl]);
  if (bootstrap.status !== 0) {
    throw new Error(`Migration ledger bootstrap failed: ${bootstrap.stderr.trim()}`);
  }
  const appliedRows = queryCsv(
    databaseUrl,
    `SELECT version, checksum_sha256 FROM ${LEDGER_TABLE} ORDER BY version`,
  );
  const applied = new Map(appliedRows.map(([version, checksum]) => [version, checksum]));
  let appliedCount = 0;
  for (const migration of migrations) {
    const existing = applied.get(migration.version);
    if (existing !== undefined) {
      if (existing !== migration.checksum) {
        throw new Error(
          `Applied migration ${migration.name} does not match its recorded checksum; ` +
            "refusing to continue against a drifted schema history.",
        );
      }
      continue;
    }
    const workDirectory = mkdtempSync(join(tmpdir(), "jbm-storage-migration-"));
    try {
      const wrapped = [
        "BEGIN;",
        `SELECT pg_advisory_xact_lock(${ADVISORY_LOCK_KEY});`,
        `INSERT INTO ${LEDGER_TABLE} (version, checksum_sha256) VALUES ('${migration.version}', '${migration.checksum}');`,
        migration.sql,
        "COMMIT;",
        "",
      ].join("\n");
      const wrappedPath = join(workDirectory, migration.name);
      writeFileSync(wrappedPath, wrapped);
      const result = runPsql(databaseUrl, ["-f", wrappedPath]);
      if (result.status !== 0) {
        throw new Error(`Migration ${migration.name} failed: ${result.stderr.trim()}`);
      }
      appliedCount += 1;
      log(`Applied storage migration ${migration.name}.`);
    } finally {
      rmSync(workDirectory, { recursive: true, force: true });
    }
  }
  return { total: migrations.length, applied: appliedCount };
}

const invokedDirectly =
  process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (invokedDirectly) {
  const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
  if (!databaseUrl) {
    console.error(
      "Set JBM_STORAGE_DATABASE_URL to the exact target database; the migration job never infers one.",
    );
    process.exit(2);
  }
  try {
    const { total, applied } = migrateStorage(databaseUrl);
    console.error(`Storage schema is current: ${total} migrations, ${applied} newly applied.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
