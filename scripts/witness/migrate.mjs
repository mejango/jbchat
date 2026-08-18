#!/usr/bin/env node
// Applies witness/migrations against the witness service's OWN database.
// Run as the Railway predeploy step for the witness service; the serving
// process never self-migrates.
import process from "node:process";
import { migrateStorage } from "../storage/migrate.mjs";

const WITNESS_MIGRATIONS = new URL("../../witness/migrations/", import.meta.url)
  .pathname;

const databaseUrl = process.env.JBM_WITNESS_DATABASE_URL;
if (!databaseUrl) {
  console.error("JBM_WITNESS_DATABASE_URL is required.");
  process.exit(2);
}
try {
  const { total, applied } = migrateStorage(databaseUrl, WITNESS_MIGRATIONS);
  console.error(
    `Witness schema is current: ${total} migrations, ${applied} newly applied.`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
