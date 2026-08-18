#!/usr/bin/env node
// Idempotently inserts the ADR 0005 chain_finality_profiles rows from the
// checked-in canonical document set. Profile hash = SHA-256 of the
// canonical (JSON.stringify, key order as checked in) document bytes.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import postgres from "postgres";

const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
if (!databaseUrl) {
  console.error("JBM_STORAGE_DATABASE_URL is required.");
  process.exit(1);
}
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const set = JSON.parse(
  readFileSync(join(root, "config", "finality-profiles.v1.json"), "utf8"),
);
if (set.kind !== "jbm-finality-profile-set.v1") {
  console.error("Unexpected profile set kind.");
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 2, onnotice: () => {} });
try {
  let inserted = 0;
  for (const profile of set.profiles) {
    const canonical = JSON.stringify(profile.canonicalDocument);
    const hash = createHash("sha256").update(canonical, "utf8").digest();
    const rows = await sql`
      INSERT INTO chain_finality_profiles (
        finality_profile_id, profile_revision, chain_id, canonical_document,
        profile_hash, adapter_release_id, ratification_evidence_ref, state,
        effective_at, created_at
      ) VALUES (
        ${profile.finalityProfileId}, ${profile.profileRevision},
        ${profile.chainId}, ${canonical}::jsonb, ${hash},
        ${profile.adapterReleaseId}, ${profile.ratificationEvidenceRef},
        'active', now(), now()
      )
      ON CONFLICT (finality_profile_id, profile_revision) DO NOTHING
      RETURNING finality_profile_id`;
    inserted += rows.length;
  }
  console.error(
    `Finality profiles: ${set.profiles.length} declared, ${inserted} newly inserted.`,
  );
} finally {
  await sql.end({ timeout: 5 });
}
