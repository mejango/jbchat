#!/usr/bin/env node
// Registers a delivery submitter's PUBLIC key in the witness database so
// the witness can verify checkpoint signatures. The witness never holds
// the delivery signing seed. Idempotent; refuses to repoint a key ID.
// Env: JBM_WITNESS_DATABASE_URL, JBM_SUBMITTER_KEY_ID,
//      JBM_SUBMITTER_PUBLIC_KEY (32 bytes base64url).
import postgres from "postgres";

const databaseUrl = process.env.JBM_WITNESS_DATABASE_URL;
const keyId = process.env.JBM_SUBMITTER_KEY_ID;
const publicKeyRaw = process.env.JBM_SUBMITTER_PUBLIC_KEY;
if (!databaseUrl || !keyId || !publicKeyRaw) {
  console.error(
    "JBM_WITNESS_DATABASE_URL, JBM_SUBMITTER_KEY_ID, and JBM_SUBMITTER_PUBLIC_KEY are required.",
  );
  process.exit(1);
}
const publicKey = Buffer.from(publicKeyRaw, "base64url");
if (publicKey.byteLength !== 32) {
  console.error("JBM_SUBMITTER_PUBLIC_KEY must decode to 32 bytes.");
  process.exit(1);
}
const sql = postgres(databaseUrl, { max: 1, onnotice: () => {} });
try {
  const existing = await sql`
    SELECT public_key FROM witness_submitter_keys WHERE key_id = ${keyId}`;
  if (existing.length === 1) {
    if (!Buffer.from(existing[0].public_key).equals(publicKey)) {
      console.error(`Submitter key ${keyId} exists with a DIFFERENT public key; refusing.`);
      process.exit(1);
    }
    console.error(`Submitter key ${keyId} already registered.`);
  } else {
    await sql`
      INSERT INTO witness_submitter_keys (key_id, public_key, valid_from, valid_until)
      VALUES (${keyId}, ${publicKey}, now(), now() + interval '365 days')`;
    console.error(`Registered submitter key ${keyId}.`);
  }
} finally {
  await sql.end({ timeout: 5 });
}
