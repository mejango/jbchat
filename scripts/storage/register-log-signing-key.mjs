#!/usr/bin/env node
// Registers the delivery-log signing key derived from
// JBM_DELIVERY_LOG_SIGNING_SEED into delivery_log_signing_keys under
// JBM_DELIVERY_LOG_SIGNING_KEY_ID. Idempotent; refuses to change the
// public key of an existing key ID (rotation is a new key ID).
import { createPrivateKey, createPublicKey } from "node:crypto";
import postgres from "postgres";

const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
const seedRaw = process.env.JBM_DELIVERY_LOG_SIGNING_SEED;
const keyId = process.env.JBM_DELIVERY_LOG_SIGNING_KEY_ID;
if (!databaseUrl || !seedRaw || !keyId) {
  console.error(
    "JBM_STORAGE_DATABASE_URL, JBM_DELIVERY_LOG_SIGNING_SEED, and JBM_DELIVERY_LOG_SIGNING_KEY_ID are required.",
  );
  process.exit(1);
}
const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedRaw, "base64url"),
  ]),
  format: "der",
  type: "pkcs8",
});
const publicRaw = Buffer.from(
  createPublicKey(privateKey).export({ format: "jwk" }).x,
  "base64url",
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => {} });
try {
  const existing = await sql`
    SELECT public_key FROM delivery_log_signing_keys WHERE key_id = ${keyId}`;
  if (existing.length === 1) {
    if (!Buffer.from(existing[0].public_key).equals(publicRaw)) {
      console.error(`Key ID ${keyId} exists with a DIFFERENT public key; refusing.`);
      process.exit(1);
    }
    console.error(`Key ${keyId} already registered.`);
  } else {
    await sql`
      INSERT INTO delivery_log_signing_keys (
        key_id, public_key, state, valid_from, valid_until, created_at
      ) VALUES (
        ${keyId}, ${publicRaw}, 'active', now(),
        now() + interval '365 days', now()
      )`;
    console.error(`Registered delivery log signing key ${keyId}.`);
  }
} finally {
  await sql.end({ timeout: 5 });
}
