#!/usr/bin/env node
// Web Push wakeup sender (service-api.md section 14): whenever new
// mailbox entries land, each affected installation's active webpush
// endpoints receive an EMPTY, payload-free push - no conversation IDs,
// senders, previews, or counts ever ride a push. Push means "poll your
// mailbox". Endpoint configurations are sealed at rest with the identity
// seal key (mirrors identityKeyedCrypto: HMAC-derived AES-256-GCM,
// iv||tag||ciphertext, version keyed-lab-v1). VAPID uses ES256 over the
// endpoint origin with the deployment's P-256 key.
// Env: JBM_STORAGE_DATABASE_URL, JBM_IDENTITY_SECRET,
//      JBM_VAPID_PRIVATE_KEY (32-byte base64url P-256 scalar),
//      JBM_VAPID_SUBJECT (mailto:), optional JBM_KEEPER_LOOP_SECONDS.
import {
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as signNode,
} from "node:crypto";
import postgres from "postgres";

const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
const identitySecretRaw = process.env.JBM_IDENTITY_SECRET;
const vapidPrivateRaw = process.env.JBM_VAPID_PRIVATE_KEY;
const vapidSubject = process.env.JBM_VAPID_SUBJECT ?? "mailto:ops@juicebox.money";
if (!databaseUrl || !identitySecretRaw || !vapidPrivateRaw) {
  console.error(
    "JBM_STORAGE_DATABASE_URL, JBM_IDENTITY_SECRET, and JBM_VAPID_PRIVATE_KEY are required.",
  );
  process.exit(1);
}
const loopSeconds = Number(process.env.JBM_KEEPER_LOOP_SECONDS ?? "0");
const sql = postgres(databaseUrl, { max: 2, onnotice: () => {} });
const sealKey = createHmac(
  "sha256",
  Buffer.from(identitySecretRaw, "base64url"),
)
  .update("jbm-identity-payload-seal-key/v1")
  .digest();

const vapidScalar = Buffer.from(vapidPrivateRaw, "base64url");
const vapidPrivateKey = (() => {
  // SEC1 EC private key DER for P-256 with embedded scalar.
  const der = Buffer.concat([
    Buffer.from("30310201010420", "hex"),
    vapidScalar,
    Buffer.from("a00a06082a8648ce3d030107", "hex"),
  ]);
  return createPrivateKey({ key: der, format: "der", type: "sec1" });
})();
const vapidPublicUncompressed = (() => {
  const jwk = createPublicKey(vapidPrivateKey).export({ format: "jwk" });
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]).toString("base64url");
})();

function openSealed(ciphertext, version) {
  if (version !== "keyed-lab-v1") throw new Error("Unknown seal version.");
  const iv = ciphertext.subarray(0, 12);
  const tag = ciphertext.subarray(12, 28);
  const sealed = ciphertext.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", sealKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(sealed), decipher.final()]).toString(
    "utf8",
  );
}

function vapidAuthorization(endpointOrigin) {
  const header = Buffer.from(
    JSON.stringify({ typ: "JWT", alg: "ES256" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      aud: endpointOrigin,
      exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
      sub: vapidSubject,
    }),
  ).toString("base64url");
  const signature = signNode("sha256", Buffer.from(`${header}.${payload}`), {
    key: vapidPrivateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  return `vapid t=${header}.${payload}.${signature}, k=${vapidPublicUncompressed}`;
}

let watermark = new Date(Date.now() - 60_000).toISOString();

async function pass() {
  const cutoff = watermark;
  const next = new Date().toISOString();
  const endpoints = await sql`
    SELECT DISTINCT p.endpoint_id, p.encrypted_configuration,
           p.kms_key_version
    FROM mailbox_entries m
    JOIN push_endpoints p ON p.installation_id = m.installation_id
    WHERE m.created_at > ${cutoff}::timestamptz AND p.status = 'active'
    LIMIT 500`;
  let sent = 0;
  for (const row of endpoints) {
    try {
      const configuration = JSON.parse(
        openSealed(
          Buffer.from(row.encrypted_configuration),
          String(row.kms_key_version),
        ),
      );
      const endpoint = new URL(configuration.endpoint);
      const response = await fetch(configuration.endpoint, {
        method: "POST",
        headers: {
          TTL: "60",
          Urgency: "normal",
          Authorization: vapidAuthorization(endpoint.origin),
        },
        signal: AbortSignal.timeout(10_000),
      });
      if (response.ok || response.status === 201) {
        sent += 1;
        await sql`
          UPDATE push_endpoints SET last_success_at = now()
          WHERE endpoint_id = ${String(row.endpoint_id)}`;
      } else if (response.status === 404 || response.status === 410) {
        await sql`
          UPDATE push_endpoints SET status = 'invalid',
            last_failure_at = now()
          WHERE endpoint_id = ${String(row.endpoint_id)}`;
      } else {
        await sql`
          UPDATE push_endpoints SET last_failure_at = now()
          WHERE endpoint_id = ${String(row.endpoint_id)}`;
      }
    } catch {
      await sql`
        UPDATE push_endpoints SET last_failure_at = now()
        WHERE endpoint_id = ${String(row.endpoint_id)}`;
    }
  }
  watermark = next;
  if (endpoints.length > 0) {
    console.error(`Push wakeups: ${endpoints.length} endpoints, ${sent} sent.`);
  }
}

try {
  if (loopSeconds > 0) {
    for (;;) {
      try {
        await pass();
      } catch (error) {
        console.error("Push pass failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, loopSeconds * 1000));
    }
  } else {
    await pass();
  }
} finally {
  await sql.end({ timeout: 5 });
}
