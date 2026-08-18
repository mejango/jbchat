# Railway deployment (owner decision, 2026-08-18)

Two Railway PROJECTS from this one repository — separation is the point,
not an inconvenience. The witness must live in its own Railway project
with its own members list, its own PostgreSQL, and its own secrets, so
that handing it to an independent operator later (a hard G3 requirement)
is a membership-and-manifest change, not a migration.

## Project 1 — `jbm-delivery` (the messaging service)

Services:
- **app** — this repo, `npm run build` / `npm start`.
  - Predeploy: `npm run storage:migrate`
  - Env: `JBM_STORAGE_DATABASE_URL` (the project Postgres),
    `JUICEBOX_MESSAGING_EMBED_DATABASE_URL`,
    `JUICEBOX_MESSAGING_EMBED_CONTEXT_SECRET`.
  - Messaging API (/v1 device-enrollments, auth, conversations) — every
    route stays a fail-closed 404 until ALL of these are set:
    `JBM_IDENTITY_SECRET` (32 bytes base64url; keys every identity HMAC
    and token hash), `JBM_DEVICE_CREDENTIAL_SIGNER_KEY_ID` +
    `JBM_DEVICE_CREDENTIAL_SIGNING_SEED` (Ed25519 seed for
    device-credential issuance), `JBM_ALLOWED_CHAIN_IDS`
    (comma-separated CAIP-2, all eight launch chains). Two more lanes
    gate independently: `JBM_DELIVERY_LOG_SIGNING_KEY_ID` +
    `JBM_DELIVERY_LOG_SIGNING_SEED` enable the Commit route (the key ID
    must exist in delivery_log_signing_keys), and `JBM_CURSOR_KEY_ID` +
    `JBM_CURSOR_KEY` enable the conversation-events page route. Note:
    wallet-proof verification stays fail-closed unavailable (503 on
    enrollment completion) until the chain adapters ship — the routes
    exist, but no credential can be issued in production yet.
  - The witness variables are NEVER set here — their absence is what
    keeps every witness route a fail-closed 404 on this deployment.
- **postgres** — Railway PostgreSQL. Acceptance for G2 promotion: rerun
  the storage lab's restore and failover drills against this instance
  (pg_basebackup access or Railway's backup/replica features standing in,
  with the same receipt-identity assertions).

## Project 2 — `jbm-witness` (isolated, transfer-ready)

Services:
- **witness** — this same repo, `npm run build` / `npm start`.
  - Predeploy: `npm run witness:migrate`
  - Env: `JBM_WITNESS_DATABASE_URL` (THIS project's Postgres, never the
    delivery one), `JBM_WITNESS_KEY_ID` (e.g. `jbm-witness-2026q3`),
    `JBM_WITNESS_SIGNING_SEED` (32 bytes base64url — generate with
    `node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))'`
    and store nowhere else), `JBM_WITNESS_SUBMIT_TOKEN` (>=32 bytes
    base64url, shared only with the delivery deployment's witness
    submitter). The delivery variables are never set here.
- **postgres** — the witness's own database. The delivery service holds
  no credential for it and vice versa.

Routes active on this deployment: `POST /v1/witness/extensions` (bearer
submit token), `POST /v1/witness/gossip`,
`GET /v1/transparency/checkpoints/{id}`,
`GET /v1/transparency/checkpoints/latest?namespace=`,
`GET /v1/transparency/proofs/consistency?namespace=&from=&to=`.

## Transfer procedure (ADR 0002 item 8)

1. Successor operator creates their own Railway project (or any infra),
   generates a fresh `JBM_WITNESS_KEY_ID` + seed, and stands up the
   service against a copy of the witness database (the log is public
   data; the key is not transferred, ever).
2. Successor cosigns a checkpoint at tree size >= the incumbent's last
   published size with the same root and publishes the consistency proof
   back to the incumbent's last checkpoint.
3. The successor key enters the release trust manifest; both witnesses
   cosign during the overlap window; the incumbent key retires from the
   manifest only after the client-anchor lifetime passes.
4. The owner's access to the successor project is removed; that removal
   is what makes the witness independent for G3.

## Standing rules

- Neither deployment ever holds the other's database URL or keys.
- The witness seed and the delivery signing keys move to a real KMS
  before mainnet launch; Railway env vars are the beta posture only.
- Quarterly drills: split-view (both logs) and witness transfer.
