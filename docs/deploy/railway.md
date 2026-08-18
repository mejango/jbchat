# Railway deployment (owner decision, 2026-08-18)

DEPLOYED 2026-08-18 via `railway up` from the local tree (GitHub main is
behind local until the owner pushes; do not connect GitHub auto-deploys
before then):
- jbm-delivery → https://app-production-bbdd.up.railway.app
  (project 9fe30c94; migrations applied, ADR 0005 profiles seeded, the
  delivery log signing key registered, every lane configured incl. RPC
  quorum + signed deployment manifest).
- jbm-witness → https://witness-production-3164.up.railway.app
  (project e3354825; witness migrations applied; isolated keys).

Operational facts learned during the first deploy:
- The nixpacks image has no `psql`: set `NIXPACKS_PKGS=postgresql_16` on
  BOTH services or the predeploy migration fails with no surfaced log.
- Set `HOSTNAME=::` on both services - Docker injects the container ID
  as HOSTNAME, the start script's `??=` keeps it, and Next then binds
  the wrong interface (502 from the edge).
- `JUICEBOX_MESSAGING_WEB_SECURITY_MODE=production`,
  `JUICEBOX_MESSAGING_CANONICAL_ORIGIN=<https origin>`, and
  `JUICEBOX_MESSAGING_EMBED_INTEGRATIONS={}` (an OBJECT keyed by
  tenantPublicId, not an array) are required at build time.
- One-time setup after first deploy, via
  `railway ssh --service app "node scripts/storage/seed-finality-profiles.mjs"`
  and `railway ssh --service app "node scripts/storage/register-log-signing-key.mjs"`.
- Second RPC providers: publicnode 403s Node fetch (curl works) - the
  quorum pairs Dwellir with drpc on mainnets/OP-Sepolia/Arb-Sepolia,
  Tenderly gateway on Ethereum Sepolia, and sepolia.base.org on Base
  Sepolia.
- The `keeper` service (jbm-delivery, service e1c6b553) runs
  `node scripts/keeper/run-keeper.mjs`: the ADR 0005 grant recheck on a
  60-second loop and the delivery->witness submission loop every 15
  seconds. Its start command lives in the service instance (set via the
  GraphQL API - railway.json intentionally carries no startCommand so
  per-service commands survive redeploys). The delivery log's PUBLIC key
  is registered in the witness database as submitter
  `jbm-delivery-log-2026q3`; receipts land in log_witness_receipts
  automatically once conversations append.
- Remaining manual: custom domains, connecting GitHub auto-deploys AFTER
  the owner pushes local main, and NEXT_PUBLIC_PARA_API_KEY (Para is
  wired and hidden until a real key lands; the WalletConnect project ID
  is set). NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID and
  JBM_PROVISIONING_SEED are live on the app service; the keeper carries
  JBM_VAPID_PRIVATE_KEY/SUBJECT + JBM_IDENTITY_SECRET for push wakeups.
- If deploys die repeatedly at "scheduling build on Metal builder", the
  assigned regional builder is stuck: move the service's region
  (GraphQL serviceInstanceUpdate multiRegionConfig) and redeploy.


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
  - Eligibility lane (POST /v1/eligibility/purchase-claims):
    `JBM_DEPLOYMENT_MANIFEST_PATH` (the signed envelope produced by
    `node scripts/manifest/build-deployment-manifest.mjs`) +
    `JBM_MANIFEST_SIGNER_PUBLIC_KEY` (32 bytes base64url). The lane also
    needs `JBM_RPC_ENDPOINTS` and the seeded ADR 0005 profile rows
    (`node scripts/storage/seed-finality-profiles.mjs`).
  - Keeper: run `node scripts/keeper/recheck-grants.mjs` on a 60-second
    cadence (Railway cron) with `JBM_STORAGE_DATABASE_URL` +
    `JBM_RPC_ENDPOINTS`; it revokes orphaned-anchor grants, suspends
    chains that lose quorum, and sweeps expired leases.
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
