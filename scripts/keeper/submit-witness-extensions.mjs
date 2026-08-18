#!/usr/bin/env node
// Delivery-to-witness submission pipeline: every envelope's signed log
// checkpoint that has no stored receipt from the configured witness key
// is POSTed to the witness /v1/witness/extensions in strict
// per-conversation position order (the witness enforces exactly-next
// continuity). A witnessed receipt is stored in log_witness_receipts; an
// equivocation is logged as SEV-0 and blocks that conversation. This is
// the self-contained JS mirror of src/production/witness/submitter.ts,
// which the storage lab proves against the real witness core.
// Env: JBM_STORAGE_DATABASE_URL, JBM_WITNESS_URL,
//      JBM_WITNESS_SUBMIT_TOKEN, JBM_WITNESS_COSIGN_KEY_ID,
//      optional JBM_KEEPER_LOOP_SECONDS.
import postgres from "postgres";

const databaseUrl = process.env.JBM_STORAGE_DATABASE_URL;
const witnessUrl = process.env.JBM_WITNESS_URL;
const submitToken = process.env.JBM_WITNESS_SUBMIT_TOKEN;
const witnessKeyId = process.env.JBM_WITNESS_COSIGN_KEY_ID;
if (!databaseUrl || !witnessUrl || !submitToken || !witnessKeyId) {
  console.error(
    "JBM_STORAGE_DATABASE_URL, JBM_WITNESS_URL, JBM_WITNESS_SUBMIT_TOKEN, and JBM_WITNESS_COSIGN_KEY_ID are required.",
  );
  process.exit(1);
}
const loopSeconds = Number(process.env.JBM_KEEPER_LOOP_SECONDS ?? "0");
const sql = postgres(databaseUrl, { max: 2, onnotice: () => {} });

const b64url = (value) =>
  Buffer.from(String(value).replace(/\s/g, ""), "base64").toString("base64url");

async function pass() {
  const rows = await sql`
    SELECT e.conversation_id, e.position,
           encode(e.previous_head_hash, 'base64') AS previous_head_hash,
           encode(e.head_hash, 'base64') AS head_hash,
           e.log_signing_key_id,
           encode(e.log_head_signature, 'base64') AS log_head_signature,
           e.received_at
    FROM envelopes e
    WHERE NOT EXISTS (
      SELECT 1 FROM log_witness_receipts r
      WHERE r.conversation_id = e.conversation_id
        AND r.position = e.position
        AND r.witness_key_id = ${witnessKeyId}
    )
    ORDER BY e.conversation_id, e.position
    LIMIT 200`;
  let witnessed = 0;
  const blocked = new Set();
  for (const row of rows) {
    const conversationId = String(row.conversation_id);
    if (blocked.has(conversationId)) continue;
    const submission = {
      namespace: "delivery",
      conversationId,
      position: String(row.position),
      previousHeadHash: b64url(row.previous_head_hash),
      headHash: b64url(row.head_hash),
      signingKeyId: String(row.log_signing_key_id),
      signature: b64url(row.log_head_signature),
      checkpointReceivedAt: new Date(row.received_at).toISOString(),
    };
    const response = await fetch(`${witnessUrl}/v1/witness/extensions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${submitToken}`,
      },
      body: JSON.stringify(submission),
      signal: AbortSignal.timeout(15000),
    });
    const result = await response.json().catch(() => null);
    if (!result || result.status !== "witnessed") {
      blocked.add(conversationId);
      const outcome =
        result?.status === "equivocation"
          ? `SEV-0 EQUIVOCATION witnessed=${result.witnessedHeadHash} submitted=${result.submittedHeadHash}`
          : `rejected ${result?.reasonCode ?? response.status}`;
      console.error(
        `Witness blocked ${conversationId}@${submission.position}: ${outcome}`,
      );
      continue;
    }
    const receipt = result.receipt;
    await sql`
      INSERT INTO log_witness_receipts (
        conversation_id, position, head_hash, witness_checkpoint_id,
        witness_tree_size, witness_root_hash, witness_key_id,
        witness_signature, witnessed_at
      ) VALUES (
        ${conversationId}, ${submission.position},
        ${Buffer.from(submission.headHash, "base64url")},
        ${receipt.checkpointId}, ${receipt.treeSize},
        ${Buffer.from(receipt.rootHash, "base64url")},
        ${receipt.witnessKeyId},
        ${Buffer.from(receipt.witnessSignature, "base64url")},
        ${receipt.witnessedAt}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    witnessed += 1;
  }
  console.error(
    `Witness submission: ${rows.length} considered, ${witnessed} witnessed, ${blocked.size} conversations blocked.`,
  );
}

try {
  if (loopSeconds > 0) {
    for (;;) {
      try {
        await pass();
      } catch (error) {
        console.error("Submission pass failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, loopSeconds * 1000));
    }
  } else {
    await pass();
  }
} finally {
  await sql.end({ timeout: 5 });
}
