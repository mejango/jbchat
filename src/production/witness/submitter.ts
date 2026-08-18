import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import type { DeliveryExtensionResult } from "./witnessCore";

const MAX_BATCH = 200;

export interface DeliveryCheckpointSubmission {
  readonly conversationId: string;
  readonly position: string;
  readonly previousHeadHash: string;
  readonly headHash: string;
  readonly signingKeyId: string;
  readonly signature: string;
  readonly checkpointReceivedAt: string;
}

export interface WitnessSubmissionPort {
  readonly submitDelivery: (
    submission: DeliveryCheckpointSubmission,
  ) => Promise<DeliveryExtensionResult>;
}

export interface SubmissionPassReport {
  readonly considered: number;
  readonly witnessed: number;
  readonly blocked: readonly {
    readonly conversationId: string;
    readonly position: string;
    readonly outcome: string;
  }[];
}

/**
 * One pass of the delivery-to-witness submission pipeline: every envelope
 * whose (conversation, position) has no stored receipt from this witness
 * key is submitted in strict per-conversation position order - the
 * witness enforces exactly-next continuity, so a failed position blocks
 * the rest of its conversation and is reported rather than skipped. A
 * witnessed result stores the receipt in log_witness_receipts in the
 * same shape the client transcript verifiers read. An equivocation
 * result is surfaced verbatim: it is the SEV-0 trigger and this pipeline
 * never papers over it.
 */
export async function runDeliverySubmissionPass(
  sql: Sql,
  witnessKeyId: string,
  port: WitnessSubmissionPort,
): Promise<SubmissionPassReport> {
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
    LIMIT ${MAX_BATCH}`;

  let witnessed = 0;
  const blocked: {
    conversationId: string;
    position: string;
    outcome: string;
  }[] = [];
  const blockedConversations = new Set<string>();
  for (const row of rows) {
    const conversationId = String(row.conversation_id);
    if (blockedConversations.has(conversationId)) continue;
    const submission: DeliveryCheckpointSubmission = {
      conversationId,
      position: String(row.position),
      previousHeadHash: fromPgBase64(row.previous_head_hash),
      headHash: fromPgBase64(row.head_hash),
      signingKeyId: String(row.log_signing_key_id),
      signature: fromPgBase64(row.log_head_signature),
      checkpointReceivedAt: new Date(row.received_at as Date).toISOString(),
    };
    const result = await port.submitDelivery(submission);
    if (result.status !== "witnessed") {
      blockedConversations.add(conversationId);
      blocked.push({
        conversationId,
        position: submission.position,
        outcome:
          result.status === "equivocation"
            ? `EQUIVOCATION witnessed=${result.witnessedHeadHash} submitted=${result.submittedHeadHash}`
            : `rejected:${result.reasonCode}`,
      });
      continue;
    }
    await sql`
      INSERT INTO log_witness_receipts (
        conversation_id, position, head_hash, witness_checkpoint_id,
        witness_tree_size, witness_root_hash, witness_key_id,
        witness_signature, witnessed_at
      ) VALUES (
        ${conversationId}, ${submission.position},
        ${Buffer.from(submission.headHash, "base64url")},
        ${result.receipt.checkpointId}, ${result.receipt.treeSize},
        ${Buffer.from(result.receipt.rootHash, "base64url")},
        ${result.receipt.witnessKeyId},
        ${Buffer.from(result.receipt.witnessSignature, "base64url")},
        ${result.receipt.witnessedAt}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    witnessed += 1;
  }
  return Object.freeze({
    considered: rows.length,
    witnessed,
    blocked: Object.freeze(blocked),
  });
}

function fromPgBase64(value: unknown): string {
  return Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
    "base64url",
  );
}
