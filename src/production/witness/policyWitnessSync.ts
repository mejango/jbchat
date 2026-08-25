import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Sql } from "postgres";
import type { ChainExtensionResult } from "./witnessCore";
import { refreshCustodySnapshotDigest } from "../storage/postgresDeliveryStore";
import { renewExpiringPolicyHeads } from "./policyHeadRenewal";

export interface PolicyWitnessSubmitPort {
  readonly submitChain: (submission: {
    readonly namespace: "policy";
    readonly checkpointId: string;
    readonly treeSize: string;
    readonly rootHash: string;
    readonly previousCheckpointId: string | null;
    readonly signerKeyId: string;
  }) => Promise<ChainExtensionResult>;
}

export interface PolicyWitnessSyncReport {
  /** Heads re-issued for freshness before this pass submitted. */
  readonly renewed: number;
  readonly submitted: number;
  readonly witnessed: number;
  readonly headsVerified: number;
  readonly blocked: string | null;
}

/**
 * Drives the policy log through the witness: every unwitnessed checkpoint
 * is submitted in tree-size order to the policy namespace; a cosigned
 * receipt marks the checkpoint witnessed and flips every policy-head
 * anchor covered by that tree size from witness_state 'missing' to
 * 'verified' - the moment the append lane opens for those conversations.
 * Anchor witness fields are custody-fenced, so every affected
 * conversation's sender fences refresh in the same transaction. An
 * equivocation from the witness stops the sync verbatim: it is the SEV-0
 * trigger.
 */
export async function runPolicyWitnessSync(
  sql: Sql,
  port: PolicyWitnessSubmitPort,
  options: { readonly provisioningSeed?: Buffer | null } = {},
): Promise<PolicyWitnessSyncReport> {
  // Freshness renewal first, so the renewed heads' checkpoints are
  // submitted and cosigned in this same pass.
  const renewed = options.provisioningSeed
    ? (
        await renewExpiringPolicyHeads(sql, {
          provisioningSeed: options.provisioningSeed,
        })
      ).renewed
    : 0;
  // The alias is text; ORDER BY must name the bigint column or ten sorts
  // before nine and the witness sees a fork.
  const pending = await sql`
    SELECT checkpoint_id, tree_size::text AS tree_size,
           encode(root_hash, 'base64') AS root_hash, previous_checkpoint_id,
           signer_key_id
    FROM policy_log_checkpoints
    WHERE signer_key_id = 'jbm-policy-log-2026q3'
      AND witness_key_id = 'jbm-witness-pending'
    ORDER BY policy_log_checkpoints.tree_size
    LIMIT 100`;
  let witnessed = 0;
  let headsVerified = 0;
  for (const row of pending) {
    const result = await port.submitChain({
      namespace: "policy",
      checkpointId: String(row.checkpoint_id),
      treeSize: String(row.tree_size),
      rootHash: Buffer.from(String(row.root_hash).replace(/\s/g, ""), "base64")
        .toString("base64url"),
      previousCheckpointId:
        row.previous_checkpoint_id === null
          ? null
          : String(row.previous_checkpoint_id),
      signerKeyId: String(row.signer_key_id),
    });
    if (result.status !== "witnessed") {
      return Object.freeze({
        renewed,
        submitted: pending.length,
        witnessed,
        headsVerified,
        blocked:
          result.status === "equivocation"
            ? `SEV-0 EQUIVOCATION expectedPrev=${result.expectedPreviousCheckpointId} submittedPrev=${result.submittedPreviousCheckpointId}`
            : `rejected:${result.reasonCode}`,
      });
    }
    const receipt = result.receipt;
    await sql.begin(async (tx) => {
      await tx`
        UPDATE policy_log_checkpoints SET
          witness_key_id = ${receipt.witnessKeyId},
          witness_signature = ${Buffer.from(
            receipt.witnessSignature,
            "base64url",
          )}
        WHERE checkpoint_id = ${String(row.checkpoint_id)}`;
      const coveredHeads = await tx`
        SELECT l.policy_head_id, l.head_hash, a.conversation_id
        FROM policy_log_leaves l
        JOIN delivery_policy_head_anchors a
          ON a.policy_head_id = l.policy_head_id
        WHERE l.leaf_index < ${Number(row.tree_size)}
          AND a.witness_state = 'missing'`;
      for (const head of coveredHeads) {
        await tx`
          UPDATE delivery_policy_head_anchors SET
            witness_state = 'verified',
            witness_checkpoint_id = ${receipt.checkpointId},
            witnessed_policy_head_hash = ${Buffer.from(
              head.head_hash as Uint8Array,
            )},
            witness_evidence_digest = ${createHash("sha256")
              .update("jb-msg-policy-witness-evidence/v1", "utf8")
              .update(receipt.checkpointId, "utf8")
              .update(Buffer.from(head.head_hash as Uint8Array))
              .digest()},
            updated_at = now()
          WHERE policy_head_id = ${String(head.policy_head_id)}`;
        await refreshCustodySnapshotDigest(
          tx,
          String(head.conversation_id),
        );
        headsVerified += 1;
      }
    });
    witnessed += 1;
  }
  return Object.freeze({
    renewed,
    submitted: pending.length,
    witnessed,
    headsVerified,
    blocked: null,
  });
}
