import { Buffer } from "node:buffer";
import type { Sql } from "postgres";
import {
  issueConversationPolicyHead,
  readProjectProvision,
  type GrantMaterial,
} from "../storage/appendAuthority";
import { refreshCustodySnapshotDigest } from "../storage/postgresDeliveryStore";

/** Heads are issued with five minutes of freshness; renew inside this. */
export const POLICY_HEAD_RENEWAL_MARGIN_MILLISECONDS = 2 * 60 * 1_000;

/**
 * Freshness renewal (architecture.md: "a stable group receives new head
 * IDs as freshness is renewed"). Every verified anchor whose head is the
 * conversation's current one and expires within the margin is re-issued
 * at sequence N+1 over the SAME send-grant set: the anchor drops to
 * witness_state='missing' and the caller (the policy-witness sync, which
 * the keeper drives every 15 s) submits and cosigns the new checkpoint in
 * the same pass, so the closed window is one sync tick. Without a witness
 * the lane stays closed - INV-MLS-003, not an outage to paper over.
 */
export async function renewExpiringPolicyHeads(
  sql: Sql,
  input: {
    readonly provisioningSeed: Buffer;
    readonly marginMilliseconds?: number;
  },
): Promise<{ renewed: number; skipped: number }> {
  const margin =
    input.marginMilliseconds ?? POLICY_HEAD_RENEWAL_MARGIN_MILLISECONDS;
  const due = await sql`
    SELECT a.conversation_id
    FROM delivery_policy_head_anchors a
    JOIN conversations c ON c.conversation_id = a.conversation_id
    WHERE a.witness_state = 'verified'
      AND a.policy_head_hash = c.current_policy_head_hash
      AND c.state = 'active'
      AND a.expires_at <= delivery_db_now() + make_interval(secs => ${margin / 1_000})
    ORDER BY a.expires_at
    LIMIT 100`;
  let renewed = 0;
  let skipped = 0;
  for (const row of due) {
    const conversationId = String(row.conversation_id);
    // One conversation that cannot renew (signer mismatch, missing
    // provision) stays closed on its own; it never blocks the others.
    const outcome = await sql.begin(async (tx) => {
      const nowRows = await tx`SELECT delivery_db_now() AS db_now`;
      const now = new Date(nowRows[0].db_now as Date).toISOString();
      const conversations = await tx`
        SELECT * FROM conversations
        WHERE conversation_id = ${conversationId} FOR UPDATE`;
      const conversation = conversations[0];
      const anchors = await tx`
        SELECT policy_head_hash, witness_state, expires_at
        FROM delivery_policy_head_anchors
        WHERE conversation_id = ${conversationId} FOR UPDATE`;
      // Re-check under the lock: a concurrent commit may have moved on.
      if (
        anchors.length !== 1 ||
        String(conversation.state) !== "active" ||
        String(anchors[0].witness_state) !== "verified" ||
        !Buffer.from(anchors[0].policy_head_hash as Uint8Array).equals(
          Buffer.from(conversation.current_policy_head_hash as Uint8Array),
        ) ||
        Date.parse(new Date(anchors[0].expires_at as Date).toISOString()) >
          Date.parse(now) + margin
      ) {
        return "skipped" as const;
      }
      const projectRefId = String(conversation.project_ref_id);
      const provision = await readProjectProvision(tx, projectRefId);
      if (!provision) return "skipped" as const;
      const grantRows = await tx`
        SELECT installation_id, credential_id, role,
               role_credential_fingerprint,
               role_credential_subject_account_id,
               role_credential_valid_from, role_credential_valid_until,
               expires_at
        FROM conversation_send_grants
        WHERE conversation_id = ${conversationId} AND state = 'active'
        ORDER BY installation_id`;
      if (grantRows.length === 0) return "skipped" as const;
      const grants: GrantMaterial[] = grantRows.map((grant) => ({
        installationId: String(grant.installation_id),
        accountId: String(grant.role_credential_subject_account_id),
        credentialId: String(grant.credential_id),
        role: String(grant.role),
        credentialFingerprint: Buffer.from(
          grant.role_credential_fingerprint as Uint8Array,
        ).toString("base64url"),
        validFrom: new Date(
          grant.role_credential_valid_from as Date,
        ).toISOString(),
        validUntil: new Date(
          grant.role_credential_valid_until as Date,
        ).toISOString(),
        expiresAt: new Date(grant.expires_at as Date).toISOString(),
      }));
      const issued = await issueConversationPolicyHead(tx, {
        provisioningSeed: input.provisioningSeed,
        conversationId,
        projectRefId,
        provision,
        conversationKind: String(conversation.delivery_purpose),
        conversationGeneration: String(conversation.generation),
        quotaPolicyDigest: Buffer.from(
          conversation.quota_policy_digest as Uint8Array,
        ),
        grants,
        selectedInstallationId: grants[0].installationId,
        anchor: { mode: "update" },
        now,
      });
      if (issued.status !== "issued") return "skipped" as const;
      await tx`
        INSERT INTO conversation_policy_transitions (
          conversation_id, policy_head_sequence, policy_head_id,
          policy_head_hash, effective_from_position, created_at
        ) VALUES (
          ${conversationId}, ${issued.policyHeadSequence},
          ${issued.policyHeadId},
          ${Buffer.from(issued.policyHeadHash, "base64url")},
          ${String(BigInt(String(conversation.last_position)) + 1n)},
          ${now}::timestamptz
        ) ON CONFLICT DO NOTHING`;
      await refreshCustodySnapshotDigest(tx, conversationId);
      return "renewed" as const;
    }).catch((error: unknown) => {
      console.error(
        `policy head renewal skipped ${conversationId}: ${String(error)}`,
      );
      return "skipped" as const;
    });
    if (outcome === "renewed") renewed += 1;
    else skipped += 1;
  }
  return { renewed, skipped };
}
