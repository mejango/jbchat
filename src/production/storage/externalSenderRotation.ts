import { Buffer } from "node:buffer";
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import type { Sql } from "postgres";

/**
 * External-sender credential aging per the frozen lifecycle
 * (ADR 0001 item 9 / storage-and-retention.md): at-most-90-day
 * credentials, the staged next generation published at least 30 days
 * before it takes over, a 14-day overlap where both generations are
 * valid, monotonic generations, and a non-rollback generation ledger
 * on project_refs.
 *
 * Provisioning publishes generations 1 (current) and 2 (staged) on day
 * one, so the 30-days-early requirement holds by construction. This
 * pass, driven by the keeper:
 *  - PROMOTES the staged credential to current once the current one is
 *    within the 14-day overlap of its expiry, and stages the next
 *    generation immediately (deterministic keys from the provisioning
 *    seed, same launch-mode boundary as provisioning itself);
 *  - RETIRES published credentials past their expiry.
 * Times come from delivery_db_now(), the durable clock.
 */

const OVERLAP = "14 days";
const LIFETIME = "89 days";

export interface ExternalSenderRotationReport {
  readonly examined: number;
  readonly promoted: number;
  readonly retired: number;
}

function ed25519PublicRaw(seed: Buffer): Buffer {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  return Buffer.from(
    createPublicKey(privateKey).export({ format: "jwk" }).x as string,
    "base64url",
  );
}

export async function rotateExternalSenderCredentials(
  sql: Sql,
  provisioningSeed: Buffer,
): Promise<ExternalSenderRotationReport> {
  const deriveSeed = (purpose: string, scope: string): Buffer =>
    createHmac("sha256", provisioningSeed)
      .update(`${purpose}\n${scope}`, "utf8")
      .digest();
  const stableUuid = (purpose: string, scope: string): string => {
    const bytes = deriveSeed(`uuid:${purpose}`, scope).subarray(0, 16);
    const value = Buffer.from(bytes);
    value[6] = (value[6] & 0x0f) | 0x40;
    value[8] = (value[8] & 0x3f) | 0x80;
    const hexed = value.toString("hex");
    return `${hexed.slice(0, 8)}-${hexed.slice(8, 12)}-${hexed.slice(12, 16)}-${hexed.slice(16, 20)}-${hexed.slice(20)}`;
  };

  const provisions = await sql`
    SELECT project_ref_id, policy_log_checkpoint_id,
           current_external_sender_credential_id,
           staged_external_sender_credential_id
    FROM project_messaging_provisions`;
  let promoted = 0;
  let retired = 0;
  for (const provision of provisions) {
    const projectRefId = String(provision.project_ref_id);
    await sql.begin(async (tx) => {
      // Promote when the current credential has entered its overlap
      // window and the staged credential is still valid to take over.
      const due = await tx`
        SELECT s.external_sender_credential_id AS staged_id,
               s.signer_generation AS staged_generation
        FROM project_messaging_provisions p
        JOIN external_sender_credentials c
          ON c.external_sender_credential_id =
             p.current_external_sender_credential_id
        JOIN external_sender_credentials s
          ON s.external_sender_credential_id =
             p.staged_external_sender_credential_id
        WHERE p.project_ref_id = ${projectRefId}
          AND c.expires_at - ${OVERLAP}::interval <= delivery_db_now()
          AND s.lifecycle_state = 'published'
          AND s.expires_at > delivery_db_now()
        FOR UPDATE OF p`;
      if (due.length === 1) {
        const stagedId = String(due[0].staged_id);
        const nextGeneration = Number(due[0].staged_generation) + 1;
        const nextId = stableUuid(
          `external-sender-gen-${nextGeneration}`,
          projectRefId,
        );
        const publicRaw = ed25519PublicRaw(
          deriveSeed(`external-sender-gen-${nextGeneration}`, projectRefId),
        );
        await tx`
          INSERT INTO external_sender_credentials (
            external_sender_credential_id, project_ref_id, signer_generation,
            credential_public, credential_fingerprint, not_before, expires_at,
            created_checkpoint_id, witnessed_at, lifecycle_state
          ) VALUES (
            ${nextId}, ${projectRefId}, ${nextGeneration}, ${publicRaw},
            ${createHash("sha256")
              .update("jb-msg-external-sender-fingerprint/v1", "utf8")
              .update(publicRaw)
              .digest()},
            delivery_db_now(), delivery_db_now() + ${LIFETIME}::interval,
            ${String(provision.policy_log_checkpoint_id)},
            delivery_db_now(), 'published'
          ) ON CONFLICT DO NOTHING`;
        await tx`
          UPDATE project_messaging_provisions SET
            current_external_sender_credential_id = ${stagedId},
            staged_external_sender_credential_id = ${nextId}
          WHERE project_ref_id = ${projectRefId}`;
        // Non-rollback generation ledger: only ever moves forward.
        await tx`
          UPDATE project_refs SET
            last_signer_generation =
              GREATEST(last_signer_generation, ${nextGeneration})
          WHERE project_ref_id = ${projectRefId}`;
        promoted += 1;
      }
      const expired = await tx`
        UPDATE external_sender_credentials SET
          lifecycle_state = 'retired', retired_at = delivery_db_now()
        WHERE project_ref_id = ${projectRefId}
          AND lifecycle_state = 'published'
          AND expires_at <= delivery_db_now()
        RETURNING external_sender_credential_id`;
      retired += expired.length;
    });
  }
  return Object.freeze({
    examined: provisions.length,
    promoted,
    retired,
  });
}
