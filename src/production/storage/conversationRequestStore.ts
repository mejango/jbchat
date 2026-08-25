import { randomUUID } from "node:crypto";
import type { Sql } from "postgres";

/**
 * Queued chat requests. A paid customer lodges a request against a project
 * before any project staff has enrolled; it sits pending until an owner
 * attends. No message content is queued — only the request — so nothing
 * crosses the end-to-end boundary. The owner's accept (a later step) runs
 * the MLS activation and sets conversation_id.
 */

export interface ConversationRequestStoreContext {
  readonly sql: Sql;
  readonly hmacEligibilityClaimHandle: (handle: string) => Buffer;
  readonly hmacEligibilitySubject: (caip10: string) => Buffer;
  readonly now: () => string;
}

export type CreateRequestResult =
  | {
      readonly status: "created" | "already_pending";
      readonly requestId: string;
      readonly projectRefId: string;
    }
  | { readonly status: "refused"; readonly reasonCode: string };

export interface OwnerQueueItem {
  readonly requestId: string;
  readonly projectRefId: string;
  readonly chainId: string;
  readonly projectId: string;
  readonly requesterAccountId: string;
  readonly requesterWallet: string | null;
  readonly createdAt: string;
}

export interface ConversationRequestStore {
  readonly createRequest: (input: {
    requesterAccountId: string;
    requesterInstallationId: string;
    eligibilityClaimHandle: string;
    requesterWalletRef?: string;
  }) => Promise<CreateRequestResult>;
  readonly listForOwnerInstallation: (
    installationId: string,
  ) => Promise<readonly OwnerQueueItem[]>;
}

export function createConversationRequestStore(
  context: ConversationRequestStoreContext,
): ConversationRequestStore {
  const { sql } = context;

  return Object.freeze({
    async createRequest(input: {
      requesterAccountId: string;
      requesterInstallationId: string;
      eligibilityClaimHandle: string;
      requesterWalletRef?: string;
    }): Promise<CreateRequestResult> {
      const now = context.now();
      return sql.begin(async (tx) => {
        const grants = await tx`
          SELECT grant_id, project_ref_id, account_id, installation_id,
                 capability, state, valid_until, subject_hash
          FROM eligibility_grants
          WHERE claim_handle_hash =
                ${context.hmacEligibilityClaimHandle(input.eligibilityClaimHandle)}
          FOR UPDATE`;
        if (
          grants.length !== 1 ||
          String(grants[0].state) !== "active" ||
          new Date(grants[0].valid_until as Date).toISOString() <= now ||
          String(grants[0].account_id) !== input.requesterAccountId ||
          !["purchase-support", "item-set-buyer"].includes(
            String(grants[0].capability),
          )
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "grant_invalid",
          });
        }
        const projectRefId = String(grants[0].project_ref_id);
        const grantId = String(grants[0].grant_id);
        // The requester's wallet is stored for the owner's queue only when
        // it HMAC-matches the grant's subject — i.e. it is the wallet that
        // verifiably paid. A mismatch or absence just stores nothing.
        let requesterWallet: string | null = null;
        if (typeof input.requesterWalletRef === "string") {
          const given = context.hmacEligibilitySubject(
            input.requesterWalletRef.toLowerCase(),
          );
          const expected = Buffer.from(grants[0].subject_hash as Uint8Array);
          if (given.length === expected.length && given.equals(expected)) {
            requesterWallet = input.requesterWalletRef.toLowerCase();
          }
        }

        const requester = await tx`
          SELECT installation_id FROM installations
          WHERE installation_id = ${input.requesterInstallationId}
            AND account_id = ${input.requesterAccountId}
            AND status = 'active'`;
        if (requester.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "requester_not_active",
          });
        }

        // A live conversation already exists for this customer/project?
        const active = await tx`
          SELECT active_conversation_id FROM relationships
          WHERE project_ref_id = ${projectRefId}
            AND customer_account_id = ${input.requesterAccountId}
            AND state = 'active'
            AND active_conversation_id IS NOT NULL`;
        if (active.length === 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "conversation_exists",
          });
        }

        // One pending request per (project, requester); reuse if present.
        const existing = await tx`
          SELECT request_id FROM conversation_requests
          WHERE project_ref_id = ${projectRefId}
            AND requester_account_id = ${input.requesterAccountId}
            AND status = 'pending'`;
        if (existing.length === 1) {
          return Object.freeze({
            status: "already_pending" as const,
            requestId: String(existing[0].request_id),
            projectRefId,
          });
        }

        const requestId = randomUUID();
        await tx`
          INSERT INTO conversation_requests (
            request_id, project_ref_id, requester_account_id,
            requester_installation_id, eligibility_grant_id, status,
            requester_wallet, created_at
          ) VALUES (
            ${requestId}, ${projectRefId}, ${input.requesterAccountId},
            ${input.requesterInstallationId}, ${grantId}, 'pending',
            ${requesterWallet}, ${now}::timestamptz
          )`;
        return Object.freeze({
          status: "created" as const,
          requestId,
          projectRefId,
        });
      });
    },

    async listForOwnerInstallation(
      installationId: string,
    ): Promise<readonly OwnerQueueItem[]> {
      const rows = await sql`
        SELECT r.request_id, r.project_ref_id, r.requester_account_id,
               r.requester_wallet, r.created_at, p.chain_id, p.project_id
        FROM project_staff_registrations s
        JOIN conversation_requests r
          ON r.project_ref_id = s.project_ref_id AND r.status = 'pending'
        JOIN project_refs p ON p.project_ref_id = r.project_ref_id
        WHERE s.installation_id = ${installationId}
          AND s.state = 'active'
          AND NOT EXISTS (
            SELECT 1 FROM relationships rel
            WHERE rel.project_ref_id = r.project_ref_id
              AND rel.customer_account_id = r.requester_account_id
              AND rel.state = 'active'
              AND rel.active_conversation_id IS NOT NULL
          )
        ORDER BY r.created_at DESC
        LIMIT 200`;
      return rows.map((row) => ({
        requestId: String(row.request_id),
        projectRefId: String(row.project_ref_id),
        chainId: String(row.chain_id),
        projectId: String(row.project_id),
        requesterAccountId: String(row.requester_account_id),
        requesterWallet:
          row.requester_wallet === null ? null : String(row.requester_wallet),
        createdAt: new Date(row.created_at as Date).toISOString(),
      }));
    },
  });
}
