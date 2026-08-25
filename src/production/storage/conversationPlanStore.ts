import { Buffer } from "node:buffer";
import { createHash, createHmac, randomUUID, sign as signNode, createPrivateKey, createPublicKey } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendQuotaPolicyDigest,
  computeApplicationAppendQuotaScopeHash,
  computeApplicationAppendRecipientSetHash,
  computeConversationSendGrantEvidenceDigest,
  computeDeliveryLimitsDigest,
} from "../delivery/state";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  type EnvelopeLeafInput,
  type DeliveryLogCheckpointInput,
} from "../delivery/hashes";
import { ZERO_HASH32 } from "../delivery/valueObjects";
import { createPolicyHeadIssuanceStore } from "./policyHeadIssuanceStore";
import { leafHash as merkleLeafHash, merkleRoot } from "../witness/merkleLog";
import type { PolicyHeadSignerPort } from "../delivery/policyHeadIssuance";
import type { ExternalProposalSigningPort } from "./externalProposalStore";
import {
  insertPageEndProjectionFromRows,
  refreshCustodySnapshotDigest,
} from "./postgresDeliveryStore";

const PLAN_TTL_MILLISECONDS = 10 * 60 * 1_000;
const SERVICE_TENANT_ID = "00000000-0000-4000-8000-00000000a001";
const SERVICE_REALM_ID = "00000000-0000-4000-8000-00000000a002";
const RELEASE_PROFILE_ID = "delivery-v1-2026q3";
const COMMIT_CONTENT_TYPE =
  "application/vnd.juicebox.messaging.mls-public-message";
const ENVELOPE_RETENTION_MILLISECONDS = 365 * 24 * 60 * 60 * 1_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

// Exactly the reviewed ceilings from delivery/limits.ts - a coherent,
// tested set; a signed deployment may later lower them.
const DELIVERY_LIMITS = Object.freeze({
  applicationCiphertextDecodedMaxBytes: "65536",
  externalProposalDecodedMaxBytes: "262144",
  mlsCommitDecodedMaxBytes: "524288",
  welcomeDecodedMaxBytes: "262144",
  pageDecodedArtifactsMaxBytes: "4194304",
  pageSerializedResponseMaxBytes: "8388608",
  conversationEventsMaxPerPage: "500",
  mailboxEntriesMaxPerPage: "100",
  conversationRecipientInstallationsMax: "2500",
  cursorMaxCharacters: "1024",
  attachmentsMaxPerEnvelope: "10",
});

export interface ConversationPlanStoreContext {
  readonly sql: Sql;
  /** Keys every lazily provisioned per-project signer deterministically. */
  readonly provisioningSeed: Buffer;
  readonly logSigner: ExternalProposalSigningPort;
  readonly logSigningKeyId: string;
  readonly hmacEligibilityClaimHandle: (handle: string) => Buffer;
}

export type PlanCreation =
  | { readonly status: "created"; readonly plan: Record<string, unknown> }
  | {
      readonly status: "reuse_generation";
      readonly conversationId: string;
    }
  | { readonly status: "refused"; readonly reasonCode: string };

export type ActivationResult =
  | {
      readonly status: "activated";
      readonly conversationId: string;
      readonly position: "1";
      readonly headHash: string;
    }
  | { readonly status: "refused"; readonly reasonCode: string };

export interface ConversationPlanStore {
  readonly createPlan: (input: {
    readonly creatorAccountId: string;
    readonly creatorInstallationId: string;
    readonly eligibilityClaimHandle: string;
  }) => Promise<PlanCreation>;
  /**
   * Owner-initiated plan for a queued request: the accepting owner (an
   * active staff installation on the request's project) becomes the MLS
   * group creator and the waiting customer is the welcome target. The
   * returned plan is activated by the OWNER's client, inverting the
   * customer-creates roster; activate() is unchanged.
   */
  readonly acceptRequest: (input: {
    readonly requestId: string;
    readonly ownerAccountId: string;
    readonly ownerInstallationId: string;
  }) => Promise<PlanCreation>;
  readonly activate: (input: unknown, callerInstallationId: string) => Promise<ActivationResult>;
}

/**
 * Purchase-support conversation planning and activation
 * (service-api.md section 6) over the spec tables. Planning resolves the
 * customer's eligibility grant, finds the project's registered support
 * installations, finds or creates the customer relationship, atomically
 * takes one KeyPackage per staff installation (the irreversible boundary),
 * and returns the exact ten-minute roster plan. Activation is one
 * transaction that materializes the ENTIRE append-authority graph the
 * delivery lane reconstructs: conversation, memberships, role credentials,
 * the creator's send grant, an issued signed policy head and its anchor,
 * quota scopes/counters/bindings, usage, roster and recipient projections
 * with ordinals, the position-one Commit envelope chained and signed by
 * the delivery log key, per-target Welcomes, mailbox items, the base
 * page-end projection, and the custody digest fence.
 *
 * Launch-mode boundary stated plainly: per-project external-sender
 * credentials and policy-head signing keys are derived deterministically
 * from the provisioning seed. Their aging lifecycle (90-day cap, staged
 * next generation, 14-day overlap, retirement) runs in
 * externalSenderRotation.ts via the keeper; issued heads are witnessed
 * through the policy-log producer below plus runPolicyWitnessSync; and
 * every member holds a per-sender custody fence, so all members send.
 */
export function createConversationPlanStore(
  context: ConversationPlanStoreContext,
): ConversationPlanStore {
  const { sql } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  const deriveSeed = (purpose: string, scope: string): Buffer =>
    createHmac("sha256", context.provisioningSeed)
      .update(`${purpose}\n${scope}`, "utf8")
      .digest();

  const ed25519 = (seed: Buffer) => {
    const privateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        seed,
      ]),
      format: "der",
      type: "pkcs8",
    });
    const publicRaw = Buffer.from(
      createPublicKey(privateKey).export({ format: "jwk" }).x as string,
      "base64url",
    );
    return { privateKey, publicRaw };
  };

  const stableUuid = (purpose: string, scope: string): string => {
    const bytes = deriveSeed(`uuid:${purpose}`, scope).subarray(0, 16);
    const copy = Buffer.from(bytes);
    copy[6] = (copy[6] & 0x0f) | 0x40;
    copy[8] = (copy[8] & 0x3f) | 0x80;
    const hex = copy.toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };

  /** Lazily provisions the service tenant/realm and release profile. */
  const provisionServiceScope = async (tx: TransactionSql, now: string) => {
    await tx`
      INSERT INTO tenants (
        tenant_id, tenant_public_id, status, kms_key_ref, created_at,
        updated_at
      ) VALUES (
        ${SERVICE_TENANT_ID}, 'juicebox-messaging', 'active',
        'jbm-service-tenant-v1', ${now}::timestamptz, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    await tx`
      INSERT INTO delivery_realms (realm_id, tenant_id, created_at)
      VALUES (${SERVICE_REALM_ID}, ${SERVICE_TENANT_ID}, ${now}::timestamptz)
      ON CONFLICT DO NOTHING`;
    const limitsDigest = computeDeliveryLimitsDigest(
      DELIVERY_LIMITS as never,
    );
    await tx`
      INSERT INTO archived_release_profiles (
        release_profile_id, delivery_limits_digest, release_trust_root_digest,
        delivery_limits_canonical, created_at
      ) VALUES (
        ${RELEASE_PROFILE_ID}, ${Buffer.from(limitsDigest, "base64url")},
        ${deriveSeed("release-trust-root", RELEASE_PROFILE_ID)},
        ${JSON.stringify(DELIVERY_LIMITS)}::jsonb, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    return {
      limitsDigest,
      trustRootDigest: deriveSeed("release-trust-root", RELEASE_PROFILE_ID)
        .toString("base64url"),
    };
  };

  /** Lazily provisions per-project signing material and checkpoints. */
  const provisionProject = async (
    tx: TransactionSql,
    projectRefId: string,
    now: string,
  ) => {
    const existing = await tx`
      SELECT * FROM project_messaging_provisions
      WHERE project_ref_id = ${projectRefId}`;
    if (existing.length === 1) return existing[0];

    const policyId = stableUuid("policy", projectRefId);
    await tx`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${policyId}, 1, ${projectRefId},
        ${JSON.stringify({ profile: "project-support-standard-v1" })}::jsonb,
        ${deriveSeed("policy-hash", projectRefId)}, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    const policyLogCheckpointId = stableUuid("policy-log-checkpoint", projectRefId);
    await tx`
      INSERT INTO policy_log_checkpoints (
        checkpoint_id, tree_size, root_hash, signer_key_id, signature,
        witness_key_id, witness_signature, created_at
      ) VALUES (
        ${policyLogCheckpointId}, 0, ${Buffer.alloc(32)},
        'jbm-policy-log-unwitnessed', ${Buffer.alloc(1)},
        'jbm-witness-pending', ${Buffer.alloc(1)}, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;
    const directoryCheckpointId = stableUuid("directory-checkpoint", projectRefId);
    await tx`
      INSERT INTO directory_checkpoints (
        checkpoint_id, tree_size, root_hash, signer_key_id, signature,
        created_at
      ) VALUES (
        ${directoryCheckpointId}, 0, ${Buffer.alloc(32)},
        'jbm-directory-unwitnessed', ${Buffer.alloc(1)}, ${now}::timestamptz
      ) ON CONFLICT DO NOTHING`;

    const currentSenderId = stableUuid("external-sender-current", projectRefId);
    const stagedSenderId = stableUuid("external-sender-staged", projectRefId);
    for (const [senderId, generation, purpose] of [
      [currentSenderId, 1, "external-sender-current"],
      [stagedSenderId, 2, "external-sender-staged"],
    ] as const) {
      const keys = ed25519(deriveSeed(purpose, projectRefId));
      await tx`
        INSERT INTO external_sender_credentials (
          external_sender_credential_id, project_ref_id, signer_generation,
          credential_public, credential_fingerprint, not_before, expires_at,
          created_checkpoint_id, witnessed_at, lifecycle_state
        ) VALUES (
          ${senderId}, ${projectRefId}, ${generation}, ${keys.publicRaw},
          ${createHash("sha256")
            .update("jb-msg-external-sender-fingerprint/v1", "utf8")
            .update(keys.publicRaw)
            .digest()},
          ${now}::timestamptz, ${now}::timestamptz + interval '89 days',
          ${policyLogCheckpointId}, ${now}::timestamptz, 'published'
        ) ON CONFLICT DO NOTHING`;
    }

    // An earlier suite or deployment may already hold this project's
    // generation slots (UNIQUE(project_ref_id, signer_generation)); adopt
    // whatever credential actually occupies each generation.
    const adopted = await tx`
      SELECT external_sender_credential_id, signer_generation
      FROM external_sender_credentials
      WHERE project_ref_id = ${projectRefId}
        AND signer_generation IN (1, 2)`;
    const adoptedByGeneration = new Map(
      adopted.map((row) => [
        Number(row.signer_generation),
        String(row.external_sender_credential_id),
      ]),
    );
    const effectiveCurrentId = adoptedByGeneration.get(1) ?? currentSenderId;
    const effectiveStagedId = adoptedByGeneration.get(2) ?? stagedSenderId;

    // The FULL project ref keeps the key id globally unique — an 8-char
    // prefix collides across projects sharing a uuid prefix, and the
    // second project would silently adopt the first's key via the
    // ON CONFLICT DO NOTHING below. Already-provisioned projects keep
    // their stored id: issuance reads it from the provision row.
    const signingKeyId = `jbm-policy-head-${projectRefId}`;
    const headKeys = ed25519(deriveSeed("policy-head-signer", projectRefId));
    await tx`
      INSERT INTO policy_head_signing_keys (
        policy_head_signing_key_id, project_ref_id, public_key,
        key_fingerprint, not_before, expires_at, lifecycle_state,
        policy_checkpoint_id
      ) VALUES (
        ${signingKeyId}, ${projectRefId}, ${headKeys.publicRaw},
        ${createHash("sha256")
          .update("jb-msg-policy-head-key-fingerprint/v1", "utf8")
          .update(headKeys.publicRaw)
          .digest()},
        ${now}::timestamptz, ${now}::timestamptz + interval '365 days',
        'active', ${policyLogCheckpointId}
      ) ON CONFLICT DO NOTHING`;

    await tx`
      INSERT INTO project_messaging_provisions (
        project_ref_id, policy_id, policy_revision, policy_log_checkpoint_id,
        directory_checkpoint_id, current_external_sender_credential_id,
        staged_external_sender_credential_id, policy_head_signing_key_id,
        provisioned_at
      ) VALUES (
        ${projectRefId}, ${policyId}, 1, ${policyLogCheckpointId},
        ${directoryCheckpointId}, ${effectiveCurrentId}, ${effectiveStagedId},
        ${signingKeyId}, ${now}::timestamptz
      )`;
    const rows = await tx`
      SELECT * FROM project_messaging_provisions
      WHERE project_ref_id = ${projectRefId}`;
    return rows[0];
  };

  // The signer id comes from the PROVISION row, never recomputed — an
  // already-provisioned project keeps whatever id it was provisioned
  // under (the pre-fix 8-char form included).
  const policyHeadSignerFor = (
    projectRefId: string,
    signerKeyId: string,
  ): PolicyHeadSignerPort => {
    const keys = ed25519(deriveSeed("policy-head-signer", projectRefId));
    return Object.freeze({
      signerKeyId,
      sign: (digest: Buffer) => signNode(null, digest, keys.privateKey),
    });
  };

  // The role-agnostic plan body shared by the customer-initiated
  // createPlan (creator = customer, welcome = staff) and the
  // owner-initiated acceptRequest (creator = owner, welcome = customer).
  // The caller resolves who fills each slot and reserves the welcome
  // members' KeyPackages; this materializes the roster, plan row, and
  // members exactly the same way for both — activate() then drives the
  // rest purely from the plan record, so nothing downstream hardcodes a
  // role.
  const materializePlan = async (
    tx: TransactionSql,
    now: string,
    params: {
      readonly projectRefId: string;
      readonly customerAccountId: string;
      readonly creator: {
        readonly accountId: string;
        readonly installationId: string;
        readonly role: string;
        readonly credentialFingerprint: string;
      };
      readonly welcomeMembers: readonly {
        readonly accountId: string;
        readonly installationId: string;
        readonly role: string;
        readonly credentialFingerprint: string;
        readonly keyPackageRef: string;
        readonly keyPackage: string;
      }[];
      readonly existingRelationship: {
        readonly relationshipId: string;
        readonly relationshipScopeId: string;
      } | null;
    },
  ): Promise<PlanCreation> => {
    const { projectRefId, customerAccountId, creator, welcomeMembers } = params;
    const scope = await provisionServiceScope(tx, now);
    const provision = await provisionProject(tx, projectRefId, now);
    const planId = randomUUID();
    const relationshipId =
      params.existingRelationship?.relationshipId ?? randomUUID();
    const relationshipScopeId =
      params.existingRelationship?.relationshipScopeId ?? randomUUID();
    const retentionPolicy = { profile: "reader-history-retained.v1" };
    const retentionHash = createHash("sha256")
      .update("jb-msg-retention/v1", "utf8")
      .update(JSON.stringify(retentionPolicy), "utf8")
      .digest();
    if (!params.existingRelationship) {
      await tx`
        INSERT INTO relationships (
          relationship_id, relationship_scope_id, project_ref_id,
          customer_account_id, policy_profile_id,
          reader_history_retention_policy,
          reader_history_retention_policy_hash, state, created_at
        ) VALUES (
          ${relationshipId}, ${relationshipScopeId}, ${projectRefId},
          ${customerAccountId}, 'project-support-standard-v1',
          ${JSON.stringify(retentionPolicy)}::jsonb, ${retentionHash},
          'active', ${now}::timestamptz
        )`;
    }

    const conversationId = randomUUID();
    const roster = [
      {
        accountId: creator.accountId,
        installationId: creator.installationId,
        installationKind: "native",
        role: creator.role,
        bootstrapMode: "creator",
        credentialFingerprint: creator.credentialFingerprint,
      },
      ...welcomeMembers.map((member) => ({
        accountId: member.accountId,
        installationId: member.installationId,
        installationKind: "native",
        role: member.role,
        bootstrapMode: "welcome",
        credentialFingerprint: member.credentialFingerprint,
        keyPackageRef: member.keyPackageRef,
        keyPackage: member.keyPackage,
      })),
    ];
    const rosterHash = createHash("sha256")
      .update("jb-msg-plan-roster/v1", "utf8")
      .update(JSON.stringify(roster), "utf8")
      .digest();
    const senderGenerations = await tx`
      SELECT external_sender_credential_id, signer_generation
      FROM external_sender_credentials
      WHERE external_sender_credential_id IN (
        ${String(provision.current_external_sender_credential_id)},
        ${String(provision.staged_external_sender_credential_id)}
      )`;
    const generationOf = (credentialId: string): string => {
      const row = senderGenerations.find(
        (candidate) =>
          String(candidate.external_sender_credential_id) === credentialId,
      );
      return row ? String(row.signer_generation) : "1";
    };
    const externalSenders = {
      current: {
        credentialId: String(provision.current_external_sender_credential_id),
        signerGeneration: generationOf(
          String(provision.current_external_sender_credential_id),
        ),
      },
      stagedNext: {
        credentialId: String(provision.staged_external_sender_credential_id),
        signerGeneration: generationOf(
          String(provision.staged_external_sender_credential_id),
        ),
      },
    };
    const externalSendersHash = createHash("sha256")
      .update("jb-msg-plan-external-senders/v1", "utf8")
      .update(JSON.stringify(externalSenders), "utf8")
      .digest();

    const quotaBindings = quotaBindingsFor(
      conversationId,
      creator.accountId,
      creator.installationId,
      projectRefId,
      now,
    );
    const quotaPolicyDigest = computeApplicationAppendQuotaPolicyDigest(
      quotaBindings.map(({ subjectId, ...identity }) => {
        void subjectId;
        return identity;
      }) as never,
    );
    const expiresAt = new Date(
      Date.parse(now) + PLAN_TTL_MILLISECONDS,
    ).toISOString();
    await tx`
      INSERT INTO conversation_plans (
        plan_id, conversation_id, relationship_id, relationship_scope_id,
        project_ref_id, creator_account_id, creator_installation_id,
        kind, delivery_purpose, generation, release_profile_id,
        delivery_limits_digest, release_trust_root_digest,
        quota_policy_digest, roster_canonical, roster_hash,
        external_senders_canonical, external_senders_hash,
        reader_history_retention_policy_hash, plan_version, created_at,
        expires_at
      ) VALUES (
        ${planId}, ${conversationId}, ${relationshipId},
        ${relationshipScopeId}, ${projectRefId},
        ${creator.accountId}, ${creator.installationId},
        'relationship', 'purchase_support', 1, ${RELEASE_PROFILE_ID},
        ${Buffer.from(scope.limitsDigest, "base64url")},
        ${Buffer.from(scope.trustRootDigest, "base64url")},
        ${Buffer.from(quotaPolicyDigest, "base64url")},
        ${JSON.stringify(roster)}::jsonb, ${rosterHash},
        ${JSON.stringify(externalSenders)}::jsonb, ${externalSendersHash},
        ${retentionHash}, 1, ${now}::timestamptz, ${expiresAt}::timestamptz
      )`;
    for (const member of roster) {
      if (member.bootstrapMode === "welcome") {
        await tx`
          UPDATE key_packages SET
            state = 'taken', taken_at = ${now}::timestamptz,
            taken_by_plan_id = ${planId}
          WHERE key_package_ref = ${Buffer.from(
            (member as { keyPackageRef: string }).keyPackageRef,
            "base64url",
          )} AND state = 'available'`;
      }
      await tx`
        INSERT INTO conversation_plan_members (
          plan_id, installation_id, account_id, role, bootstrap_mode,
          mls_credential_fingerprint, key_package_ref
        ) VALUES (
          ${planId}, ${member.installationId}, ${member.accountId},
          ${member.role}, ${member.bootstrapMode},
          ${Buffer.from(member.credentialFingerprint, "base64url")},
          ${
            member.bootstrapMode === "creator"
              ? null
              : Buffer.from(
                  (member as { keyPackageRef: string }).keyPackageRef,
                  "base64url",
                )
          }
        )`;
    }

    return Object.freeze({
      status: "created" as const,
      plan: {
        planId,
        action: "create_generation",
        relationshipId,
        relationshipScopeId,
        conversationId,
        kind: "relationship",
        deliveryPurpose: "purchase-support",
        releaseProfileId: RELEASE_PROFILE_ID,
        deliveryLimitsDigest: scope.limitsDigest,
        releaseTrustRootDigest: scope.trustRootDigest,
        expiresAt,
        planEtag: `"plan-${planId}-1"`,
        roster,
        rosterHash: rosterHash.toString("base64url"),
        externalSenders,
        externalSendersHash: externalSendersHash.toString("base64url"),
      },
    });
  };

  // Reserve one available KeyPackage per installation (the irreversible
  // take is committed later in materializePlan). Best-effort per
  // installation: an id with no available package is simply absent from
  // the map, and the CALLER decides how many welcomes it needs — one
  // stale device with an empty shelf must never block a chat for the
  // devices that do have keys.
  const reserveKeyPackages = async (
    tx: TransactionSql,
    now: string,
    installationIds: readonly string[],
  ): Promise<Map<string, { ref: string; bytes: string }>> => {
    const out = new Map<string, { ref: string; bytes: string }>();
    for (const installationId of installationIds) {
      const taken = await tx`
        SELECT encode(key_package_ref, 'base64') AS ref,
               encode(package_bytes, 'base64') AS bytes
        FROM key_packages
        WHERE installation_id = ${installationId}
          AND state = 'available' AND taken_at IS NULL
          AND expires_at > ${now}::timestamptz
        ORDER BY created_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED`;
      if (taken.length !== 1) continue;
      out.set(installationId, {
        ref: b64ToUrl(taken[0].ref),
        bytes: b64ToUrl(taken[0].bytes),
      });
    }
    return out;
  };

  return Object.freeze({
    async createPlan(input: {
      readonly creatorAccountId: string;
      readonly creatorInstallationId: string;
      readonly eligibilityClaimHandle: string;
    }): Promise<PlanCreation> {
      if (
        !UUID_PATTERN.test(input.creatorAccountId) ||
        !UUID_PATTERN.test(input.creatorInstallationId) ||
        !HANDLE_PATTERN.test(input.eligibilityClaimHandle)
      ) {
        return Object.freeze({ status: "refused", reasonCode: "malformed_request" });
      }
      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const grants = await tx`
          SELECT grant_id, project_ref_id, account_id, capability, state,
                 valid_until
          FROM eligibility_grants
          WHERE claim_handle_hash =
                ${context.hmacEligibilityClaimHandle(input.eligibilityClaimHandle)}
          FOR UPDATE`;
        if (
          grants.length !== 1 ||
          String(grants[0].state) !== "active" ||
          new Date(grants[0].valid_until as Date).toISOString() <= now ||
          String(grants[0].account_id) !== input.creatorAccountId ||
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

        const creator = await tx`
          SELECT i.installation_id, i.account_id, i.platform,
                 encode(i.mls_credential_fingerprint, 'base64') AS fingerprint
          FROM installations i
          WHERE i.installation_id = ${input.creatorInstallationId}
            AND i.account_id = ${input.creatorAccountId}
            AND i.status = 'active'`;
        if (creator.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "creator_not_active",
          });
        }

        // Existing relationship with an active generation is reused.
        const relationships = await tx`
          SELECT relationship_id, relationship_scope_id,
                 active_conversation_id
          FROM relationships
          WHERE project_ref_id = ${projectRefId}
            AND customer_account_id = ${input.creatorAccountId}
            AND state = 'active'
          FOR UPDATE`;
        if (
          relationships.length === 1 &&
          relationships[0].active_conversation_id !== null
        ) {
          return Object.freeze({
            status: "reuse_generation" as const,
            conversationId: String(relationships[0].active_conversation_id),
          });
        }

        const staff = await tx`
          SELECT r.installation_id, r.account_id,
                 encode(i.mls_credential_fingerprint, 'base64') AS fingerprint
          FROM project_staff_registrations r
          JOIN installations i ON i.installation_id = r.installation_id
          WHERE r.project_ref_id = ${projectRefId} AND r.state = 'active'
            AND i.status = 'active'
          ORDER BY r.registered_at
          LIMIT 8`;
        if (staff.length === 0) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "no_project_staff_registered",
          });
        }

        // Welcome every staff device that has a KeyPackage; refuse only if
        // none does — a stale device must not block the reachable ones.
        const reserved = await reserveKeyPackages(
          tx,
          now,
          staff.map((member) => String(member.installation_id)),
        );
        const reachableStaff = staff.filter((member) =>
          reserved.has(String(member.installation_id)),
        );
        if (reachableStaff.length === 0) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "recipient_keys_unavailable",
          });
        }
        return materializePlan(tx, now, {
          projectRefId,
          customerAccountId: input.creatorAccountId,
          creator: {
            accountId: input.creatorAccountId,
            installationId: input.creatorInstallationId,
            role: "customer",
            credentialFingerprint: b64ToUrl(creator[0].fingerprint),
          },
          welcomeMembers: reachableStaff.map((member) => ({
            accountId: String(member.account_id),
            installationId: String(member.installation_id),
            role: "project-staff",
            credentialFingerprint: b64ToUrl(String(member.fingerprint)),
            keyPackageRef: reserved.get(String(member.installation_id))!.ref,
            keyPackage: reserved.get(String(member.installation_id))!.bytes,
          })),
          existingRelationship:
            relationships.length === 1
              ? {
                  relationshipId: String(relationships[0].relationship_id),
                  relationshipScopeId: String(
                    relationships[0].relationship_scope_id,
                  ),
                }
              : null,
        });
      });
    },

    async acceptRequest(input: {
      readonly requestId: string;
      readonly ownerAccountId: string;
      readonly ownerInstallationId: string;
    }): Promise<PlanCreation> {
      if (
        !UUID_PATTERN.test(input.requestId) ||
        !UUID_PATTERN.test(input.ownerAccountId) ||
        !UUID_PATTERN.test(input.ownerInstallationId)
      ) {
        return Object.freeze({ status: "refused", reasonCode: "malformed_request" });
      }
      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const requests = await tx`
          SELECT request_id, project_ref_id, requester_account_id,
                 requester_installation_id, eligibility_grant_id, status
          FROM conversation_requests
          WHERE request_id = ${input.requestId}
          FOR UPDATE`;
        if (requests.length !== 1 || String(requests[0].status) !== "pending") {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "request_not_pending",
          });
        }
        const projectRefId = String(requests[0].project_ref_id);
        const customerAccountId = String(requests[0].requester_account_id);
        const customerInstallationId = String(
          requests[0].requester_installation_id,
        );

        // The accepting installation must be active staff on this project.
        const owner = await tx`
          SELECT i.installation_id,
                 encode(i.mls_credential_fingerprint, 'base64') AS fingerprint
          FROM project_staff_registrations r
          JOIN installations i ON i.installation_id = r.installation_id
          WHERE r.project_ref_id = ${projectRefId}
            AND r.installation_id = ${input.ownerInstallationId}
            AND r.account_id = ${input.ownerAccountId}
            AND r.state = 'active' AND i.status = 'active'`;
        if (owner.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "not_project_staff",
          });
        }

        // Revalidate the customer's grant is still live (it may have
        // expired or been revoked since the request was lodged).
        const grants = await tx`
          SELECT state, valid_until, capability
          FROM eligibility_grants
          WHERE grant_id = ${String(requests[0].eligibility_grant_id)}`;
        if (
          grants.length !== 1 ||
          String(grants[0].state) !== "active" ||
          new Date(grants[0].valid_until as Date).toISOString() <= now ||
          !["purchase-support", "item-set-buyer"].includes(
            String(grants[0].capability),
          )
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "grant_invalid",
          });
        }

        // ALL of the customer's active devices, requester first, so every
        // browser they enrolled can decrypt the conversation from birth.
        const customerDevices = await tx`
          SELECT installation_id,
                 encode(mls_credential_fingerprint, 'base64') AS fingerprint
          FROM installations
          WHERE account_id = ${customerAccountId} AND status = 'active'
          ORDER BY (installation_id = ${customerInstallationId}) DESC,
                   created_at`;
        if (
          !customerDevices.some(
            (device) =>
              String(device.installation_id) === customerInstallationId,
          )
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "requester_not_active",
          });
        }

        const relationships = await tx`
          SELECT relationship_id, relationship_scope_id,
                 active_conversation_id
          FROM relationships
          WHERE project_ref_id = ${projectRefId}
            AND customer_account_id = ${customerAccountId}
            AND state = 'active'
          FOR UPDATE`;
        if (
          relationships.length === 1 &&
          relationships[0].active_conversation_id !== null
        ) {
          return Object.freeze({
            status: "reuse_generation" as const,
            conversationId: String(relationships[0].active_conversation_id),
          });
        }

        // Welcome every customer device that has a KeyPackage; refuse only
        // if none does.
        const reserved = await reserveKeyPackages(
          tx,
          now,
          customerDevices.map((device) => String(device.installation_id)),
        );
        const reachableDevices = customerDevices.filter((device) =>
          reserved.has(String(device.installation_id)),
        );
        if (reachableDevices.length === 0) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "recipient_keys_unavailable",
          });
        }
        return materializePlan(tx, now, {
          projectRefId,
          customerAccountId,
          creator: {
            accountId: input.ownerAccountId,
            installationId: input.ownerInstallationId,
            role: "project-staff",
            credentialFingerprint: b64ToUrl(owner[0].fingerprint),
          },
          welcomeMembers: reachableDevices.map((device) => ({
            accountId: customerAccountId,
            installationId: String(device.installation_id),
            role: "customer",
            credentialFingerprint: b64ToUrl(String(device.fingerprint)),
            keyPackageRef: reserved.get(String(device.installation_id))!.ref,
            keyPackage: reserved.get(String(device.installation_id))!.bytes,
          })),
          existingRelationship:
            relationships.length === 1
              ? {
                  relationshipId: String(relationships[0].relationship_id),
                  relationshipScopeId: String(
                    relationships[0].relationship_scope_id,
                  ),
                }
              : null,
        });
      });
    },

    async activate(
      inputValue: unknown,
      callerInstallationId: string,
    ): Promise<ActivationResult> {
      const record = inputValue as Record<string, unknown>;
      const mls = record?.mls as Record<string, unknown> | undefined;
      if (
        !record ||
        !mls ||
        !UUID_PATTERN.test(String(record.planId)) ||
        !UUID_PATTERN.test(String(record.conversationId)) ||
        !UUID_V4_PATTERN.test(String(mls.envelopeId)) ||
        mls.cipherSuite !== "0x0001" ||
        String(mls.epoch) !== "1" ||
        typeof mls.commit !== "string" ||
        !BASE64URL_PATTERN.test(mls.commit) ||
        !Array.isArray(mls.welcomeByInstallation)
      ) {
        return Object.freeze({ status: "refused", reasonCode: "malformed_request" });
      }
      const commitBytes = Buffer.from(String(mls.commit), "base64url");
      if (commitBytes.length === 0 || commitBytes.length > 524288) {
        return Object.freeze({ status: "refused", reasonCode: "malformed_request" });
      }

      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const plans = await tx`
          SELECT * FROM conversation_plans
          WHERE plan_id = ${String(record.planId)} FOR UPDATE`;
        if (
          plans.length !== 1 ||
          plans[0].consumed_at !== null ||
          new Date(plans[0].expires_at as Date).toISOString() <= now ||
          String(plans[0].conversation_id) !== String(record.conversationId) ||
          String(plans[0].creator_installation_id) !== callerInstallationId ||
          Buffer.from(plans[0].roster_hash as Uint8Array).toString(
            "base64url",
          ) !== String(record.rosterHash) ||
          Buffer.from(plans[0].external_senders_hash as Uint8Array).toString(
            "base64url",
          ) !== String(record.externalSendersHash)
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "plan_invalid",
          });
        }
        const plan = plans[0];
        const conversationId = String(plan.conversation_id);
        const projectRefId = String(plan.project_ref_id);
        const members = await tx`
          SELECT m.*, encode(m.mls_credential_fingerprint, 'base64') AS fp,
                 encode(m.key_package_ref, 'base64') AS kp_ref
          FROM conversation_plan_members m
          WHERE m.plan_id = ${String(plan.plan_id)}
          ORDER BY m.bootstrap_mode, m.installation_id`;
        const welcomeMembers = members.filter(
          (member) => String(member.bootstrap_mode) === "welcome",
        );
        const welcomes = (mls.welcomeByInstallation as Record<string, unknown>[]).map(
          (entry) => ({
            installationId: String(entry.installationId),
            welcome: String(entry.welcome),
          }),
        );
        const welcomeIds = new Set(welcomes.map((w) => w.installationId));
        if (
          welcomes.length !== welcomeMembers.length ||
          !welcomeMembers.every((member) =>
            welcomeIds.has(String(member.installation_id)),
          ) ||
          welcomes.some(
            (w) =>
              !BASE64URL_PATTERN.test(w.welcome) ||
              Buffer.from(w.welcome, "base64url").length > 262144,
          )
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "welcome_set_mismatch",
          });
        }

        const provision = await provisionProject(tx, projectRefId, now);
        const rawRoster = plan.roster_canonical;
        const rosterCanonical = (
          typeof rawRoster === "string" ? JSON.parse(rawRoster) : rawRoster
        ) as {
          accountId: string;
          installationId: string;
          role: string;
          bootstrapMode: string;
          credentialFingerprint: string;
        }[];

        // Conversation row first; nearly every other row references it.
        const generation = "1";
        const quotaBindings = quotaBindingsFor(
          conversationId,
          String(plan.creator_account_id),
          String(plan.creator_installation_id),
          projectRefId,
          new Date(plan.created_at as Date).toISOString(),
        );
        // Every non-creator member additionally gets its own
        // installation/account-scoped rows; each sender's snapshot selects
        // exactly its five.
        const memberScopedBindings = (
          plan.roster_canonical && true
            ? ((typeof plan.roster_canonical === "string"
                ? JSON.parse(plan.roster_canonical as string)
                : plan.roster_canonical) as {
                accountId: string;
                installationId: string;
                bootstrapMode: string;
              }[])
            : []
        )
          .filter((member) => member.bootstrapMode !== "creator")
          .flatMap((member) =>
            quotaBindingsFor(
              conversationId,
              member.accountId,
              member.installationId,
              projectRefId,
              new Date(plan.created_at as Date).toISOString(),
            ).filter(
              (binding) =>
                binding.scope === "installation" || binding.scope === "account",
            ),
          );
        // Two devices on one account (multi-device welcome) produce the
        // SAME account-scope binding; they must share one row, not insert
        // two. Dedupe by scope identity, first occurrence wins.
        const seenBindingKeys = new Set<string>();
        const allBindings = [...quotaBindings, ...memberScopedBindings].filter(
          (binding) => {
            const key = `${binding.scope}:${binding.scopeHash}:${binding.quotaName}`;
            if (seenBindingKeys.has(key)) return false;
            seenBindingKeys.add(key);
            return true;
          },
        );
        const rosterProjection = rosterCanonical.map((member) => ({
          conversationId,
          conversationGeneration: generation,
          rosterVersion: "0",
          accountId: member.accountId,
          installationId: member.installationId,
          credentialId: roleCredentialId(member.installationId, conversationId),
          credentialFingerprint: member.credentialFingerprint,
        }));
        const rosterHash = computeApplicationAppendMlsRosterHash(
          rosterProjection as never,
        );
        const groupIdHash = createHash("sha256")
          .update("jb-msg-group-id/v1", "utf8")
          .update(Buffer.from(String(mls.groupId ?? ""), "base64url"))
          .digest();
        const envelopeSha256 = computeEnvelopeSha256(commitBytes);
        if (String(mls.envelopeSha256) !== envelopeSha256) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "artifact_hash_mismatch",
          });
        }
        const resultingTranscript = String(
          mls.resultingConfirmedTranscriptHash,
        );
        if (Buffer.from(resultingTranscript, "base64url").length !== 32) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "malformed_request",
          });
        }

        const credentialExpiry = new Date(
          Date.parse(now) + 30 * 24 * 60 * 60 * 1_000,
        ).toISOString();
        const recipientProjection = rosterCanonical.map((member, index) => ({
          conversationId,
          conversationGeneration: generation,
          recipientSetVersion: "0",
          accountId: member.accountId,
          installationId: member.installationId,
          credentialId: roleCredentialId(member.installationId, conversationId),
          credentialFingerprint: member.credentialFingerprint,
          credentialRevocationVersion: "1",
          credentialState: "active",
          credentialExpiresAt: credentialExpiry,
          joinedPosition: "1",
          removedPosition: null as string | null,
          installationState: "active",
          ordinal: index,
        }));
        const recipientSetHash = computeApplicationAppendRecipientSetHash(
          recipientProjection.map((projection) => {
            const { ordinal, ...rest } = projection;
            void ordinal;
            return rest;
          }) as never,
        );

        await tx`
          INSERT INTO conversations (
            conversation_id, relationship_id, relationship_scope_id,
            project_ref_id, kind, delivery_purpose, generation, state,
            group_id_hash, release_profile_id, delivery_limits_digest,
            release_trust_root_digest, quota_policy_digest, epoch,
            roster_version, roster_hash, external_senders_hash,
            reader_history_retention_policy_hash, confirmed_transcript_hash,
            last_policy_head_sequence, current_policy_head_hash,
            last_position, current_log_head_hash, retention_policy_version,
            retention_policy, created_at, last_activity_at, expires_at,
            realm_id, project_scope_id, tenant_scope_id, etag,
            recipient_set_version, recipient_set_hash
          ) VALUES (
            ${conversationId}, ${String(plan.relationship_id)},
            ${String(plan.relationship_scope_id)}, ${projectRefId},
            'relationship', 'purchase_support', ${generation}, 'active',
            ${groupIdHash}, ${RELEASE_PROFILE_ID},
            ${plan.delivery_limits_digest as Buffer},
            ${plan.release_trust_root_digest as Buffer},
            ${plan.quota_policy_digest as Buffer}, 1, 0,
            ${Buffer.from(rosterHash, "base64url")},
            ${plan.external_senders_hash as Buffer},
            ${plan.reader_history_retention_policy_hash as Buffer},
            ${Buffer.from(resultingTranscript, "base64url")},
            0, ${Buffer.alloc(32)}, 0, ${Buffer.alloc(32)}, 1,
            ${JSON.stringify({ profile: "reader-history-retained.v1" })}::jsonb,
            ${now}::timestamptz, ${now}::timestamptz,
            ${now}::timestamptz + interval '365 days',
            ${SERVICE_REALM_ID}, ${`project:${projectRefId}`},
            ${`tenant:${SERVICE_TENANT_ID}`}, '"e1-r0"',
            0, ${Buffer.from(recipientSetHash, "base64url")}
          )`;

        for (const binding of allBindings) {
          await tx`
            INSERT INTO quota_scopes (
              scope_type, scope_hash, realm_id, subject_id, created_at
            ) VALUES (
              ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
              ${SERVICE_REALM_ID}, ${binding.subjectId}, ${now}::timestamptz
            ) ON CONFLICT DO NOTHING`;
          await tx`
            INSERT INTO quota_counters (
              scope_type, scope_hash, quota_name, window_started_at,
              window_seconds, operation_count, byte_count,
              reserved_operation_count, reserved_byte_count, row_version,
              updated_at
            ) VALUES (
              ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
              ${binding.quotaName}, ${binding.windowStartedAt}::timestamptz,
              ${binding.windowSeconds}, 0, 0, 0, 0, 0, ${now}::timestamptz
            ) ON CONFLICT DO NOTHING`;
        }
        await tx`
          INSERT INTO quota_policies (
            quota_policy_digest, canonical_document, created_at
          ) VALUES (
            ${plan.quota_policy_digest as Buffer},
            ${JSON.stringify(quotaBindings)}::jsonb, ${now}::timestamptz
          ) ON CONFLICT DO NOTHING`;
        for (const [ordinal, binding] of allBindings.entries()) {
          await tx`
            INSERT INTO conversation_quota_bindings (
              conversation_id, quota_policy_digest, scope_type, scope_hash,
              quota_name, window_seconds, operation_limit, byte_limit,
              ordinal, window_started_at
            ) VALUES (
              ${conversationId}, ${plan.quota_policy_digest as Buffer},
              ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
              ${binding.quotaName}, ${binding.windowSeconds},
              ${binding.operationLimit}, ${binding.byteLimit}, ${ordinal},
              ${binding.windowStartedAt}::timestamptz
            )`;
        }
        await tx`
          INSERT INTO conversation_usage (
            conversation_id, envelope_count, envelope_bytes, attachment_bytes,
            envelope_count_limit, envelope_bytes_limit,
            attachment_bytes_limit, updated_at
          ) VALUES (
            ${conversationId}, 0, 0, 0, 10000, 33554432, 134217728,
            ${now}::timestamptz
          )`;

        // Role credentials + memberships + projections per member.
        for (const [ordinal, member] of rosterCanonical.entries()) {
          const credentialId = roleCredentialId(
            member.installationId,
            conversationId,
          );
          await tx`
            INSERT INTO role_credentials (
              credential_id, conversation_id, installation_id, account_id,
              policy_id, policy_revision, role, credential_public,
              credential_fingerprint, issued_at, expires_at,
              revocation_version, state
            ) VALUES (
              ${credentialId}, ${conversationId}, ${member.installationId},
              ${member.accountId}, ${String(provision.policy_id)}, 1,
              ${member.role},
              ${Buffer.from(member.credentialFingerprint, "base64url")},
              ${Buffer.from(member.credentialFingerprint, "base64url")},
              ${now}::timestamptz, ${credentialExpiry}::timestamptz, 1,
              'active'
            )`;
          await tx`
            INSERT INTO memberships (
              conversation_id, installation_id, account_id, credential_id,
              role, delivery_purpose, bootstrap_mode, joined_position,
              joined_at
            ) VALUES (
              ${conversationId}, ${member.installationId}, ${member.accountId},
              ${credentialId}, ${member.role}, 'purchase_support',
              ${member.bootstrapMode}, 1, ${now}::timestamptz
            )`;
          await tx`
            INSERT INTO conversation_roster_projections (
              conversation_id, conversation_generation, roster_version,
              account_id, installation_id, credential_id,
              credential_fingerprint, ordinal
            ) VALUES (
              ${conversationId}, ${generation}, 0, ${member.accountId},
              ${member.installationId}, ${credentialId},
              ${Buffer.from(member.credentialFingerprint, "base64url")},
              ${ordinal}
            )`;
          await tx`
            INSERT INTO conversation_recipient_projections (
              conversation_id, conversation_generation, recipient_set_version,
              account_id, installation_id, credential_id,
              credential_fingerprint, credential_revocation_version,
              credential_state, credential_expires_at, joined_position,
              removed_position, installation_state, ordinal
            ) VALUES (
              ${conversationId}, ${generation}, 0, ${member.accountId},
              ${member.installationId}, ${credentialId},
              ${Buffer.from(member.credentialFingerprint, "base64url")}, 1,
              'active', ${credentialExpiry}::timestamptz, 1, ${null},
              'active', ${ordinal}
            )`;
        }

        // Issued signed policy head + its append-lane anchor.
        const issuance = createPolicyHeadIssuanceStore({
          sql: tx as unknown as Sql,
          signer: policyHeadSignerFor(
            projectRefId,
            String(provision.policy_head_signing_key_id),
          ),
        });
        const currentSender = await tx`
          SELECT encode(credential_fingerprint, 'base64') AS fp,
                 signer_generation
          FROM external_sender_credentials
          WHERE external_sender_credential_id =
                ${String(provision.current_external_sender_credential_id)}`;
        // EVERY member gets a send grant with its REAL evidence digest
        // over the exact row values the reconstruction re-reads, so every
        // member has a per-sender custody fence and can append. Genesis
        // grants anchor to the zero prior head: the digests must exist
        // BEFORE the head that carries them is signed.
        const creatorRosterMember = rosterCanonical.find(
          (member) => member.bootstrapMode === "creator",
        )!;
        const issuedSequence = "1";
        const memberGrants = rosterCanonical.map((member) => {
          const credentialId = roleCredentialId(
            member.installationId,
            conversationId,
          );
          const grantWithoutDigests = {
            conversationId,
            installationId: member.installationId,
            credentialId,
            conversationKind: "purchase_support",
            conversationGeneration: generation,
            role: member.role,
            roleCredentialId: credentialId,
            roleCredentialFingerprint: member.credentialFingerprint,
            roleCredentialSubjectAccountId: member.accountId,
            roleCredentialSubjectInstallationId: member.installationId,
            roleCredentialValidFrom: now,
            roleCredentialValidUntil: credentialExpiry,
            capability: "send_application",
            state: "active",
            policyRevision: "1",
            policyHeadSequence: issuedSequence,
            policyHeadHash: ZERO_HASH32,
            expiresAt: credentialExpiry,
          };
          return {
            member,
            credentialId,
            grantWithoutDigests,
            grantEvidenceDigest: computeConversationSendGrantEvidenceDigest(
              grantWithoutDigests as never,
            ),
            grantInclusionEvidenceDigest: deriveSeed(
              "send-grant-inclusion",
              `${conversationId}:${member.installationId}`,
            ).toString("base64url"),
          };
        });
        const creatorGrant = memberGrants.find(
          (grant) => grant.member.bootstrapMode === "creator",
        )!;
        const sendGrantSetMembers = memberGrants.map((grant) => ({
          grantEvidenceDigest: grant.grantEvidenceDigest,
          grantInclusionEvidenceDigest: grant.grantInclusionEvidenceDigest,
          installationId: grant.member.installationId,
          credentialId: grant.credentialId,
          role: grant.member.role,
        }));
        const issued = await issuance.issuePolicyHead({
          conversationId,
          policyId: String(provision.policy_id),
          policyRevision: "1",
          policyHash: deriveSeed("policy-hash", projectRefId).toString(
            "base64url",
          ),
          authorizedQuotaPolicyDigest: Buffer.from(
            plan.quota_policy_digest as Uint8Array,
          ).toString("base64url"),
          evaluatedChainId: await projectChainId(tx, projectRefId),
          evaluatedBlock: "0",
          evaluatedBlockHash: deriveSeed(
            "evaluated-block",
            conversationId,
          ).toString("base64url"),
          activeExternalSenderCredentialId: String(
            provision.current_external_sender_credential_id,
          ),
          activeExternalSenderFingerprint: b64ToUrl(
            String(currentSender[0].fp),
          ),
          activeSignerGeneration: String(currentSender[0].signer_generation),
          directoryCheckpointId: String(provision.directory_checkpoint_id),
          policyLogCheckpointId: String(provision.policy_log_checkpoint_id),
          mandatoryProposals: [],
          sendGrantSetMembers,
        });
        // Re-anchor every grant at the issued head. The grant digest
        // commits the head hash, and the head's signed body committed the
        // genesis zero-anchored digests - the bootstrap order the kernel
        // admits: rows carry the post-issuance digests the append path
        // recomputes.
        for (const grant of memberGrants) {
          grant.grantEvidenceDigest = computeConversationSendGrantEvidenceDigest(
            {
              ...grant.grantWithoutDigests,
              policyHeadHash: issued.policyHeadHash,
            } as never,
          );
        }
        const served = await issuance.readNewestPolicyHead(conversationId);
        if (!served) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "policy_head_unavailable",
          });
        }
        const signedBodySha = createHash("sha256")
          .update(Buffer.from(served.canonicalSignedBody, "base64url"))
          .digest();
        const headExpiry = served.expiresAt;
        await tx`
          INSERT INTO delivery_policy_head_anchors (
            conversation_id, policy_head_id, policy_head_sequence,
            policy_head_hash, delivery_log_position, delivery_log_head_hash,
            evaluation_log_position, evaluation_log_head_hash, epoch,
            roster_version, confirmed_transcript_hash, policy_revision,
            signed_body_sha256, signer_key_id, signature_sha256,
            witness_evidence_digest, proof_evidence_digest,
            policy_consistency_evidence_digest, proof_verified_at, issued_at,
            expires_at, witness_state, witness_checkpoint_id,
            witnessed_policy_head_hash, mandatory_proposal_count,
            mandatory_proposal_set_hash, authorized_send_grant_set_hash,
            selected_send_grant_evidence_digest,
            selected_send_grant_inclusion_evidence_digest,
            authorized_quota_policy_digest, prior_policy_head_sequence,
            prior_policy_head_hash, prior_policy_witness_checkpoint_id,
            prior_policy_witness_evidence_digest, updated_at
          ) VALUES (
            ${conversationId}, ${issued.policyHeadId},
            ${issued.policyHeadSequence},
            ${Buffer.from(issued.policyHeadHash, "base64url")}, 0,
            ${Buffer.alloc(32)}, 0, ${Buffer.alloc(32)}, 1, 0,
            ${Buffer.from(resultingTranscript, "base64url")}, 1,
            ${signedBodySha}, ${served.signerKeyId},
            ${createHash("sha256")
              .update(Buffer.from(served.signature, "base64url"))
              .digest()},
            ${deriveSeed("witness-evidence", conversationId)},
            ${deriveSeed("proof-evidence", conversationId)},
            ${deriveSeed("policy-consistency", conversationId)},
            ${now}::timestamptz, ${issued.issuedAt}::timestamptz,
            ${headExpiry}::timestamptz, 'missing', ${null}, ${null},
            0, ${zeroSetHash("jb-msg-policy-mandatory-proposal-set/v1")},
            ${zeroSetHash("jb-msg-send-grant-set/v1")},
            ${Buffer.from(creatorGrant.grantEvidenceDigest, "base64url")},
            ${Buffer.from(creatorGrant.grantInclusionEvidenceDigest, "base64url")},
            ${plan.quota_policy_digest as Buffer},
            ${issued.policyHeadSequence === "1" ? 0 : Number(issued.policyHeadSequence) - 1},
            ${
              issued.previousPolicyHeadHash === ZERO_HASH32
                ? Buffer.alloc(32)
                : Buffer.from(issued.previousPolicyHeadHash, "base64url")
            },
            ${stableUuid("prior-witness-checkpoint", conversationId)},
            ${deriveSeed("prior-witness", conversationId)},
            ${now}::timestamptz
          )`;

        // Global policy log: this head becomes a leaf, and a checkpoint
        // commits the RFC 6962 root over the whole prefix. The keeper
        // submits unwitnessed checkpoints to the witness's policy
        // namespace; heads stay witness_state='missing' - and appends
        // stay closed - until the cosigned receipt lands.
        const leafCountRows = await tx`
          SELECT count(*)::int AS total FROM policy_log_leaves`;
        const leafIndex = Number(leafCountRows[0].total);
        await tx`
          INSERT INTO policy_log_leaves (
            leaf_index, policy_head_id, head_hash, created_at
          ) VALUES (
            ${leafIndex}, ${issued.policyHeadId},
            ${Buffer.from(issued.policyHeadHash, "base64url")},
            ${now}::timestamptz
          )`;
        const allLeaves = await tx`
          SELECT head_hash FROM policy_log_leaves ORDER BY leaf_index`;
        const policyRoot = merkleRoot(
          allLeaves.map((row) =>
            merkleLeafHash(Buffer.from(row.head_hash as Uint8Array)),
          ),
        );
        const previousCheckpoint = await tx`
          SELECT checkpoint_id FROM policy_log_checkpoints
          WHERE tree_size > 0 AND signer_key_id = 'jbm-policy-log-2026q3'
          ORDER BY tree_size DESC LIMIT 1`;
        const policyLogKeys = ed25519(deriveSeed("policy-log-signer", "global"));
        await tx`
          INSERT INTO policy_log_checkpoints (
            checkpoint_id, tree_size, root_hash, previous_checkpoint_id,
            signer_key_id, signature, witness_key_id, witness_signature,
            created_at
          ) VALUES (
            ${randomUUID()}, ${leafIndex + 1}, ${policyRoot},
            ${previousCheckpoint.length === 1
              ? String(previousCheckpoint[0].checkpoint_id)
              : null},
            'jbm-policy-log-2026q3',
            ${signNode(null, policyRoot, policyLogKeys.privateKey)},
            'jbm-witness-pending', ${Buffer.alloc(1)}, ${now}::timestamptz
          )`;

        // Send grants for every member; each column mirrors the
        // digest-covered values exactly.
        const creatorMember = creatorRosterMember;
        for (const grant of memberGrants) {
          await tx`
            INSERT INTO conversation_send_grants (
              conversation_id, installation_id, credential_id,
              conversation_kind, conversation_generation, role,
              role_credential_id, role_credential_fingerprint,
              role_credential_subject_account_id,
              role_credential_subject_installation_id,
              role_credential_valid_from, role_credential_valid_until,
              capability, state, policy_revision, policy_head_sequence,
              policy_head_hash, expires_at, grant_evidence_digest,
              grant_inclusion_evidence_digest
            ) VALUES (
              ${conversationId}, ${grant.member.installationId},
              ${grant.credentialId}, 'purchase_support', ${generation},
              ${grant.member.role}, ${grant.credentialId},
              ${Buffer.from(grant.member.credentialFingerprint, "base64url")},
              ${grant.member.accountId}, ${grant.member.installationId},
              ${now}::timestamptz, ${credentialExpiry}::timestamptz,
              'send_application', 'active', 1, ${issuedSequence},
              ${Buffer.from(issued.policyHeadHash, "base64url")},
              ${credentialExpiry}::timestamptz,
              ${Buffer.from(grant.grantEvidenceDigest, "base64url")},
              ${Buffer.from(grant.grantInclusionEvidenceDigest, "base64url")}
            )`;
        }

        // The position-one Commit envelope, chained and signed.
        const envelopeId = String(mls.envelopeId);
        const leafHash = computeEnvelopeLeafHash({
          conversationId,
          position: "1",
          envelopeId,
          envelopeClass: "mls_commit",
          sender: {
            type: "installation",
            accountId: creatorMember.accountId,
            installationId: creatorMember.installationId,
          },
          epoch: "1",
          rosterVersion: "0",
          contentType: COMMIT_CONTENT_TYPE,
          envelopeSha256,
          receivedAt: now,
        } as unknown as EnvelopeLeafInput);
        const headHash = computeLogHeadHash(ZERO_HASH32, leafHash);
        const checkpointDigest = computeDeliveryLogCheckpointDigest({
          conversationId,
          position: "1",
          previousHeadHash: ZERO_HASH32,
          headHash,
          signingKeyId: context.logSigningKeyId,
        } as unknown as DeliveryLogCheckpointInput);
        const signature = await context.logSigner.signCheckpointDigest(
          context.logSigningKeyId,
          checkpointDigest,
        );
        const envelopeExpiresAt = new Date(
          Date.parse(now) + ENVELOPE_RETENTION_MILLISECONDS,
        ).toISOString();
        await tx`
          INSERT INTO envelopes (
            conversation_id, position, envelope_id, envelope_class,
            sender_type, sender_account_id, sender_installation_id, epoch,
            roster_version, base_confirmed_transcript_hash,
            resulting_confirmed_transcript_hash,
            content_type, envelope_bytes, envelope_sha256,
            previous_head_hash, leaf_hash, head_hash, log_signing_key_id,
            log_checkpoint_digest, log_head_signature, received_at,
            expires_at
          ) VALUES (
            ${conversationId}, 1, ${envelopeId}, 'mls_commit', 'installation',
            ${creatorMember.accountId}, ${creatorMember.installationId}, 1, 0,
            ${Buffer.alloc(32)},
            ${Buffer.from(resultingTranscript, "base64url")},
            ${COMMIT_CONTENT_TYPE}, ${commitBytes},
            ${Buffer.from(envelopeSha256, "base64url")},
            ${Buffer.alloc(32)}, ${Buffer.from(leafHash, "base64url")},
            ${Buffer.from(headHash, "base64url")},
            ${context.logSigningKeyId},
            ${Buffer.from(checkpointDigest, "base64url")},
            ${Buffer.from(signature, "base64url")},
            ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
          )`;
        await tx`
          UPDATE conversations SET last_position = 1,
            current_log_head_hash = ${Buffer.from(headHash, "base64url")},
            last_policy_head_sequence = ${issued.policyHeadSequence},
            current_policy_head_hash =
              ${Buffer.from(issued.policyHeadHash, "base64url")}
          WHERE conversation_id = ${conversationId}`;

        for (const welcome of welcomes) {
          const welcomeBytes = Buffer.from(welcome.welcome, "base64url");
          await tx`
            INSERT INTO mls_welcomes (
              conversation_id, commit_position, commit_envelope_id,
              target_installation_id, welcome_bytes, welcome_sha256,
              created_at, expires_at
            ) VALUES (
              ${conversationId}, 1, ${envelopeId}, ${welcome.installationId},
              ${welcomeBytes},
              ${createHash("sha256").update(welcomeBytes).digest()},
              ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
            )`;
        }
        for (const member of rosterCanonical) {
          const counter = await tx`
            INSERT INTO mailbox_counters (installation_id, last_position)
            VALUES (${member.installationId}, 1)
            ON CONFLICT (installation_id)
            DO UPDATE SET last_position = mailbox_counters.last_position + 1
            RETURNING last_position`;
          await tx`
            INSERT INTO mailbox_entries (
              installation_id, mailbox_position, conversation_id,
              envelope_position, envelope_id, delivery_class, created_at,
              expires_at
            ) VALUES (
              ${member.installationId}, ${String(counter[0].last_position)},
              ${conversationId}, 1, ${envelopeId}, 'commit',
              ${now}::timestamptz, ${envelopeExpiresAt}::timestamptz
            )`;
        }
        await tx`
          UPDATE key_packages SET state = 'used', used_at = ${now}::timestamptz
          WHERE taken_by_plan_id = ${String(plan.plan_id)}`;
        await tx`
          UPDATE conversation_usage SET envelope_count = 1,
            envelope_bytes = ${commitBytes.length},
            updated_at = ${now}::timestamptz
          WHERE conversation_id = ${conversationId}`;
        await tx`
          UPDATE conversation_plans SET consumed_at = ${now}::timestamptz
          WHERE plan_id = ${String(plan.plan_id)}`;
        await tx`
          UPDATE relationships SET active_conversation_id = ${conversationId}
          WHERE relationship_id = ${String(plan.relationship_id)}`;
        await tx`
          INSERT INTO outbox_events (
            aggregate_type, aggregate_id_hash, event_type, payload,
            created_at, available_at
          ) VALUES (
            'conversation',
            ${createHash("sha256").update(conversationId).digest()},
            'conversation-activated',
            ${JSON.stringify({ conversationId })}::jsonb,
            ${now}::timestamptz, ${now}::timestamptz
          )`;
        await insertPageEndProjectionFromRows(tx, conversationId, "1", now);
        await tx`
          INSERT INTO conversation_policy_transitions (
            conversation_id, policy_head_sequence, policy_head_id,
            policy_head_hash, effective_from_position, created_at
          ) VALUES (
            ${conversationId}, ${issued.policyHeadSequence},
            ${issued.policyHeadId},
            ${Buffer.from(issued.policyHeadHash, "base64url")}, 1,
            ${now}::timestamptz
          ) ON CONFLICT DO NOTHING`;
        await tx`
          INSERT INTO delivery_conversation_authority (
            conversation_id, conversation_generation, realm_id,
            snapshot_digest, active_signing_key_id, updated_at
          ) VALUES (
            ${conversationId}, ${generation}, ${SERVICE_REALM_ID},
            ${Buffer.alloc(32)}, ${context.logSigningKeyId},
            ${now}::timestamptz
          )`;
        await refreshCustodySnapshotDigest(tx, conversationId);

        return Object.freeze({
          status: "activated" as const,
          conversationId,
          position: "1" as const,
          headHash,
        });
      });
    },
  });

  function roleCredentialId(installationId: string, conversationId: string): string {
    return stableUuid("role-credential", `${conversationId}:${installationId}`);
  }

  async function projectChainId(
    tx: TransactionSql,
    projectRefId: string,
  ): Promise<string> {
    const rows = await tx`
      SELECT chain_id FROM project_refs WHERE project_ref_id = ${projectRefId}`;
    return String(rows[0].chain_id);
  }
}

function quotaBindingsFor(
  conversationId: string,
  accountId: string,
  installationId: string,
  projectRefId: string,
  windowStartedAt: string,
) {
  const windowStart = new Date(
    Math.floor(Date.parse(windowStartedAt) / 86_400_000) * 86_400_000,
  ).toISOString();
  // Subjects must equal the conversation row's locked scope IDs exactly
  // (state.ts quotaSubjectId): project/tenant use the prefixed scope form.
  const subjects = {
    installation: installationId,
    account: accountId,
    project: `project:${projectRefId}`,
    conversation: conversationId,
    tenant: `tenant:${SERVICE_TENANT_ID}`,
  } as const;
  return (
    ["installation", "account", "project", "conversation", "tenant"] as const
  ).map((scope) => ({
    scope,
    scopeHash: computeApplicationAppendQuotaScopeHash({
      realmId: SERVICE_REALM_ID,
      scope,
      subjectId: subjects[scope],
    }),
    subjectId: subjects[scope],
    quotaName: "application-append",
    windowStartedAt: windowStart,
    windowSeconds: "86400",
    operationLimit: "1000",
    byteLimit: "1048576",
  }));
}

/** The deployment trust context every activation-created conversation
 * binds; the append lane's admission checks requests against it. */
export function serviceTrustContext(provisioningSeed: Buffer) {
  const trustRoot = createHmac("sha256", provisioningSeed)
    .update(`release-trust-root\n${RELEASE_PROFILE_ID}`, "utf8")
    .digest();
  return Object.freeze({
    realmId: SERVICE_REALM_ID,
    releaseProfileId: RELEASE_PROFILE_ID,
    releaseTrustRootDigest: trustRoot.toString("base64url"),
    deliveryLimitsDigest: computeDeliveryLimitsDigest(DELIVERY_LIMITS as never),
    deliveryLimits: DELIVERY_LIMITS,
  });
}

function zeroSetHash(domain: string): Buffer {
  return createHash("sha256").update(domain, "utf8").digest();
}

function b64ToUrl(value: unknown): string {
  return Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
    "base64url",
  );
}
