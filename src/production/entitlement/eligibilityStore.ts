import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import type { Sql } from "postgres";
import type { FinalityPolicy } from "../authority/finality";
import type { CanonicalPurchaseVerifierPort } from "../authority/ports";
import {
  parseCanonicalPurchaseVerificationExpectation,
  parseCanonicalPurchaseVerificationResult,
  type CanonicalPurchaseVerificationExpectation,
  type VerifiedCanonicalPurchaseVerificationResult,
} from "../authority/purchases";
import { parseWalletRef } from "../identity/identityCrypto";
import type { IdentityKeyedCryptoPort } from "../identity/identityKeyedCrypto";
import {
  resolvePurchaseDeployment,
  type DeploymentManifest,
} from "./deploymentManifest";

const GRANT_LEASE_MILLISECONDS = 5 * 60 * 1_000;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH_PATTERN = /^0x[0-9a-f]{64}$/;

export interface EligibilityStoreContext {
  readonly sql: Sql;
  readonly now: () => string;
  readonly crypto: IdentityKeyedCryptoPort;
  readonly purchaseVerifier: CanonicalPurchaseVerifierPort;
  readonly finalityPolicy: FinalityPolicy;
  readonly manifest: DeploymentManifest;
}

export type PurchaseGrantIssueResult =
  | {
      readonly status: "issued";
      readonly grantId: string;
      readonly claimHandle: string;
      readonly capability: "purchase-support" | "item-set-buyer";
      readonly issuedAt: string;
      readonly validUntil: string;
    }
  | { readonly status: "refused"; readonly reasonCode: string }
  | { readonly status: "ineligible"; readonly reasonCode: string }
  | {
      readonly status: "pending-finality";
      readonly reasonCode: "receipt-above-finalized-head";
    }
  | { readonly status: "unavailable"; readonly reasonCode: string };

export type GrantReadResult =
  | {
      readonly status: "found";
      readonly grantId: string;
      readonly state: "active" | "suspended" | "revoked" | "expired";
      readonly capability: string;
      readonly accountId: string;
      readonly installationId: string;
      readonly projectRefId: string;
      readonly validUntil: string;
    }
  | { readonly status: "unknown" };

export type RelayGrantIssueResult =
  | {
      readonly status: "issued";
      readonly grantId: string;
      readonly claimHandle: string;
      readonly capability: "channel-relay";
      readonly issuedAt: string;
      readonly validUntil: string;
    }
  | { readonly status: "refused"; readonly reasonCode: string };

export interface RelayGrantInput {
  readonly projectRefId: string;
  readonly relayAccountId: string;
  readonly relayInstallationId: string;
  readonly servedAccountId: string;
  readonly channelKind: string;
}

export interface EligibilityStore {
  readonly issuePurchaseGrant: (input: unknown) => Promise<PurchaseGrantIssueResult>;
  /**
   * ADR 0006 consent grant: a channel-relay lease bound to the relay's
   * service account, minted only under the served member's session (the
   * HTTP layer proves that); it carries no finality anchor by design.
   */
  readonly issueRelayGrant: (input: RelayGrantInput) => Promise<RelayGrantIssueResult>;
  readonly readGrantByClaimHandle: (handle: unknown) => Promise<GrantReadResult>;
  readonly suspendGrantsForFinalityLoss: (chainId: string) => Promise<number>;
  readonly revokeGrantsForOrphanedAnchor: (
    chainId: string,
    blockHash: string,
  ) => Promise<number>;
  readonly sweepExpiredGrants: () => Promise<number>;
}

/**
 * The eligibility_grants transaction (storage-and-retention.md section on
 * eligibility issuance): a bounded lease exists only after the strict
 * purchase-verification parser accepts a verified result AND the exact
 * project policy row, active installation, and one ratified active finality
 * profile for the source chain are locked in the same transaction that
 * writes the grant with its finality anchor. Every other outcome — refused
 * input, ineligible, pending-finality, unavailable, unpinned deployment,
 * unknown subject — writes no row. Claim handles are returned once and
 * stored only as purpose-separated keyed hashes. Loss of finality
 * availability suspends live grants; an orphaned anchor revokes them.
 * project-staff and token-holder direct resolution need real chain reads
 * and stay with the fail-closed unavailable adapters.
 */
export function createEligibilityStore(
  context: EligibilityStoreContext,
): EligibilityStore {
  const { sql, crypto } = context;
  const nowIso = (): string => {
    const value = context.now();
    if (new Date(value).toISOString() !== value) {
      throw new TypeError("Eligibility clock must be canonical UTC ISO time.");
    }
    return value;
  };

  return Object.freeze({
    async issuePurchaseGrant(inputValue: unknown): Promise<PurchaseGrantIssueResult> {
      let claim: CanonicalPurchaseVerificationExpectation["claim"];
      let expectation: CanonicalPurchaseVerificationExpectation;
      let walletCaip10: string;
      let walletAddress: string;
      let projectRefId: string;
      let installationId: string;
      let policyId: string;
      let policyRevision: number;
      let policyHash: Buffer;
      const now = nowIso();
      try {
        const record = expectExactRecord(inputValue, [
          "projectRefId",
          "installationId",
          "walletRef",
          "policyId",
          "policyRevision",
          "policyHash",
          "claim",
          "terminal",
          "tierHook",
        ]);
        projectRefId = expectUuid(record.projectRefId);
        installationId = expectUuid(record.installationId);
        policyId = expectUuid(record.policyId);
        if (
          typeof record.policyRevision !== "number" ||
          !Number.isSafeInteger(record.policyRevision) ||
          record.policyRevision < 1
        ) {
          throw new TypeError("The policy revision is malformed.");
        }
        policyRevision = record.policyRevision;
        policyHash = expectHashBytes(record.policyHash);
        const candidateClaim = record.claim as CanonicalPurchaseVerificationExpectation["claim"];
        const chainId = candidateClaim?.project?.chainId;
        if (typeof chainId !== "number") {
          throw new TypeError("The purchase claim carries no chain.");
        }
        const wallet = parseWalletRef(record.walletRef, [`eip155:${chainId}`]);
        walletCaip10 = wallet.caip10;
        walletAddress = wallet.address;
        if (
          typeof record.terminal !== "string" ||
          (record.tierHook !== null && typeof record.tierHook !== "string")
        ) {
          throw new TypeError("The deployment selection is malformed.");
        }
        const deployment = resolvePurchaseDeployment(context.manifest, {
          chainId,
          terminal: record.terminal,
          tierHook: record.tierHook,
        });
        if (!deployment) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "deployment-not-pinned",
          });
        }
        expectation = parseCanonicalPurchaseVerificationExpectation({
          claim: candidateClaim,
          deployment,
          now,
        });
        claim = expectation.claim;
        if (
          claim.expectedBeneficiary.toLowerCase() !== walletAddress ||
          claim.project.deploymentManifestId !== context.manifest.manifestId
        ) {
          throw new TypeError("The claim does not bind the presented subject.");
        }
      } catch {
        return Object.freeze({
          status: "refused" as const,
          reasonCode: "malformed-claim",
        });
      }

      let verified: VerifiedCanonicalPurchaseVerificationResult;
      try {
        const raw = await context.purchaseVerifier.verify({
          expectation,
          policy: context.finalityPolicy,
        });
        const result = parseCanonicalPurchaseVerificationResult(
          raw,
          context.finalityPolicy,
          expectation,
        );
        if (result.status === "ineligible") {
          return Object.freeze({
            status: "ineligible" as const,
            reasonCode: result.reasonCode,
          });
        }
        if (result.status === "pending-finality") {
          return Object.freeze({
            status: "pending-finality" as const,
            reasonCode: "receipt-above-finalized-head" as const,
          });
        }
        if (result.status === "unavailable") {
          return Object.freeze({
            status: "unavailable" as const,
            reasonCode: result.reasonCode,
          });
        }
        verified = result;
      } catch {
        return Object.freeze({
          status: "unavailable" as const,
          reasonCode: "verification-result-malformed",
        });
      }

      const evidence = verified.evidence;
      if (evidence.customerAccount.toLowerCase() !== walletAddress) {
        return Object.freeze({
          status: "refused" as const,
          reasonCode: "subject-mismatch",
        });
      }
      const capability =
        claim.kind === "juicebox-v6-payment-beneficiary-claim.v1"
          ? ("purchase-support" as const)
          : ("item-set-buyer" as const);
      const sourceChainId = `eip155:${claim.project.chainId}`;
      const block = evidence.receipt.block;
      const finalityEvidenceDigest = sha256(
        JSON.stringify({
          evidenceId: evidence.evidenceId,
          receiptDigest: evidence.receipt.receiptDigest,
          blockNumber: block.blockNumber,
          blockHash: block.blockHash,
          providerIds: block.providerIds,
          adapterRevision: expectation.deployment.adapterRevision,
          manifestId: context.manifest.manifestId,
        }),
      );

      return sql.begin(async (tx) => {
        const projectRows = await tx`
          SELECT chain_id, projects_contract, project_id::text AS project_id
          FROM project_refs
          WHERE project_ref_id = ${projectRefId} AND status = 'active'
          FOR SHARE`;
        if (
          projectRows.length !== 1 ||
          String(projectRows[0].chain_id) !== sourceChainId ||
          `0x${Buffer.from(projectRows[0].projects_contract as Uint8Array).toString("hex")}` !==
            claim.project.projectsContract.toLowerCase() ||
          String(projectRows[0].project_id) !== String(claim.project.projectId)
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "project-ref-mismatch",
          });
        }
        const policyRows = await tx`
          SELECT policy_hash FROM policies
          WHERE policy_id = ${policyId} AND policy_revision = ${policyRevision}
            AND project_ref_id = ${projectRefId} AND superseded_at IS NULL
          FOR SHARE`;
        if (
          policyRows.length !== 1 ||
          !Buffer.from(policyRows[0].policy_hash as Uint8Array).equals(policyHash)
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "policy-mismatch",
          });
        }
        const linkRows = await tx`
          SELECT account_id FROM wallet_links
          WHERE wallet_ref_lookup = ${crypto.hmacWalletRefLookup(walletCaip10)}
            AND status = 'active'`;
        if (linkRows.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "unknown-subject",
          });
        }
        const accountId = String(linkRows[0].account_id);
        const installationRows = await tx`
          SELECT 1 FROM installations
          WHERE installation_id = ${installationId} AND account_id = ${accountId}
            AND status = 'active'`;
        if (installationRows.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "installation-not-active",
          });
        }
        const profileRows = await tx`
          SELECT finality_profile_id, profile_revision, profile_hash
          FROM chain_finality_profiles
          WHERE chain_id = ${sourceChainId} AND state = 'active'
          FOR SHARE`;
        if (profileRows.length !== 1) {
          return Object.freeze({
            status: "unavailable" as const,
            reasonCode: "no-ratified-finality-profile",
          });
        }
        const profile = profileRows[0];
        const grantId = uuidV7(now);
        const claimHandle = randomBytes(32).toString("base64url");
        const validUntil = new Date(
          Date.parse(now) + GRANT_LEASE_MILLISECONDS,
        ).toISOString();
        await tx`
          INSERT INTO eligibility_grants (
            grant_id, project_ref_id, account_id, installation_id, capability,
            policy_id, policy_revision, policy_hash, subject_hash,
            claim_handle_hash, finality_profile_id, finality_profile_revision,
            finality_profile_hash, finality_evidence_digest, source_chain_id,
            source_block, source_block_hash, finality_status, state, issued_at,
            valid_until
          ) VALUES (
            ${grantId}, ${projectRefId}, ${accountId}, ${installationId},
            ${capability}, ${policyId}, ${policyRevision}, ${policyHash},
            ${crypto.hmacEligibilitySubject(walletCaip10)},
            ${crypto.hmacEligibilityClaimHandle(claimHandle)},
            ${String(profile.finality_profile_id)},
            ${String(profile.profile_revision)},
            ${Buffer.from(profile.profile_hash as Uint8Array)},
            ${finalityEvidenceDigest}, ${sourceChainId},
            ${block.blockNumber}, ${hashBytes(block.blockHash)},
            'verified-finalized', 'active', ${now}::timestamptz,
            ${validUntil}::timestamptz
          )`;
        return Object.freeze({
          status: "issued" as const,
          grantId,
          claimHandle,
          capability,
          issuedAt: now,
          validUntil,
        });
      });
    },

    async issueRelayGrant(input: RelayGrantInput): Promise<RelayGrantIssueResult> {
      return issueRelayGrant(sql, crypto, input, nowIso());
    },

    async readGrantByClaimHandle(handleValue: unknown): Promise<GrantReadResult> {
      if (typeof handleValue !== "string" || !HANDLE_PATTERN.test(handleValue)) {
        return Object.freeze({ status: "unknown" });
      }
      const rows = await sql`
        SELECT grant_id, state, capability, account_id, installation_id,
               project_ref_id, valid_until
        FROM eligibility_grants
        WHERE claim_handle_hash = ${crypto.hmacEligibilityClaimHandle(handleValue)}`;
      if (rows.length !== 1) return Object.freeze({ status: "unknown" });
      const row = rows[0];
      const state = String(row.state) as "active" | "suspended" | "revoked" | "expired";
      const validUntil = new Date(row.valid_until as string | Date).toISOString();
      return Object.freeze({
        status: "found",
        grantId: String(row.grant_id),
        state: state === "active" && nowIso() >= validUntil ? "expired" : state,
        capability: String(row.capability),
        accountId: String(row.account_id),
        installationId: String(row.installation_id),
        projectRefId: String(row.project_ref_id),
        validUntil,
      });
    },

    async suspendGrantsForFinalityLoss(chainId: string): Promise<number> {
      return suspendGrantsForFinalityLoss(sql, chainId, nowIso());
    },

    async revokeGrantsForOrphanedAnchor(
      chainId: string,
      blockHash: string,
    ): Promise<number> {
      return revokeGrantsForOrphanedAnchor(sql, chainId, blockHash, nowIso());
    },

    async sweepExpiredGrants(): Promise<number> {
      return sweepExpiredGrants(sql, nowIso());
    },
  });
}

/**
 * ADR 0006 consent grant, callable without the purchase lane (no manifest,
 * no chain): the HTTP layer proves the served member's session before
 * calling; the row binds the relay's service account and carries no
 * finality anchor (migration 0025).
 */
export async function issueRelayGrant(
sql: Sql,
crypto: IdentityKeyedCryptoPort,
input: RelayGrantInput,
now: string,
): Promise<RelayGrantIssueResult> {
    return sql.begin(async (tx) => {
      const policies = await tx`
        SELECT policy_id, policy_revision, policy_hash FROM policies
        WHERE project_ref_id = ${input.projectRefId}
          AND superseded_at IS NULL
        ORDER BY policy_revision DESC LIMIT 1 FOR SHARE`;
      if (policies.length !== 1) {
        return Object.freeze({
          status: "refused" as const,
          reasonCode: "project-policy-unavailable",
        });
      }
      const relay = await tx`
        SELECT 1 FROM relay_installations r
        JOIN installations i ON i.installation_id = r.relay_installation_id
        WHERE r.relay_installation_id = ${input.relayInstallationId}
          AND r.served_account_id = ${input.servedAccountId}
          AND r.channel_kind = ${input.channelKind}
          AND r.state = 'active'
          AND i.account_id = ${input.relayAccountId}
          AND i.status = 'active'`;
      if (relay.length !== 1) {
        return Object.freeze({
          status: "refused" as const,
          reasonCode: "relay-not-active",
        });
      }
      const grantId = uuidV7(now);
      const claimHandle = randomBytes(32).toString("base64url");
      const validUntil = new Date(
        Date.parse(now) + GRANT_LEASE_MILLISECONDS,
      ).toISOString();
      await tx`
        INSERT INTO eligibility_grants (
          grant_id, project_ref_id, account_id, installation_id, capability,
          policy_id, policy_revision, policy_hash, subject_hash,
          claim_handle_hash, finality_status, state, issued_at, valid_until
        ) VALUES (
          ${grantId}, ${input.projectRefId}, ${input.relayAccountId},
          ${input.relayInstallationId}, 'channel-relay',
          ${String(policies[0].policy_id)},
          ${String(policies[0].policy_revision)},
          ${Buffer.from(policies[0].policy_hash as Uint8Array)},
          ${crypto.hmacRelaySubject(input.servedAccountId, input.channelKind)},
          ${crypto.hmacEligibilityClaimHandle(claimHandle)},
          'not-applicable', 'active', ${now}::timestamptz,
          ${validUntil}::timestamptz
        )`;
      return Object.freeze({
        status: "issued" as const,
        grantId,
        claimHandle,
        capability: "channel-relay" as const,
        issuedAt: now,
        validUntil,
      });
    });
  }

/** Standalone grant-lifecycle transitions shared with the recheck keeper. */
export async function suspendGrantsForFinalityLoss(
  sql: Sql,
  chainId: string,
  now: string,
): Promise<number> {
  const rows = await sql`
    UPDATE eligibility_grants
    SET state = 'suspended', finality_status = 'unavailable',
        suspended_at = ${now}::timestamptz
    WHERE source_chain_id = ${chainId} AND state = 'active'
      AND capability <> 'channel-relay'
    RETURNING grant_id`;
  return rows.length;
}

export async function revokeGrantsForOrphanedAnchor(
  sql: Sql,
  chainId: string,
  blockHash: string,
  now: string,
): Promise<number> {
  const rows = await sql`
    UPDATE eligibility_grants
    SET state = 'revoked', finality_status = 'orphaned',
        revoked_at = ${now}::timestamptz
    WHERE source_chain_id = ${chainId}
      AND source_block_hash = ${hashBytes(blockHash)}
      AND state IN ('active', 'suspended')
      AND capability <> 'channel-relay'
    RETURNING grant_id`;
  return rows.length;
}

export async function sweepExpiredGrants(sql: Sql, now: string): Promise<number> {
  const rows = await sql`
    UPDATE eligibility_grants SET state = 'expired'
    WHERE state = 'active' AND valid_until <= ${now}::timestamptz
    RETURNING grant_id`;
  return rows.length;
}

function expectExactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Eligibility input must be a plain record.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new TypeError("Eligibility input has an unexpected shape.");
  }
  return value as Record<string, unknown>;
}

function expectUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new TypeError("Expected a lowercase UUID.");
  }
  return value;
}

function expectHashBytes(value: unknown): Buffer {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new TypeError("Expected a 0x-prefixed 32-byte hash.");
  }
  return Buffer.from(value.slice(2), "hex");
}

function hashBytes(value: string): Buffer {
  if (!HASH_PATTERN.test(value)) {
    throw new TypeError("Expected a 0x-prefixed 32-byte hash.");
  }
  return Buffer.from(value.slice(2), "hex");
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function uuidV7(nowIsoValue: string): string {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.parse(nowIsoValue));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((milliseconds >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
