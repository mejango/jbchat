import { Buffer } from "node:buffer";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import type { FinalityPolicy } from "../authority/finality";
import {
  ADDRESS_B,
  ADDRESS_TERMINAL,
  finalityPolicy,
  hash,
  paymentEvidence,
  paymentPurchaseClaim,
} from "../authority/fixtures.testing";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import {
  createEligibilityStore,
  type EligibilityStore,
} from "./eligibilityStore";
import {
  FIXTURE_ENTITLEMENT_ACCOUNT_ID,
  FIXTURE_ENTITLEMENT_CHAIN_ID,
  FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID,
  FIXTURE_ENTITLEMENT_INSTALLATION_ID,
  FIXTURE_ENTITLEMENT_POLICY_HASH,
  FIXTURE_ENTITLEMENT_POLICY_ID,
  FIXTURE_ENTITLEMENT_PROJECT_REF_ID,
  FIXTURE_ENTITLEMENT_WALLET_REF,
  createFictionalPurchaseVerifier,
  fictionalSignedManifest,
  seedEntitlementFixture,
} from "./entitlementFixture.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const BASE_NOW = "2026-08-14T12:03:00.000Z";

describeStorage("eligibility grants", () => {
  let sql: Sql;
  let store: EligibilityStore;
  let now = BASE_NOW;
  let respond: () => unknown = () => {
    throw new Error("verifier response unscripted");
  };

  const crypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x7c));

  const verifiedResponse = () => ({
    status: "verified",
    claimId: "claim.payment.1",
    evidence: paymentEvidence(),
  });

  const issueInput = (overrides: Record<string, unknown> = {}) => ({
    projectRefId: FIXTURE_ENTITLEMENT_PROJECT_REF_ID,
    installationId: FIXTURE_ENTITLEMENT_INSTALLATION_ID,
    walletRef: FIXTURE_ENTITLEMENT_WALLET_REF,
    policyId: FIXTURE_ENTITLEMENT_POLICY_ID,
    policyRevision: 1,
    policyHash: FIXTURE_ENTITLEMENT_POLICY_HASH,
    claim: paymentPurchaseClaim(),
    terminal: ADDRESS_TERMINAL,
    tierHook: null,
    ...overrides,
  });

  const grantCount = async (): Promise<number> => {
    // Scoped to this fixture's project so a sibling suite writing grants to
    // the shared lab DB in parallel cannot perturb the no-new-lease checks.
    const rows = await sql`
      SELECT count(*)::int AS total FROM eligibility_grants
      WHERE project_ref_id = ${FIXTURE_ENTITLEMENT_PROJECT_REF_ID}`;
    return rows[0].total as number;
  };

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    await seedEntitlementFixture(sql, crypto, BASE_NOW);
    store = createEligibilityStore({
      sql,
      now: () => now,
      crypto,
      purchaseVerifier: createFictionalPurchaseVerifier(() => respond()),
      finalityPolicy: finalityPolicy() as FinalityPolicy,
      manifest: fictionalSignedManifest().manifest,
    });
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("issues a bounded active grant only from a verified parsed receipt", async () => {
    now = BASE_NOW;
    respond = verifiedResponse;
    const issued = await store.issuePurchaseGrant(issueInput());
    expect(issued.status).toBe("issued");
    if (issued.status !== "issued") throw new Error("grant refused");
    expect(issued.capability).toBe("purchase-support");
    expect(Date.parse(issued.validUntil) - Date.parse(now)).toBe(5 * 60 * 1_000);

    const [row] = await sql`
      SELECT * FROM eligibility_grants WHERE grant_id = ${issued.grantId}`;
    expect(row.state).toBe("active");
    expect(row.finality_status).toBe("verified-finalized");
    expect(String(row.account_id)).toBe(FIXTURE_ENTITLEMENT_ACCOUNT_ID);
    expect(String(row.finality_profile_id)).toBe(
      FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID,
    );
    expect(row.source_chain_id).toBe(FIXTURE_ENTITLEMENT_CHAIN_ID);
    expect(String(row.source_block)).toBe("123456");
    expect(
      Buffer.from(row.source_block_hash as Uint8Array).toString("hex"),
    ).toBe("a".repeat(64));
    expect(
      Buffer.from(row.claim_handle_hash as Uint8Array).equals(
        crypto.hmacEligibilityClaimHandle(issued.claimHandle),
      ),
    ).toBe(true);
    expect(
      Buffer.from(row.subject_hash as Uint8Array).toString("hex"),
    ).not.toContain(ADDRESS_B.slice(2));

    const read = await store.readGrantByClaimHandle(issued.claimHandle);
    expect(read.status).toBe("found");
    if (read.status !== "found") throw new Error("grant unreadable");
    expect(read.state).toBe("active");
    expect(read.installationId).toBe(FIXTURE_ENTITLEMENT_INSTALLATION_ID);
  });

  it("writes no lease for ineligible, malformed, or unscripted verdicts", async () => {
    now = BASE_NOW;
    const before = await grantCount();
    respond = () => ({
      status: "ineligible",
      claimId: "claim.payment.1",
      reasonCode: "beneficiary-mismatch",
    });
    await expect(store.issuePurchaseGrant(issueInput())).resolves.toEqual({
      status: "ineligible",
      reasonCode: "beneficiary-mismatch",
    });
    respond = () => ({ status: "verified", claimId: "claim.payment.1" });
    await expect(store.issuePurchaseGrant(issueInput())).resolves.toEqual({
      status: "unavailable",
      reasonCode: "verification-result-malformed",
    });
    respond = () => ({
      status: "eligible-trust-me",
      claimId: "claim.payment.1",
    });
    await expect(store.issuePurchaseGrant(issueInput())).resolves.toEqual({
      status: "unavailable",
      reasonCode: "verification-result-malformed",
    });
    expect(await grantCount()).toBe(before);
  });

  it("refuses unpinned deployments and mismatched policy or subject", async () => {
    now = BASE_NOW;
    const before = await grantCount();
    respond = verifiedResponse;
    await expect(
      store.issuePurchaseGrant(issueInput({ terminal: `0x${"88".repeat(20)}` })),
    ).resolves.toEqual({ status: "refused", reasonCode: "deployment-not-pinned" });
    await expect(
      store.issuePurchaseGrant(issueInput({ policyHash: `0x${"33".repeat(32)}` })),
    ).resolves.toEqual({ status: "refused", reasonCode: "policy-mismatch" });
    await expect(
      store.issuePurchaseGrant(
        issueInput({ walletRef: `eip155:8453:0x${"44".repeat(20)}` }),
      ),
    ).resolves.toEqual({ status: "refused", reasonCode: "malformed-claim" });
    await expect(
      store.issuePurchaseGrant(issueInput({ extra: true })),
    ).resolves.toEqual({ status: "refused", reasonCode: "malformed-claim" });
    expect(await grantCount()).toBe(before);
  });

  it("returns unavailable without a ratified active finality profile", async () => {
    now = BASE_NOW;
    respond = verifiedResponse;
    const before = await grantCount();
    await sql`
      UPDATE chain_finality_profiles SET state = 'paused'
      WHERE finality_profile_id = ${FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID}`;
    try {
      await expect(store.issuePurchaseGrant(issueInput())).resolves.toEqual({
        status: "unavailable",
        reasonCode: "no-ratified-finality-profile",
      });
    } finally {
      await sql`
        UPDATE chain_finality_profiles SET state = 'active'
        WHERE finality_profile_id = ${FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID}`;
    }
    expect(await grantCount()).toBe(before);
  });

  it("suspends live grants on finality loss and revokes on an orphaned anchor", async () => {
    now = BASE_NOW;
    respond = verifiedResponse;
    const issued = await store.issuePurchaseGrant(issueInput());
    if (issued.status !== "issued") throw new Error("grant refused");

    const suspended = await store.suspendGrantsForFinalityLoss(
      FIXTURE_ENTITLEMENT_CHAIN_ID,
    );
    expect(suspended).toBeGreaterThanOrEqual(1);
    const readSuspended = await store.readGrantByClaimHandle(issued.claimHandle);
    expect(readSuspended).toMatchObject({ status: "found", state: "suspended" });

    const revoked = await store.revokeGrantsForOrphanedAnchor(
      FIXTURE_ENTITLEMENT_CHAIN_ID,
      hash("a"),
    );
    expect(revoked).toBeGreaterThanOrEqual(1);
    const [row] = await sql`
      SELECT state, finality_status FROM eligibility_grants
      WHERE grant_id = ${issued.grantId}`;
    expect(row.state).toBe("revoked");
    expect(row.finality_status).toBe("orphaned");
  });

  it("expires leases past the five-minute recheck bound", async () => {
    now = BASE_NOW;
    respond = verifiedResponse;
    const issued = await store.issuePurchaseGrant(issueInput());
    if (issued.status !== "issued") throw new Error("grant refused");
    now = "2026-08-14T12:07:30.000Z";
    expect(
      await store.readGrantByClaimHandle(issued.claimHandle),
    ).toMatchObject({ status: "found", state: "active" });
    now = "2026-08-14T12:09:00.000Z";
    expect(
      await store.readGrantByClaimHandle(issued.claimHandle),
    ).toMatchObject({ status: "found", state: "expired" });
    const swept = await store.sweepExpiredGrants();
    expect(swept).toBeGreaterThanOrEqual(1);
    const [row] = await sql`
      SELECT state FROM eligibility_grants WHERE grant_id = ${issued.grantId}`;
    expect(row.state).toBe("expired");
    now = BASE_NOW;
  });
});
