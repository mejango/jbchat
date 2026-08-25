import { Buffer } from "node:buffer";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { LAB_CONVERSATION_ID } from "../delivery/fixtures.testing";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
import {
  issueRelayGrant,
  suspendGrantsForFinalityLoss,
  sweepExpiredGrants,
} from "../entitlement/eligibilityStore";
import { provisionProjectMessaging } from "./appendAuthority";
import {
  createRelayInstallationStore,
  RELAY_KEY_PACKAGE_KIND,
  relayStateAad,
} from "./relayInstallationStore";
import { fictionalRelayBridgeForTesting } from "./relayBridge.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const NOW = "2026-08-14T16:21:30.000Z";
// a5xx: this suite's fixture family.
const SERVED_ACCOUNT = "00000000-0000-4000-8000-00000000a501";

describeStorage("relay installations", () => {
  let sql: Sql;
  let projectRefId: string;
  const seal = createKeyedIdentityCrypto(Buffer.alloc(32, 0x5f));
  const bridge = fictionalRelayBridgeForTesting();
  const store = () => createRelayInstallationStore({ sql, bridge, seal });

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 2, onnotice: () => {} });
    await sql`
      INSERT INTO accounts (account_id, status, created_at)
      VALUES (${SERVED_ACCOUNT}, 'active', ${NOW}::timestamptz)`;
    const [conversation] = await sql`
      SELECT project_ref_id FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    projectRefId = String(conversation.project_ref_id);
    await sql.begin((tx) =>
      provisionProjectMessaging(tx, Buffer.alloc(32, 0x63), projectRefId, NOW),
    );
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("provisions a relay with a sealed state and a relay-kind KeyPackage", async () => {
    const provisioned = await store().provision({
      servedAccountId: SERVED_ACCOUNT,
      channelKind: "telegram",
    });
    expect(provisioned.created).toBe(true);
    const [installation] = await sql`
      SELECT platform, status, account_id FROM installations
      WHERE installation_id = ${provisioned.relayInstallationId}`;
    expect(installation).toMatchObject({ platform: "desktop", status: "active" });
    expect(String(installation.account_id)).toBe(provisioned.relayAccountId);
    const packages = await sql`
      SELECT package_kind, device_credential_id, state FROM key_packages
      WHERE installation_id = ${provisioned.relayInstallationId}`;
    expect(packages).toHaveLength(1);
    expect(packages[0]).toMatchObject({
      package_kind: RELAY_KEY_PACKAGE_KIND,
      device_credential_id: null,
      state: "available",
    });
    const [relay] = await sql`
      SELECT mls_state_ciphertext, kms_key_version, state
      FROM relay_installations
      WHERE relay_installation_id = ${provisioned.relayInstallationId}`;
    expect(String(relay.state)).toBe("active");
    const opened = JSON.parse(
      seal.openPayloadBound(
        Buffer.from(relay.mls_state_ciphertext as Uint8Array),
        String(relay.kms_key_version),
        relayStateAad(provisioned.relayInstallationId),
      ),
    ) as { packages: number };
    // The sealed snapshot is the post-KeyPackage state, never the bare identity.
    expect(opened.packages).toBe(1);

    // A second call reuses the seat and leaves the shelf alone.
    const again = await store().provision({
      servedAccountId: SERVED_ACCOUNT,
      channelKind: "telegram",
    });
    expect(again).toEqual({ ...provisioned, created: false });
    expect(bridge.calls.filter((call) => call.startsWith("kp:"))).toHaveLength(1);

    // Once the shelf is consumed, provisioning tops it up and reseals.
    await sql`
      UPDATE key_packages SET expires_at = ${NOW}::timestamptz - interval '1 second'
      WHERE installation_id = ${provisioned.relayInstallationId}`;
    await store().provision({
      servedAccountId: SERVED_ACCOUNT,
      channelKind: "telegram",
    });
    const shelf = await sql`
      SELECT 1 FROM key_packages
      WHERE installation_id = ${provisioned.relayInstallationId}
        AND state = 'available' AND expires_at > ${NOW}::timestamptz`;
    expect(shelf).toHaveLength(1);
    const [resealed] = await sql`
      SELECT mls_state_ciphertext, kms_key_version FROM relay_installations
      WHERE relay_installation_id = ${provisioned.relayInstallationId}`;
    expect(
      (
        JSON.parse(
          seal.openPayloadBound(
            Buffer.from(resealed.mls_state_ciphertext as Uint8Array),
            String(resealed.kms_key_version),
            relayStateAad(provisioned.relayInstallationId),
          ),
        ) as { packages: number }
      ).packages,
    ).toBe(2);
    expect(await store().activeFor(SERVED_ACCOUNT, "telegram")).toEqual({
      relayInstallationId: provisioned.relayInstallationId,
      relayAccountId: provisioned.relayAccountId,
    });
  });

  it("mints a channel-relay grant with no finality anchor that sweepers leave alone", async () => {
    const relay = (await store().activeFor(SERVED_ACCOUNT, "telegram"))!;
    const issued = await issueRelayGrant(
      sql,
      seal,
      {
        projectRefId,
        relayAccountId: relay.relayAccountId,
        relayInstallationId: relay.relayInstallationId,
        servedAccountId: SERVED_ACCOUNT,
        channelKind: "telegram",
      },
      NOW,
    );
    if (issued.status !== "issued") throw new Error(issued.reasonCode);
    expect(issued.claimHandle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const [grant] = await sql`
      SELECT capability, finality_status, finality_profile_id, source_chain_id,
             state, account_id, installation_id
      FROM eligibility_grants WHERE grant_id = ${issued.grantId}`;
    expect(grant).toMatchObject({
      capability: "channel-relay",
      finality_status: "not-applicable",
      finality_profile_id: null,
      source_chain_id: null,
      state: "active",
    });
    expect(String(grant.account_id)).toBe(relay.relayAccountId);
    expect(String(grant.installation_id)).toBe(relay.relayInstallationId);

    // A wrong served account / channel never mints.
    const refused = await issueRelayGrant(
      sql,
      seal,
      {
        projectRefId,
        relayAccountId: relay.relayAccountId,
        relayInstallationId: relay.relayInstallationId,
        servedAccountId: "00000000-0000-4000-8000-00000000a502",
        channelKind: "telegram",
      },
      NOW,
    );
    expect(refused).toEqual({ status: "refused", reasonCode: "relay-not-active" });

    // Finality lifecycles never touch a relay grant; expiry does.
    for (const chain of ["eip155:99999", "eip155:8453"]) {
      await suspendGrantsForFinalityLoss(sql, chain, NOW);
    }
    const [still] = await sql`
      SELECT state FROM eligibility_grants WHERE grant_id = ${issued.grantId}`;
    expect(String(still.state)).toBe("active");
    await sweepExpiredGrants(sql, "2026-08-14T16:30:00.000Z");
    const [expired] = await sql`
      SELECT state FROM eligibility_grants WHERE grant_id = ${issued.grantId}`;
    expect(String(expired.state)).toBe("expired");
  });

  it("revokes the relay and its shelf in one step", async () => {
    const relay = (await store().activeFor(SERVED_ACCOUNT, "telegram"))!;
    expect(await store().revoke(relay.relayInstallationId)).toBe(true);
    expect(await store().activeFor(SERVED_ACCOUNT, "telegram")).toBeNull();
    const [installation] = await sql`
      SELECT status FROM installations
      WHERE installation_id = ${relay.relayInstallationId}`;
    expect(String(installation.status)).toBe("revoked");
    const available = await sql`
      SELECT 1 FROM key_packages
      WHERE installation_id = ${relay.relayInstallationId} AND state = 'available'`;
    expect(available).toHaveLength(0);
    expect(await store().revoke(relay.relayInstallationId)).toBe(false);
  });
});
