import { Buffer } from "node:buffer";
import { generateKeyPairSync, randomBytes, sign as signNode } from "node:crypto";
import type { Sql } from "postgres";
import type { CanonicalPurchaseVerifierPort } from "../authority/ports";
import type { IdentityKeyedCryptoPort } from "../identity/identityKeyedCrypto";
import {
  ADDRESS_B,
  ADDRESS_C,
  ADDRESS_HOOK,
  ADDRESS_TERMINAL,
  hash,
} from "../authority/fixtures.testing";
import {
  parseSignedDeploymentManifest,
  type DeploymentManifest,
} from "./deploymentManifest";

export const FIXTURE_ENTITLEMENT_CHAIN_ID = "eip155:8453";
export const FIXTURE_ENTITLEMENT_WALLET_REF = `eip155:8453:${ADDRESS_B}`;
export const FIXTURE_ENTITLEMENT_PROJECT_REF_ID =
  "00000000-0000-4000-8000-00000000e001";
export const FIXTURE_ENTITLEMENT_POLICY_ID =
  "00000000-0000-4000-8000-00000000e002";
export const FIXTURE_ENTITLEMENT_POLICY_HASH = `0x${"e2".repeat(32)}`;
export const FIXTURE_ENTITLEMENT_ACCOUNT_ID =
  "00000000-0000-4000-8000-00000000e003";
export const FIXTURE_ENTITLEMENT_INSTALLATION_ID =
  "00000000-0000-4000-8000-00000000e004";
export const FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID =
  "00000000-0000-4000-8000-00000000e005";
export const FIXTURE_ENTITLEMENT_FINALITY_PROFILE_HASH = Buffer.alloc(32, 0xe5);

/**
 * A fictional signed manifest whose only pinned deployment matches the
 * authority fixtures' base-chain purchase expectation exactly.
 */
export function fictionalSignedManifest(): {
  manifest: DeploymentManifest;
  envelope: unknown;
  signerPublicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const body = {
    kind: "juicebox-deployment-manifest.v1",
    manifestId: "deployments.base.v1",
    adapterRevision: "juicebox-v6-receipt.v1",
    chains: [
      {
        chainId: 8453,
        projectsContract: ADDRESS_C,
        abiDigests: {
          pay: hash("0"),
          hookAfterRecordPay: hash("0"),
          tierMint: hash("0"),
        },
        terminals: [
          { address: ADDRESS_TERMINAL, implementationCodeHash: hash("5") },
        ],
        tierHooks: [{ address: ADDRESS_HOOK, implementationCodeHash: hash("7") }],
      },
    ],
  };
  const canonical = Buffer.from(JSON.stringify(body), "utf8");
  const envelope = {
    manifest: body,
    signature: {
      algorithm: "ed25519",
      signerKeyId: "fictional-manifest-ratifier-1",
      signature: signNode(null, canonical, privateKey).toString("base64url"),
    },
  };
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const signerPublicKey = Buffer.from(jwk.x, "base64url");
  return {
    manifest: parseSignedDeploymentManifest(envelope, signerPublicKey),
    envelope,
    signerPublicKey,
  };
}

/** A verifier whose untrusted output is scripted per call by the test. */
export function createFictionalPurchaseVerifier(
  respond: (input: unknown) => unknown,
): CanonicalPurchaseVerifierPort {
  return Object.freeze({ verify: async (input: unknown) => respond(input) });
}

/**
 * Seeds the relational neighborhood one grant needs: tenant, project ref,
 * policy, enrolled account with a wallet link for the fixture beneficiary,
 * one active installation, and one active finality profile for base.
 */
export async function seedEntitlementFixture(
  sql: Sql,
  crypto: IdentityKeyedCryptoPort,
  now: string,
): Promise<void> {
  const TENANT_ID = "00000000-0000-4000-8000-00000000e006";
  const WALLET_LINK_ID = "00000000-0000-4000-8000-00000000e007";
  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO tenants (
        tenant_id, tenant_public_id, status, embed_state, frame_audience,
        embed_theme_hash, top_level_destinations_hash, kms_key_ref,
        created_at, updated_at
      ) VALUES (
        ${TENANT_ID}, 'fictional-entitlement-tenant', 'active', 'active',
        'https://messages.fictional.example/embed', ${Buffer.alloc(32, 0xe6)},
        ${Buffer.alloc(32, 0xe7)}, 'fictional-kms', ${now}::timestamptz,
        ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO project_refs (
        project_ref_id, tenant_id, protocol, protocol_version, chain_id,
        projects_contract, project_id, canonical_hash, status, created_at
      ) VALUES (
        ${FIXTURE_ENTITLEMENT_PROJECT_REF_ID}, ${TENANT_ID}, 'juicebox', '6',
        ${FIXTURE_ENTITLEMENT_CHAIN_ID},
        ${Buffer.from(ADDRESS_C.slice(2), "hex")}, 9,
        ${Buffer.alloc(32, 0xe8)}, 'active', ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO policies (
        policy_id, policy_revision, project_ref_id, canonical_document,
        policy_hash, created_at
      ) VALUES (
        ${FIXTURE_ENTITLEMENT_POLICY_ID}, 1,
        ${FIXTURE_ENTITLEMENT_PROJECT_REF_ID},
        ${JSON.stringify({ policy: "fictional-support-policy.v1" })}::jsonb,
        ${Buffer.from(FIXTURE_ENTITLEMENT_POLICY_HASH.slice(2), "hex")},
        ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO accounts (account_id, status, created_at)
      VALUES (${FIXTURE_ENTITLEMENT_ACCOUNT_ID}, 'active', ${now}::timestamptz)`;
    await tx`
      INSERT INTO wallet_links (
        wallet_link_id, account_id, wallet_ref_lookup, wallet_ref_ciphertext,
        kms_key_version, status, verified_at
      ) VALUES (
        ${WALLET_LINK_ID}, ${FIXTURE_ENTITLEMENT_ACCOUNT_ID},
        ${crypto.hmacWalletRefLookup(FIXTURE_ENTITLEMENT_WALLET_REF)},
        ${crypto.sealPayload(FIXTURE_ENTITLEMENT_WALLET_REF).ciphertext},
        'keyed-lab-v1', 'active', ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO installations (
        installation_id, account_id, platform, storage_partition_class,
        installation_auth_profile, installation_auth_public_jwk,
        installation_auth_jkt, mls_credential_profile, mls_credential_public,
        mls_credential_fingerprint, status, created_at, last_seen_at
      ) VALUES (
        ${FIXTURE_ENTITLEMENT_INSTALLATION_ID},
        ${FIXTURE_ENTITLEMENT_ACCOUNT_ID}, 'ios', 'top_level',
        'p256-es256-dpop.v1',
        ${JSON.stringify({ kty: "EC", crv: "P-256", x: "x", y: "y" })}::jsonb,
        ${randomBytes(32)}, 'mls-credential-ed25519-suite-0x0001.v1',
        ${randomBytes(32)}, ${randomBytes(32)}, 'active', ${now}::timestamptz,
        ${now}::timestamptz
      )`;
    await tx`
      INSERT INTO chain_finality_profiles (
        finality_profile_id, profile_revision, chain_id, canonical_document,
        profile_hash, adapter_release_id, ratification_evidence_ref, state,
        effective_at, created_at
      ) VALUES (
        ${FIXTURE_ENTITLEMENT_FINALITY_PROFILE_ID}, 1,
        ${FIXTURE_ENTITLEMENT_CHAIN_ID},
        ${JSON.stringify({ profile: "fictional-finality.v1", quorum: 2 })}::jsonb,
        ${FIXTURE_ENTITLEMENT_FINALITY_PROFILE_HASH},
        'fictional-adapter-1.0.0', 'fictional-ratification-record', 'active',
        ${now}::timestamptz, ${now}::timestamptz
      )`;
  });
}
