import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signNode } from "node:crypto";
import type { Sql } from "postgres";
import type { DeviceCredentialSignerPort } from "./enrollmentStore";
import type { FictionalChainState } from "./walletProofVerifier";

export const FIXTURE_CHAIN_ID = "eip155:99999";
export const FIXTURE_FINALITY_PROFILE_ID =
  "00000000-0000-4000-8000-0000000000f1";
export const FIXTURE_FINALITY_PROFILE_HASH = Buffer.alloc(32, 0xf1);

/** Fictional finality facts matching the seeded chain_finality_profiles row. */
export function fixtureChainState(
  contractAddresses: readonly string[] = [],
): FictionalChainState {
  return {
    contractAddresses,
    finalityProfileId: FIXTURE_FINALITY_PROFILE_ID,
    finalityProfileRevision: "1",
    finalityProfileHash: FIXTURE_FINALITY_PROFILE_HASH,
    finalizedChainId: FIXTURE_CHAIN_ID,
    finalizedBlock: "123456",
    finalizedBlockHash: Buffer.alloc(32, 0xf2),
    providerQuorumHash: Buffer.alloc(32, 0xf3),
  };
}

/** Seeds the one active fictional finality profile the completion FK requires. */
export async function seedIdentityFixture(sql: Sql, now: string): Promise<void> {
  await sql`
    INSERT INTO chain_finality_profiles (
      finality_profile_id, profile_revision, chain_id, canonical_document,
      profile_hash, adapter_release_id, ratification_evidence_ref, state,
      effective_at, created_at
    ) VALUES (
      ${FIXTURE_FINALITY_PROFILE_ID}, 1, ${FIXTURE_CHAIN_ID},
      ${JSON.stringify({ profile: "fictional-finality.v1", confirmations: 64 })}::jsonb,
      ${FIXTURE_FINALITY_PROFILE_HASH}, 'fictional-adapter-1.0.0',
      'fictional-ratification-record', 'active', ${now}::timestamptz,
      ${now}::timestamptz
    ) ON CONFLICT (finality_profile_id, profile_revision) DO NOTHING`;
}

/** Ed25519 signer standing in for the KMS-held device-credential issuer key. */
export function createFictionalDeviceCredentialSigner(): DeviceCredentialSignerPort {
  const { privateKey } = generateKeyPairSync("ed25519");
  return Object.freeze({
    signerKeyId: "fictional-device-credential-signer-1",
    sign: (payload: Buffer) => signNode(null, payload, privateKey),
  });
}
