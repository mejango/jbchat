"use client";

/**
 * Browser MLS core: the frozen-profile Rust client compiled to wasm32
 * (crypto/crates/wasm-client). One client per installation; its whole
 * state - OpenMLS storage map plus the identity - persists in IndexedDB
 * as the wasm module's own versioned snapshot and never leaves the
 * device in any other shape. Every mutating operation persists before
 * returning; a failed persist throws rather than silently forking the
 * ratchet state.
 */

import initWasm, { MlsClient } from "./mlsWasm/jbm_mls_client";
import { idbGet, idbSet } from "./idb";

const MLS_STATE_KEY = "mls-state-v1";

let instance: Promise<MlsClient> | null = null;

function randomLabel(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function loadClient(): Promise<MlsClient> {
  // The glue resolves the wasm beside itself; webpack bundles it as an asset.
  await initWasm();
  const saved = await idbGet<string>(MLS_STATE_KEY);
  if (saved) {
    // A stored snapshot that no longer imports is a hard fault: silently
    // starting fresh would fork every group this device is in.
    return MlsClient.importState(saved);
  }
  const client = new MlsClient(randomLabel());
  await idbSet(MLS_STATE_KEY, client.exportState());
  return client;
}

export function mlsClient(): Promise<MlsClient> {
  if (!instance) {
    instance = loadClient().catch((error: unknown) => {
      instance = null;
      throw error;
    });
  }
  return instance;
}

async function persisted<T>(client: MlsClient, result: T): Promise<T> {
  await idbSet(MLS_STATE_KEY, client.exportState());
  return result;
}

/** Raw 32-byte Ed25519 public key of this device's MLS identity. */
export async function mlsSignaturePublicKey(): Promise<Uint8Array> {
  return (await mlsClient()).signaturePublicKey();
}

/** Serialized MLS KeyPackage message (profile ciphersuite 0x0001). */
export async function generateMlsKeyPackage(): Promise<Uint8Array> {
  const client = await mlsClient();
  return persisted(client, client.generateKeyPackage());
}

export async function createMlsGroup(groupId: Uint8Array): Promise<void> {
  const client = await mlsClient();
  client.createGroup(groupId);
  await persisted(client, undefined);
}

export interface MlsAddMemberResult {
  readonly commit: Uint8Array;
  readonly welcome: Uint8Array;
  readonly epoch: bigint;
  readonly confirmedTranscriptHash: Uint8Array;
}

export async function addMlsMember(
  groupId: Uint8Array,
  keyPackage: Uint8Array,
): Promise<MlsAddMemberResult> {
  const client = await mlsClient();
  const output = client.addMember(groupId, keyPackage);
  return persisted(client, {
    commit: output.commit,
    welcome: output.welcome,
    epoch: output.epoch,
    confirmedTranscriptHash: output.confirmed_transcript_hash,
  });
}

/** Join from a Welcome; returns the group id. */
export async function joinMlsWelcome(welcome: Uint8Array): Promise<Uint8Array> {
  const client = await mlsClient();
  return persisted(client, client.joinFromWelcome(welcome));
}

export async function sealMlsApplication(
  groupId: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const client = await mlsClient();
  return persisted(client, client.sealApplication(groupId, plaintext));
}

export async function openMlsApplication(
  groupId: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const client = await mlsClient();
  return persisted(client, client.openApplication(groupId, message));
}

export async function processMlsCommit(
  groupId: Uint8Array,
  commit: Uint8Array,
): Promise<void> {
  const client = await mlsClient();
  client.processCommit(groupId, commit);
  await persisted(client, undefined);
}

export async function mlsGroupEpoch(groupId: Uint8Array): Promise<bigint> {
  return (await mlsClient()).groupEpoch(groupId);
}

export async function mlsGroupConfirmedTranscriptHash(
  groupId: Uint8Array,
): Promise<Uint8Array> {
  return (await mlsClient()).groupConfirmedTranscriptHash(groupId);
}
