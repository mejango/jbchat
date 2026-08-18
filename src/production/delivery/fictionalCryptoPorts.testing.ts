import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  verify as verifyEd25519,
} from "node:crypto";
import { computeDeliveryLogCheckpointDigest } from "./hashes";
import { parseApplicationEnvelopeReceipt } from "./service";

export { parsePolicyEvidenceForSnapshot } from "./appendPersistence";


import {
  createKeyedDeliveryCryptoPorts,
  type KeyedDeliveryCryptoContext,
  type KeyedDeliveryCryptoPorts,
} from "./deliveryCryptoPorts";

export type {
  DeliveryLabSignerHistoryEntry,
} from "./deliveryCryptoPorts";
export type FictionalDeliveryCryptoContext = Omit<
  KeyedDeliveryCryptoContext,
  "privateKey" | "publicKey"
>;
export type FictionalDeliveryCryptoPorts = KeyedDeliveryCryptoPorts;

const FICTIONAL_ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const FICTIONAL_ED25519_SEED = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
);
const FICTIONAL_DELIVERY_LAB_PRIVATE_KEY = createPrivateKey({
  key: Buffer.concat([FICTIONAL_ED25519_PKCS8_PREFIX, FICTIONAL_ED25519_SEED]),
  format: "der",
  type: "pkcs8",
});
const FICTIONAL_DELIVERY_LAB_PUBLIC_KEY = createPublicKey(
  FICTIONAL_DELIVERY_LAB_PRIVATE_KEY,
);
export const FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL =
  FICTIONAL_DELIVERY_LAB_PUBLIC_KEY.export({
    format: "der",
    type: "spki",
  }).toString("base64url");

export const FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW = Buffer.from(
  FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL,
  "base64url",
).subarray(-32);

/** Signs a raw 32-byte delivery checkpoint digest with the lab key. */
export function signFictionalDeliveryCheckpointDigestForTesting(
  digest: Buffer,
): Buffer {
  return signEd25519(null, digest, FICTIONAL_DELIVERY_LAB_PRIVATE_KEY);
}

export function verifyFictionalDeliveryLabReceiptSignatureForTesting(
  value: unknown,
): boolean {
  try {
    const receipt = parseApplicationEnvelopeReceipt(value);
    const digest = computeDeliveryLogCheckpointDigest({
      conversationId: receipt.conversationId,
      position: receipt.position,
      previousHeadHash: receipt.logHead.previousHeadHash,
      headHash: receipt.logHead.headHash,
      signingKeyId: receipt.logHead.signingKeyId,
    });
    return (
      digest === receipt.logHead.checkpointDigest &&
      verifyEd25519(
        null,
        Buffer.from(digest, "base64url"),
        FICTIONAL_DELIVERY_LAB_PUBLIC_KEY,
        Buffer.from(receipt.logHead.signature, "base64url"),
      )
    );
  } catch {
    return false;
  }
}

export function fictionalDeliveryLabKeyPairForTesting(): {
  readonly privateKey: import("node:crypto").KeyObject;
  readonly publicKey: import("node:crypto").KeyObject;
} {
  return Object.freeze({
    privateKey: FICTIONAL_DELIVERY_LAB_PRIVATE_KEY,
    publicKey: FICTIONAL_DELIVERY_LAB_PUBLIC_KEY,
  });
}

export function createFictionalDeliveryCryptoPorts(
  context: FictionalDeliveryCryptoContext,
): FictionalDeliveryCryptoPorts {
  return createKeyedDeliveryCryptoPorts({
    ...context,
    privateKey: FICTIONAL_DELIVERY_LAB_PRIVATE_KEY,
    publicKey: FICTIONAL_DELIVERY_LAB_PUBLIC_KEY,
  });
}
