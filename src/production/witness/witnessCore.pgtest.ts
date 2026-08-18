import { Buffer } from "node:buffer";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as signNode,
  verify as verifyNodeSignature,
} from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import { computeDeliveryLogCheckpointDigest } from "../delivery/hashes";
import {
  LAB_CONVERSATION_ID,
  LAB_NOW,
} from "../delivery/fixtures.testing";
import {
  FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW,
  signFictionalDeliveryCheckpointDigestForTesting,
} from "../delivery/fictionalCryptoPorts.testing";
import { leafHash, verifyConsistency, verifyInclusion } from "./merkleLog";
import {
  computeWitnessCheckpointDigest,
  createWitnessCore,
  type WitnessSignerPort,
} from "./witnessCore";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;
const WITNESS_DATABASE = "jbm_witness_lab";
const WITNESS_KEY_ID = "fictional-witness-2026q3";
const WITNESS_MIGRATIONS = new URL(
  "../../../witness/migrations/",
  import.meta.url,
).pathname;

function fictionalWitnessSigner(): {
  port: WitnessSignerPort;
  rawPublicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return {
    port: Object.freeze({
      witnessKeyId: WITNESS_KEY_ID,
      sign: (digest: Buffer) => signNode(null, digest, privateKey),
    }),
    rawPublicKey: Buffer.from(jwk.x, "base64url"),
  };
}

function verifyEd25519Raw(
  rawPublicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): boolean {
  return verifyNodeSignature(
    null,
    message,
    createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        rawPublicKey,
      ]),
      format: "der",
      type: "spki",
    }),
    signature,
  );
}

describeStorage("witness core", () => {
  let deliverySql: Sql;
  let witnessSql: Sql;
  let core: ReturnType<typeof createWitnessCore>;
  let rawWitnessPublicKey: Buffer;

  beforeAll(async () => {
    deliverySql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    await deliverySql.unsafe(`DROP DATABASE IF EXISTS ${WITNESS_DATABASE}`);
    await deliverySql.unsafe(`CREATE DATABASE ${WITNESS_DATABASE}`);
    const witnessUrl = DATABASE_URL!.replace(/[^/]+$/, WITNESS_DATABASE);
    const runner = (await import(
      // @ts-expect-error the migration runner is intentionally untyped .mjs
      /* @vite-ignore */ "../../../scripts/storage/migrate.mjs"
    )) as {
      migrateStorage: (
        databaseUrl: string,
        directory?: string,
        log?: (message: string) => void,
      ) => unknown;
    };
    runner.migrateStorage(witnessUrl, WITNESS_MIGRATIONS, () => {});
    witnessSql = postgres(witnessUrl, { max: 4, onnotice: () => {} });
    const signer = fictionalWitnessSigner();
    rawWitnessPublicKey = signer.rawPublicKey;
    core = createWitnessCore({ sql: witnessSql, signer: signer.port });
    const delivery = await deliverySql`
      SELECT log_signing_key_id FROM envelopes
      WHERE conversation_id = ${LAB_CONVERSATION_ID} AND position = 1`;
    await witnessSql`
      INSERT INTO witness_submitter_keys (
        key_id, public_key, valid_from, valid_until
      ) VALUES (
        ${String(delivery[0].log_signing_key_id)},
        ${Buffer.from(FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_RAW)},
        ${LAB_NOW}::timestamptz - interval '30 days',
        ${LAB_NOW}::timestamptz + interval '30 days'
      )`;
  });

  afterAll(async () => {
    await witnessSql?.end({ timeout: 5 });
    await deliverySql?.end({ timeout: 5 });
  });

  const envelopeSubmission = async (position: number) => {
    const [row] = await deliverySql`
      SELECT envelope_id, encode(previous_head_hash, 'base64') AS previous,
             encode(head_hash, 'base64') AS head, log_signing_key_id,
             encode(log_head_signature, 'base64') AS signature, received_at
      FROM envelopes
      WHERE conversation_id = ${LAB_CONVERSATION_ID}
        AND position = ${position}`;
    const b64url = (value: unknown): string =>
      Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
        "base64url",
      );
    return {
      conversationId: LAB_CONVERSATION_ID,
      position: String(position),
      previousHeadHash: b64url(row.previous),
      headHash: b64url(row.head),
      signingKeyId: String(row.log_signing_key_id),
      signature: b64url(row.signature),
      checkpointReceivedAt: new Date(row.received_at as Date).toISOString(),
    };
  };

  it("cosigns real delivery extensions in order and refuses gaps and forgeries", async () => {
    const genesis = await envelopeSubmission(1);
    const second = await envelopeSubmission(2);

    // Continuity: position 2 before position 1 is not an extension.
    expect(await core.extendDelivery(second)).toEqual({
      status: "rejected",
      reasonCode: "not-an-extension",
    });

    const witnessedGenesis = await core.extendDelivery(genesis);
    expect(witnessedGenesis.status).toBe("witnessed");
    if (witnessedGenesis.status !== "witnessed") throw new Error("unreached");
    expect(witnessedGenesis.receipt.treeSize).toBe("1");
    const digest = computeWitnessCheckpointDigest({
      namespace: "delivery",
      checkpointId: witnessedGenesis.receipt.checkpointId,
      treeSize: witnessedGenesis.receipt.treeSize,
      rootHash: Buffer.from(witnessedGenesis.receipt.rootHash, "base64url"),
      witnessKeyId: witnessedGenesis.receipt.witnessKeyId,
      witnessedAt: witnessedGenesis.receipt.witnessedAt,
    });
    expect(
      verifyEd25519Raw(
        rawWitnessPublicKey,
        digest,
        Buffer.from(witnessedGenesis.receipt.witnessSignature, "base64url"),
      ),
    ).toBe(true);

    // A forged submitter signature is refused before any cosigning.
    expect(
      await core.extendDelivery({
        ...second,
        signature: Buffer.alloc(64, 0x42).toString("base64url"),
      }),
    ).toEqual({
      status: "rejected",
      reasonCode: "submitter-signature-invalid",
    });

    const witnessedSecond = await core.extendDelivery(second);
    expect(witnessedSecond.status).toBe("witnessed");
    expect(await core.extendDelivery(second)).toEqual({
      status: "rejected",
      reasonCode: "already-witnessed",
    });
  });

  it("returns a typed equivocation carrying both heads and stores neither", async () => {
    const second = await envelopeSubmission(2);
    // A validly signed CONFLICTING head at an already-witnessed position is
    // the SEV-0 case: the compromised-or-forked delivery service really
    // signed two different heads for position 2.
    const forgedHead = Buffer.alloc(32, 0xee).toString("base64url");
    const forgedDigest = Buffer.from(
      computeDeliveryLogCheckpointDigest({
        conversationId: second.conversationId,
        position: second.position,
        previousHeadHash: second.previousHeadHash,
        headHash: forgedHead,
        signingKeyId: second.signingKeyId,
      } as Parameters<typeof computeDeliveryLogCheckpointDigest>[0]),
      "base64url",
    );
    const equivocation = await core.extendDelivery({
      ...second,
      headHash: forgedHead,
      signature:
        signFictionalDeliveryCheckpointDigestForTesting(forgedDigest).toString(
          "base64url",
        ),
    });
    expect(equivocation).toEqual({
      status: "equivocation",
      position: "2",
      witnessedHeadHash: second.headHash,
      submittedHeadHash: forgedHead,
    });
    // An unsigned forgery never even reaches the continuity check.
    expect(
      await core.extendDelivery({
        ...second,
        headHash: forgedHead,
        signature: Buffer.alloc(64, 0x42).toString("base64url"),
      }),
    ).toEqual({
      status: "rejected",
      reasonCode: "submitter-signature-invalid",
    });
    // Direct storage-level proof: the UNIQUE (namespace, tree_size) and
    // primary keys make a second head at position 2 unstorable even if
    // code misbehaved.
    await expect(
      witnessSql`
        INSERT INTO witness_delivery_heads (
          conversation_id, position, head_hash, tree_index
        ) VALUES (
          ${LAB_CONVERSATION_ID}, 2, ${Buffer.alloc(32, 0xee)}, 999
        )`,
    ).rejects.toThrow(/duplicate key/);
  });

  it("extends the policy chain exactly and flags a mismatched predecessor", async () => {
    const first = await core.extendChain("policy", {
      checkpointId: "00000000-0000-4000-8000-0000000c0001",
      treeSize: "1",
      rootHash: Buffer.alloc(32, 0xc1).toString("base64url"),
      previousCheckpointId: null,
      signerKeyId: "fictional-policy-signer",
    });
    expect(first.status).toBe("witnessed");
    const wrongPredecessor = await core.extendChain("policy", {
      checkpointId: "00000000-0000-4000-8000-0000000c0002",
      treeSize: "2",
      rootHash: Buffer.alloc(32, 0xc2).toString("base64url"),
      previousCheckpointId: "00000000-0000-4000-8000-0000000c0099",
      signerKeyId: "fictional-policy-signer",
    });
    expect(wrongPredecessor).toMatchObject({ status: "equivocation" });
    const second = await core.extendChain("policy", {
      checkpointId: "00000000-0000-4000-8000-0000000c0002",
      treeSize: "2",
      rootHash: Buffer.alloc(32, 0xc2).toString("base64url"),
      previousCheckpointId: "00000000-0000-4000-8000-0000000c0001",
      signerKeyId: "fictional-policy-signer",
    });
    expect(second.status).toBe("witnessed");
  });

  it("serves verifiable inclusion and consistency proofs", async () => {
    const latest = await core.latestCheckpoint("delivery");
    if (!latest) throw new Error("no delivery checkpoint");
    const size = Number(latest.treeSize);
    expect(size).toBeGreaterThanOrEqual(2);

    const [firstLeaf] = await witnessSql`
      SELECT leaf_payload FROM witness_leaves
      WHERE namespace = 'delivery' AND tree_index = 0`;
    const inclusion = await core.proveInclusion("delivery", "0", latest.treeSize);
    if (!inclusion) throw new Error("no inclusion proof");
    expect(
      verifyInclusion(
        leafHash(Buffer.from(firstLeaf.leaf_payload as Uint8Array)),
        0,
        size,
        inclusion.map((entry) => Buffer.from(entry, "base64url")),
        Buffer.from(latest.rootHash, "base64url"),
      ),
    ).toBe(true);

    const checkpoints = await witnessSql`
      SELECT tree_size, root_hash FROM witness_checkpoints
      WHERE namespace = 'delivery' ORDER BY tree_size`;
    const oldest = checkpoints[0];
    const consistency = await core.proveConsistency(
      "delivery",
      String(oldest.tree_size),
      latest.treeSize,
    );
    if (!consistency) throw new Error("no consistency proof");
    expect(
      verifyConsistency(
        Number(oldest.tree_size),
        Buffer.from(oldest.root_hash as Uint8Array),
        size,
        Buffer.from(latest.rootHash, "base64url"),
        consistency.map((entry) => Buffer.from(entry, "base64url")),
      ),
    ).toBe(true);
  });

  it("detects split views from gossip within the alert channel", async () => {
    const second = await envelopeSubmission(2);
    const latest = await core.latestCheckpoint("delivery");
    if (!latest) throw new Error("no checkpoint");
    const honest = await core.reportGossip({
      conversationId: LAB_CONVERSATION_ID,
      position: "2",
      headHash: second.headHash,
      witnessCheckpointId: latest.checkpointId,
    });
    expect(honest.splitView).toBe(false);
    const before = await core.splitViewCount();
    const conflicting = await core.reportGossip({
      conversationId: LAB_CONVERSATION_ID,
      position: "2",
      headHash: Buffer.alloc(32, 0xdd).toString("base64url"),
      witnessCheckpointId: latest.checkpointId,
    });
    expect(conflicting.splitView).toBe(true);
    expect(await core.splitViewCount()).toBe(before + 1);
  });
});
