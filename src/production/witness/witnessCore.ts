import { Buffer } from "node:buffer";
import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifyNodeSignature,
} from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import { computeDeliveryLogCheckpointDigest } from "../delivery/hashes";
import {
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
} from "./merkleLog";

export const WITNESS_CHECKPOINT_DOMAIN = "jb-msg-witness-checkpoint/v1";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ZERO_HASH_32 = Buffer.alloc(32);

export type WitnessNamespace = "delivery" | "policy" | "directory";

export interface WitnessSignerPort {
  readonly witnessKeyId: string;
  readonly sign: (checkpointDigest: Buffer) => Buffer;
}

export interface WitnessCheckpoint {
  readonly checkpointId: string;
  readonly namespace: WitnessNamespace;
  readonly treeSize: string;
  readonly rootHash: string;
  readonly witnessKeyId: string;
  readonly witnessSignature: string;
  readonly witnessedAt: string;
}

export type DeliveryExtensionResult =
  | { readonly status: "witnessed"; readonly receipt: WitnessCheckpoint }
  | {
      readonly status: "equivocation";
      readonly position: string;
      readonly witnessedHeadHash: string;
      readonly submittedHeadHash: string;
    }
  | { readonly status: "rejected"; readonly reasonCode: string };

export type ChainExtensionResult =
  | { readonly status: "witnessed"; readonly receipt: WitnessCheckpoint }
  | {
      readonly status: "equivocation";
      readonly expectedPreviousCheckpointId: string | null;
      readonly submittedPreviousCheckpointId: string | null;
    }
  | { readonly status: "rejected"; readonly reasonCode: string };

/**
 * The witness core (ADR 0002): three RFC 6962 append-only namespaces in the
 * witness's OWN database. Before cosigning, the witness independently
 * verifies the submitter's Ed25519 signature against its registered public
 * key valid at the checkpoint's receipt time and enforces continuity -
 * exactly-next positions with matching previous heads for the delivery
 * namespace, exact chain extension for the policy and directory
 * namespaces. Any conflict returns a typed equivocation result carrying
 * both facts (the SEV-0 trigger) and cosigns nothing. Checkpoints are
 * signed over the jb-msg-witness-checkpoint/v1 preimage; the UNIQUE
 * (namespace, tree_size) constraint makes stored equivocation impossible.
 */
export function createWitnessCore(context: {
  readonly sql: Sql;
  readonly signer: WitnessSignerPort;
}): {
  extendDelivery: (input: {
    conversationId: string;
    position: string;
    previousHeadHash: string;
    headHash: string;
    signingKeyId: string;
    signature: string;
    checkpointReceivedAt: string;
  }) => Promise<DeliveryExtensionResult>;
  extendChain: (
    namespace: "policy" | "directory",
    input: {
      checkpointId: string;
      treeSize: string;
      rootHash: string;
      previousCheckpointId: string | null;
      signerKeyId: string;
    },
  ) => Promise<ChainExtensionResult>;
  readCheckpoint: (checkpointId: string) => Promise<WitnessCheckpoint | null>;
  latestCheckpoint: (
    namespace: WitnessNamespace,
  ) => Promise<WitnessCheckpoint | null>;
  proveConsistency: (
    namespace: WitnessNamespace,
    fromTreeSize: string,
    toTreeSize: string,
  ) => Promise<readonly string[] | null>;
  proveInclusion: (
    namespace: WitnessNamespace,
    treeIndex: string,
    treeSize: string,
  ) => Promise<readonly string[] | null>;
  reportGossip: (input: {
    conversationId: string;
    position: string;
    headHash: string;
    witnessCheckpointId: string;
  }) => Promise<{ readonly splitView: boolean }>;
  splitViewCount: () => Promise<number>;
} {
  const { sql, signer } = context;

  const dbNow = async (tx: TransactionSql | Sql): Promise<string> => {
    const rows = await tx`SELECT witness_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  const lockNamespace = async (
    tx: TransactionSql,
    namespace: WitnessNamespace,
  ): Promise<{ lastUpstreamCheckpointId: string | null }> => {
    const rows = await tx`
      SELECT last_upstream_checkpoint_id FROM witness_chain_heads
      WHERE namespace = ${namespace} FOR UPDATE`;
    return {
      lastUpstreamCheckpointId:
        rows[0].last_upstream_checkpoint_id === null
          ? null
          : String(rows[0].last_upstream_checkpoint_id),
    };
  };

  const loadLeafHashes = async (
    tx: TransactionSql | Sql,
    namespace: WitnessNamespace,
    limit?: bigint,
  ): Promise<Buffer[]> => {
    const rows = limit === undefined
      ? await tx`
          SELECT leaf_hash FROM witness_leaves
          WHERE namespace = ${namespace} ORDER BY tree_index`
      : await tx`
          SELECT leaf_hash FROM witness_leaves
          WHERE namespace = ${namespace} AND tree_index < ${String(limit)}
          ORDER BY tree_index`;
    return rows.map((row) => Buffer.from(row.leaf_hash as Uint8Array));
  };

  const appendAndCheckpoint = async (
    tx: TransactionSql,
    namespace: WitnessNamespace,
    leafPayload: Buffer,
    witnessedAt: string,
  ): Promise<{ receipt: WitnessCheckpoint; treeIndex: bigint }> => {
    const existing = await loadLeafHashes(tx, namespace);
    const treeIndex = BigInt(existing.length);
    const hash = leafHash(leafPayload);
    await tx`
      INSERT INTO witness_leaves (
        namespace, tree_index, leaf_payload, leaf_hash, appended_at
      ) VALUES (
        ${namespace}, ${String(treeIndex)}, ${leafPayload}, ${hash},
        ${witnessedAt}::timestamptz
      )`;
    const treeSize = String(treeIndex + 1n);
    const rootHash = merkleRoot([...existing, hash]);
    const checkpointId = uuidV4();
    const digest = computeWitnessCheckpointDigest({
      namespace,
      checkpointId,
      treeSize,
      rootHash,
      witnessKeyId: signer.witnessKeyId,
      witnessedAt,
    });
    const signature = signer.sign(digest);
    await tx`
      INSERT INTO witness_checkpoints (
        checkpoint_id, namespace, tree_size, root_hash, witness_key_id,
        witness_signature, witnessed_at
      ) VALUES (
        ${checkpointId}, ${namespace}, ${treeSize}, ${rootHash},
        ${signer.witnessKeyId}, ${signature}, ${witnessedAt}::timestamptz
      )`;
    return {
      receipt: Object.freeze({
        checkpointId,
        namespace,
        treeSize,
        rootHash: b64(rootHash),
        witnessKeyId: signer.witnessKeyId,
        witnessSignature: b64(signature),
        witnessedAt,
      }),
      treeIndex,
    };
  };

  const checkpointFromRow = (row: Record<string, unknown>): WitnessCheckpoint =>
    Object.freeze({
      checkpointId: String(row.checkpoint_id),
      namespace: String(row.namespace) as WitnessNamespace,
      treeSize: String(row.tree_size),
      rootHash: b64(row.root_hash as Uint8Array),
      witnessKeyId: String(row.witness_key_id),
      witnessSignature: b64(row.witness_signature as Uint8Array),
      witnessedAt: new Date(row.witnessed_at as Date).toISOString(),
    });

  return Object.freeze({
    async extendDelivery(input): Promise<DeliveryExtensionResult> {
      return sql.begin(async (tx) => {
        await lockNamespace(tx, "delivery");
        const witnessedAt = await dbNow(tx);
        const submitterKeys = await tx`
          SELECT public_key FROM witness_submitter_keys
          WHERE key_id = ${input.signingKeyId}
            AND valid_from <= ${input.checkpointReceivedAt}::timestamptz
            AND valid_until > ${input.checkpointReceivedAt}::timestamptz`;
        if (submitterKeys.length !== 1) {
          return Object.freeze({
            status: "rejected" as const,
            reasonCode: "submitter-key-unknown",
          });
        }
        const digest = Buffer.from(
          computeDeliveryLogCheckpointDigest({
            conversationId: input.conversationId,
            position: input.position,
            previousHeadHash: input.previousHeadHash,
            headHash: input.headHash,
            signingKeyId: input.signingKeyId,
          } as Parameters<typeof computeDeliveryLogCheckpointDigest>[0]),
          "base64url",
        );
        if (
          !verifyEd25519(
            Buffer.from(submitterKeys[0].public_key as Uint8Array),
            digest,
            Buffer.from(input.signature, "base64url"),
          )
        ) {
          return Object.freeze({
            status: "rejected" as const,
            reasonCode: "submitter-signature-invalid",
          });
        }
        const position = BigInt(input.position);
        const existingAtPosition = await tx`
          SELECT head_hash FROM witness_delivery_heads
          WHERE conversation_id = ${input.conversationId}
            AND position = ${input.position}`;
        if (existingAtPosition.length === 1) {
          const witnessedHead = b64(
            existingAtPosition[0].head_hash as Uint8Array,
          );
          if (witnessedHead === input.headHash) {
            return Object.freeze({
              status: "rejected" as const,
              reasonCode: "already-witnessed",
            });
          }
          return Object.freeze({
            status: "equivocation" as const,
            position: input.position,
            witnessedHeadHash: witnessedHead,
            submittedHeadHash: input.headHash,
          });
        }
        const previous = await tx`
          SELECT head_hash FROM witness_delivery_heads
          WHERE conversation_id = ${input.conversationId}
            AND position = ${String(position - 1n)}`;
        const expectedPrevious =
          position === 1n
            ? ZERO_HASH_32
            : previous.length === 1
              ? Buffer.from(previous[0].head_hash as Uint8Array)
              : null;
        if (
          expectedPrevious === null ||
          !expectedPrevious.equals(Buffer.from(input.previousHeadHash, "base64url"))
        ) {
          return Object.freeze({
            status: "rejected" as const,
            reasonCode: "not-an-extension",
          });
        }
        const leafPayload = Buffer.concat([
          lengthPrefixed(input.conversationId),
          lengthPrefixed(input.position),
          lengthPrefixed(Buffer.from(input.previousHeadHash, "base64url")),
          lengthPrefixed(Buffer.from(input.headHash, "base64url")),
          lengthPrefixed(input.signingKeyId),
        ]);
        const { receipt, treeIndex } = await appendAndCheckpoint(
          tx,
          "delivery",
          leafPayload,
          witnessedAt,
        );
        await tx`
          INSERT INTO witness_delivery_heads (
            conversation_id, position, head_hash, tree_index
          ) VALUES (
            ${input.conversationId}, ${input.position},
            ${Buffer.from(input.headHash, "base64url")}, ${String(treeIndex)}
          )`;
        return Object.freeze({ status: "witnessed" as const, receipt });
      });
    },

    async extendChain(namespace, input): Promise<ChainExtensionResult> {
      return sql.begin(async (tx) => {
        const head = await lockNamespace(tx, namespace);
        const witnessedAt = await dbNow(tx);
        if (head.lastUpstreamCheckpointId !== input.previousCheckpointId) {
          return Object.freeze({
            status: "equivocation" as const,
            expectedPreviousCheckpointId: head.lastUpstreamCheckpointId,
            submittedPreviousCheckpointId: input.previousCheckpointId,
          });
        }
        const leafPayload = Buffer.concat([
          lengthPrefixed(input.checkpointId),
          lengthPrefixed(input.treeSize),
          lengthPrefixed(Buffer.from(input.rootHash, "base64url")),
          lengthPrefixed(input.previousCheckpointId ?? ""),
          lengthPrefixed(input.signerKeyId),
        ]);
        const { receipt } = await appendAndCheckpoint(
          tx,
          namespace,
          leafPayload,
          witnessedAt,
        );
        await tx`
          UPDATE witness_chain_heads SET
            last_upstream_checkpoint_id = ${input.checkpointId},
            updated_at = ${witnessedAt}::timestamptz
          WHERE namespace = ${namespace}`;
        return Object.freeze({ status: "witnessed" as const, receipt });
      });
    },

    async readCheckpoint(checkpointId): Promise<WitnessCheckpoint | null> {
      const rows = await sql`
        SELECT * FROM witness_checkpoints
        WHERE checkpoint_id = ${checkpointId}`;
      return rows.length === 1
        ? checkpointFromRow(rows[0] as Record<string, unknown>)
        : null;
    },

    async latestCheckpoint(namespace): Promise<WitnessCheckpoint | null> {
      const rows = await sql`
        SELECT * FROM witness_checkpoints
        WHERE namespace = ${namespace}
        ORDER BY tree_size DESC LIMIT 1`;
      return rows.length === 1
        ? checkpointFromRow(rows[0] as Record<string, unknown>)
        : null;
    },

    async proveConsistency(
      namespace,
      fromTreeSize,
      toTreeSize,
    ): Promise<readonly string[] | null> {
      const to = BigInt(toTreeSize);
      const from = BigInt(fromTreeSize);
      if (from < 1n || from > to) return null;
      const hashes = await loadLeafHashes(sql, namespace, to);
      if (BigInt(hashes.length) !== to) return null;
      return consistencyProof(hashes, Number(from)).map(b64);
    },

    async proveInclusion(
      namespace,
      treeIndex,
      treeSize,
    ): Promise<readonly string[] | null> {
      const size = BigInt(treeSize);
      const index = BigInt(treeIndex);
      if (index < 0n || index >= size) return null;
      const hashes = await loadLeafHashes(sql, namespace, size);
      if (BigInt(hashes.length) !== size) return null;
      return inclusionProof(hashes, Number(index)).map(b64);
    },

    async reportGossip(input): Promise<{ readonly splitView: boolean }> {
      return sql.begin(async (tx) => {
        const receivedAt = await dbNow(tx);
        const rows = await tx`
          SELECT head_hash FROM witness_delivery_heads
          WHERE conversation_id = ${input.conversationId}
            AND position = ${input.position}`;
        const splitView =
          rows.length === 0 ||
          b64(rows[0].head_hash as Uint8Array) !== input.headHash;
        await tx`
          INSERT INTO witness_gossip_reports (
            report_id, conversation_id, position, head_hash,
            witness_checkpoint_id, split_view, received_at
          ) VALUES (
            ${uuidV4()}, ${input.conversationId}, ${input.position},
            ${Buffer.from(input.headHash, "base64url")},
            ${input.witnessCheckpointId}, ${splitView},
            ${receivedAt}::timestamptz
          )`;
        return Object.freeze({ splitView });
      });
    },

    async splitViewCount(): Promise<number> {
      const rows = await sql`
        SELECT count(*)::int AS total FROM witness_gossip_reports
        WHERE split_view`;
      return rows[0].total as number;
    },
  });
}

export function computeWitnessCheckpointDigest(input: {
  namespace: string;
  checkpointId: string;
  treeSize: string;
  rootHash: Buffer;
  witnessKeyId: string;
  witnessedAt: string;
}): Buffer {
  return createHash("sha256")
    .update(WITNESS_CHECKPOINT_DOMAIN, "ascii")
    .update(lengthPrefixed(input.namespace))
    .update(lengthPrefixed(input.checkpointId))
    .update(lengthPrefixed(input.treeSize))
    .update(lengthPrefixed(input.rootHash))
    .update(lengthPrefixed(input.witnessKeyId))
    .update(lengthPrefixed(input.witnessedAt))
    .digest();
}

function verifyEd25519(
  rawPublicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
      format: "der",
      type: "spki",
    });
    return verifyNodeSignature(null, message, key, signature);
  } catch {
    return false;
  }
}

function lengthPrefixed(value: string | Buffer): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

function b64(value: Uint8Array | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function uuidV4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
