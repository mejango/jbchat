import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

/**
 * RFC 6962 section 2.1 Merkle tree over an ordered leaf sequence: leaf hash
 * SHA-256(0x00 || leaf), interior node SHA-256(0x01 || left || right), with
 * the standard inclusion (audit path) and consistency proofs. Everything is
 * recomputed from the stored leaf hashes on demand.
 * ponytail: O(n) per operation over in-memory leaf hashes; incremental
 * node caching is the upgrade path if witnessed logs grow past memory.
 */

const LEAF_PREFIX = Buffer.of(0);
const NODE_PREFIX = Buffer.of(1);

export function leafHash(payload: Buffer): Buffer {
  return createHash("sha256").update(LEAF_PREFIX).update(payload).digest();
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256")
    .update(NODE_PREFIX)
    .update(left)
    .update(right)
    .digest();
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function merkleRoot(leafHashes: readonly Buffer[]): Buffer {
  if (leafHashes.length === 0) {
    return createHash("sha256").digest();
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const k = splitPoint(leafHashes.length);
  return nodeHash(
    merkleRoot(leafHashes.slice(0, k)),
    merkleRoot(leafHashes.slice(k)),
  );
}

/** RFC 6962 PATH(m, D[n]). */
export function inclusionProof(
  leafHashes: readonly Buffer[],
  index: number,
): readonly Buffer[] {
  if (index < 0 || index >= leafHashes.length) {
    throw new RangeError("Inclusion index is outside the tree.");
  }
  if (leafHashes.length === 1) return [];
  const k = splitPoint(leafHashes.length);
  if (index < k) {
    return [
      ...inclusionProof(leafHashes.slice(0, k), index),
      merkleRoot(leafHashes.slice(k)),
    ];
  }
  return [
    ...inclusionProof(leafHashes.slice(k), index - k),
    merkleRoot(leafHashes.slice(0, k)),
  ];
}

export function verifyInclusion(
  leaf: Buffer,
  index: number,
  treeSize: number,
  proof: readonly Buffer[],
  expectedRoot: Buffer,
): boolean {
  // RFC 6962-bis section 2.1.3.2 iterative verification.
  if (index < 0 || index >= treeSize) return false;
  let fn = index;
  let sn = treeSize - 1;
  let hash = leaf;
  for (const sibling of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      hash = nodeHash(sibling, hash);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = fn >> 1;
          sn = sn >> 1;
        }
      }
    } else {
      hash = nodeHash(hash, sibling);
    }
    fn = fn >> 1;
    sn = sn >> 1;
  }
  return sn === 0 && hash.equals(expectedRoot);
}

/** RFC 6962 PROOF(m, D[n]) consistency between sizes m and n. */
export function consistencyProof(
  leafHashes: readonly Buffer[],
  oldSize: number,
): readonly Buffer[] {
  const newSize = leafHashes.length;
  if (oldSize < 1 || oldSize > newSize) {
    throw new RangeError("Consistency sizes are out of range.");
  }
  if (oldSize === newSize) return [];
  return subProof(leafHashes, oldSize, true);
}

function subProof(
  leafHashes: readonly Buffer[],
  m: number,
  complete: boolean,
): Buffer[] {
  const n = leafHashes.length;
  if (m === n) {
    return complete ? [] : [merkleRoot(leafHashes)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    return [
      ...subProof(leafHashes.slice(0, k), m, complete),
      merkleRoot(leafHashes.slice(k)),
    ];
  }
  return [
    ...subProof(leafHashes.slice(k), m - k, false),
    merkleRoot(leafHashes.slice(0, k)),
  ];
}

export function verifyConsistency(
  oldSize: number,
  oldRoot: Buffer,
  newSize: number,
  newRoot: Buffer,
  proof: readonly Buffer[],
): boolean {
  // Canonical RFC 6962 section 2.1.4.2 verification.
  if (oldSize < 1 || oldSize > newSize) return false;
  if (oldSize === newSize) {
    return proof.length === 0 && oldRoot.equals(newRoot);
  }
  let node = oldSize - 1;
  let lastNode = newSize - 1;
  while (node % 2 === 1) {
    node = node >> 1;
    lastNode = lastNode >> 1;
  }
  const path = [...proof];
  let oldHash: Buffer;
  let newHash: Buffer;
  if (node > 0) {
    const seed = path.shift();
    if (!seed) return false;
    oldHash = seed;
    newHash = seed;
  } else {
    oldHash = oldRoot;
    newHash = oldRoot;
  }
  for (const sibling of path) {
    if (lastNode === 0) return false;
    if (node % 2 === 1 || node === lastNode) {
      oldHash = nodeHash(sibling, oldHash);
      newHash = nodeHash(sibling, newHash);
      if (node % 2 === 0) {
        while (node % 2 === 0 && node !== 0) {
          node = node >> 1;
          lastNode = lastNode >> 1;
        }
      }
    } else {
      newHash = nodeHash(newHash, sibling);
    }
    node = node >> 1;
    lastNode = lastNode >> 1;
  }
  return lastNode === 0 && oldHash.equals(oldRoot) && newHash.equals(newRoot);
}
