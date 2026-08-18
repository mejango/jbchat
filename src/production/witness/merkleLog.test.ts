import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
  verifyConsistency,
  verifyInclusion,
} from "./merkleLog";

function leaves(count: number): Buffer[] {
  return Array.from({ length: count }, (_, index) =>
    leafHash(Buffer.from(`leaf-${index}`, "utf8")),
  );
}

describe("RFC 6962 merkle log", () => {
  it("matches the RFC's fixed points", () => {
    expect(merkleRoot([]).toString("hex")).toBe(
      createHash("sha256").digest("hex"),
    );
    const single = leafHash(Buffer.from("only", "utf8"));
    expect(merkleRoot([single]).equals(single)).toBe(true);
    const pair = leaves(2);
    expect(merkleRoot(pair).toString("hex")).toBe(
      createHash("sha256")
        .update(Buffer.of(1))
        .update(pair[0])
        .update(pair[1])
        .digest("hex"),
    );
  });

  it("proves and verifies inclusion for every leaf of every size up to 33", () => {
    for (let size = 1; size <= 33; size += 1) {
      const tree = leaves(size);
      const root = merkleRoot(tree);
      for (let index = 0; index < size; index += 1) {
        const proof = inclusionProof(tree, index);
        expect(verifyInclusion(tree[index], index, size, proof, root)).toBe(
          true,
        );
        expect(
          verifyInclusion(
            leafHash(Buffer.from("forged", "utf8")),
            index,
            size,
            proof,
            root,
          ),
        ).toBe(false);
        if (proof.length > 0) {
          const truncated = proof.slice(0, -1);
          expect(
            verifyInclusion(tree[index], index, size, truncated, root),
          ).toBe(false);
        }
      }
    }
  });

  it("proves and verifies consistency for every size pair up to 33", () => {
    for (let newSize = 1; newSize <= 33; newSize += 1) {
      const tree = leaves(newSize);
      const newRoot = merkleRoot(tree);
      for (let oldSize = 1; oldSize <= newSize; oldSize += 1) {
        const oldRoot = merkleRoot(tree.slice(0, oldSize));
        const proof = consistencyProof(tree, oldSize);
        expect(
          verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof),
        ).toBe(true);
        expect(
          verifyConsistency(
            oldSize,
            leafHash(Buffer.from("wrong-root", "utf8")),
            newSize,
            newRoot,
            proof,
          ),
        ).toBe(false);
      }
    }
  });

  it("rejects a forked history through consistency", () => {
    const honest = leaves(9);
    const forked = [...leaves(6), ...leaves(3).map((leaf) =>
      leafHash(Buffer.concat([leaf, Buffer.of(0xff)])),
    )];
    const proof = consistencyProof(forked, 6);
    // The fork agrees on the first six leaves, so consistency to ITS OWN
    // root verifies - but never to the honest tree's root at size 9.
    expect(
      verifyConsistency(
        6,
        merkleRoot(honest.slice(0, 6)),
        9,
        merkleRoot(forked),
        proof,
      ),
    ).toBe(true);
    expect(
      verifyConsistency(
        6,
        merkleRoot(honest.slice(0, 6)),
        9,
        merkleRoot(honest),
        proof,
      ),
    ).toBe(false);
  });
});
