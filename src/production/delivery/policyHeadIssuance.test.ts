import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  POLICY_HEAD_SIGNED_BODY_DOMAIN,
  canonicalJcs,
  computeMandatoryProposalSetHash,
  computePolicyHeadHash,
  computeSendGrantSetHash,
} from "./policyHeadIssuance";

describe("policy head issuance primitives", () => {
  it("canonicalizes with sorted members, preserved array order, and JSON escaping", () => {
    expect(
      canonicalJcs({
        zulu: "1",
        alpha: "2",
        nested: { b: "3", a: ["x", "y"] },
      }),
    ).toBe('{"alpha":"2","nested":{"a":["x","y"],"b":"3"},"zulu":"1"}');
    expect(canonicalJcs({ "é": 'quote"back\\slash' })).toBe(
      '{"é":"quote\\"back\\\\slash"}',
    );
    expect(canonicalJcs([])).toBe("[]");
    expect(() => canonicalJcs({ count: 1 })).toThrow(/strings, arrays/);
    expect(() => canonicalJcs({ flag: true })).toThrow(/strings, arrays/);
    expect(() => canonicalJcs({ absent: null })).toThrow(/strings, arrays/);
  });

  it("hashes the canonical body under the exact domain separator", () => {
    const body = Buffer.from('{"a":"1"}', "utf8");
    const expected = createHash("sha256")
      .update(Buffer.from(POLICY_HEAD_SIGNED_BODY_DOMAIN, "ascii"))
      .update(Buffer.of(0))
      .update(body)
      .digest();
    expect(computePolicyHeadHash(body).equals(expected)).toBe(true);
  });

  it("binds mandatory-proposal and send-grant set hashes to content and order", () => {
    const proposalA = {
      proposalId: "00000000-0000-4000-8000-000000000001",
      proposalHash: Buffer.alloc(32, 1).toString("base64url"),
    };
    const proposalB = {
      proposalId: "00000000-0000-4000-8000-000000000002",
      proposalHash: Buffer.alloc(32, 2).toString("base64url"),
    };
    expect(
      computeMandatoryProposalSetHash([proposalA, proposalB]).equals(
        computeMandatoryProposalSetHash([proposalB, proposalA]),
      ),
    ).toBe(false);
    expect(
      computeMandatoryProposalSetHash([]).equals(
        computeSendGrantSetHash([]),
      ),
    ).toBe(false);

    const member = {
      grantEvidenceDigest: Buffer.alloc(32, 3).toString("base64url"),
      grantInclusionEvidenceDigest: Buffer.alloc(32, 4).toString("base64url"),
      installationId: "00000000-0000-4000-8000-000000000003",
      credentialId: "00000000-0000-4000-8000-000000000004",
      role: "member",
    };
    const swapped = {
      ...member,
      grantEvidenceDigest: member.grantInclusionEvidenceDigest,
      grantInclusionEvidenceDigest: member.grantEvidenceDigest,
    };
    expect(
      computeSendGrantSetHash([member]).equals(
        computeSendGrantSetHash([swapped]),
      ),
    ).toBe(false);
  });
});
