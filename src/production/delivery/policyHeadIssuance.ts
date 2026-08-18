import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

export const POLICY_HEAD_SIGNED_BODY_DOMAIN = "jb-msg-policy-head/v1";
const SEND_GRANT_SET_DOMAIN = "jb-msg-send-grant-set/v1";
const MANDATORY_PROPOSAL_SET_DOMAIN = "jb-msg-mandatory-proposal-set/v1";

/**
 * RFC 8785 (JCS) serialization for the policy-head unsigned body. The body's
 * value domain is deliberately restricted - strings, arrays, and plain
 * objects only (uint64s travel as canonical decimal strings) - so canonical
 * form is lexicographic member ordering by UTF-16 code units plus ECMA-262
 * JSON string escaping, which JSON.stringify already produces exactly.
 * Numbers, booleans, and null are rejected rather than canonicalized so a
 * drifting caller fails loudly instead of signing an unintended encoding.
 */
export function canonicalJcs(value: unknown): string {
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJcs(entry)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const members = keys.map(
      (key) => `${JSON.stringify(key)}:${canonicalJcs(record[key])}`,
    );
    return `{${members.join(",")}}`;
  }
  throw new TypeError(
    "The policy-head canonical form admits only strings, arrays, and records.",
  );
}

/** SHA-256(ASCII(domain) || 0x00 || JCS(body)) per service-api.md. */
export function computePolicyHeadHash(canonicalBody: Buffer): Buffer {
  return createHash("sha256")
    .update(POLICY_HEAD_SIGNED_BODY_DOMAIN, "ascii")
    .update(Buffer.of(0))
    .update(canonicalBody)
    .digest();
}

export interface MandatoryProposalEntry {
  readonly proposalId: string;
  /** base64url 32 bytes */
  readonly proposalHash: string;
}

export interface SendGrantSetMemberEntry {
  readonly grantEvidenceDigest: string;
  readonly grantInclusionEvidenceDigest: string;
  readonly installationId: string;
  readonly credentialId: string;
  readonly role: string;
}

function lengthPrefixed(parts: readonly (string | Buffer)[]): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    const bytes = typeof part === "string" ? Buffer.from(part, "utf8") : part;
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength);
    chunks.push(length, bytes);
  }
  return Buffer.concat(chunks);
}

/**
 * Ordered set hash over the exact (proposalId, proposalHash) pairs; neither
 * an ID nor a hash alone satisfies the mandatory set, and order is bound.
 */
export function computeMandatoryProposalSetHash(
  proposals: readonly MandatoryProposalEntry[],
): Buffer {
  return createHash("sha256")
    .update(MANDATORY_PROPOSAL_SET_DOMAIN, "utf8")
    .update(
      lengthPrefixed(
        proposals.flatMap((proposal) => [
          proposal.proposalId,
          Buffer.from(proposal.proposalHash, "base64url"),
        ]),
      ),
    )
    .digest();
}

/**
 * The lab's authorized-send-grant set root: a domain-separated hash over the
 * complete ordered leaves. This is full-set recomputation evidence, NOT a
 * succinct inclusion proof - the accumulator for succinct per-grant
 * inclusion under this root is not yet specified by the ratified documents
 * and stays open.
 */
export function computeSendGrantSetHash(
  members: readonly SendGrantSetMemberEntry[],
): Buffer {
  return createHash("sha256")
    .update(SEND_GRANT_SET_DOMAIN, "utf8")
    .update(
      lengthPrefixed(
        members.flatMap((member) => [
          Buffer.from(member.grantEvidenceDigest, "base64url"),
          Buffer.from(member.grantInclusionEvidenceDigest, "base64url"),
          member.installationId,
          member.credentialId,
          member.role,
        ]),
      ),
    )
    .digest();
}

/**
 * Signs exactly the 32-byte domain-separated policy-head hash under the
 * policy_head_v1 signature domain. Production custody is a KMS role separate
 * from the MLS external-sender domain; the lab implementation is an
 * in-process Ed25519 key registered in policy_head_signing_keys.
 */
export interface PolicyHeadSignerPort {
  readonly signerKeyId: string;
  readonly sign: (policyHeadHash: Buffer) => Buffer;
}
