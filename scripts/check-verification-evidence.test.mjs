import {
  createHash,
  generateKeyPairSync,
  sign as signMessage,
} from "node:crypto";
import { copyFile, lstat, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import {
  approvalEnvelopeSigningBytes,
  canonicalJson,
  decodeUtf8Strict,
  parseJsonRejectingDuplicateKeys,
  loadTrustedApprovalVerifier,
  promotionApprovalSubjectDigest,
  readStableRegularFile,
  unreachabilityProofDigest,
  validateEvidenceManifest,
  validateEvidenceManifestFile,
} from "./check-verification-evidence.mjs";
import {
  EVIDENCE_TEMPLATE_PATH,
  PROJECT_ROOT,
  REQUIRED_APPROVAL_ROLES,
  REQUIRED_UNREACHABILITY_LAYERS,
} from "./lib/verification-evidence-policy.mjs";

const AS_OF = new Date("2026-01-02T00:00:00Z");

let template;
let templateFileDigest;
let templateFileSize;

function copyTemplate() {
  return structuredClone(template);
}

function issueCodes(result) {
  return new Set(result.issues.map((entry) => entry.code));
}

function findRecord(manifest, requirementId) {
  const record = manifest.traceability.find((entry) => entry.requirement_id === requirementId);
  if (!record) throw new Error(`Missing fixture record ${requirementId}`);
  return record;
}

function bindAutomatedEvidence(manifest, record, evidenceIds) {
  const primaryArtifact = manifest.release.artifacts.find(
    (artifact) => artifact.artifact_id === manifest.release.primary_artifact_id,
  );
  if (!primaryArtifact) throw new Error("Missing fixture primary artifact");
  let evidenceArtifact = manifest.release.artifacts.find(
    (artifact) => artifact.artifact_id === "fixture-test-output",
  );
  if (!evidenceArtifact) {
    evidenceArtifact = {
      artifact_id: "fixture-test-output",
      kind: "test_output",
      path: "evidence-template.v1.json",
      digest: templateFileDigest,
      size_bytes: templateFileSize,
      media_type: "application/json",
      evidence_ids: [],
      subject_artifact_id: primaryArtifact.artifact_id,
      subject_artifact_digest: primaryArtifact.digest,
    };
    manifest.release.artifacts.push(evidenceArtifact);
  }
  evidenceArtifact.evidence_ids = [...new Set([...evidenceArtifact.evidence_ids, ...evidenceIds])];
  record.automated_test_ids = evidenceIds;
  record.evidence_artifact_ids = [evidenceArtifact.artifact_id];
  return evidenceArtifact.artifact_id;
}

function makeUnreachabilityProof(featureId, manifest) {
  const primaryArtifact = manifest.release.artifacts.find(
    (artifact) => artifact.artifact_id === manifest.release.primary_artifact_id,
  );
  if (!primaryArtifact) throw new Error("Missing fixture primary artifact");
  const verificationIds = REQUIRED_UNREACHABILITY_LAYERS.map(
    (layer) => `proof:${featureId}:${layer}`,
  );
  const evidenceArtifactId = bindAutomatedEvidence(
    manifest,
    { automated_test_ids: [], evidence_artifact_ids: [] },
    verificationIds,
  );
  const proof = {
    feature_id: featureId,
    proof_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    layers: REQUIRED_UNREACHABILITY_LAYERS.map((layer) => ({
      layer,
      assertion: "unreachable",
      method: "negative_integration_test",
      verification_ids: [`proof:${featureId}:${layer}`],
      artifact_id: primaryArtifact.artifact_id,
      artifact_digest: primaryArtifact.digest,
      evidence_artifact_ids: [evidenceArtifactId],
    })),
  };
  proof.proof_digest = unreachabilityProofDigest(proof);
  return proof;
}

function markNotApplicable(manifest, requirementId, featureId) {
  const record = findRecord(manifest, requirementId);
  record.applicability = "not_applicable";
  record.applicability_justification =
    "The scoped feature is absent from every shipped layer in the digest-bound artifact.";
  bindAutomatedEvidence(manifest, record, [`proof:${featureId}:suite`]);
  record.result = "not_applicable";
  record.completed_at = "2026-01-01T00:02:00Z";
  record.evidence_expires_at = "2026-01-30T00:02:00Z";
  record.unreachability_proof = makeUnreachabilityProof(featureId, manifest);
  return record;
}

async function createPromotionBundle() {
  const bundleDirectory = await mkdtemp(join(tmpdir(), "messaging-evidence-"));
  const fixtureDirectory = dirname(EVIDENCE_TEMPLATE_PATH);
  for (const file of [
    "non-promotable-build.txt",
    "dependency-lock.fixture.json",
    "sbom.fixture.json",
    "build-provenance.fixture.json",
  ]) {
    await copyFile(join(fixtureDirectory, file), join(bundleDirectory, file));
  }

  const manifest = copyTemplate();
  const now = Math.floor(Date.now() / 1000) * 1000;
  const timestamp = (offsetMs) => new Date(now + offsetMs).toISOString().replace(".000Z", "Z");
  manifest.manifest_kind = "release_evidence";
  manifest.release.build.started_at = timestamp(-240_000);
  manifest.release.build.completed_at = timestamp(-180_000);
  manifest.generated_at = timestamp(-90_000);
  manifest.evidence_as_of = timestamp(0);
  manifest.promotion.requested = true;
  manifest.promotion.target_gate = "G1";
  manifest.environment.kind = "deterministic_crypto_lab";
  manifest.environment.description =
    "Deterministic release-evidence verifier integration test environment.";

  const primaryArtifact = manifest.release.artifacts.find(
    (artifact) => artifact.artifact_id === manifest.release.primary_artifact_id,
  );
  if (!primaryArtifact) throw new Error("Missing fixture primary artifact");
  const evidenceIds = [];
  for (const record of manifest.traceability) {
    const due =
      record.requirement_id.startsWith("INV-") ||
      [
        "CRY-01",
        "CRY-03",
        "CRY-05",
        "CRY-06",
        "CRY-07",
        "CRY-08",
        "CRY-09",
        "CRY-14",
        "PRO-01",
        "PRO-07",
        "PRO-10",
        "PRO-13",
        "PRO-14",
      ].includes(record.requirement_id);
    if (!due) continue;
    const evidenceId = `release:${record.requirement_id.toLowerCase()}`;
    evidenceIds.push(evidenceId);
    record.automated_test_ids = [evidenceId];
    record.evidence_artifact_ids = ["release-test-output"];
    record.result = "pass";
    record.completed_at = timestamp(-120_000);
    record.evidence_expires_at = timestamp(86_400_000);
  }

  const testOutput = Buffer.from('{"suite":"trusted promotion fixture"}\n');
  await writeFile(join(bundleDirectory, "test-output.json"), testOutput);
  manifest.release.artifacts.push({
    artifact_id: "release-test-output",
    kind: "test_output",
    path: "test-output.json",
    digest: `sha256:${createHash("sha256").update(testOutput).digest("hex")}`,
    size_bytes: testOutput.byteLength,
    media_type: "application/json",
    evidence_ids: evidenceIds,
    subject_artifact_id: primaryArtifact.artifact_id,
    subject_artifact_digest: primaryArtifact.digest,
  });
  manifest.promotion.approval_subject_digest = promotionApprovalSubjectDigest(manifest);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const trustPolicy = {
    schema_version: "juicebox-evidence-approval-trust/v1",
    entries: [],
  };
  manifest.approvals = [];
  for (const role of REQUIRED_APPROVAL_ROLES) {
    const signerSubject = `person:${role.replaceAll("_", "-")}-signer`;
    const keyId = `${role.replaceAll("_", "-")}-release-key-1`;
    trustPolicy.entries.push({
      role,
      signer_subject: signerSubject,
      key_id: keyId,
      algorithm: "Ed25519",
      public_key_spki_base64: publicKeySpki,
    });
    const envelope = {
      schema_version: "juicebox-evidence-approval-envelope/v1",
      algorithm: "Ed25519",
      key_id: keyId,
      role,
      signer_subject: signerSubject,
      subject_digest: manifest.promotion.approval_subject_digest,
      signed_at: timestamp(-60_000),
      expires_at: timestamp(86_400_000),
    };
    const signedEnvelope = {
      ...envelope,
      signature_base64: signMessage(
        null,
        approvalEnvelopeSigningBytes(envelope),
        privateKey,
      ).toString("base64"),
    };
    const approvalOutput = Buffer.from(`${JSON.stringify(signedEnvelope, null, 2)}\n`);
    const artifactId = `release-approval-${role.replaceAll("_", "-")}`;
    const artifactPath = `approval-${role.replaceAll("_", "-")}.json`;
    await writeFile(join(bundleDirectory, artifactPath), approvalOutput);
    const artifactDigest = `sha256:${createHash("sha256").update(approvalOutput).digest("hex")}`;
    manifest.release.artifacts.push({
      artifact_id: artifactId,
      kind: "approval",
      path: artifactPath,
      digest: artifactDigest,
      size_bytes: approvalOutput.byteLength,
      media_type: "application/json",
      evidence_ids: [],
      subject_artifact_id: null,
      subject_artifact_digest: null,
    });
    manifest.approvals.push({
      role,
      approver: {
        subject: signerSubject,
        display_name: `${role.replaceAll("_", " ")} signer`,
      },
      artifact_id: artifactId,
      artifact_digest: artifactDigest,
      signed_payload_digest: manifest.promotion.approval_subject_digest,
      signed_at: envelope.signed_at,
      expires_at: envelope.expires_at,
    });
  }
  const trustPolicyBytes = Buffer.from(`${JSON.stringify(trustPolicy, null, 2)}\n`);
  const trustPolicyPath = join(bundleDirectory, "approval-trust.json");
  const trustPolicyDigest = `sha256:${createHash("sha256").update(trustPolicyBytes).digest("hex")}`;
  await writeFile(trustPolicyPath, trustPolicyBytes);
  const manifestPath = join(bundleDirectory, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return {
    bundleDirectory,
    manifest,
    manifestPath,
    trustPolicyPath,
    trustPolicyDigest,
  };
}

async function validate(manifest, extra = {}) {
  return validateEvidenceManifest({
    manifest,
    manifestPath: EVIDENCE_TEMPLATE_PATH,
    asOf: AS_OF,
    ...extra,
  });
}

beforeAll(async () => {
  const templateBytes = await readFile(EVIDENCE_TEMPLATE_PATH);
  templateFileDigest = `sha256:${createHash("sha256").update(templateBytes).digest("hex")}`;
  templateFileSize = templateBytes.byteLength;
  template = parseJsonRejectingDuplicateKeys(templateBytes.toString("utf8"));
});

describe("verification evidence contract", () => {
  it("accepts the deterministic template as a contract but never as promotion evidence", async () => {
    const contract = await validate(copyTemplate());
    expect(contract.schemaValid).toBe(true);
    expect(contract.contractValid).toBe(true);
    expect(contract.configuredRequirementCount).toBe(152);
    expect(contract.traceabilityCount).toBe(152);
    expect(contract.promotionPreflightPassed).toBe(false);

    const promotion = await validate(copyTemplate(), {
      mode: "promotion",
      expectedCommit: template.release.source_commit,
      expectedArtifactDigest: template.release.artifacts[0].digest,
      expectedGate: "G1",
    });
    expect(promotion.contractValid).toBe(true);
    expect(promotion.promotionPreflightPassed).toBe(false);
    expect(promotion.promotionIssues.map((entry) => entry.code)).toContain(
      "non_promotable_manifest",
    );
    expect(promotion.promotionIssues.map((entry) => entry.code)).toContain("missing_approval");
  });

  it("keeps release prerequisites distinct and makes real promotion mandatory", async () => {
    const packageJson = JSON.parse(await readFile(join(PROJECT_ROOT, "package.json"), "utf8"));
    expect(packageJson.scripts["check:release:prerequisites"]).toMatch(/check-release-supply-chain/);
    expect(packageJson.scripts["check:release"]).toContain("check:release:prerequisites");
    expect(packageJson.scripts["check:release"]).toMatch(/check-verification-evidence.*promotion/);
  });

  it("rejects missing, duplicate, and unknown verification IDs", async () => {
    const missing = copyTemplate();
    missing.traceability.pop();
    expect(issueCodes(await validate(missing))).toContain("missing_requirement");

    const duplicate = copyTemplate();
    duplicate.traceability[1].requirement_id = duplicate.traceability[0].requirement_id;
    const duplicateCodes = issueCodes(await validate(duplicate));
    expect(duplicateCodes).toContain("duplicate_identifier");
    expect(duplicateCodes).toContain("missing_requirement");

    const unknown = copyTemplate();
    unknown.traceability[0].requirement_id = "CRY-99";
    const unknownCodes = issueCodes(await validate(unknown));
    expect(unknownCodes).toContain("unknown_requirement");
    expect(unknownCodes).toContain("missing_requirement");
  });

  it("rejects invalid and stale evidence dates", async () => {
    const invalid = copyTemplate();
    const invalidRecord = findRecord(invalid, "CRY-01");
    invalidRecord.result = "pass";
    bindAutomatedEvidence(invalid, invalidRecord, ["crypto:release-provenance"]);
    invalidRecord.completed_at = "2026-02-30T00:02:00Z";
    invalidRecord.evidence_expires_at = "2026-03-01T00:02:00Z";
    expect(issueCodes(await validate(invalid))).toContain("invalid_timestamp");

    const stale = copyTemplate();
    const staleRecord = findRecord(stale, "CRY-01");
    staleRecord.result = "pass";
    bindAutomatedEvidence(stale, staleRecord, ["crypto:release-provenance"]);
    staleRecord.completed_at = "2026-01-01T00:02:00Z";
    staleRecord.evidence_expires_at = "2026-01-31T00:02:00Z";
    const staleResult = await validate(stale, { asOf: new Date("2026-02-01T00:02:00Z") });
    expect(issueCodes(staleResult)).toContain("stale_evidence");
  });

  it("accepts only complete digest-bound N/A reachability proofs for conditional rows", async () => {
    const valid = copyTemplate();
    markNotApplicable(valid, "PRIV-10", "attachments");
    expect((await validate(valid)).contractValid).toBe(true);

    const incomplete = copyTemplate();
    const incompleteRecord = markNotApplicable(incomplete, "PRIV-10", "attachments");
    incompleteRecord.unreachability_proof.layers.pop();
    incompleteRecord.unreachability_proof.proof_digest = unreachabilityProofDigest(
      incompleteRecord.unreachability_proof,
    );
    expect(issueCodes(await validate(incomplete))).toContain("incomplete_unreachability_layers");

    const substituted = copyTemplate();
    const substitutedRecord = markNotApplicable(substituted, "PRIV-10", "attachments");
    substitutedRecord.unreachability_proof.proof_digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    expect(issueCodes(await validate(substituted))).toContain(
      "unreachability_digest_mismatch",
    );

    const unconditional = copyTemplate();
    markNotApplicable(unconditional, "INV-01", "attachments");
    expect(issueCodes(await validate(unconditional))).toContain("invalid_not_applicable");

    const enabled = copyTemplate();
    enabled.promotion.scope.attachment_types.push("application-pdf");
    markNotApplicable(enabled, "PRIV-10", "attachments");
    expect(issueCodes(await validate(enabled))).toContain("enabled_feature_not_applicable");
  });

  it("rejects subject-artifact substitution and retained-file digest mismatch", async () => {
    const recordSubstitution = copyTemplate();
    findRecord(recordSubstitution, "CRY-01").artifact_digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    expect(issueCodes(await validate(recordSubstitution))).toContain("unbound_subject_artifact");

    const retainedFileSubstitution = copyTemplate();
    retainedFileSubstitution.release.artifacts[0].digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    expect(issueCodes(await validate(retainedFileSubstitution))).toContain(
      "artifact_digest_mismatch",
    );
  });

  it("rejects primary-build paths masquerading as typed row evidence", async () => {
    const substituted = copyTemplate();
    const record = findRecord(substituted, "CRY-01");
    record.result = "pass";
    record.automated_test_ids = ["crypto:claim-only"];
    record.evidence_artifact_ids = [substituted.release.primary_artifact_id];
    record.completed_at = "2026-01-01T00:02:00Z";
    record.evidence_expires_at = "2026-01-30T00:02:00Z";
    const codes = issueCodes(await validate(substituted));
    expect(codes).toContain("invalid_evidence_artifact_kind");
    expect(codes).toContain("unbound_evidence_id");
  });

  it("binds N/A proofs to the exact enabled conditional feature", async () => {
    const reporting = copyTemplate();
    reporting.promotion.scope.capabilities = ["reports_and_moderation"];
    markNotApplicable(reporting, "PRIV-12", "reports_and_moderation");
    expect(issueCodes(await validate(reporting))).toContain("enabled_feature_not_applicable");

    const announcements = copyTemplate();
    announcements.promotion.scope.capabilities = ["announcements"];
    markNotApplicable(announcements, "OPS-11", "announcements");
    expect(issueCodes(await validate(announcements))).toContain("enabled_feature_not_applicable");

    const oldWrongFeature = copyTemplate();
    markNotApplicable(oldWrongFeature, "PRIV-12", "bridges");
    expect((await validate(oldWrongFeature)).schemaValid).toBe(false);
  });

  it("requires a file-backed manifest and externally trusted approval verifier", async () => {
    const {
      bundleDirectory,
      manifest,
      manifestPath,
      trustPolicyPath,
      trustPolicyDigest,
    } = await createPromotionBundle();
    try {
      const rawVerifier = async () => ({
        signatureVerified: true,
        roleAuthorized: true,
      });
      const objectOnly = await validateEvidenceManifest({
        manifest,
        manifestPath,
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier: rawVerifier,
      });
      expect(objectOnly.promotionPreflightPassed).toBe(false);
      expect(objectOnly.promotionIssues.map((entry) => entry.code)).toContain(
        "unverified_artifact_files",
      );
      expect(objectOnly.promotionIssues.map((entry) => entry.code)).toContain(
        "untrusted_approval_verifier",
      );

      const unsigned = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
      });
      expect(unsigned.promotionPreflightPassed).toBe(false);
      expect(unsigned.promotionIssues.map((entry) => entry.code)).toContain(
        "missing_approval_verifier",
      );

      const injected = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier: rawVerifier,
      });
      expect(injected.promotionPreflightPassed).toBe(false);
      expect(injected.promotionIssues.map((entry) => entry.code)).toContain(
        "untrusted_approval_verifier",
      );

      const approvalVerifier = await loadTrustedApprovalVerifier(
        trustPolicyPath,
        trustPolicyDigest,
      );
      const verified = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier,
      });
      expect(verified.contractValid).toBe(true);
      expect(verified.promotionPreflightPassed).toBe(true);
    } finally {
      await rm(bundleDirectory, { recursive: true, force: true });
    }
  });

  it("rejects approvals that do not bind the canonical subject or evaluator time", async () => {
    const {
      bundleDirectory,
      manifest,
      manifestPath,
      trustPolicyPath,
      trustPolicyDigest,
    } = await createPromotionBundle();
    try {
      manifest.approvals[0].signed_payload_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      manifest.approvals[1].signed_at = "2099-01-01T00:00:00Z";
      manifest.approvals[1].expires_at = "2100-01-01T00:00:00Z";
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      const approvalVerifier = await loadTrustedApprovalVerifier(
        trustPolicyPath,
        trustPolicyDigest,
      );
      const result = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier,
      });
      const codes = issueCodes(result);
      expect(codes).toContain("approval_subject_mismatch");
      expect(codes).toContain("future_approval");
      expect(result.promotionPreflightPassed).toBe(false);
    } finally {
      await rm(bundleDirectory, { recursive: true, force: true });
    }
  });

  it("does not allow promotion callers to backdate the evaluator clock or checker bundle", async () => {
    const {
      bundleDirectory,
      manifest,
      manifestPath,
      trustPolicyPath,
      trustPolicyDigest,
    } = await createPromotionBundle();
    try {
      const approvalVerifier = await loadTrustedApprovalVerifier(
        trustPolicyPath,
        trustPolicyDigest,
      );
      const backdated = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        asOf: new Date("2026-01-02T00:00:00Z"),
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier,
      });
      expect(backdated.promotionPreflightPassed).toBe(false);
      expect(backdated.promotionIssues.map((entry) => entry.code)).toContain(
        "untrusted_clock_override",
      );

      const wrongChecker = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        expectedApprovalTrustDigest: trustPolicyDigest,
        approvalVerifier,
      });
      expect(wrongChecker.promotionPreflightPassed).toBe(false);
      expect(wrongChecker.promotionIssues.map((entry) => entry.code)).toContain(
        "checker_bundle_digest_mismatch",
      );

      const wrongTrust = await validateEvidenceManifestFile(manifestPath, {
        mode: "promotion",
        expectedCommit: manifest.release.source_commit,
        expectedArtifactDigest: manifest.release.artifacts[0].digest,
        expectedGate: "G1",
        expectedCheckerBundleDigest: manifest.policy.evidence_checker_digest,
        expectedApprovalTrustDigest:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        approvalVerifier,
      });
      expect(wrongTrust.promotionPreflightPassed).toBe(false);
      expect(wrongTrust.promotionIssues.map((entry) => entry.code)).toContain(
        "approval_trust_digest_mismatch",
      );
    } finally {
      await rm(bundleDirectory, { recursive: true, force: true });
    }
  });

  it("rejects artifact catalogs above the aggregate verification budget before reads", async () => {
    const oversized = copyTemplate();
    for (let index = 0; index < 5; index += 1) {
      oversized.release.artifacts.push({
        artifact_id: `oversized-${index}`,
        kind: "other",
        path: `oversized-${index}.bin`,
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        size_bytes: 1024 * 1024 * 1024,
        media_type: "application/octet-stream",
        evidence_ids: [],
        subject_artifact_id: null,
        subject_artifact_digest: null,
      });
    }
    const result = await validate(oversized);
    expect(issueCodes(result)).toContain("artifact_bundle_too_large");
    expect(issueCodes(result)).not.toContain("missing_artifact_file");
    expect(result.contractValid).toBe(false);
  });

  it("rejects policy reinterpretation under an unchanged requirement ID list", async () => {
    const substituted = copyTemplate();
    substituted.policy.verification_spec_digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    expect(issueCodes(await validate(substituted))).toContain("policy_binding_mismatch");
  });

  it("rejects noncanonical result states and placeholder or non-independent reviewers", async () => {
    const resultAlias = copyTemplate();
    findRecord(resultAlias, "CRY-01").result = "passed";
    expect((await validate(resultAlias)).schemaValid).toBe(false);

    const placeholder = copyTemplate();
    findRecord(placeholder, "CRY-01").owner = {
      subject: "team:tbd",
      display_name: "TBD owner",
    };
    expect(issueCodes(await validate(placeholder))).toContain("placeholder_identity");

    const sameReviewer = copyTemplate();
    const record = findRecord(sameReviewer, "CRY-01");
    record.independent_reviewer = structuredClone(record.owner);
    expect(issueCodes(await validate(sameReviewer))).toContain("non_independent_reviewer");
  });

  it("rejects duplicate raw JSON object keys before JSON Schema validation", () => {
    expect(() =>
      parseJsonRejectingDuplicateKeys('{"schema_version":"1.0.0","schema_version":"1.0.0"}'),
    ).toThrow(/Duplicate JSON object key/);
  });

  it("uses portable canonical signing bytes and rejects malformed Unicode inputs", () => {
    const signingValue = {
      schema_version: "juicebox-evidence-approval-envelope/v1",
      algorithm: "Ed25519",
      key_id: "release-key-1",
      role: "security",
      signer_subject: "person:alice",
      subject_digest:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      signed_at: "2026-08-14T12:00:00Z",
      expires_at: "2026-08-15T12:00:00Z",
    };
    const signingBytes = approvalEnvelopeSigningBytes(signingValue);
    expect(signingBytes.toString("utf8")).toBe(
      '{"algorithm":"Ed25519","expires_at":"2026-08-15T12:00:00Z","key_id":"release-key-1","role":"security","schema_version":"juicebox-evidence-approval-envelope/v1","signed_at":"2026-08-14T12:00:00Z","signer_subject":"person:alice","subject_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}',
    );
    expect(`sha256:${createHash("sha256").update(signingBytes).digest("hex")}`).toBe(
      "sha256:5d64ac529ed130cd629d9854d9022e9065f9872108f38d1ad6e98a9f00bac02d",
    );

    expect(() => decodeUtf8Strict(Buffer.from([0xc3, 0x28]))).toThrow(/UTF-8/);
    expect(() => decodeUtf8Strict(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))).toThrow(
      /UTF-8/,
    );
    expect(() => parseJsonRejectingDuplicateKeys('{"x":"\\ud800"}')).toThrow();
    expect(() => parseJsonRejectingDuplicateKeys('{"\\udc00":1}')).toThrow();
    expect(() => canonicalJson(Array(2))).toThrow(/sparse/);
    const accessorArray = [];
    Object.defineProperty(accessorArray, 0, {
      enumerable: true,
      get: () => "must not execute",
    });
    accessorArray.length = 1;
    expect(() => canonicalJson(accessorArray)).toThrow(/sparse|decorated/);
    const cyclic = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(/cyclic/);
    expect(canonicalJson({ x: "é" })).not.toBe(canonicalJson({ x: "e\u0301" }));
  });

  it("keeps __proto__ as ordinary untrusted data instead of mutating parser state", () => {
    const parsed = parseJsonRejectingDuplicateKeys(
      '{"__proto__":{"polluted":true},"safe":true}',
    );

    expect(Object.prototype.hasOwnProperty.call(parsed, "__proto__")).toBe(true);
    expect(parsed.__proto__).toEqual({ polluted: true });
    expect(parsed.polluted).toBeUndefined();
    expect({}.polluted).toBeUndefined();
  });
});

describe("stable evidence artifact reads", () => {
  it("hashes one bounded regular-file descriptor", async () => {
    const directory = await mkdtemp(join(tmpdir(), "messaging-artifact-"));
    const path = join(directory, "artifact.bin");
    try {
      const bytes = Buffer.from("stable artifact bytes");
      await writeFile(path, bytes);
      const result = await readStableRegularFile(path, {
        maxBytes: 1024,
        expectedSize: bytes.byteLength,
        expectedPathStats: await lstat(path, { bigint: true }),
        captureBytes: true,
      });
      expect(result.digest).toBe(`sha256:${createHash("sha256").update(bytes).digest("hex")}`);
      expect(result.bytes).toEqual(bytes);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("loads only an externally digest-pinned declarative approval trust policy", async () => {
    const {
      bundleDirectory,
      trustPolicyPath,
      trustPolicyDigest,
    } = await createPromotionBundle();
    try {
      await expect(
        loadTrustedApprovalVerifier(trustPolicyPath, trustPolicyDigest),
      ).resolves.toEqual(expect.any(Function));
      await expect(
        loadTrustedApprovalVerifier(
          trustPolicyPath,
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
      ).rejects.toThrow(/digest mismatch/i);
    } finally {
      await rm(bundleDirectory, { recursive: true, force: true });
    }
  });

  it("never imports approval-policy files as executable modules", async () => {
    const directory = await mkdtemp(join(tmpdir(), "messaging-trust-policy-"));
    const path = join(directory, "not-a-policy.mjs");
    try {
      const source = Buffer.from(
        'import "node:fs"; export async function verifyApprovalSignature() { return true; }\n',
      );
      await writeFile(path, source);
      const digest = `sha256:${createHash("sha256").update(source).digest("hex")}`;
      await expect(loadTrustedApprovalVerifier(path, digest)).rejects.toThrow(/JSON/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects symlinks, oversize files, and path replacement races", async () => {
    const directory = await mkdtemp(join(tmpdir(), "messaging-artifact-"));
    const target = join(directory, "target.bin");
    const link = join(directory, "link.bin");
    try {
      await writeFile(target, "abc");
      await symlink(target, link);
      await expect(
        readStableRegularFile(link, {
          maxBytes: 1024,
          expectedSize: 3,
          expectedPathStats: await lstat(link, { bigint: true }),
        }),
      ).rejects.toThrow();
      await expect(
        readStableRegularFile(target, {
          maxBytes: 2,
          expectedSize: 3,
          expectedPathStats: await lstat(target, { bigint: true }),
        }),
      ).rejects.toMatchObject({ evidenceCode: "artifact_too_large" });

      const original = await lstat(target, { bigint: true });
      await expect(
        readStableRegularFile(target, {
          maxBytes: 1024,
          expectedSize: 3,
          expectedPathStats: original,
          checkpoint: async (name) => {
            if (name !== "after_pre_stat") return;
            await rename(target, join(directory, "opened-original.bin"));
            await writeFile(target, "xyz");
          },
        }),
      ).rejects.toMatchObject({ evidenceCode: "artifact_changed_during_validation" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects an intermediate symlink that escapes the evidence bundle", async () => {
    const bundleDirectory = await mkdtemp(join(tmpdir(), "messaging-bundle-"));
    const outsideDirectory = await mkdtemp(join(tmpdir(), "messaging-outside-"));
    try {
      const fixtureDirectory = dirname(EVIDENCE_TEMPLATE_PATH);
      for (const file of [
        "dependency-lock.fixture.json",
        "sbom.fixture.json",
        "build-provenance.fixture.json",
      ]) {
        await copyFile(join(fixtureDirectory, file), join(bundleDirectory, file));
      }
      await copyFile(
        join(fixtureDirectory, "non-promotable-build.txt"),
        join(outsideDirectory, "non-promotable-build.txt"),
      );
      await symlink(outsideDirectory, join(bundleDirectory, "linked"));
      const manifest = copyTemplate();
      manifest.release.artifacts[0].path = "linked/non-promotable-build.txt";
      const manifestPath = join(bundleDirectory, "manifest.json");
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      const result = await validateEvidenceManifestFile(manifestPath, { asOf: AS_OF });
      expect(issueCodes(result)).toContain("invalid_artifact_file");
      expect(result.contractValid).toBe(false);
    } finally {
      await rm(bundleDirectory, { recursive: true, force: true });
      await rm(outsideDirectory, { recursive: true, force: true });
    }
  });
});
