import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import {
  EVIDENCE_TEMPLATE_PATH,
  EVIDENCE_CHECKER_PATH,
  EVIDENCE_POLICY_SOURCE_PATH,
  EVIDENCE_SCHEMA_PATH,
  LAUNCH_GATES_SPEC_PATH,
  PACKAGE_LOCK_PATH,
  PROJECT_ROOT,
  VERIFICATION_SPEC_PATH,
  readVerificationRequirements,
  requirementCatalogValue,
} from "./lib/verification-evidence-policy.mjs";

const PRIMARY_DIGEST =
  "sha256:51e89fb44bb7e9aefbc84295ca84ad885ee84d48b304de01e446ea567bc8852e";

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function evidenceCheckerBundleDigest(checkerSource, policySource, packageLock) {
  return sha256(
    canonicalJson({
      schema_version: "juicebox-evidence-checker-source-bundle/v1",
      sources: [
        { path: "scripts/check-verification-evidence.mjs", digest: sha256(checkerSource) },
        {
          path: "scripts/lib/verification-evidence-policy.mjs",
          digest: sha256(policySource),
        },
        { path: "package-lock.json", digest: sha256(packageLock) },
      ],
    }),
  );
}

const RESPONSIBILITY_BY_PREFIX = Object.freeze({
  INV: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-security-engineering",
      display_name: "Messaging security engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-security-assurance",
      display_name: "Independent security assurance",
    }),
  }),
  CRY: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-cryptography-engineering",
      display_name: "Messaging cryptography engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-cryptography-assurance",
      display_name: "Independent cryptography assurance",
    }),
  }),
  PRO: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-protocol-engineering",
      display_name: "Messaging protocol engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-protocol-assurance",
      display_name: "Independent protocol assurance",
    }),
  }),
  ID: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-identity-engineering",
      display_name: "Messaging identity engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-identity-assurance",
      display_name: "Independent identity assurance",
    }),
  }),
  ENT: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-entitlement-engineering",
      display_name: "Messaging entitlement engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-chain-assurance",
      display_name: "Independent chain assurance",
    }),
  }),
  PRIV: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-privacy-engineering",
      display_name: "Messaging privacy engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-privacy-assurance",
      display_name: "Independent privacy assurance",
    }),
  }),
  EMB: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-embed-engineering",
      display_name: "Messaging embed engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-web-security-assurance",
      display_name: "Independent web security assurance",
    }),
  }),
  UX: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-product-accessibility",
      display_name: "Messaging product accessibility",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-accessibility-assurance",
      display_name: "Independent accessibility assurance",
    }),
  }),
  DATA: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-data-engineering",
      display_name: "Messaging data engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-data-assurance",
      display_name: "Independent data assurance",
    }),
  }),
  OPS: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-site-reliability",
      display_name: "Messaging site reliability",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-operations-assurance",
      display_name: "Independent operations assurance",
    }),
  }),
  PLAT: Object.freeze({
    owner: Object.freeze({
      subject: "team:messaging-platform-engineering",
      display_name: "Messaging platform engineering",
    }),
    reviewer: Object.freeze({
      subject: "team:independent-platform-assurance",
      display_name: "Independent platform assurance",
    }),
  }),
});

export async function createVerificationEvidenceTemplate() {
  const [
    requirements,
    verificationSpec,
    launchGates,
    evidenceSchema,
    evidenceChecker,
    evidencePolicySource,
    packageLock,
  ] = await Promise.all([
    readVerificationRequirements(),
    readFile(VERIFICATION_SPEC_PATH),
    readFile(LAUNCH_GATES_SPEC_PATH),
    readFile(EVIDENCE_SCHEMA_PATH),
    readFile(EVIDENCE_CHECKER_PATH),
    readFile(EVIDENCE_POLICY_SOURCE_PATH),
    readFile(PACKAGE_LOCK_PATH),
  ]);

  return {
    schema_version: "1.0.0",
    manifest_kind: "template",
    generated_at: "2026-01-01T00:05:00Z",
    evidence_as_of: "2026-01-01T00:05:00Z",
    policy: {
      verification_spec_digest: sha256(verificationSpec),
      launch_gates_digest: sha256(launchGates),
      requirement_catalog_digest: sha256(
        canonicalJson(requirementCatalogValue(requirements)),
      ),
      evidence_schema_digest: sha256(evidenceSchema),
      evidence_checker_digest: evidenceCheckerBundleDigest(
        evidenceChecker,
        evidencePolicySource,
        packageLock,
      ),
    },
    promotion: {
      requested: false,
      target_gate: "G0",
      approval_subject_digest: null,
      scope: {
        chains: [],
        clients: [],
        wallet_methods: [],
        embed_hosts: [],
        recovery_modes: [],
        attachment_types: [],
        connectors: [],
        capabilities: [],
      },
    },
    release: {
      source_commit: "0123456789abcdef0123456789abcdef01234567",
      primary_artifact_id: "fixture-build-artifact",
      dependency_lock_artifact_id: "fixture-dependency-lock",
      sbom_artifact_id: "fixture-sbom",
      build_provenance_artifact_id: "fixture-build-provenance",
      artifacts: [
        {
          artifact_id: "fixture-build-artifact",
          kind: "build",
          path: "non-promotable-build.txt",
          digest: PRIMARY_DIGEST,
          size_bytes: 98,
          media_type: "text/plain",
          evidence_ids: [],
          subject_artifact_id: null,
          subject_artifact_digest: null,
        },
        {
          artifact_id: "fixture-dependency-lock",
          kind: "dependency_lock",
          path: "dependency-lock.fixture.json",
          digest:
            "sha256:abad39ea1193ba0a1c27557b07ebccf0e9ad69dc485c815c72fff33510304c1a",
          size_bytes: 124,
          media_type: "application/json",
          evidence_ids: [],
          subject_artifact_id: "fixture-build-artifact",
          subject_artifact_digest: PRIMARY_DIGEST,
        },
        {
          artifact_id: "fixture-sbom",
          kind: "sbom",
          path: "sbom.fixture.json",
          digest:
            "sha256:87c8eec2546d7427b45fe5e1f3c81462b3e4c5dfbe381f2ab385c82ccbb04101",
          size_bytes: 113,
          media_type: "application/json",
          evidence_ids: [],
          subject_artifact_id: "fixture-build-artifact",
          subject_artifact_digest: PRIMARY_DIGEST,
        },
        {
          artifact_id: "fixture-build-provenance",
          kind: "build_provenance",
          path: "build-provenance.fixture.json",
          digest:
            "sha256:c340c6336c9bb6851031a5894a3ef5096f9fe3c1bcba78b769fc1060c810d6b7",
          size_bytes: 125,
          media_type: "application/json",
          evidence_ids: [],
          subject_artifact_id: "fixture-build-artifact",
          subject_artifact_digest: PRIMARY_DIGEST,
        },
      ],
      build: {
        command: "fixture-only-no-build-was-run",
        environment_id: "fixture-environment-v1",
        started_at: "2026-01-01T00:00:00Z",
        completed_at: "2026-01-01T00:01:00Z",
        deterministic_seed: null,
      },
      toolchain: {
        node: "fixture-node-version-not-evidence",
        package_manager: "fixture-package-manager-version-not-evidence",
        compiler: "fixture-compiler-version-not-evidence",
        platforms: ["fixture-platform-not-evidence"],
      },
    },
    revisions: {
      protocol: "fixture-protocol-revision-not-evidence",
      schema: "fixture-schema-revision-not-evidence",
      abi: "fixture-abi-revision-not-evidence",
      deployment_manifest: "fixture-deployment-revision-not-evidence",
      chain_policy: "fixture-chain-policy-revision-not-evidence",
      feature_flags: "fixture-feature-flags-revision-not-evidence",
    },
    environment: {
      environment_id: "fixture-environment-v1",
      kind: "fixture",
      description:
        "Deterministic contract fixture only; no release or verification execution occurred.",
    },
    approvals: [],
    exceptions: [],
    traceability: requirements.map((requirement) => {
      const [prefix] = requirement.id.split("-");
      const responsibility = RESPONSIBILITY_BY_PREFIX[prefix];
      if (!responsibility) throw new Error(`No responsibility mapping for ${prefix}`);

      return {
        requirement_id: requirement.id,
        applicability: "applicable",
        applicability_justification:
          "Template row only; no verification execution or result is asserted.",
        automated_test_ids: [],
        manual_evidence_ids: [],
        environment_id: "fixture-environment-v1",
        artifact_id: "fixture-build-artifact",
        artifact_digest: PRIMARY_DIGEST,
        evidence_artifact_ids: [],
        owner: responsibility.owner,
        independent_reviewer: responsibility.reviewer,
        result: "not_run",
        completed_at: null,
        evidence_expires_at: null,
        unreachability_proof: null,
      };
    }),
  };
}

export function serializeVerificationEvidenceTemplate(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

async function main() {
  const mode = process.argv[2] ?? "--check";
  if (!["--check", "--write"].includes(mode) || process.argv.length > 3) {
    throw new Error(
      "Usage: node scripts/generate-verification-evidence-template.mjs [--check|--write]",
    );
  }

  const expected = serializeVerificationEvidenceTemplate(
    await createVerificationEvidenceTemplate(),
  );
  if (mode === "--write") {
    await writeFile(EVIDENCE_TEMPLATE_PATH, expected, "utf8");
    process.stdout.write(
      `Wrote ${relative(PROJECT_ROOT, EVIDENCE_TEMPLATE_PATH).split(sep).join("/")}\n`,
    );
    return;
  }

  const actual = await readFile(EVIDENCE_TEMPLATE_PATH, "utf8");
  if (actual !== expected) {
    throw new Error(
      "Verification evidence template drifted; run `npm run evidence:template:write` and review the diff.",
    );
  }
  process.stdout.write("Verification evidence template is deterministic and current.\n");
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath && pathToFileURL(invokedPath).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
