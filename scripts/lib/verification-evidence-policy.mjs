import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REQUIREMENT_PREFIXES = Object.freeze([
  "INV",
  "CRY",
  "PRO",
  "ID",
  "ENT",
  "PRIV",
  "EMB",
  "UX",
  "DATA",
  "OPS",
  "PLAT",
]);

export const REQUIRED_UNREACHABILITY_LAYERS = Object.freeze([
  "web_clients",
  "native_clients",
  "server_routes",
  "admission_decisions",
  "background_jobs",
  "configuration",
  "key_paths",
]);

export const REQUIRED_APPROVAL_ROLES = Object.freeze([
  "security",
  "cryptography",
  "identity",
  "chain_entitlement",
  "privacy",
  "sre",
  "accessibility",
  "product",
]);

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
export const EVIDENCE_POLICY_SOURCE_PATH = fileURLToPath(import.meta.url);
export const PROJECT_ROOT = resolve(scriptDirectory, "../..");
export const VERIFICATION_SPEC_PATH = resolve(
  PROJECT_ROOT,
  "docs/production/verification.md",
);
export const LAUNCH_GATES_SPEC_PATH = resolve(
  PROJECT_ROOT,
  "docs/production/launch-gates.md",
);
export const EVIDENCE_SCHEMA_PATH = resolve(
  PROJECT_ROOT,
  "verification/evidence-manifest.v1.schema.json",
);
export const EVIDENCE_CHECKER_PATH = resolve(
  PROJECT_ROOT,
  "scripts/check-verification-evidence.mjs",
);
export const PACKAGE_LOCK_PATH = resolve(PROJECT_ROOT, "package-lock.json");
export const EVIDENCE_TEMPLATE_PATH = resolve(
  PROJECT_ROOT,
  "verification/fixtures/evidence-template.v1.json",
);

export function extractVerificationRequirements(verificationText) {
  const configuredPrefixes = new Set(REQUIREMENT_PREFIXES);
  const requirements = [];

  for (const line of verificationText.split("\n")) {
    if (!/^\s*\|.*\|\s*$/.test(line)) continue;
    const cells = line
      .trim()
      .replace(/^\||\|$/g, "")
      .split("|")
      .map((cell) => cell.trim());
    const id = cells[0];
    if (!/^[A-Z][A-Z0-9]*-(?:0[1-9]|[1-9]\d+)$/.test(id)) continue;

    const [prefix] = id.split("-");
    if (!configuredPrefixes.has(prefix)) {
      throw new Error(`Verification matrix row ${id} uses an unconfigured requirement prefix`);
    }
    const expectedCellCount = prefix === "INV" ? 2 : 4;
    if (cells.length !== expectedCellCount || cells.some((cell) => cell.length === 0)) {
      throw new Error(
        `Cannot parse verification matrix row ${id}: expected ${expectedCellCount} non-empty cells, received ${cells.length}`,
      );
    }

    requirements.push(
      Object.freeze({
        id,
        title: cells[1],
        evidence: cells.length >= 4 ? cells[2] : cells[1],
        earliestGate: cells.length >= 4 ? cells[3] : null,
      }),
    );
  }

  return Object.freeze(requirements);
}

export async function readVerificationRequirements() {
  return extractVerificationRequirements(await readFile(VERIFICATION_SPEC_PATH, "utf8"));
}

export function requirementCatalogValue(requirements) {
  return requirements.map((requirement) => ({
    id: requirement.id,
    title: requirement.title,
    evidence: requirement.evidence,
    earliest_gate: requirement.earliestGate,
  }));
}

export function isConditionalRequirement(requirement) {
  const gate = requirement.earliestGate ?? "";
  return /\bif\s+(?:shipping\s+)?enabled\b|\bper\s+native\s+client\b/i.test(gate);
}

export function isRequirementInPromotionScope(requirement, targetGate) {
  if (requirement.id.startsWith("INV-")) return targetGate !== "G0";
  if (targetGate === "GX") return /(?:^|\/)GX(?:$|\/)/.test(requirement.earliestGate ?? "");

  const targetNumber = Number(targetGate.slice(1));
  if (!Number.isInteger(targetNumber) || targetNumber < 1 || targetNumber > 8) return false;

  const numericGates = [...(requirement.earliestGate ?? "").matchAll(/\bG([0-8])\b/g)].map(
    (match) => Number(match[1]),
  );
  return numericGates.length > 0 && Math.min(...numericGates) <= targetNumber;
}
