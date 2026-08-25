#!/usr/bin/env node
// Release gate for the vendored MLS bridge (ADR 0004): every artifact in
// bin/mls-bridge/manifest.json must hash to the committed bytes, and the
// manifest's Cargo.lock digest must equal crypto/Cargo.lock - a Rust change
// without `npm run mls:bridge:build` fails here, not in production.
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const manifestPath = join(root, "bin", "mls-bridge", "manifest.json");
const sha256 = (path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const failures = [];
if (manifest.kind !== "jbm-mls-bridge-release-manifest.v1") {
  failures.push(`unexpected manifest kind ${manifest.kind}`);
}
if (manifest.bridgeProtocol !== 1) {
  failures.push(`unexpected bridgeProtocol ${manifest.bridgeProtocol}`);
}
const lockDigest = sha256(join(root, "crypto", "Cargo.lock"));
if (manifest.cargoLockSha256 !== lockDigest) {
  failures.push(
    `crypto/Cargo.lock is ${lockDigest} but the shipped bridge was built from ${manifest.cargoLockSha256}; run npm run mls:bridge:build`,
  );
}
if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
  failures.push("manifest lists no artifacts");
}
for (const artifact of manifest.artifacts ?? []) {
  const path = join(root, "bin", "mls-bridge", artifact.path);
  let digest;
  let size;
  try {
    digest = sha256(path);
    size = statSync(path).size;
  } catch (error) {
    failures.push(`${artifact.platform}: ${String(error)}`);
    continue;
  }
  if (digest !== artifact.sha256 || size !== artifact.sizeBytes) {
    failures.push(
      `${artifact.platform}: committed binary is ${digest} (${size} bytes), manifest pins ${artifact.sha256} (${artifact.sizeBytes} bytes)`,
    );
  }
  if ((statSync(path).mode & 0o111) === 0) {
    failures.push(`${artifact.platform}: binary is not executable`);
  }
}
if (failures.length > 0) {
  for (const failure of failures) console.error(`bridge manifest: ${failure}`);
  process.exit(1);
}
console.log(
  `bridge manifest ok: ${manifest.artifacts.length} artifact(s), Cargo.lock ${lockDigest.slice(0, 12)}`,
);
