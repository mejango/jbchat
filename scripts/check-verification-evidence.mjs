import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { basename, dirname, posix, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import {
  EVIDENCE_SCHEMA_PATH,
  EVIDENCE_CHECKER_PATH,
  EVIDENCE_POLICY_SOURCE_PATH,
  EVIDENCE_TEMPLATE_PATH,
  LAUNCH_GATES_SPEC_PATH,
  PACKAGE_LOCK_PATH,
  PROJECT_ROOT,
  REQUIRED_APPROVAL_ROLES,
  REQUIRED_UNREACHABILITY_LAYERS,
  isConditionalRequirement,
  isRequirementInPromotionScope,
  readVerificationRequirements,
  requirementCatalogValue,
  VERIFICATION_SPEC_PATH,
} from "./lib/verification-evidence-policy.mjs";

const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;
const MAX_APPROVAL_ARTIFACT_BYTES = 1024 * 1024;
const MAX_APPROVAL_TRUST_POLICY_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_VALIDATION_MS = 15 * 60 * 1_000;
const FILE_READ_CHUNK_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_EVIDENCE_AGE_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1_000;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const GATE_PATTERN = /^G(?:[0-8]|X)$/;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const IDENTITY_SUBJECT_PATTERN = /^(?:person|team):[a-z0-9][a-z0-9._/-]*$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._:/-]{2,127}$/;
const APPROVAL_TRUST_SCHEMA = "juicebox-evidence-approval-trust/v1";
const APPROVAL_ENVELOPE_SCHEMA = "juicebox-evidence-approval-envelope/v1";
const APPROVAL_ALGORITHM = "Ed25519";
const VERIFIED_MANIFEST_FILE_TOKEN = Object.freeze({});
const TRUSTED_APPROVAL_VERIFIERS = new WeakMap();
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const CONDITIONAL_FEATURES = Object.freeze({
  "PRIV-10": "attachments",
  "PRIV-12": "reports_and_moderation",
  "DATA-09": "history_archive",
  "UX-11": "shipping",
  "OPS-11": "announcements",
  "PLAT-04": "native_clients",
});

const PLACEHOLDER_TOKEN_PATTERN =
  /(?:^|[-_.:/\s])(?:tbd|todo|fixme|xxx|unknown|unassigned|placeholder|sample|example|nobody|someone|owner|reviewer)(?:$|[-_.:/\s])/i;

function formatJsonLocation(text, offset) {
  const prefix = text.slice(0, offset);
  const line = prefix.split("\n").length;
  const lastNewline = prefix.lastIndexOf("\n");
  return `${line}:${offset - lastNewline}`;
}

function assertUnicodeScalarString(value, label = "JSON string") {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error(`${label} contains an unpaired high surrogate`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new Error(`${label} contains an unpaired low surrogate`);
    }
  }
  return value;
}

export function decodeUtf8Strict(bytes, label = "JSON document") {
  try {
    const text = UTF8_DECODER.decode(bytes);
    if (text.charCodeAt(0) === 0xfeff) {
      throw new Error("byte-order marks are not permitted");
    }
    return text;
  } catch {
    throw new Error(`${label} is not canonical UTF-8`);
  }
}

export function parseJsonRejectingDuplicateKeys(text) {
  if (Buffer.byteLength(text, "utf8") > MAX_MANIFEST_BYTES) {
    throw new Error(`JSON document exceeds ${MAX_MANIFEST_BYTES} bytes`);
  }

  let offset = 0;

  function fail(message) {
    throw new Error(`${message} at ${formatJsonLocation(text, offset)}`);
  }

  function skipWhitespace() {
    while (/[\t\n\r ]/.test(text[offset] ?? "")) offset += 1;
  }

  function parseString() {
    if (text[offset] !== '"') fail("Expected JSON string");
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return assertUnicodeScalarString(
            JSON.parse(text.slice(start, offset)),
            "JSON string",
          );
        } catch {
          fail("Invalid JSON string or Unicode scalar value");
        }
      }
      if (character === "\\") {
        offset += 1;
        const escape = text[offset];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(offset + 1, offset + 5))) {
            fail("Invalid JSON unicode escape");
          }
          offset += 5;
          continue;
        }
        if (!/["\\/bfnrt]/.test(escape ?? "")) fail("Invalid JSON escape");
        offset += 1;
        continue;
      }
      if (character.charCodeAt(0) <= 0x1f) fail("Unescaped control character in JSON string");
      offset += 1;
    }
    fail("Unterminated JSON string");
  }

  function parseNumber() {
    const match = text.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) fail("Invalid JSON number");
    offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail("Non-finite JSON number");
    return value;
  }

  function parseValue(depth) {
    if (depth > MAX_JSON_DEPTH) fail(`JSON nesting exceeds ${MAX_JSON_DEPTH}`);
    skipWhitespace();
    const character = text[offset];
    if (character === "{") return parseObject(depth + 1);
    if (character === "[") return parseArray(depth + 1);
    if (character === '"') return parseString();
    if (character === "-" || /\d/.test(character ?? "")) return parseNumber();
    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    fail("Unexpected JSON token");
  }

  function parseObject(depth) {
    const value = {};
    const keys = new Set();
    offset += 1;
    skipWhitespace();
    if (text[offset] === "}") {
      offset += 1;
      return value;
    }

    while (offset < text.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail(`Duplicate JSON object key ${JSON.stringify(key)}`);
      keys.add(key);
      skipWhitespace();
      if (text[offset] !== ":") fail("Expected ':' after JSON object key");
      offset += 1;
      Object.defineProperty(value, key, {
        value: parseValue(depth),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return value;
      }
      if (text[offset] !== ",") fail("Expected ',' or '}' in JSON object");
      offset += 1;
    }
    fail("Unterminated JSON object");
  }

  function parseArray(depth) {
    const value = [];
    offset += 1;
    skipWhitespace();
    if (text[offset] === "]") {
      offset += 1;
      return value;
    }

    while (offset < text.length) {
      value.push(parseValue(depth));
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return value;
      }
      if (text[offset] !== ",") fail("Expected ',' or ']' in JSON array");
      offset += 1;
    }
    fail("Unterminated JSON array");
  }

  const value = parseValue(0);
  skipWhitespace();
  if (offset !== text.length) fail("Trailing data after JSON document");
  return value;
}

export function canonicalJson(value) {
  const ancestors = new WeakSet();

  function serialize(entry) {
    if (entry === null || typeof entry === "boolean") return JSON.stringify(entry);
    if (typeof entry === "string") {
      return JSON.stringify(assertUnicodeScalarString(entry));
    }
    if (typeof entry === "number") {
      if (!Number.isFinite(entry)) throw new Error("Cannot canonicalize a non-finite number");
      return JSON.stringify(entry);
    }
    if (typeof entry !== "object") throw new Error("Cannot canonicalize a non-JSON value");
    if (ancestors.has(entry)) throw new Error("Cannot canonicalize a cyclic JSON value");
    ancestors.add(entry);
    try {
      if (Array.isArray(entry)) {
        const ownKeys = Reflect.ownKeys(entry);
        const descriptors = Object.getOwnPropertyDescriptors(entry);
        if (
          ownKeys.some(
            (key) =>
              typeof key === "symbol" ||
              (key !== "length" && !/^(?:0|[1-9]\d*)$/.test(key)),
          ) ||
          Object.keys(entry).length !== entry.length ||
          Array.from({ length: entry.length }, (_, index) => index).some(
            (index) => {
              const descriptor = descriptors[index];
              return (
                !descriptor?.enumerable ||
                !("value" in descriptor) ||
                descriptor.get !== undefined ||
                descriptor.set !== undefined
              );
            },
          )
        ) {
          throw new Error("Cannot canonicalize a sparse or decorated JSON array");
        }
        return `[${Array.from({ length: entry.length }, (_, index) => serialize(descriptors[index].value)).join(",")}]`;
      }

      const prototype = Object.getPrototypeOf(entry);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error("Cannot canonicalize a non-plain JSON object");
      }
      if (Object.getOwnPropertySymbols(entry).length > 0) {
        throw new Error("Cannot canonicalize symbol-keyed JSON data");
      }
      const descriptors = Object.getOwnPropertyDescriptors(entry);
      const keys = Object.keys(entry).sort();
      if (
        Object.getOwnPropertyNames(entry).length !== keys.length ||
        keys.some(
          (key) =>
            !descriptors[key]?.enumerable ||
            !("value" in descriptors[key]) ||
            descriptors[key].get !== undefined ||
            descriptors[key].set !== undefined,
        )
      ) {
        throw new Error("Cannot canonicalize hidden or accessor JSON properties");
      }
      return `{${keys
        .map(
          (key) =>
            `${JSON.stringify(assertUnicodeScalarString(key, "JSON object key"))}:${serialize(descriptors[key].value)}`,
        )
        .join(",")}}`;
    } finally {
      ancestors.delete(entry);
    }
  }

  return serialize(value);
}

export function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function evidenceCheckerBundleValue(checkerSource, policySource, packageLock) {
  return {
    schema_version: "juicebox-evidence-checker-source-bundle/v1",
    sources: [
      { path: "scripts/check-verification-evidence.mjs", digest: sha256(checkerSource) },
      {
        path: "scripts/lib/verification-evidence-policy.mjs",
        digest: sha256(policySource),
      },
      { path: "package-lock.json", digest: sha256(packageLock) },
    ],
  };
}

export function evidenceCheckerBundleDigest(checkerSource, policySource, packageLock) {
  return sha256(canonicalJson(evidenceCheckerBundleValue(checkerSource, policySource, packageLock)));
}

function requireExactObjectKeys(value, expectedKeys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  const actualKeys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actualKeys.join("\0") !== expected.join("\0")) {
    throw new Error(`${label} must contain exactly: ${expected.join(", ")}`);
  }
}

function decodeCanonicalBase64(value, label, maximumCharacters) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumCharacters ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new Error(`${label} must be canonical padded base64`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new Error(`${label} must be canonical padded base64`);
  }
  return bytes;
}

export function approvalEnvelopeSigningValue(envelope) {
  return {
    schema_version: envelope?.schema_version,
    algorithm: envelope?.algorithm,
    key_id: envelope?.key_id,
    role: envelope?.role,
    signer_subject: envelope?.signer_subject,
    subject_digest: envelope?.subject_digest,
    signed_at: envelope?.signed_at,
    expires_at: envelope?.expires_at,
  };
}

export function approvalEnvelopeSigningBytes(envelope) {
  return Buffer.from(canonicalJson(approvalEnvelopeSigningValue(envelope)), "utf8");
}

export function promotionApprovalSubjectValue(manifest) {
  const release = manifest?.release ?? {};
  const promotion = manifest?.promotion ?? {};
  return {
    schema_version: manifest?.schema_version,
    manifest_kind: manifest?.manifest_kind,
    generated_at: manifest?.generated_at,
    evidence_as_of: manifest?.evidence_as_of,
    policy: manifest?.policy,
    promotion: {
      requested: promotion.requested,
      target_gate: promotion.target_gate,
      scope: promotion.scope,
    },
    release: {
      ...release,
      artifacts: Array.isArray(release.artifacts)
        ? release.artifacts.filter((artifact) => artifact?.kind !== "approval")
        : release.artifacts,
    },
    revisions: manifest?.revisions,
    environment: manifest?.environment,
    exceptions: manifest?.exceptions,
    traceability: manifest?.traceability,
  };
}

export function promotionApprovalSubjectDigest(manifest) {
  return sha256(canonicalJson(promotionApprovalSubjectValue(manifest)));
}

export function unreachabilityProofDigest(proof) {
  return sha256(
    canonicalJson({
      feature_id: proof.feature_id,
      layers: proof.layers,
    }),
  );
}

function issue(code, path, message) {
  return Object.freeze({ code, path, message });
}

function parseCanonicalTimestamp(value, path, issues) {
  if (typeof value !== "string") return undefined;
  if (!TIMESTAMP_PATTERN.test(value)) {
    issues.push(issue("invalid_timestamp", path, "must be canonical UTC RFC 3339 seconds"));
    return undefined;
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    issues.push(issue("invalid_timestamp", path, "is not a real calendar timestamp"));
    return undefined;
  }
  const roundTrip = new Date(milliseconds).toISOString().replace(".000Z", "Z");
  if (roundTrip !== value) {
    issues.push(issue("invalid_timestamp", path, "is not a real canonical UTC timestamp"));
    return undefined;
  }
  return milliseconds;
}

function checkChronology(start, end, startPath, endPath, issues) {
  if (start !== undefined && end !== undefined && start > end) {
    issues.push(issue("invalid_chronology", endPath, `must not precede ${startPath}`));
  }
}

function isPlaceholderIdentity(identity) {
  if (!identity || typeof identity !== "object") return false;
  return [identity.subject, identity.display_name].some(
    (value) => typeof value === "string" && PLACEHOLDER_TOKEN_PATTERN.test(value.trim()),
  );
}

function checkIdentity(identity, path, issues) {
  if (!identity || typeof identity !== "object") return;
  if (isPlaceholderIdentity(identity)) {
    issues.push(issue("placeholder_identity", path, "must name a concrete accountable principal or team"));
  }
}

function addDuplicateIssues(values, field, path, issues) {
  if (!Array.isArray(values)) return;
  const firstIndex = new Map();
  for (const [index, value] of values.entries()) {
    if (typeof value !== "string") continue;
    if (firstIndex.has(value)) {
      issues.push(
        issue(
          "duplicate_identifier",
          `${path}/${index}/${field}`,
          `duplicates ${JSON.stringify(value)} from index ${firstIndex.get(value)}`,
        ),
      );
    } else {
      firstIndex.set(value, index);
    }
  }
}

function isInsideDirectory(base, target) {
  const pathFromBase = relative(base, target);
  return pathFromBase === "" || (pathFromBase !== ".." && !pathFromBase.startsWith(`..${sep}`));
}

function fileIssue(code, message) {
  return Object.assign(new Error(message), { evidenceCode: code });
}

function enforceArtifactDeadline(deadlineMs) {
  if (Number.isFinite(deadlineMs) && performance.now() >= deadlineMs) {
    throw fileIssue(
      "artifact_validation_timeout",
      `artifact validation exceeded ${MAX_ARTIFACT_VALIDATION_MS} milliseconds`,
    );
  }
}

function sameFileIdentity(left, right, { stableContent = false } = {}) {
  if (!left || !right) return false;
  if (left.dev !== right.dev || left.ino !== right.ino || left.mode !== right.mode) return false;
  if (!stableContent) return true;
  return (
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function snapshotArtifactPath(realBundle, artifactPath, deadlineMs) {
  const snapshots = [];
  let currentPath = realBundle;
  const segments = artifactPath.split("/");
  for (const [index, segment] of segments.entries()) {
    enforceArtifactDeadline(deadlineMs);
    currentPath = resolve(currentPath, segment);
    const stats = await lstat(currentPath, { bigint: true });
    enforceArtifactDeadline(deadlineMs);
    if (stats.isSymbolicLink()) {
      throw fileIssue("invalid_artifact_file", "must not traverse a symbolic-link path component");
    }
    if (index < segments.length - 1 && !stats.isDirectory()) {
      throw fileIssue("invalid_artifact_file", "contains a non-directory path component");
    }
    snapshots.push({ path: currentPath, stats });
  }
  return snapshots;
}

async function recheckArtifactPath(snapshots, descriptorStats, deadlineMs) {
  for (const [index, snapshot] of snapshots.entries()) {
    enforceArtifactDeadline(deadlineMs);
    const current = await lstat(snapshot.path, { bigint: true });
    enforceArtifactDeadline(deadlineMs);
    const isTarget = index === snapshots.length - 1;
    if (
      current.isSymbolicLink() ||
      !sameFileIdentity(snapshot.stats, current, { stableContent: isTarget })
    ) {
      throw fileIssue("artifact_changed_during_validation", "path identity changed during validation");
    }
  }
  const target = snapshots.at(-1)?.stats;
  if (!sameFileIdentity(target, descriptorStats, { stableContent: true })) {
    throw fileIssue(
      "artifact_changed_during_validation",
      "opened descriptor does not match the validated bundle path",
    );
  }
}

export async function readStableRegularFile(
  targetPath,
  {
    maxBytes,
    expectedSize,
    expectedPathStats,
    captureBytes = false,
    checkpoint,
    deadlineMs,
  } = {},
) {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0) {
    throw fileIssue(
      "unsupported_artifact_filesystem",
      "this platform does not expose O_NOFOLLOW; promotion verification is unavailable",
    );
  }
  const byteLimit = Number.isSafeInteger(maxBytes) && maxBytes > 0 ? maxBytes : MAX_ARTIFACT_BYTES;
  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_NONBLOCK ?? 0);
  enforceArtifactDeadline(deadlineMs);
  await checkpoint?.("before_open");
  enforceArtifactDeadline(deadlineMs);
  const handle = await open(targetPath, flags);
  try {
    enforceArtifactDeadline(deadlineMs);
    const before = await handle.stat({ bigint: true });
    enforceArtifactDeadline(deadlineMs);
    if (!before.isFile()) {
      throw fileIssue("invalid_artifact_file", "must be a regular file");
    }
    if (before.nlink !== 1n) {
      throw fileIssue("invalid_artifact_file", "must not be hard-linked outside the immutable bundle");
    }
    if (expectedPathStats && !sameFileIdentity(expectedPathStats, before, { stableContent: true })) {
      throw fileIssue(
        "artifact_changed_during_validation",
        "path identity changed before the file descriptor was opened",
      );
    }
    if (before.size > BigInt(byteLimit)) {
      throw fileIssue("artifact_too_large", `exceeds the ${byteLimit}-byte verifier limit`);
    }
    if (expectedSize !== undefined && before.size !== BigInt(expectedSize)) {
      throw fileIssue(
        "artifact_size_mismatch",
        `declares ${expectedSize} bytes but retained file has ${before.size.toString()}`,
      );
    }

    const expectedBytes = Number(before.size);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(FILE_READ_CHUNK_BYTES, Math.max(1, expectedBytes)));
    const captured = captureBytes ? [] : undefined;
    let position = 0;
    await checkpoint?.("after_pre_stat");
    enforceArtifactDeadline(deadlineMs);
    while (position < expectedBytes) {
      enforceArtifactDeadline(deadlineMs);
      const length = Math.min(buffer.length, expectedBytes - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      enforceArtifactDeadline(deadlineMs);
      if (bytesRead === 0) {
        throw fileIssue("artifact_changed_during_validation", "file truncated while it was being hashed");
      }
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (captured) captured.push(Buffer.from(chunk));
      position += bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    if ((await handle.read(probe, 0, 1, position)).bytesRead !== 0) {
      throw fileIssue("artifact_changed_during_validation", "file grew while it was being hashed");
    }
    await checkpoint?.("after_hash");
    enforceArtifactDeadline(deadlineMs);

    const after = await handle.stat({ bigint: true });
    enforceArtifactDeadline(deadlineMs);
    if (!sameFileIdentity(before, after, { stableContent: true })) {
      throw fileIssue("artifact_changed_during_validation", "file metadata changed while it was being hashed");
    }
    const pathAfter = await lstat(targetPath, { bigint: true });
    enforceArtifactDeadline(deadlineMs);
    if (
      pathAfter.isSymbolicLink() ||
      !sameFileIdentity(after, pathAfter, { stableContent: true })
    ) {
      throw fileIssue(
        "artifact_changed_during_validation",
        "bundle path no longer identifies the opened file",
      );
    }
    return {
      bytes: captured ? Buffer.concat(captured, expectedBytes) : undefined,
      digest: `sha256:${hash.digest("hex")}`,
      stats: after,
    };
  } finally {
    await handle.close();
  }
}

async function validateArtifactFile(
  artifact,
  index,
  manifestDirectory,
  { captureApprovalBytes = false, deadlineMs } = {},
) {
  const issues = [];
  const artifactPath = artifact?.path;
  if (typeof artifactPath !== "string") return { issues };
  if (
    artifactPath !== posix.normalize(artifactPath) ||
    artifactPath.startsWith("/") ||
    artifactPath.split("/").includes("..") ||
    artifactPath.includes("\\")
  ) {
    issues.push(
      issue("unsafe_artifact_path", `/release/artifacts/${index}/path`, "must be a normalized relative POSIX path"),
    );
    return { issues };
  }

  enforceArtifactDeadline(deadlineMs);
  const realBundle = await realpath(manifestDirectory);
  enforceArtifactDeadline(deadlineMs);
  const targetPath = resolve(realBundle, artifactPath);
  if (!isInsideDirectory(realBundle, targetPath)) {
    issues.push(issue("unsafe_artifact_path", `/release/artifacts/${index}/path`, "escapes the evidence bundle"));
    return { issues };
  }

  try {
    const snapshots = await snapshotArtifactPath(realBundle, artifactPath, deadlineMs);
    const realTargetBefore = await realpath(targetPath);
    enforceArtifactDeadline(deadlineMs);
    if (!isInsideDirectory(realBundle, realTargetBefore)) {
      issues.push(issue("unsafe_artifact_path", `/release/artifacts/${index}/path`, "resolves outside the bundle"));
      return { issues };
    }
    const result = await readStableRegularFile(targetPath, {
      maxBytes: artifact?.kind === "approval" ? MAX_APPROVAL_ARTIFACT_BYTES : MAX_ARTIFACT_BYTES,
      expectedSize: Number.isSafeInteger(artifact?.size_bytes) ? artifact.size_bytes : undefined,
      expectedPathStats: snapshots.at(-1)?.stats,
      captureBytes: artifact?.kind === "approval" && captureApprovalBytes,
      deadlineMs,
    });
    await recheckArtifactPath(snapshots, result.stats, deadlineMs);
    const realTargetAfter = await realpath(targetPath);
    enforceArtifactDeadline(deadlineMs);
    if (realTargetAfter !== realTargetBefore || !isInsideDirectory(realBundle, realTargetAfter)) {
      throw fileIssue("artifact_changed_during_validation", "resolved path changed during validation");
    }
    if (typeof artifact?.digest === "string" && SHA256_PATTERN.test(artifact.digest) && result.digest !== artifact.digest) {
      issues.push(
        issue(
          "artifact_digest_mismatch",
          `/release/artifacts/${index}/digest`,
          `declares ${artifact.digest} but retained file hashes to ${result.digest}`,
        ),
      );
    }
    return {
      artifactId: artifact?.artifact_id,
      bytes: result.bytes,
      digest: result.digest,
      fileIdentity: `${result.stats.dev.toString()}:${result.stats.ino.toString()}`,
      issues,
      path: targetPath,
    };
  } catch (error) {
    issues.push(
      issue(
        error?.evidenceCode ?? (error?.code === "ENOENT" ? "missing_artifact_file" : "invalid_artifact_file"),
        `/release/artifacts/${index}/path`,
        `cannot read retained artifact: ${error instanceof Error ? error.message : String(error)}`,
      ),
    );
    return { issues };
  }
}

function checkArtifactBinding(binding, path, primaryArtifact, issues) {
  if (!binding || typeof binding !== "object" || !primaryArtifact) return;
  if (binding.artifact_id !== primaryArtifact.artifact_id) {
    issues.push(
      issue(
        "unbound_subject_artifact",
        `${path}/artifact_id`,
        `must bind the primary release artifact ${JSON.stringify(primaryArtifact.artifact_id)}`,
      ),
    );
  }
  if (binding.artifact_digest !== primaryArtifact.digest) {
    issues.push(
      issue(
        "unbound_subject_artifact",
        `${path}/artifact_digest`,
        "must equal the primary release artifact digest",
      ),
    );
  }
}

function checkEvidenceArtifactReferences(
  artifactIds,
  automatedTestIds,
  manualEvidenceIds,
  path,
  retainedArtifacts,
  primaryArtifact,
  issues,
) {
  if (!Array.isArray(artifactIds)) return;
  const automatedBindings = new Set();
  const manualBindings = new Set();
  for (const [index, artifactId] of artifactIds.entries()) {
    const artifact = retainedArtifacts.get(artifactId);
    if (!artifact) {
      issues.push(
        issue("unbound_evidence_artifact", `${path}/${index}`, "does not identify a retained artifact"),
      );
      continue;
    }
    if (!["test_output", "review"].includes(artifact.kind)) {
      issues.push(
        issue(
          "invalid_evidence_artifact_kind",
          `${path}/${index}`,
          "must identify a typed test_output or review artifact",
        ),
      );
      continue;
    }
    if (
      !primaryArtifact ||
      artifact.subject_artifact_id !== primaryArtifact.artifact_id ||
      artifact.subject_artifact_digest !== primaryArtifact.digest
    ) {
      issues.push(
        issue(
          "unbound_evidence_subject",
          `${path}/${index}`,
          "must bind the primary release artifact ID and digest",
        ),
      );
    }
    const destination = artifact.kind === "test_output" ? automatedBindings : manualBindings;
    for (const evidenceId of artifact.evidence_ids ?? []) destination.add(evidenceId);
  }
  for (const [index, evidenceId] of (automatedTestIds ?? []).entries()) {
    if (!automatedBindings.has(evidenceId)) {
      issues.push(
        issue(
          "unbound_evidence_id",
          `${path.replace(/evidence_artifact_ids$/, "automated_test_ids")}/${index}`,
          "has no matching ID in a referenced test_output artifact",
        ),
      );
    }
  }
  for (const [index, evidenceId] of (manualEvidenceIds ?? []).entries()) {
    if (!manualBindings.has(evidenceId)) {
      issues.push(
        issue(
          "unbound_evidence_id",
          `${path.replace(/evidence_artifact_ids$/, "manual_evidence_ids")}/${index}`,
          "has no matching ID in a referenced review artifact",
        ),
      );
    }
  }
}

function checkEvidenceWindow(record, index, buildCompletedAt, asOf, issues) {
  const recordPath = `/traceability/${index}`;
  const completedAt = parseCanonicalTimestamp(
    record.completed_at,
    `${recordPath}/completed_at`,
    issues,
  );
  const expiresAt = parseCanonicalTimestamp(
    record.evidence_expires_at,
    `${recordPath}/evidence_expires_at`,
    issues,
  );
  if (record.result === "not_run") return;

  if (completedAt !== undefined && buildCompletedAt !== undefined && completedAt < buildCompletedAt) {
    issues.push(
      issue(
        "pre_artifact_evidence",
        `${recordPath}/completed_at`,
        "predates completion of the bound build artifact",
      ),
    );
  }
  checkChronology(
    completedAt,
    expiresAt,
    `${recordPath}/completed_at`,
    `${recordPath}/evidence_expires_at`,
    issues,
  );
  if (completedAt !== undefined && expiresAt !== undefined && expiresAt - completedAt > MAX_EVIDENCE_AGE_MS) {
    issues.push(
      issue(
        "invalid_evidence_expiry",
        `${recordPath}/evidence_expires_at`,
        "may be at most 30 days after completion",
      ),
    );
  }
  if (completedAt !== undefined && asOf - completedAt > MAX_EVIDENCE_AGE_MS) {
    issues.push(issue("stale_evidence", `${recordPath}/completed_at`, "is more than 30 days old"));
  }
  if (completedAt !== undefined && completedAt > asOf + MAX_CLOCK_SKEW_MS) {
    issues.push(issue("future_evidence", `${recordPath}/completed_at`, "is in the future"));
  }
  if (expiresAt !== undefined && asOf >= expiresAt) {
    issues.push(issue("stale_evidence", `${recordPath}/evidence_expires_at`, "has expired"));
  }
}

function activeCapabilities(promotion) {
  const scope = promotion?.scope ?? {};
  const capabilities = new Set(scope.capabilities ?? []);
  if ((scope.attachment_types ?? []).length > 0) capabilities.add("attachments");
  if ((scope.recovery_modes ?? []).some((mode) => /archive/i.test(mode))) {
    capabilities.add("history_archive");
  }
  if (
    (scope.clients ?? []).some((client) =>
      /(?:^|[-_.:/])(ios|android|native)(?:$|[-_.:/])/i.test(client),
    )
  ) {
    capabilities.add("native_clients");
  }
  return capabilities;
}

function checkUnreachabilityProof(
  record,
  index,
  requirement,
  primaryArtifact,
  retainedArtifacts,
  capabilities,
  issues,
) {
  if (record.applicability !== "not_applicable") return;
  const path = `/traceability/${index}/unreachability_proof`;
  if (!isConditionalRequirement(requirement)) {
    issues.push(
      issue(
        "invalid_not_applicable",
        `/traceability/${index}/applicability`,
        "unconditional requirements cannot be marked not applicable",
      ),
    );
  }

  const proof = record.unreachability_proof;
  if (!proof || typeof proof !== "object") return;
  const expectedFeature = CONDITIONAL_FEATURES[requirement.id];
  if (expectedFeature && proof.feature_id !== expectedFeature) {
    issues.push(
      issue(
        "wrong_unreachability_feature",
        `${path}/feature_id`,
        `must be ${JSON.stringify(expectedFeature)} for ${requirement.id}`,
      ),
    );
  }
  if (capabilities.has(proof.feature_id)) {
    issues.push(
      issue(
        "enabled_feature_not_applicable",
        `${path}/feature_id`,
        "is enabled in the promotion scope and cannot be declared unreachable",
      ),
    );
  }

  if (Array.isArray(proof.layers)) {
    const observed = proof.layers.map((layer) => layer?.layer);
    if (observed.join("|") !== REQUIRED_UNREACHABILITY_LAYERS.join("|")) {
      issues.push(
        issue(
          "incomplete_unreachability_layers",
          `${path}/layers`,
          `must contain each shipped layer exactly once in canonical order: ${REQUIRED_UNREACHABILITY_LAYERS.join(", ")}`,
        ),
      );
    }
    for (const [layerIndex, layer] of proof.layers.entries()) {
      checkArtifactBinding(layer, `${path}/layers/${layerIndex}`, primaryArtifact, issues);
      checkEvidenceArtifactReferences(
        layer?.evidence_artifact_ids,
        ["static_analysis", "negative_integration_test"].includes(layer?.method)
          ? layer?.verification_ids
          : [],
        ["artifact_inspection", "configuration_attestation"].includes(layer?.method)
          ? layer?.verification_ids
          : [],
        `${path}/layers/${layerIndex}/evidence_artifact_ids`,
        retainedArtifacts,
        primaryArtifact,
        issues,
      );
    }
  }

  if (typeof proof.proof_digest === "string" && Array.isArray(proof.layers)) {
    const expectedDigest = unreachabilityProofDigest(proof);
    if (proof.proof_digest !== expectedDigest) {
      issues.push(
        issue(
          "unreachability_digest_mismatch",
          `${path}/proof_digest`,
          `must equal ${expectedDigest}`,
        ),
      );
    }
  }
}

function checkApprovalAndExceptionDates(
  manifest,
  asOf,
  generatedAt,
  approvalSubjectDigest,
  retainedArtifacts,
  issues,
) {
  for (const [index, approval] of (manifest.approvals ?? []).entries()) {
    checkIdentity(approval?.approver, `/approvals/${index}/approver`, issues);
    const signedAt = parseCanonicalTimestamp(approval?.signed_at, `/approvals/${index}/signed_at`, issues);
    const expiresAt = parseCanonicalTimestamp(
      approval?.expires_at,
      `/approvals/${index}/expires_at`,
      issues,
    );
    checkChronology(
      signedAt,
      expiresAt,
      `/approvals/${index}/signed_at`,
      `/approvals/${index}/expires_at`,
      issues,
    );
    if (signedAt !== undefined && signedAt > asOf + MAX_CLOCK_SKEW_MS) {
      issues.push(issue("future_approval", `/approvals/${index}/signed_at`, "is in the future"));
    }
    if (signedAt !== undefined && generatedAt !== undefined && signedAt < generatedAt) {
      issues.push(
        issue(
          "pre_manifest_approval",
          `/approvals/${index}/signed_at`,
          "predates the canonical manifest subject it claims to approve",
        ),
      );
    }
    if (expiresAt !== undefined && asOf >= expiresAt) {
      issues.push(issue("stale_approval", `/approvals/${index}/expires_at`, "has expired"));
    }
    const artifact = retainedArtifacts.get(approval?.artifact_id);
    if (!artifact || artifact.digest !== approval?.artifact_digest || artifact.kind !== "approval") {
      issues.push(
        issue(
          "unbound_approval",
          `/approvals/${index}/artifact_id`,
          "must reference a digest-matching retained approval artifact",
        ),
      );
    }
    if (
      typeof approvalSubjectDigest === "string" &&
      approval?.signed_payload_digest !== approvalSubjectDigest
    ) {
      issues.push(
        issue(
          "approval_subject_mismatch",
          `/approvals/${index}/signed_payload_digest`,
          "must equal the canonical promotion approval subject digest",
        ),
      );
    }
  }

  for (const [index, exception] of (manifest.exceptions ?? []).entries()) {
    checkIdentity(exception?.owner, `/exceptions/${index}/owner`, issues);
    checkIdentity(exception?.reviewer, `/exceptions/${index}/reviewer`, issues);
    if (exception?.owner?.subject === exception?.reviewer?.subject) {
      issues.push(
        issue(
          "non_independent_reviewer",
          `/exceptions/${index}/reviewer/subject`,
          "must differ from the exception owner",
        ),
      );
    }
    const approvedAt = parseCanonicalTimestamp(
      exception?.approved_at,
      `/exceptions/${index}/approved_at`,
      issues,
    );
    const expiresAt = parseCanonicalTimestamp(
      exception?.expires_at,
      `/exceptions/${index}/expires_at`,
      issues,
    );
    checkChronology(
      approvedAt,
      expiresAt,
      `/exceptions/${index}/approved_at`,
      `/exceptions/${index}/expires_at`,
      issues,
    );
    if (approvedAt !== undefined && approvedAt > asOf + MAX_CLOCK_SKEW_MS) {
      issues.push(issue("future_exception", `/exceptions/${index}/approved_at`, "is in the future"));
    }
    if (approvedAt !== undefined && expiresAt !== undefined && expiresAt - approvedAt > MAX_EVIDENCE_AGE_MS) {
      issues.push(
        issue(
          "invalid_exception_expiry",
          `/exceptions/${index}/expires_at`,
          "may be at most 30 days after approval",
        ),
      );
    }
    if (expiresAt !== undefined && asOf >= expiresAt) {
      issues.push(issue("stale_exception", `/exceptions/${index}/expires_at`, "has expired"));
    }
    if ((exception?.requirement_ids ?? []).some((id) => id.startsWith("INV-"))) {
      issues.push(
        issue(
          "invariant_exception",
          `/exceptions/${index}/requirement_ids`,
          "release-blocking invariants cannot have exceptions",
        ),
      );
    }
  }
}

async function checkTrustedApprovalSignatures(
  manifest,
  approvalSubjectDigest,
  retainedArtifacts,
  verifiedArtifactFiles,
  approvalVerifier,
  issues,
) {
  if (typeof approvalVerifier !== "function") {
    issues.push(
      issue(
        "missing_approval_verifier",
        "/approvals",
        "promotion requires an externally trusted signature and role-authorization verifier",
      ),
    );
    return;
  }
  if (!TRUSTED_APPROVAL_VERIFIERS.has(approvalVerifier)) {
    issues.push(
      issue(
        "untrusted_approval_verifier",
        "/approvals",
        "promotion rejects caller-supplied verifier functions; load a digest-pinned declarative trust policy",
      ),
    );
    return;
  }

  for (const [index, approval] of (manifest.approvals ?? []).entries()) {
    const artifact = retainedArtifacts.get(approval?.artifact_id);
    const verifiedFile = verifiedArtifactFiles.get(approval?.artifact_id);
    if (!artifact || !verifiedFile?.bytes) {
      issues.push(
        issue(
          "unverified_approval_signature",
          `/approvals/${index}/artifact_id`,
          "approval artifact bytes were not safely retained for signature verification",
        ),
      );
      continue;
    }

    try {
      const verification = await approvalVerifier(
        Object.freeze({
          approval: structuredClone(approval),
          approvalArtifact: structuredClone(artifact),
          approvalArtifactBytes: Uint8Array.from(verifiedFile.bytes),
          subjectDigest: approvalSubjectDigest,
        }),
      );
      if (
        verification?.signatureVerified !== true ||
        verification?.roleAuthorized !== true ||
        verification?.role !== approval.role ||
        verification?.signerSubject !== approval.approver?.subject ||
        verification?.subjectDigest !== approvalSubjectDigest ||
        verification?.artifactDigest !== approval.artifact_digest ||
        verification?.signedAt !== approval.signed_at ||
        verification?.expiresAt !== approval.expires_at
      ) {
        issues.push(
          issue(
            "unverified_approval_signature",
            `/approvals/${index}`,
            "trusted verifier did not confirm the signature, role, principal, subject, dates, and artifact digest",
          ),
        );
      }
    } catch (error) {
      issues.push(
        issue(
          "approval_verifier_failure",
          `/approvals/${index}`,
          `trusted verifier failed closed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
    }
  }
}

function schemaIssues(validate) {
  return (validate.errors ?? []).map((error) =>
    issue(
      "schema_violation",
      error.instancePath || "/",
      `${error.message ?? "violates schema"}${
        error.params?.additionalProperty
          ? `: ${JSON.stringify(error.params.additionalProperty)}`
          : ""
      }`,
    ),
  );
}

async function compileSchema() {
  const schemaBytes = await readFile(EVIDENCE_SCHEMA_PATH);
  const schemaText = decodeUtf8Strict(schemaBytes, "evidence schema");
  const schema = parseJsonRejectingDuplicateKeys(schemaText);
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
  });
  addFormats(ajv);
  return { schema, schemaBytes, schemaText, validate: ajv.compile(schema) };
}

export async function validateEvidenceManifest({
  manifest,
  manifestPath,
  mode = "contract",
  asOf,
  expectedCommit,
  expectedArtifactDigest,
  expectedGate,
  expectedCheckerBundleDigest,
  expectedApprovalTrustDigest,
  verifyArtifactFiles = true,
  approvalVerifier,
  _manifestFileVerification,
} = {}) {
  if (!["contract", "promotion"].includes(mode)) throw new Error(`Unknown validation mode ${mode}`);
  if (asOf !== undefined && (!(asOf instanceof Date) || !Number.isFinite(asOf.getTime()))) {
    throw new Error("asOf must be a valid Date");
  }
  const evaluationAsOf = mode === "promotion" ? new Date() : (asOf ?? new Date());

  const [
    { schema, schemaBytes, validate },
    requirements,
    verificationSpec,
    launchGates,
    checkerSource,
    policySource,
    packageLock,
  ] = await Promise.all([
    compileSchema(),
    readVerificationRequirements(),
    readFile(VERIFICATION_SPEC_PATH),
    readFile(LAUNCH_GATES_SPEC_PATH),
    readFile(EVIDENCE_CHECKER_PATH),
    readFile(EVIDENCE_POLICY_SOURCE_PATH),
    readFile(PACKAGE_LOCK_PATH),
  ]);
  const requirementById = new Map(requirements.map((requirement) => [requirement.id, requirement]));
  const configuredIds = requirements.map((requirement) => requirement.id);
  const schemaIds = schema.$defs.requirementId.enum;
  const issues = [];

  const schemaValid = validate(manifest);
  if (!schemaValid) issues.push(...schemaIssues(validate));
  let approvalSubjectDigest;
  if (schemaValid && manifest?.manifest_kind === "release_evidence") {
    approvalSubjectDigest = promotionApprovalSubjectDigest(manifest);
    if (manifest?.promotion?.approval_subject_digest !== approvalSubjectDigest) {
      issues.push(
        issue(
          "approval_subject_mismatch",
          "/promotion/approval_subject_digest",
          `must bind the canonical promotion subject as ${approvalSubjectDigest}`,
        ),
      );
    }
  }
  if (schemaIds.join("|") !== configuredIds.join("|")) {
    issues.push(
      issue(
        "schema_policy_drift",
        "/$defs/requirementId/enum",
        "schema requirement IDs must exactly match docs/production/verification.md in canonical order",
      ),
    );
  }
  const configuredConditionalIds = requirements
    .filter((requirement) => isConditionalRequirement(requirement))
    .map((requirement) => requirement.id)
    .sort();
  const mappedConditionalIds = Object.keys(CONDITIONAL_FEATURES).sort();
  if (configuredConditionalIds.join("|") !== mappedConditionalIds.join("|")) {
    issues.push(
      issue(
        "conditional_policy_drift",
        "/$defs/conditionalFeature/enum",
        "every conditional requirement must have exactly one explicit feature mapping",
      ),
    );
  }
  const schemaConditionalFeatures = new Set(schema.$defs.conditionalFeature.enum);
  const mappedConditionalFeatures = new Set(Object.values(CONDITIONAL_FEATURES));
  if (
    schemaConditionalFeatures.size !== mappedConditionalFeatures.size ||
    [...schemaConditionalFeatures].some((feature) => !mappedConditionalFeatures.has(feature))
  ) {
    issues.push(
      issue(
        "conditional_policy_drift",
        "/$defs/conditionalFeature/enum",
        "schema conditional features must exactly match checker mappings",
      ),
    );
  }
  const checkedEvidenceBundleDigest = evidenceCheckerBundleDigest(
    checkerSource,
    policySource,
    packageLock,
  );
  for (const [field, expectedDigest] of [
    ["verification_spec_digest", sha256(verificationSpec)],
    ["launch_gates_digest", sha256(launchGates)],
    ["requirement_catalog_digest", sha256(canonicalJson(requirementCatalogValue(requirements)))],
    ["evidence_schema_digest", sha256(schemaBytes)],
    ["evidence_checker_digest", checkedEvidenceBundleDigest],
  ]) {
    if (manifest?.policy?.[field] !== expectedDigest) {
      issues.push(
        issue(
          "policy_binding_mismatch",
          `/policy/${field}`,
          `must bind the exact checked-in policy as ${expectedDigest}`,
        ),
      );
    }
  }

  const generatedAt = parseCanonicalTimestamp(manifest?.generated_at, "/generated_at", issues);
  const evidenceAsOf = parseCanonicalTimestamp(manifest?.evidence_as_of, "/evidence_as_of", issues);
  checkChronology(generatedAt, evidenceAsOf, "/generated_at", "/evidence_as_of", issues);
  if (generatedAt !== undefined && generatedAt > evaluationAsOf.getTime() + MAX_CLOCK_SKEW_MS) {
    issues.push(issue("future_manifest", "/generated_at", "is more than five minutes in the future"));
  }

  const artifactList = Array.isArray(manifest?.release?.artifacts)
    ? manifest.release.artifacts
    : [];
  let declaredArtifactBytes = 0n;
  for (const artifact of artifactList) {
    if (Number.isSafeInteger(artifact?.size_bytes) && artifact.size_bytes >= 0) {
      declaredArtifactBytes += BigInt(artifact.size_bytes);
    }
  }
  const artifactBundleWithinBudget = declaredArtifactBytes <= BigInt(MAX_ARTIFACT_BUNDLE_BYTES);
  if (!artifactBundleWithinBudget) {
    issues.push(
      issue(
        "artifact_bundle_too_large",
        "/release/artifacts",
        `declares ${declaredArtifactBytes.toString()} bytes; the verifier limit is ${MAX_ARTIFACT_BUNDLE_BYTES}`,
      ),
    );
  }
  addDuplicateIssues(artifactList.map((artifact) => artifact?.artifact_id), "artifact_id", "/release/artifacts", issues);
  addDuplicateIssues(artifactList.map((artifact) => artifact?.path), "path", "/release/artifacts", issues);
  const retainedArtifacts = new Map(
    artifactList
      .filter((artifact) => typeof artifact?.artifact_id === "string")
      .map((artifact) => [artifact.artifact_id, artifact]),
  );
  const evidenceIdOwner = new Map();
  for (const [artifactIndex, artifact] of artifactList.entries()) {
    for (const [evidenceIndex, evidenceId] of (artifact?.evidence_ids ?? []).entries()) {
      if (evidenceIdOwner.has(evidenceId)) {
        issues.push(
          issue(
            "duplicate_evidence_id",
            `/release/artifacts/${artifactIndex}/evidence_ids/${evidenceIndex}`,
            `duplicates ${JSON.stringify(evidenceId)} from artifact ${JSON.stringify(evidenceIdOwner.get(evidenceId))}`,
          ),
        );
      } else {
        evidenceIdOwner.set(evidenceId, artifact?.artifact_id);
      }
    }
  }
  const primaryArtifact = retainedArtifacts.get(manifest?.release?.primary_artifact_id);
  if (!primaryArtifact || primaryArtifact.kind !== "build") {
    issues.push(
      issue(
        "missing_primary_artifact",
        "/release/primary_artifact_id",
        "must identify one retained build artifact",
      ),
    );
  } else if (
    primaryArtifact.subject_artifact_id !== null ||
    primaryArtifact.subject_artifact_digest !== null
  ) {
    issues.push(
      issue(
        "invalid_primary_subject",
        "/release/primary_artifact_id",
        "the primary build artifact must not claim another artifact as its subject",
      ),
    );
  }
  for (const [field, kind] of [
    ["dependency_lock_artifact_id", "dependency_lock"],
    ["sbom_artifact_id", "sbom"],
    ["build_provenance_artifact_id", "build_provenance"],
  ]) {
    const artifact = retainedArtifacts.get(manifest?.release?.[field]);
    if (!artifact || artifact.kind !== kind) {
      issues.push(issue("missing_release_artifact", `/release/${field}`, `must identify a retained ${kind} artifact`));
    } else if (
      !primaryArtifact ||
      artifact.subject_artifact_id !== primaryArtifact.artifact_id ||
      artifact.subject_artifact_digest !== primaryArtifact.digest
    ) {
      issues.push(
        issue(
          "unbound_release_artifact",
          `/release/${field}`,
          `retained ${kind} must bind the primary build artifact ID and digest`,
        ),
      );
    }
  }

  const verifiedArtifactFiles = new Map();
  if (schemaValid && verifyArtifactFiles && manifestPath && artifactBundleWithinBudget) {
    const manifestDirectory = await realpath(dirname(resolve(manifestPath)));
    const approvalArtifactIds = new Set(
      (manifest?.approvals ?? []).map((approval) => approval?.artifact_id),
    );
    const artifactDeadlineMs = performance.now() + MAX_ARTIFACT_VALIDATION_MS;
    const physicalArtifactOwner = new Map();
    for (const [index, artifact] of artifactList.entries()) {
      enforceArtifactDeadline(artifactDeadlineMs);
      const result = await validateArtifactFile(artifact, index, manifestDirectory, {
        captureApprovalBytes: approvalArtifactIds.has(artifact?.artifact_id),
        deadlineMs: artifactDeadlineMs,
      });
      issues.push(...result.issues);
      const existingPhysicalOwner = physicalArtifactOwner.get(result.fileIdentity);
      if (result.fileIdentity && existingPhysicalOwner) {
        issues.push(
          issue(
            "duplicate_artifact_file",
            `/release/artifacts/${index}/path`,
            `resolves to the same retained file as artifact ${JSON.stringify(existingPhysicalOwner)}`,
          ),
        );
      } else if (result.fileIdentity) {
        physicalArtifactOwner.set(result.fileIdentity, artifact?.artifact_id);
      }
      if (result.artifactId && result.issues.length === 0) {
        verifiedArtifactFiles.set(result.artifactId, result);
      }
    }
  }

  const buildStartedAt = parseCanonicalTimestamp(
    manifest?.release?.build?.started_at,
    "/release/build/started_at",
    issues,
  );
  const buildCompletedAt = parseCanonicalTimestamp(
    manifest?.release?.build?.completed_at,
    "/release/build/completed_at",
    issues,
  );
  checkChronology(
    buildStartedAt,
    buildCompletedAt,
    "/release/build/started_at",
    "/release/build/completed_at",
    issues,
  );
  checkChronology(
    buildCompletedAt,
    generatedAt,
    "/release/build/completed_at",
    "/generated_at",
    issues,
  );
  if (manifest?.release?.build?.environment_id !== manifest?.environment?.environment_id) {
    issues.push(
      issue(
        "environment_binding_mismatch",
        "/release/build/environment_id",
        "must equal environment.environment_id",
      ),
    );
  }

  const traceability = Array.isArray(manifest?.traceability) ? manifest.traceability : [];
  const observedIds = traceability.map((record) => record?.requirement_id);
  addDuplicateIssues(observedIds, "requirement_id", "/traceability", issues);
  const observedIdSet = new Set(observedIds.filter((id) => typeof id === "string"));
  for (const id of configuredIds) {
    if (!observedIdSet.has(id)) {
      issues.push(issue("missing_requirement", "/traceability", `has no record for ${id}`));
    }
  }
  for (const [index, id] of observedIds.entries()) {
    if (typeof id === "string" && !requirementById.has(id)) {
      issues.push(issue("unknown_requirement", `/traceability/${index}/requirement_id`, `${id} is not configured`));
    }
  }

  const capabilities = activeCapabilities(manifest?.promotion);
  for (const [index, record] of traceability.entries()) {
    const path = `/traceability/${index}`;
    const requirement = requirementById.get(record?.requirement_id);
    if (record?.environment_id !== manifest?.environment?.environment_id) {
      issues.push(
        issue(
          "environment_binding_mismatch",
          `${path}/environment_id`,
          "must equal environment.environment_id",
        ),
      );
    }
    checkArtifactBinding(record, path, primaryArtifact, issues);
    checkEvidenceArtifactReferences(
      record?.evidence_artifact_ids,
      record?.automated_test_ids,
      record?.manual_evidence_ids,
      `${path}/evidence_artifact_ids`,
      retainedArtifacts,
      primaryArtifact,
      issues,
    );
    checkIdentity(record?.owner, `${path}/owner`, issues);
    checkIdentity(record?.independent_reviewer, `${path}/independent_reviewer`, issues);
    if (record?.owner?.subject === record?.independent_reviewer?.subject) {
      issues.push(
        issue(
          "non_independent_reviewer",
          `${path}/independent_reviewer/subject`,
          "must differ from the requirement owner",
        ),
      );
    }
    checkEvidenceWindow(record, index, buildCompletedAt, evaluationAsOf.getTime(), issues);
    if (requirement) {
      checkUnreachabilityProof(
        record,
        index,
        requirement,
        primaryArtifact,
        retainedArtifacts,
        capabilities,
        issues,
      );
    }
  }

  addDuplicateIssues(
    (manifest?.approvals ?? []).map((approval) => approval?.role),
    "role",
    "/approvals",
    issues,
  );
  addDuplicateIssues(
    (manifest?.exceptions ?? []).map((exception) => exception?.exception_id),
    "exception_id",
    "/exceptions",
    issues,
  );
  checkApprovalAndExceptionDates(
    manifest ?? {},
    evaluationAsOf.getTime(),
    generatedAt,
    approvalSubjectDigest,
    retainedArtifacts,
    issues,
  );

  const promotionIssues = [];
  if (mode === "promotion") {
    if (asOf !== undefined) {
      promotionIssues.push(
        issue(
          "untrusted_clock_override",
          "/evidence_as_of",
          "promotion uses the evaluator's current clock and rejects caller-supplied clock overrides",
        ),
      );
    }
    if (
      !manifestPath ||
      verifyArtifactFiles !== true ||
      _manifestFileVerification !== VERIFIED_MANIFEST_FILE_TOKEN
    ) {
      promotionIssues.push(
        issue(
          "unverified_artifact_files",
          "/release/artifacts",
          "promotion requires validateEvidenceManifestFile and mandatory retained-file verification",
        ),
      );
    }
    if (manifest?.manifest_kind !== "release_evidence" || manifest?.promotion?.requested !== true) {
      promotionIssues.push(
        issue(
          "non_promotable_manifest",
          "/manifest_kind",
          "only release_evidence with promotion.requested=true can enter promotion preflight",
        ),
      );
    }
    if (!expectedCommit || !COMMIT_PATTERN.test(expectedCommit)) {
      promotionIssues.push(
        issue(
          "missing_external_commit",
          "/release/source_commit",
          "promotion requires --expected-commit with the externally trusted release commit",
        ),
      );
    } else if (manifest?.release?.source_commit !== expectedCommit) {
      promotionIssues.push(
        issue(
          "release_commit_mismatch",
          "/release/source_commit",
          "does not match the externally trusted release commit",
        ),
      );
    }
    if (!expectedArtifactDigest || !SHA256_PATTERN.test(expectedArtifactDigest)) {
      promotionIssues.push(
        issue(
          "missing_external_artifact_digest",
          "/release/primary_artifact_id",
          "promotion requires --expected-artifact-digest from the externally trusted release subject",
        ),
      );
    } else if (primaryArtifact?.digest !== expectedArtifactDigest) {
      promotionIssues.push(
        issue(
          "release_artifact_mismatch",
          "/release/primary_artifact_id",
          "does not match the externally trusted release artifact digest",
        ),
      );
    }
    if (!expectedGate || !GATE_PATTERN.test(expectedGate) || expectedGate === "G0") {
      promotionIssues.push(
        issue(
          "missing_external_gate",
          "/promotion/target_gate",
          "promotion requires --expected-gate G1..G8 or GX",
        ),
      );
    } else if (manifest?.promotion?.target_gate !== expectedGate) {
      promotionIssues.push(
        issue(
          "target_gate_mismatch",
          "/promotion/target_gate",
          "does not match the externally selected target gate",
        ),
      );
    }
    if (!expectedCheckerBundleDigest || !SHA256_PATTERN.test(expectedCheckerBundleDigest)) {
      promotionIssues.push(
        issue(
          "missing_external_checker_bundle_digest",
          "/policy/evidence_checker_digest",
          "promotion requires --expected-checker-bundle-digest from the trusted immutable evaluator source bundle",
        ),
      );
    } else if (expectedCheckerBundleDigest !== checkedEvidenceBundleDigest) {
      promotionIssues.push(
        issue(
          "checker_bundle_digest_mismatch",
          "/policy/evidence_checker_digest",
          "the retained checker, policy helper, or dependency lock does not match the externally trusted digest",
        ),
      );
    }
    if (!expectedApprovalTrustDigest || !SHA256_PATTERN.test(expectedApprovalTrustDigest)) {
      promotionIssues.push(
        issue(
          "missing_external_approval_trust_digest",
          "/approvals",
          "promotion requires --expected-approval-trust-digest from the external release authority",
        ),
      );
    } else if (
      typeof approvalVerifier === "function" &&
      TRUSTED_APPROVAL_VERIFIERS.get(approvalVerifier) !== expectedApprovalTrustDigest
    ) {
      promotionIssues.push(
        issue(
          "approval_trust_digest_mismatch",
          "/approvals",
          "the loaded approval trust policy does not match the externally selected digest",
        ),
      );
    }
    if (manifest?.environment?.kind === "fixture") {
      promotionIssues.push(issue("fixture_environment", "/environment/kind", "fixtures cannot promote"));
    }
    if (
      evidenceAsOf !== undefined &&
      Math.abs(evaluationAsOf.getTime() - evidenceAsOf) > MAX_CLOCK_SKEW_MS
    ) {
      promotionIssues.push(
        issue(
          "stale_manifest_clock",
          "/evidence_as_of",
          "must be within five minutes of the evaluator's trusted clock",
        ),
      );
    }

    if (expectedGate && GATE_PATTERN.test(expectedGate) && expectedGate !== "G0") {
      for (const requirement of requirements.filter((entry) =>
        isRequirementInPromotionScope(entry, expectedGate),
      )) {
        const record = traceability.find((entry) => entry?.requirement_id === requirement.id);
        if (!record) continue;
        const validConditionalNa =
          record.applicability === "not_applicable" &&
          record.result === "not_applicable" &&
          isConditionalRequirement(requirement);
        if (record.applicability === "applicable" && record.result !== "pass") {
          promotionIssues.push(
            issue(
              "requirement_not_passed",
              `/traceability/${traceability.indexOf(record)}/result`,
              `${requirement.id} is required for ${expectedGate} and has result ${JSON.stringify(record.result)}`,
            ),
          );
        } else if (record.applicability === "not_applicable" && !validConditionalNa) {
          promotionIssues.push(
            issue(
              "invalid_promotion_applicability",
              `/traceability/${traceability.indexOf(record)}/applicability`,
              `${requirement.id} cannot satisfy ${expectedGate} as not applicable`,
            ),
          );
        }
      }
    }

    const approvalRoles = new Set((manifest?.approvals ?? []).map((approval) => approval?.role));
    for (const role of REQUIRED_APPROVAL_ROLES) {
      if (!approvalRoles.has(role)) {
        promotionIssues.push(issue("missing_approval", "/approvals", `missing signed ${role} approval artifact`));
      }
    }
    await checkTrustedApprovalSignatures(
      manifest ?? {},
      approvalSubjectDigest,
      retainedArtifacts,
      verifiedArtifactFiles,
      approvalVerifier,
      promotionIssues,
    );
  }

  return Object.freeze({
    schemaValid,
    contractValid: issues.length === 0,
    promotionPreflightPassed:
      mode === "promotion" && issues.length === 0 && promotionIssues.length === 0,
    configuredRequirementCount: configuredIds.length,
    traceabilityCount: traceability.length,
    manifestKind: manifest?.manifest_kind,
    issues: Object.freeze(issues),
    promotionIssues: Object.freeze(promotionIssues),
  });
}

export async function validateEvidenceManifestFile(manifestPath, options = {}) {
  const requestedPath = resolve(manifestPath);
  const realParent = await realpath(dirname(requestedPath));
  const absolutePath = resolve(realParent, basename(requestedPath));
  const pathStats = await lstat(absolutePath, { bigint: true });
  if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
    throw new Error("Evidence manifest must be a regular file, not a symlink or special file");
  }
  const realTargetBefore = await realpath(absolutePath);
  const readResult = await readStableRegularFile(absolutePath, {
    maxBytes: MAX_MANIFEST_BYTES,
    expectedSize: Number(pathStats.size),
    expectedPathStats: pathStats,
    captureBytes: true,
  });
  const pathStatsAfter = await lstat(absolutePath, { bigint: true });
  if (
    !sameFileIdentity(pathStats, pathStatsAfter, { stableContent: true }) ||
    !sameFileIdentity(pathStatsAfter, readResult.stats, { stableContent: true }) ||
    (await realpath(absolutePath)) !== realTargetBefore
  ) {
    throw new Error("Evidence manifest changed while it was being read");
  }
  const manifestText = decodeUtf8Strict(readResult.bytes, "evidence manifest");
  const manifest = parseJsonRejectingDuplicateKeys(manifestText);
  return validateEvidenceManifest({
    ...options,
    manifest,
    manifestPath: absolutePath,
    _manifestFileVerification: VERIFIED_MANIFEST_FILE_TOKEN,
  });
}

function parseApprovalTrustPolicy(trustPolicyText) {
  const policy = parseJsonRejectingDuplicateKeys(trustPolicyText);
  requireExactObjectKeys(policy, ["schema_version", "entries"], "approval trust policy");
  if (policy.schema_version !== APPROVAL_TRUST_SCHEMA) {
    throw new Error(`approval trust policy schema_version must be ${APPROVAL_TRUST_SCHEMA}`);
  }
  if (!Array.isArray(policy.entries) || policy.entries.length === 0 || policy.entries.length > 64) {
    throw new Error("approval trust policy entries must contain between 1 and 64 keys");
  }

  const requiredRoles = new Set(REQUIRED_APPROVAL_ROLES);
  const observedRoles = new Set();
  const trustedKeys = new Map();
  for (const [index, entry] of policy.entries.entries()) {
    const label = `approval trust policy entries[${index}]`;
    requireExactObjectKeys(
      entry,
      ["role", "signer_subject", "key_id", "algorithm", "public_key_spki_base64"],
      label,
    );
    if (!requiredRoles.has(entry.role)) throw new Error(`${label}.role is not authorized`);
    if (
      typeof entry.signer_subject !== "string" ||
      entry.signer_subject.length > 160 ||
      !IDENTITY_SUBJECT_PATTERN.test(entry.signer_subject)
    ) {
      throw new Error(`${label}.signer_subject is invalid`);
    }
    if (typeof entry.key_id !== "string" || !KEY_ID_PATTERN.test(entry.key_id)) {
      throw new Error(`${label}.key_id is invalid`);
    }
    if (entry.algorithm !== APPROVAL_ALGORITHM) {
      throw new Error(`${label}.algorithm must be ${APPROVAL_ALGORITHM}`);
    }
    const publicKeyBytes = decodeCanonicalBase64(
      entry.public_key_spki_base64,
      `${label}.public_key_spki_base64`,
      512,
    );
    let publicKey;
    try {
      publicKey = createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
    } catch {
      throw new Error(`${label}.public_key_spki_base64 is not a DER SPKI public key`);
    }
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new Error(`${label}.public_key_spki_base64 must contain an Ed25519 key`);
    }
    const authorizationKey = `${entry.role}\0${entry.signer_subject}\0${entry.key_id}`;
    if (trustedKeys.has(authorizationKey)) {
      throw new Error(`${label} duplicates a role, signer subject, and key ID authorization`);
    }
    trustedKeys.set(authorizationKey, publicKey);
    observedRoles.add(entry.role);
  }
  for (const role of REQUIRED_APPROVAL_ROLES) {
    if (!observedRoles.has(role)) {
      throw new Error(`approval trust policy has no authorized key for required role ${role}`);
    }
  }
  return trustedKeys;
}

function validateApprovalEnvelope(envelope) {
  requireExactObjectKeys(
    envelope,
    [
      "schema_version",
      "algorithm",
      "key_id",
      "role",
      "signer_subject",
      "subject_digest",
      "signed_at",
      "expires_at",
      "signature_base64",
    ],
    "approval envelope",
  );
  if (envelope.schema_version !== APPROVAL_ENVELOPE_SCHEMA) {
    throw new Error(`approval envelope schema_version must be ${APPROVAL_ENVELOPE_SCHEMA}`);
  }
  if (envelope.algorithm !== APPROVAL_ALGORITHM) {
    throw new Error(`approval envelope algorithm must be ${APPROVAL_ALGORITHM}`);
  }
  if (typeof envelope.key_id !== "string" || !KEY_ID_PATTERN.test(envelope.key_id)) {
    throw new Error("approval envelope key_id is invalid");
  }
  if (!REQUIRED_APPROVAL_ROLES.includes(envelope.role)) {
    throw new Error("approval envelope role is invalid");
  }
  if (
    typeof envelope.signer_subject !== "string" ||
    envelope.signer_subject.length > 160 ||
    !IDENTITY_SUBJECT_PATTERN.test(envelope.signer_subject)
  ) {
    throw new Error("approval envelope signer_subject is invalid");
  }
  if (typeof envelope.subject_digest !== "string" || !SHA256_PATTERN.test(envelope.subject_digest)) {
    throw new Error("approval envelope subject_digest is invalid");
  }
  for (const field of ["signed_at", "expires_at"]) {
    if (
      typeof envelope[field] !== "string" ||
      !TIMESTAMP_PATTERN.test(envelope[field]) ||
      new Date(envelope[field]).toISOString().replace(".000Z", "Z") !== envelope[field]
    ) {
      throw new Error(`approval envelope ${field} is not a canonical UTC timestamp`);
    }
  }
  const signature = decodeCanonicalBase64(
    envelope.signature_base64,
    "approval envelope signature_base64",
    128,
  );
  if (signature.length !== 64) throw new Error("approval envelope signature must be 64 bytes");
  return signature;
}

export async function loadTrustedApprovalVerifier(trustPolicyPath, expectedDigest) {
  if (typeof expectedDigest !== "string" || !SHA256_PATTERN.test(expectedDigest)) {
    throw new Error("A trusted approval policy requires an external sha256 digest");
  }
  const requestedPath = resolve(trustPolicyPath);
  const realParent = await realpath(dirname(requestedPath));
  const absolutePath = resolve(realParent, basename(requestedPath));
  const pathStats = await lstat(absolutePath, { bigint: true });
  if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
    throw new Error("Approval trust policy must be a regular file, not a symlink or special file");
  }
  const result = await readStableRegularFile(absolutePath, {
    maxBytes: MAX_APPROVAL_TRUST_POLICY_BYTES,
    expectedSize: Number(pathStats.size),
    expectedPathStats: pathStats,
    captureBytes: true,
  });
  if (result.digest !== expectedDigest) {
    throw new Error(
      `Approval trust policy digest mismatch: expected ${expectedDigest}, read ${result.digest}`,
    );
  }
  const trustedKeys = parseApprovalTrustPolicy(
    decodeUtf8Strict(result.bytes, "approval trust policy"),
  );
  const verifier = async ({ approval, approvalArtifact, approvalArtifactBytes, subjectDigest }) => {
    if (!(approvalArtifactBytes instanceof Uint8Array)) {
      throw new Error("approval artifact bytes are unavailable");
    }
    const artifactBytes = Buffer.from(approvalArtifactBytes);
    if (sha256(artifactBytes) !== approvalArtifact?.digest) {
      throw new Error("approval artifact digest does not match its safely retained bytes");
    }
    const envelope = parseJsonRejectingDuplicateKeys(
      decodeUtf8Strict(artifactBytes, "approval envelope"),
    );
    const signature = validateApprovalEnvelope(envelope);
    if (
      envelope.role !== approval?.role ||
      envelope.signer_subject !== approval?.approver?.subject ||
      envelope.subject_digest !== subjectDigest ||
      envelope.subject_digest !== approval?.signed_payload_digest ||
      envelope.signed_at !== approval?.signed_at ||
      envelope.expires_at !== approval?.expires_at
    ) {
      throw new Error("approval envelope does not exactly match the manifest approval and subject");
    }
    const authorizationKey = `${envelope.role}\0${envelope.signer_subject}\0${envelope.key_id}`;
    const publicKey = trustedKeys.get(authorizationKey);
    const roleAuthorized = publicKey !== undefined;
    const signatureVerified =
      roleAuthorized &&
      verifySignature(null, approvalEnvelopeSigningBytes(envelope), publicKey, signature);
    return {
      signatureVerified,
      roleAuthorized,
      role: envelope.role,
      signerSubject: envelope.signer_subject,
      subjectDigest: envelope.subject_digest,
      artifactDigest: approvalArtifact.digest,
      signedAt: envelope.signed_at,
      expiresAt: envelope.expires_at,
    };
  };
  Object.freeze(verifier);
  TRUSTED_APPROVAL_VERIFIERS.set(verifier, expectedDigest);
  return verifier;
}

function parseArguments(argv) {
  const options = {
    manifestPath: EVIDENCE_TEMPLATE_PATH,
    mode: "contract",
  };
  const observedArguments = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const [name, inlineValue] = argument.split("=", 2);
    if (
      ![
        "--manifest",
        "--mode",
        "--expected-commit",
        "--expected-artifact-digest",
        "--expected-gate",
        "--expected-checker-bundle-digest",
        "--approval-trust-policy",
        "--expected-approval-trust-digest",
      ].includes(name)
    ) {
      throw new Error(`Unknown argument ${argument}`);
    }
    if (observedArguments.has(name)) throw new Error(`Duplicate argument ${name}`);
    observedArguments.add(name);
    const value = inlineValue ?? argv[++index];
    if (!value) throw new Error(`${name} requires a value`);
    if (name === "--manifest") options.manifestPath = resolve(value);
    if (name === "--mode") options.mode = value;
    if (name === "--expected-commit") options.expectedCommit = value;
    if (name === "--expected-artifact-digest") options.expectedArtifactDigest = value;
    if (name === "--expected-gate") options.expectedGate = value;
    if (name === "--expected-checker-bundle-digest") {
      options.expectedCheckerBundleDigest = value;
    }
    if (name === "--approval-trust-policy") options.approvalTrustPolicyPath = resolve(value);
    if (name === "--expected-approval-trust-digest") {
      options.expectedApprovalTrustDigest = value;
    }
  }
  return options;
}

function printIssues(title, issues) {
  if (issues.length === 0) return;
  process.stderr.write(`${title}:\n`);
  for (const entry of issues) {
    process.stderr.write(`- [${entry.code}] ${entry.path}: ${entry.message}\n`);
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.mode === "promotion") {
    const watchdog = setTimeout(() => {
      process.stderr.write(
        `Promotion preflight exceeded ${MAX_ARTIFACT_VALIDATION_MS} milliseconds and was terminated.\n`,
      );
      process.exit(124);
    }, MAX_ARTIFACT_VALIDATION_MS);
    watchdog.unref();
  }
  if (options.approvalTrustPolicyPath || options.expectedApprovalTrustDigest) {
    if (!options.approvalTrustPolicyPath || !options.expectedApprovalTrustDigest) {
      throw new Error(
        "--approval-trust-policy and --expected-approval-trust-digest must be supplied together",
      );
    }
    options.approvalVerifier = await loadTrustedApprovalVerifier(
      options.approvalTrustPolicyPath,
      options.expectedApprovalTrustDigest,
    );
  }
  const result = await validateEvidenceManifestFile(options.manifestPath, options);
  const displayPath = relative(PROJECT_ROOT, resolve(options.manifestPath)).split(sep).join("/");
  if (!result.contractValid) {
    printIssues("Evidence contract validation failed", result.issues);
    process.exitCode = 1;
    return;
  }

  process.stdout.write(
    `Evidence contract valid: ${displayPath} (${result.traceabilityCount}/${result.configuredRequirementCount} traceability records).\n`,
  );
  if (options.mode === "contract") {
    process.stdout.write(
      result.manifestKind === "template"
        ? "Promotion status: not evaluated. This template is a non-promotable fixture and asserts no pass or signature.\n"
        : "Promotion status: not evaluated in contract mode; use the promotion command with external trust inputs.\n",
    );
    return;
  }
  if (!result.promotionPreflightPassed) {
    printIssues("Promotion preflight rejected", result.promotionIssues);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    "Matrix promotion preflight passed. This is not a go decision: explicit transition criteria, signature trust, audit completeness, and the release board remain external gates.\n",
  );
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath && pathToFileURL(invokedPath).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
