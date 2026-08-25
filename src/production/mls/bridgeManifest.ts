import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The release-pinned MLS bridge (ADR 0004): the binary that ships with the
 * app is named by bin/mls-bridge/manifest.json together with the SHA-256
 * of the Cargo.lock it was built from (its SBOM). Nothing spawns a bridge
 * whose bytes are not in the manifest - an unpinned path is refused, not
 * trusted. The lab may opt out explicitly (JBM_MLS_BRIDGE_ALLOW_UNPINNED=1)
 * to drive a fresh debug build; production never sets it.
 */

export const MLS_BRIDGE_MANIFEST_KIND = "jbm-mls-bridge-release-manifest.v1";
export const MLS_BRIDGE_MANIFEST_RELATIVE_PATH = "bin/mls-bridge/manifest.json";

export interface MlsBridgeArtifact {
  readonly platform: string;
  readonly target: string;
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface MlsBridgeManifest {
  readonly kind: typeof MLS_BRIDGE_MANIFEST_KIND;
  readonly bridgeProtocol: number;
  readonly cargoLockSha256: string;
  readonly artifacts: readonly MlsBridgeArtifact[];
}

export type MlsBridgeVerification =
  | { readonly status: "pinned"; readonly artifact: MlsBridgeArtifact }
  | { readonly status: "unpinned-allowed"; readonly sha256: string }
  | { readonly status: "refused"; readonly reason: string };

const HEX_SHA256 = /^[0-9a-f]{64}$/;

export function parseMlsBridgeManifest(value: unknown): MlsBridgeManifest {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as Record<string, unknown>).kind !== MLS_BRIDGE_MANIFEST_KIND
  ) {
    throw new Error("The MLS bridge manifest has an unexpected shape.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.bridgeProtocol !== 1 ||
    typeof record.cargoLockSha256 !== "string" ||
    !HEX_SHA256.test(record.cargoLockSha256) ||
    !Array.isArray(record.artifacts) ||
    record.artifacts.length === 0
  ) {
    throw new Error("The MLS bridge manifest has an unexpected shape.");
  }
  const artifacts = record.artifacts.map((entry) => {
    const artifact = entry as Record<string, unknown>;
    if (
      typeof artifact.platform !== "string" ||
      typeof artifact.target !== "string" ||
      typeof artifact.path !== "string" ||
      artifact.path.includes("..") ||
      typeof artifact.sha256 !== "string" ||
      !HEX_SHA256.test(artifact.sha256) ||
      typeof artifact.sizeBytes !== "number" ||
      !Number.isInteger(artifact.sizeBytes) ||
      artifact.sizeBytes <= 0
    ) {
      throw new Error("The MLS bridge manifest has an unexpected shape.");
    }
    return Object.freeze({
      platform: artifact.platform,
      target: artifact.target,
      path: artifact.path,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
    });
  });
  return Object.freeze({
    kind: MLS_BRIDGE_MANIFEST_KIND,
    bridgeProtocol: 1,
    cargoLockSha256: record.cargoLockSha256,
    artifacts: Object.freeze(artifacts),
  });
}

export function readMlsBridgeManifest(
  manifestPath: string = defaultManifestPath(),
): MlsBridgeManifest {
  return parseMlsBridgeManifest(
    JSON.parse(readFileSync(manifestPath, "utf8")) as unknown,
  );
}

export function defaultManifestPath(): string {
  return (
    process.env.JBM_MLS_BRIDGE_MANIFEST ??
    join(process.cwd(), MLS_BRIDGE_MANIFEST_RELATIVE_PATH)
  );
}

export function sha256File(path: string): { sha256: string; sizeBytes: number } {
  const bytes = readFileSync(path);
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sizeBytes: bytes.byteLength,
  };
}

/**
 * Verifies the bytes at binaryPath against the manifest. The match is by
 * digest alone - a binary copied to any path is still the pinned release,
 * and a rebuilt one at the documented path is not.
 */
export function verifyMlsBridgeBinary(
  binaryPath: string,
  options: {
    readonly manifestPath?: string;
    readonly allowUnpinned?: boolean;
  } = {},
): MlsBridgeVerification {
  let digest: { sha256: string; sizeBytes: number };
  try {
    digest = sha256File(binaryPath);
  } catch (error) {
    return Object.freeze({
      status: "refused" as const,
      reason: `bridge binary unreadable: ${String(error)}`,
    });
  }
  let manifest: MlsBridgeManifest | null = null;
  let manifestError: string | null = null;
  try {
    manifest = readMlsBridgeManifest(options.manifestPath);
  } catch (error) {
    manifestError = String(error);
  }
  const artifact = manifest?.artifacts.find(
    (entry) =>
      entry.sha256 === digest.sha256 && entry.sizeBytes === digest.sizeBytes,
  );
  if (artifact) {
    return Object.freeze({ status: "pinned" as const, artifact });
  }
  if (options.allowUnpinned) {
    return Object.freeze({
      status: "unpinned-allowed" as const,
      sha256: digest.sha256,
    });
  }
  return Object.freeze({
    status: "refused" as const,
    reason: manifestError
      ? `bridge manifest unavailable: ${manifestError}`
      : `bridge binary sha256 ${digest.sha256} is not a pinned release`,
  });
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}
