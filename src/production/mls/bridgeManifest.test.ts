import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseMlsBridgeManifest,
  readMlsBridgeManifest,
  sha256File,
  verifyMlsBridgeBinary,
} from "./bridgeManifest";

describe("mls bridge release manifest", () => {
  const dir = mkdtempSync(join(tmpdir(), "jbm-bridge-manifest-"));
  const pinned = join(dir, "pinned");
  const stranger = join(dir, "stranger");
  writeFileSync(pinned, "pinned-bridge-bytes");
  writeFileSync(stranger, "rebuilt-bridge-bytes");
  const digest = sha256File(pinned);
  const manifestPath = join(dir, "manifest.json");
  writeFileSync(
    manifestPath,
    JSON.stringify({
      kind: "jbm-mls-bridge-release-manifest.v1",
      bridgeProtocol: 1,
      cargoLockSha256: "a".repeat(64),
      artifacts: [
        {
          platform: "linux-x64",
          target: "x86_64-unknown-linux-musl",
          path: "linux-x64/jbm-mls-bridge",
          sha256: digest.sha256,
          sizeBytes: digest.sizeBytes,
        },
      ],
    }),
  );

  it("admits only bytes the manifest pins", () => {
    expect(verifyMlsBridgeBinary(pinned, { manifestPath })).toMatchObject({
      status: "pinned",
      artifact: { platform: "linux-x64" },
    });
    expect(verifyMlsBridgeBinary(stranger, { manifestPath })).toMatchObject({
      status: "refused",
    });
    expect(
      verifyMlsBridgeBinary(join(dir, "missing"), { manifestPath }),
    ).toMatchObject({ status: "refused" });
  });

  it("lets only an explicit lab opt-out run unpinned bytes", () => {
    expect(
      verifyMlsBridgeBinary(stranger, { manifestPath, allowUnpinned: true }),
    ).toMatchObject({ status: "unpinned-allowed" });
  });

  it("refuses when the manifest itself is unavailable", () => {
    expect(
      verifyMlsBridgeBinary(pinned, { manifestPath: join(dir, "nope.json") }),
    ).toMatchObject({ status: "refused" });
    expect(() =>
      parseMlsBridgeManifest({ kind: "jbm-mls-bridge-release-manifest.v1" }),
    ).toThrow();
  });

  it("ships a committed manifest whose artifacts hash to the committed bytes", () => {
    const manifest = readMlsBridgeManifest();
    expect(manifest.artifacts.length).toBeGreaterThan(0);
    for (const artifact of manifest.artifacts) {
      const actual = sha256File(join("bin", "mls-bridge", artifact.path));
      expect(actual).toEqual({
        sha256: artifact.sha256,
        sizeBytes: artifact.sizeBytes,
      });
    }
  });
});
