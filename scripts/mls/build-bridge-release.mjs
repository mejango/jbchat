#!/usr/bin/env node
// Builds the release-pinned MLS bridge for Railway (linux-x64, static musl)
// inside the pinned Rust toolchain image and writes the artifact plus its
// manifest under bin/mls-bridge/ (ADR 0004: the binary ships vendored,
// its hash and the Cargo.lock digest are the release pins). Docker
// Desktop cannot mount ~/Documents, so the workspace is copied to a
// shareable temp dir first. Re-run whenever crypto/ changes;
// `npm run mls:bridge:check` fails until you do.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cryptoDir = join(root, "crypto");
const outDir = join(root, "bin", "mls-bridge");
const toolchain = readFileSync(join(cryptoDir, "rust-toolchain.toml"), "utf8")
  .match(/channel\s*=\s*"([^"]+)"/)[1];
const image = `rust:${toolchain}-alpine`;
const target = "x86_64-unknown-linux-musl";
const platform = "linux-x64";

const work = mkdtempSync(join(tmpdir(), "jbm-bridge-build-"));
const sync = spawnSync(
  "rsync",
  ["-a", "--exclude", "target", "--exclude", "crates/wasm-client/pkg", `${cryptoDir}/`, `${work}/`],
  { stdio: "inherit" },
);
if (sync.status !== 0) process.exit(sync.status ?? 1);

console.error(`Building jbm-mls-bridge in ${image} for ${target}...`);
const build = spawnSync(
  "docker",
  [
    "run", "--rm", "--platform", "linux/amd64",
    "-v", `${work}:/work`,
    "-v", "jbm-cargo-registry:/usr/local/cargo/registry",
    "-w", "/work", image, "sh", "-c",
    `apk add --no-cache musl-dev >/dev/null && cargo build --release --locked -p juicebox-messaging-mls-service-bridge --target ${target}`,
  ],
  { stdio: "inherit" },
);
if (build.status !== 0) process.exit(build.status ?? 1);

const built = join(work, "target", target, "release", "jbm-mls-bridge");
mkdirSync(join(outDir, platform), { recursive: true });
const artifactPath = join(outDir, platform, "jbm-mls-bridge");
copyFileSync(built, artifactPath);
chmodSync(artifactPath, 0o755);
const sha256 = (path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");
const manifest = {
  kind: "jbm-mls-bridge-release-manifest.v1",
  bridgeProtocol: 1,
  toolchain,
  image,
  cargoLockSha256: sha256(join(cryptoDir, "Cargo.lock")),
  artifacts: [
    {
      platform,
      target,
      path: `${platform}/jbm-mls-bridge`,
      sha256: sha256(artifactPath),
      sizeBytes: statSync(artifactPath).size,
    },
  ],
};
writeFileSync(join(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.error(`Wrote ${artifactPath} (${manifest.artifacts[0].sha256})`);
