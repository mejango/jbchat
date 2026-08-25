#!/usr/bin/env node
// Builds the MLS bridge binary from the locked workspace and drives it end
// to end from Node over the ADR 0004 stdio protocol. Lab evidence only.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cryptoDir = join(root, "crypto");

console.error("Building the MLS bridge binary (locked)...");
const build = spawnSync(
  "cargo",
  ["build", "--locked", "-p", "juicebox-messaging-mls-service-bridge"],
  { cwd: cryptoDir, stdio: ["ignore", "inherit", "inherit"] },
);
assert.equal(build.status, 0, "the bridge binary must build");

const binary = join(cryptoDir, "target", "debug", "jbm-mls-bridge");
assert.ok(existsSync(binary), "the bridge binary must exist after the build");

console.error("Running the bridge lab suite...");
const suite = spawnSync(
  "npx",
  [
    "vitest",
    "run",
    "--config",
    "vitest.bridge.config.ts",
    "src/production/mls/bridgeClient.labtest.ts",
  ],
  {
    cwd: root,
    // A fresh debug build is not the pinned release; the lab says so
    // explicitly instead of the client silently trusting it.
    env: {
      ...process.env,
      JBM_MLS_BRIDGE_BINARY: binary,
      JBM_MLS_BRIDGE_ALLOW_UNPINNED: "1",
    },
    stdio: ["ignore", "inherit", "inherit"],
  },
);
assert.equal(suite.status, 0, "the bridge lab suite must pass");
console.error("Bridge lab passed. This is lab evidence only.");
