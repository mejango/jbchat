#!/usr/bin/env node
// The single keeper process for the delivery deployment: the ADR 0005
// grant recheck (60s) and the delivery-to-witness submission loop (15s)
// run as child processes; if either dies, the keeper exits and the
// platform restarts it.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const children = [
  spawn(
    process.execPath,
    [join(here, "recheck-grants.mjs")],
    { env: { ...process.env, JBM_KEEPER_LOOP_SECONDS: "60" }, stdio: "inherit" },
  ),
  spawn(
    process.execPath,
    [join(here, "submit-witness-extensions.mjs")],
    { env: { ...process.env, JBM_KEEPER_LOOP_SECONDS: "15" }, stdio: "inherit" },
  ),
  ...(process.env.JBM_VAPID_PRIVATE_KEY
    ? [
        spawn(
          process.execPath,
          [join(here, "send-push-wakeups.mjs")],
          {
            env: { ...process.env, JBM_KEEPER_LOOP_SECONDS: "15" },
            stdio: "inherit",
          },
        ),
      ]
    : []),
];
for (const child of children) {
  child.on("exit", (code) => {
    console.error(`Keeper child exited with ${code}; stopping.`);
    for (const other of children) other.kill();
    process.exit(code ?? 1);
  });
}
