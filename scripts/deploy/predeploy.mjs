#!/usr/bin/env node
// One predeploy for both Railway deployments of this repo: the delivery
// service (JBM_STORAGE_DATABASE_URL set) runs the delivery migrations;
// the witness service (JBM_WITNESS_DATABASE_URL set) runs the witness
// migrations. A service with neither variable deploys nothing stateful.
import { spawnSync } from "node:child_process";

function run(script) {
  const result = spawnSync("npm", ["run", script], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (process.env.JBM_STORAGE_DATABASE_URL) run("storage:migrate");
if (process.env.JBM_WITNESS_DATABASE_URL) run("witness:migrate");
