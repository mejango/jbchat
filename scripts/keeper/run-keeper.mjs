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

// The policy-witness sync rides the keeper too: a lightweight trigger loop
// against the app's internal route (the app holds the witness credentials).
if (process.env.JBM_INTERNAL_SYNC_URL && process.env.JBM_INTERNAL_SYNC_TOKEN) {
  const loop = async () => {
    for (;;) {
      try {
        await fetch(process.env.JBM_INTERNAL_SYNC_URL, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.JBM_INTERNAL_SYNC_TOKEN}`,
          },
          signal: AbortSignal.timeout(30_000),
        });
      } catch (error) {
        console.error("Policy witness sync trigger failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, 15_000));
    }
  };
  void loop();

  // External-sender credential aging shares the sync route's origin and
  // token; a six-hour cadence is generous against 14-day windows.
  const rotationUrl = new URL(process.env.JBM_INTERNAL_SYNC_URL);
  rotationUrl.pathname = "/v1/internal/external-sender-rotation";
  const rotationLoop = async () => {
    for (;;) {
      try {
        const response = await fetch(rotationUrl, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.JBM_INTERNAL_SYNC_TOKEN}`,
          },
          signal: AbortSignal.timeout(60_000),
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const report = await response.json();
        if (report.promoted || report.retired) {
          console.log(
            `External-sender rotation: ${report.promoted} promoted, ${report.retired} retired.`,
          );
        }
      } catch (error) {
        console.error("External-sender rotation failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, 6 * 60 * 60 * 1_000));
    }
  };
  void rotationLoop();

  // ADR 0006 §4: the relay drain runs in the app (it holds the bridge and
  // the channel credentials); the keeper only ticks it, like the witness
  // sync. Every 15 s: join pending Welcomes, fold Commits, forward new
  // messages to each relayed member's channel.
  const drainUrl = new URL(process.env.JBM_INTERNAL_SYNC_URL);
  drainUrl.pathname = "/v1/internal/relay-drain";
  const drainLoop = async () => {
    for (;;) {
      try {
        const response = await fetch(drainUrl, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.JBM_INTERNAL_SYNC_TOKEN}`,
          },
          signal: AbortSignal.timeout(60_000),
        });
        if (response.status !== 200 && response.status !== 503) {
          throw new Error(`HTTP ${response.status}`);
        }
        if (response.status === 200) {
          const report = await response.json();
          if (report.joined || report.forwarded || report.sendFailures || report.skipped?.length) {
            console.log(
              `Relay drain: ${report.joined} joined, ${report.forwarded} forwarded, ${report.sendFailures} send failures, ${report.skipped?.length ?? 0} skipped.`,
            );
          }
        }
      } catch (error) {
        console.error("Relay drain trigger failed:", String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, 15_000));
    }
  };
  void drainLoop();
}
