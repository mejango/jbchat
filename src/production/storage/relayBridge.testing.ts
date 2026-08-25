import { randomBytes } from "node:crypto";
import type { RelayBridgePort } from "./relayInstallationStore";

/**
 * The lanes treat MLS bytes as opaque; a fictional bridge that threads a
 * JSON "state" and hands out random KeyPackages proves the store's row
 * shape and sealing without the subprocess (bridgeClient.labtest.ts
 * proves the real verbs).
 */
export function fictionalRelayBridgeForTesting(): RelayBridgePort & {
  readonly calls: string[];
} {
  const calls: string[] = [];
  return Object.freeze({
    calls,
    async createIdentity(label: string) {
      calls.push(`create:${label}`);
      return {
        state: JSON.stringify({ label, packages: 0 }),
        signaturePublicKey: randomBytes(32).toString("base64url"),
      };
    },
    async generateKeyPackage(state: string) {
      const parsed = JSON.parse(state) as { label: string; packages: number };
      calls.push(`kp:${parsed.label}:${parsed.packages + 1}`);
      return {
        state: JSON.stringify({ ...parsed, packages: parsed.packages + 1 }),
        keyPackage: randomBytes(200).toString("base64url"),
      };
    },
  });
}
