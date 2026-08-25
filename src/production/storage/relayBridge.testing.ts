import { Buffer } from "node:buffer";
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
    // The fictional group: joining a Welcome yields a group id derived from
    // the Welcome bytes; seal/open are the identity over the plaintext so
    // tests can assert on what the relay would forward; commits only bump a
    // counter in the state.
    async joinWelcome(state: string, welcome: string) {
      const parsed = JSON.parse(state) as { label: string; joined?: number };
      calls.push(`join:${parsed.label}`);
      return {
        state: JSON.stringify({ ...parsed, joined: (parsed.joined ?? 0) + 1 }),
        groupId: Buffer.from(`group:${welcome.slice(0, 8)}`, "utf8").toString("base64url"),
      };
    },
    async sealApplication(state: string, groupId: string, plaintext: Uint8Array) {
      void groupId;
      const parsed = JSON.parse(state) as { label: string; sealed?: number };
      calls.push(`seal:${parsed.label}`);
      return {
        state: JSON.stringify({ ...parsed, sealed: (parsed.sealed ?? 0) + 1 }),
        message: Buffer.from(plaintext).toString("base64url"),
      };
    },
    async openApplication(state: string, groupId: string, message: string) {
      void groupId;
      const parsed = JSON.parse(state) as { label: string; opened?: number };
      calls.push(`open:${parsed.label}`);
      return {
        state: JSON.stringify({ ...parsed, opened: (parsed.opened ?? 0) + 1 }),
        plaintext: new Uint8Array(Buffer.from(message, "base64url")),
      };
    },
    async processCommit(state: string, groupId: string, commit: string) {
      void groupId;
      void commit;
      const parsed = JSON.parse(state) as { label: string; commits?: number };
      calls.push(`commit:${parsed.label}`);
      return {
        state: JSON.stringify({ ...parsed, commits: (parsed.commits ?? 0) + 1 }),
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
