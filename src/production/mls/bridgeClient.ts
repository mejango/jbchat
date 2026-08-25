import { Buffer } from "node:buffer";
import {
  verifyMlsBridgeBinary,
  type MlsBridgeVerification,
} from "./bridgeManifest";
import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { createInterface } from "node:readline";

const SUPPORTED_BRIDGE_PROTOCOL = 1;
const REQUEST_TIMEOUT_MILLISECONDS = 10_000;

export interface MlsBridgeDescription {
  readonly bridgeProtocol: number;
  readonly profile: string;
  readonly ciphersuite: string;
  readonly maxKeyPackageWireBytes: number;
  readonly maxCommitWireBytes: number;
  readonly maxWelcomeWireBytes: number;
  readonly maxApplicationWireBytes: number;
  readonly keyPackageLifetimeSeconds: number;
}

export type MlsKeyPackageValidation =
  | {
      readonly valid: true;
      readonly credentialContent: string;
      readonly signatureKey: string;
    }
  | { readonly valid: false; readonly code: string };

export interface MlsBridgeClient {
  readonly describe: () => Promise<MlsBridgeDescription>;
  readonly validateKeyPackage: (
    keyPackageBase64Url: string,
  ) => Promise<MlsKeyPackageValidation>;
  readonly generateSyntheticKeyPackage: (label: string) => Promise<string>;
  /**
   * State-threading client verbs (ADR 0006 phase 0). Every call takes the
   * caller's snapshot and returns the MUTATED snapshot — MLS ratchets
   * advance on open/seal, so the caller must atomically replace its stored
   * state with the returned one, under whatever lock guards that row.
   */
  readonly createIdentity: (
    label: string,
  ) => Promise<{ state: string; signaturePublicKey: string }>;
  readonly generateKeyPackage: (
    state: string,
  ) => Promise<{ state: string; keyPackage: string }>;
  readonly joinWelcome: (
    state: string,
    welcomeBase64Url: string,
  ) => Promise<{ state: string; groupId: string }>;
  readonly sealApplication: (
    state: string,
    groupIdBase64Url: string,
    plaintext: Uint8Array,
  ) => Promise<{ state: string; message: string }>;
  readonly openApplication: (
    state: string,
    groupIdBase64Url: string,
    messageBase64Url: string,
  ) => Promise<{ state: string; plaintext: Uint8Array }>;
  readonly processCommit: (
    state: string,
    groupIdBase64Url: string,
    commitBase64Url: string,
  ) => Promise<{ state: string }>;
  readonly close: () => void;
}

/**
 * JSONL client for the release-pinned MLS bridge subprocess (ADR 0004).
 * Binary fields cross the boundary as hex; this client speaks base64url
 * to the rest of the service. Any protocol surprise - unknown response
 * id, non-JSON line, unsupported bridge protocol, process exit - fails
 * the affected requests; there is no fallback implementation.
 */
export function createMlsBridgeClient(binaryPath: string): MlsBridgeClient {
  const child: ChildProcessByStdio<Writable, Readable, null> = spawn(
    binaryPath,
    [],
    { stdio: ["pipe", "pipe", "ignore"] },
  );
  const pending = new Map<
    string,
    {
      resolve: (value: Record<string, unknown>) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();
  let nextId = 0;
  let closed = false;

  const failAll = (message: string): void => {
    for (const [, entry] of pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error(message));
    }
    pending.clear();
  };
  child.on("error", () => failAll("The MLS bridge process failed to start."));
  child.on("exit", () => {
    closed = true;
    failAll("The MLS bridge process exited.");
  });
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    const record = parsed as Record<string, unknown>;
    const entry = pending.get(String(record.id));
    if (!entry) return;
    pending.delete(String(record.id));
    clearTimeout(entry.timer);
    entry.resolve(record);
  });

  const request = async (
    verb: string,
    fields: Record<string, unknown>,
  ): Promise<Record<string, unknown>> => {
    if (closed) throw new Error("The MLS bridge process exited.");
    nextId += 1;
    const id = `r${nextId}`;
    const payload = `${JSON.stringify({ id, verb, ...fields })}\n`;
    const response = await new Promise<Record<string, unknown>>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error("The MLS bridge request timed out."));
        }, REQUEST_TIMEOUT_MILLISECONDS);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(payload, (error) => {
          if (error) {
            pending.delete(id);
            clearTimeout(timer);
            reject(new Error("The MLS bridge request could not be written."));
          }
        });
      },
    );
    if (response.ok !== true) {
      const error = response.error as Record<string, unknown> | undefined;
      throw new Error(
        `The MLS bridge refused the request (${String(error?.code)}).`,
      );
    }
    return response.result as Record<string, unknown>;
  };

  return Object.freeze({
    async describe(): Promise<MlsBridgeDescription> {
      const result = await request("bridge/describe", {});
      if (Number(result.bridgeProtocol) !== SUPPORTED_BRIDGE_PROTOCOL) {
        throw new Error("The MLS bridge protocol version is unsupported.");
      }
      return {
        bridgeProtocol: Number(result.bridgeProtocol),
        profile: String(result.profile),
        ciphersuite: String(result.ciphersuite),
        maxKeyPackageWireBytes: Number(result.maxKeyPackageWireBytes),
        maxCommitWireBytes: Number(result.maxCommitWireBytes),
        maxWelcomeWireBytes: Number(result.maxWelcomeWireBytes),
        maxApplicationWireBytes: Number(result.maxApplicationWireBytes),
        keyPackageLifetimeSeconds: Number(result.keyPackageLifetimeSeconds),
      };
    },
    async validateKeyPackage(
      keyPackageBase64Url: string,
    ): Promise<MlsKeyPackageValidation> {
      const result = await request("key-package/validate", {
        keyPackage: Buffer.from(keyPackageBase64Url, "base64url").toString(
          "hex",
        ),
      });
      if (result.valid === true) {
        return {
          valid: true,
          credentialContent: Buffer.from(
            String(result.credentialContent),
            "hex",
          ).toString("base64url"),
          signatureKey: Buffer.from(String(result.signatureKey), "hex").toString(
            "base64url",
          ),
        };
      }
      return { valid: false, code: String(result.code) };
    },
    async generateSyntheticKeyPackage(label: string): Promise<string> {
      const result = await request("key-package/generate-synthetic", { label });
      return Buffer.from(String(result.keyPackage), "hex").toString(
        "base64url",
      );
    },
    async createIdentity(label: string) {
      const result = await request("client/create-identity", { label });
      return {
        state: String(result.state),
        signaturePublicKey: Buffer.from(
          String(result.signaturePublicKey),
          "hex",
        ).toString("base64url"),
      };
    },
    async generateKeyPackage(state: string) {
      const result = await request("client/generate-key-package", { state });
      return {
        state: String(result.state),
        keyPackage: Buffer.from(String(result.keyPackage), "hex").toString(
          "base64url",
        ),
      };
    },
    async joinWelcome(state: string, welcomeBase64Url: string) {
      const result = await request("client/join-welcome", {
        state,
        welcome: Buffer.from(welcomeBase64Url, "base64url").toString("hex"),
      });
      return {
        state: String(result.state),
        groupId: Buffer.from(String(result.groupId), "hex").toString(
          "base64url",
        ),
      };
    },
    async sealApplication(
      state: string,
      groupIdBase64Url: string,
      plaintext: Uint8Array,
    ) {
      const result = await request("client/seal-application", {
        state,
        groupId: Buffer.from(groupIdBase64Url, "base64url").toString("hex"),
        plaintext: Buffer.from(plaintext).toString("hex"),
      });
      return {
        state: String(result.state),
        message: Buffer.from(String(result.message), "hex").toString(
          "base64url",
        ),
      };
    },
    async openApplication(
      state: string,
      groupIdBase64Url: string,
      messageBase64Url: string,
    ) {
      const result = await request("client/open-application", {
        state,
        groupId: Buffer.from(groupIdBase64Url, "base64url").toString("hex"),
        message: Buffer.from(messageBase64Url, "base64url").toString("hex"),
      });
      return {
        state: String(result.state),
        plaintext: new Uint8Array(
          Buffer.from(String(result.plaintext), "hex"),
        ),
      };
    },
    async processCommit(
      state: string,
      groupIdBase64Url: string,
      commitBase64Url: string,
    ) {
      const result = await request("client/process-commit", {
        state,
        groupId: Buffer.from(groupIdBase64Url, "base64url").toString("hex"),
        commit: Buffer.from(commitBase64Url, "base64url").toString("hex"),
      });
      return { state: String(result.state) };
    },
    close(): void {
      closed = true;
      lines.close();
      child.stdin.end();
      child.kill();
    },
  });
}

export type MlsBridgeResolution =
  | {
      readonly status: "ready";
      readonly binaryPath: string;
      readonly verification: MlsBridgeVerification;
      readonly open: () => MlsBridgeClient;
    }
  | { readonly status: "absent" }
  | { readonly status: "refused"; readonly reason: string };

/**
 * Fail-closed environment resolution: an unset JBM_MLS_BRIDGE_BINARY means
 * the capability is absent, never a substitute implementation; a set one
 * is spawned only when its bytes are a pinned release in
 * bin/mls-bridge/manifest.json (or the lab has explicitly allowed an
 * unpinned build via JBM_MLS_BRIDGE_ALLOW_UNPINNED=1).
 */
export function resolveMlsBridgeFromEnvironment(): MlsBridgeResolution {
  const binaryPath = process.env.JBM_MLS_BRIDGE_BINARY;
  if (!binaryPath) return Object.freeze({ status: "absent" as const });
  const verification = verifyMlsBridgeBinary(binaryPath, {
    allowUnpinned: process.env.JBM_MLS_BRIDGE_ALLOW_UNPINNED === "1",
  });
  if (verification.status === "refused") {
    return Object.freeze({
      status: "refused" as const,
      reason: verification.reason,
    });
  }
  return Object.freeze({
    status: "ready" as const,
    binaryPath,
    verification,
    open: () => createMlsBridgeClient(binaryPath),
  });
}

export function mlsBridgeFromEnvironment(): MlsBridgeClient | null {
  const resolved = resolveMlsBridgeFromEnvironment();
  return resolved.status === "ready" ? resolved.open() : null;
}
