import { Buffer } from "node:buffer";
import { afterAll, describe, expect, it } from "vitest";
import {
  createMlsBridgeClient,
  type MlsBridgeClient,
} from "./bridgeClient";

const BINARY = process.env.JBM_MLS_BRIDGE_BINARY;
const describeBridge = BINARY ? describe : describe.skip;

describeBridge("mls bridge", () => {
  let client: MlsBridgeClient;

  afterAll(() => {
    client?.close();
  });

  it("describes the frozen profile and validates real key packages", async () => {
    client = createMlsBridgeClient(BINARY!);
    const description = await client.describe();
    expect(description.bridgeProtocol).toBe(1);
    expect(description.ciphersuite).toBe(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    );
    expect(description.maxKeyPackageWireBytes).toBe(64 * 1024);

    const keyPackage = await client.generateSyntheticKeyPackage("bridgelab");
    const validation = await client.validateKeyPackage(keyPackage);
    expect(validation.valid).toBe(true);
    if (!validation.valid) throw new Error("validation refused");
    expect(validation.credentialContent.length).toBeGreaterThan(0);
    expect(
      Buffer.from(validation.signatureKey, "base64url").length,
    ).toBe(32);

    const tampered = Buffer.from(keyPackage, "base64url");
    tampered[tampered.length - 1] ^= 0x01;
    const refused = await client.validateKeyPackage(
      tampered.toString("base64url"),
    );
    expect(refused.valid).toBe(false);
    if (refused.valid) throw new Error("tampered package accepted");
    expect(refused.code).toMatch(/^mls\./);

    // Requests interleave correctly on one process.
    const results = await Promise.all([
      client.describe(),
      client.generateSyntheticKeyPackage("interleavea"),
      client.describe(),
      client.generateSyntheticKeyPackage("interleaveb"),
    ]);
    expect((results[0] as { profile: string }).profile).toBe("jb-msg-mls-v1");
    expect(results[1]).not.toBe(results[3]);
  });
});
