import { Buffer } from "node:buffer";
import { afterAll, describe, expect, it } from "vitest";
import { createKeyedIdentityCrypto } from "../identity/identityKeyedCrypto";
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

  it("threads client state through identity + key package + fail-closed joins", async () => {
    // The full welcome/seal/open round trip is proven at the Rust layer
    // (the bridge crate's relay_state_threading test); this exercises the
    // TS translation over the real subprocess.
    const created = await client.createIdentity("relay-lab-000001");
    expect(Buffer.from(created.signaturePublicKey, "base64url").length).toBe(
      32,
    );
    const generated = await client.generateKeyPackage(created.state);
    // Generating a KeyPackage stores private material: state mutates.
    expect(generated.state).not.toBe(created.state);
    const validation = await client.validateKeyPackage(generated.keyPackage);
    expect(validation.valid).toBe(true);
    // The relay provisioner seals this exact snapshot with the identity
    // secret and hands it back verbatim on the next verb.
    const seal = createKeyedIdentityCrypto(Buffer.alloc(32, 0x5f));
    const sealed = seal.sealPayload(generated.state);
    const reopened = seal.openPayload(sealed.ciphertext, sealed.kmsKeyVersion);
    expect(reopened).toBe(generated.state);
    const next = await client.generateKeyPackage(reopened);
    expect(next.keyPackage).not.toBe(generated.keyPackage);

    // A garbage welcome fails closed with a stable code, never a crash.
    await expect(
      client.joinWelcome(
        generated.state,
        Buffer.from("not a welcome").toString("base64url"),
      ),
    ).rejects.toThrow(/bridge refused|mls\./);

    // Stale/corrupt state fails closed too.
    await expect(client.generateKeyPackage("{}")).rejects.toThrow(
      /bridge refused/,
    );
  });
});
