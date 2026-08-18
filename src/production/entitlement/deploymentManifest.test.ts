import { describe, expect, it } from "vitest";
import {
  ADDRESS_HOOK,
  ADDRESS_TERMINAL,
  hash,
} from "../authority/fixtures.testing";
import {
  fictionalSignedManifest,
} from "./entitlementFixture.testing";
import {
  parseSignedDeploymentManifest,
  resolvePurchaseDeployment,
} from "./deploymentManifest";

describe("deployment manifest", () => {
  it("accepts only the exactly signed document", () => {
    const { envelope, signerPublicKey, manifest } = fictionalSignedManifest();
    expect(manifest.manifestId).toBe("deployments.base.v1");

    const tampered = JSON.parse(JSON.stringify(envelope)) as {
      manifest: { chains: { terminals: { address: string }[] }[] };
    };
    tampered.manifest.chains[0].terminals[0].address = `0x${"99".repeat(20)}`;
    expect(() =>
      parseSignedDeploymentManifest(tampered, signerPublicKey),
    ).toThrow("does not verify");

    const wrongKey = Buffer.alloc(32, 0x11);
    expect(() => parseSignedDeploymentManifest(envelope, wrongKey)).toThrow();

    const extended = {
      ...(envelope as Record<string, unknown>),
      note: "extra",
    };
    expect(() =>
      parseSignedDeploymentManifest(extended, signerPublicKey),
    ).toThrow("unexpected shape");
  });

  it("resolves pinned deployments and nothing else", () => {
    const { manifest } = fictionalSignedManifest();
    const resolved = resolvePurchaseDeployment(manifest, {
      chainId: 8453,
      terminal: ADDRESS_TERMINAL,
      tierHook: null,
    });
    expect(resolved).toEqual({
      deploymentManifestId: "deployments.base.v1",
      projectsContract: manifest.chains[0].projectsContract,
      adapterRevision: "juicebox-v6-receipt.v1",
      abiDigests: {
        pay: hash("0"),
        hookAfterRecordPay: hash("0"),
        tierMint: hash("0"),
      },
      terminal: { address: ADDRESS_TERMINAL, implementationCodeHash: hash("5") },
      tierHook: null,
    });
    expect(
      resolvePurchaseDeployment(manifest, {
        chainId: 8453,
        terminal: ADDRESS_TERMINAL,
        tierHook: ADDRESS_HOOK,
      })?.tierHook,
    ).toEqual({ address: ADDRESS_HOOK, implementationCodeHash: hash("7") });
    expect(
      resolvePurchaseDeployment(manifest, {
        chainId: 1,
        terminal: ADDRESS_TERMINAL,
        tierHook: null,
      }),
    ).toBeNull();
    expect(
      resolvePurchaseDeployment(manifest, {
        chainId: 8453,
        terminal: `0x${"88".repeat(20)}`,
        tierHook: null,
      }),
    ).toBeNull();
    expect(
      resolvePurchaseDeployment(manifest, {
        chainId: 8453,
        terminal: ADDRESS_TERMINAL,
        tierHook: `0x${"88".repeat(20)}`,
      }),
    ).toBeNull();
  });
});
