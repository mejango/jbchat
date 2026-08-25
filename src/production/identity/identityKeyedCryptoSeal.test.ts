import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { createKeyedIdentityCrypto } from "./identityKeyedCrypto";

describe("keyed identity crypto sealing", () => {
  const crypto = createKeyedIdentityCrypto(Buffer.alloc(32, 0x42));

  it("binds a sealed payload to its associated data", () => {
    const sealed = crypto.sealPayloadBound("relay-state", "relay:a");
    expect(crypto.openPayloadBound(sealed.ciphertext, sealed.kmsKeyVersion, "relay:a")).toBe(
      "relay-state",
    );
    // Moved to another row, the blob is garbage - never silently another relay's state.
    expect(() =>
      crypto.openPayloadBound(sealed.ciphertext, sealed.kmsKeyVersion, "relay:b"),
    ).toThrow();
    // Nor does an unbound open accept a bound blob.
    expect(() => crypto.openPayload(sealed.ciphertext, sealed.kmsKeyVersion)).toThrow();
  });

  it("keeps the unbound seal for the legacy payloads", () => {
    const sealed = crypto.sealPayload("wakeup");
    expect(crypto.openPayload(sealed.ciphertext, sealed.kmsKeyVersion)).toBe("wakeup");
    expect(() => crypto.openPayload(sealed.ciphertext, "other-version")).toThrow();
  });
});
