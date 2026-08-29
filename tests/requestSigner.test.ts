import { describe, expect, it } from "vitest";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";
import { RequestSigner, sha256Hex } from "../src/main/security/requestSigner";

describe("RequestSigner", () => {
  it("produces the headers required by the v1 Mobile API contract", () => {
    const identity = DeviceIdentity.create();
    const signed = new RequestSigner(identity).sign("POST", "/api/mobile/v1/account", "token", Buffer.from("{}"));
    expect(signed.deviceId).toBe(identity.deviceId());
    expect(signed.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(signed.signature.length).toBeGreaterThan(300);
    expect(signed.requestHash.length).toBe(43);
  });

  it("hashes empty values exactly as the Android contract", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

