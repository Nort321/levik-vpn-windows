import { constants, publicEncrypt, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";

describe("DeviceIdentity", () => {
  it("persists the same device id and verifies RS256 signatures", () => {
    const identity = DeviceIdentity.create();
    const restored = DeviceIdentity.restore(identity.serialize());
    const payload = Buffer.from("levik-request");
    const signature = Buffer.from(restored.sign(payload), "base64url");
    expect(restored.deviceId()).toBe(identity.deviceId());
    expect(verify("RSA-SHA256", payload, identity.serialize().publicKeyPem, signature)).toBe(true);
  });

  it("decrypts the legacy RSA-OAEP profile key used by Mobile API", () => {
    const identity = DeviceIdentity.create();
    const key = Buffer.alloc(32, 7);
    const encrypted = publicEncrypt({
      key: identity.serialize().publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    }, key);
    expect(identity.decryptProfileKey("RSA-OAEP+A256GCM", encrypted.toString("base64url"))).toEqual(key);
  });
});

