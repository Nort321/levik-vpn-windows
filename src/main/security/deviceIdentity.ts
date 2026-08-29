import {
  constants,
  createHash,
  generateKeyPairSync,
  privateDecrypt,
  sign as cryptoSign,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import { decodeBase64Url, encodeBase64Url } from "../../shared/base64";

export interface SerializedIdentity {
  privateKeyPem: string;
  publicKeyPem: string;
}

export class DeviceIdentity {
  private constructor(
    private readonly privateKey: KeyObject,
    private readonly publicKey: KeyObject,
  ) {}

  static create(): DeviceIdentity {
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 3072,
      publicExponent: 0x10001,
    });
    return new DeviceIdentity(pair.privateKey, pair.publicKey);
  }

  static restore(serialized: SerializedIdentity): DeviceIdentity {
    const { createPrivateKey, createPublicKey } = require("node:crypto") as typeof import("node:crypto");
    return new DeviceIdentity(
      createPrivateKey(serialized.privateKeyPem),
      createPublicKey(serialized.publicKeyPem),
    );
  }

  serialize(): SerializedIdentity {
    return {
      privateKeyPem: this.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKeyPem: this.publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  }

  publicKeySpkiBase64Url(): string {
    return encodeBase64Url(this.spki());
  }

  deviceId(): string {
    return createHash("sha256").update(this.spki()).digest("hex");
  }

  sign(payload: Uint8Array): string {
    return encodeBase64Url(cryptoSign("RSA-SHA256", payload, {
      key: this.privateKey,
      padding: constants.RSA_PKCS1_PADDING,
    }));
  }

  decryptProfileKey(algorithm: string, encryptedKey: string): Buffer {
    if (algorithm !== "RSA-OAEP+A256GCM") {
      throw new Error(`Unsupported profile encryption: ${algorithm}`);
    }
    return privateDecrypt({
      key: this.privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    }, decodeBase64Url(encryptedKey));
  }

  private spki(): Buffer {
    return this.publicKey.export({ type: "spki", format: "der" });
  }
}

