import type { LevikCoreModule } from "../core/levikCore";
import type { NativeApiRequest, NativeIdentity } from "../core/nativeIdentity";
import type { RustCore } from "../core/rustCore";
import type { SignedRequest } from "./requestSigner";
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
  private native: NativeIdentity | null = null;
  private core: RustCore | null = null;
  private restoreNative: LevikCoreModule["restoreIdentity"];
  private nativeAttempted = false;

  /** Restore lazily, including when the remote flag changes from ts to rust. */
  useRustCore(core: RustCore, restore: LevikCoreModule["restoreIdentity"]): void {
    this.core = core;
    this.restoreNative = restore;
    this.native = null;
    this.nativeAttempted = false;
  }

  private nativeIdentity(): NativeIdentity | null {
    if (!this.restoreNative || !this.core || this.core.mode === "ts") return null;
    if (this.nativeAttempted) return this.native;
    this.nativeAttempted = true;
    const restore = this.restoreNative;
    this.core.runNative("identity.restore", () => {
      const identity = restore(JSON.stringify(this.serialize()));
      if (identity.deviceId() !== this.deviceId() || identity.publicKeySpkiBase64Url() !== this.publicKeySpkiBase64Url()) {
        throw new Error("identity mismatch");
      }
      this.native = identity;
      return true;
    }, () => true, (value): value is boolean => value === true);
    return this.native;
  }

  /** Pure signing compares on the same nonce and clock, without issuing a second request. */
  signedRequest(method: string, path: string, token: string | null, body: Uint8Array, timestamp: number, nonce: string,
    typescript: () => SignedRequest): SignedRequest {
    const native = this.nativeIdentity();
    if (!native || !this.core) return typescript();
    return this.core.runNative("identity.signRequest", () => {
      const value: unknown = JSON.parse(native.signRequestAt(method, path, token ?? "", Buffer.from(body), timestamp, nonce));
      if (!isSignedRequest(value) || value.deviceId !== this.deviceId() || value.timestamp !== timestamp || value.nonce !== nonce) {
        throw new Error("invalid signature");
      }
      return value;
    }, typescript, isSignedRequest);
  }

  /** Null means no attempt. Once started, a network request must never fall back or replay. */
  requestWithRust(input: NativeApiRequest): Promise<string> | null {
    if (this.core?.mode !== "rust") return null;
    const native = this.nativeIdentity();
    return native ? native.apiRequest(JSON.stringify(input)) : null;
  }

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
    const typescript = () => encodeBase64Url(cryptoSign("RSA-SHA256", payload, {
      key: this.privateKey,
      padding: constants.RSA_PKCS1_PADDING,
    }));
    const native = this.nativeIdentity();
    if (!native || !this.core) return typescript();
    return this.core.runNative("identity.sign", () => native.sign(Buffer.from(payload)), typescript,
      (value): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{300,1400}$/.test(value));
  }

  decryptProfileKey(algorithm: string, encryptedKey: string): Buffer {
    if (algorithm !== "RSA-OAEP+A256GCM") {
      throw new Error(`Unsupported profile encryption: ${algorithm}`);
    }
    const typescript = () => privateDecrypt({
      key: this.privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    }, decodeBase64Url(encryptedKey));
    const native = this.nativeIdentity();
    if (!native || !this.core) return typescript();
    return this.core.runNative("identity.decryptProfileKey", () => native.decryptProfileKey(algorithm, encryptedKey), typescript,
      (value): value is Buffer => Buffer.isBuffer(value) && value.length === 32);
  }

  private spki(): Buffer {
    return this.publicKey.export({ type: "spki", format: "der" });
  }
}

function isSignedRequest(value: unknown): value is SignedRequest {
  if (typeof value !== "object" || value === null) return false;
  return "deviceId" in value && typeof value.deviceId === "string" && /^[0-9a-f]{64}$/.test(value.deviceId)
    && "timestamp" in value && typeof value.timestamp === "number" && Number.isSafeInteger(value.timestamp) && value.timestamp >= 0
    && "nonce" in value && typeof value.nonce === "string" && /^[A-Za-z0-9_-]{22}$/.test(value.nonce)
    && "signature" in value && typeof value.signature === "string" && /^[A-Za-z0-9_-]{300,1400}$/.test(value.signature)
    && "requestHash" in value && typeof value.requestHash === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.requestHash);
}
