import { createHash, randomBytes } from "node:crypto";
import { DeviceIdentity } from "./deviceIdentity";

export interface SignedRequest {
  deviceId: string;
  timestamp: number;
  nonce: string;
  signature: string;
  requestHash: string;
}

export function sha256Hex(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export class RequestSigner {
  constructor(private readonly identity: DeviceIdentity) {}

  sign(method: string, path: string, accessToken: string | null, body: Uint8Array): SignedRequest {
    if (!/^[A-Z]{3,10}$/.test(method)) throw new Error("Invalid HTTP method");
    if (!path.startsWith("/") || path.includes("?") || path.includes("#")) {
      throw new Error("Only encoded URL paths can be signed");
    }
    if (body.byteLength > 1024 * 1024) throw new Error("Signed request body is too large");
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(16).toString("base64url");
    const deviceId = this.identity.deviceId();
    const canonical = [
      "v1",
      method,
      path,
      String(timestamp),
      nonce,
      deviceId,
      sha256Hex(accessToken ?? ""),
      sha256Hex(body),
    ].join("\n");
    return {
      deviceId,
      timestamp,
      nonce,
      signature: this.identity.sign(Buffer.from(canonical)),
      requestHash: createHash("sha256").update(canonical).digest("base64url"),
    };
  }
}

