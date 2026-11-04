/** A typed main-process handle; private keys never enter RustCore.call() or diagnostics. */
export interface NativeIdentity {
  deviceId(): string;
  publicKeySpkiBase64Url(): string;
  sign(payload: Buffer): string;
  signRequestAt(method: string, path: string, accessToken: string, body: Buffer, timestamp: number, nonce: string): string;
  decryptProfileKey(algorithm: string, encryptedKey: string): Buffer;
  decryptProfile(envelope: string): Buffer;
  apiRequest(input: string): Promise<string>;
}

export interface NativeApiRequest {
  origin: string;
  method: string;
  path: string;
  accessToken: string | null;
  body: string;
  platform: "windows" | "macos" | "linux";
  version: string;
  road: boolean;
  game: boolean;
}

export function isNativeIdentity(value: unknown): value is NativeIdentity {
  if (typeof value !== "object" || value === null) return false;
  return "deviceId" in value && typeof value.deviceId === "function"
    && "publicKeySpkiBase64Url" in value && typeof value.publicKeySpkiBase64Url === "function"
    && "sign" in value && typeof value.sign === "function"
    && "signRequestAt" in value && typeof value.signRequestAt === "function"
    && "decryptProfileKey" in value && typeof value.decryptProfileKey === "function"
    && "decryptProfile" in value && typeof value.decryptProfile === "function"
    && "apiRequest" in value && typeof value.apiRequest === "function";
}
