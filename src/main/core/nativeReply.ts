/** Opaque ephemeral RSA key: never serialized, persisted, or passed to a renderer. */
export interface NativeReplyKey {
  publicKeySpkiBase64(): string;
  open(sealed: string): string | null;
}

export interface NativeReplyCrypto {
  createKey(): NativeReplyKey;
  seal(publicKey: string, link: string): string;
}

export function isNativeReplyKey(value: unknown): value is NativeReplyKey {
  return typeof value === "object" && value !== null
    && "publicKeySpkiBase64" in value && typeof value.publicKeySpkiBase64 === "function"
    && "open" in value && typeof value.open === "function";
}
