import { ProtocolError, type SessionKeys } from "../platform/levikDrop/protocol";
import type { DropAgreement, Identity } from "../platform/levikDrop/session";
import type { RustCore } from "./rustCore";

export interface NativeDropKeys { sr: Buffer; rs: Buffer; lan: Buffer; code: string }
export interface NativeDropAgreement {
  publicKey(): Buffer;
  signTranscript(role: "sender" | "receiver", th: Buffer): Buffer;
  derive(peer: Buffer, th: Buffer): NativeDropKeys;
  close(): void;
}
export type OpenDropAgreement = (privateDer: Buffer, publicSpki: Buffer) => NativeDropAgreement;
export function isNativeDropAgreement(value: unknown): value is NativeDropAgreement {
  return typeof value === "object" && value !== null && "publicKey" in value && typeof value.publicKey === "function"
    && "signTranscript" in value && typeof value.signTranscript === "function" && "derive" in value && typeof value.derive === "function"
    && "close" in value && typeof value.close === "function";
}
function isAgreement(value: unknown): value is DropAgreement {
  return typeof value === "object" && value !== null && "publicKey" in value && typeof value.publicKey === "function"
    && "signTranscript" in value && typeof value.signTranscript === "function" && "sessionKeys" in value && typeof value.sessionKeys === "function"
    && "close" in value && typeof value.close === "function";
}
const REASONS = new Set(["bad identity key", "bad ephemeral key", "bad transcript", "bad signature", "no keys", "bad role"]);
function refused(error: unknown): ProtocolError {
  return new ProtocolError(error instanceof Error && REASONS.has(error.message) ? error.message : "native handshake operation failed");
}
function wipe(value: unknown): void {
  if (typeof value !== "object" || value === null) return;
  if ("sr" in value && Buffer.isBuffer(value.sr)) value.sr.fill(0);
  if ("rs" in value && Buffer.isBuffer(value.rs)) value.rs.fill(0);
  if ("lan" in value && Buffer.isBuffer(value.lan)) value.lan.fill(0);
}
function isKeys(value: unknown): value is SessionKeys {
  return typeof value === "object" && value !== null && "sr" in value && Buffer.isBuffer(value.sr) && value.sr.length === 32
    && "rs" in value && Buffer.isBuffer(value.rs) && value.rs.length === 32 && "lan" in value && Buffer.isBuffer(value.lan) && value.lan.length === 32
    && "code" in value && typeof value.code === "string" && /^\d{3} \d{3}$/.test(value.code);
}

/** PKCS8 is exported only for primary-mode activation and wiped immediately.
 * Once the public ephemeral point is selected, the attempt never switches
 * implementations. Its owner closes private signing/ECDH state on every exit. */
export function dropAgreementWithCore(core: RustCore, open: OpenDropAgreement | undefined, identity: Identity,
  report: () => void): DropAgreement | null {
  if (core.mode !== "rust" || !open) return null;
  return core.runNative<DropAgreement | null>("levikDrop.agreement.activate", () => {
    let native: NativeDropAgreement | undefined;
    let privateDer: Buffer | undefined;
    try {
      const serialized: unknown = identity.privateKey.export({ type: "pkcs8", format: "der" });
      if (!Buffer.isBuffer(serialized)) throw new ProtocolError("bad identity key");
      privateDer = serialized;
      if (privateDer.length > 4096 || identity.spki.length > 4096) throw new ProtocolError("bad identity key");
      const opened: unknown = open(privateDer, identity.spki);
      if (!isNativeDropAgreement(opened)) throw new ProtocolError("native handshake operation failed");
      native = opened;
      const point: unknown = native.publicKey();
      if (!Buffer.isBuffer(point) || point.length !== 65 || point[0] !== 4) throw new ProtocolError("bad ephemeral key");
      const handle = native;
      let closed = false; let derived = false;
      const close = (): void => { if (closed) return; closed = true; try { handle.close(); } catch { report(); } };
      const operate = <T>(run: () => T): T => {
        if (closed) throw new ProtocolError("no keys");
        try { return run(); } catch (error) { close(); throw refused(error); }
      };
      const agreement: DropAgreement = {
        publicKey: () => operate(() => { if (derived) throw new ProtocolError("no keys"); return Buffer.from(point); }),
        signTranscript: (role, th) => operate(() => {
          if (!Buffer.isBuffer(th) || th.length !== 32) throw new ProtocolError("bad transcript");
          const signature: unknown = handle.signTranscript(role, th);
          if (!Buffer.isBuffer(signature) || signature.length < 8 || signature.length > 80) throw new ProtocolError("bad signature");
          return signature;
        }),
        sessionKeys: (peer, th) => operate(() => {
          if (derived) throw new ProtocolError("no keys"); derived = true;
          if (!Buffer.isBuffer(peer) || ![33,65].includes(peer.length) || !Buffer.isBuffer(th) || th.length !== 32) throw new ProtocolError("bad ephemeral key");
          const keys: unknown = handle.derive(peer, th);
          if (!isKeys(keys)) { wipe(keys); throw new ProtocolError("native handshake operation failed"); }
          return { sr: keys.sr, rs: keys.rs, lan: keys.lan, code: keys.code };
        }), close,
      };
      native = undefined;
      return agreement;
    } catch (error) {
      try { native?.close(); } catch { report(); }
      throw error;
    } finally { privateDer?.fill(0); }
  }, () => null, isAgreement);
}
