import { ProtocolError, MAX_FRAME, type SessionKeys, type DropRecords } from "../platform/levikDrop/protocol";
import type { RustCore } from "./rustCore";

export interface NativeDropRecords {
  seal(plaintext: Buffer, data: boolean): Buffer;
  open(record: Buffer): Buffer;
  close(): void;
}
export type OpenDropRecords = (send: Buffer, receive: Buffer) => NativeDropRecords;
export function isNativeDropRecords(value: unknown): value is NativeDropRecords {
  return typeof value === "object" && value !== null && "seal" in value && typeof value.seal === "function"
    && "open" in value && typeof value.open === "function" && "close" in value && typeof value.close === "function";
}
const REASONS = new Set(["bad key length", "no keys", "not a record", "record out of order", "record too long", "record does not authenticate"]);
function refusal(error: unknown): ProtocolError {
  return new ProtocolError(error instanceof Error && REASONS.has(error.message) ? error.message : "native record operation failed");
}

/** The only fallback point is construction, before either counter is used.
 * An activated attempt keeps its codec across flag changes. An error closes
 * it permanently; retrying the transfer requires the existing fresh handshake. */
export function dropRecordsWithCore(core: RustCore, open: OpenDropRecords | undefined, keys: SessionKeys,
  role: "sender" | "receiver", report: () => void): DropRecords | null {
  if (core.mode !== "rust" || !open) return null;
  const send = role === "sender" ? keys.sr : keys.rs;
  const receive = role === "sender" ? keys.rs : keys.sr;
  if (!Buffer.isBuffer(send) || send.length !== 32 || !Buffer.isBuffer(receive) || receive.length !== 32) throw new ProtocolError("bad key length");
  const native = core.runNative<NativeDropRecords | null>("levikDrop.records.activate", () => open(send, receive), () => null, isNativeDropRecords);
  if (!native) return null;
  let closed = false;
  const close = (): void => {
    if (closed) return;
    closed = true;
    try { native.close(); } catch { report(); }
  };
  const operate = (run: () => unknown, accepts: (value: Buffer) => boolean): Buffer => {
    if (closed) throw new ProtocolError("no keys");
    try {
      const value = run();
      if (!Buffer.isBuffer(value) || !accepts(value)) throw new ProtocolError("native record operation failed");
      return value;
    } catch (error) { close(); throw refusal(error); }
  };
  return {
    seal: (plaintext, data = false) => operate(() => {
      if (!Buffer.isBuffer(plaintext) || plaintext.length > MAX_FRAME - 25) throw new ProtocolError("record too long");
      return native.seal(plaintext, data);
    }, (value) => value.length === plaintext.length + 25 && value[0] === (data ? 0x11 : 0x10)),
    open: (record) => operate(() => {
      if (!Buffer.isBuffer(record) || record.length < 26 || record.length > MAX_FRAME || (record[0] !== 0x10 && record[0] !== 0x11)) throw new ProtocolError("not a record");
      return native.open(record);
    }, (value) => value.length === record.length - 25),
    close,
  };
}
