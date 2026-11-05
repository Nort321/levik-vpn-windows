import { isAbsolute } from "node:path";
import { TransferFailure, type SourceFile, type DropSource } from "../platform/levikDrop/files";
import { MAX_CHUNK } from "../platform/levikDrop/protocol";
import type { RustCore } from "./rustCore";
export interface NativeDropSource { read(): Promise<Buffer | null>; digest(): string; close(): void }
export type OpenDropSource = (path: string, size: number, mtime: number, offset: number, prefix: string | null) => NativeDropSource;
export function isNativeDropSource(value: unknown): value is NativeDropSource {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "digest" in value && typeof value.digest === "function" && "close" in value && typeof value.close === "function";
}
const REASONS = new Set(["protocol", "source_changed", "source_unreadable"]);
function refusal(error: unknown): TransferFailure {
  const reason = error instanceof Error && REASONS.has(error.message) ? error.message : "source_unreadable";
  return new TransferFailure(reason === "protocol" ? "protocol" : reason === "source_changed" ? "source_changed" : "source_unreadable");
}
/** Select before any I/O. Once a reader starts, failure ends that file attempt;
 * bytes are never replayed by Node. The owner remains selected across flag changes. */
export function dropSourceWithCore(core: RustCore, open: OpenDropSource | undefined, file: SourceFile,
  offset: number, prefix: string | null, report: () => void): DropSource | null {
  if (core.mode !== "rust" || !open) return null;
  if (!isAbsolute(file.path) || !Number.isSafeInteger(file.size) || file.size < 0 || !Number.isSafeInteger(file.mtimeMs)
    || !Number.isSafeInteger(offset) || offset < 0 || offset > file.size
    || (prefix !== null && !/^[0-9a-f]{64}$/.test(prefix)) || (offset > 0 && offset < file.size && prefix === null)) throw new TransferFailure("protocol");
  const native = core.runNative<NativeDropSource | null>("levikDrop.source.activate",
    () => open(file.path, file.size, file.mtimeMs, offset, prefix), () => null, isNativeDropSource);
  if (!native) return null;
  let closed = false; let reading = false; let ended = false; let position = offset;
  const close = (): void => { if (closed) return; closed = true; try { native.close(); } catch { report(); } };
  return {
    read: async () => {
      if (closed) throw new TransferFailure("source_unreadable");
      if (reading) { close(); throw new TransferFailure("protocol"); }
      if (ended) return null;
      reading = true;
      try {
        const value: unknown = await native.read();
        if (closed) throw new TransferFailure("source_unreadable");
        if (value === null) { if (position !== file.size) throw new TransferFailure("source_changed"); ended = true; return null; }
        if (!Buffer.isBuffer(value) || value.length < 1 || value.length > MAX_CHUNK || position + value.length > file.size) throw new TransferFailure("protocol");
        position += value.length; return value;
      } catch (error) { close(); throw refusal(error); }
      finally { reading = false; }
    },
    digest: () => {
      if (closed) throw new TransferFailure("source_unreadable");
      try {
        if (!ended) throw new TransferFailure("protocol");
        const digest: unknown = native.digest();
        if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) throw new TransferFailure("protocol");
        return digest;
      } catch (error) { close(); throw refusal(error); }
    }, close,
  };
}
