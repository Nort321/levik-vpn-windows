import { basename, dirname, isAbsolute, resolve } from "node:path";
import { TransferFailure, type DropTargetIO, type TargetFile } from "../platform/levikDrop/files";
import { MAX_CHUNK } from "../platform/levikDrop/protocol";
import type { RustCore } from "./rustCore";
export interface NativeDropTarget { name: string; size: number; partial: string; finalPath: string | null }
export interface NativeDropTargets {
  offsets(): Promise<unknown>;
  write(index: number, offset: number, bytes: Buffer): Promise<number>;
  finish(index: number, sha256: string): Promise<string>;
  closeWriting(): Promise<void>;
  discardPartials(): Promise<void>;
}
export type OpenDropTargets = (folder: string, targets: NativeDropTarget[]) => NativeDropTargets;
export function isNativeDropTargets(value: unknown): value is NativeDropTargets {
  return typeof value === "object" && value !== null && "offsets" in value && typeof value.offsets === "function"
    && "write" in value && typeof value.write === "function" && "finish" in value && typeof value.finish === "function"
    && "closeWriting" in value && typeof value.closeWriting === "function" && "discardPartials" in value && typeof value.discardPartials === "function";
}
interface Offsets { offsets: number[]; prefix: Array<string | null> }
function isOffsets(value: unknown): value is Offsets {
  return typeof value === "object" && value !== null && "offsets" in value && Array.isArray(value.offsets)
    && value.offsets.every((n: unknown) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0)
    && "prefix" in value && Array.isArray(value.prefix) && value.prefix.every((p: unknown) => p === null || typeof p === "string" && /^[0-9a-f]{64}$/.test(p));
}
function refusal(error: unknown): TransferFailure {
  const message = error instanceof Error ? error.message : "";
  return new TransferFailure(message === "protocol" ? "protocol" : message === "integrity" ? "integrity" : message === "storage_full" ? "storage_full" : "storage_error");
}
/** Activate without I/O, then retain the same owner through pause/resume and
 * flag changes. No Node writer may replay a mutation after adoption. */
export function dropTargetsWithCore(core: RustCore, open: OpenDropTargets | undefined, folder: string,
  targets: TargetFile[], report: () => void): DropTargetIO | null {
  if (core.mode !== "rust" || !open) return null;
  if (!isAbsolute(folder) || targets.some((target) => !Number.isSafeInteger(target.size) || target.size < 0
    || !isAbsolute(target.partial) || dirname(target.partial) !== resolve(folder)
    || (target.final !== null && (!isAbsolute(target.final) || dirname(target.final) !== resolve(folder))))) throw new TransferFailure("protocol");
  // Unix JS paths with lone UTF-16 surrogates use Node's filesystem encoding;
  // keep their exact legacy metadata before a native owner can touch files.
  if (process.platform !== "win32" && [folder, ...targets.flatMap((target) => [target.partial, ...(target.final === null ? [] : [target.final])])]
    .some((path) => Buffer.from(path).toString("utf8") !== path)) return null;
  const native = core.runNative<NativeDropTargets | null>("levikDrop.targets.activate", () => open(folder,
    targets.map((target) => ({ name: target.name, size: target.size, partial: target.partial, finalPath: target.final }))), () => null, isNativeDropTargets);
  if (!native) return null;
  let failed = false; let busy = false;
  const closeWriting = async (): Promise<void> => { try { await native.closeWriting(); } catch { failed = true; report(); } };
  const operate = async <T>(run: () => Promise<unknown>, accept: (value: unknown) => value is T): Promise<T> => {
    if (failed) throw new TransferFailure("storage_error");
    if (busy) { failed = true; throw new TransferFailure("protocol"); }
    busy = true;
    try { const value = await run(); if (failed || !accept(value)) throw new TransferFailure("storage_error"); return value; }
    catch (error) { failed = true; await closeWriting(); throw refusal(error); }
    finally { busy = false; }
  };
  return {
    offsets: () => operate(() => native.offsets(), (value): value is Offsets => {
      if (!isOffsets(value) || value.offsets.length !== targets.length || value.prefix.length !== targets.length) return false;
      return targets.every((target, index) => {
        const offset = value.offsets[index]!, prefix = value.prefix[index];
        return target.final !== null ? offset === target.size && prefix === null
          : offset <= Math.max(0,target.size-1) && (offset === 0 ? prefix === null : typeof prefix === "string");
      });
    }),
    write: (index, offset, bytes) => operate(async () => {
      const target = targets[index];
      if (!Number.isSafeInteger(index) || index < 0 || !target || target.final !== null || !Number.isSafeInteger(offset) || offset < 0
        || !Buffer.isBuffer(bytes) || bytes.length > MAX_CHUNK || offset + bytes.length > target.size) throw new TransferFailure("protocol");
      return native.write(index,offset,bytes);
    }, (value): value is number => typeof value === "number" && value === offset + bytes.length),
    finish: (index, sha256) => operate(async () => {
      if (!Number.isSafeInteger(index) || index < 0 || !targets[index] || targets[index]!.final !== null || !/^[0-9a-f]{64}$/.test(sha256)) throw new TransferFailure("protocol");
      return native.finish(index,sha256);
    }, (value): value is string => typeof value === "string" && isAbsolute(value) && dirname(value) === resolve(folder) && basename(value).length > 0),
    closeWriting,
    discardPartials: async () => { try { await native.discardPartials(); } catch { failed = true; report(); } },
  };
}
