import { basename, dirname, isAbsolute, join, normalize } from "node:path";
import { planTargets, TransferFailure, type TargetFile } from "../platform/levikDrop/files";
import { numberedName, partialName, safeFileName } from "../platform/levikDrop/fileNames";
import type { ManifestFile } from "../platform/levikDrop/protocol";
import { isPromise } from "./nativeDropConnection";
import type { NativeDropTarget } from "./nativeDropTargets";
import type { RustCore } from "./rustCore";
export interface NativeDropFilePlan { read(): Promise<NativeDropTarget[]>; commit(): void; discard(): Promise<void>; close(): void }
export type StartDropFilePlan = (folder: string, files: ManifestFile[]) => NativeDropFilePlan;
export function isNativeDropFilePlan(value: unknown): value is NativeDropFilePlan {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "commit" in value && typeof value.commit === "function" && "discard" in value && typeof value.discard === "function"
    && "close" in value && typeof value.close === "function";
}
function reservedName(path: string, name: string): boolean {
  if (path === partialName(name)) return true;
  // Use the existing UTF-16 extension rule instead of duplicating it in a
  // second validator. Real directory collision counts fit safe integers.
  for (const match of path.matchAll(/ \(([1-9][0-9]{0,15})\)/g)) {
    const attempt = Number(match[1]);
    if (Number.isSafeInteger(attempt) && path === partialName(numberedName(name, attempt))) return true;
  }
  return false;
}
function checked(value: unknown, folder: string, files: readonly ManifestFile[]): TargetFile[] {
  if (!Array.isArray(value) || value.length !== files.length) throw new TransferFailure("protocol");
  const paths = new Set<string>();
  return value.map((target: unknown, index) => {
    const expected = files[index];
    if (!expected || typeof target !== "object" || target === null || !("name" in target) || target.name !== safeFileName(expected.name)
      || !("size" in target) || target.size !== expected.size || !("partial" in target) || typeof target.partial !== "string"
      || !isAbsolute(target.partial) || dirname(target.partial) !== folder || paths.has(target.partial)
      || !reservedName(basename(target.partial), target.name) || !("finalPath" in target) || target.finalPath !== null) throw new TransferFailure("protocol");
    paths.add(target.partial);
    return { name: target.name, size: expected.size, partial: target.partial, final: null };
  });
}
const REASONS = new Set(["protocol", "storage_full", "storage_error"]);
function refusal(error: unknown): TransferFailure {
  const reason = error instanceof Error && REASONS.has(error.message) ? error.message : "storage_error";
  return new TransferFailure(reason === "protocol" ? "protocol" : reason === "storage_full" ? "storage_full" : "storage_error");
}
/** Activate before any reservation. A worker error never reserves the batch
 * again through Node. Completed reservations belong to the engine generation;
 * its existing late-result cleanup and persisted TargetFiles stay unchanged. */
export async function planTargetsWithCore(core: RustCore, start: StartDropFilePlan | undefined, folder: string,
  manifest: readonly ManifestFile[], report: () => void, typescript = planTargets): Promise<TargetFile[]> {
  if (core.mode !== "rust" || !start) return typescript(folder, manifest);
  if (!isAbsolute(folder) || manifest.length > 2147483647) throw new TransferFailure("protocol");
  let total = 0;
  for (const file of manifest) {
    if (typeof file.name !== "string" || file.name.length < 1 || file.name.length > 1024 || !Number.isSafeInteger(file.size) || file.size < 0) throw new TransferFailure("protocol");
    total += file.size;
    if (!Number.isSafeInteger(total)) throw new TransferFailure("protocol");
  }
  // Node normalizes a selected folder's lexical spelling during join. Keep its
  // legacy path for uncommon spellings before a native operation is adopted.
  if (normalize(folder) !== folder || join(folder, ".") !== folder
    || process.platform !== "win32" && Buffer.from(folder).toString("utf8") !== folder) return typescript(folder, manifest);
  const expected = manifest.map((file) => ({ name: file.name, size: file.size }));
  const native = core.runNative<NativeDropFilePlan | null>("levikDrop.planning.activate",
    () => start(folder, expected.map((file) => ({ ...file }))), () => null, isNativeDropFilePlan);
  if (!native) return typescript(folder, manifest);
  let committed = false;
  try {
    const pending: unknown = native.read();
    if (!isPromise(pending)) throw new TransferFailure("protocol");
    const targets = checked(await pending, folder, expected);
    native.commit(); committed = true;
    return targets;
  } catch (error) { throw refusal(error); }
  finally {
    try { native.close(); } catch { try { report(); } catch {} }
    if (!committed) {
      try {
        const cleanup: unknown = native.discard();
        if (!isPromise(cleanup)) throw new TransferFailure("storage_error");
        await cleanup;
      } catch { try { report(); } catch {} }
    }
  }
}
