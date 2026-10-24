import { createHash } from "node:crypto";
import type { Hash } from "node:crypto";
import { link, open, rename, stat, statfs, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { basename, join } from "node:path";
import { numberedName, partialName, safeFileName } from "./fileNames";
import { MAX_CHUNK } from "./protocol";
import type { FailReason, ManifestFile } from "./protocol";

/** Files on both ends of a transfer, docs/levik-drop.md "Records" and "Saving". */

export class TransferFailure extends Error {
  constructor(readonly reason: FailReason, message: string = reason) {
    super(message);
  }
}

function code(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error ? String((error as { code: unknown }).code) : "";
}

function storageFailure(error: unknown): TransferFailure {
  const errno = code(error);
  return new TransferFailure(errno === "ENOSPC" || errno === "EDQUOT" ? "storage_full" : "storage_error", errno || "storage");
}

// Sender ---------------------------------------------------------------------------------

export interface SourceFile {
  path: string;
  name: string;
  size: number;
  mtimeMs: number;
}

/** Regular files only, as the user picked them. */
export async function describeSources(paths: readonly string[]): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  for (const path of paths) {
    let info;
    try {
      info = await stat(path);
    } catch {
      throw new Error(`Не удалось открыть «${basename(path)}»`);
    }
    if (!info.isFile()) throw new Error(`«${basename(path)}» — это не файл. Папки пока не передаются.`);
    files.push({ path, name: basename(path), size: info.size, mtimeMs: Math.trunc(info.mtimeMs) });
  }
  return files;
}

async function openSource(file: SourceFile): Promise<FileHandle> {
  let info;
  try {
    info = await stat(file.path);
  } catch {
    throw new TransferFailure("source_unreadable");
  }
  if (!info.isFile() || info.size !== file.size || Math.trunc(info.mtimeMs) !== file.mtimeMs) throw new TransferFailure("source_changed");
  try {
    return await open(file.path, "r");
  } catch {
    throw new TransferFailure("source_unreadable");
  }
}

/**
 * Reads the file from its start: the first `offset` bytes only go into `hash`
 * and must match `prefix`; the rest comes out in chunks (and into `hash`).
 * Sequential reading, as the Android app does for content:// sources.
 */
export async function* readSource(file: SourceFile, offset: number, prefix: string | null, hash: Hash): AsyncGenerator<Buffer> {
  if (offset > file.size || (offset > 0 && offset < file.size && prefix === null)) throw new TransferFailure("protocol");
  const handle = await openSource(file);
  try {
    let position = 0;
    const read = async (length: number): Promise<Buffer> => {
      const buffer = Buffer.allocUnsafe(length);
      let filled = 0;
      while (filled < length) {
        let bytesRead: number;
        try {
          ({ bytesRead } = await handle.read(buffer, filled, length - filled, position + filled));
        } catch {
          throw new TransferFailure("source_unreadable");
        }
        if (bytesRead === 0) throw new TransferFailure("source_changed");
        filled += bytesRead;
      }
      position += length;
      hash.update(buffer);
      return buffer;
    };
    while (position < offset) await read(Math.min(MAX_CHUNK, offset - position));
    if (offset > 0 && offset < file.size && hash.copy().digest("hex") !== prefix) throw new TransferFailure("source_changed");
    while (position < file.size) yield await read(Math.min(MAX_CHUNK, file.size - position));
    // The file grew or changed while it was read.
    const after = await handle.stat();
    if (after.size !== file.size || Math.trunc(after.mtimeMs) !== file.mtimeMs) throw new TransferFailure("source_changed");
  } finally {
    await handle.close().catch(() => {});
  }
}

// Receiver -------------------------------------------------------------------------------

export interface TargetFile {
  /** Safe name the file gets (before " (1)" numbering). */
  name: string;
  size: number;
  partial: string;
  /** Where the finished file lies; null until it is in place. */
  final: string | null;
}

export type MarkDownloaded = (path: string) => Promise<void>;

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    return code(error) !== "ENOENT";
  }
}

/** Safe names and fresh partial paths for a manifest in `folder`. */
export async function planTargets(folder: string, manifest: readonly ManifestFile[]): Promise<TargetFile[]> {
  const targets: TargetFile[] = [];
  for (const file of manifest) {
    const name = safeFileName(file.name);
    let partial = "";
    for (let attempt = 0; attempt < 1000; attempt++) {
      const candidate = join(folder, partialName(numberedName(name, attempt)));
      if (!targets.some((target) => target.partial === candidate) && !(await exists(candidate))) {
        partial = candidate;
        break;
      }
    }
    if (!partial) throw new TransferFailure("storage_error");
    targets.push({ name, size: file.size, partial, final: null });
  }
  return targets;
}

export async function freeBytes(folder: string): Promise<number | null> {
  try {
    const info = await statfs(folder);
    return Number(info.bavail) * Number(info.bsize);
  } catch {
    return null;
  }
}

interface Writing {
  index: number;
  handle: FileHandle;
  written: number;
  hash: Hash;
}

/** The receiving side's files: partial files, offsets for `accept`, finishing. */
export class TargetFiles {
  private writing: Writing | null = null;
  /** Hashes of partial files as of `offsets()`, so writing continues them. */
  private readonly hashes = new Map<number, { length: number; hash: Hash }>();

  constructor(readonly folder: string, readonly targets: TargetFile[], private readonly mark: MarkDownloaded) {}

  /**
   * offsets/prefix for `accept`: what is kept of each file. A partial file that
   * already has every byte is cut by one, so the sender's `end` still checks it.
   */
  async offsets(): Promise<{ offsets: number[]; prefix: Array<string | null> }> {
    await this.closeWriting();
    const offsets: number[] = [];
    const prefix: Array<string | null> = [];
    for (const [index, target] of this.targets.entries()) {
      if (target.final) {
        offsets.push(target.size);
        prefix.push(null);
        continue;
      }
      let length = 0;
      try {
        length = (await stat(target.partial)).size;
      } catch {
        length = 0;
      }
      const keep = Math.min(length, Math.max(0, target.size - 1));
      const hash = createHash("sha256");
      if (keep > 0) {
        try {
          const handle = await open(target.partial, "r+");
          try {
            if (length !== keep) await handle.truncate(keep);
            const buffer = Buffer.allocUnsafe(MAX_CHUNK);
            let position = 0;
            while (position < keep) {
              const { bytesRead } = await handle.read(buffer, 0, Math.min(MAX_CHUNK, keep - position), position);
              if (bytesRead === 0) break;
              hash.update(buffer.subarray(0, bytesRead));
              position += bytesRead;
            }
            if (position !== keep) throw new Error("short read");
          } finally {
            await handle.close();
          }
        } catch {
          await unlink(target.partial).catch(() => {});
          offsets.push(0);
          prefix.push(null);
          this.hashes.set(index, { length: 0, hash: createHash("sha256") });
          continue;
        }
      }
      offsets.push(keep);
      prefix.push(keep > 0 ? hash.copy().digest("hex") : null);
      this.hashes.set(index, { length: keep, hash });
    }
    return { offsets, prefix };
  }

  /** Bytes of the transfer already in place or written. */
  doneBytes(offsets: readonly number[]): number {
    return offsets.reduce((sum, offset) => sum + offset, 0);
  }

  /** Writes the next bytes of `index`; anything but the next offset is a protocol error. */
  async write(index: number, offset: number, bytes: Buffer): Promise<number> {
    const target = this.targets[index];
    if (!target || target.final) throw new TransferFailure("protocol");
    let writing = this.writing;
    if (!writing || writing.index !== index) {
      await this.closeWriting();
      const known = this.hashes.get(index) ?? { length: 0, hash: createHash("sha256") };
      if (known.length !== offset) throw new TransferFailure("protocol");
      let handle: FileHandle;
      try {
        handle = await open(target.partial, offset === 0 ? "w" : "r+", 0o644);
      } catch (error) {
        throw storageFailure(error);
      }
      writing = { index, handle, written: known.length, hash: known.hash };
      this.hashes.delete(index);
      this.writing = writing;
    }
    if (offset !== writing.written || offset + bytes.length > target.size) throw new TransferFailure("protocol");
    try {
      await writing.handle.write(bytes, 0, bytes.length, offset);
    } catch (error) {
      throw storageFailure(error);
    }
    writing.hash.update(bytes);
    writing.written += bytes.length;
    return writing.written;
  }

  /** `end`: the hash of the whole file must match; then it moves to its final name. */
  async finish(index: number, sha256: string): Promise<string> {
    const target = this.targets[index];
    if (!target || target.final) throw new TransferFailure("protocol");
    let writing = this.writing;
    if (!writing || writing.index !== index) {
      // Empty file, or nothing new since the last session.
      await this.closeWriting();
      const known = this.hashes.get(index) ?? { length: 0, hash: createHash("sha256") };
      let handle: FileHandle;
      try {
        handle = await open(target.partial, known.length === 0 ? "w" : "r+", 0o644);
      } catch (error) {
        throw storageFailure(error);
      }
      writing = { index, handle, written: known.length, hash: known.hash };
      this.hashes.delete(index);
    }
    this.writing = null;
    try {
      if (writing.written !== target.size) throw new TransferFailure("protocol");
      if (writing.hash.digest("hex") !== sha256) throw new TransferFailure("integrity");
      try {
        await writing.handle.datasync();
      } catch (error) {
        throw storageFailure(error);
      }
    } catch (error) {
      await writing.handle.close().catch(() => {});
      if (error instanceof TransferFailure && error.reason === "integrity") await unlink(target.partial).catch(() => {});
      throw error;
    }
    await writing.handle.close().catch(() => {});
    const final = await this.place(target);
    target.final = final;
    await this.mark(final).catch(() => {});
    return final;
  }

  /** Never overwrites: a hard link fails on an existing name; rename is the fallback where links are not supported. */
  private async place(target: TargetFile): Promise<string> {
    for (let attempt = 0; attempt < 1000; attempt++) {
      const candidate = join(this.folder, numberedName(target.name, attempt));
      try {
        await link(target.partial, candidate);
        await unlink(target.partial).catch(() => {});
        return candidate;
      } catch (error) {
        if (code(error) === "EEXIST") continue;
        if (await exists(candidate)) continue;
        try {
          await rename(target.partial, candidate);
          return candidate;
        } catch (renameError) {
          throw storageFailure(renameError);
        }
      }
    }
    throw new TransferFailure("storage_error");
  }

  async closeWriting(): Promise<void> {
    const writing = this.writing;
    this.writing = null;
    if (!writing) return;
    this.hashes.set(writing.index, { length: writing.written, hash: writing.hash });
    await writing.handle.close().catch(() => {});
  }

  /** Cancel, failure or expiry: partial files go, finished files stay. */
  async discardPartials(): Promise<void> {
    await this.closeWriting();
    await removePartials(this.targets);
  }
}

export async function removePartials(targets: readonly TargetFile[]): Promise<void> {
  for (const target of targets) if (!target.final) await unlink(target.partial).catch(() => {});
}
