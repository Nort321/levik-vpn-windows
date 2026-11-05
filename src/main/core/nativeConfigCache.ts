import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import type { RustCore } from "./rustCore";

export type ConfigCacheKind = "remote-config" | "service-endpoints";
export interface NativeConfigCache {
  read(kind: ConfigCacheKind): Promise<string | null | undefined>;
  write(kind: ConfigCacheKind, contents: string): Promise<void>;
}
export type OpenConfigCache = (directory: string) => Promise<NativeConfigCache>;
export function isNativeConfigCache(value: unknown): value is NativeConfigCache {
  return typeof value === "object" && value !== null
    && "read" in value && typeof value.read === "function"
    && "write" in value && typeof value.write === "function";
}

/** One writer per public cache, including mode changes. No operation is replayed
 * through Node after a native write has begun. Domain parsers and pinned-key
 * signature verification still run on every read. */
export class ConfigCacheFile {
  private core: RustCore | null = null;
  private open: OpenConfigCache | undefined;
  private report: () => void = () => {};
  private opening: Promise<NativeConfigCache | null> | null = null;
  private operation: Promise<unknown> = Promise.resolve();
  constructor(private readonly path: string, private readonly kind: ConfigCacheKind) {}

  useRustCore(core: RustCore, open: OpenConfigCache | undefined, report: () => void): void {
    this.core = core; this.open = open; this.report = report; this.opening = null;
  }
  private async handle(): Promise<NativeConfigCache | null> {
    if (this.core?.mode !== "rust" || !this.open || basename(this.path) !== `${this.kind}.json`) return null;
    this.opening ??= this.activate();
    const native = await this.opening;
    return this.core?.mode === "rust" ? native : null;
  }
  private async activate(): Promise<NativeConfigCache | null> {
    try {
      const native: unknown = await this.open?.(dirname(this.path));
      if (!isNativeConfigCache(native)) throw new Error("Invalid native cache");
      return native;
    } catch { this.report(); return null; }
  }
  read(): Promise<string | null> {
    return this.enqueue(async () => {
      const native = await this.handle();
      if (!native) return readFile(this.path, "utf8");
      const contents: unknown = await native.read(this.kind);
      if (contents === null || contents === undefined) return null;
      if (typeof contents !== "string" || Buffer.byteLength(contents) > 1024 * 1024) throw new Error("Invalid cached configuration");
      return contents;
    });
  }
  write(contents: string): Promise<void> {
    return this.enqueue(async () => {
      const native = await this.handle();
      if (native) { await native.write(this.kind, contents); return; }
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.tmp`;
      await writeFile(temporary, contents, { mode: 0o600 });
      await rename(temporary, this.path);
    });
  }
  private enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
    const next = this.operation.then(operation); this.operation = next.catch(() => {}); return next;
  }
}
