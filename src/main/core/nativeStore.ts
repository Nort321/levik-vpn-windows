import { timingSafeEqual } from "node:crypto";
import type { CoreMode } from "./rustCore";

export interface NativeSecretValue { found: boolean; value?: Buffer | null }
export interface NativeSecureStore {
  get(name: string): Promise<NativeSecretValue>;
  put(name: string, encoded: string): Promise<void>;
  remove(name: string): Promise<void>;
}
export type OpenNativeStore = (directory: string, backend: string) => Promise<NativeSecureStore>;

export function isNativeSecureStore(value: unknown): value is NativeSecureStore {
  return typeof value === "object" && value !== null
    && "get" in value && typeof value.get === "function"
    && "put" in value && typeof value.put === "function"
    && "remove" in value && typeof value.remove === "function";
}

export function secretValue(value: unknown): Buffer | null {
  if (typeof value !== "object" || value === null || !("found" in value)) throw invalid();
  if (value.found === false && (!("value" in value) || value.value === undefined || value.value === null)) return null;
  if (value.found === true && "value" in value && Buffer.isBuffer(value.value) && value.value.length <= 8 * 1024 * 1024) return value.value;
  if ("value" in value && Buffer.isBuffer(value.value)) value.value.fill(0);
  throw invalid();
}

/** Only primary mode opens the OS key store. Before handing any writes to Rust,
 * prove it reads the exact existing identity through the existing platform key.
 * An activation failure leaves the old writer available; a failed native write
 * itself must never be caught and repeated through the old writer. */
export class CoreSecureStore {
  private opening: Promise<NativeSecureStore | null> | null = null;

  constructor(private readonly options: {
    directory: string;
    backend: () => string;
    mode: () => CoreMode;
    open: OpenNativeStore | undefined;
    reference: () => Promise<Buffer | null>;
    report: () => void;
  }) {}

  async handle(): Promise<NativeSecureStore | null> {
    if (this.options.mode() !== "rust" || !this.options.open) return null;
    this.opening ??= this.activate();
    const handle = await this.opening;
    return this.options.mode() === "rust" ? handle : null;
  }

  private async activate(): Promise<NativeSecureStore | null> {
    let reference: Buffer | null = null;
    let restored: Buffer | null = null;
    try {
      reference = await this.options.reference();
      if (!reference?.length || !this.options.open) throw invalid();
      const native: unknown = await this.options.open(this.options.directory, this.options.backend());
      if (!isNativeSecureStore(native)) throw invalid();
      restored = secretValue(await native.get("device_identity"));
      if (!restored || reference.length !== restored.length || !timingSafeEqual(reference, restored)) throw invalid();
      return native;
    } catch {
      this.options.report();
      return null;
    } finally {
      reference?.fill(0);
      restored?.fill(0);
    }
  }
}

function invalid(): Error { return new Error("Не удалось восстановить защищённые данные Levik"); }
