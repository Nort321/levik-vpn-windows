import type { RustCore } from "./rustCore";

export interface NativeTunnelProbe { read(): Promise<string>; close(): void }
export type StartTunnelProbe = (input: string) => NativeTunnelProbe;
export function isNativeTunnelProbe(value: unknown): value is NativeTunnelProbe {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "close" in value && typeof value.close === "function";
}
export interface TunnelHealthOptions {
  startup?: boolean;
  shouldContinue?: () => boolean;
  onFailure?: ((codes: string[]) => void) | undefined;
}
interface Outcome { healthy: boolean; durationMs: number | null; codes: string[]; cancelled: boolean }
const cancelled = (): Outcome => ({ healthy: false, durationMs: null, codes: [], cancelled: true });

/** Only the fixed health proxy and fixed public test destinations are used.
 * The shell translates its connection generation into cancellation, while Rust
 * owns CONNECT, system-verified TLS, startup grace and both traffic downloads. */
export class CoreTunnelHealth {
  private start: StartTunnelProbe | undefined;
  private readonly active = new Set<NativeTunnelProbe>();
  private generation = 0;
  constructor(private readonly current: () => RustCore, private readonly platform: "windows" | "macos" | "linux", private readonly report: () => void) {}
  useRustCore(start: StartTunnelProbe | undefined): void { this.cancel(); this.start = start; }
  cancel(): void {
    this.generation++;
    for (const probe of this.active) { try { probe.close(); } catch { this.report(); } }
  }
  check(options: TunnelHealthOptions, fallback: (options: TunnelHealthOptions) => Promise<boolean>): Promise<boolean> {
    if (this.current().mode !== "rust" || !this.start) return fallback(options);
    return this.checkNative(options, fallback);
  }
  private async checkNative(options: TunnelHealthOptions, fallback: (options: TunnelHealthOptions) => Promise<boolean>): Promise<boolean> {
    const value = await this.execute("handshake", options.startup === true, options.shouldContinue ?? (() => true));
    if (value === undefined) return fallback(options);
    if (!value.cancelled && !value.healthy && value.codes.length) options.onFailure?.(value.codes);
    return value.healthy;
  }
  traffic(shouldContinue: () => boolean, fallback: (current: () => boolean) => Promise<number | null>): Promise<number | null> {
    if (this.current().mode !== "rust" || !this.start) return fallback(shouldContinue);
    return this.trafficNative(shouldContinue, fallback);
  }
  private async trafficNative(shouldContinue: () => boolean, fallback: (current: () => boolean) => Promise<number | null>): Promise<number | null> {
    const value = await this.execute("traffic", false, shouldContinue);
    if (value === undefined) return fallback(shouldContinue);
    return value.healthy ? value.durationMs : null;
  }
  private async execute(kind: "handshake" | "traffic", startup: boolean, shouldContinue: () => boolean): Promise<Outcome | undefined> {
    if (this.current().mode !== "rust" || !this.start) return undefined;
    const current = () => { try { return shouldContinue(); } catch { this.report(); return false; } };
    if (!current()) return cancelled();
    const generation = this.generation;
    let probe: NativeTunnelProbe;
    try {
      const native: unknown = this.start(JSON.stringify({ kind, startup, windows: this.platform === "windows" }));
      if (!isNativeTunnelProbe(native)) throw new Error("Invalid native tunnel probe");
      probe = native;
    } catch { this.report(); this.start = undefined; return undefined; }
    this.active.add(probe);
    const timer = setInterval(() => {
      if (generation !== this.generation || !current()) { try { probe.close(); } catch { this.report(); } }
    }, 100);
    timer.unref?.();
    try {
      const text: unknown = await probe.read();
      if (generation !== this.generation || !current()) return cancelled();
      if (typeof text !== "string" || text.length > 4096) throw new Error("Invalid native tunnel result");
      const result: unknown = JSON.parse(text);
      if (typeof result !== "object" || result === null || !("ok" in result) || result.ok !== true || !("value" in result)
        || !outcomeValid(result.value, kind)) throw new Error("Invalid native tunnel result");
      return result.value;
    } catch {
      if (generation !== this.generation || !current()) return cancelled();
      this.report(); return { healthy: false, durationMs: null, codes: ["other"], cancelled: false };
    } finally {
      clearInterval(timer); this.active.delete(probe); try { probe.close(); } catch { this.report(); }
    }
  }
}

function outcomeValid(value: unknown, kind: "handshake" | "traffic"): value is Outcome {
  if (typeof value !== "object" || value === null || !("healthy" in value) || typeof value.healthy !== "boolean"
    || !("cancelled" in value) || typeof value.cancelled !== "boolean" || !("durationMs" in value)
    || !("codes" in value) || !Array.isArray(value.codes) || value.codes.length > 4
    || !value.codes.every((code: unknown) => typeof code === "string" && /^(?:timeout|refused|unreachable|reset|tls|other|no_vpn_network|http_[0-9]{1,3})$/.test(code))) return false;
  if (value.cancelled) return !value.healthy && value.durationMs === null && value.codes.length === 0;
  if (kind === "handshake" || !value.healthy) return value.durationMs === null;
  return typeof value.durationMs === "number" && Number.isInteger(value.durationMs) && value.durationMs >= 1 && value.durationMs <= 60_000;
}
