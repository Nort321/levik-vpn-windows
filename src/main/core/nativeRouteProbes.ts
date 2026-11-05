import type { RustCore } from "./rustCore";
import type { RouteProbeSession } from "../vpn/routeProbe";

export interface NativeRouteProbe {
  latency(target: string, verifyData: boolean): Promise<string>;
  transfer(target: string, direction: "down" | "up"): Promise<string>;
  close(): void;
}
export type OpenRouteProbe = (input: string) => NativeRouteProbe;
export function isNativeRouteProbe(value: unknown): value is NativeRouteProbe {
  return typeof value === "object" && value !== null && "latency" in value && typeof value.latency === "function"
    && "transfer" in value && typeof value.transfer === "function" && "close" in value && typeof value.close === "function";
}
type Latency = Awaited<ReturnType<RouteProbeSession["latency"]>>;
const failure = () => new Error("Измерение маршрута не подтверждено");

/** Rust owns TLS and HTTP. The existing owner keeps its Xray process and all
 * connection generations; a started operation never replays through Node. */
export class CoreRouteProbes {
  private current: (() => RustCore) | undefined;
  private open: OpenRouteProbe | undefined;
  private report: () => void = () => {};
  private generation = 0;
  private readonly active = new Set<() => Promise<void>>();
  useRustCore(current: () => RustCore, open: OpenRouteProbe | undefined, report: () => void): void {
    this.cancel(); this.current = current; this.open = open; this.report = report;
  }
  cancel(): void {
    this.generation++;
    for (const close of this.active) void close().catch(() => this.report());
  }
  wrap(port: number, auth: { user: string; password: string }, signal: AbortSignal, available: () => boolean,
    closeOwner: () => Promise<void>, verifyData: boolean, fallback: () => RouteProbeSession): RouteProbeSession {
    if (this.current?.().mode !== "rust" || !this.open) return fallback();
    signal.throwIfAborted();
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || !/^[a-z0-9-]{1,32}$/.test(auth.user)
      || !/^[a-f0-9]{48}$/.test(auth.password)) throw failure();
    let native: NativeRouteProbe;
    try {
      const opened: unknown = this.open(JSON.stringify({ port, auth: { port, user: auth.user, password: auth.password } }));
      if (!isNativeRouteProbe(opened)) throw failure();
      native = opened;
    } catch { this.report(); this.open = undefined; return fallback(); }
    const generation = this.generation;
    let closed = false; let closing: Promise<void> | undefined;
    const current = (): boolean => !closed && !signal.aborted && generation === this.generation && available();
    const close = (): Promise<void> => {
      if (closing) return closing;
      closed = true; signal.removeEventListener("abort", abort); this.active.delete(close);
      try { native.close(); } catch { this.report(); }
      closing = Promise.resolve().then(closeOwner); return closing;
    };
    const abort = (): void => { void close().catch(() => this.report()); };
    signal.addEventListener("abort", abort, { once: true }); this.active.add(close);
    if (signal.aborted) abort();
    const execute = async (read: () => Promise<string>): Promise<unknown> => {
      try {
        if (!current()) throw failure();
        const text: unknown = await read();
        if (!current()) throw failure();
        if (typeof text !== "string" || text.length > 4096) throw failure();
        const response: unknown = JSON.parse(text);
        if (typeof response !== "object" || response === null || !("ok" in response) || response.ok !== true || !("value" in response)) throw failure();
        return response.value;
      } catch { if (!closed && !signal.aborted && generation === this.generation) this.report(); throw failure(); }
    };
    return {
      latency: async (target) => {
        const value = await execute(() => native.latency(target, verifyData));
        if (!isLatency(value)) { this.report(); throw failure(); }
        return value;
      },
      transfer: async (target, direction) => {
        const value = await execute(() => native.transfer(target, direction));
        if (value === null || typeof value === "number" && Number.isFinite(value) && value > 0 && value <= 10_000) return value;
        this.report(); throw failure();
      }, close,
    };
  }
}
function isLatency(value: unknown): value is Latency {
  if (typeof value !== "object" || value === null || !("values" in value) || !Array.isArray(value.values)
    || value.values.length > 3 || !value.values.every((v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 60_000)
    || !("failed" in value) || typeof value.failed !== "number" || !Number.isInteger(value.failed) || value.failed < 0 || value.failed > 3
    || !("setupMs" in value) || typeof value.setupMs !== "number" || !Number.isFinite(value.setupMs) || value.setupMs < 0 || value.setupMs > 10_000
    || "dataVerified" in value && typeof value.dataVerified !== "boolean") return false;
  if ("dataVerified" in value && value.dataVerified === false) return value.values.length === 0 && value.failed === 0;
  return value.values.length + value.failed === 3;
}
