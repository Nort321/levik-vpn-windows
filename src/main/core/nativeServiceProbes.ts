import type { ServiceRouteAuth } from "../vpn/serviceRoutes";
import type { RustCore } from "./rustCore";

export interface NativeServiceProbe { read(): Promise<string>; close(): void }
export type StartServiceProbe = (input: string) => NativeServiceProbe;
export function isNativeServiceProbe(value: unknown): value is NativeServiceProbe {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "close" in value && typeof value.close === "function";
}

/** The session owns probe cancellation. Only activation failure before read
 * may select Node; a started probe never opens a second network path. */
export class CoreServiceProbes {
  private current: (() => RustCore) | undefined;
  private start: StartServiceProbe | undefined;
  private report: () => void = () => {};
  private generation = 0;
  private readonly active = new Set<NativeServiceProbe>();
  useRustCore(current: () => RustCore, start: StartServiceProbe | undefined, report: () => void): void {
    this.cancel(); this.current = current; this.start = start; this.report = report;
  }
  cancel(): void {
    this.generation++;
    for (const probe of this.active) { try { probe.close(); } catch { this.report(); } }
  }
  transport(port: number, auth: ServiceRouteAuth, fallback: () => Promise<boolean>): Promise<boolean> {
    if (this.current?.().mode !== "rust" || !this.start) return fallback();
    return this.execute("transport", port, auth, [], undefined, fallback);
  }
  dns(port: number, auth: ServiceRouteAuth, resolvers: readonly string[], signal: AbortSignal | undefined,
    fallback: () => Promise<boolean>): Promise<boolean> {
    if (this.current?.().mode !== "rust" || !this.start) return fallback();
    return this.execute("dns", port, auth, resolvers, signal, fallback);
  }
  private async execute(kind: "transport" | "dns", port: number, auth: ServiceRouteAuth, resolvers: readonly string[],
    signal: AbortSignal | undefined, fallback: () => Promise<boolean>): Promise<boolean> {
    if (signal?.aborted) return false;
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || (kind === "transport" && (port < 47200 || port > 47231))
      || !Number.isInteger(auth.port) || auth.port < 1024 || auth.port > 65535
      || !/^[a-z0-9-]{1,32}$/.test(auth.user) || !/^[0-9a-f]{48}$/.test(auth.password)
      || resolvers.length > 16 || resolvers.some((s) => typeof s !== "string" || Buffer.byteLength(s) > 4096)) return false;
    const generation = this.generation;
    let probe: NativeServiceProbe;
    try {
      const opened: unknown = this.start?.(JSON.stringify({ kind, port,
        auth: { port: auth.port, user: auth.user, password: auth.password }, resolvers }));
      if (!isNativeServiceProbe(opened)) throw new Error("Invalid native service probe");
      probe = opened;
    } catch { this.report(); this.start = undefined; return fallback(); }
    this.active.add(probe);
    const close = (): void => { try { probe.close(); } catch { this.report(); } };
    signal?.addEventListener("abort", close, { once: true });
    try {
      if (signal?.aborted || generation !== this.generation) return false;
      const text: unknown = await probe.read();
      if (signal?.aborted || generation !== this.generation) return false;
      if (typeof text !== "string" || text.length > 4096) throw new Error("Invalid native service result");
      const response: unknown = JSON.parse(text);
      if (typeof response !== "object" || response === null || !("ok" in response) || response.ok !== true
        || !("value" in response) || typeof response.value !== "boolean") throw new Error("Invalid native service result");
      return response.value;
    } catch {
      if (!signal?.aborted && generation === this.generation) this.report();
      return false;
    } finally { signal?.removeEventListener("abort", close); this.active.delete(probe); close(); }
  }
}
