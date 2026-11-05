import type { ServiceRouteAuth } from "../vpn/serviceRoutes";
import type { RustCore } from "./rustCore";

export interface NativeXrayRequest { read(): Promise<string>; close(): void }
export type StartXrayRequest = (input: string) => NativeXrayRequest;
export function isNativeXrayRequest(value: unknown): value is NativeXrayRequest {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "close" in value && typeof value.close === "function";
}
export interface XrayStatistics { uplink: number; downlink: number; initialized: boolean }
type Command = { kind: "statistics" } | { kind: "override"; balancer: string; target: string };
const failure = () => new Error("Локальный API ядра не подтвердил запрос");

/** A session owns these requests. Construction is lazy in Rust, so only a
 * failed activation may use Node. After read starts, a lost acknowledgement
 * must reach the existing reconciliation logic without replaying a write. */
export class CoreXrayApi {
  private current: (() => RustCore) | undefined;
  private start: StartXrayRequest | undefined;
  private report: () => void = () => {};
  private generation = 0;
  private readonly active = new Set<NativeXrayRequest>();
  useRustCore(current: () => RustCore, start: StartXrayRequest | undefined, report: () => void): void {
    this.cancel(); this.current = current; this.start = start; this.report = report;
  }
  cancel(): void {
    this.generation++;
    for (const request of this.active) { try { request.close(); } catch { this.report(); } }
  }
  statistics(auth: ServiceRouteAuth | undefined, fallback: () => Promise<XrayStatistics>, endpoint = "127.0.0.1:47185"): Promise<XrayStatistics> {
    if (this.current?.().mode !== "rust" || !this.start) return fallback();
    return this.statisticsNative(auth, fallback, endpoint);
  }
  private async statisticsNative(auth: ServiceRouteAuth | undefined, fallback: () => Promise<XrayStatistics>, endpoint: string): Promise<XrayStatistics> {
    const value = await this.execute({ kind: "statistics" }, endpoint, auth);
    if (value === undefined) return fallback();
    if (!isStatistics(value)) { this.report(); throw failure(); }
    return value;
  }
  override(balancer: string, target: string, auth: ServiceRouteAuth | undefined, fallback: () => Promise<void>, endpoint = "127.0.0.1:47185"): Promise<void> {
    if (this.current?.().mode !== "rust" || !this.start) return fallback();
    return this.overrideNative(balancer, target, auth, fallback, endpoint);
  }
  private async overrideNative(balancer: string, target: string, auth: ServiceRouteAuth | undefined, fallback: () => Promise<void>, endpoint: string): Promise<void> {
    if (!/^levik-service-(?:main|rule-\d{1,3})$/.test(balancer)
      || !/^(?:levik-service-endpoint-\d{1,2}|levik-block|direct|levik-direct)$/.test(target)) throw failure();
    const value = await this.execute({ kind: "override", balancer, target }, endpoint, auth);
    if (value === undefined) return fallback();
    if (typeof value !== "object" || value === null || !("applied" in value) || value.applied !== true) { this.report(); throw failure(); }
  }
  private async execute(request: Command, endpoint: string, auth: ServiceRouteAuth | undefined): Promise<unknown> {
    if (!/^127\.0\.0\.1:\d{1,5}$/.test(endpoint)) throw failure();
    const port = Number(endpoint.slice("127.0.0.1:".length));
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw failure();
    if (auth && (!Number.isInteger(auth.port) || auth.port < 1024 || auth.port > 65535
      || !/^[a-z0-9-]{1,32}$/.test(auth.user) || !/^[0-9a-f]{48}$/.test(auth.password))) throw failure();
    const generation = this.generation;
    let native: NativeXrayRequest;
    try {
      const opened: unknown = this.start?.(JSON.stringify({ request, port,
        ...(auth ? { auth: { port: auth.port, user: auth.user, password: auth.password } } : {}) }));
      if (!isNativeXrayRequest(opened)) throw failure();
      native = opened;
    } catch { this.report(); this.start = undefined; return undefined; }
    this.active.add(native);
    try {
      const text: unknown = await native.read();
      if (generation !== this.generation) throw failure();
      if (typeof text !== "string" || text.length > 4096) throw failure();
      const response: unknown = JSON.parse(text);
      if (typeof response !== "object" || response === null || !("ok" in response) || response.ok !== true
        || !("value" in response) || response.value === undefined) throw failure();
      return response.value;
    } catch { if (generation === this.generation) this.report(); throw failure(); }
    finally { this.active.delete(native); try { native.close(); } catch { this.report(); } }
  }
}
function isStatistics(value: unknown): value is XrayStatistics {
  return typeof value === "object" && value !== null && "initialized" in value && typeof value.initialized === "boolean"
    && "uplink" in value && typeof value.uplink === "number" && Number.isSafeInteger(value.uplink) && value.uplink >= 0
    && "downlink" in value && typeof value.downlink === "number" && Number.isSafeInteger(value.downlink) && value.downlink >= 0;
}
