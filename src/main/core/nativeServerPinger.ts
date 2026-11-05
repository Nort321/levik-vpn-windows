import type { TunnelServer } from "../../shared/contracts";
import { extractServerEndpoint } from "../vpn/serverPinger";
import type { RustCore } from "./rustCore";

export interface NativePingBatch { read(): Promise<string>; close(): void }
export type StartServerPings = (input: string) => NativePingBatch;
export function isNativePingBatch(value: unknown): value is NativePingBatch {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function"
    && "close" in value && typeof value.close === "function";
}

/** Batch inputs contain endpoints only: never protocol credentials or profiles.
 * Shadow uses the old network path once. A started native batch is not repeated
 * through Node, including cancellation, rejection or malformed output. */
export class CoreServerPinger {
  private start: StartServerPings | undefined;
  private readonly active = new Set<NativePingBatch>();
  private generation = 0;
  constructor(private readonly current: () => RustCore, private readonly report: () => void) {}
  useRustCore(start: StartServerPings | undefined): void { this.cancel(); this.start = start; }
  cancel(): void {
    this.generation++;
    for (const batch of this.active) { try { batch.close(); } catch { this.report(); } }
  }
  async measure(servers: readonly TunnelServer[], fallback: () => Promise<Record<string, number | null>>): Promise<Record<string, number | null>> {
    if (this.current().mode !== "rust" || !this.start) return fallback();
    if (servers.length === 0) return {};
    const generation = this.generation;
    const missing = () => Object.fromEntries(servers.map((server) => [server.id, null]));
    if (servers.length > 512 || servers.some((server) => server.id.length === 0 || Buffer.byteLength(server.id) > 128)) {
      this.report(); return missing();
    }
    const input = servers.map((server) => {
      const protocol = [server.outbound.protocol, server.outbound.type].find((value): value is string =>
        typeof value === "string" && value.trim().length > 0)?.trim().toLowerCase() ?? "";
      const endpoint = extractServerEndpoint(server.outbound);
      const safe = endpoint && Buffer.byteLength(endpoint.host) <= 1024 && !/[\u0000-\u001f\u007f-\u009f]/.test(endpoint.host) ? endpoint : null;
      return { id: server.id, endpoint: safe, udp: ["hysteria", "hysteria2", "tuic", "wireguard"].includes(protocol) };
    });
    let batch: NativePingBatch;
    try {
      const opened: unknown = this.start(JSON.stringify(input));
      if (!isNativePingBatch(opened)) throw new Error("Invalid native ping batch");
      batch = opened;
    } catch { this.report(); this.start = undefined; return fallback(); }
    this.active.add(batch);
    try {
      const text: unknown = await batch.read();
      if (generation !== this.generation) return missing();
      if (typeof text !== "string" || text.length > 256 * 1024) throw new Error("Invalid native ping result");
      const result: unknown = JSON.parse(text);
      if (typeof result !== "object" || result === null || !("ok" in result) || result.ok !== true || !("value" in result)
        || !latenciesValid(result.value, new Set(servers.map((server) => server.id)))) throw new Error("Invalid native ping result");
      return result.value;
    } catch { if (generation === this.generation) this.report(); return missing(); }
    finally { this.active.delete(batch); try { batch.close(); } catch { this.report(); } }
  }
}

function latenciesValid(value: unknown, ids: ReadonlySet<string>): value is Record<string, number | null> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === ids.size
    && Object.entries(value).every(([key, latency]) => ids.has(key) && (latency === null
      || (typeof latency === "number" && Number.isInteger(latency) && latency >= 1 && latency <= 60_000)));
}
