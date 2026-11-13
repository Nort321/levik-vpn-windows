import { isIP } from "node:net";
import type { TunnelServer } from "../../shared/contracts";
import { EXTERNAL_AUTO_ID, EXTERNAL_AUTO_NAME, type ExternalPoolProgress } from "../../shared/externalPool";
export { EXTERNAL_AUTO_ID } from "../../shared/externalPool";

export interface ExternalPool { version: 1; sequence: string; updatedAt: string; servers: TunnelServer[] }
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function publicIp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (isIP(value) === 6) {
    const [first, second] = value.split(":").map((part) => Number.parseInt(part || "0", 16));
    return first !== undefined && first >= 0x2000 && first <= 0x3fff && first !== 0x2002
      && !(first === 0x2001 && ((second ?? 0) < 0x200 || second === 0xdb8))
      && !(first === 0x3fff && (second ?? 0) < 0x1000);
  }
  if (isIP(value) !== 4) return false;
  const [a, b, c] = value.split(".").map(Number);
  return a !== undefined && b !== undefined && a > 0 && a < 224
    && ![10, 127].includes(a) && !(a === 100 && b >= 64 && b <= 127)
    && !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31)
    && !(a === 192 && (b === 168 || b === 0 && (c === 0 || c === 2) || b === 88 && c === 99))
    && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100))
    && !(a === 203 && b === 0 && c === 113);
}
function safeFields(value: unknown): boolean {
  if (Array.isArray(value)) return value.every(safeFields);
  if (!record(value)) return typeof value !== "string" || value.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value);
  return Object.entries(value).every(([key, child]) =>
    !["sendThrough", "proxySettings", "dialerProxy", "sockopt", "fragment", "finalmask", "inbounds", "routing"].includes(key)
    && !(key === "allowInsecure" && child !== false) && safeFields(child));
}
export function parseExternalPool(value: unknown): ExternalPool | undefined {
  if (value === undefined) return undefined;
  if (!record(value) || value.version !== 1 || typeof value.sequence !== "string" || !/^\d{1,20}$/.test(value.sequence)
    || typeof value.updatedAt !== "string" || !Number.isFinite(Date.parse(value.updatedAt))
    || !Array.isArray(value.servers) || value.servers.length > 10_000) throw new Error("Некорректный список безлимитных серверов");
  const seen = new Set<string>();
  const servers: TunnelServer[] = value.servers.flatMap((item) => {
    if (!record(item) || typeof item.id !== "string" || !/^external:[a-f0-9]{64}$/.test(item.id)
      || seen.has(item.id) || item.tag !== "external-node-" + item.id.slice(9) || !record(item.outbound)) return [];
    const outbound = item.outbound;
    if (outbound.tag !== item.tag || !["vless", "vmess", "trojan", "shadowsocks"].includes(String(outbound.protocol))
      || Object.keys(outbound).some((key) => !["tag", "protocol", "settings", "streamSettings"].includes(key))
      || !record(outbound.settings) || !safeFields(outbound)) return [];
    const endpoints = outbound.protocol === "vless" || outbound.protocol === "vmess" ? outbound.settings.vnext : outbound.settings.servers;
    if (!Array.isArray(endpoints) || endpoints.length !== 1 || !record(endpoints[0]) || !publicIp(endpoints[0].address)
      || !Number.isInteger(endpoints[0].port) || Number(endpoints[0].port) < 1 || Number(endpoints[0].port) > 65535) return [];
    seen.add(item.id);
    return [{ id: item.id, tag: item.tag, name: "Безлимитный маршрут " + (seen.size), countryCode: "XX", outbound }];
  });
  return { version: 1, sequence: value.sequence, updatedAt: value.updatedAt, servers };
}
export function externalAutoServer(): TunnelServer {
  return { id: EXTERNAL_AUTO_ID, tag: EXTERNAL_AUTO_ID, name: EXTERNAL_AUTO_NAME, countryCode: "XX",
    outbound: { tag: EXTERNAL_AUTO_ID, protocol: "blackhole", settings: {} } };
}

/** Desktop clients never retain or expose external routes, including legacy cached profiles. */
export function removeDesktopExternalPool(profile: { servers: TunnelServer[]; externalPool?: ExternalPool }): boolean {
  const changed = profile.externalPool !== undefined || profile.servers.some((server) => server.id === EXTERNAL_AUTO_ID || server.id.startsWith("external:"));
  delete profile.externalPool;
  profile.servers = profile.servers.filter((server) => server.id !== EXTERNAL_AUTO_ID && !server.id.startsWith("external:"));
  return changed;
}

export function retainExternalPool(incoming: { subscriptionId: string; servers: TunnelServer[]; externalPool?: ExternalPool; gameOnly?: boolean },
  _previous: { subscriptionId: string; externalPool?: ExternalPool } | null): void {
  removeDesktopExternalPool(incoming);
}

/** Every candidate is eligible, but only four cores/real transfers run at a time. */
export async function findExternalServer<T>(options: {
  servers: readonly T[]; signal: AbortSignal; verify: (server: T, signal: AbortSignal) => Promise<boolean>;
  progress: (value: ExternalPoolProgress) => void;
}): Promise<T | null> {
  const controller = new AbortController();
  const stop = (): void => controller.abort();
  options.signal.addEventListener("abort", stop, { once: true });
  if (options.signal.aborted) stop();
  let next = 0, checked = 0;
  let winner: T | null = null;
  options.progress({ checked, total: options.servers.length });
  try {
    await Promise.all(Array.from({ length: Math.min(4, options.servers.length) }, async () => {
      while (!controller.signal.aborted) {
        const server = options.servers[next++]; if (server === undefined) return;
        const candidate = new AbortController();
        const abort = (): void => candidate.abort();
        controller.signal.addEventListener("abort", abort, { once: true });
        if (controller.signal.aborted) abort();
        const timer = setTimeout(abort, 8000);
        try {
          if (await options.verify(server, candidate.signal) && !candidate.signal.aborted && winner === null) { winner = server; stop(); }
        } catch { /* A refused or stalled route is skipped. */ }
        finally {
          clearTimeout(timer); controller.signal.removeEventListener("abort", abort);
          if (!options.signal.aborted) options.progress({ checked: ++checked, total: options.servers.length });
        }
      }
    }));
    options.signal.throwIfAborted();
    return winner;
  } finally { stop(); options.signal.removeEventListener("abort", stop); }
}
