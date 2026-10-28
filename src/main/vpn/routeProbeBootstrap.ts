import { request } from "node:https";
import { isIP, isIPv4 } from "node:net";
import type { ClientRequest, IncomingMessage } from "node:http";

const RESOLVERS = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"] as const;
const CONNECT_MS = 3_000;
const REQUEST_MS = 5_000;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_HOSTS = 32;
const HOST = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;
const LOCAL_PROTOCOLS = new Set(["freedom", "blackhole", "dns"]);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Match native/Helper.swift endpointHosts: only address fields below settings. */
function endpointHosts(value: unknown, hosts: Set<string>, depth = 0): void {
  if (depth > 16) throw new Error("Probe endpoint nesting exceeds its limit");
  if (Array.isArray(value)) {
    for (const child of value) endpointHosts(child, hosts, depth + 1);
  } else if (record(value)) {
    if (typeof value.address === "string" && !isIP(value.address)) {
      if (!HOST.test(value.address)) throw new Error("Invalid probe endpoint hostname");
      hosts.add(value.address);
      if (hosts.size > MAX_HOSTS) throw new Error("Too many probe endpoint hostnames");
    }
    for (const child of Object.values(value)) {
      if (child !== null && typeof child === "object") endpointHosts(child, hosts, depth + 1);
    }
  }
}

function dnsAnswer(body: Buffer): string[] | null {
  let value: unknown;
  try { value = JSON.parse(body.toString("utf8")); } catch { return null; }
  if (!record(value) || value.Status !== 0 || !Array.isArray(value.Answer) || value.Answer.length > 128) return null;
  const addresses = value.Answer.flatMap((answer: unknown) =>
    record(answer) && answer.type === 1 && typeof answer.data === "string" && isIPv4(answer.data) ? [answer.data] : []);
  return addresses.length ? [...new Set(addresses)] : null;
}

/** IP-literal HTTPS with no proxy agent, redirects, OS DNS or unbounded body. */
function queryResolver(resolver: string, host: string, signal: AbortSignal): Promise<string[] | null> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    let settled = false;
    let outgoing: ClientRequest | undefined;
    let response: IncomingMessage | undefined;
    const chunks: Buffer[] = [];
    let size = 0;
    const url = new URL(resolver);
    url.searchParams.set("name", host);
    url.searchParams.set("type", "A");
    const finish = (addresses: string[] | null, cancelled = false): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer); clearTimeout(requestTimer);
      signal.removeEventListener("abort", abort);
      response?.destroy(); outgoing?.destroy();
      if (cancelled) reject(new Error("Probe bootstrap cancelled")); else resolve(addresses);
    };
    const abort = (): void => finish(null, true);
    const connectTimer = setTimeout(() => finish(null), CONNECT_MS);
    const requestTimer = setTimeout(() => finish(null), REQUEST_MS);
    try { outgoing = request(url, { method: "GET", agent: false, headers: { Accept: "application/dns-json" } }, (reply) => {
      response = reply;
      if (settled) { reply.destroy(); return; }
      const declared = reply.headers["content-length"];
      if ((reply.statusCode ?? 0) < 200 || (reply.statusCode ?? 0) >= 300
        || typeof declared === "string" && Number(declared) > MAX_BODY_BYTES) { finish(null); return; }
      reply.on("data", (chunk: Buffer) => {
        if (settled) return;
        size += chunk.length;
        if (size > MAX_BODY_BYTES) { finish(null); return; }
        chunks.push(chunk);
      });
      reply.once("error", () => finish(null));
      reply.once("aborted", () => finish(null));
      reply.once("end", () => { if (!settled) finish(dnsAnswer(Buffer.concat(chunks, size))); });
    }); } catch { finish(null); return; }
    outgoing.once("socket", (socket) => socket.once("secureConnect", () => clearTimeout(connectTimer)));
    outgoing.once("error", () => finish(null));
    signal.addEventListener("abort", abort, { once: true });
    outgoing.end();
    if (signal.aborted) abort();
  });
}

/**
 * Mirror macOS Helper.swift start/resolveEndpoint before the probe core starts:
 * overwrite endpoint hosts using the same public DoH A-only bootstrap and force
 * built-in DNS resolution on proxy outbounds. User traffic still uses its VPN.
 * Mutate only after every required hostname resolved; also return the config.
 */
export async function prepareMacProbeConfig(config: Record<string, unknown>, signal: AbortSignal): Promise<Record<string, unknown>> {
  signal.throwIfAborted();
  const source = Array.isArray(config.outbounds) ? config.outbounds : [];
  if (source.length > 16 || !source.every(record)) throw new Error("Invalid probe outbounds");
  const outbounds = source.map((outbound) => structuredClone(outbound));
  const names = new Set<string>();
  for (const outbound of outbounds) endpointHosts(outbound.settings, names);
  const dns = record(config.dns) ? structuredClone(config.dns) : {};
  const hosts: Record<string, unknown> = record(dns.hosts) ? { ...dns.hosts } : {};
  for (const name of names) {
    let addresses: string[] | null = null;
    for (const resolver of RESOLVERS) {
      addresses = await queryResolver(resolver, name, signal);
      if (addresses) break;
    }
    if (!addresses) throw new Error("Probe endpoint bootstrap unavailable");
    hosts[name] = addresses;
  }
  signal.throwIfAborted();
  for (const outbound of outbounds) {
    if (typeof outbound.protocol === "string" && LOCAL_PROTOCOLS.has(outbound.protocol)) continue;
    const stream = record(outbound.streamSettings) ? outbound.streamSettings : {};
    const sockopt = record(stream.sockopt) ? stream.sockopt : {};
    outbound.streamSettings = { ...stream, sockopt: { ...sockopt, domainStrategy: "UseIP" } };
  }
  config.dns = { ...dns, hosts };
  config.outbounds = outbounds;
  return config;
}
