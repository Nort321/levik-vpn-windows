import { lookup } from "node:dns/promises";
import { createSocket } from "node:dgram";
import { Socket } from "node:net";
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";
import type { TunnelServer } from "../../shared/contracts";

const TIMEOUT_MS = 3_000;
const MAX_ENDPOINT_DEPTH = 6;
const MAX_PARALLEL_PROBES = 8;

interface ServerEndpoint {
  host: string;
  port: number;
}

export async function measureServerLatency(server: TunnelServer): Promise<number | null> {
  const endpoint = extractServerEndpoint(server.outbound);
  if (!endpoint) return null;
  const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol.toLowerCase() : "";
  if (["hysteria", "hysteria2", "tuic", "wireguard"].includes(protocol)) {
    return await measureUdp(endpoint) ?? measureTcp(endpoint);
  }
  return measureTcp(endpoint);
}

export async function measureServerLatencies(servers: TunnelServer[]): Promise<Record<string, number | null>> {
  const result: Record<string, number | null> = {};
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(MAX_PARALLEL_PROBES, servers.length) }, async () => {
    while (nextIndex < servers.length) {
      const server = servers[nextIndex++];
      if (server) result[server.id] = await measureServerLatency(server);
    }
  });
  await Promise.all(workers);
  return result;
}

export function extractServerEndpoint(outbound: Record<string, unknown>): ServerEndpoint | null {
  return findEndpoint(outbound.settings, 0) ?? findEndpoint(outbound, 0);
}

function findEndpoint(value: unknown, depth: number): ServerEndpoint | null {
  if (depth > MAX_ENDPOINT_DEPTH) return null;
  if (isRecord(value)) {
    const host = firstString(value.address, value.host, value.server);
    const port = numberPort(value.port);
    if (host && port) return { host, port };
    for (const child of Object.values(value)) {
      const endpoint = findEndpoint(child, depth + 1);
      if (endpoint) return endpoint;
    }
  } else if (Array.isArray(value)) {
    for (const child of value) {
      const endpoint = findEndpoint(child, depth + 1);
      if (endpoint) return endpoint;
    }
  }
  return null;
}

function measureTcp(endpoint: ServerEndpoint): Promise<number | null> {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    const socket = new Socket();
    let settled = false;
    const finish = (latency: number | null): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(latency);
    };
    socket.setTimeout(TIMEOUT_MS);
    socket.once("connect", () => finish(Math.max(1, Math.round(performance.now() - startedAt))));
    socket.once("timeout", () => finish(null));
    socket.once("error", () => finish(null));
    socket.connect(endpoint.port, endpoint.host);
  });
}

async function measureUdp(endpoint: ServerEndpoint): Promise<number | null> {
  try {
    const address = await lookup(endpoint.host);
    return await new Promise((resolve) => {
      const socket = createSocket(address.family === 6 ? "udp6" : "udp4");
      const startedAt = performance.now();
      let settled = false;
      const timeout = setTimeout(() => finish(null), TIMEOUT_MS);
      const finish = (latency: number | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        socket.close();
        resolve(latency);
      };
      socket.once("message", () => finish(Math.max(1, Math.round(performance.now() - startedAt))));
      socket.once("error", () => finish(null));
      socket.send(buildQuicProbePacket(), endpoint.port, address.address, (error) => {
        if (error) finish(null);
      });
    });
  } catch {
    return null;
  }
}

function buildQuicProbePacket(): Buffer {
  const packet = Buffer.alloc(1_200);
  packet[0] = 0xc0;
  packet[4] = 0x01;
  packet[5] = 0x08;
  randomBytes(8).copy(packet, 6);
  packet[14] = 0x08;
  randomBytes(8).copy(packet, 15);
  packet[24] = 0x44;
  packet[25] = 0x90;
  return packet;
}

function numberPort(value: unknown): number | null {
  const port = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
  return Number.isInteger(port) && port >= 1 && port <= 65_535 ? port : null;
}

function firstString(...values: unknown[]): string | null {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0)?.trim() ?? null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
