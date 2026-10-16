import { isIP } from "node:net";

// Carried exclusively inside authenticated Game tunnels. Never expose the relay
// publicly: possession of a session id is not a substitute for VPN authentication.
export const RELAY_PORT = 37079;
export const HEADER = 56;
export const PROTOCOL_VERSION = 2;
export const HEADER_V2 = HEADER + 82;
export const MAX_CONTROL_BYTES = 8192;
export const MAX_PATHS = 8;
export const MAX_PAYLOAD = 60_000;
export const enum Kind { Ping = 1, Pong = 2, Up = 3, Down = 4, NodeInfo = 5, ProbeRequest = 6, ProbeResult = 7, MeshRow = 8 }
export interface Packet {
  kind: Kind; path: number; session: Buffer; flow: Buffer; sequence: number;
  address: string; port: number; payload: Buffer;
  version?: 2; exitNodeId?: string; hops?: number; instance?: Buffer;
}
export function encode(packet: Packet): Buffer {
  if (packet.session.length !== 32 || packet.flow.length !== 8 || packet.payload.length > MAX_PAYLOAD
    || isIP(packet.address) !== 4 || !Number.isInteger(packet.path) || packet.path < 0 || packet.path >= MAX_PATHS
    || !Number.isInteger(packet.sequence) || packet.sequence < 0 || packet.sequence > 0xffffffff
    || !Number.isInteger(packet.port) || packet.port < 0 || packet.port > 65535
    || packet.kind < Kind.Ping || packet.kind > Kind.MeshRow
    || (packet.kind > Kind.Down && (!packet.version || packet.payload.length > MAX_CONTROL_BYTES))) throw new Error("Invalid Game packet");
  const offset = packet.version === 2 ? HEADER_V2 : HEADER;
  const out = Buffer.alloc(offset + packet.payload.length);
  out.write(packet.version === 2 ? "LGM2" : "LGM1", 0, "ascii"); out[4] = packet.kind; out[5] = packet.path;
  packet.session.copy(out, 6); packet.flow.copy(out, 38); out.writeUInt32BE(packet.sequence, 46);
  packet.address.split(".").forEach((value, i) => { out[50 + i] = Number(value); });
  out.writeUInt16BE(packet.port, 54);
  if (packet.version === 2) {
    const nodeId = packet.exitNodeId ?? "";
    if ((nodeId && !validNodeId(nodeId)) || ![0, 1].includes(packet.hops ?? 0)
      || (packet.instance && packet.instance.length !== 16)) throw new Error("Invalid Game envelope");
    out[56] = Buffer.byteLength(nodeId); out.write(nodeId, 57, "ascii"); out[121] = packet.hops ?? 0;
    packet.instance?.copy(out, 122);
  }
  packet.payload.copy(out, offset);
  return out;
}
export function decode(data: Buffer): Packet | null {
  const version = data.toString("ascii", 0, 4);
  const modern = version === "LGM2";
  const offset = modern ? HEADER_V2 : HEADER;
  if ((!modern && version !== "LGM1") || data.length < offset || data.length > offset + MAX_PAYLOAD
    || data[4]! < Kind.Ping || data[4]! > (modern ? Kind.MeshRow : Kind.Down) || data[5]! >= MAX_PATHS
    || (data[4]! > Kind.Down && data.length > offset + MAX_CONTROL_BYTES)) return null;
  const nodeId = modern ? data.toString("ascii", 57, 57 + data[56]!) : "";
  if (modern && (data[56]! > 64 || (nodeId && !validNodeId(nodeId)) || data[121]! > 1
    || data.subarray(57 + data[56]!, 121).some((byte) => byte !== 0))) return null;
  return { kind: data[4]!, path: data[5]!, session: data.subarray(6, 38), flow: data.subarray(38, 46),
    sequence: data.readUInt32BE(46), address: [...data.subarray(50, 54)].join("."),
    port: data.readUInt16BE(54), payload: data.subarray(offset),
    ...(modern ? { version: 2 as const, exitNodeId: nodeId, hops: data[121]!, instance: data.subarray(122, 138) } : {}) };
}

export const validNodeId = (value: string): boolean => /^[A-Za-z0-9_-]{1,64}$/.test(value);
export function controlPayload(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value));
  if (payload.length > MAX_CONTROL_BYTES) throw new Error("Game control frame too large");
  return payload;
}
export function parseControl(payload: Buffer): unknown {
  if (payload.length > MAX_CONTROL_BYTES) return null;
  try { return JSON.parse(payload.toString("utf8")) as unknown; } catch { return null; }
}

export interface ProbeTarget { address: string; port: number }
export interface ProbeMeasurement extends ProbeTarget {
  medianMs: number | null; p95Ms: number | null; jitterMs: number | null; lossPercent: number;
  method: "icmp" | "ttl-hop" | "unavailable"; sampleCount: number; measuredAt: string;
  region?: string; operator?: string; routeKey?: string;
  approximate?: boolean;
  scope?: "target" | "subnet";
}
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
export function parseMeasurement(value: unknown): ProbeMeasurement | null {
  if (!isRecord(value) || typeof value.address !== "string" || !publicIPv4(value.address)
    || !Number.isInteger(value.port) || Number(value.port) < 1 || Number(value.port) > 65535
    || !["icmp", "ttl-hop", "unavailable"].includes(String(value.method))
    || !Number.isInteger(value.sampleCount) || Number(value.sampleCount) < 0 || Number(value.sampleCount) > 1024
    || typeof value.lossPercent !== "number" || !Number.isFinite(value.lossPercent) || value.lossPercent < 0 || value.lossPercent > 100
    || typeof value.measuredAt !== "string" || !Number.isFinite(Date.parse(value.measuredAt))) return null;
  for (const key of ["medianMs", "p95Ms", "jitterMs"] as const) {
    const item = value[key]; if (item !== null && (typeof item !== "number" || !Number.isFinite(item) || item < 0 || item > 120_000)) return null;
  }
  if (value.method !== "unavailable" && (value.medianMs === null || Number(value.sampleCount) === 0)) return null;
  return { address: value.address, port: Number(value.port), medianMs: value.medianMs as number | null,
    p95Ms: value.p95Ms as number | null, jitterMs: value.jitterMs as number | null, lossPercent: value.lossPercent,
    method: value.method as ProbeMeasurement["method"], sampleCount: Number(value.sampleCount), measuredAt: value.measuredAt,
    ...(typeof value.approximate === "boolean" ? { approximate: value.approximate } : {}),
    ...(value.scope === "target" || value.scope === "subnet" ? { scope: value.scope } : {}),
    ...Object.fromEntries(["region", "operator", "routeKey"].flatMap((key) => typeof value[key] === "string"
      && /^[\p{L}\p{N} ._/-]{1,80}$/u.test(value[key]) ? [[key, value[key]]] : [])) };
}

/** Bounded replay window. Do not wait for missing packets: games handle reordering. */
export class SequenceWindow {
  private high = -1;
  private readonly seen = new Set<number>();
  accept(sequence: number): boolean {
    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffffffff
      || sequence <= this.high - 512 || this.seen.has(sequence)) return false;
    this.high = Math.max(this.high, sequence); this.seen.add(sequence);
    for (const old of this.seen) if (old <= this.high - 512) this.seen.delete(old);
    return true;
  }
}

export function publicIPv4(address: string): boolean {
  if (isIP(address) !== 4) return false;
  const [a, b, c] = address.split(".").map(Number) as [number, number, number, number];
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0) || (a === 192 && b === 88 && c === 99)
    || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    || (a === 203 && b === 0 && c === 113));
}
