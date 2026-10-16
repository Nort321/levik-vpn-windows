import { createHash } from "node:crypto";
import { isIP } from "node:net";

// Carried exclusively inside authenticated Game tunnels. Never expose the relay
// publicly: possession of a session id is not a substitute for VPN authentication.
export const RELAY_PORT = 37079;
export const HEADER = 56;
export const PROTOCOL_VERSION = 3;
export const HEADER_V2 = HEADER + 82;
/** LGM3 keeps the same fields in 38 bytes: 8-byte session, 4-byte flow, 4-byte exit/instance tags. */
export const HEADER_V3 = 38;
export const MAX_CONTROL_BYTES = 8192;
export const MAX_PATHS = 8;
export const MAX_PAYLOAD = 60_000;
export const enum Kind { Ping = 1, Pong = 2, Up = 3, Down = 4, NodeInfo = 5, ProbeRequest = 6, ProbeResult = 7, MeshRow = 8, Parity = 9, Regions = 10 }
/** v3 flag bits. Unknown bits are rejected so that a future meaning cannot be silently ignored. */
const FLAG_HOP = 1;
export interface Packet {
  kind: Kind; path: number; session: Buffer; flow: Buffer; sequence: number;
  address: string; port: number; payload: Buffer;
  version?: 2 | 3; exitNodeId?: string; hops?: number; instance?: Buffer;
}
/** Resolves a v3 exit tag (8 hex chars) to a known nodeId. */
export type TagResolver = (tag: string) => string | undefined;

const tags = new Map<string, Buffer>();
/** Stable 4-byte exit tag. Configuration rejects colliding tags among known nodes. */
export function nodeTag(nodeId: string): Buffer {
  let tag = tags.get(nodeId);
  if (!tag) { tag = createHash("sha256").update(`levik-game-node:${nodeId}`).digest().subarray(0, 4); if (tags.size < 4096) tags.set(nodeId, tag); }
  return tag;
}
export function tagResolver(nodeIds: Iterable<string>): TagResolver {
  const known = new Map<string, string>();
  for (const nodeId of nodeIds) if (validNodeId(nodeId)) {
    const tag = nodeTag(nodeId).toString("hex"); const previous = known.get(tag);
    if (previous && previous !== nodeId) throw new Error("Game node tag collision");
    known.set(tag, nodeId);
  }
  return (tag) => known.get(tag);
}
/** v3 sessions/flows are random prefixes with a zero tail, so both encodings name the same state. */
export const newSession = (random: Buffer): Buffer => Buffer.concat([random.subarray(0, 8), Buffer.alloc(24)]);
export const newFlow = (random: Buffer): Buffer => Buffer.concat([random.subarray(0, 4), Buffer.alloc(4)]);
const zeroTail = (value: Buffer, from: number): boolean => value.subarray(from).every((byte) => byte === 0);
export const compactable = (packet: Pick<Packet, "session" | "flow">): boolean => zeroTail(packet.session, 8) && zeroTail(packet.flow, 4);
export const isControl = (kind: number): boolean => kind >= Kind.NodeInfo && kind <= Kind.MeshRow || kind === Kind.Regions;
const isData = (kind: number): boolean => kind >= Kind.Ping && kind <= Kind.Down || kind === Kind.Parity;

/** Same bytes as encode() but with a caller-owned prefix (the SOCKS UDP header) in one allocation. */
export function encode(packet: Packet, prefix?: Buffer): Buffer {
  if (packet.session.length !== 32 || packet.flow.length !== 8 || packet.payload.length > MAX_PAYLOAD
    || isIP(packet.address) !== 4 || !Number.isInteger(packet.path) || packet.path < 0 || packet.path >= MAX_PATHS
    || !Number.isInteger(packet.sequence) || packet.sequence < 0 || packet.sequence > 0xffffffff
    || !Number.isInteger(packet.port) || packet.port < 0 || packet.port > 65535
    || !(isData(packet.kind) || isControl(packet.kind))
    || (packet.kind > Kind.Down && !packet.version) || (isControl(packet.kind) && (packet.version !== 2 || packet.payload.length > MAX_CONTROL_BYTES))) throw new Error("Invalid Game packet");
  const nodeId = packet.exitNodeId ?? "";
  if (packet.version && ((nodeId && !validNodeId(nodeId)) || ![0, 1].includes(packet.hops ?? 0))) throw new Error("Invalid Game envelope");
  const lead = prefix?.length ?? 0;
  if (packet.version === 3) {
    if (!compactable(packet) || (packet.instance && packet.instance.length !== 16 && packet.instance.length !== 4)) throw new Error("Invalid Game envelope");
    const out = Buffer.allocUnsafe(lead + HEADER_V3 + packet.payload.length);
    prefix?.copy(out, 0);
    out.write("LGM3", lead, "ascii"); out[lead + 4] = packet.kind; out[lead + 5] = packet.path;
    out[lead + 6] = packet.hops ? FLAG_HOP : 0; out[lead + 7] = 0;
    packet.session.copy(out, lead + 8, 0, 8); packet.flow.copy(out, lead + 16, 0, 4);
    out.writeUInt32BE(packet.sequence, lead + 20);
    if (nodeId) nodeTag(nodeId).copy(out, lead + 24); else out.fill(0, lead + 24, lead + 28);
    if (packet.instance) packet.instance.copy(out, lead + 28, 0, 4); else out.fill(0, lead + 28, lead + 32);
    writeAddress(out, lead + 32, packet.address, packet.port);
    packet.payload.copy(out, lead + HEADER_V3);
    return out;
  }
  if (packet.version === 2 && packet.instance && packet.instance.length !== 16) throw new Error("Invalid Game envelope");
  const offset = packet.version === 2 ? HEADER_V2 : HEADER;
  const out = Buffer.alloc(lead + offset + packet.payload.length);
  prefix?.copy(out, 0);
  out.write(packet.version === 2 ? "LGM2" : "LGM1", lead, "ascii"); out[lead + 4] = packet.kind; out[lead + 5] = packet.path;
  packet.session.copy(out, lead + 6); packet.flow.copy(out, lead + 38); out.writeUInt32BE(packet.sequence, lead + 46);
  writeAddress(out, lead + 50, packet.address, packet.port);
  if (packet.version === 2) {
    out[lead + 56] = Buffer.byteLength(nodeId); out.write(nodeId, lead + 57, "ascii"); out[lead + 121] = packet.hops ?? 0;
    packet.instance?.copy(out, lead + 122);
  }
  packet.payload.copy(out, lead + offset);
  return out;
}
function writeAddress(out: Buffer, offset: number, address: string, port: number): void {
  let index = 0; let value = 0;
  for (let i = 0; i < address.length; i++) {
    const code = address.charCodeAt(i);
    if (code === 46) { out[offset + index++] = value; value = 0; } else value = value * 10 + code - 48;
  }
  out[offset + index] = value; out.writeUInt16BE(port, offset + 4);
}
const readAddress = (data: Buffer, offset: number): string => `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;

export function decode(data: Buffer, resolve?: TagResolver): Packet | null {
  if (data.length < 4) return null;
  const version = data.toString("ascii", 0, 4);
  if (version === "LGM3") {
    const kind = data[4]!;
    if (data.length < HEADER_V3 || data.length > HEADER_V3 + MAX_PAYLOAD || !isData(kind) || data[5]! >= MAX_PATHS
      || (data[6]! & ~FLAG_HOP) !== 0 || data[7] !== 0) return null;
    const tag = data.subarray(24, 28); let exitNodeId = "";
    if (tag.some((byte) => byte !== 0)) {
      const resolved = resolve?.(tag.toString("hex")); if (!resolved) return null; exitNodeId = resolved;
    }
    const session = Buffer.alloc(32); data.copy(session, 0, 8, 16);
    const flow = Buffer.alloc(8); data.copy(flow, 0, 16, 20);
    return { kind, path: data[5]!, session, flow, sequence: data.readUInt32BE(20), address: readAddress(data, 32),
      port: data.readUInt16BE(36), payload: data.subarray(HEADER_V3), version: 3, exitNodeId, hops: data[6]! & FLAG_HOP,
      instance: data.subarray(28, 32) };
  }
  const modern = version === "LGM2";
  const offset = modern ? HEADER_V2 : HEADER;
  if ((!modern && version !== "LGM1") || data.length < offset || data.length > offset + MAX_PAYLOAD
    || !(modern ? isData(data[4]!) || isControl(data[4]!) : data[4]! >= Kind.Ping && data[4]! <= Kind.Down) || data[5]! >= MAX_PATHS
    || (isControl(data[4]!) && data.length > offset + MAX_CONTROL_BYTES)) return null;
  const nodeId = modern ? data.toString("ascii", 57, 57 + data[56]!) : "";
  if (modern && (data[56]! > 64 || (nodeId && !validNodeId(nodeId)) || data[121]! > 1
    || data.subarray(57 + data[56]!, 121).some((byte) => byte !== 0))) return null;
  return { kind: data[4]!, path: data[5]!, session: data.subarray(6, 38), flow: data.subarray(38, 46),
    sequence: data.readUInt32BE(46), address: readAddress(data, 50),
    port: data.readUInt16BE(54), payload: data.subarray(offset),
    ...(modern ? { version: 2 as const, exitNodeId: nodeId, hops: data[121]!, instance: data.subarray(122, 138) } : {}) };
}
/** An all-zero instance means "any"; a v3 4-byte tag matches the prefix of the full 16-byte instance. */
export function instanceMatches(received: Buffer | undefined, instance: Buffer): boolean {
  if (!received || received.every((byte) => byte === 0)) return true;
  return received.length <= instance.length && instance.subarray(0, received.length).equals(received);
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

/** Relay features announced in NODE_INFO. Absent fields mean an older relay. */
export interface RelayCapabilities { probe: boolean; mesh: boolean; lgm3: boolean; eim: boolean; fec: boolean; regions: boolean; spread: boolean }
export function parseCapabilities(value: unknown): RelayCapabilities {
  const item = isRecord(value) ? value : {};
  return { probe: item.probe === true, mesh: item.mesh === true, lgm3: item.lgm3 === true, eim: item.eim === true,
    fec: item.fec === true, regions: item.regions === true, spread: item.spread === true };
}
/** Ping payload bits: active copy and "delay this copy" for same-route time diversity. */
export const PING_ACTIVE = 1;
export const PING_SPREAD = 2;
/** The client wants Down parity for this session. */
export const PING_FEC = 4;

export interface ProbeTarget { address: string; port: number }
export interface ProbeMeasurement extends ProbeTarget {
  medianMs: number | null; p95Ms: number | null; jitterMs: number | null; lossPercent: number;
  method: "icmp" | "ttl-hop" | "udp-echo" | "unavailable"; sampleCount: number; measuredAt: string;
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
    || !["icmp", "ttl-hop", "udp-echo", "unavailable"].includes(String(value.method))
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
      && /^[\p{L}\p{N} ._/:-]{1,80}$/u.test(value[key]) ? [[key, value[key]]] : [])) };
}

/** Bounded replay window. Do not wait for missing packets: games handle reordering.
 * A ring of the last 512 sequence numbers: O(1) per packet, no allocation. */
export class SequenceWindow {
  private high = -1;
  private readonly slots = new Float64Array(512);
  accept(sequence: number): boolean {
    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffffffff || sequence <= this.high - 512) return false;
    const index = sequence % 512;
    if (this.slots[index] === sequence + 1) return false;
    this.slots[index] = sequence + 1; if (sequence > this.high) this.high = sequence;
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
