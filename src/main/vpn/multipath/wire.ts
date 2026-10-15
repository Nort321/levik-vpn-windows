import { isIP } from "node:net";

// Carried exclusively inside authenticated Game tunnels. Never expose the relay
// publicly: possession of a session id is not a substitute for VPN authentication.
export const RELAY_PORT = 37079;
export const HEADER = 56;
export const MAX_PATHS = 8;
export const MAX_PAYLOAD = 60_000;
export const enum Kind { Ping = 1, Pong = 2, Up = 3, Down = 4 }
export interface Packet {
  kind: Kind; path: number; session: Buffer; flow: Buffer; sequence: number;
  address: string; port: number; payload: Buffer;
}
export function encode(packet: Packet): Buffer {
  if (packet.session.length !== 32 || packet.flow.length !== 8 || packet.payload.length > MAX_PAYLOAD
    || isIP(packet.address) !== 4 || packet.path < 0 || packet.path >= MAX_PATHS) throw new Error("Invalid Game packet");
  const out = Buffer.allocUnsafe(HEADER + packet.payload.length);
  out.write("LGM1", 0, "ascii"); out[4] = packet.kind; out[5] = packet.path;
  packet.session.copy(out, 6); packet.flow.copy(out, 38); out.writeUInt32BE(packet.sequence, 46);
  packet.address.split(".").forEach((value, i) => { out[50 + i] = Number(value); });
  out.writeUInt16BE(packet.port, 54); packet.payload.copy(out, HEADER);
  return out;
}
export function decode(data: Buffer): Packet | null {
  if (data.length < HEADER || data.length > HEADER + MAX_PAYLOAD || data.toString("ascii", 0, 4) !== "LGM1"
    || data[4]! < Kind.Ping || data[4]! > Kind.Down || data[5]! >= MAX_PATHS) return null;
  return { kind: data[4]!, path: data[5]!, session: data.subarray(6, 38), flow: data.subarray(38, 46),
    sequence: data.readUInt32BE(46), address: [...data.subarray(50, 54)].join("."),
    port: data.readUInt16BE(54), payload: data.subarray(HEADER) };
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
