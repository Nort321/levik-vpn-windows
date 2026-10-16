import { MAX_PAYLOAD } from "./wire";

/** XOR parity over groups of four consecutive sequence numbers of one wire flow.
 * Recovers any single lost packet of a group for +25% bytes, independent of
 * duplication, so it also helps when every copy shares one physical route.
 *
 * Parity payload: [mask u8][xor length u16][xor address 4][xor port u16][xor data].
 * The parity header sequence is the group base (a multiple of FEC_GROUP). */
export const FEC_GROUP = 4;
export const FEC_FLUSH_MS = 15;
const PARITY_HEADER = 9;
const KEEP_GROUPS = 32;

export interface FecPacket { sequence: number; address: string; port: number; payload: Buffer }
interface Group { mask: number; packets: Array<FecPacket | undefined>; parity: Buffer | null; done: boolean }

const base = (sequence: number): number => sequence - sequence % FEC_GROUP;
function addressBytes(address: string): [number, number, number, number] {
  const parts = address.split(".").map(Number); return [parts[0]!, parts[1]!, parts[2]!, parts[3]!];
}

export class FecEncoder {
  private group = -1; private mask = 0; private length = 0; private address = [0, 0, 0, 0]; private port = 0;
  private data = Buffer.alloc(0); private size = 0;
  /** Returns the parity to send after this packet, or null while the group is still open. */
  add(packet: FecPacket): { sequence: number; payload: Buffer } | null {
    const groupBase = base(packet.sequence); let previous: { sequence: number; payload: Buffer } | null = null;
    if (this.group !== groupBase) { previous = this.flush(); this.group = groupBase; }
    if (packet.payload.length > MAX_PAYLOAD) return previous;
    const offset = packet.sequence - groupBase; if (this.mask & (1 << offset)) return previous;
    this.mask |= 1 << offset; this.length ^= packet.payload.length; this.port ^= packet.port;
    const bytes = addressBytes(packet.address); for (let i = 0; i < 4; i++) this.address[i]! ^= bytes[i]!;
    if (packet.payload.length > this.data.length) { const grown = Buffer.alloc(Math.max(packet.payload.length, this.data.length * 2, 256)); this.data.copy(grown); this.data = grown; }
    for (let i = 0; i < packet.payload.length; i++) this.data[i]! ^= packet.payload[i]!;
    this.size = Math.max(this.size, packet.payload.length);
    if (offset === FEC_GROUP - 1) return previous ?? this.flush();
    return previous;
  }
  /** Ends an open group early (after FEC_FLUSH_MS of silence). Single packets need no parity. */
  flush(): { sequence: number; payload: Buffer } | null {
    if (this.group < 0 || !this.mask) return null;
    const single = (this.mask & (this.mask - 1)) === 0;
    const result = single ? null : { sequence: this.group, payload: Buffer.concat([Buffer.from([this.mask, this.length >> 8, this.length & 255, ...this.address, this.port >> 8, this.port & 255]), this.data.subarray(0, this.size)]) };
    this.mask = 0; this.length = 0; this.address = [0, 0, 0, 0]; this.port = 0; this.data.fill(0, 0, this.size); this.size = 0;
    return result;
  }
  get open(): boolean { return this.mask !== 0; }
}

export class FecDecoder {
  private readonly groups = new Map<number, Group>();
  /** Records a received data packet; returns a packet recovered with it, if any. */
  data(packet: FecPacket): FecPacket | null {
    const group = this.entry(base(packet.sequence)); if (!group) return null;
    const offset = packet.sequence - base(packet.sequence);
    if (group.packets[offset]) return null;
    group.packets[offset] = packet;
    return this.recover(base(packet.sequence), group);
  }
  parity(sequence: number, payload: Buffer): FecPacket | null {
    if (sequence % FEC_GROUP !== 0 || payload.length < PARITY_HEADER || payload.length > PARITY_HEADER + MAX_PAYLOAD) return null;
    const mask = payload[0]!; if (!mask || mask >= 1 << FEC_GROUP) return null;
    const group = this.entry(sequence); if (!group || group.parity) return null;
    group.parity = payload; group.mask = mask;
    return this.recover(sequence, group);
  }
  private entry(groupBase: number): Group | null {
    let group = this.groups.get(groupBase);
    if (!group) {
      const newest = Math.max(-1, ...this.groups.keys());
      if (newest >= 0 && groupBase < newest - KEEP_GROUPS * FEC_GROUP) return null;
      group = { mask: 0, packets: [], parity: null, done: false }; this.groups.set(groupBase, group);
      for (const key of this.groups.keys()) if (key < Math.max(newest, groupBase) - KEEP_GROUPS * FEC_GROUP) this.groups.delete(key);
    }
    return group;
  }
  private recover(groupBase: number, group: Group): FecPacket | null {
    if (group.done || !group.parity) return null;
    let missing = -1;
    for (let offset = 0; offset < FEC_GROUP; offset++) if (group.mask & (1 << offset) && !group.packets[offset]) {
      if (missing >= 0) return null; missing = offset;
    }
    group.done = true; if (missing < 0) return null;
    const parity = group.parity; let length = parity.readUInt16BE(1); const address = [...parity.subarray(3, 7)]; let port = parity.readUInt16BE(7);
    const data = Buffer.from(parity.subarray(PARITY_HEADER));
    for (let offset = 0; offset < FEC_GROUP; offset++) {
      const packet = group.packets[offset]; if (!packet || !(group.mask & (1 << offset))) continue;
      length ^= packet.payload.length; port ^= packet.port;
      const bytes = addressBytes(packet.address); for (let i = 0; i < 4; i++) address[i]! ^= bytes[i]!;
      for (let i = 0; i < packet.payload.length && i < data.length; i++) data[i]! ^= packet.payload[i]!;
    }
    if (length > data.length || port < 1 || address[0] === 0) return null;
    const recovered = { sequence: groupBase + missing, address: address.join("."), port, payload: data.subarray(0, length) };
    group.packets[missing] = recovered; return recovered;
  }
}

/** Delays a send by a few milliseconds through one shared timer (copy time diversity). */
export class DelayQueue {
  private readonly queue: Array<{ due: number; send: () => void }> = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  constructor(private readonly now: () => number) {}
  push(delayMs: number, send: () => void): void {
    this.queue.push({ due: this.now() + delayMs, send });
    if (!this.timer) this.timer = setTimeout(() => this.drain(), delayMs);
  }
  private drain(): void {
    this.timer = null; const now = this.now();
    while (this.queue.length && this.queue[0]!.due <= now + 0.5) this.queue.shift()!.send();
    if (this.queue.length) this.timer = setTimeout(() => this.drain(), Math.max(1, this.queue[0]!.due - now));
  }
  clear(): void { if (this.timer) clearTimeout(this.timer); this.timer = null; this.queue.length = 0; }
}
