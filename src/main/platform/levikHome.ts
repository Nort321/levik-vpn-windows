import { createSocket } from "node:dgram";
import { networkInterfaces } from "node:os";

/**
 * Levik Home on the computer, docs/app-platform.md "Levik Home". A router
 * with the Levik Home agent answers mDNS queries for `_levik._tcp.local` on
 * its home network with a beacon: the home, a five-minute window and a proof
 * only the account's server can check.
 */
export interface HomeBeacon {
  homeId: string;
  window: number;
  proof: string;
}

/** The server recognised the beacon as the account's home. */
export interface VerifiedHome {
  name: string;
  routerOnline: boolean;
  routerVpnActive: boolean;
}

export const HOME_WINDOW_SECONDS = 300;
const TOKEN = /^[A-Za-z0-9_-]{22}$/;
const WINDOW = /^[0-9]{1,12}$/;
const MAX_NAME = 60;
const SERVICE = "_levik._tcp.local";
const MDNS_GROUP = "224.0.0.251";
const MDNS_PORT = 5353;
const TYPE_PTR = 12;
const TYPE_TXT = 16;
const CLASS_IN = 1;
const MAX_BEACONS = 8;

/** The router's VPN protects the home, so the computer's own may sleep. */
export function protects(home: VerifiedHome): boolean {
  return home.routerOnline && home.routerVpnActive;
}

/** TXT strings of a service instance; anything that is not a v1 beacon is ignored. */
export function parseBeacon(strings: readonly string[]): HomeBeacon | null {
  const values = new Map<string, string>();
  for (const item of strings) {
    const separator = item.indexOf("=");
    if (separator > 0 && !values.has(item.slice(0, separator))) values.set(item.slice(0, separator), item.slice(separator + 1));
  }
  if (values.get("v") !== "1") return null;
  const homeId = values.get("h");
  const window = values.get("w");
  const proof = values.get("p");
  if (!homeId || !TOKEN.test(homeId) || !window || !WINDOW.test(window) || !proof || !TOKEN.test(proof)) return null;
  const number = Number(window);
  return number > 0 ? { homeId, window: number, proof } : null;
}

export function homeWindow(nowMs: number): number {
  return Math.floor(nowMs / 1000 / HOME_WINDOW_SECONDS);
}

/** The server accepts the current window and its neighbours. */
export function beaconFresh(beacon: HomeBeacon, nowMs: number): boolean {
  return Math.abs(beacon.window - homeWindow(nowMs)) <= 1;
}

/** The server's answer to a sighting; null when it is not the account's home. */
export function parseSighting(value: unknown): VerifiedHome | null {
  if (!isRecord(value) || !isRecord(value.home)) return null;
  const { name, routerOnline, routerVpnActive } = value.home;
  if (typeof name !== "string" || typeof routerOnline !== "boolean" || typeof routerVpnActive !== "boolean") return null;
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > MAX_NAME) return null;
  return { name: trimmed, routerOnline, routerVpnActive };
}

export type HomeAction = { kind: "none" } | { kind: "sleep"; home: string } | { kind: "wake" };

const NONE: HomeAction = { kind: "none" };
const WAKE: HomeAction = { kind: "wake" };

/**
 * When the VPN sleeps at home. It falls asleep when the account's home is
 * heard while the router's VPN protects it, and wakes as soon as the
 * computer leaves the network, the router's VPN stops or the home goes
 * silent. A user who connects again at home keeps the VPN until the next
 * arrival.
 */
export class HomeSleepPolicy {
  static readonly SILENCE_MS = 3 * HOME_WINDOW_SECONDS * 1000;
  private sleeping = false;
  private declined = false;
  private heardAtMs: number | null = null;

  constructor(private readonly silenceMs = HomeSleepPolicy.SILENCE_MS) {}

  get asleep(): boolean {
    return this.sleeping;
  }

  /** A scan result: the account's home, or null when none answered on this network. */
  heard(home: VerifiedHome | null, nowMs: number, vpnConnected: boolean, enabled: boolean): HomeAction {
    if (home === null) return this.silence(nowMs);
    if (!protects(home)) {
      this.heardAtMs = null;
      return this.wake();
    }
    this.heardAtMs = nowMs;
    if (!enabled) return this.wake();
    if (this.sleeping || this.declined || !vpnConnected) return NONE;
    this.sleeping = true;
    return { kind: "sleep", home: home.name };
  }

  /** No answer lately: after a while the computer is no longer home. */
  silence(nowMs: number): HomeAction {
    if (this.heardAtMs === null) return this.wake();
    if (nowMs - this.heardAtMs <= this.silenceMs) return NONE;
    this.heardAtMs = null;
    this.declined = false;
    return this.wake();
  }

  /** The computer left the network it fell asleep on. */
  left(): HomeAction {
    this.heardAtMs = null;
    this.declined = false;
    return this.wake();
  }

  /** The user connected again at home: not again until the next arrival. */
  resumedByUser(): void {
    if (!this.sleeping) return;
    this.sleeping = false;
    this.declined = true;
  }

  /** The VPN was turned off altogether; there is nothing to wake. */
  stopped(): void {
    this.sleeping = false;
  }

  private wake(): HomeAction {
    if (!this.sleeping) return NONE;
    this.sleeping = false;
    return WAKE;
  }
}

/** The private IPv4 addresses of this computer's own network interfaces (no tunnels). */
export function localAddresses(): string[] {
  const addresses: string[] = [];
  for (const [name, entries] of Object.entries(networkInterfaces())) {
    if (/^(utun|tun|tap|wg|ppp|ipsec|lo)|levik|wintun/i.test(name)) continue;
    for (const entry of entries ?? []) {
      // 10.89.0.0/30 is Levik VPN's own tunnel (vpn/xrayConfig.ts).
      if (entry.family === "IPv4" && !entry.internal && isPrivate(entry.address) && !entry.address.startsWith("10.89.0.")) {
        addresses.push(entry.address);
      }
    }
  }
  return addresses.sort();
}

/** A query for the service from an ephemeral port: the router answers it directly (RFC 6762 §6.7). */
export function encodeQuery(id: number): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(4);
  question.writeUInt16BE(TYPE_PTR, 0);
  question.writeUInt16BE(CLASS_IN, 2);
  return Buffer.concat([header, encodeName(SERVICE), question]);
}

/** TXT strings of every `_levik._tcp.local` instance in a response. */
export function parseResponse(packet: Buffer): string[][] {
  if (packet.length < 12 || (packet.readUInt16BE(2) & 0x8000) === 0) return [];
  const questions = packet.readUInt16BE(4);
  const records = packet.readUInt16BE(6) + packet.readUInt16BE(8) + packet.readUInt16BE(10);
  let offset = 12;
  for (let index = 0; index < questions; index += 1) {
    offset = decodeName(packet, offset).end + 4;
  }
  const found: string[][] = [];
  for (let index = 0; index < records && index < 64; index += 1) {
    const { name, end } = decodeName(packet, offset);
    if (end + 10 > packet.length) break;
    const type = packet.readUInt16BE(end);
    const length = packet.readUInt16BE(end + 8);
    const start = end + 10;
    if (start + length > packet.length) break;
    if (type === TYPE_TXT && name.toLowerCase().endsWith(`.${SERVICE}`)) found.push(txtStrings(packet.subarray(start, start + length)));
    offset = start + length;
  }
  return found;
}

/** Asks every local network for Levik Home routers and collects their beacons for a moment. */
export async function scanHomes(durationMs = 2_500): Promise<HomeBeacon[]> {
  const addresses = localAddresses();
  if (addresses.length === 0) return [];
  const socket = createSocket({ type: "udp4", reuseAddr: true });
  const beacons = new Map<string, HomeBeacon>();
  socket.on("message", (packet) => {
    let instances: string[][];
    try {
      instances = parseResponse(packet);
    } catch {
      return;
    }
    for (const strings of instances) {
      const beacon = parseBeacon(strings);
      if (beacon && beacons.size < MAX_BEACONS && !beacons.has(beacon.homeId)) beacons.set(beacon.homeId, beacon);
    }
  });
  socket.on("error", () => undefined);
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(0, () => {
        socket.off("error", reject);
        resolve();
      });
    });
    const query = encodeQuery(Math.floor(Math.random() * 0x10000));
    for (const address of addresses) {
      try {
        socket.setMulticastInterface(address);
        await new Promise<void>((resolve) => socket.send(query, MDNS_PORT, MDNS_GROUP, () => resolve()));
      } catch {
        // An interface that went away meanwhile.
      }
    }
    await new Promise((resolve) => setTimeout(resolve, durationMs));
  } catch {
    return [];
  } finally {
    socket.close();
  }
  return [...beacons.values()];
}

function encodeName(name: string): Buffer {
  const parts = name.split(".").map((label) => {
    const raw = Buffer.from(label, "utf8");
    return Buffer.concat([Buffer.from([raw.length]), raw]);
  });
  return Buffer.concat([...parts, Buffer.from([0])]);
}

function decodeName(packet: Buffer, start: number): { name: string; end: number } {
  const labels: string[] = [];
  let offset = start;
  let end: number | null = null;
  for (let jumps = 0; jumps <= 16; ) {
    if (offset >= packet.length) throw new Error("truncated name");
    const length = packet.readUInt8(offset);
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length) throw new Error("truncated pointer");
      end ??= offset + 2;
      offset = ((length & 0x3f) << 8) | packet.readUInt8(offset + 1);
      jumps += 1;
      continue;
    }
    if (length === 0) return { name: labels.join("."), end: end ?? offset + 1 };
    if (length > 63 || offset + 1 + length > packet.length) throw new Error("bad label");
    labels.push(packet.toString("utf8", offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  throw new Error("pointer loop");
}

function txtStrings(data: Buffer): string[] {
  const strings: string[] = [];
  let offset = 0;
  while (offset < data.length) {
    const length = data.readUInt8(offset);
    if (offset + 1 + length > data.length) break;
    strings.push(data.toString("utf8", offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  return strings;
}

function isPrivate(address: string): boolean {
  const [a = 0, b = 0] = address.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
