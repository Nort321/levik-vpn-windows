import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { networkInterfaces, type NetworkInterfaceInfo } from "node:os";
import { dirname } from "node:path";
import type { ProtocolAdvice } from "../platform/remoteConfig";

/**
 * Smart Auto, docs/app-platform.md "Smart Auto": the automatic server is the
 * one that carries traffic on this network, answers fast and is not busy.
 *
 *     score = latency × (1 + 2 × load) × history × advice      (lower is better)
 *
 * The history is the computer's own record of which protocols passed a real
 * download on which network. It stays on the computer; a network is named by
 * a salted hash, never by its addresses.
 */

export type ProtocolVerdict = "blocked" | "suspect" | "works" | "unknown";

export interface SmartCandidate {
  id: string;
  /** The protocol's telemetry name: VLESS Reality and VLESS XHTTP are different rungs. */
  protocol: string;
  /** Time to reach the server; null when it did not answer. */
  latencyMs: number | null;
  /** True when no answer means the server is down (TCP); a UDP server may just not answer probes. */
  silenceMeansDown: boolean;
  /** 0 (idle) to 1 (full); null when the website did not say. */
  load: number | null;
  verdict: ProtocolVerdict;
}

export interface RankedServer {
  id: string;
  protocol: string;
  score: number;
}

/** Assumed for a UDP server that does not answer probes (obfuscated or filtered). */
export const UNKNOWN_LATENCY_MS = 400;
/** Assumed when the website did not report the load. */
export const UNKNOWN_LOAD = 0.35;
/** A running connection moves only to a server this much better. */
export const SWITCH_MARGIN = 0.75;
const LOAD_WEIGHT = 2;
const OVERLOADED = 0.9;
const OVERLOAD_FACTOR = 2;
const HISTORY_FACTOR: Record<ProtocolVerdict, number> = { works: 0.8, unknown: 1, suspect: 2, blocked: 10 };
const UNANSWERED_PROTOCOLS = new Set(["hysteria", "hysteria2", "tuic", "wireguard"]);

/** Best first. Protocols seen blocked here are left out unless nothing else is left. */
export function rankSmart(candidates: readonly SmartCandidate[], advice: ProtocolAdvice | null): RankedServer[] {
  const reachable = candidates.filter((item) => item.latencyMs !== null || !item.silenceMeansDown);
  const allowed = reachable.filter((item) => item.verdict !== "blocked");
  // Everything blocked or silent: better to try something than nothing.
  const pool = allowed.length ? allowed : reachable.length ? reachable : [...candidates];
  return pool
    .map((item) => ({ id: item.id, protocol: item.protocol, score: smartScore(item, advice) }))
    .sort((left, right) => left.score - right.score || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
}

export function smartScore(candidate: SmartCandidate, advice: ProtocolAdvice | null): number {
  const latency = Math.max(1, candidate.latencyMs ?? UNKNOWN_LATENCY_MS);
  const load = Math.min(1, Math.max(0, candidate.load ?? UNKNOWN_LOAD));
  const loadFactor = (1 + LOAD_WEIGHT * load) * (load >= OVERLOADED ? OVERLOAD_FACTOR : 1);
  // The computer's own experience outweighs the operator average.
  const operator = candidate.verdict === "works" || !advice ? 1
    : advice.avoid.includes(candidate.protocol) ? 3
      : advice.preferred.includes(candidate.protocol) ? 0.85
        : 1;
  return latency * loadFactor * HISTORY_FACTOR[candidate.verdict] * operator;
}

/** The next rung after a failed traffic check: a protocol not tried yet, else any untried server. */
export function nextRung(ranked: readonly RankedServer[], triedProtocols: ReadonlySet<string>, triedIds: ReadonlySet<string>): RankedServer | null {
  return ranked.find((item) => !triedProtocols.has(item.protocol) && !triedIds.has(item.id))
    ?? ranked.find((item) => !triedIds.has(item.id))
    ?? null;
}

/** Moving a running connection costs a reconnect; only a clearly better server is worth it. */
export function worthSwitching(currentScore: number | null, bestScore: number): boolean {
  return currentScore === null || bestScore < currentScore * SWITCH_MARGIN;
}

/** Whether a server that does not answer the probe is down: obfuscated UDP servers ignore probes. */
export function silenceMeansDown(outbound: Record<string, unknown>): boolean {
  const protocol = typeof outbound.protocol === "string" ? outbound.protocol.toLowerCase()
    : typeof outbound.type === "string" ? outbound.type.toLowerCase() : "";
  return !UNANSWERED_PROTOCOLS.has(protocol);
}

/** A protocol's name for people, from its telemetry name. */
export function protocolLabel(protocol: string): string {
  switch (protocol) {
    case "vless-reality": return "VLESS Reality";
    case "vless-xhttp": return "VLESS XHTTP";
    case "vless-ws": return "VLESS WS";
    case "vless-grpc": return "VLESS gRPC";
    case "vless-tcp": return "VLESS";
    case "hysteria2": return "Hysteria 2";
    case "tuic": return "TUIC";
    case "trojan": return "Trojan";
    case "shadowsocks": return "Shadowsocks";
    default: return protocol.toUpperCase();
  }
}

export interface ProtocolRecord {
  /** Node ids where the check failed since the last success. */
  failedNodes: string[];
  lastFailureAt: number;
  lastSuccessAt: number;
}

export interface ProtocolHistory {
  /** The most recently updated network last. */
  networks: Array<{ key: string; protocols: Record<string, ProtocolRecord> }>;
  /** Network key → the server that last carried traffic there. */
  winners: Record<string, string>;
}

export const BLOCK_AFTER_NODES = 2;
export const BLOCK_TTL_MS = 24 * 60 * 60_000;
export const SUSPECT_TTL_MS = 6 * 60 * 60_000;
export const WORKS_TTL_MS = 7 * 24 * 60 * 60_000;
export const MAX_NETWORKS = 16;
const MAX_PROTOCOLS = 16;
const MAX_FAILED_NODES = 8;
const KEY = /^[0-9a-f]{16}$/;
const NAME = /^[a-z0-9-]{1,24}$/;
const ID = /^[\x21-\x7e]{1,128}$/;

export const emptyHistory = (): ProtocolHistory => ({ networks: [], winners: {} });

export function verdictOf(history: ProtocolHistory, networkKey: string | null, protocol: string, now: number): ProtocolVerdict {
  const record = networkKey ? history.networks.find((item) => item.key === networkKey)?.protocols[protocol] : undefined;
  if (!record) return "unknown";
  const sinceFailure = now - record.lastFailureAt;
  if (record.failedNodes.length >= BLOCK_AFTER_NODES && sinceFailure < BLOCK_TTL_MS) return "blocked";
  if (record.failedNodes.length && sinceFailure < SUSPECT_TTL_MS) return "suspect";
  if (record.lastSuccessAt > 0 && now - record.lastSuccessAt < WORKS_TTL_MS) return "works";
  return "unknown";
}

export function winnerOf(history: ProtocolHistory, networkKey: string | null): string | null {
  return networkKey ? history.winners[networkKey] ?? null : null;
}

export function recordSuccess(history: ProtocolHistory, networkKey: string, protocol: string, now: number, serverId?: string): ProtocolHistory {
  const next = updateRecord(history, networkKey, protocol, (record) => ({ failedNodes: [], lastFailureAt: record.lastFailureAt, lastSuccessAt: now }));
  return serverId ? { ...next, winners: { ...next.winners, [networkKey]: serverId } } : next;
}

/**
 * A failure counts once per node: a dead server is not a blocked protocol,
 * the same protocol failing on a second server is. Failures older than a day
 * start over.
 */
export function recordFailure(
  history: ProtocolHistory,
  networkKey: string,
  protocol: string,
  nodeId: string,
  now: number,
  failedServerId?: string,
): ProtocolHistory {
  const next = updateRecord(history, networkKey, protocol, (record) => {
    const nodes = now - record.lastFailureAt < BLOCK_TTL_MS ? record.failedNodes : [];
    return { ...record, failedNodes: [...new Set([...nodes, nodeId])].sort().slice(0, MAX_FAILED_NODES), lastFailureAt: now };
  });
  // A server that stopped carrying traffic here no longer names the network's winner.
  if (!failedServerId || next.winners[networkKey] !== failedServerId) return next;
  const winners = { ...next.winners };
  delete winners[networkKey];
  return { ...next, winners };
}

function updateRecord(
  history: ProtocolHistory,
  networkKey: string,
  protocol: string,
  change: (record: ProtocolRecord) => ProtocolRecord,
): ProtocolHistory {
  const current = history.networks.find((item) => item.key === networkKey)?.protocols ?? {};
  const record = change(current[protocol] ?? { failedNodes: [], lastFailureAt: 0, lastSuccessAt: 0 });
  const protocols = Object.fromEntries(Object.entries({ ...current, [protocol]: record }).slice(-MAX_PROTOCOLS));
  // The network moves to the end; the oldest ones are forgotten.
  const networks = [...history.networks.filter((item) => item.key !== networkKey), { key: networkKey, protocols }].slice(-MAX_NETWORKS);
  const kept = new Set(networks.map((item) => item.key));
  const winners = Object.fromEntries(Object.entries(history.winners).filter(([key]) => kept.has(key)));
  return { networks, winners };
}

export function parseHistory(value: unknown): ProtocolHistory {
  if (!isRecord(value) || !Array.isArray(value.networks)) return emptyHistory();
  const networks = value.networks.slice(-MAX_NETWORKS).flatMap((item) => {
    if (!isRecord(item) || typeof item.key !== "string" || !KEY.test(item.key) || !isRecord(item.protocols)) return [];
    const protocols = Object.fromEntries(Object.entries(item.protocols).slice(-MAX_PROTOCOLS).flatMap(([name, record]) => {
      if (!NAME.test(name) || !isRecord(record) || !Array.isArray(record.failedNodes)) return [];
      const failedNodes = record.failedNodes.filter((node): node is string => typeof node === "string" && ID.test(node)).slice(0, MAX_FAILED_NODES);
      const lastFailureAt = finiteTime(record.lastFailureAt);
      const lastSuccessAt = finiteTime(record.lastSuccessAt);
      return [[name, { failedNodes, lastFailureAt, lastSuccessAt }]];
    }));
    return [{ key: item.key, protocols }];
  });
  const kept = new Set(networks.map((item) => item.key));
  const winners = isRecord(value.winners)
    ? Object.fromEntries(Object.entries(value.winners).filter((entry): entry is [string, string] =>
      kept.has(entry[0]) && typeof entry[1] === "string" && ID.test(entry[1])))
    : {};
  return { networks, winners };
}

/** [ProtocolHistory] on disk with the salt that hides the networks' addresses. */
export class ProtocolHistoryStore {
  private history: ProtocolHistory = emptyHistory();
  private salt = "";
  private saving: Promise<void> = Promise.resolve();

  constructor(private readonly path: string) {}

  async load(): Promise<void> {
    try {
      const value: unknown = JSON.parse(await readFile(this.path, "utf8"));
      this.history = parseHistory(isRecord(value) ? value.history : null);
      if (isRecord(value) && typeof value.salt === "string" && /^[0-9a-f]{32}$/.test(value.salt)) this.salt = value.salt;
    } catch {
      this.history = emptyHistory();
    }
    if (!this.salt) this.salt = randomBytes(16).toString("hex");
  }

  current(): ProtocolHistory {
    return this.history;
  }

  update(change: (history: ProtocolHistory) => ProtocolHistory): Promise<void> {
    this.history = change(this.history);
    const snapshot = JSON.stringify({ salt: this.salt, history: this.history });
    this.saving = this.saving.then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.tmp`;
      await writeFile(temporary, snapshot, { mode: 0o600 });
      await rename(temporary, this.path);
    }).catch(() => {});
    return this.saving;
  }

  /**
   * The network this computer is on: its own adapters' subnets and the IPv6
   * prefix the provider assigned. Two homes on the same 192.168.1.0/24
   * without IPv6 look alike; the history then simply covers both.
   */
  networkKey(interfaces: NodeJS.Dict<NetworkInterfaceInfo[]> = networkInterfaces()): string | null {
    const parts = Object.entries(interfaces)
      .filter(([name]) => !VIRTUAL_INTERFACE.test(name))
      .flatMap(([name, entries]) => (entries ?? []).flatMap((entry) => {
        if (entry.internal) return [];
        if (entry.family === "IPv4") {
          if (entry.address.startsWith("169.254.") || entry.address.startsWith("198.18.")) return [];
          return [`${name}|${ipv4Network(entry.address, entry.netmask)}/${entry.netmask}`];
        }
        // Link-local, unique-local and temporary suffixes say nothing about the provider.
        if (!/^[23]/.test(entry.address)) return [];
        return [`${name}|${entry.address.split(":").slice(0, 4).join(":")}::/64`];
      }));
    if (!parts.length || !this.salt) return null;
    const digest = createHash("sha256").update(`levik-net-v1|${this.salt}|${[...new Set(parts)].sort().join(",")}`).digest("hex");
    return digest.slice(0, 16);
  }
}

const VIRTUAL_INTERFACE = /^(utun|tun|tap|wg|ppp|ipsec|lo|gif|stf|awdl|llw|anpi|bridge|vmnet|vboxnet|virbr|docker|br-|veth|zt|tailscale|nordlynx)|levik|wintun|loopback|vethernet|virtualbox|vmware|hyper-v/i;

function ipv4Network(address: string, netmask: string): string {
  const octets = address.split(".").map(Number);
  const mask = netmask.split(".").map(Number);
  return octets.map((octet, index) => octet & (mask[index] ?? 0)).join(".");
}

/** Servers and protocols tried since the user connected; a few rungs at most, so a bad network cannot loop. */
export class SmartLadder {
  private readonly ids = new Set<string>();
  private readonly protocols = new Set<string>();
  private climbs = 0;

  constructor(private readonly maxClimbs = 3) {}

  tried(id: string, protocol: string): void {
    this.ids.add(id);
    this.protocols.add(protocol);
  }

  climbed(): void {
    this.climbs += 1;
  }

  exhausted(): boolean {
    return this.climbs >= this.maxClimbs;
  }

  triedIds(): ReadonlySet<string> {
    return this.ids;
  }

  triedProtocols(): ReadonlySet<string> {
    return this.protocols;
  }

  reset(): void {
    this.ids.clear();
    this.protocols.clear();
    this.climbs = 0;
  }
}

/**
 * Notices a tunnel that sends but hardly receives: operators that throttle a
 * protocol freeze each connection after about 16 KB, so pages hang while the
 * handshake probes still pass. Ordinary use downloads more than it uploads.
 * A hit only asks for a traffic check, so a false alarm costs 64 KB.
 */
export class TunnelFreezeDetector {
  private samples: Array<{ at: number; rx: number; tx: number }> = [];
  private lastAlarmAt: number | null = null;

  constructor(
    private readonly windowMs = 12_000,
    private readonly minUploadBytes = 24 * 1024,
    private readonly cooldownMs = 2 * 60_000,
  ) {}

  /** Totals since the connection started; true when the last window looks frozen. */
  record(rx: number, tx: number, now: number): boolean {
    const last = this.samples[this.samples.length - 1];
    if (last && (rx < last.rx || tx < last.tx)) this.samples = [];
    this.samples.push({ at: now, rx, tx });
    while (this.samples.length > 2 && now - (this.samples[1]?.at ?? now) >= this.windowMs) this.samples.shift();
    const first = this.samples[0];
    if (!first || now - first.at < this.windowMs) return false;
    const received = rx - first.rx;
    const sent = tx - first.tx;
    // Frozen when less than half as much comes back as goes out.
    if (sent < this.minUploadBytes || received * 2 >= sent) return false;
    if (this.lastAlarmAt !== null && now - this.lastAlarmAt < this.cooldownMs) return false;
    this.lastAlarmAt = now;
    this.samples = [];
    return true;
  }

  reset(): void {
    this.samples = [];
    this.lastAlarmAt = null;
  }
}

function finiteTime(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
