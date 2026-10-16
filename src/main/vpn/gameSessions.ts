import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { GameMatchReport, GameSessionRecord } from "../../shared/contracts";

export const GAME_SESSIONS_MAX_ENTRIES = 30;
export const GAME_SESSIONS_MAX_BYTES = 128 * 1024;
/** Shorter connections are menus, voice or reconnect blips, not a match. */
export const GAME_SESSION_MIN_MS = 20_000;
const LIVE_WRITE_MS = 30_000;

const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const latency = (value: unknown): value is number | null => value === null || (typeof value === "number" && Number.isFinite(value) && value >= 0 && value < 100_000);
const label = (value: unknown, max: number): value is string => typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f]/.test(value);

function parseRecord(value: unknown): GameSessionRecord | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.id !== "string" || !/^\d{1,16}-[a-z0-9-]{1,48}$/.test(v.id) || typeof v.gameId !== "string" || !/^[a-z0-9-]{1,48}$/.test(v.gameId)
    || !count(v.startedAt) || !count(v.endedAt) || !count(v.durationMs) || typeof v.live !== "boolean"
    || !latency(v.averageRttMs) || !latency(v.p95RttMs) || !latency(v.minRttMs) || !latency(v.jitterMs) || typeof v.lowerBound !== "boolean"
    || !(v.lossPercent === null || (typeof v.lossPercent === "number" && Number.isFinite(v.lossPercent) && v.lossPercent >= 0 && v.lossPercent <= 100))
    || !(v.lostPackets === null || count(v.lostPackets)) || !count(v.rescuedPackets) || !count(v.recoveredPackets)
    || !count(v.receivedPackets) || !count(v.sentPackets) || !(v.region === null || label(v.region, 80)) || !label(v.exitName, 80)
    || typeof v.direct !== "boolean" || !count(v.pathCount) || !Array.isArray(v.paths) || v.paths.length > 16) return null;
  const paths: GameSessionRecord["paths"] = [];
  for (const path of v.paths) {
    if (!path || typeof path !== "object" || !label((path as Record<string, unknown>).name, 160) || !count((path as Record<string, unknown>).packets)) return null;
    paths.push({ name: (path as { name: string }).name, packets: (path as { packets: number }).packets });
  }
  return { id: v.id, gameId: v.gameId, startedAt: v.startedAt, endedAt: v.endedAt, durationMs: v.durationMs, live: v.live,
    averageRttMs: v.averageRttMs, p95RttMs: v.p95RttMs, minRttMs: v.minRttMs, jitterMs: v.jitterMs, lowerBound: v.lowerBound,
    lossPercent: v.lossPercent, lostPackets: v.lostPackets, rescuedPackets: v.rescuedPackets, recoveredPackets: v.recoveredPackets,
    receivedPackets: v.receivedPackets, sentPackets: v.sentPackets, region: v.region, exitName: v.exitName, direct: v.direct,
    pathCount: v.pathCount, paths };
}

export function parseGameSessions(value: unknown): GameSessionRecord[] {
  if (!Array.isArray(value)) return [];
  return value.slice(-GAME_SESSIONS_MAX_ENTRIES).flatMap((entry) => { const record = parseRecord(entry); return record ? [record] : []; });
}

/** Turns a data-plane report into a stored record. `pathName` resolves a route to a server
 * name; the game server's address is never stored. */
export function sessionRecord(report: GameMatchReport, live: boolean,
  pathName: (routeIndex: number, entryNodeId: string) => string): GameSessionRecord | null {
  const gameId = report.gameId ?? "custom";
  const record = parseRecord({
    id: `${report.startedAt}-${gameId}`, gameId, startedAt: report.startedAt, endedAt: report.endedAt,
    durationMs: Math.max(0, report.durationMs), live,
    averageRttMs: report.averageRttMs, p95RttMs: report.p95RttMs, minRttMs: report.minRttMs ?? null, jitterMs: report.jitterMs,
    lowerBound: report.lowerBound === true, lossPercent: report.lossPercent === null ? null : Math.min(100, Math.max(0, report.lossPercent)),
    lostPackets: report.lostPackets ?? null, rescuedPackets: report.rescuedPackets, recoveredPackets: report.recoveredPackets ?? 0,
    receivedPackets: report.receivedPackets, sentPackets: report.sentPackets ?? 0, region: report.server?.region ?? null,
    exitName: (report.exitName ?? "Игровой узел").slice(0, 80), direct: report.exitId === "direct",
    pathCount: report.protection?.pathCount ?? 0,
    paths: (report.paths ?? []).slice(0, 16).map((path) => ({ name: pathName(path.routeIndex, path.entryNodeId).slice(0, 160), packets: path.packets })),
  });
  return record && record.durationMs >= GAME_SESSION_MIN_MS ? record : null;
}

/** Local userData only: the last matches with their quality, never uploaded. */
export class GameSessions {
  private entries: GameSessionRecord[] = [];
  private writing: Promise<void> = Promise.resolve();
  private writtenAt = 0;
  constructor(private readonly path: string) {}
  async load(): Promise<void> {
    try {
      if ((await stat(this.path)).size > GAME_SESSIONS_MAX_BYTES) return;
      // A connection still running when the app closed is history now.
      this.entries = parseGameSessions(JSON.parse(await readFile(this.path, "utf8"))).map((entry) => ({ ...entry, live: false }));
    } catch { this.entries = []; }
  }
  /** Newest first. */
  snapshot(): GameSessionRecord[] { return [...this.entries].reverse().map((entry) => ({ ...entry, paths: entry.paths.map((path) => ({ ...path })) })); }
  /** Applies the running and finished connections of one tick; true when anything changed. */
  update(records: GameSessionRecord[], now = Date.now()): boolean {
    const liveIds = new Set(records.filter((record) => record.live).map((record) => record.id));
    let changed = false; let final = false;
    this.entries = this.entries.map((entry) => {
      if (!entry.live || liveIds.has(entry.id) || records.some((record) => record.id === entry.id)) return entry;
      changed = final = true; return { ...entry, live: false };
    });
    for (const record of records) {
      const index = this.entries.findIndex((entry) => entry.id === record.id);
      const previous = this.entries[index];
      // A finished report never turns back into a running one.
      if (previous && !previous.live && record.live) continue;
      if (previous && JSON.stringify(previous) === JSON.stringify(record)) continue;
      changed = true; if (!record.live || !previous) final = true;
      if (index < 0) this.entries.push(record); else this.entries[index] = record;
    }
    if (!changed) return false;
    this.entries.sort((a, b) => a.startedAt - b.startedAt);
    this.entries = this.entries.slice(-GAME_SESSIONS_MAX_ENTRIES);
    if (final || now - this.writtenAt >= LIVE_WRITE_MS) void this.persist(now).catch(() => {});
    return true;
  }
  private persist(now: number): Promise<void> {
    this.writtenAt = now;
    const json = JSON.stringify(this.entries);
    if (Buffer.byteLength(json) > GAME_SESSIONS_MAX_BYTES) return Promise.resolve();
    this.writing = this.writing.catch(() => {}).then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      await writeFile(`${this.path}.tmp`, json, { mode: 0o600 });
      await rename(`${this.path}.tmp`, this.path);
    });
    return this.writing;
  }
  flush(): Promise<void> { return this.persist(Date.now()); }
}
