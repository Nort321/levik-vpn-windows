import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GAME_SESSIONS_MAX_ENTRIES, GameSessions, parseGameSessions, sessionRecord } from "../src/main/vpn/gameSessions";
import type { GameMatchReport } from "../src/shared/contracts";

const report = (patch: Partial<GameMatchReport> = {}): GameMatchReport => ({
  startedAt: 1_000_000, endedAt: 1_600_000, durationMs: 600_000, averageRttMs: 42.4, p95RttMs: 58, jitterMs: 3, lossPercent: 0.5,
  rescuedPackets: 12, receivedPackets: 30_000, approximate: true, gameId: "valorant", exitId: "node-spb", exitName: "SPB",
  server: { address: "203.0.113.7", port: 7000, region: "DE" }, protection: { enabled: true, pathCount: 3 },
  minRttMs: 37, sentPackets: 31_000, lostPackets: 150, recoveredPackets: 4,
  paths: [{ routeIndex: 1, entryNodeId: "node-spb", packets: 20_000 }, { routeIndex: 0, entryNodeId: "node-msk", packets: 9_996 }], ...patch,
});
const names = (routeIndex: number, entryNodeId: string): string => `${entryNodeId}#${routeIndex}`;
let directory: string | null = null;
afterEach(async () => { if (directory) await rm(directory, { recursive: true, force: true }); directory = null; });

describe("Game session history", () => {
  it("keeps quality and per-path packets but never the game server's address", () => {
    const record = sessionRecord(report(), false, names)!;
    expect(record).toMatchObject({ id: "1000000-valorant", gameId: "valorant", live: false, averageRttMs: 42.4, minRttMs: 37, p95RttMs: 58,
      lossPercent: 0.5, lostPackets: 150, rescuedPackets: 12, recoveredPackets: 4, sentPackets: 31_000, receivedPackets: 30_000,
      region: "DE", exitName: "SPB", direct: false, pathCount: 3,
      paths: [{ name: "node-spb#1", packets: 20_000 }, { name: "node-msk#0", packets: 9_996 }] });
    expect(JSON.stringify(record)).not.toContain("203.0.113.7");
  });
  it("skips blips shorter than a match and rejects malformed stored entries", () => {
    expect(sessionRecord(report({ durationMs: 5_000, endedAt: 1_005_000 }), true, names)).toBeNull();
    const valid = sessionRecord(report(), false, names)!;
    expect(parseGameSessions([valid, { ...valid, id: "../x" }, { ...valid, lossPercent: 400 }, { ...valid, paths: [{ name: "\u0000", packets: 1 }] }, null]))
      .toEqual([valid]);
  });
  it("updates a running match, finishes it when it disappears and never reopens a finished one", async () => {
    directory = await mkdtemp(join(tmpdir(), "levik-sessions-"));
    const store = new GameSessions(join(directory, "sessions.json"));
    const live = sessionRecord(report({ durationMs: 60_000, endedAt: 1_060_000 }), true, names)!;
    expect(store.update([live], 1)).toBe(true);
    expect(store.update([live], 2)).toBe(false);
    const longer = sessionRecord(report({ durationMs: 120_000, endedAt: 1_120_000 }), true, names)!;
    expect(store.update([longer], 3)).toBe(true);
    expect(store.snapshot()).toMatchObject([{ live: true, durationMs: 120_000 }]);
    expect(store.update([], 4)).toBe(true);
    expect(store.snapshot()).toMatchObject([{ live: false, durationMs: 120_000 }]);
    const final = sessionRecord(report(), false, names)!;
    store.update([final], 5);
    store.update([live], 6);
    expect(store.snapshot()).toMatchObject([{ live: false, durationMs: 600_000 }]);
    await store.flush();
    const reloaded = new GameSessions(join(directory, "sessions.json")); await reloaded.load();
    expect(reloaded.snapshot()).toEqual(store.snapshot());
  });
  it("shows newest first, keeps a bounded history and treats a match running at exit as finished", async () => {
    directory = await mkdtemp(join(tmpdir(), "levik-sessions-"));
    const path = join(directory, "sessions.json");
    const store = new GameSessions(path);
    for (let index = 0; index < GAME_SESSIONS_MAX_ENTRIES + 5; index++) {
      store.update([sessionRecord(report({ startedAt: 1_000_000 + index * 1_000_000, endedAt: 1_600_000 + index * 1_000_000 }), index === GAME_SESSIONS_MAX_ENTRIES + 4, names)!], index);
    }
    const snapshot = store.snapshot();
    expect(snapshot).toHaveLength(GAME_SESSIONS_MAX_ENTRIES);
    expect(snapshot[0]!.startedAt).toBeGreaterThan(snapshot[1]!.startedAt);
    await store.flush();
    const stored = JSON.parse(await readFile(path, "utf8")) as Array<{ live: boolean }>;
    expect(stored.at(-1)?.live).toBe(true);
    const reloaded = new GameSessions(path); await reloaded.load();
    expect(reloaded.snapshot().every((entry) => !entry.live)).toBe(true);
    await writeFile(path, "{broken");
    const broken = new GameSessions(path); await broken.load();
    expect(broken.snapshot()).toEqual([]);
  });
});
