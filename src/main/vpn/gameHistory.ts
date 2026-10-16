import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isIPv4 } from "node:net";

export const GAME_HISTORY_MAX_ENTRIES = 512;
export const GAME_HISTORY_MAX_BYTES = 256 * 1024;
export interface GameHistoryEntry { gameId: string; subnet: string; region: string | null; nodeId: string; updatedAt: number }

export function parseGameHistory(value: unknown): GameHistoryEntry[] {
  if (!Array.isArray(value)) return [];
  return value.slice(-GAME_HISTORY_MAX_ENTRIES).flatMap((entry): GameHistoryEntry[] => {
    if (!entry || typeof entry !== "object" || !("gameId" in entry) || !("subnet" in entry) || !("region" in entry)
      || !("nodeId" in entry) || !("updatedAt" in entry) || typeof entry.gameId !== "string" || !/^[a-z0-9-]{1,48}$/.test(entry.gameId)
      || typeof entry.subnet !== "string" || !entry.subnet.endsWith(".0/24") || !isIPv4(entry.subnet.slice(0, -3))
      || typeof entry.nodeId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(entry.nodeId)
      || (entry.region !== null && (typeof entry.region !== "string" || entry.region.length > 80 || /[\u0000-\u001f]/.test(entry.region)))
      || typeof entry.updatedAt !== "number" || !Number.isSafeInteger(entry.updatedAt) || entry.updatedAt < 0) return [];
    return [{ gameId: entry.gameId, subnet: entry.subnet, region: entry.region, nodeId: entry.nodeId, updatedAt: entry.updatedAt }];
  });
}

/** Local userData only. No account identifiers, full destination IPs or uploads. */
export class GameHistory {
  private entries: GameHistoryEntry[] = [];
  private writing: Promise<void> = Promise.resolve();
  constructor(private readonly path: string) {}
  async load(): Promise<void> {
    try {
      if ((await stat(this.path)).size > GAME_HISTORY_MAX_BYTES) return;
      this.entries = parseGameHistory(JSON.parse(await readFile(this.path, "utf8")));
    } catch { this.entries = []; }
  }
  snapshot(gameId?: string): GameHistoryEntry[] { return this.entries.filter((entry) => !gameId || entry.gameId === gameId).map((entry) => ({ ...entry })); }
  preferredExit(gameId: string): string | null { return this.entries.filter((entry) => entry.gameId === gameId).at(-1)?.nodeId ?? null; }
  record(gameId: string, address: string, region: string | undefined, nodeId: string, now = Date.now()): Promise<void> {
    if (!isIPv4(address)) return Promise.resolve();
    const subnet = `${address.split(".").slice(0, 3).join(".")}.0/24`;
    const parsed = parseGameHistory([{ gameId, subnet, region: region ?? null, nodeId, updatedAt: now }]);
    if (!parsed.length) return Promise.resolve();
    this.entries = [...this.entries.filter((entry) => entry.gameId !== gameId || entry.subnet !== subnet), parsed[0]!].slice(-GAME_HISTORY_MAX_ENTRIES);
    const json = JSON.stringify(this.entries);
    if (Buffer.byteLength(json) > GAME_HISTORY_MAX_BYTES) return Promise.resolve();
    this.writing = this.writing.catch(() => {}).then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      await writeFile(`${this.path}.tmp`, json, { mode: 0o600 });
      await rename(`${this.path}.tmp`, this.path);
    });
    return this.writing;
  }
}
