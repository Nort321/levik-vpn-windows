import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { GAMES } from "../../shared/games";

export type InstalledGame = { gameId: string; launcher: "steam" | "riot" | "epic" };
const STEAM_IDS: Readonly<Record<string, string>> = { "730": "cs2", "570": "dota2", "1172470": "apex", "578080": "pubg", "252950": "rocket", "1938090": "warzone", "2357570": "overwatch" };
const FILE_LIMIT = 1024 * 1024;
const execute = promisify(execFile);
type LauncherRoots = { steam: string[]; riot: string[]; epic: string[] };

async function installedGameRoots(): Promise<LauncherRoots> {
  const roots: LauncherRoots = {
    steam: [join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Steam")],
    riot: ["C:\\Riot Games", join(process.env.ProgramData || "C:\\ProgramData", "Riot Games")],
    epic: [join(process.env.ProgramData || "C:\\ProgramData", "Epic", "EpicGamesLauncher", "Data", "Manifests")],
  };
  if (process.platform === "win32") {
    try {
      const { stdout } = await execute("reg.exe", ["QUERY", "HKCU\\Software\\Valve\\Steam", "/v", "SteamPath"], {
        windowsHide: true, timeout: 3_000, maxBuffer: 16 * 1024,
      });
      const path = stdout.match(/SteamPath\s+REG_SZ\s+([^\r\n]+)/i)?.[1]?.trim();
      if (path && /^[A-Za-z]:[\\/]/.test(path) && !/[\u0000-\u001f]/.test(path)) roots.steam.unshift(path);
    } catch { /* Standard installation root remains usable without registry access. */ }
  }
  return roots;
}

async function readSmall(path: string): Promise<string | null> {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size > FILE_LIMIT) return null;
    return await readFile(path, "utf8");
  } catch { return null; }
}

export function steamLibraryPaths(text: string): string[] {
  return [...text.matchAll(/"path"\s*"((?:\\.|[^"\\])*)"/gi)].map((match) => match[1]!.replaceAll("\\\\", "\\"))
    .filter((path) => /^[A-Za-z]:[\\/]/.test(path) && !/[\u0000-\u001f]/.test(path)).slice(0, 32);
}

export function gameFromManifest(text: string, launcher: "steam" | "epic"): InstalledGame | null {
  if (text.length > FILE_LIMIT) return null;
  if (launcher === "steam") {
    const id = text.match(/"appid"\s*"(\d+)"/i)?.[1];
    return id && STEAM_IDS[id] ? { gameId: STEAM_IDS[id], launcher } : null;
  }
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || !("DisplayName" in value) || typeof value.DisplayName !== "string") return null;
    const normalized = value.DisplayName.toLowerCase().replace(/[^a-z0-9]/g, "");
    const game = GAMES.find((entry) => entry.name.toLowerCase().replace(/[^a-z0-9]/g, "") === normalized);
    return game ? { gameId: game.id, launcher } : null;
  } catch { return null; }
}

/** Launchers' manifests only; no executable, launcher, account or registry writes. */
export async function discoverInstalledGames(
  suppliedRoots?: LauncherRoots,
): Promise<InstalledGame[]> {
  const roots = suppliedRoots ?? await installedGameRoots();
  const found = new Map<string, InstalledGame>();
  const libraries = new Set(roots.steam);
  for (const root of roots.steam) {
    const folders = await readSmall(join(root, "steamapps", "libraryfolders.vdf"));
    if (folders) for (const library of steamLibraryPaths(folders)) libraries.add(library);
  }
  for (const library of [...libraries].slice(0, 32)) {
    const directory = join(library, "steamapps");
    const names = await readdir(directory).catch(() => [] as string[]);
    for (const name of names.filter((entry) => /^appmanifest_\d+\.acf$/i.test(entry)).slice(0, 512)) {
      const text = await readSmall(join(directory, name));
      const game = text && gameFromManifest(text, "steam");
      if (game) found.set(game.gameId, game);
    }
  }
  for (const directory of roots.epic) {
    const names = await readdir(directory).catch(() => [] as string[]);
    for (const name of names.filter((entry) => /^[^\\/]+\.item$/i.test(entry)).slice(0, 512)) {
      const text = await readSmall(join(directory, name));
      const game = text && gameFromManifest(text, "epic");
      if (game) found.set(game.gameId, game);
    }
  }
  for (const directory of roots.riot) {
    // RiotClientInstalls stores known installation roots; do not expose them or
    // read launcher account/session stores. Product metadata contains no tokens.
    const text = await readSmall(join(directory, "RiotClientInstalls.json"));
    if (text) {
      try {
        const value: unknown = JSON.parse(text);
        if (value && typeof value === "object" && "associated_client" in value && value.associated_client && typeof value.associated_client === "object") {
          for (const path of Object.keys(value.associated_client)) {
            if (/VALORANT/i.test(path)) found.set("valorant", { gameId: "valorant", launcher: "riot" });
            if (/League of Legends/i.test(path)) found.set("lol", { gameId: "lol", launcher: "riot" });
          }
        }
      } catch { /* A launcher may be updating its manifest. */ }
    }
    for (const [gameId, product] of [["valorant", "VALORANT"], ["lol", "League of Legends"]] as const) {
      if ((await stat(join(directory, product)).catch(() => null))?.isDirectory()) found.set(gameId, { gameId, launcher: "riot" });
    }
  }
  return [...found.values()];
}
