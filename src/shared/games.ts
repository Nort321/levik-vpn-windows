import { normalizeProcessSelection } from "./processes";
import type { AppSettings } from "./contracts";

const CATALOG = [
  { id: "valorant", name: "VALORANT", genre: "Тактический шутер", initials: "VA", processes: ["VALORANT.exe", "VALORANT-Win64-Shipping.exe"] },
  { id: "cs2", name: "Counter-Strike 2", genre: "Тактический шутер", initials: "CS", processes: ["cs2.exe"] },
  { id: "dota2", name: "Dota 2", genre: "MOBA", initials: "D2", processes: ["dota2.exe"] },
  { id: "lol", name: "League of Legends", genre: "MOBA", initials: "LoL", processes: ["League of Legends.exe"] },
  { id: "overwatch", name: "Overwatch 2", genre: "Командный шутер", initials: "OW", processes: ["Overwatch.exe"] },
  { id: "apex", name: "Apex Legends", genre: "Королевская битва", initials: "AP", processes: ["r5apex.exe", "r5apex_dx12.exe"] },
  { id: "fortnite", name: "Fortnite", genre: "Королевская битва", initials: "FN", processes: ["FortniteClient-Win64-Shipping.exe"] },
  { id: "pubg", name: "PUBG: Battlegrounds", genre: "Королевская битва", initials: "PG", processes: ["TslGame.exe"] },
  // Party/lobby traffic is peer-to-peer: every destination must see one public IP:port.
  { id: "warzone", name: "Call of Duty", genre: "Шутер", initials: "CoD", processes: ["cod.exe"], exitScope: "socket" },
  { id: "rocket", name: "Rocket League", genre: "Спорт", initials: "RL", processes: ["RocketLeague.exe"] },
  { id: "tarkov", name: "Escape from Tarkov", genre: "Тактический шутер", initials: "ET", processes: ["EscapeFromTarkov.exe"] },
  { id: "wot", name: "Мир танков", genre: "Командные сражения", initials: "MT", processes: ["WorldOfTanks.exe"] },
] as const;

/** flow: exit per destination; socket: one exit per game socket (P2P/NAT punching);
 * session: one exit for the whole game process. */
export type GameExitScope = "flow" | "socket" | "session";
export const GAMES = CATALOG.map((game) => ({ ...game, exitScope: ("exitScope" in game ? game.exitScope : "flow") as GameExitScope }));

/** Unknown/custom games use per-flow selection; individual compatibility exceptions are explicit.
 * The strictest scope among the selected games applies to the shared bridge. */
export function gameExitScope(settings: AppSettings): GameExitScope {
  const scopes = new Set(GAMES.filter((game) => settings.gameIds?.includes(game.id)).map((game) => game.exitScope));
  return scopes.has("session") ? "session" : scopes.has("socket") ? "socket" : "flow";
}

export function normalizeGameIds(value: unknown): string[] {
  return Array.isArray(value) ? GAMES.filter((game) => value.includes(game.id)).map((game) => game.id) : [];
}

export function gameProcesses(settings: AppSettings): string[] {
  const ids = normalizeGameIds(settings.gameIds);
  // Launchers, anti-cheat services and shared voice clients keep ordinary VPN.
  return normalizeProcessSelection([
    ...GAMES.filter((game) => ids.includes(game.id)).flatMap((game) => [...game.processes]),
    ...normalizeProcessSelection(settings.gameProcesses),
  ]);
}
