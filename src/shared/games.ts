import { normalizeProcessSelection } from "./processes";
import type { AppSettings } from "./contracts";

const CATALOG = [
  // Riot: match servers are UDP 7000-8000 and 8180-8181. Voice (UDP 27016-27024, 54000-54012
  // and TCP) keeps ordinary VPN like the game's login: its server expects one address for both.
  { id: "valorant", name: "VALORANT", genre: "Тактический шутер", initials: "VA", processes: ["VALORANT.exe", "VALORANT-Win64-Shipping.exe"], matchUdpPorts: "7000-8000,8180-8181" },
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

/** A game's processes and, when known, the only UDP ports of its matches: the rest of
 * its UDP (voice, party, store) keeps ordinary VPN, as it does with Game turned off. */
export interface GameRouteGroup { processes: string[]; matchUdpPorts: string | null }

/** Games with known match ports first, each on its own; every other selected game and
 * custom process shares one group whose whole IPv4 UDP takes the game path. */
export function gameRouteGroups(settings: AppSettings): GameRouteGroup[] {
  const ids = normalizeGameIds(settings.gameIds);
  const ported = GAMES.filter((game) => ids.includes(game.id)).flatMap((game) => "matchUdpPorts" in game
    ? [{ processes: normalizeProcessSelection([...game.processes]), matchUdpPorts: game.matchUdpPorts }] : []);
  const taken = new Set(ported.flatMap((group) => group.processes.map((name) => name.toLowerCase())));
  const rest = gameProcesses(settings).filter((name) => !taken.has(name.toLowerCase()));
  return [...ported, ...(rest.length ? [{ processes: rest, matchUdpPorts: null }] : [])];
}

export function gameProcesses(settings: AppSettings): string[] {
  const ids = normalizeGameIds(settings.gameIds);
  // Launchers, anti-cheat services and shared voice clients keep ordinary VPN.
  return normalizeProcessSelection([
    ...GAMES.filter((game) => ids.includes(game.id)).flatMap((game) => [...game.processes]),
    ...normalizeProcessSelection(settings.gameProcesses),
  ]);
}
