import type { WindowsProcess } from "./contracts";

export function normalizeExecutableName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim();
  return /^[^<>:"/\\|?*\u0000-\u001f]{1,251}\.exe$/i.test(name) ? name : null;
}

export function normalizeProcessSelection(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names = new Map<string, string>();
  for (const item of value) {
    const name = normalizeExecutableName(item);
    if (name && !names.has(name.toLowerCase())) names.set(name.toLowerCase(), name);
  }
  return [...names.values()].slice(0, 200);
}

// Keep groups narrow: selecting a game must not bypass every game using its
// launcher, or unrelated traffic owned by Steam, Battle.net, Agent or svchost.
const COMPANION_GROUPS = [
  { triggers: ["overwatch.exe", "overwatch launcher.exe"], names: ["Overwatch.exe", "Overwatch Launcher.exe", "VivoxVoiceService.exe"] },
  { triggers: ["valorant.exe", "valorant-win64-shipping.exe"], names: ["VALORANT.exe", "VALORANT-Win64-Shipping.exe"] },
];

export function resolveProcessCompanions(selected: readonly string[]): string[] {
  const names = normalizeProcessSelection(selected);
  const keys = new Set(names.map((name) => name.toLowerCase()));
  for (const group of COMPANION_GROUPS) {
    if (!group.triggers.some((name) => keys.has(name))) continue;
    for (const name of group.names) {
      if (!keys.has(name.toLowerCase())) {
        keys.add(name.toLowerCase());
        names.push(name);
      }
    }
  }
  return names;
}

export function mergeProcessList(processes: readonly WindowsProcess[], selected: readonly string[]): WindowsProcess[] {
  const entries = new Map<string, WindowsProcess>();
  for (const item of processes) {
    const key = item.name.toLowerCase();
    const previous = entries.get(key);
    entries.set(key, {
      name: item.running === true ? item.name : previous?.name ?? item.name,
      path: item.path ?? previous?.path ?? null,
      running: item.running === true || previous?.running === true ? true : item.running ?? previous?.running ?? null,
    });
  }
  for (const name of resolveProcessCompanions(selected)) {
    if (!entries.has(name.toLowerCase())) entries.set(name.toLowerCase(), { name, path: null, running: false });
  }
  return [...entries.values()];
}

export function sortProcessList(processes: readonly WindowsProcess[], selected: readonly string[]): WindowsProcess[] {
  const keys = new Set(resolveProcessCompanions(selected).map((name) => name.toLowerCase()));
  return [...processes].sort((left, right) => Number(keys.has(right.name.toLowerCase())) - Number(keys.has(left.name.toLowerCase()))
    || left.name.localeCompare(right.name, "ru", { sensitivity: "base" }));
}

export function processStatusLabel(process: WindowsProcess): string {
  if (process.running === true) return process.path ?? "Запущено · путь недоступен";
  if (process.running === false) return "Процесс сейчас не запущен";
  return process.path ?? "Состояние процесса неизвестно";
}
