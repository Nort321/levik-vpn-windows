import { describe, expect, it } from "vitest";
import { parseWindowsProcesses, windowsProcessFromPath } from "../src/main/windows/processes";
import { mergeProcessList, normalizeExecutableName, normalizeProcessSelection, processStatusLabel, resolveProcessCompanions, sortProcessList } from "../src/shared/processes";

describe("Windows process split tunneling", () => {
  it("keeps the executable extension required by Xray", () => {
    expect(windowsProcessFromPath("C:\\Program Files\\Telegram Desktop\\Telegram.exe")).toEqual({
      name: "Telegram.exe",
      path: "C:/Program Files/Telegram Desktop/Telegram.exe",
      running: null,
    });
  });

  it("rejects non-executable selections", () => {
    expect(windowsProcessFromPath("C:\\Temp\\notes.txt")).toBeNull();
  });

  it("accepts spaces, Unicode and uppercase extensions without changing display casing", () => {
    expect(normalizeProcessSelection([" Battle.net Helper.exe ", "Игровой Клиент.EXE", "battle.NET HELPER.EXE", null, 123])).toEqual([
      "Battle.net Helper.exe", "Игровой Клиент.EXE",
    ]);
    expect(windowsProcessFromPath("C:\\Games\\Overwatch Launcher.exe")?.name).toBe("Overwatch Launcher.exe");
    expect(normalizeProcessSelection(null)).toEqual([]);
  });

  it.each(["../game.exe", "C:\\game.exe", "self/", "*.exe", "game\u0000.exe", "game.exe:stream", "game.txt", "", ".exe", "a".repeat(252) + ".exe"])("rejects invalid executable name %j", (name) => {
    expect(normalizeExecutableName(name)).toBeNull();
  });

  it("deduplicates selections before enforcing the limit", () => {
    const names = Array.from({ length: 201 }, (_, index) => `Game${index}.exe`);
    expect(normalizeProcessSelection([...names, ...names])).toHaveLength(200);
  });

  it("lists active processes without requiring a readable path and prefers the readable duplicate", () => {
    const processes = parseWindowsProcesses(JSON.stringify([
      { Name: "Overwatch.exe", Path: null },
      { Name: "overwatch.exe", Path: "C:\\Games\\Overwatch.exe" },
      { Name: "VivoxVoiceService.exe", Path: null },
      { Name: "Игровой Клиент.EXE", Path: "C:\\Игры\\Игровой Клиент.EXE" },
      { Name: 32 }, null,
    ]));
    expect(processes).toHaveLength(3);
    expect(processes.find((item) => item.name === "Overwatch.exe")).toEqual({
      name: "Overwatch.exe", path: "C:/Games/Overwatch.exe", running: true,
    });
    const voice = processes.find((item) => item.name === "VivoxVoiceService.exe")!;
    expect(processStatusLabel(voice)).toBe("Запущено · путь недоступен");
    expect(processes.every((item) => item.running)).toBe(true);
  });

  it("handles PowerShell fallback names, single records, BOM and empty results", () => {
    expect(parseWindowsProcesses('\uFEFF{"Name":"Battle.net Helper","Path":null}')).toEqual([
      { name: "Battle.net Helper.exe", path: null, running: true },
    ]);
    for (const result of ["", "  ", "null", "[]"]) expect(parseWindowsProcesses(result)).toEqual([]);
    expect(() => parseWindowsProcesses("invalid JSON")).toThrow();
  });

  it("expands game companions once without selecting unrelated launchers or shared Windows services", () => {
    expect(resolveProcessCompanions(["overwatch.exe", "Chrome.exe", "VivoxVoiceService.EXE"])).toEqual([
      "overwatch.exe", "Chrome.exe", "VivoxVoiceService.EXE", "Overwatch Launcher.exe",
    ]);
    expect(resolveProcessCompanions(["Overwatch Launcher.exe"])).toEqual([
      "Overwatch Launcher.exe", "Overwatch.exe", "VivoxVoiceService.exe",
    ]);
    expect(resolveProcessCompanions(["VALORANT.exe"])).toEqual(["VALORANT.exe", "VALORANT-Win64-Shipping.exe"]);
    for (const name of ["Agent.exe", "Battle.net.exe", "Steam.exe", "svchost.exe", "VivoxVoiceService.exe"]) {
      expect(resolveProcessCompanions([name])).toEqual([name]);
    }
  });

  it("merges saved lowercase selections with running names and pins all selected rows", () => {
    const running = parseWindowsProcesses(JSON.stringify([{ Name: "Zulu.exe" }, { Name: "Alpha.exe" }, { Name: "Overwatch.exe" }]));
    const selected = ["zulu.exe", "overwatch.exe", "Missing.exe"];
    const items = mergeProcessList(running, selected);
    expect(items.filter((item) => item.name.toLowerCase() === "overwatch.exe")).toHaveLength(1);
    expect(items.find((item) => item.name === "Overwatch.exe")?.running).toBe(true);
    expect(processStatusLabel(items.find((item) => item.name === "Missing.exe")!)).toBe("Процесс сейчас не запущен");
    const sorted = sortProcessList(items, selected);
    expect(sorted.at(-1)?.name).toBe("Alpha.exe");
    expect(sorted.slice(0, -1).map((item) => item.name)).toEqual(["Missing.exe", "Overwatch Launcher.exe", "Overwatch.exe", "VivoxVoiceService.exe", "Zulu.exe"]);
    expect(sortProcessList(items, []).at(0)?.name).toBe("Alpha.exe");
    expect(running).toHaveLength(3);
  });

  it("does not infer running status from a browsed executable path", () => {
    const browsed = windowsProcessFromPath("C:\\Games\\Game.exe")!;
    expect(browsed.running).toBeNull();
    expect(processStatusLabel({ ...browsed, path: null })).toBe("Состояние процесса неизвестно");
    const active = { name: "game.exe", path: null, running: true };
    expect(mergeProcessList([active, browsed], [])[0]).toMatchObject({ running: true, path: browsed.path });
    expect(mergeProcessList([browsed, active], [])[0]).toMatchObject({ running: true, path: browsed.path });
  });
});
