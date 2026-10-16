import { describe, expect, it } from "vitest";
import { elevatedStartScript, hasElevatedLevel, powerShellString, windowsArgument } from "../src/main/windows/elevation";
import { closeProcessesScript, conflictScanScript, detectConflicts, parseConflictScan, parseExcludedRanges } from "../src/main/windows/tunnelConflicts";
import type { ConflictScanInput, ConflictScanOptions } from "../src/main/windows/tunnelConflicts";

const options: ConflictScanOptions = {
  ports: [47185, 47186],
  ownExecutables: ["C:\\Program Files\\Levik VPN\\Levik VPN.exe", "C:\\Program Files\\Levik VPN\\resources\\kill-switch\\levik-kill-switch.exe"],
  coreExecutables: ["C:\\Program Files\\Levik VPN\\resources\\xray\\xray.exe", "C:\\Program Files\\Levik VPN\\resources\\singbox\\sing-box.exe"],
  ownPid: 100,
};

function scan(input: Partial<ConflictScanInput>): ReturnType<typeof detectConflicts> {
  return detectConflicts({ processes: [], portOwners: [], excludedRanges: [], ...input }, options);
}

describe("administrator rights", () => {
  it("reads the integrity level independently of the Windows language", () => {
    expect(hasElevatedLevel('"Обязательная метка\\Высокий обязательный уровень","Метка","S-1-16-12288",""')).toBe(true);
    expect(hasElevatedLevel('"Mandatory Label\\Medium Mandatory Level","Label","S-1-16-8192",""')).toBe(false);
  });

  it("quotes the relaunch command for PowerShell and the Windows command line", () => {
    expect(powerShellString("C:\\Users\\O'Neil\\app.exe")).toBe("'C:\\Users\\O''Neil\\app.exe'");
    expect(windowsArgument("C:\\Program Files\\Levik")).toBe('"C:\\Program Files\\Levik"');
    expect(windowsArgument('say "hi"\\')).toBe('"say \\"hi\\"\\\\"');
    expect(elevatedStartScript("C:\\Levik\\Levik VPN.exe", [])).toBe("$ErrorActionPreference = 'Stop';Start-Process -FilePath 'C:\\Levik\\Levik VPN.exe' -Verb RunAs");
    expect(elevatedStartScript("C:\\electron.exe", ["C:\\dev app"])).toContain("-ArgumentList '\"C:\\dev app\"'");
  });
});

describe("tunnel conflicts", () => {
  it("names other VPN clients once per app, whatever processes they run", () => {
    const found = scan({ processes: [
      { pid: 200, name: "clash-verge.exe", path: "C:\\Apps\\Clash Verge\\clash-verge.exe" },
      { pid: 201, name: "verge-mihomo.exe", path: "C:\\Apps\\Clash Verge\\verge-mihomo.exe" },
      { pid: 300, name: "WireGuard.exe", path: null },
      { pid: 400, name: "Telegram.exe", path: "C:\\Telegram\\Telegram.exe" },
    ] });
    expect(found.map(({ conflict, pids }) => [conflict.name, conflict.kind, conflict.closable, pids])).toEqual([
      ["Clash Verge", "vpn", true, [200, 201]],
      ["WireGuard", "vpn", true, [300]],
    ]);
  });

  it("treats a Levik core still running without a tunnel as left from a crash and ignores the app itself", () => {
    const found = scan({
      processes: [
        { pid: 100, name: "Levik VPN.exe", path: "C:\\Program Files\\Levik VPN\\Levik VPN.exe" },
        { pid: 101, name: "Levik VPN.exe", path: "C:/Program Files/Levik VPN/Levik VPN.exe" },
        { pid: 500, name: "xray.exe", path: "C:\\Program Files\\Levik VPN\\resources\\xray\\xray.exe" },
        { pid: 600, name: "xray.exe", path: "C:\\v2rayN\\bin\\xray\\xray.exe" },
      ],
      portOwners: [{ port: 47185, pid: 500 }],
    });
    expect(found.map(({ conflict, pids }) => [conflict.id, pids])).toEqual([["orphan", [500]], ["client:Xray", [600]]]);
    expect(found[0]?.conflict.detail).toContain("47185");
  });

  it("reports the owner of a port Xray needs and never offers to close a system service", () => {
    const found = scan({
      processes: [
        { pid: 700, name: "node.exe", path: "C:\\nodejs\\node.exe" },
        { pid: 800, name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe" },
      ],
      portOwners: [{ port: 47186, pid: 700 }, { port: 47185, pid: 800 }, { port: 47185, pid: 4 }, { port: 9999, pid: 700 }],
    });
    expect(found.map(({ conflict, pids }) => [conflict.name, conflict.closable, pids])).toEqual([
      ["node", true, [700]],
      ["Процесс 4", false, []],
      ["svchost", false, []],
    ]);
  });

  it("explains ports Windows reserved for Hyper-V", () => {
    const ranges = parseExcludedRanges([
      "Диапазоны исключенных портов протокола tcp", "", "Начальный порт   Конечный порт", "----------    --------",
      "     47100       47199", "     50000       50059     *", "", "* - Управляемые исключения портов.",
    ].join("\r\n"));
    expect(ranges).toEqual([{ start: 47100, end: 47199 }, { start: 50000, end: 50059 }]);
    const found = scan({ excludedRanges: ranges });
    expect(found.map(({ conflict }) => [conflict.kind, conflict.closable])).toEqual([["reserved", false], ["reserved", false]]);
  });

  it("parses the PowerShell scan, including single objects and missing fields", () => {
    expect(parseConflictScan('\uFEFF{"processes":{"pid":5,"name":"a.exe","path":""},"owners":[{"port":47185,"pid":5},{"port":"x","pid":1}],"excluded":""}')).toEqual({
      processes: [{ pid: 5, name: "a.exe", path: null }],
      portOwners: [{ port: 47185, pid: 5 }],
      excludedRanges: [],
    });
    expect(parseConflictScan("")).toEqual({ processes: [], portOwners: [], excludedRanges: [] });
  });

  it("only puts validated numbers into the scripts", () => {
    expect(conflictScanScript([47185, 0, 70000, 1.5])).toContain("$ports = @(47185);");
    expect(closeProcessesScript([12, -1, Number.NaN, 34])).toContain("$ids = @(12,34);");
    expect(closeProcessesScript([])).toContain("$ids = @(0);");
  });
});
