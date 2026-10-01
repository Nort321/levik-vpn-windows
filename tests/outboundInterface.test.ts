import { execFileSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import { FALLBACK_ROUTES_SCRIPT, findWindowsOutboundInterface, ROUTES_SCRIPT, selectWindowsOutboundInterface } from "../src/main/windows/outboundInterface";

const ethernet = { name: "Ethernet", physical: true, up: true, index: 2, prefix: "0.0.0.0/0", routeMetric: 10, interfaceMetric: 5 };
const unavailableNative = async (): Promise<string> => { throw new Error("Native helper unavailable"); };

describe("Windows physical outbound interface", () => {
  it("uses the combined route and interface metric instead of preferring the Wi-Fi name", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "Wi-Fi", index: 3, routeMetric: 1, interfaceMetric: 50 },
      ethernet,
    ])).toBe("Ethernet");
    expect(selectWindowsOutboundInterface([
      ethernet,
      { ...ethernet, name: "Wi-Fi", index: 3, interfaceMetric: 1 },
    ])).toBe("Wi-Fi");
  });

  it("excludes TUN, virtual adapters, disconnected adapters and non-default routes", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "LevikVPN", routeMetric: 0 },
      { ...ethernet, name: "Other VPN", physical: false, routeMetric: 0 },
      { ...ethernet, name: "Wi-Fi", up: false, routeMetric: 0 },
      { ...ethernet, name: "Half default", prefix: "0.0.0.0/1", routeMetric: 0 },
      ethernet,
    ])).toBe("Ethernet");
  });

  it("supports singleton PowerShell output, Unicode aliases and IPv6-only networks", () => {
    expect(selectWindowsOutboundInterface({ ...ethernet, name: "Сеть Ethernet", prefix: "::/0" })).toBe("Сеть Ethernet");
  });

  it("prefers IPv4 when different adapters own the two default routes, with a stable metric tie-break", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "IPv6", prefix: "::/0", routeMetric: 0, interfaceMetric: 0 },
      { ...ethernet, name: "Higher index", index: 3 },
      ethernet,
    ])).toBe("Ethernet");
  });

  it.each([null, [], {}, [{ ...ethernet, routeMetric: "10" }], [{ ...ethernet, interfaceMetric: -1 }], [{ ...ethernet, name: "bad\nname" }]])(
    "fails closed for unavailable or malformed route data: %j",
    (value) => expect(() => selectWindowsOutboundInterface(value)).toThrow(/физического интерфейса/),
  );
});

describe("Windows outbound interface discovery", () => {
  it("keeps the primary route selection and handles BOM, whitespace and Unicode", async () => {
    const query = vi.fn(async () => `\uFEFF  ${JSON.stringify({ ...ethernet, name: "Сеть Ethernet" })}\r\n`);
    await expect(findWindowsOutboundInterface(vi.fn(), query, unavailableNative)).resolves.toBe("Сеть Ethernet");
    expect(query).toHaveBeenCalledExactlyOnceWith(ROUTES_SCRIPT);
  });

  it.each([
    new Error("NetTCPIP module unavailable"),
    Object.assign(new Error("Command failed: sensitive/full script"), { code: 1, stderr: "CIM provider unavailable\r\n" }),
    Object.assign(new Error("Command timed out"), { killed: true }),
  ])("recovers from a failed modern provider through the independent Win32 provider: %s", async (error) => {
    const query = vi.fn<(script: string) => Promise<string>>()
      .mockRejectedValueOnce(error).mockResolvedValueOnce(JSON.stringify(ethernet));
    const report = vi.fn();
    await expect(findWindowsOutboundInterface(report, query, unavailableNative)).resolves.toBe("Ethernet");
    expect(query.mock.calls.map(([script]) => script)).toEqual([ROUTES_SCRIPT, FALLBACK_ROUTES_SCRIPT]);
    expect(report).toHaveBeenCalledWith(expect.stringContaining("резервным способом"));
    expect(report.mock.calls.flat().join(" ")).not.toContain("sensitive/full script");
  });

  it.each(["", " \r\n", "invalid JSON", "[]", JSON.stringify({ ...ethernet, physical: false })])(
    "tries the fallback when the primary output is unusable: %j", async (stdout) => {
      const query = vi.fn<(script: string) => Promise<string>>()
        .mockResolvedValueOnce(stdout).mockResolvedValueOnce(JSON.stringify(ethernet));
      await expect(findWindowsOutboundInterface(vi.fn(), query, unavailableNative)).resolves.toBe("Ethernet");
      expect(query).toHaveBeenCalledTimes(2);
    },
  );

  it("rejects another VPN in both providers and records why the physical route was unavailable", async () => {
    const query = vi.fn(async () => JSON.stringify([
      { ...ethernet, name: "Ethernet", physical: false },
      { ...ethernet, name: "Wi-Fi", up: false },
    ]));
    const report = vi.fn();
    await expect(findWindowsOutboundInterface(report, query, unavailableNative)).rejects.toThrow("Подробности — в журнале");
    expect(query).toHaveBeenCalledTimes(2);
    expect(report).toHaveBeenCalledWith(expect.stringContaining("Ethernet (physical=false"));
    expect(report).toHaveBeenCalledWith(expect.stringContaining("Wi-Fi (physical=true, up=false"));
  });
});

describe("Windows interface discovery with unavailable WMI classes", () => {
  const invalidClass = Object.assign(new Error("CIM query failed"), {
    code: 1, stderr: "Get-NetAdapter / Get-CimInstance: Invalid class (0x80041010)",
  });

  it("connects through the native API without invoking either broken WMI provider", async () => {
    const wmi = vi.fn<(script: string) => Promise<string>>().mockRejectedValue(invalidClass);
    const native = vi.fn(async () => JSON.stringify({ ...ethernet, name: "Сеть Ethernet" }));
    const report = vi.fn();
    await expect(findWindowsOutboundInterface(report, wmi, native)).resolves.toBe("Сеть Ethernet");
    expect(native).toHaveBeenCalledOnce();
    expect(wmi).not.toHaveBeenCalled();
    expect(report).toHaveBeenCalledWith(expect.stringContaining("Windows API"));
  });

  it("keeps VPN adapters out of the native selection even when they have the lowest metric", async () => {
    const wmi = vi.fn<(script: string) => Promise<string>>().mockRejectedValue(invalidClass);
    const native = async () => JSON.stringify([
      { ...ethernet, name: "Other VPN", physical: false, routeMetric: 0, interfaceMetric: 0 },
      { ...ethernet, name: "Wi-Fi", index: 3, routeMetric: 1, interfaceMetric: 50 },
      ethernet,
    ]);
    await expect(findWindowsOutboundInterface(vi.fn(), wmi, native)).resolves.toBe("Ethernet");
    expect(wmi).not.toHaveBeenCalled();
  });

  it.each(["[]", "invalid JSON", JSON.stringify({ ...ethernet, physical: false })])(
    "reports both native and WMI failures when no usable route is available: %j", async (stdout) => {
      const wmi = vi.fn<(script: string) => Promise<string>>().mockRejectedValue(invalidClass);
      const report = vi.fn();
      await expect(findWindowsOutboundInterface(report, wmi, async () => stdout)).rejects.toThrow("Подробности — в журнале");
      expect(wmi.mock.calls.map(([script]) => script)).toEqual([ROUTES_SCRIPT, FALLBACK_ROUTES_SCRIPT]);
      const logs = report.mock.calls.flat().join(" ");
      expect(logs).toContain("Windows API");
      expect(logs).toContain("0x80041010");
    },
  );
});

// Exercise the actual PowerShell source in Windows CI, including CIM values and
// singleton/empty serialization. Pure TS fixtures cannot catch script failures.
describe.skipIf(process.platform !== "win32")("Windows PowerShell interface collectors", () => {
  function collect(stubs: string, script: string): unknown {
    const stdout = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `${stubs}\n${script}`], {
      encoding: "utf8", windowsHide: true, timeout: 20_000,
    });
    return JSON.parse(stdout.replace(/^\uFEFF/, "").trim() || "[]") as unknown;
  }

  it("collects hidden physical adapters without selecting a lower-metric VPN", () => {
    const rows = collect(`
function Get-NetAdapter {
  param([switch]$IncludeHidden)
  if (!$IncludeHidden) { throw 'Hidden adapters must be included' }
  [pscustomobject]@{ ifIndex = 2; Name = 'Ethernet'; HardwareInterface = $true; Status = 'Up' }
  [pscustomobject]@{ ifIndex = 3; Name = 'Other VPN'; HardwareInterface = $false; Status = 'Up' }
}
function Get-NetRoute {
  param($PolicyStore)
  [pscustomobject]@{ InterfaceIndex = 2; DestinationPrefix = '0.0.0.0/0'; RouteMetric = 10; InterfaceMetric = 5 }
  [pscustomobject]@{ InterfaceIndex = 3; DestinationPrefix = '0.0.0.0/0'; RouteMetric = 0; InterfaceMetric = 0 }
}
`, ROUTES_SCRIPT);
    expect(selectWindowsOutboundInterface(rows)).toBe("Ethernet");
  });

  it("joins legacy adapters by device Index and binds by the different InterfaceIndex", () => {
    const rows = collect(`
function Get-CimInstance {
  param($ClassName, $Filter)
  if ($ClassName -eq 'Win32_NetworkAdapter') {
    [pscustomobject]@{ Index = 9; InterfaceIndex = 2; NetConnectionID = 'Ethernet'; PhysicalAdapter = $true; NetConnectionStatus = 2 }
    [pscustomobject]@{ Index = 10; InterfaceIndex = 3; NetConnectionID = 'Disconnected'; PhysicalAdapter = $true; NetConnectionStatus = 7 }
  } else {
    [pscustomobject]@{ Index = 9; DefaultIPGateway = @('0.0.0.0', '::', 'invalid', '192.168.1.1'); IPConnectionMetric = 15 }
    [pscustomobject]@{ Index = 10; DefaultIPGateway = @('192.168.2.1'); IPConnectionMetric = 1 }
    [pscustomobject]@{ Index = 11; DefaultIPGateway = @('10.0.0.1'); IPConnectionMetric = 1 }
  }
}
`, FALLBACK_ROUTES_SCRIPT);
    expect(rows).toEqual({ ...ethernet, routeMetric: 0, interfaceMetric: 15 });
    expect(selectWindowsOutboundInterface(rows)).toBe("Ethernet");
  });

  it("does not invent a route when Win32 reports no default gateway", () => {
    const rows = collect(`
function Get-CimInstance {
  param($ClassName, $Filter)
  if ($ClassName -eq 'Win32_NetworkAdapter') {
    [pscustomobject]@{ Index = 9; InterfaceIndex = 2; NetConnectionID = 'Ethernet'; PhysicalAdapter = $true; NetConnectionStatus = 2 }
  } else {
    [pscustomobject]@{ Index = 9; DefaultIPGateway = $null; IPConnectionMetric = 15 }
  }
}
`, FALLBACK_ROUTES_SCRIPT);
    expect(() => selectWindowsOutboundInterface(rows)).toThrow(/физического интерфейса/);
  });
});
