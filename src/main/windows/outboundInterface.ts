import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Read ActiveStore without interpolating interface names into PowerShell code.
const ROUTES_SCRIPT = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$adapters = @{}
Get-NetAdapter | ForEach-Object { $adapters[[int]$_.ifIndex] = $_ }
@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
  $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0'
} | ForEach-Object {
  $adapter = $adapters[[int]$_.InterfaceIndex]
  [pscustomobject]@{
    name = $adapter.Name
    physical = $adapter.HardwareInterface
    up = ($adapter.Status -eq 'Up')
    index = [int]$_.InterfaceIndex
    prefix = $_.DestinationPrefix
    routeMetric = [long]$_.RouteMetric
    interfaceMetric = [long]$_.InterfaceMetric
  }
}) | ConvertTo-Json -Compress
`;

export async function findWindowsOutboundInterface(): Promise<string> {
  try {
    const { stdout } = await execFileAsync("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ROUTES_SCRIPT,
    ], { windowsHide: true, timeout: 10_000, maxBuffer: 256 * 1024, encoding: "utf8" });
    return selectWindowsOutboundInterface(JSON.parse(stdout.replace(/^\uFEFF/, "") || "[]") as unknown);
  } catch {
    throw new Error("Не удалось определить основной физический сетевой интерфейс. Проверьте подключение Wi-Fi или Ethernet и подключите VPN повторно.");
  }
}

export function selectWindowsOutboundInterface(value: unknown): string {
  const rows: unknown[] = Array.isArray(value) ? value : [value];
  const candidates = rows.flatMap((row) => {
    if (typeof row !== "object" || row === null) return [];
    const route = row as Record<string, unknown>;
    if (route.physical !== true || route.up !== true
      || typeof route.name !== "string" || !route.name.trim() || /[\u0000-\u001f]/.test(route.name)
      || route.name === "LevikVPN"
      || !isMetric(route.index) || route.index === 0
      || !isMetric(route.routeMetric) || !isMetric(route.interfaceMetric)
      || (route.prefix !== "0.0.0.0/0" && route.prefix !== "::/0")) return [];
    return [{ name: route.name, index: route.index, ipv4: route.prefix === "0.0.0.0/0", metric: route.routeMetric + route.interfaceMetric }];
  });
  // Prefer the primary IPv4 route; IPv6-only networks use their IPv6 default.
  candidates.sort((a, b) => Number(b.ipv4) - Number(a.ipv4) || a.metric - b.metric || a.index - b.index);
  const selected = candidates[0];
  if (!selected) throw new Error("Нет активного физического интерфейса с маршрутом по умолчанию");
  return selected.name;
}

function isMetric(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
