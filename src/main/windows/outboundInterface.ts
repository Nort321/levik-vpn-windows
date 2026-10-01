import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Read ActiveStore without interpolating interface names into PowerShell code.
export const ROUTES_SCRIPT = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$adapters = @{}
Get-NetAdapter -IncludeHidden | ForEach-Object { $adapters[[int]$_.ifIndex] = $_ }
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

// The legacy provider lives in root/cimv2, independently of the NetAdapter and
// NetTCPIP modules' root/StandardCimv2 provider. Do not guess physical devices
// from their display names: TAP/Wintun adapters can also be named Ethernet.
export const FALLBACK_ROUTES_SCRIPT = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$adapters = @{}
Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter = True' | ForEach-Object {
  $adapters[[int]$_.Index] = $_
}
@(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | ForEach-Object {
  $config = $_
  $adapter = $adapters[[int]$config.Index]
  if ($null -ne $adapter -and $adapter.NetConnectionStatus -eq 2) {
    foreach ($gateway in $config.DefaultIPGateway) {
      $address = $null
      if ([System.Net.IPAddress]::TryParse($gateway, [ref]$address) -and
          !$address.Equals([System.Net.IPAddress]::Any) -and !$address.Equals([System.Net.IPAddress]::IPv6Any)) {
        [pscustomobject]@{
          name = $adapter.NetConnectionID
          physical = $adapter.PhysicalAdapter
          up = $true
          index = [int]$adapter.InterfaceIndex
          prefix = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { '0.0.0.0/0' } else { '::/0' }
          routeMetric = 0
          interfaceMetric = if ($null -ne $config.IPConnectionMetric) { [long]$config.IPConnectionMetric } else { 2147483647 }
        }
      }
    }
  }
}) | ConvertTo-Json -Compress
`;

export async function findWindowsOutboundInterface(
  report: (message: string) => void = () => {},
  query: (script: string) => Promise<string> = queryWindowsRoutes,
): Promise<string> {
  for (const [source, script] of [["NetTCPIP", ROUTES_SCRIPT], ["Win32", FALLBACK_ROUTES_SCRIPT]] as const) {
    try {
      const stdout = await query(script);
      const json = stdout.replace(/^\uFEFF/, "").trim();
      const routes: unknown = JSON.parse(json || "[]");
      report(`Сетевые интерфейсы (${source}): ${summarizeRoutes(routes)}`);
      const selected = selectWindowsOutboundInterface(routes);
      if (source === "Win32") report("Сетевой интерфейс определён резервным способом Win32");
      return selected;
    } catch (error) {
      report(`Определение интерфейса (${source}): ${diagnosticReason(error)}`);
    }
  }
  throw new Error("Не удалось определить сетевой интерфейс с выходом в интернет. Отключите другие VPN, проверьте подключение Wi-Fi или Ethernet и повторите подключение. Подробности — в журнале приложения.");
}

async function queryWindowsRoutes(script: string): Promise<string> {
  const { stdout } = await execFileAsync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
  ], { windowsHide: true, timeout: 20_000, maxBuffer: 256 * 1024, encoding: "utf8" });
  return stdout;
}

function diagnosticReason(error: unknown): string {
  if (!(error instanceof Error)) return "Неизвестная ошибка Windows";
  const details = error as Error & { killed?: boolean; code?: string | number; stderr?: string };
  if (details.killed) return "Windows не ответила на запрос сетевых интерфейсов за 20 секунд";
  // execFile.message contains the full PowerShell command; stderr is more useful.
  return (details.stderr?.trim() || (details.code !== undefined ? `Ошибка PowerShell: ${details.code}` : error.message))
    .replace(/[\u0000-\u001f]+/g, " ").slice(0, 1_000);
}

function summarizeRoutes(value: unknown): string {
  const rows = Array.isArray(value) ? value : [value];
  const summary = rows.filter((row): row is Record<string, unknown> => typeof row === "object" && row !== null)
    .slice(0, 12).map((row) => `${typeof row.name === "string" ? row.name.replace(/[\u0000-\u001f]/g, "").slice(0, 100) : "?"} (physical=${row.physical === true}, up=${row.up === true}, IPv4=${row.prefix === "0.0.0.0/0"})`);
  return summary.join("; ") || "маршруты по умолчанию отсутствуют";
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
