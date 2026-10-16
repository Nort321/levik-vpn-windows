import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { win32 } from "node:path";
import type { TunnelConflict } from "../../shared/contracts";
import { encodePowerShell } from "./elevation";

const execFileAsync = promisify(execFile);

/**
 * What stops Levik VPN from creating its tunnel: another VPN client holding
 * the routes or its own TUN, a process on one of Xray's local ports, a port
 * Windows reserved (Hyper-V, WSL, Docker), or a Levik core left from a crash.
 * Process ids stay in the main process; the renderer only sees names.
 */

/** Other VPN and proxy clients, by executable name in lower case. */
const KNOWN_CLIENTS: Readonly<Record<string, string>> = {
  "v2rayn.exe": "v2rayN",
  "v2ray.exe": "V2Ray",
  "xray.exe": "Xray",
  "sing-box.exe": "sing-box",
  "nekoray.exe": "NekoRay",
  "nekobox.exe": "NekoBox",
  "throne.exe": "Throne",
  "hiddify.exe": "Hiddify",
  "hiddifycli.exe": "Hiddify",
  "happ.exe": "Happ",
  "v2raytun.exe": "v2RayTun",
  "clash-verge.exe": "Clash Verge",
  "clash-verge-service.exe": "Clash Verge",
  "verge-mihomo.exe": "Clash Verge",
  "verge-mihomo-alpha.exe": "Clash Verge",
  "clash for windows.exe": "Clash for Windows",
  "clash-win64.exe": "Clash",
  "clash.exe": "Clash",
  "mihomo.exe": "Mihomo",
  "clash-meta.exe": "Mihomo",
  "flclash.exe": "FlClash",
  "flclashcore.exe": "FlClash",
  "amneziavpn.exe": "AmneziaVPN",
  "amneziavpn-service.exe": "AmneziaVPN",
  "amneziawg.exe": "AmneziaWG",
  "wireguard.exe": "WireGuard",
  "openvpn.exe": "OpenVPN",
  "openvpn-gui.exe": "OpenVPN",
  "openvpnserv.exe": "OpenVPN",
  "openvpnconnect.exe": "OpenVPN Connect",
  "outline.exe": "Outline",
  "outlineservice.exe": "Outline",
  "tun2socks.exe": "tun2socks",
  "protonvpn.exe": "Proton VPN",
  "protonvpn.client.exe": "Proton VPN",
  "protonvpnservice.exe": "Proton VPN",
  "protonvpn.wireguardservice.exe": "Proton VPN",
  "nordvpn.exe": "NordVPN",
  "nordvpn-service.exe": "NordVPN",
  "expressvpn.exe": "ExpressVPN",
  "expressvpnd.exe": "ExpressVPN",
  "windscribe.exe": "Windscribe",
  "windscribeservice.exe": "Windscribe",
  "surfshark.exe": "Surfshark",
  "surfshark.service.exe": "Surfshark",
  "cyberghost.exe": "CyberGhost",
  "cyberghost.service.exe": "CyberGhost",
  "pia-client.exe": "Private Internet Access",
  "pia-service.exe": "Private Internet Access",
  "mullvad vpn.exe": "Mullvad VPN",
  "mullvad-daemon.exe": "Mullvad VPN",
  "tunnelbear.exe": "TunnelBear",
  "psiphon3.exe": "Psiphon",
  "psiphon-tunnel-core.exe": "Psiphon",
  "lantern.exe": "Lantern",
  "cloudflare warp.exe": "Cloudflare WARP",
  "warp-svc.exe": "Cloudflare WARP",
  "ksde.exe": "Kaspersky VPN",
  "ksdeui.exe": "Kaspersky VPN",
  "shadowsocks.exe": "Shadowsocks",
  "goodbyedpi.exe": "GoodbyeDPI",
  "winws.exe": "zapret",
};

/** Never closed from here, whatever port they hold. */
const PROTECTED_PROCESSES = new Set([
  "system", "idle", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
  "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "explorer.exe", "dwm.exe",
  "fontdrvhost.exe", "spoolsv.exe", "msmpeng.exe", "searchindexer.exe",
]);

export interface ScannedProcess {
  pid: number;
  name: string;
  path: string | null;
}

export interface ConflictScanInput {
  processes: ScannedProcess[];
  /** Local port → owning process ids, TCP listeners and UDP endpoints together. */
  portOwners: Array<{ port: number; pid: number }>;
  /** TCP port ranges Windows keeps for itself (netsh excludedportrange). */
  excludedRanges: Array<{ start: number; end: number }>;
}

export interface ConflictScanOptions {
  ports: readonly number[];
  /** Levik's own executables: the app itself, its Xray, sing-box and kill switch helper. */
  ownExecutables: readonly string[];
  /** Cores at these paths are Levik's; while no tunnel runs, a running one is left from a crash. */
  coreExecutables: readonly string[];
  ownPid: number;
}

/** A conflict with the processes that make it up; only `conflict` leaves the main process. */
export interface DetectedConflict {
  conflict: TunnelConflict;
  pids: number[];
}

export function detectConflicts(input: ConflictScanInput, options: ConflictScanOptions): DetectedConflict[] {
  const own = new Set(options.ownExecutables.map(normalizePath));
  const cores = new Set(options.coreExecutables.map(normalizePath));
  const byPid = new Map(input.processes.map((item) => [item.pid, item]));
  const items = new Map<string, { conflict: TunnelConflict; pids: Set<number> }>();
  const add = (id: string, conflict: TunnelConflict, pid: number | null): void => {
    const existing = items.get(id);
    if (existing) {
      if (pid !== null) existing.pids.add(pid);
      if (!existing.conflict.detail.includes(conflict.detail)) existing.conflict.detail = `${existing.conflict.detail}; ${conflict.detail}`;
      return;
    }
    items.set(id, { conflict, pids: new Set(pid === null ? [] : [pid]) });
  };

  for (const item of input.processes) {
    if (item.pid === options.ownPid) continue;
    const path = item.path ? normalizePath(item.path) : null;
    const key = item.name.toLowerCase();
    if (path && cores.has(path)) {
      add("orphan", {
        id: "orphan", kind: "orphan", name: "Ядро Levik VPN от прошлого запуска", processName: item.name,
        detail: "Осталось после сбоя и удерживает сетевой адаптер", closable: true,
      }, item.pid);
      continue;
    }
    if (path && own.has(path)) continue;
    const client = KNOWN_CLIENTS[key];
    if (!client) continue;
    add(`client:${client}`, {
      id: `client:${client}`, kind: "vpn", name: client, processName: item.name,
      detail: "Другой VPN-клиент: перехватывает маршруты и мешает создать туннель", closable: true,
    }, item.pid);
  }

  const wanted = new Set(options.ports);
  for (const owner of input.portOwners) {
    if (!wanted.has(owner.port) || owner.pid === options.ownPid) continue;
    const item = byPid.get(owner.pid);
    const path = item?.path ? normalizePath(item.path) : null;
    if (path && own.has(path) && !cores.has(path)) continue;
    const processName = item?.name ?? null;
    const key = processName?.toLowerCase() ?? "";
    const protectedProcess = owner.pid <= 4 || PROTECTED_PROCESSES.has(key);
    const detail = protectedProcess
      ? `Порт ${owner.port} занят системной службой Windows`
      : `Занимает порт ${owner.port}, нужный для туннеля`;
    if (path && cores.has(path)) {
      add("orphan", { id: "orphan", kind: "orphan", name: "Ядро Levik VPN от прошлого запуска", processName, detail, closable: true }, owner.pid);
      continue;
    }
    const client = KNOWN_CLIENTS[key];
    const id = client ? `client:${client}` : `port:${key || owner.pid}`;
    add(id, {
      id, kind: client ? "vpn" : "port", name: client ?? displayName(processName, owner.pid), processName, detail,
      closable: !protectedProcess,
    }, protectedProcess ? null : owner.pid);
  }

  for (const port of options.ports) {
    const range = input.excludedRanges.find((item) => port >= item.start && port <= item.end);
    if (!range) continue;
    add(`reserved:${port}`, {
      id: `reserved:${port}`, kind: "reserved", name: `Порт ${port} зарезервирован Windows`, processName: null,
      detail: `Диапазон ${range.start}–${range.end} забрали Hyper-V, WSL или Docker. Обычно помогает перезагрузка компьютера`,
      closable: false,
    }, null);
  }

  return [...items.values()]
    .map(({ conflict, pids }) => ({ conflict, pids: [...pids].sort((a, b) => a - b) }))
    .sort((left, right) => KIND_ORDER[left.conflict.kind] - KIND_ORDER[right.conflict.kind]
      || Number(right.conflict.closable) - Number(left.conflict.closable)
      || left.conflict.name.localeCompare(right.conflict.name, "ru"));
}

const KIND_ORDER: Record<TunnelConflict["kind"], number> = { orphan: 0, port: 1, vpn: 2, reserved: 3 };

function displayName(processName: string | null, pid: number): string {
  if (!processName) return `Процесс ${pid}`;
  return processName.replace(/\.exe$/i, "");
}

function normalizePath(value: string): string {
  return win32.normalize(value.trim().replaceAll("/", "\\")).toLowerCase();
}

/** One PowerShell run: every process, owners of the given ports and Windows' reserved TCP ranges. */
export function conflictScanScript(ports: readonly number[]): string {
  const list = ports.filter(isPort).join(",") || "0";
  return [
    "$ErrorActionPreference = 'SilentlyContinue';",
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false);",
    `$ports = @(${list});`,
    "$processes = @(Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ pid = [int]$_.ProcessId; name = [string]$_.Name; path = [string]$_.ExecutablePath } });",
    "$owners = @(Get-NetTCPConnection -State Listen -LocalPort $ports | ForEach-Object { [pscustomobject]@{ port = [int]$_.LocalPort; pid = [int]$_.OwningProcess } });",
    "$owners += @(Get-NetUDPEndpoint -LocalPort $ports | ForEach-Object { [pscustomobject]@{ port = [int]$_.LocalPort; pid = [int]$_.OwningProcess } });",
    "$excluded = (netsh.exe interface ipv4 show excludedportrange protocol=tcp) -join \"`n\";",
    "[pscustomobject]@{ processes = $processes; owners = $owners; excluded = $excluded } | ConvertTo-Json -Compress -Depth 4",
  ].join(" ");
}

export function parseConflictScan(stdout: string): ConflictScanInput {
  const decoded = JSON.parse(stdout.trim().replace(/^﻿/, "") || "{}") as unknown;
  if (!isRecord(decoded)) return { processes: [], portOwners: [], excludedRanges: [] };
  const processes = asArray(decoded.processes).flatMap((item): ScannedProcess[] => {
    if (!isRecord(item) || !isPid(item.pid) || typeof item.name !== "string" || !item.name.trim()) return [];
    const path = typeof item.path === "string" && item.path.trim() ? item.path.trim() : null;
    return [{ pid: item.pid, name: item.name.trim().slice(0, 260), path }];
  });
  const portOwners = asArray(decoded.owners).flatMap((item) => {
    if (!isRecord(item) || !isPort(item.port) || !isPid(item.pid)) return [];
    return [{ port: item.port, pid: item.pid }];
  });
  return { processes, portOwners, excludedRanges: parseExcludedRanges(typeof decoded.excluded === "string" ? decoded.excluded : "") };
}

/** Rows of two numbers; the headers are localized, the numbers are not. */
export function parseExcludedRanges(text: string): Array<{ start: number; end: number }> {
  return text.split(/\r?\n/).flatMap((line) => {
    const match = /^\s*(\d{1,5})\s+(\d{1,5})(?:\s+\*)?\s*$/.exec(line);
    if (!match) return [];
    const start = Number(match[1]);
    const end = Number(match[2]);
    return isPort(start) && isPort(end) && start <= end ? [{ start, end }] : [];
  });
}

export async function scanTunnelConflicts(options: ConflictScanOptions): Promise<DetectedConflict[]> {
  if (process.platform !== "win32") return [];
  const { stdout } = await execFileAsync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encodePowerShell(conflictScanScript(options.ports)),
  ], { windowsHide: true, timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
  return detectConflicts(parseConflictScan(stdout), options);
}

/**
 * Stops the services behind these processes, so Windows does not start them
 * again, then ends the processes. The ids come from a scan made just before.
 */
export function closeProcessesScript(pids: readonly number[]): string {
  const list = pids.filter(isPid).join(",") || "0";
  return [
    "$ErrorActionPreference = 'SilentlyContinue';",
    `$ids = @(${list});`,
    "$services = @(Get-CimInstance Win32_Service -Filter \"State='Running'\" | Where-Object { $ids -contains [int]$_.ProcessId });",
    "foreach ($service in $services) { Stop-Service -Name $service.Name -Force };",
    "foreach ($id in $ids) { Stop-Process -Id $id -Force };",
    "Start-Sleep -Milliseconds 800",
  ].join(" ");
}

export async function closeConflictingProcesses(pids: readonly number[]): Promise<void> {
  if (process.platform !== "win32" || !pids.length) return;
  await execFileAsync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encodePowerShell(closeProcessesScript(pids)),
  ], { windowsHide: true, timeout: 45_000, maxBuffer: 256 * 1024 });
}

function asArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  return value === null || value === undefined ? [] : [value];
}

function isPid(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 0xffffffff;
}

function isPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65_535;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
