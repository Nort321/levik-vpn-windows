import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { win32 } from "node:path";
import type { WindowsProcess } from "../../shared/contracts";
import { mergeProcessList, normalizeExecutableName } from "../../shared/processes";

const execFileAsync = promisify(execFile);

export async function listWindowsProcesses(): Promise<WindowsProcess[]> {
  if (process.platform !== "win32") return [];
  const script = [
    "$ErrorActionPreference = 'Stop';",
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false);",
    "try { $items = Get-CimInstance Win32_Process | Select-Object Name,@{Name='Path';Expression={$_.ExecutablePath}} }",
    "catch { $items = Get-Process | Where-Object { $_.Name } | Select-Object Name,Path };",
    "@($items) | ConvertTo-Json -Compress",
  ].join(" ");
  const { stdout } = await execFileAsync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script,
  ], { windowsHide: true, timeout: 10_000, maxBuffer: 2 * 1024 * 1024 });
  return parseWindowsProcesses(stdout);
}

export function parseWindowsProcesses(stdout: string): WindowsProcess[] {
  const decoded = JSON.parse(stdout.trim().replace(/^\uFEFF/, "") || "[]") as unknown;
  const values = Array.isArray(decoded) ? decoded : [decoded];
  const processes = values.flatMap((value): WindowsProcess[] => {
    if (!isRecord(value) || typeof value.Name !== "string") return [];
    const executablePath = typeof value.Path === "string" ? value.Path.trim() : "";
    const processName = value.Name.trim();
    const rawName = executablePath ? win32.basename(executablePath) : /\.exe$/i.test(processName) ? processName : `${processName}.exe`;
    const name = normalizeExecutableName(rawName);
    if (!name) return [];
    return [{ name, path: executablePath ? executablePath.replaceAll("\\", "/") : null, running: true }];
  });
  return mergeProcessList(processes, []).sort((left, right) => left.name.localeCompare(right.name));
}

export function windowsProcessFromPath(executablePath: string): WindowsProcess | null {
  const normalizedPath = executablePath.trim();
  const name = normalizeExecutableName(win32.basename(normalizedPath));
  if (!name) return null;
  return { name, path: normalizedPath.replaceAll("\\", "/"), running: null };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
