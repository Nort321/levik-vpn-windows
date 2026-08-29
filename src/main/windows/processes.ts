import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { win32 } from "node:path";
import type { WindowsProcess } from "../../shared/contracts";

const execFileAsync = promisify(execFile);

export async function listWindowsProcesses(): Promise<WindowsProcess[]> {
  if (process.platform !== "win32") return [];
  const script = [
    "Get-Process | Where-Object { $_.Name } |",
    "Select-Object Name,Path | Sort-Object Name -Unique |",
    "ConvertTo-Json -Compress",
  ].join(" ");
  const { stdout } = await execFileAsync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script,
  ], { windowsHide: true, timeout: 10_000, maxBuffer: 2 * 1024 * 1024 });
  const decoded = JSON.parse(stdout || "[]") as unknown;
  const values = Array.isArray(decoded) ? decoded : [decoded];
  return values.flatMap((value): WindowsProcess[] => {
    if (!isRecord(value) || typeof value.Name !== "string") return [];
    const executablePath = typeof value.Path === "string" ? value.Path.trim() : "";
    const rawName = executablePath ? win32.basename(executablePath) : `${value.Name.trim()}.exe`;
    const name = normalizeExecutableName(rawName);
    if (!name) return [];
    return [{ name, path: executablePath ? executablePath.replaceAll("\\", "/") : null }];
  });
}

export function windowsProcessFromPath(executablePath: string): WindowsProcess | null {
  const normalizedPath = executablePath.trim();
  const name = normalizeExecutableName(win32.basename(normalizedPath));
  if (!name) return null;
  return { name, path: normalizedPath.replaceAll("\\", "/") };
}

function normalizeExecutableName(value: string): string | null {
  const name = value.trim();
  if (!/^[^<>:"/\\|?*\u0000-\u001f]{1,128}\.exe$/i.test(name)) return null;
  return name;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
