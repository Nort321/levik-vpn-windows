import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Mandatory integrity levels of an elevated (High) or service (System) token. */
const ELEVATED_LEVELS = ["S-1-16-12288", "S-1-16-16384"];

/**
 * Whether this process runs with an elevated token. Wintun, the kill switch
 * helper and DNS protection all need it. Null when it cannot be told.
 */
export async function isProcessElevated(platform: NodeJS.Platform = process.platform): Promise<boolean | null> {
  if (platform !== "win32") return null;
  try {
    // The integrity SID is the same in every Windows language, unlike group names.
    const { stdout } = await execFileAsync("whoami.exe", ["/groups", "/fo", "csv", "/nh"], {
      windowsHide: true, timeout: 5_000, maxBuffer: 256 * 1024,
    });
    return hasElevatedLevel(stdout);
  } catch {
    return null;
  }
}

export function hasElevatedLevel(whoamiGroups: string): boolean {
  return ELEVATED_LEVELS.some((sid) => whoamiGroups.includes(sid));
}

/**
 * Starts the executable again through the UAC prompt. Resolves once the new
 * process has started; rejects when the user declined the prompt.
 */
export async function startElevated(executable: string, args: readonly string[]): Promise<void> {
  if (process.platform !== "win32") throw new Error("Перезапуск с правами администратора доступен только в Windows");
  try {
    await execFileAsync("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-EncodedCommand", encodePowerShell(elevatedStartScript(executable, args)),
    ], { windowsHide: true, timeout: 120_000, maxBuffer: 64 * 1024 });
  } catch {
    throw new Error("Перезапуск от имени администратора отменён. Подтвердите запрос Windows, чтобы подключить VPN.");
  }
}

export function elevatedStartScript(executable: string, args: readonly string[]): string {
  const argumentList = args.map(windowsArgument).join(" ");
  return [
    "$ErrorActionPreference = 'Stop';",
    `Start-Process -FilePath ${powerShellString(executable)} -Verb RunAs`,
    argumentList ? ` -ArgumentList ${powerShellString(argumentList)}` : "",
  ].join("");
}

/** One argument as CommandLineToArgvW reads it back. */
export function windowsArgument(value: string): string {
  if (value && !/[\s"]/.test(value)) return value;
  return `"${value.replace(/(\\*)"/g, "$1$1\\\"").replace(/(\\+)$/, "$1$1")}"`;
}

export function powerShellString(value: string): string {
  // PowerShell ends a single-quoted string at any of these; doubling keeps the character.
  return `'${value.replace(/['‘’‚‛]/g, "$&$&")}'`;
}

export function encodePowerShell(script: string): string {
  return Buffer.from(script, "utf16le").toString("base64");
}
