import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DNS_CLIENT_POLICY_KEY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
const SMHNR_VALUE_NAME = "DisableSmartNameResolution";

interface RegistryValue {
  existed: boolean;
  value: number;
}

export class DnsLeakProtection {
  private previousValue: RegistryValue | null = null;
  private enabled = false;

  async enable(): Promise<void> {
    if (process.platform !== "win32" || this.enabled) return;
    this.previousValue = await readDword(DNS_CLIENT_POLICY_KEY, SMHNR_VALUE_NAME);
    await execFileAsync("reg.exe", [
      "ADD", DNS_CLIENT_POLICY_KEY, "/v", SMHNR_VALUE_NAME, "/t", "REG_DWORD", "/d", "1", "/f",
    ], { windowsHide: true, timeout: 10_000 });
    this.enabled = true;
  }

  async disable(): Promise<void> {
    if (process.platform !== "win32" || !this.enabled) return;
    const previousValue = this.previousValue;
    this.enabled = false;
    this.previousValue = null;
    if (!previousValue || !previousValue.existed) {
      await ignoreMissingValue(() => execFileAsync("reg.exe", [
        "DELETE", DNS_CLIENT_POLICY_KEY, "/v", SMHNR_VALUE_NAME, "/f",
      ], { windowsHide: true, timeout: 10_000 }));
      return;
    }
    await execFileAsync("reg.exe", [
      "ADD", DNS_CLIENT_POLICY_KEY, "/v", SMHNR_VALUE_NAME, "/t", "REG_DWORD", "/d", String(previousValue.value), "/f",
    ], { windowsHide: true, timeout: 10_000 });
  }
}

async function readDword(key: string, name: string): Promise<RegistryValue> {
  try {
    const { stdout } = await execFileAsync("reg.exe", ["QUERY", key, "/v", name], {
      windowsHide: true,
      timeout: 10_000,
    });
    const match = stdout.match(/REG_DWORD\s+0x([0-9a-f]+)/i);
    return match?.[1] ? { existed: true, value: Number.parseInt(match[1], 16) } : { existed: false, value: 0 };
  } catch {
    return { existed: false, value: 0 };
  }
}

async function ignoreMissingValue(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch {
    // The policy value can be removed externally while the tunnel is active.
  }
}
