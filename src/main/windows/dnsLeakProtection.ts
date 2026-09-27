import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SecureStore } from "../security/secureStore";

const execFileAsync = promisify(execFile);
const DNS_CLIENT_POLICY_KEY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
const SMHNR_VALUE_NAME = "DisableSmartNameResolution";
const BACKUP_KEY = "dns_policy_backup";

export interface RegistryValue {
  existed: boolean;
  value: number;
}

interface DnsPolicyAccess {
  read(): Promise<RegistryValue>;
  write(value: RegistryValue): Promise<void>;
}

export class DnsLeakProtection {
  private previousValue: RegistryValue | null = null;
  private enabled = false;
  private operation: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly store: Pick<SecureStore, "get" | "put" | "remove">,
    private readonly platform: NodeJS.Platform = process.platform,
    private readonly registry: DnsPolicyAccess = { read: readPolicy, write: writePolicy },
  ) {}

  enable(): Promise<void> {
    return this.serialize(async () => {
      if (this.platform !== "win32" || this.enabled) return;
      // Persist before changing Windows, including a crash during the write.
      this.previousValue ??= await this.loadBackup() ?? await this.registry.read();
      await this.store.put(BACKUP_KEY, Buffer.from(JSON.stringify(this.previousValue)));
      await this.registry.write({ existed: true, value: 1 });
      this.enabled = true;
    });
  }

  disable(): Promise<void> {
    return this.serialize(async () => {
      if (this.platform !== "win32") return;
      const previous = this.previousValue ?? await this.loadBackup();
      if (!previous) return;
      const current = await this.registry.read();
      // Preserve changes made by an administrator while VPN was connected.
      if (current.existed && current.value === 1) await this.registry.write(previous);
      // Failures retain both the snapshot and enabled state for another try.
      await this.store.remove(BACKUP_KEY);
      this.previousValue = null;
      this.enabled = false;
    });
  }

  private async loadBackup(): Promise<RegistryValue | null> {
    const buffer = await this.store.get(BACKUP_KEY);
    return buffer ? parsePolicy(buffer.toString("utf8")) : null;
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.operation.then(operation);
    this.operation = pending.catch(() => {});
    return pending;
  }
}

function parsePolicy(json: string): RegistryValue {
  const value: unknown = JSON.parse(json);
  if (typeof value !== "object" || value === null || !("existed" in value) || !("value" in value)
    || typeof value.existed !== "boolean" || typeof value.value !== "number"
    || !Number.isInteger(value.value) || value.value < 0 || value.value > 0xffffffff) {
    throw new Error("Не удалось прочитать DNS-политику Windows");
  }
  return { existed: value.existed, value: value.value };
}

async function readPolicy(): Promise<RegistryValue> {
  // reg QUERY conflates missing values with access errors. Use the registry API
  // to distinguish absence from failure without parsing localized error text.
  const script = `
$ErrorActionPreference = 'Stop'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')
try {
  $value = if ($null -eq $key) { $null } else { $key.GetValue('${SMHNR_VALUE_NAME}', $null) }
  if ($null -eq $value) { '{"existed":false,"value":0}' }
  else {
    if ($key.GetValueKind('${SMHNR_VALUE_NAME}') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'Unexpected DNS policy type' }
    @{ existed = $true; value = ([long]$value -band 4294967295) } | ConvertTo-Json -Compress
  }
} finally { if ($null -ne $key) { $key.Dispose() } }
`;
  const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    windowsHide: true, timeout: 10_000, maxBuffer: 16 * 1024,
  });
  return parsePolicy(stdout.trim());
}

async function writePolicy(value: RegistryValue): Promise<void> {
  await execFileAsync("reg.exe", value.existed
    ? ["ADD", DNS_CLIENT_POLICY_KEY, "/v", SMHNR_VALUE_NAME, "/t", "REG_DWORD", "/d", String(value.value), "/f"]
    : ["DELETE", DNS_CLIENT_POLICY_KEY, "/v", SMHNR_VALUE_NAME, "/f"],
  { windowsHide: true, timeout: 10_000 });
}
