import { execFile } from "node:child_process";
import { windowsHelperPath } from "./helperPath";

interface HelperResult {
  exitCode: number;
  errorText: string;
}

export type KillSwitchCommandRunner = (arguments_: string[]) => Promise<HelperResult>;

interface WindowsKillSwitchOptions {
  platform?: NodeJS.Platform;
  appExecutablePath?: string;
  helperExecutablePath?: string;
  run?: KillSwitchCommandRunner;
}

export class WindowsKillSwitch {
  private active = false;
  private operation: Promise<unknown> = Promise.resolve();
  private readonly platform: NodeJS.Platform;
  private readonly appExecutablePath: string;
  private readonly helperExecutablePath: string;
  private readonly run: KillSwitchCommandRunner;

  constructor(
    private readonly xrayExecutablePath: () => string,
    options: WindowsKillSwitchOptions = {},
  ) {
    this.platform = options.platform ?? process.platform;
    this.appExecutablePath = options.appExecutablePath ?? process.execPath;
    this.helperExecutablePath = options.helperExecutablePath ?? windowsHelperPath();
    this.run = options.run ?? ((arguments_) => runHelper(this.helperExecutablePath, arguments_));
  }

  async recover(): Promise<boolean> {
    return this.serialize(() => this.recoverBoundary());
  }

  private async recoverBoundary(): Promise<boolean> {
    if (this.platform !== "win32") return false;
    const status = await this.run(["status"]);
    if (status.exitCode === 2) return false;
    if (status.exitCode !== 3) this.assertSuccessful(status, "проверить состояние");
    await this.execute("enable", this.appExecutablePath, this.xrayExecutablePath());
    this.active = true;
    return true;
  }

  async ensureActive(shouldRestore: () => boolean): Promise<boolean> {
    return this.serialize(() => this.restoreBoundary(shouldRestore));
  }

  private async restoreBoundary(shouldRestore: () => boolean): Promise<boolean> {
    if (this.platform !== "win32" || !this.active) return false;
    const status = await this.run(["status"]);
    if (status.exitCode === 0) return false;
    if (status.exitCode !== 2 && status.exitCode !== 3) {
      this.assertSuccessful(status, "проверить состояние");
    }
    if (!shouldRestore()) return false;
    // Keep monitoring after a failed repair; active also records our intent.
    await this.execute("enable", this.appExecutablePath, this.xrayExecutablePath());
    return true;
  }

  async cleanupLegacyConfig(userDataPath: string): Promise<void> {
    if (this.platform !== "win32") return;
    await this.execute("cleanup-legacy", userDataPath);
  }

  async enable(): Promise<void> {
    return this.serialize(async () => {
      if (this.platform !== "win32" || this.active) return;
      await this.execute("enable", this.appExecutablePath, this.xrayExecutablePath());
      this.active = true;
    });
  }

  async allowTunnel(): Promise<void> {
    if (this.platform !== "win32" || !this.active) return;
    // Wintun can still be registering after Xray has passed its startup grace period.
    // Retry only ERROR_NOT_FOUND; permission/filter errors must fail immediately.
    for (let attempt = 0; attempt <= 20 && this.active; attempt += 1) {
      const result = await this.serialize(() => this.active
        ? this.run(["allow-tunnel", "LevikVPN"])
        : Promise.resolve({ exitCode: 0, errorText: "" }));
      if (result.exitCode !== 1168 || attempt === 20) {
        this.assertSuccessful(result, "allow-tunnel");
        return;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 250));
    }
  }

  async disable(): Promise<void> {
    return this.serialize(async () => {
      if (this.platform !== "win32") return;
      await this.execute("disable");
      this.active = false;
    });
  }

  isActive(): boolean {
    return this.active;
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.operation.then(operation);
    this.operation = pending.catch(() => {});
    return pending;
  }

  private async execute(...arguments_: string[]): Promise<void> {
    this.assertSuccessful(await this.run(arguments_), arguments_[0] ?? "выполнить операцию");
  }

  private assertSuccessful(result: HelperResult, operation: string): void {
    if (result.exitCode === 0) return;
    throw new Error(`Kill Switch не удалось ${operation}: ${result.errorText || `код ${result.exitCode}`}`);
  }
}

async function runHelper(executablePath: string, arguments_: string[]): Promise<HelperResult> {
  return await new Promise<HelperResult>((resolve, reject) => {
    execFile(executablePath, arguments_, {
      windowsHide: true,
      timeout: 15_000,
      maxBuffer: 256 * 1024,
    }, (error, _stdout, stderr) => {
      if (!error) {
        resolve({ exitCode: 0, errorText: stderr.trim() });
        return;
      }
      if (typeof error.code === "number") {
        resolve({ exitCode: error.code, errorText: stderr.trim() || error.message });
        return;
      }
      reject(error);
    });
  });
}
