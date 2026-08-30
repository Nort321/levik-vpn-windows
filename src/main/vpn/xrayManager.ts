import { app } from "electron";
import { execFile, spawn } from "node:child_process";
import type { ChildProcess, ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { parseXrayStats, XRAY_STATS_ENDPOINT } from "./xrayStats";

const execFileAsync = promisify(execFile);

interface XrayEvents {
  log: [line: string];
  exit: [code: number | null, expected: boolean];
  stats: [downloadBytes: number, uploadBytes: number];
}

export class XrayManager extends EventEmitter<XrayEvents> {
  private process: ChildProcessWithoutNullStreams | null = null;
  private stopping = false;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private statsQueryRunning = false;
  private statsErrorReported = false;

  async start(config: Record<string, unknown>): Promise<void> {
    if (process.platform !== "win32") throw new Error("VPN-туннель запускается только в Windows-сборке");
    const configInput = Buffer.from(JSON.stringify(config), "utf8");
    try {
      await this.stop();
      await this.validate(configInput);
      this.stopping = false;
      const child = spawn(this.executablePath(), xrayConfigArguments(false), {
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, XRAY_LOCATION_ASSET: this.assetDirectory() },
      });
      this.process = child;
      child.stdout.on("data", (chunk: Buffer) => this.emitLines(chunk));
      child.stderr.on("data", (chunk: Buffer) => this.emitLines(chunk));
      child.once("error", (error) => this.emit("log", `Xray: ${error.message}`));
      child.once("exit", (code) => {
        this.stopStatsPolling();
        const expected = this.stopping;
        if (this.process === child) this.process = null;
        this.emit("exit", code, expected);
      });
      await Promise.all([
        writeConfigInput(child, configInput),
        waitForStartup(child),
      ]);
      this.startStatsPolling();
    } finally {
      configInput.fill(0);
    }
  }

  async stop(): Promise<void> {
    this.stopStatsPolling();
    const child = this.process;
    if (!child) return;
    this.stopping = true;
    child.kill();
    await Promise.race([
      new Promise<void>((resolve) => child.once("exit", () => resolve())),
      new Promise<void>((resolve) => setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 5_000)),
    ]);
    this.process = null;
  }

  isRunning(): boolean {
    return this.process !== null;
  }

  async isHealthy(): Promise<boolean> {
    if (!this.process) return false;
    try {
      await execFileAsync(this.executablePath(), [
        "api", "statsquery", `--server=${XRAY_STATS_ENDPOINT}`, "-pattern", "inbound>>>levik-tun-in>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
      return this.process !== null;
    } catch {
      return false;
    }
  }

  private async validate(configInput: Buffer): Promise<void> {
    const validation = spawn(this.executablePath(), xrayConfigArguments(true), {
      windowsHide: true,
      stdio: ["pipe", "ignore", "pipe"],
      env: { ...process.env, XRAY_LOCATION_ASSET: this.assetDirectory() },
    });
    let errorText = "";
    validation.stderr.on("data", (chunk: Buffer) => { errorText = `${errorText}${chunk}`.slice(-4_096); });
    await Promise.all([
      writeConfigInput(validation, configInput),
      new Promise<void>((resolve, reject) => {
        validation.once("error", reject);
        validation.once("exit", (code) => code === 0
          ? resolve()
          : reject(new Error(errorText.trim() || "Xray отклонил конфигурацию")));
      }),
    ]);
  }

  executablePath(): string {
    return join(this.assetDirectory(), "xray.exe");
  }

  private assetDirectory(): string {
    return app.isPackaged
      ? join(process.resourcesPath, "xray")
      : join(app.getAppPath(), "vendor", "xray", "windows-x64");
  }

  private emitLines(chunk: Buffer): void {
    chunk.toString("utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      .forEach((line) => this.emit("log", line.replace(/[\u0000-\u001f]/g, "")));
  }

  private startStatsPolling(): void {
    this.stopStatsPolling();
    this.statsErrorReported = false;
    void this.queryStats();
    this.statsTimer = setInterval(() => void this.queryStats(), 2_000);
  }

  private stopStatsPolling(): void {
    if (this.statsTimer) clearInterval(this.statsTimer);
    this.statsTimer = null;
    this.statsQueryRunning = false;
  }

  private async queryStats(): Promise<void> {
    if (!this.process || this.statsQueryRunning) return;
    this.statsQueryRunning = true;
    try {
      const { stdout } = await execFileAsync(this.executablePath(), [
        "api", "statsquery",
        `--server=${XRAY_STATS_ENDPOINT}`,
        "-pattern", "inbound>>>levik-tun-in>>>traffic>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
      const values = parseXrayStats(stdout);
      this.statsErrorReported = false;
      if (this.process) this.emit("stats", values.downlink, values.uplink);
    } catch (error) {
      if (!this.statsErrorReported && this.process) {
        this.statsErrorReported = true;
        this.emit("log", `Статистика Xray: ${error instanceof Error ? error.message : "ошибка запроса"}`);
      }
    } finally {
      this.statsQueryRunning = false;
    }
  }
}

export function xrayConfigArguments(validateOnly: boolean): string[] {
  return ["run", ...(validateOnly ? ["-test"] : []), "-format", "json", "-config", "stdin:"];
}

async function writeConfigInput(child: ChildProcess, configInput: Buffer): Promise<void> {
  const stdin = child.stdin;
  if (!stdin) throw new Error("Xray не открыл канал конфигурации");
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      stdin.off("error", onError);
      if (error) reject(error);
      else resolve();
    };
    const onError = (error: Error): void => finish(error);
    stdin.once("error", onError);
    stdin.end(configInput, () => finish());
  });
}

async function waitForStartup(child: ChildProcess): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      child.off("error", onError);
      if (error) reject(error);
      else resolve();
    };
    const onExit = (code: number | null): void => finish(new Error(`Xray завершился при запуске (код ${code ?? "unknown"})`));
    const onError = (error: Error): void => finish(error);
    const timer = setTimeout(() => finish(), 1_500);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}
