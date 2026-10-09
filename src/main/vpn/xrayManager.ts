import { app } from "electron";
import { execFile, spawn } from "node:child_process";
import type { ChildProcess, ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { parseXrayStats, XRAY_STATS_ENDPOINT } from "./xrayStats";
import { bindXrayOutboundInterface } from "./xrayConfig";
import { findWindowsOutboundInterface } from "../windows/outboundInterface";
import { TuicSidecar, withTuicProxy } from "./tuicSidecar";
import type { TuicEndpoint } from "../../shared/contracts";

const execFileAsync = promisify(execFile);

interface XrayEvents {
  log: [line: string];
  exit: [code: number | null, expected: boolean];
  stats: [downloadBytes: number, uploadBytes: number];
}

export class XrayManager extends EventEmitter<XrayEvents> {
  private process: ChildProcessWithoutNullStreams | null = null;
  private readonly stopping = new WeakSet<ChildProcess>();
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private statsQueryRunning: ChildProcess | null = null;
  private statsErrorReported = false;
  private readonly tuic = new TuicSidecar(stopChild);

  constructor() {
    super();
    this.tuic.on("log", (line) => this.emit("log", line));
    // Without its sidecar a TUIC session blackholes traffic. Ending the core
    // surfaces an unexpected exit, so the controller reconnects.
    this.tuic.on("exit", (code) => {
      const child = this.process;
      if (!child) return;
      this.emit("log", `TUIC: ядро завершилось (код ${code ?? "?"})`);
      child.kill();
    });
  }

  async start(config: Record<string, unknown>, tuic?: TuicEndpoint): Promise<void> {
    if (process.platform !== "win32") throw new Error("VPN-туннель запускается только в Windows-сборке");
    const { stdout: version } = await execFileAsync(this.executablePath(), ["version"], {
      windowsHide: true, timeout: 5_000, maxBuffer: 64 * 1024,
    });
    assertProcessRoutingSupport(config, version);
    await this.stop();
    const outbound = await findWindowsOutboundInterface((message) => this.emit("log", message));
    const interfaceName = outbound.name;
    let launchConfig = config;
    if (tuic) {
      const proxy = await this.tuic.start(tuic, interfaceName);
      try {
        launchConfig = withTuicProxy(config, proxy);
      } catch (error) {
        await this.tuic.stop();
        throw error;
      }
      this.emit("log", `TUIC: sing-box bound to [${interfaceName}]`);
    }
    const configInput = Buffer.from(JSON.stringify(bindXrayOutboundInterface(launchConfig, interfaceName, outbound.ipv6)), "utf8");
    this.emit("log", `Xray: outbound interface [${interfaceName}] (TCP/UDP, direct, IPv6 ${outbound.ipv6 ? "on" : "off"})`);
    try {
      await this.validate(configInput);
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
        if (this.process !== child) return;
        this.stopStatsPolling();
        const expected = this.stopping.has(child);
        this.process = null;
        this.emit("exit", code, expected);
      });
      await Promise.all([
        waitForStartup(child),
        writeConfigInput(child, configInput),
      ]);
      this.startStatsPolling();
    } catch (error) {
      await this.stop();
      throw error;
    } finally {
      configInput.fill(0);
    }
  }

  async stop(): Promise<void> {
    this.stopStatsPolling();
    const child = this.process;
    if (child) {
      this.stopping.add(child);
      await stopChild(child);
      if (this.process === child) this.process = null;
    }
    await this.tuic.stop();
  }

  tuicExecutablePath(): string {
    return this.tuic.executablePath();
  }

  isRunning(): boolean {
    return this.process !== null;
  }

  async isHealthy(): Promise<boolean> {
    const child = this.process;
    if (!child) return false;
    try {
      await execFileAsync(this.executablePath(), [
        "api", "statsquery", `--server=${XRAY_STATS_ENDPOINT}`, "-pattern", "inbound>>>levik-tun-in>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
      return this.process === child;
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
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.all([
        new Promise<void>((resolve, reject) => {
          timer = setTimeout(() => reject(new Error("Превышено время проверки конфигурации VPN")), 10_000);
          validation.once("error", reject);
          validation.once("exit", (code) => code === 0
            ? resolve()
            : reject(new Error(errorText.trim() || "Xray отклонил конфигурацию")));
        }),
        writeConfigInput(validation, configInput),
      ]);
    } finally {
      clearTimeout(timer);
      await stopChild(validation);
    }
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
  }

  private async queryStats(): Promise<void> {
    const child = this.process;
    if (!child || this.statsQueryRunning === child) return;
    this.statsQueryRunning = child;
    try {
      const { stdout } = await execFileAsync(this.executablePath(), [
        "api", "statsquery",
        `--server=${XRAY_STATS_ENDPOINT}`,
        "-pattern", "inbound>>>levik-tun-in>>>traffic>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
      const values = parseXrayStats(stdout);
      if (this.process !== child) return;
      this.statsErrorReported = false;
      if (this.process) this.emit("stats", values.downlink, values.uplink);
    } catch (error) {
      if (!this.statsErrorReported && this.process === child) {
        this.statsErrorReported = true;
        this.emit("log", `Статистика Xray: ${error instanceof Error ? error.message : "ошибка запроса"}`);
      }
    } finally {
      if (this.statsQueryRunning === child) this.statsQueryRunning = null;
    }
  }
}

export async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
  await new Promise<void>((resolve, reject) => {
    const finish = (error?: Error): void => {
      clearTimeout(forceTimer);
      clearTimeout(deadline);
      child.off("exit", onExit);
      child.off("error", onError);
      if (error) reject(error); else resolve();
    };
    const onExit = (): void => finish();
    const onError = (error: Error): void => finish(error);
    const forceTimer = setTimeout(() => child.kill("SIGKILL"), 5_000);
    const deadline = setTimeout(() => finish(new Error("Не удалось остановить процесс VPN")), 10_000);
    // Subscribe before killing: a fast exit must not be lost.
    child.once("exit", onExit);
    child.once("error", onError);
    child.kill();
  });
}

export function assertProcessRoutingSupport(config: Record<string, unknown>, version: string): void {
  const routing = config.routing;
  if (!routing || typeof routing !== "object" || !("rules" in routing) || !Array.isArray(routing.rules)) return;
  const hasProcessRules = routing.rules.some((rule: unknown) => rule !== null && typeof rule === "object"
    && "process" in rule && Array.isArray(rule.process) && rule.process.length > 0);
  if (hasProcessRules && !version.includes("levik-process-v1")) {
    throw new Error("Для раздельного туннелирования требуется обновлённое VPN-ядро. Переустановите актуальную версию Levik VPN.");
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
