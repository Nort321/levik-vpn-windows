import { app } from "electron";
import { execFile, spawn } from "node:child_process";
import type { ChildProcess, ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { parseXrayStats, XRAY_STATS_ENDPOINT } from "./xrayStats";
import { bindXrayOutboundInterface, GAME_MULTIPATH, GAME_UDP_BALANCER } from "./xrayConfig";
import type { GameRouteCandidate, GameRuntimeOptions } from "./multipath/client";
import type { GameConfigurableOptions, GameDataPlane } from "./multipath/dataPlane";
import { RemoteGameDataPlane } from "./multipath/remote";
import { networkInterfaces } from "node:os";
import { findWindowsOutboundInterface } from "../windows/outboundInterface";
import { TuicSidecar, withTuicProxy } from "./tuicSidecar";
import type { TuicEndpoint, GameMultipathStats, GameRuntimeSnapshot, GameRouteQuality } from "../../shared/contracts";
import { GAME_BLOCK, gameTag } from "./gameRoutes";
import { gameProcesses } from "../../shared/games";
import type { AppSettings } from "../../shared/contracts";

const execFileAsync = promisify(execFile);

/** Per-connection Xray info chatter: it would push every app event out of the 200-line journal. */
const CORE_NOISE = /\b(?:proxy\/tun: processing from|app\/dispatcher: sniffed domain|app\/dispatcher: default route for|transport\/internet\/splithttp: XHTTP is dialing|proxy\/vless\/outbound: tunneling request|transport\/internet\/tcp: dialing TCP to|proxy\/dns: handling DNS traffic|app\/dispatcher: taking detour \[levik-dns-out\])/;

interface XrayEvents {
  log: [line: string];
  exit: [code: number | null, expected: boolean];
  stats: [downloadBytes: number, uploadBytes: number];
  /** The game data plane is gone for good; the game was moved to the ordinary VPN (or could not be). */
  gameDown: [movedToTunnel: boolean];
}

export class XrayManager extends EventEmitter<XrayEvents> {
  private process: ChildProcessWithoutNullStreams | null = null;
  private readonly stopping = new WeakSet<ChildProcess>();
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private statsQueryRunning: ChildProcess | null = null;
  private statsErrorReported = false;
  private readonly tuic = new TuicSidecar(stopChild);
  private readonly gameTuic = new TuicSidecar(stopChild);
  private outboundName: string | null = null;
  private multipath: GameDataPlane | null = null;
  private gameUdpFallback = false;
  private routing: Record<string, unknown> | null = null;
  private selectedGameUdpRoute: number | null = null;
  private gameUdpReady = false;
  /** The selected VPN outbound: carries the game when no game node answers. */
  private tunnelTag: string | null = null;
  private gameViaTunnel = false;
  private readonly repeatedLines = new Map<string, number>();

  get gameMultipathStats(): GameMultipathStats | null {
    const stats = this.multipath?.snapshot();
    return stats ? { ...stats, ...(this.gameUdpFallback || this.gameViaTunnel ? { state: "fallback" as const } : {}) } : null;
  }

  /** route: game UDP over one game node without multipath; tunnel: the game uses the ordinary VPN. */
  get gameFallback(): "route" | "tunnel" | null { return this.gameViaTunnel ? "tunnel" : this.gameUdpFallback ? "route" : null; }

  /** No game node carries the match: the game's UDP uses the selected VPN server, as its TCP
   * always does, instead of being blocked. Kept until reconnect, so a running match never changes its exit. */
  async routeGameThroughTunnel(): Promise<void> {
    const child = this.process; const tag = this.tunnelTag;
    if (!child || !tag) throw new Error("VPN disconnected");
    await execFileAsync(this.executablePath(), ["api", "bo", `--server=${XRAY_STATS_ENDPOINT}`, "-b", GAME_UDP_BALANCER, tag],
      { windowsHide: true, timeout: 4_000, maxBuffer: 16 * 1024 });
    if (this.process !== child) throw new Error("VPN connection changed");
    this.gameViaTunnel = true; this.selectedGameUdpRoute = null; this.gameUdpReady = true;
    await this.multipath?.stop();
  }

  /** Xray would keep sending game UDP to the dead loopback port until reconnect. */
  private async gameDataPlaneDown(): Promise<void> {
    if (this.gameViaTunnel || !this.process) return;
    try { await this.routeGameThroughTunnel(); this.emit("gameDown", true); } catch { this.emit("gameDown", false); }
  }

  async selectGameUdpRoute(index: number | null): Promise<void> {
    const child = this.process;
    if (!child) throw new Error("VPN disconnected");
    await execFileAsync(this.executablePath(), ["api", "bo", `--server=${XRAY_STATS_ENDPOINT}`, "-b", GAME_UDP_BALANCER,
      index === null ? GAME_MULTIPATH : gameTag(index)], { windowsHide: true, timeout: 4_000, maxBuffer: 16 * 1024 });
    if (this.process !== child) throw new Error("VPN connection changed");
    this.gameUdpFallback = index !== null;
    this.selectedGameUdpRoute = index; this.gameUdpReady = true;
    if (index === null) this.multipath?.startCounting();
    else await this.multipath?.stop();
  }

  get gameRuntimeSnapshot(): GameRuntimeSnapshot | undefined { return this.multipath?.runtimeSnapshot(); }
  get gameRouteQualities(): Record<number, GameRouteQuality> { return this.multipath?.routeQualities() ?? {}; }
  refreshGameMeasurements(): void { this.multipath?.refreshMeasurements(); }

  setGamePlaying(active: boolean): void { this.multipath?.setPlaying(active); }
  pauseNewGameFlowsIfIdle(): boolean { return this.multipath?.pauseNewFlowsIfIdle() ?? true; }
  resumeNewGameFlows(): void { this.multipath?.resumeNewFlows(); }

  updateGameOptions(options: GameConfigurableOptions): void {
    this.multipath?.configure(options);
  }

  /** Pinned Xray supports AddRule from stdin. Replacing routing recreates
   * balancers, so their initial selectors must retain the live overrides. */
  async updateGameProcesses(settings: AppSettings): Promise<void> {
    const child = this.process;
    if (!child || !this.routing || !Array.isArray(this.routing.rules)) throw new Error("Подключите VPN для обновления игр");
    const routing = structuredClone(this.routing);
    if (!Array.isArray(routing.rules)) return;
    const processes = gameProcesses(settings);
    for (const rule of routing.rules) if (rule && typeof rule === "object" && "ruleTag" in rule
      && (rule.ruleTag === "game" || rule.ruleTag === "game-multipath")) Object.assign(rule, { process: processes });
    if (!processes.length) routing.rules = routing.rules.filter((rule: unknown) => !(rule && typeof rule === "object"
      && "ruleTag" in rule && (rule.ruleTag === "game" || rule.ruleTag === "game-multipath")));
    if (Array.isArray(routing.balancers)) for (const balancer of routing.balancers) {
      if (!balancer || typeof balancer !== "object" || !("tag" in balancer)) continue;
      if (balancer.tag === GAME_UDP_BALANCER) Object.assign(balancer, { selector: [this.gameViaTunnel && this.tunnelTag ? this.tunnelTag
        : !this.gameUdpReady ? GAME_BLOCK : this.selectedGameUdpRoute === null ? GAME_MULTIPATH : gameTag(this.selectedGameUdpRoute)] });
    }
    try {
      await updateXrayRouting(this.executablePath(), XRAY_STATS_ENDPOINT, routing);
      if (this.process !== child) throw new Error("Подключение изменилось");
      this.routing = routing;
    } catch {
      // ReloadRules is not transactional on this core. Never leave a partially
      // rebuilt policy running after API failure; existing WFP protection stays.
      if (this.process === child) { this.stopping.add(child); await stopChild(child); if (this.process === child) this.process = null; }
      throw new Error("Не удалось обновить игровые правила; переподключите VPN");
    }
  }

  async connectGameMultipath(candidates: GameRouteCandidate[], password: string, options?: GameRuntimeOptions): Promise<void> {
    await this.multipath?.connect(candidates, password, options);
  }

  constructor() {
    super();
    this.tuic.on("log", (line) => this.emit("log", line));
    this.gameTuic.on("log", (line) => this.emit("log", `Game ${line}`));
    this.gameTuic.on("exit", () => this.emit("log", "Game: TUIC остановлен; переподключите VPN для восстановления"));
    // Without its sidecar a TUIC session blackholes traffic. Ending the core
    // surfaces an unexpected exit, so the controller reconnects.
    this.tuic.on("exit", (code) => {
      const child = this.process;
      if (!child) return;
      this.emit("log", `TUIC: ядро завершилось (код ${code ?? "?"})`);
      child.kill();
    });
  }

  /** The physical adapter the last tunnel was bound to. */
  get outboundInterfaceName(): string | null {
    return this.outboundName;
  }

  async start(config: Record<string, unknown>, tuic?: TuicEndpoint, gameTuic: Array<{ tag: string; endpoint: TuicEndpoint }> = []): Promise<void> {
    if (process.platform !== "win32") throw new Error("VPN-туннель запускается только в Windows-сборке");
    const { stdout: version } = await execFileAsync(this.executablePath(), ["version"], {
      windowsHide: true, timeout: 5_000, maxBuffer: 64 * 1024,
    });
    assertProcessRoutingSupport(config, version);
    await this.stop();
    const outbound = await findWindowsOutboundInterface((message) => this.emit("log", message));
    const interfaceName = outbound.name;
    this.outboundName = interfaceName;
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
    if (gameTuic.length) {
      try {
        const proxies = await this.gameTuic.startRoutes(gameTuic, interfaceName);
        for (const [tag, proxy] of proxies) launchConfig = withTuicProxy(launchConfig, proxy, tag);
      } catch {
        await this.gameTuic.stop();
        const tags = new Set(gameTuic.map((route) => route.tag));
        const outbounds = Array.isArray(launchConfig.outbounds) ? launchConfig.outbounds : [];
        launchConfig = { ...launchConfig, outbounds: outbounds.map((outbound: unknown) => {
          if (typeof outbound === "object" && outbound !== null && "tag" in outbound && typeof outbound.tag === "string" && tags.has(outbound.tag)) {
            return { tag: outbound.tag, protocol: "blackhole", settings: {} };
          }
          return outbound;
        }) };
        this.emit("log", "Game: TUIC недоступен; проверяем остальные игровые маршруты");
      }
    }
    if (Array.isArray(launchConfig.outbounds) && launchConfig.outbounds.some((outbound: unknown) =>
      typeof outbound === "object" && outbound !== null && "tag" in outbound && outbound.tag === GAME_MULTIPATH)) {
      this.multipath = await RemoteGameDataPlane.create((line) => this.emit("log", line), () => void this.gameDataPlaneDown());
      const local = await this.multipath.listen();
      launchConfig = withTuicProxy(launchConfig, { port: local.port, id: local.uuid }, GAME_MULTIPATH);
    }
    const first: unknown = Array.isArray(launchConfig.outbounds) ? launchConfig.outbounds[0] : null;
    this.tunnelTag = typeof first === "object" && first !== null && "tag" in first && typeof first.tag === "string" ? first.tag : null;
    const loopback = Object.entries(networkInterfaces()).find(([, addresses]) => addresses?.some((address) => address.address === "127.0.0.1"))?.[0];
    const configInput = Buffer.from(JSON.stringify(bindXrayOutboundInterface(launchConfig, interfaceName, outbound.ipv6, loopback)), "utf8");
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
      this.routing = typeof launchConfig.routing === "object" && launchConfig.routing !== null
        ? structuredClone(launchConfig.routing) as Record<string, unknown> : null;
      this.startStatsPolling();
    } catch (error) {
      await this.stop();
      throw error;
    } finally {
      configInput.fill(0);
    }
  }

  async stop(): Promise<void> {
    this.routing = null; this.selectedGameUdpRoute = null; this.gameUdpReady = false;
    this.gameUdpFallback = false; this.gameViaTunnel = false; this.tunnelTag = null;
    const multipath = this.multipath; this.multipath = null;
    await multipath?.stop();
    this.stopStatsPolling();
    const child = this.process;
    if (child) {
      this.stopping.add(child);
      await stopChild(child);
      if (this.process === child) this.process = null;
    }
    await this.tuic.stop();
    await this.gameTuic.stop();
  }

  tuicExecutablePath(): string {
    return this.tuic.executablePath();
  }

  isRunning(): boolean {
    return this.process !== null;
  }

  /** The game node multipath prefers as its first exit. The game's TCP never follows it:
   * it always takes the ordinary tunnel. */
  async selectGameRoute(index: number | null): Promise<void> {
    if (index !== null && (!Number.isInteger(index) || index < 0 || index >= 256)) throw new Error("Некорректный игровой маршрут");
    if (!this.process) throw new Error("Подключите VPN для выбора игрового маршрута");
    if (index !== null) this.multipath?.setPrimaryRoute(index);
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
    const now = Date.now();
    chunk.toString("utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean).forEach((raw) => {
      const line = raw.replace(/[\u0000-\u001f]/g, "");
      if (CORE_NOISE.test(line)) return;
      // One failing destination repeats per connection; the first line per 10 s tells the story.
      const key = line.replace(/^\S+ \S+ /, "").replace(/\[\d+\] /, "").replace(/^(from \S+?):\d+ /, "$1 ");
      const seen = this.repeatedLines.get(key);
      if (seen !== undefined && now - seen < 10_000) return;
      if (this.repeatedLines.size > 256) this.repeatedLines.clear();
      this.repeatedLines.set(key, now);
      this.emit("log", line);
    });
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

export async function updateXrayRouting(executable: string, endpoint: string, routing: Record<string, unknown>): Promise<void> {
  const bytes = Buffer.from(JSON.stringify({ routing }));
  const child = spawn(executable, ["api", "adrules", `--server=${endpoint}`], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
  try {
    await Promise.all([writeConfigInput(child, bytes), new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error("Game routing timeout")); }, 4_000);
      child.once("error", () => { clearTimeout(timer); reject(new Error("Game routing unavailable")); });
      child.once("exit", (code) => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error("Game routing rejected")); });
    })]);
  } finally { bytes.fill(0); if (child.exitCode === null) await stopChild(child); }
}
