import { ServiceRouteSession } from "./serviceRouteSession";
import type { ServiceRouteStatus } from "./serviceRoutes";
import { app } from "electron";
import { execFile, spawn } from "node:child_process";
import type { ChildProcess, ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { parseXrayStats, XRAY_STATS_ENDPOINT } from "./xrayStats";
import { bindXrayOutboundInterface, gameRoutingRules, isGameRule, ordinaryTunnelTag, GAME_MULTIPATH, GAME_UDP_BALANCER } from "./xrayConfig";
import type { GameRouteCandidate, GameRuntimeOptions } from "./multipath/client";
import type { GameConfigurableOptions, GameDataPlane } from "./multipath/dataPlane";
import { RemoteGameDataPlane } from "./multipath/remote";
import { networkInterfaces } from "node:os";
import { findWindowsOutboundInterface } from "../windows/outboundInterface";
import { TuicSidecar, withTuicProxy } from "./tuicSidecar";
import type { TuicEndpoint, GameMultipathStats, GameRuntimeSnapshot, GameRouteQuality } from "../../shared/contracts";
import { GAME_BLOCK, gameTag } from "./gameRoutes";
import type { AppSettings } from "../../shared/contracts";

const execFileAsync = promisify(execFile);

/** Per-connection Xray info chatter: it would push every app event out of the 200-line journal. */
const CORE_NOISE = /\b(?:proxy\/tun: processing from|app\/dispatcher: sniffed domain|app\/dispatcher: default route for|transport\/internet\/splithttp: XHTTP is dialing|proxy\/vless\/outbound: tunneling request|transport\/internet\/tcp: dialing TCP to|proxy\/dns: handling DNS traffic|app\/dispatcher: taking detour \[levik-dns-out\])/;

interface XrayEvents {
  serviceRoutes: [status: ServiceRouteStatus];
  log: [line: string];
  exit: [code: number | null, expected: boolean];
  stats: [downloadBytes: number, uploadBytes: number];
  /** The game data plane is gone for good; the game was moved to the ordinary VPN (or could not be). */
  gameDown: [movedToTunnel: boolean];
}

export class XrayManager extends EventEmitter<XrayEvents> {
  readonly serviceRoutes = new ServiceRouteSession((status) => this.emit("serviceRoutes", status));
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
    await execFileAsync(this.executablePath(), ["api", "bo", `--server=${this.routingEndpoint()}`, "-b", GAME_UDP_BALANCER, tag],
      { windowsHide: true, timeout: 4_000, maxBuffer: 16 * 1024, ...(this.apiEnvironment() ? { env: this.apiEnvironment() } : {}) });
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
    await execFileAsync(this.executablePath(), ["api", "bo", `--server=${this.routingEndpoint()}`, "-b", GAME_UDP_BALANCER,
      index === null ? GAME_MULTIPATH : gameTag(index)], { windowsHide: true, timeout: 4_000, maxBuffer: 16 * 1024, ...(this.apiEnvironment() ? { env: this.apiEnvironment() } : {}) });
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
    // Rebuilt in place, Game's rules are contiguous: a game with known match ports has its own rule.
    const at = routing.rules.findIndex(isGameRule);
    if (at >= 0) {
      const multipath = Array.isArray(routing.balancers) && routing.balancers.some((balancer: unknown) => typeof balancer === "object" && balancer !== null && "tag" in balancer && balancer.tag === GAME_UDP_BALANCER);
      const rest = routing.rules.filter((rule: unknown) => !isGameRule(rule));
      routing.rules = [...rest.slice(0, at), ...gameRoutingRules(settings, multipath), ...rest.slice(at)];
    }
    if (Array.isArray(routing.balancers)) for (const balancer of routing.balancers) {
      if (!balancer || typeof balancer !== "object" || !("tag" in balancer)) continue;
      const serviceTarget = typeof balancer.tag === "string" ? this.serviceRoutes.selectedTarget(balancer.tag) : undefined;
      if (serviceTarget) Object.assign(balancer, { selector: [serviceTarget] });
      if (balancer.tag === GAME_UDP_BALANCER) Object.assign(balancer, { selector: [this.gameViaTunnel && this.tunnelTag ? this.tunnelTag
        : !this.gameUdpReady ? GAME_BLOCK : this.selectedGameUdpRoute === null ? GAME_MULTIPATH : gameTag(this.selectedGameUdpRoute)] });
    }
    try {
      await updateXrayRouting(this.executablePath(), this.routingEndpoint(), routing, this.apiEnvironment());
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

  /** shouldContinue: false once the caller no longer wants this tunnel, so a retry is never started for it. */
  async start(config: Record<string, unknown>, tuic?: TuicEndpoint, gameTuic: Array<{ tag: string; endpoint: TuicEndpoint }> = [],
    shouldContinue: () => boolean = () => true): Promise<void> {
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
    this.tunnelTag = ordinaryTunnelTag(launchConfig);
    const loopback = Object.entries(networkInterfaces()).find(([, addresses]) => addresses?.some((address) => address.address === "127.0.0.1"))?.[0];
    const configInput = Buffer.from(JSON.stringify(bindXrayOutboundInterface(launchConfig, interfaceName, outbound.ipv6, loopback)), "utf8");
    this.emit("log", `Xray: outbound interface [${interfaceName}] (TCP/UDP, direct, IPv6 ${outbound.ipv6 ? "on" : "off"})`);
    try {
      await this.validate(configInput);
      for (let attempt = 1; ; attempt++) {
        try {
          await this.launch(configInput);
          break;
        } catch (error) {
          // A core killed moments ago may still hold its Wintun adapter: Windows
          // removes it asynchronously, and the new core cannot create it until then.
          if (!(error instanceof CoreStartError) || !error.retryable || attempt >= CORE_START_ATTEMPTS || !shouldContinue()) throw error;
          this.emit("log", `Xray: ядро не запустилось, повтор через ${attempt} с`);
          await delay(attempt * 1_000);
          if (!shouldContinue()) throw error;
        }
      }
      this.routing = typeof launchConfig.routing === "object" && launchConfig.routing !== null
        ? structuredClone(launchConfig.routing) as Record<string, unknown> : null;
      try { await this.serviceRoutes.start(config); }
      catch (error) { await this.stop(); throw error; }
      this.startStatsPolling();
    } catch (error) {
      await this.stop();
      throw error;
    } finally {
      configInput.fill(0);
    }
  }

  /** One core process, resolved once Xray reports every inbound, the TUN included, started. */
  private async launch(configInput: Buffer): Promise<void> {
    const child = spawn(this.executablePath(), xrayConfigArguments(false), {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, XRAY_LOCATION_ASSET: this.assetDirectory() },
    });
    this.process = child;
    // Listeners first: a core that fails at once must not lose its reason.
    const startup = waitForStartup(child);
    child.stdout.on("data", (chunk: Buffer) => this.emitLines(chunk));
    child.stderr.on("data", (chunk: Buffer) => this.emitLines(chunk));
    child.once("error", (error) => this.emit("log", `Xray: ${error.message}`));
    child.once("exit", (code) => {
      if (this.process !== child) return;
      this.stopStatsPolling();
      this.serviceRoutes.stop();
      const expected = this.stopping.has(child);
      this.process = null;
      this.emit("exit", code, expected);
    });
    try {
      // A core that exits mid-write breaks the pipe: its own reason explains more than EPIPE.
      const [started, written] = await Promise.allSettled([startup, writeConfigInput(child, configInput)]);
      if (started.status === "rejected") throw started.reason;
      if (written.status === "rejected") throw written.reason;
    } catch (error) {
      if (this.process === child) {
        this.stopping.add(child);
        await stopChild(child);
        if (this.process === child) this.process = null;
      }
      throw error;
    }
  }

  async stop(): Promise<void> {
    this.serviceRoutes.stop();
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

  private routingEndpoint(): string { return this.serviceRoutes.authentication ? "levik-service-api:80" : XRAY_STATS_ENDPOINT; }
  private apiEnvironment(): NodeJS.ProcessEnv | undefined {
    const auth = this.serviceRoutes.authentication;
    if (!auth) return undefined;
    const proxy = `http://${auth.user}:${auth.password}@127.0.0.1:${auth.port}`;
    return { ...process.env, HTTPS_PROXY: proxy, HTTP_PROXY: proxy, https_proxy: proxy, http_proxy: proxy, NO_PROXY: "", no_proxy: "" };
  }

  async isHealthy(): Promise<boolean> {
    const child = this.process;
    if (!child) return false;
    try {
      if (this.serviceRoutes.authentication) {
        if (this.serviceRoutes.active) await this.serviceRoutes.queryStats();
        const healthy = this.serviceRoutes.active || await this.serviceRoutes.probeCurrent();
        return this.process === child && healthy;
      }
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
      if (this.serviceRoutes.authentication) {
        const stats = await this.serviceRoutes.queryStats();
        if (this.process === child) this.emit("stats", stats.downlink, stats.uplink);
        return;
      }
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

/** A core start failure the controller can explain; retryable when the same start may work a moment later. */
export class CoreStartError extends Error {
  constructor(message: string, readonly retryable: boolean) {
    super(message);
    this.name = "CoreStartError";
  }
}

const CORE_START_ATTEMPTS = 3;
/** Creating the Wintun adapter takes seconds, and much longer while an antivirus inspects the driver. */
export const CORE_START_TIMEOUT_MS = 45_000;
const CORE_STARTED = /\bXray \S+ started\b/;
const CORE_START_FAILED = /\bFailed to start: (.+)/;

/**
 * Resolves on Xray's own "started" line: it is written after every inbound,
 * the TUN included, has started. A fixed delay took a core that was still
 * creating its adapter for a running one and blamed its later exit on an antivirus.
 */
export async function waitForStartup(child: ChildProcess, timeoutMs = CORE_START_TIMEOUT_MS): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let reason: string | null = null;
    let pending = "";
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      child.off("error", onError);
      child.stdout?.off("data", onData);
      child.stderr?.off("data", onData);
      if (error) reject(error);
      else resolve();
    };
    const onData = (chunk: Buffer | string): void => {
      const lines = `${pending}${chunk.toString()}`.split(/\r?\n/);
      pending = (lines.pop() ?? "").slice(-4_096);
      for (const line of lines) {
        const failed = CORE_START_FAILED.exec(line);
        if (failed?.[1]) reason = failed[1].trim();
        else if (CORE_STARTED.test(line)) finish();
      }
    };
    const onExit = (code: number | null): void => {
      if (pending) onData("\n");
      finish(startupExitError(code, reason));
    };
    const onError = (): void => finish(new CoreStartError(
      "Windows не дал запустить ядро VPN (xray.exe). Чаще всего его блокирует или удаляет антивирус: добавьте папку Levik VPN в исключения и подключитесь снова.",
      false,
    ));
    const timer = setTimeout(() => finish(new CoreStartError(
      "Ядро VPN слишком долго создаёт сетевой адаптер. Подключитесь снова; если не поможет, перезагрузите компьютер.",
      false,
    )), timeoutMs);
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

/** Xray exits with 23 on a configuration it cannot load and with -1 when an inbound, such as the TUN, fails to start. */
export function startupExitError(code: number | null, reason: string | null): CoreStartError {
  const failedToStart = code === -1 || code === 4294967295;
  if (failedToStart && reason) {
    if (/wintun|\btun\b|adapter|already exists/i.test(reason)) {
      return new CoreStartError("Windows ещё не освободил сетевой адаптер Levik VPN. Подключитесь снова через несколько секунд; если не поможет, перезагрузите компьютер.", true);
    }
    if (/only one usage of each socket address|address already in use|access a socket in a way forbidden|bind/i.test(reason)) {
      return new CoreStartError("Нужный ядру VPN локальный порт занят другой программой.", true);
    }
    return new CoreStartError("Ядро VPN не смогло запуститься на этом компьютере. Подробности — в журнале приложения.", true);
  }
  // Without its own message, -1 is a process ended from outside, usually by an antivirus.
  if (failedToStart) {
    return new CoreStartError("Ядро VPN было остановлено при запуске, скорее всего антивирусом. Добавьте папку Levik VPN в исключения антивируса и подключитесь снова.", false);
  }
  if (code === 23) return new CoreStartError("Ядро VPN отклонило конфигурацию. Обновите приложение или выберите другой сервер.", false);
  return new CoreStartError(`Ядро VPN завершилось при запуске (код ${code ?? "unknown"})`, false);
}

function delay(ms: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

export async function updateXrayRouting(executable: string, endpoint: string, routing: Record<string, unknown>, environment?: NodeJS.ProcessEnv): Promise<void> {
  const bytes = Buffer.from(JSON.stringify({ routing }));
  const child = spawn(executable, ["api", "adrules", `--server=${endpoint}`], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"], ...(environment ? { env: environment } : {}) });
  try {
    await Promise.all([writeConfigInput(child, bytes), new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error("Game routing timeout")); }, 4_000);
      child.once("error", () => { clearTimeout(timer); reject(new Error("Game routing unavailable")); });
      child.once("exit", (code) => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error("Game routing rejected")); });
    })]);
  } finally { bytes.fill(0); if (child.exitCode === null) await stopChild(child); }
}
