import { utilityProcess, type UtilityProcess } from "electron";
import { constants, setPriority } from "node:os";
import { join } from "node:path";
import type { GameMultipathStats, GameRouteQuality, GameRuntimeSnapshot } from "../../../shared/contracts";
import { GameMultipath, type GameRouteCandidate, type GameRuntimeOptions } from "./client";
import type { DataPlaneEvent, DataPlaneRequest, GameConfigurableOptions, GameDataPlane, LoopbackIdentity, SerializableRuntimeOptions } from "./dataPlane";

const START_TIMEOUT_MS = 5_000;
const CALL_TIMEOUT_MS = 30_000;
/** Crashes inside this window beyond the limit leave the data plane down until reconnect. */
const RESTART_WINDOW_MS = 60_000;
const RESTART_LIMIT = 3;
const STDERR_TAIL_BYTES = 2_048;
/** Shown while the data plane has no state: no paths, no flows. */
const EMPTY_STATE: Extract<DataPlaneEvent, { type: "state" }> = {
  type: "state", idle: true, qualities: {},
  snapshot: { state: "unavailable", paths: [], receivedPackets: 0, duplicateReplies: 0, uploadedPackets: 0 },
  runtime: { currentMatch: null, lastMatch: null, exits: [], selectedExitId: null, selectionReason: null, ingressPaths: [],
    protection: { enabled: false, limitedByUpload: false, reason: null }, shadowAlternative: null, matchReport: null,
    estimateHistory: [], compatibility: "full" },
};

type Call = Extract<DataPlaneRequest, { type: "call" }>;
type CallMethod = Call["method"];
type Notify = Extract<DataPlaneRequest, { type: "notify" }>;

/** Game data plane in an Electron utility process (gameDataPlane.js). Reads are
 * served from the last pushed state, so XrayManager's synchronous API is kept. */
export class RemoteGameDataPlane implements GameDataPlane {
  private child: UtilityProcess | null = null;
  private nextId = 0;
  private readonly calls = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private readonly measurements = new Map<number, AbortController>();
  private state: Extract<DataPlaneEvent, { type: "state" }> | null = null;
  private identity: LoopbackIdentity | null = null;
  private connection: { candidates: GameRouteCandidate[]; password: string; options: GameRuntimeOptions | undefined } | null = null;
  private configured: GameConfigurableOptions = {};
  private playing = false; private counting = false; private primary: number | null = null;
  private stopped = false;
  private crashes: number[] = [];
  /** Bumped per restart so a restart overtaken by a newer crash leaves its successor alone. */
  private generation = 0;

  private constructor(private readonly entry: string, private readonly log: (line: string) => void,
    private readonly down: () => void) {}

  /** Falls back to the in-process data plane when the utility process cannot start.
   * `down` runs once when a crashed data plane cannot be brought back. */
  static async create(log: (line: string) => void, down: () => void = () => {}): Promise<GameDataPlane> {
    const plane = new RemoteGameDataPlane(join(__dirname, "gameDataPlane.js"), log, down);
    try { await plane.spawn(); return plane; } catch {
      plane.stopped = true; plane.discard(); log("Game: отдельный процесс маршрутизации недоступен; пакеты обрабатываются в основном процессе");
      const local = new GameMultipath(false); local.setLogger(log); return local;
    }
  }

  private spawn(): Promise<void> {
    const child = utilityProcess.fork(this.entry, [], { serviceName: "Levik Game data plane", stdio: ["ignore", "ignore", "pipe"] });
    // A native crash or out-of-memory leaves its reason only on stderr.
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => { stderr = (stderr + chunk.toString("utf8")).slice(-STDERR_TAIL_BYTES); });
    this.child = child;
    let started = false;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Game data plane did not start")), START_TIMEOUT_MS);
      child.once("spawn", () => {
        // Windows: HIGH_PRIORITY_CLASS for the process that forwards game packets.
        try { if (child.pid) setPriority(child.pid, constants.priority.PRIORITY_HIGH); } catch { /* Normal priority still works. */ }
      });
      child.on("message", (event: DataPlaneEvent) => {
        if (this.child !== child) return;
        if (event.type === "state" && !started) { started = true; clearTimeout(timer); this.state = event; resolve(); return; }
        this.receive(event);
      });
      child.once("exit", (code) => {
        clearTimeout(timer); reject(new Error("Game data plane exited"));
        if (this.child !== child) return;
        const reason = stderr.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(-3).join(" | ");
        if (reason) this.log(`Game: процесс маршрутизации: ${reason.slice(0, 600)}`);
        void this.crashed(code);
      });
    });
  }

  private receive(event: DataPlaneEvent): void {
    if (event.type === "state") { this.state = event; return; }
    if (event.type === "result") {
      const call = this.calls.get(event.id); if (!call) return;
      this.calls.delete(event.id); clearTimeout(call.timer);
      if (event.ok) call.resolve(event.value); else call.reject(new Error("Game data plane request failed"));
      return;
    }
    if (event.type === "measure") {
      const measure = this.connection?.options?.measureDirect; const abort = new AbortController();
      if (!measure) { this.post({ type: "measured", id: event.id, results: [] }); return; }
      this.measurements.set(event.id, abort);
      void measure(event.targets, abort.signal).catch(() => []).then((results) => {
        if (this.measurements.delete(event.id)) this.post({ type: "measured", id: event.id, results });
      });
      return;
    }
    if (event.type === "measure-abort") { this.measurements.get(event.id)?.abort(); this.measurements.delete(event.id); return; }
    if (event.type === "log") this.log(event.line);
  }

  /** A crash re-creates the same loopback identity; Xray keeps sending to it. */
  private async crashed(code: number): Promise<void> {
    this.child = null;
    for (const call of this.calls.values()) { clearTimeout(call.timer); call.reject(new Error("Game data plane exited")); }
    this.calls.clear();
    for (const abort of this.measurements.values()) abort.abort();
    this.measurements.clear();
    if (this.stopped) return;
    const now = Date.now(); this.crashes = [...this.crashes.filter((at) => now - at < RESTART_WINDOW_MS), now];
    if (this.crashes.length > RESTART_LIMIT || !this.identity) {
      this.log(`Game: процесс маршрутизации завершился (код ${code})`); this.giveUp(); return;
    }
    this.log(`Game: процесс маршрутизации перезапущен (код ${code}); текущие потоки открываются заново`);
    const generation = ++this.generation;
    try {
      await this.spawn();
      const identity = await this.request("listen", [this.identity]);
      // Xray keeps sending to the old port: any other one is as good as none.
      if (!isIdentity(identity) || identity.port !== this.identity.port) throw new Error("Game listener moved");
      this.replay();
      if (this.connection) await this.request("connect", [this.connection.candidates, this.connection.password, serializable(this.connection.options)]);
    } catch {
      if (generation !== this.generation || this.stopped) return;
      this.discard(); this.log("Game: не удалось перезапустить процесс маршрутизации"); this.giveUp();
    }
  }

  /** No data plane until reconnect: its last state goes too, and the owner moves the game elsewhere. */
  private giveUp(): void {
    this.stopped = true; this.state = null; this.connection = null;
    this.down();
  }

  /** Drops a child that never became usable without treating its exit as a crash. */
  private discard(): void { const child = this.child; this.child = null; child?.kill(); }

  private replay(): void {
    if (Object.keys(this.configured).length) this.notify({ type: "notify", method: "configure", args: [this.configured] });
    if (this.playing) this.notify({ type: "notify", method: "setPlaying", args: [true] });
    if (this.counting) this.notify({ type: "notify", method: "startCounting", args: [] });
    if (this.primary !== null) this.notify({ type: "notify", method: "setPrimaryRoute", args: [this.primary] });
  }

  private post(message: DataPlaneRequest): void { this.child?.postMessage(message); }
  private notify(message: Notify): void { this.post(message); }

  private request(method: "listen", args: [LoopbackIdentity | undefined]): Promise<unknown>;
  private request(method: "connect", args: [GameRouteCandidate[], string, SerializableRuntimeOptions | undefined]): Promise<unknown>;
  private request(method: "stop" | "pauseNewFlowsIfIdle", args: []): Promise<unknown>;
  private request(method: CallMethod, args: Call["args"]): Promise<unknown> {
    const child = this.child;
    if (!child) return Promise.reject(new Error("Game data plane unavailable"));
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.calls.delete(id); reject(new Error("Game data plane timed out")); }, CALL_TIMEOUT_MS);
      this.calls.set(id, { resolve, reject, timer });
      child.postMessage({ type: "call", id, method, args } as Call);
    });
  }

  async listen(preferred?: LoopbackIdentity): Promise<LoopbackIdentity> {
    const value = await this.request("listen", [preferred]);
    if (!isIdentity(value)) throw new Error("Game listener unavailable");
    this.identity = value; return value;
  }
  async connect(candidates: GameRouteCandidate[], password: string, options?: GameRuntimeOptions): Promise<void> {
    this.connection = { candidates, password, options };
    await this.request("connect", [candidates, password, serializable(options)]);
  }
  async stop(): Promise<void> {
    this.stopped = true; this.connection = null;
    const child = this.child;
    if (!child) return;
    try { await this.request("stop", []); } catch { /* Exiting below either way. */ }
    this.child = null; child.kill();
  }
  snapshot(): GameMultipathStats { return this.current().snapshot; }
  runtimeSnapshot(): GameRuntimeSnapshot { return this.current().runtime; }
  routeQualities(): Record<number, GameRouteQuality> { return this.current().qualities; }
  refreshMeasurements(): void { this.notify({ type: "notify", method: "refreshMeasurements", args: [] }); }
  setPlaying(active: boolean): void { this.playing = active; this.notify({ type: "notify", method: "setPlaying", args: [active] }); }
  /** Decided from the last state (at most STATE_INTERVAL_MS old); the data plane
   * re-checks atomically and keeps accepting flows if one started meanwhile. */
  pauseNewFlowsIfIdle(): boolean {
    if (!this.current().idle) return false;
    void this.request("pauseNewFlowsIfIdle", []).catch(() => {});
    return true;
  }
  resumeNewFlows(): void { this.notify({ type: "notify", method: "resumeNewFlows", args: [] }); }
  configure(options: GameConfigurableOptions): void {
    this.configured = { ...this.configured, ...options };
    this.notify({ type: "notify", method: "configure", args: [options] });
  }
  startCounting(): void { this.counting = true; this.notify({ type: "notify", method: "startCounting", args: [] }); }
  setPrimaryRoute(index: number): void { this.primary = index; this.notify({ type: "notify", method: "setPrimaryRoute", args: [index] }); }

  private current(): Extract<DataPlaneEvent, { type: "state" }> { return this.state ?? EMPTY_STATE; }
}

function serializable(options: GameRuntimeOptions | undefined): SerializableRuntimeOptions | undefined {
  if (!options) return undefined;
  const { measureDirect, ...rest } = options;
  return { ...rest, measureDirect: Boolean(measureDirect) };
}
function isIdentity(value: unknown): value is LoopbackIdentity {
  return typeof value === "object" && value !== null && "port" in value && "uuid" in value
    && typeof value.port === "number" && typeof value.uuid === "string";
}
