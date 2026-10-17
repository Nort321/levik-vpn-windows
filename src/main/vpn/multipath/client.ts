import { createServer, type Server, type Socket } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { DeliveryEvidence } from "./delivery";
import { DelayQueue, FecDecoder, FecEncoder, FEC_FLUSH_MS } from "./fec";
import { openRelayPath, type RelayPath } from "./socks";
import { decode, encode, Kind, MAX_PAYLOAD, MAX_PATHS, SequenceWindow, controlPayload, parseControl, newFlow, newSession,
  parseCapabilities, parseMeasurement, isRecord, nodeTag, publicIPv4, tagResolver, validNodeId, PING_ACTIVE, PING_FEC, PING_SPREAD,
  type Packet, type ProbeTarget, type ProbeMeasurement, type RelayCapabilities, type TagResolver } from "./wire";
import { QualityWindow, FastQuality, MeasurementHistory, chooseExit, chooseIngress, classifyFlow, estimateExit, GAME_POLICY, UploadQueueGuard, subnet24, byLatency,
  type DestinationMetric, type FlowKind, type ExitCandidate, type PathEstimate, type Segment } from "../gameEngine";
import type { GameExitScope } from "../../../shared/games";
import type { GameMultipathStats, GameNode, GameRuntimeSnapshot, GameExitComparison, GameMatchReport, GameMatchServer, GameRouteQuality, GameRouteDecision } from "../../../shared/contracts";

export interface GameRuntimeOptions {
  nodes: GameNode[]; preferredExitId: string | null; protection: boolean; exitScope: GameExitScope; gameId?: string;
  directSourceAddress?: string; directSocksPort?: number;
  measureDirect?: (targets: ProbeTarget[], signal: AbortSignal) => Promise<ProbeMeasurement[]>;
  history?: Array<{ gameId: string; subnet: string; region: string | null; nodeId: string; updatedAt: number }>;
}
/** One authenticated route to the relay. `reliable` marks UDP carried in a TCP/HTTP stream. */
export interface GameRouteCandidate { index: number; port: number; nodeId?: string; reliable?: boolean }
interface Path { index: number; slot: number; pathSlot: number; session: Buffer; port: number; epoch: number; accepted: boolean; active: boolean; spread: boolean; repairing: boolean;
  transport: RelayPath; instance: string | null; latencyMs: number | null; lastReply: number;
  /** First ping sent since the last reply: silence is measured from when the path was asked, not from its last answer. */
  awaitingSince: number | null; lastLatencyMs: number | null; sent: Map<number, number>; wins: number; recentWins: number; misses: number;
  entryNodeId: string; exitNodeId: string; modern: boolean; mesh: boolean; caps: RelayCapabilities; quality: QualityWindow; fast: FastQuality;
  cpuPercent: number; networkBytesPerSecond: number; activeFlows: number; probe: boolean; reliable: boolean }
/** Relay-side identity of one client socket at one exit. With endpoint-independent mapping
 * every destination of that socket shares one external IP:port at the exit. */
interface Wire { id: Buffer; key: string; sequence: number; seen: SequenceWindow; exitId: string; instance: string; session: Buffer | null;
  connection: Connection; flows: Map<string, Flow>; encoder: FecEncoder; decoder: FecDecoder; flushTimer: ReturnType<typeof setTimeout> | null;
  evidence: DeliveryEvidence }
interface Connection { socket: Socket; xudp: boolean; flows: Map<string, Flow>; wires: Map<string, Wire>; exitId: string | null; touched: number }
interface Hold { waiting: Set<string>; timer: ReturnType<typeof setTimeout> }
interface Flow { id: string; connection: Connection; address: string; port: number; counted: boolean;
  startedAt: number; touched: number; sent: number; received: number; exitId: string; instance: string | null; wire: Wire | null; direct: RelayPath | null;
  pending: Buffer[]; hold: Hold | null; held: boolean; kind: FlowKind; latencyHistory: number[]; lowerBoundSamples: boolean; evidence: DeliveryEvidence; gameId: string;
  decision: (GameRouteDecision & { selectedAt: number }) | null; protectionRequested: boolean; maxPathCount: number; noPathSince: number | null;
  /** Last second with match-rate traffic; a long-quiet flow may follow a better exit. */
  lastBusyAt: number; sentAtTick: number; reopenReason: string | null; finished: boolean;
  /** Once a flow carried match-rate traffic it is a game connection: it never moves to another exit while alive. */
  busy: boolean; recovered: number;
  /** Replies each path delivered first, keyed by route index and entry node. */
  pathPackets: Map<string, { routeIndex: number; entryNodeId: string; packets: number }> }
const emptyOptions = (): GameRuntimeOptions => ({ nodes: [], preferredExitId: null, protection: true, exitScope: "flow" });
const NO_CAPS: RelayCapabilities = parseCapabilities({});
const ACTIVE_MATCH_MS = 5_000;
/** Below the relay's 60 s session idle timeout with room for two lost pings. */
const IDLE_PING_MS = 20_000;
const IDLE_FRESH_MS = 65_000;
/** While a game is busy, a path asked and silent this long is gone. */
const ACTIVE_SILENCE_MS = 6_000;
export const GAME_FLOW_LIMITS = Object.freeze({ perConnection: 256, total: 1024, connections: 128 });
/** A connection silent this long may give its place to a new one when the bridge is full. */
const EVICT_IDLE_MS = 2_000;
const REGIONS_INTERVAL_MS = 30_000;

/** UDP observation, selection and replication share one bridge in both protection modes. */
export class GameMultipath {
  constructor(private counting = true) {}
  private log: (line: string) => void = () => {};
  /** Flow re-decisions go to the app log: they explain a game's disconnects. */
  setLogger(log: (line: string) => void): void { this.log = log; }
  startCounting(): void { this.counting = true; }
  private readonly session = newSession(randomBytes(8));
  private readonly exitSessions = new Map<string, Buffer>();
  private readonly nodeAliases = new Map<string, string>();
  private readonly nodeCaps = new Map<string, RelayCapabilities>();
  private readonly openingSlots = new Set<number>();
  private readonly preparingMesh = new Set<string>();
  private readonly exitPathCounts = new Map<string, number>();
  private readonly flows = new Map<string, Flow>();
  private readonly wires = new Map<string, Wire>();
  private readonly connections = new Set<Connection>();
  private acceptingNewFlows = true;
  private paths: Path[] = [];
  private abort = new AbortController();
  private server: Server | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private fastTimer: ReturnType<typeof setInterval> | null = null;
  private pingSequence = 0; private controlSequence = 0x80000000;
  private received = 0; private duplicates = 0; private uploaded = 0; private recovered = 0;
  private relayInstance: string | null = null; private password = "";
  private options = emptyOptions(); private playing = false; private lastProbeAt = 0; private lastIdlePingAt = 0; private lastPacketAt = 0;
  private resolve: TagResolver = () => undefined;
  private readonly destinations = new Map<string, ProbeTarget>();
  private readonly meshRows = new Map<string, Array<{ nodeId: string; quality: Segment }>>();
  private readonly measurements = new Map<string, DestinationMetric[]>();
  private readonly anchors = new Map<string, DestinationMetric[]>();
  private readonly regionsRequestedAt = new Map<string, number>();
  private readonly probeStates = new Map<string, "collecting" | "service-unavailable">();
  private readonly queries = new Map<string, { session: Buffer; targets: Set<string>; handshake: boolean }>();
  private readonly directMeasurements = new Map<string, Segment>();
  private readonly directHistory = new Map<string, MeasurementHistory>();
  private readonly holds = new Set<Flow>();
  private readonly delays = new DelayQueue(() => performance.now());
  private lastDirectProbeAt = -Infinity;
  private measuringDirect = false; private sessionExit: string | null = null; private lastExit: string | null = null;
  private primaryExitId: string | null = null;
  private readonly uploadGuard = new UploadQueueGuard(); private uploadBytes = 0; private limitedByUpload = false;
  private lastMatch: GameRuntimeSnapshot["lastMatch"] = null; private matchReport: GameMatchReport | null = null;
  private readonly estimateHistory: GameRuntimeSnapshot["estimateHistory"] = [];
  private estimateFlowId: string | null = null;

  private canonical(id: string): string {
    for (let i = 0; i < 4 && this.nodeAliases.has(id); i++) id = this.nodeAliases.get(id)!;
    return id;
  }
  private node(id: string): GameNode | undefined {
    const values = this.options.nodes.filter((node) => this.canonical(node.nodeId) === this.canonical(id));
    return values.sort((a, b) => Number(a.state === "enabled") - Number(b.state === "enabled"))[0];
  }
  private alias(previous: string, canonical: string): void {
    if (previous === canonical) return;
    this.nodeAliases.set(previous, canonical);
    if (this.lastExit === previous) this.lastExit = canonical;
    if (this.sessionExit === previous) this.sessionExit = canonical;
    if (this.primaryExitId === previous) this.primaryExitId = canonical;
    const query = this.queries.get(previous); if (query && !this.queries.has(canonical)) this.queries.set(canonical, query);
    const caps = this.nodeCaps.get(previous); if (caps && !this.nodeCaps.has(canonical)) this.nodeCaps.set(canonical, caps);
    for (const flow of this.flows.values()) if (flow.exitId === previous) {
      flow.exitId = canonical;
      if (flow.decision) flow.decision.exitId = canonical;
    }
    for (const wire of this.wires.values()) if (wire.exitId === previous) wire.exitId = canonical;
    for (const connection of this.connections) if (connection.exitId === previous) connection.exitId = canonical;
    this.rebuildResolver();
  }
  private rebuildResolver(): void {
    try { this.resolve = tagResolver(new Set([...this.options.nodes.map((node) => node.nodeId), ...this.paths.flatMap((path) => path ? [path.exitNodeId, path.entryNodeId] : [])]
      .values()).values()); } catch { this.resolve = () => undefined; }
  }
  private normalizeSessions(): boolean {
    let changed = false;
    const groups = new Map<string, Path[]>();
    for (const path of this.paths) if (path?.accepted && path.instance) {
      // Old relays have no node metadata; their random instance is still a
      // trustworthy convergence identity discovered through authenticated tunnels.
      if (path.exitNodeId.startsWith("legacy-")) {
        const canonical = `legacy-${path.instance}`; this.alias(path.exitNodeId, canonical);
        path.entryNodeId = path.exitNodeId = canonical;
      }
      groups.set(path.exitNodeId, [...(groups.get(path.exitNodeId) ?? []), path]);
    }
    for (const [exit, values] of groups) {
      const ranked = values.sort(byLatency);
      const session = this.exitSessions.get(exit) ?? ranked[0]!.session; this.exitSessions.set(exit, session);
      for (const [slot, path] of ranked.entries()) {
        if (slot >= MAX_PATHS) { path.accepted = false; path.transport.close(); continue; }
        if (!path.session.equals(session) || path.pathSlot !== slot) changed = true;
        path.session = session; path.pathSlot = slot; path.sent.clear();
      }
      this.exitPathCounts.set(exit, Math.min(MAX_PATHS, values.length));
    }
    return changed;
  }
  setPlaying(active: boolean): void {
    if (this.playing && !active) this.sessionExit = null;
    const starting = active && !this.playing;
    if (starting) this.lastProbeAt = 0;
    this.playing = active;
    // A game is starting: confirm every path now instead of on the next tick.
    if (starting) this.ping();
  }
  configure(options: Partial<Pick<GameRuntimeOptions, "protection" | "preferredExitId" | "exitScope" | "gameId" | "history" | "nodes">>): void {
    this.options = { ...this.options, ...options }; if (options.nodes) this.rebuildResolver(); this.selectActive();
  }
  /** No counted flow is pinned to an exit: reconnecting now interrupts no game. */
  idle(): boolean { return ![...this.flows.values()].some((flow) => flow.counted && flow.exitId); }
  pauseNewFlowsIfIdle(): boolean {
    if (!this.idle()) return false;
    this.acceptingNewFlows = false; return true;
  }
  resumeNewFlows(): void { this.acceptingNewFlows = true; }
  setPrimaryRoute(index: number): void {
    const path = this.paths.find((path) => path?.index === index && path.entryNodeId === path.exitNodeId && path.accepted);
    if (path) this.primaryExitId = path.exitNodeId;
  }
  /** A path is usable while it answers. Idle paths are pinged only every IDLE_PING_MS, so a
   * path that answered its last ping stays usable until it has been asked again and kept
   * silent for the window; a game starting after idle time never finds every path stale. */
  private fresh(path: Path): boolean {
    const now = performance.now();
    return now - path.lastReply < IDLE_FRESH_MS && (path.awaitingSince === null || now - path.awaitingSince < this.silenceLimit());
  }
  private silenceLimit(): number { return this.playing || Date.now() - this.lastPacketAt < 5_000 ? ACTIVE_SILENCE_MS : IDLE_FRESH_MS; }
  routeQualities(): Record<number, GameRouteQuality> {
    return Object.fromEntries(this.paths.filter((path) => path?.accepted && !path.transport.closed && this.fresh(path)
      && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples && path.entryNodeId === path.exitNodeId)
      .map((path) => [path.index, path.quality.snapshot()]));
  }
  refreshMeasurements(): void {
    if (this.abort.signal.aborted || Date.now() - this.lastProbeAt < 1000) return;
    this.lastProbeAt = Date.now(); this.selectActive(); this.ping(); this.requestMeasurements();
  }
  snapshot(): GameMultipathStats {
    const paths = this.paths.filter((path) => path !== undefined);
    const activeCounts = new Map<string, number>();
    for (const path of paths) if (path.active && this.fresh(path))
      activeCounts.set(`${path.exitNodeId}:${path.instance}`, (activeCounts.get(`${path.exitNodeId}:${path.instance}`) ?? 0) + 1);
    const copies = this.lastExit === "direct" ? Number([...this.flows.values()].some((flow) => flow.direct && !flow.direct.closed))
      : this.lastExit ? Math.max(0, ...[...activeCounts].filter(([key]) => key.startsWith(`${this.lastExit}:`)).map(([, count]) => count)) : Math.max(0, ...activeCounts.values());
    return { state: copies >= 2 ? "protected" : copies === 1 ? "single" : "unavailable",
      paths: paths.map((p) => ({ routeIndex: p.index, latencyMs: p.latencyMs,
        responding: p.accepted && this.fresh(p), active: p.active, firstReplies: p.wins })),
      receivedPackets: this.received, duplicateReplies: this.duplicates, uploadedPackets: this.uploaded, recoveredPackets: this.recovered };
  }
  private activeMatchFlows(): Flow[] {
    const now = Date.now();
    return [...this.flows.values()].filter((flow) => flow.counted && flow.kind === "match" && now - flow.touched < ACTIVE_MATCH_MS)
      .sort((a, b) => b.received - a.received);
  }
  private activePaths(wire: Wire | null): Path[] {
    if (!wire) return [];
    return this.paths.filter((path) => path?.accepted && path.active && path.exitNodeId === wire.exitId && path.instance === wire.instance
      && !path.transport.closed && this.fresh(path));
  }
  /** Every usable path to the wire's exit process, active or not. */
  private exitPaths(wire: Wire | null): Path[] {
    if (!wire) return [];
    return this.paths.filter((path): path is Path => Boolean(path?.accepted && path.exitNodeId === wire.exitId && path.instance === wire.instance
      && !path.transport.closed));
  }
  private livePaths(exitId: string): Path[] {
    return this.paths.filter((path) => path?.accepted && path.exitNodeId === exitId && !path.transport.closed && this.fresh(path)
      && path.instance !== null);
  }
  runtimeSnapshot(): GameRuntimeSnapshot {
    const activeMatches = this.activeMatchFlows(); const current = activeMatches[0];
    const target = current ? { address: current.address, port: current.port } : this.lastMatch;
    const exits = target ? this.comparisons(target) : [];
    const estimates = target ? this.estimates(target) : [];
    const next = target ? this.decideExit(target, true) : null;
    const better = next?.estimate ?? null;
    const selected = estimates.find((exit) => exit.nodeId === current?.exitId);
    const metadata = current ? this.measurements.get(current.exitId)?.find((item) => item.address === current.address && item.port === current.port)?.metric : null;
    const currentPaths = current ? this.activePaths(current.wire) : [];
    const pathCount = current ? current.exitId === "direct" ? Number(Boolean(current.direct && !current.direct.closed)) : currentPaths.length : 0;
    const fec = Boolean(current && current.exitId !== "direct" && this.options.protection && this.nodeCaps.get(current.exitId)?.fec);
    const protectionReason = !current ? "Нет активного UDP-потока матча"
      : current.exitId === "direct" ? "Прямой путь: резервные копии через Levik не используются"
      : !this.options.protection ? "Дублирование выключено"
      : this.limitedByUpload ? "Похоже на очередь отдачи: временно оставлен один путь, затем защита проверится снова"
      : pathCount < 2 ? fec ? "Один рабочий путь: потери закрывает избыточный код" : "Для текущего потока нет двух рабочих путей" : null;
    return { ...(current ? { gameId: current.gameId } : {}), activeFlowCount: [...this.flows.values()].filter((flow) => flow.counted && flow.exitId).length,
      currentMatch: current ? { address: current.address, port: current.port,
        ...(metadata?.region ? { region: metadata.region } : {}), ...(metadata?.operator ? { operator: metadata.operator } : {}) } : null,
      lastMatch: this.lastMatch, exits, selectedExitId: current?.exitId ?? this.lastExit,
      routeDecision: current?.decision ? { ...current.decision } : null, nextRouteDecision: next?.decision ?? null,
      activeMatchFlowCount: activeMatches.length, mixedMatchExits: new Set(activeMatches.map((flow) => flow.exitId)).size > 1,
      selectionReason: this.options.exitScope === "session" && this.sessionExit && Boolean(this.node(this.sessionExit) && this.node(this.sessionExit)!.state !== "enabled")
        ? "Выход завершает текущие потоки; новые потоки этой игры ждут её перезапуска" : current?.decision?.reason ?? null,
      ingressPaths: this.paths.filter(Boolean).map((path) => ({ routeId: String(path.index), entryNodeId: path.entryNodeId, exitNodeId: path.exitNodeId,
        latencyMs: path.latencyMs, active: currentPaths.includes(path) })),
      protection: { enabled: this.options.protection, limitedByUpload: this.limitedByUpload,
        effective: this.options.protection && (pathCount >= 2 || fec), pathCount, reason: protectionReason, fec },
      shadowAlternative: better && selected && selected.evidence === "endpoint" && better.evidence === "endpoint" && selected.confidence === better.confidence
        && better.nodeId !== selected.nodeId && selected.latencyMs !== null && better.latencyMs !== null
        && selected.latencyMs > better.latencyMs
        ? { nodeId: better.nodeId, name: exits.find((exit) => exit.nodeId === better.nodeId)?.name ?? better.nodeId,
          savingMs: Math.max(0, Math.round(selected.latencyMs - better.latencyMs)) } : null,
      matchReport: this.matchReport, liveMatchReport: current ? this.report(current) : null, estimateHistory: [...this.estimateHistory],
      compatibility: current?.exitId === "direct" || this.paths.some((path) => (!current || path.exitNodeId === current.exitId) && path.modern) ? "full" : "legacy",
      meshRows: [...this.meshRows].map(([nodeId, neighbors]) => ({ nodeId, neighbors: [...neighbors] })) };
  }
  /** `preferred` re-creates the same loopback identity after a data-plane restart:
   * the running Xray core keeps pointing at that port and UUID. */
  async listen(preferred?: { port: number; uuid: string }): Promise<{ port: number; uuid: string }> {
    const uuid = preferred?.uuid ?? randomUUID(); const identity = Buffer.from(uuid.replaceAll("-", ""), "hex");
    this.server = createServer((socket) => {
      // Xray opens one connection per game socket, and games open many short-lived ones
      // (VALORANT pings every region from a fresh socket each second). Refusing the
      // newest would refuse the match itself: the longest-silent connection goes instead.
      if (this.connections.size >= GAME_FLOW_LIMITS.connections && !this.evictConnection()) { socket.destroy(); return; }
      const connection: Connection = { socket, xudp: false, flows: new Map(), wires: new Map(), exitId: null, touched: Date.now() };
      this.connections.add(connection); socket.setNoDelay(true); socket.setTimeout(60_000, () => socket.destroy());
      let buffer: Buffer = Buffer.alloc(0); let mode: "udp" | "xudp" | null = null;
      let target: { address: string; port: number } | null = null;
      socket.on("error", () => {});
      socket.on("close", () => {
        this.connections.delete(connection);
        for (const flow of connection.flows.values()) this.dropFlow(flow);
      });
      const forward = (payload: Buffer): void => {
        if (!target) { socket.destroy(); return; }
        const key = `${target.address}:${target.port}`;
        let flow = connection.flows.get(key);
        if (!flow || flow.finished) {
          if (!this.acceptingNewFlows) return;
          if (!this.admitFlow(connection)) return;
          flow = { id: randomBytes(8).toString("hex"), connection, ...target, counted: this.counting, startedAt: Date.now(), touched: Date.now(), sent: 0, received: 0,
            exitId: "", instance: null, wire: null, direct: null, pending: [], hold: null, held: false, kind: "service", latencyHistory: [], lowerBoundSamples: false,
            evidence: new DeliveryEvidence(), gameId: this.options.gameId ?? "custom", finished: false, decision: null,
            protectionRequested: this.options.protection, maxPathCount: 0, noPathSince: null, lastBusyAt: Date.now(), sentAtTick: 0, reopenReason: null, busy: false, recovered: 0, pathPackets: new Map() };
          connection.flows.set(key, flow); this.flows.set(flow.id, flow);
        }
        connection.touched = Date.now();
        this.forward(flow, payload);
      };
      socket.on("data", (data: Buffer) => {
        buffer = buffer.length ? Buffer.concat([buffer, data]) : data;
        if (buffer.length > 128 * 1024) { socket.destroy(); return; }
        if (!mode) {
          if (buffer.length < 19) return;
          if (buffer[0] !== 0 || !buffer.subarray(1, 17).equals(identity) || buffer[17] !== 0) { socket.destroy(); return; }
          if (buffer[18] === 3) {
            // Xray's default cone mode uses XUDP for game ports even with mux disabled.
            mode = "xudp"; connection.xudp = true; buffer = buffer.subarray(19);
          } else {
            if (buffer[18] !== 2) { socket.destroy(); return; }
            if (buffer.length < 26) return;
            if (buffer[21] !== 1 || !buffer.readUInt16BE(19)) { socket.destroy(); return; }
            target = { address: [...buffer.subarray(22, 26)].join("."), port: buffer.readUInt16BE(19) };
            mode = "udp"; buffer = buffer.subarray(26);
          }
          socket.write(Buffer.from([0, 0]));
        }
        while (buffer.length >= 2) {
          let payloadOffset = 2; let length = buffer.readUInt16BE(0);
          if (mode === "xudp") {
            const metaLength = length;
            if (metaLength < 4 || metaLength > 64) { socket.destroy(); return; }
            if (buffer.length < 2 + metaLength) return;
            const meta = buffer.subarray(2, 2 + metaLength);
            // This local outbound emits one XUDP session (id zero) per VLESS connection.
            if (meta.readUInt16BE(0) !== 0 || ![1, 2].includes(meta[2]!) || meta[3] !== 1) { socket.destroy(); return; }
            if (metaLength > 4) {
              if (metaLength < 12 || meta[4] !== 2 || meta[7] !== 1 || !meta.readUInt16BE(5)) { socket.destroy(); return; }
              target = { address: [...meta.subarray(8, 12)].join("."), port: meta.readUInt16BE(5) };
            }
            payloadOffset = 2 + metaLength + 2;
            if (buffer.length < payloadOffset) return;
            length = buffer.readUInt16BE(payloadOffset - 2);
          }
          if (length > MAX_PAYLOAD) { socket.destroy(); return; }
          if (buffer.length < payloadOffset + length) return;
          forward(buffer.subarray(payloadOffset, payloadOffset + length));
          buffer = buffer.subarray(payloadOffset + length);
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(preferred?.port ?? 0, "127.0.0.1", () => { this.server!.removeListener("error", reject); resolve(); });
    });
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("Game listener unavailable");
    return { port: address.port, uuid };
  }
  /** A new destination never tears down the socket: the least recently used
   * non-match flow is ended instead. Steam pings dozens of relays from one socket. */
  private evictConnection(): boolean {
    const now = Date.now(); let oldest: Connection | null = null;
    for (const connection of this.connections) {
      if (connection.socket.destroyed || now - connection.touched < EVICT_IDLE_MS) continue;
      if ([...connection.flows.values()].some((flow) => flow.kind === "match" && now - flow.touched < ACTIVE_MATCH_MS)) continue;
      if (!oldest || connection.touched < oldest.touched) oldest = connection;
    }
    if (!oldest) return false;
    this.connections.delete(oldest); oldest.socket.destroy(); return true;
  }
  private admitFlow(connection: Connection): boolean {
    const evict = (flows: Iterable<Flow>): boolean => {
      let oldest: Flow | null = null;
      for (const flow of flows) if (flow.kind !== "match" && (!oldest || flow.touched < oldest.touched)) oldest = flow;
      if (!oldest) return false;
      this.dropFlow(oldest); return true;
    };
    if (connection.flows.size >= GAME_FLOW_LIMITS.perConnection && !evict(connection.flows.values())) return false;
    if (this.flows.size >= GAME_FLOW_LIMITS.total && !evict(this.flows.values())) return false;
    return true;
  }
  private dropFlow(flow: Flow): void {
    this.finishFlow(flow); this.detach(flow);
    if (flow.connection.flows.get(`${flow.address}:${flow.port}`) === flow) flow.connection.flows.delete(`${flow.address}:${flow.port}`);
    this.flows.delete(flow.id);
  }
  /** Separates a flow from its exit. The next packet re-decides; already pinned flows never call this lightly. */
  private detach(flow: Flow): void {
    if (flow.hold) { clearTimeout(flow.hold.timer); flow.hold = null; this.holds.delete(flow); }
    const wire = flow.wire; flow.wire = null;
    if (wire) {
      wire.flows.delete(`${flow.address}:${flow.port}`);
      if (!wire.flows.size) { if (wire.flushTimer) clearTimeout(wire.flushTimer); this.wires.delete(wire.id.toString("hex")); wire.connection.wires.delete(wire.key); }
    }
    flow.direct?.close(); flow.direct = null;
  }
  private reopen(flow: Flow, reason: string): void {
    this.log(`Game: поток ${flow.kind === "match" ? "матча" : "игры"} открыт заново (${flow.exitId || "без выхода"}): ${reason}`);
    this.finishFlow(flow, false); this.detach(flow);
    flow.exitId = ""; flow.instance = null; flow.noPathSince = null; flow.pending = []; flow.held = true; flow.finished = false;
    flow.decision = null; flow.reopenReason = reason; flow.lastBusyAt = Date.now();
  }

  async connect(candidates: GameRouteCandidate[], password: string, options?: GameRuntimeOptions): Promise<void> {
    this.password = password; this.options = options ?? emptyOptions(); this.rebuildResolver();
    await Promise.all(candidates.slice(0, this.options.nodes.length ? 256 : MAX_PATHS).map(async (candidate, slot) => {
      await this.openPath(candidate, slot, candidate.nodeId ?? "", false);
    }));
    for (let attempt = 0; attempt < 10 && !this.abort.signal.aborted; attempt++) {
      this.ping(); await new Promise<void>((resolve) => setTimeout(resolve, 200));
    }
    const groups = new Map<string, Path[]>();
    for (const route of this.paths) if (route?.instance && route.latencyMs !== null && performance.now() - route.lastReply < 2_000)
      groups.set(route.instance, [...(groups.get(route.instance) ?? []), route]);
    const ranked = [...groups.entries()].sort((a, b) => Math.min(...a[1].map((p) => p.latencyMs!)) - Math.min(...b[1].map((p) => p.latencyMs!)) || b[1].length - a[1].length);
    this.relayInstance = ranked[0]?.[0] ?? null;
    if (!this.relayInstance || this.abort.signal.aborted) { this.paths.forEach((route) => route?.transport.close()); throw new Error("Game relay unavailable"); }
    for (const route of this.paths) if (route) {
      route.accepted = Boolean(route.instance && (this.options.nodes.length || route.instance === this.relayInstance));
      if (!route.exitNodeId) route.exitNodeId = route.entryNodeId = `legacy-${route.instance}`;
      if (!route.accepted) route.transport.close();
    }
    // First query the node itself before attempting authenticated two-node paths.
    for (const route of this.paths) if (route?.accepted) this.control(route, Kind.NodeInfo, {});
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    if (this.options.nodes.length) for (let i = 0; i < 10 && this.paths.some((path) => path?.accepted && !path.modern); i++)
      await new Promise<void>((resolve) => setTimeout(resolve, 150));
    const changed = this.normalizeSessions();
    if (changed) for (let i = 0; i < 5 && !this.abort.signal.aborted; i++) { this.ping(); await new Promise<void>((resolve) => setTimeout(resolve, 200)); }
    const queried = new Set<string>();
    for (const path of this.paths) if (path?.accepted && path.modern && path.mesh && !queried.has(path.exitNodeId)) {
      queried.add(path.exitNodeId); this.control(path, Kind.MeshRow, {});
    }
    this.rebuildResolver(); this.selectActive(); this.ping();
    this.timer = setInterval(() => this.tick(), 1_000); this.timer.unref();
    this.fastTimer = setInterval(() => this.fastTick(), GAME_POLICY.fastPingIntervalMs); this.fastTimer.unref();
  }
  private async openPath(candidate: GameRouteCandidate, slot: number, exitNodeId: string, modern: boolean): Promise<void> {
    this.openingSlots.add(slot);
    try {
      const pathSlot = this.exitPathCounts.get(exitNodeId) ?? 0;
      if (pathSlot >= MAX_PATHS) return;
      this.exitPathCounts.set(exitNodeId, pathSlot + 1);
      let session = this.exitSessions.get(exitNodeId);
      if (!session) { session = exitNodeId ? newSession(randomBytes(8)) : this.session; this.exitSessions.set(exitNodeId, session); }
      const transport = await openRelayPath(candidate.port, this.password, (data) => this.receive(slot, data), this.abort.signal);
      if (this.abort.signal.aborted) { transport.close(); return; }
      this.paths[slot] = { index: candidate.index, slot, pathSlot, session, port: candidate.port, epoch: 0, accepted: modern, active: false, spread: false,
        repairing: false, transport, instance: null, latencyMs: null, lastReply: -Infinity, awaitingSince: null, lastLatencyMs: null, sent: new Map(), wins: 0, recentWins: 0, misses: 0,
        entryNodeId: candidate.nodeId ?? "", exitNodeId, modern, mesh: modern, caps: NO_CAPS, quality: new QualityWindow(), fast: new FastQuality(),
        cpuPercent: 0, networkBytesPerSecond: 0, activeFlows: 0, probe: false, reliable: candidate.reliable === true };
    } catch { /* Remaining authenticated paths may still carry the game. */ }
    finally { this.openingSlots.delete(slot); }
  }
  private async ensureMeshPaths(exitNodeId: string): Promise<void> {
    if (this.preparingMesh.has(exitNodeId) || this.abort.signal.aborted) return;
    const directExit = this.paths.find((path) => path?.exitNodeId === exitNodeId && path.modern && path.mesh && path.instance);
    if (!directExit) return;
    const entries = new Map<string, Path>();
    for (const path of this.paths) if (path?.accepted && path.modern && path.mesh && path.entryNodeId === path.exitNodeId
      && path.entryNodeId !== exitNodeId && !path.transport.closed && performance.now() - path.lastReply < 6000) {
      const previous = entries.get(path.entryNodeId);
      if (!previous || byLatency(path, previous) < 0) entries.set(path.entryNodeId, path);
    }
    const ranked = [...entries.values()].sort((a, b) => {
      const cost = (entry: Path): number => (entry.latencyMs ?? Infinity) + (entry.reliable ? GAME_POLICY.reliablePenaltyMs : 0)
        + (this.meshRows.get(entry.entryNodeId)?.find((item) => item.nodeId === exitNodeId)?.quality.latencyMs ?? 1000);
      return cost(a) - cost(b) || 0;
    }).slice(0, 3);
    this.preparingMesh.add(exitNodeId);
    try {
      for (const entry of ranked) {
        if (this.paths.some((path) => path?.entryNodeId === entry.entryNodeId && path.exitNodeId === exitNodeId)) continue;
        if ((this.exitPathCounts.get(exitNodeId) ?? 0) >= MAX_PATHS) break;
        let slot = this.paths.findIndex((path, index) => !path && !this.openingSlots.has(index));
        if (slot < 0) { slot = this.paths.length; while (this.openingSlots.has(slot)) slot++; }
        await this.openPath({ index: entry.index, port: entry.port, nodeId: entry.entryNodeId, reliable: entry.reliable }, slot, exitNodeId, true);
        const created = this.paths[slot]; if (created) this.pingOne(created);
      }
    } finally {
      this.preparingMesh.delete(exitNodeId);
      this.exitPathCounts.set(exitNodeId, Math.max(-1, ...this.paths.filter((path) => path?.exitNodeId === exitNodeId).map((path) => path.pathSlot)) + 1);
    }
  }
  /** 5 Hz echo of the copies that carry a match: path ranking reacts within a second. */
  private fastTick(): void {
    if (this.abort.signal.aborted || !this.playing) return;
    let lostActive = false;
    for (const route of this.paths) if (route?.active && route.accepted) {
      this.pingOne(route);
      if (route.misses >= 3) lostActive = true;
    }
    if (lostActive) this.selectActive();
  }
  private tick(): void {
    const now = Date.now();
    for (const flow of [...this.flows.values()]) {
      if (flow.kind !== "match") flow.kind = classifyFlow({ startedAt: flow.startedAt, now, sent: flow.sent, received: flow.received, distinctTargets: this.destinations.size });
      if (flow.kind === "match") {
        this.admitTarget(flow);
        this.playing = true;
        const estimate = this.estimates(flow).find((item) => item.nodeId === flow.exitId);
        const comparable = estimate && estimate.confidence !== "access" && estimate.confidence !== "unavailable";
        if (comparable && estimate.latencyMs !== null) {
          flow.latencyHistory.push(estimate.latencyMs);
          flow.lowerBoundSamples ||= estimate.evidence === "lower-bound";
        }
        if (flow.latencyHistory.length > 3600) flow.latencyHistory.shift();
      }
      if (flow.sent - flow.sentAtTick >= GAME_POLICY.matchPacketsPerSecond) { flow.lastBusyAt = now; flow.busy = true; }
      flow.sentAtTick = flow.sent;
      if (now - flow.touched > 60_000) { this.dropFlow(flow); continue; }
      this.checkPinnedExit(flow, now);
    }
    const principal = this.activeMatchFlows()[0]; const principalId = principal?.id ?? null;
    if (principalId !== this.estimateFlowId) { this.estimateFlowId = principalId; this.estimateHistory.length = 0; }
    if (principal) {
      const estimate = this.estimates(principal).find((item) => item.nodeId === principal.exitId);
      const comparable = estimate && estimate.confidence !== "access" && estimate.confidence !== "unavailable";
      this.estimateHistory.push({ measuredAt: now, latencyMs: comparable ? estimate.latencyMs : null,
        approximate: estimate?.approximate ?? true, lowerBound: estimate?.evidence === "lower-bound" });
      while (this.estimateHistory.length > 120) this.estimateHistory.shift();
    }
    const activeExits = new Set([...this.flows.values()].filter((flow) => flow.counted && flow.exitId && flow.exitId !== "direct").map((flow) => flow.exitId));
    // The exit the next match will most likely take keeps its backup entries open and
    // measured, so a match has a copy through another node from its first packet.
    const warmExits = new Set(activeExits);
    for (const exit of [this.sessionExit, this.primaryExitId]) if (exit && exit !== "direct") warmExits.add(exit);
    for (const exit of warmExits) void this.ensureMeshPaths(exit);
    for (const [slot, path] of this.paths.entries()) if (path && path.entryNodeId !== path.exitNodeId
      && !warmExits.has(path.exitNodeId) && !this.preparingMesh.has(path.exitNodeId)) {
      path.accepted = false; path.epoch++; path.transport.close(); delete this.paths[slot];
      this.exitPathCounts.set(path.exitNodeId, Math.max(-1, ...this.paths.filter((item) => item?.exitNodeId === path.exitNodeId).map((item) => item.pathSlot)) + 1);
    }
    for (const [key, target] of this.destinations) if (![...this.flows.values()].some((flow) => flow.address === target.address && flow.port === target.port)) this.destinations.delete(key);
    for (const path of this.paths) if (path) path.recentWins *= 0.8;
    const active = this.playing || [...this.flows.values()].some((flow) => now - flow.touched < 5_000);
    if (now - this.lastProbeAt >= (active ? 1_000 : 60_000)) {
      this.selectActive(); this.ping(); this.requestMeasurements(); this.lastProbeAt = now; this.lastIdlePingAt = now;
      const carrying = [...this.flows.values()].filter((flow) => flow.counted && flow.wire)
        .sort((a, b) => b.sent - a.sent)[0];
      const best = this.activePaths(carrying?.wire ?? null).sort(byLatency)[0];
      if (best && (best.lastLatencyMs ?? best.latencyMs) !== null) this.limitedByUpload = this.uploadGuard.update(`${best.exitNodeId}:${best.instance}:${best.pathSlot}`,
        (best.lastLatencyMs ?? best.latencyMs)!, this.uploadBytes, this.activePaths(carrying!.wire).length, now);
      else if (!carrying) this.limitedByUpload = false;
      this.uploadBytes = 0;
    }
    // Idle pings keep the relay session (60 s idle timeout) and the path state alive.
    if (now - this.lastIdlePingAt >= IDLE_PING_MS) { this.ping(); this.lastIdlePingAt = now; }
    // Only a path that was asked and kept silent is rebuilt: the first busy tick after idle
    // time must not tear down every path the game is about to use.
    const silence = active ? ACTIVE_SILENCE_MS : IDLE_FRESH_MS;
    for (const [slot, route] of this.paths.entries()) if (route?.accepted && !route.repairing && (route.transport.closed
      || (route.awaitingSince !== null && performance.now() - route.awaitingSince >= silence))) void this.repair(slot);
  }
  /** A pinned exit with no live path for long is a lost match: re-decide instead of
   * dropping the game's packets forever. A non-match flow may also follow a clearly
   * better measured exit; match flows never move while alive. */
  private checkPinnedExit(flow: Flow, now: number): void {
    if (!flow.exitId || flow.hold) return;
    // Any reply (pong or game data) on any path of the exit keeps it alive; a new
    // exit means a new source address, which a game server treats as a disconnect.
    const alive = flow.exitId === "direct" ? Boolean(flow.direct && !flow.direct.closed) || flow.pending.length > 0
      : this.exitPaths(flow.wire).some((path) => performance.now() - path.lastReply < GAME_POLICY.pathSilentMs);
    const game = flow.kind === "match" || flow.busy;
    if (alive) flow.noPathSince = null;
    else if (flow.noPathSince === null) flow.noPathSince = now;
    else if (now - flow.noPathSince >= (game ? GAME_POLICY.deadMatchExitMs : GAME_POLICY.deadExitMs)) {
      this.reopen(flow, "Выход перестал отвечать; поток открыт заново через доступный выход"); return;
    }
    // Only ping-like flows move (relay/lobby pings): moving a game connection disconnects it.
    if (game || now - flow.lastBusyAt < GAME_POLICY.migrateQuietMs || now - flow.startedAt < GAME_POLICY.migrateQuietMs
      || !flow.counted || flow.exitId === "direct" || this.options.exitScope !== "flow" || this.options.preferredExitId || flow.decision?.source === "manual") return;
    const estimates = this.estimates(flow, true);
    const current = estimates.find((item) => item.nodeId === flow.exitId);
    const best = chooseExit(estimates, flow.exitId);
    if (!best || best.nodeId === flow.exitId || best.evidence !== "endpoint" || !current || !Number.isFinite(current.score)
      || current.score - best.score < Math.max(GAME_POLICY.migrateMinGainMs, current.score * GAME_POLICY.hysteresisRatio)) return;
    this.reopen(flow, "Служебный поток перенесён на выход с лучшим замером до сервера");
  }
  private hasLivePath(exitId: string): boolean {
    return exitId === "direct" ? Boolean(this.options.directSocksPort) : this.livePaths(exitId).some((path) => path.active || path.latencyMs !== null);
  }
  private forward(flow: Flow, payload: Buffer): void {
    flow.touched = this.lastPacketAt = Date.now(); flow.sent++;
    if (flow.hold) { if (flow.pending.length < GAME_POLICY.holdMaxPackets) flow.pending.push(Buffer.from(payload)); if (flow.counted) this.uploaded++; return; }
    if (!flow.exitId) {
      this.selectActive();
      if (flow.counted) this.admitTarget(flow);
      if (!flow.held && this.startHold(flow, payload)) return;
      if (!this.pin(flow)) return;
    }
    this.send(flow, payload);
    if (flow.counted) this.uploaded++;
  }
  /** Chooses and pins the exit of a flow. Returns false while no exit can carry it. */
  private pin(flow: Flow): boolean {
    const selected = this.decideExit(flow, flow.counted, flow.gameId, flow.connection);
    if (!selected) return false;
    const reopened = flow.reopenReason; flow.reopenReason = null;
    flow.exitId = selected.decision.exitId;
    flow.decision = { ...selected.decision, ...(reopened ? { reason: `${reopened}. ${selected.decision.reason}` } : {}), selectedAt: Date.now() };
    flow.held = true;
    if (flow.counted && this.options.exitScope === "session") this.sessionExit = flow.exitId;
    // The socket's exit only changes when the old one is gone (decideExit did not keep it).
    if (flow.counted && this.options.exitScope === "socket" && selected.decision.source !== "session") flow.connection.exitId = flow.exitId;
    if (flow.counted) this.lastExit = flow.exitId;
    if (flow.exitId !== "direct") {
      const route = this.livePaths(flow.exitId).filter((path) => path.active).sort(byLatency)[0]
        ?? this.livePaths(flow.exitId).sort(byLatency)[0];
      flow.instance = route?.instance ?? null;
      if (route?.instance) this.bind(flow, route);
      if (flow.counted) void this.ensureMeshPaths(flow.exitId);
    }
    this.requestMeasurements();
    if (flow.exitId === "direct") void this.openDirect(flow);
    return true;
  }
  /** Shares one relay flow (one external port) between destinations of one client socket
   * when the exit maps endpoint-independently; otherwise each destination has its own. */
  private bind(flow: Flow, route: Path): void {
    const eim = this.nodeCaps.get(flow.exitId)?.eim === true;
    const key = eim ? `${flow.exitId}:${route.instance}` : `${flow.exitId}:${route.instance}:${flow.address}:${flow.port}`;
    let wire = flow.connection.wires.get(key);
    if (!wire) {
      let id = newFlow(randomBytes(4)); while (this.wires.has(id.toString("hex"))) id = newFlow(randomBytes(4));
      wire = { id, key, sequence: 0, seen: new SequenceWindow(), exitId: flow.exitId, instance: route.instance!, session: route.session,
        connection: flow.connection, flows: new Map(), encoder: new FecEncoder(), decoder: new FecDecoder(), flushTimer: null, evidence: flow.evidence };
      flow.connection.wires.set(key, wire); this.wires.set(id.toString("hex"), wire);
    }
    wire.flows.set(`${flow.address}:${flow.port}`, flow); flow.wire = wire;
  }
  /** Holds the first packets of a new destination for about one access RTT, so the
   * cached node measurement of that server (shared by all players) decides the exit. */
  private startHold(flow: Flow, payload: Buffer): boolean {
    if (!flow.counted || this.options.preferredExitId || this.options.exitScope !== "flow" || !publicIPv4(flow.address)) return false;
    const exits = new Set(this.paths.filter((path) => path?.accepted && path.probe && path.entryNodeId === path.exitNodeId && this.fresh(path)
      && this.node(path.exitNodeId)?.state !== "disabled").map((path) => path.exitNodeId));
    if (!exits.size) return false;
    if (this.estimates(flow, true).some((item) => item.evidence === "endpoint" && item.confidence !== "access")) return false;
    const access = Math.min(...this.paths.filter((path) => path && exits.has(path.exitNodeId)).map((path) => path.fast.latencyMs ?? path.latencyMs ?? Infinity));
    const wait = Math.max(GAME_POLICY.holdMinMs, Math.min(GAME_POLICY.holdMaxMs, Number.isFinite(access) ? access * 1.5 + 20 : GAME_POLICY.holdMaxMs));
    flow.pending = [Buffer.from(payload)];
    flow.hold = { waiting: exits, timer: setTimeout(() => this.releaseHold(flow), wait) };
    this.holds.add(flow); if (flow.counted) this.uploaded++;
    this.requestMeasurements([flow]);
    return true;
  }
  private releaseHold(flow: Flow): void {
    if (!flow.hold) return;
    clearTimeout(flow.hold.timer); flow.hold = null; this.holds.delete(flow); flow.held = true;
    if (flow.finished || !this.flows.has(flow.id)) return;
    const pending = flow.pending; flow.pending = [];
    if (!this.pin(flow)) return;
    if (flow.exitId === "direct") { flow.pending.push(...pending.slice(0, 8)); return; }
    for (const payload of pending) this.send(flow, payload);
  }
  private send(flow: Flow, payload: Buffer): void {
    if (flow.exitId === "direct") {
      if (flow.direct) flow.direct.send(payload);
      else if (flow.pending.length < 8) flow.pending.push(Buffer.from(payload));
      return;
    }
    const wire = flow.wire; if (!wire || wire.sequence >= 0xffffffff) return;
    // With no active path (all missing pings for a moment) the game keeps using the
    // path that answered last instead of losing its packets.
    const active = this.activePaths(wire);
    const paths = active.length ? active : this.exitPaths(wire).sort((a, b) => b.lastReply - a.lastReply).slice(0, 1);
    flow.maxPathCount = Math.max(flow.maxPathCount, active.length);
    if (!paths.length) return;
    const sequence = wire.sequence++;
    const packet: Packet = { kind: Kind.Up, path: 0, session: wire.session ?? this.session, flow: wire.id, sequence, address: flow.address, port: flow.port, payload };
    for (const route of paths) {
      const data = this.envelope(route, packet, wire);
      if (route.spread) this.delays.push(2, () => { if (!route.transport.closed) this.transmit(route, data); }); else this.transmit(route, data);
      this.uploadBytes += payload.length;
    }
    if (!this.options.protection || !this.nodeCaps.get(wire.exitId)?.fec) return;
    const parity = wire.encoder.add({ sequence, address: flow.address, port: flow.port, payload });
    if (parity) this.sendParity(wire, parity);
    if (wire.flushTimer) clearTimeout(wire.flushTimer);
    wire.flushTimer = wire.encoder.open ? setTimeout(() => { wire.flushTimer = null; const late = wire.encoder.flush(); if (late) this.sendParity(wire, late); }, FEC_FLUSH_MS) : null;
  }
  /** Parity rides on the backup copy when there is one: a loss on the primary route is then independent of it. */
  private sendParity(wire: Wire, parity: { sequence: number; payload: Buffer }): void {
    const paths = this.activePaths(wire).sort((a, b) => (a.fast.rankMs ?? Infinity) - (b.fast.rankMs ?? Infinity) || 0);
    const route = paths[1] ?? paths[0]; if (!route) return;
    this.transmit(route, this.envelope(route, { kind: Kind.Parity, path: 0, session: wire.session ?? this.session, flow: wire.id,
      sequence: parity.sequence, address: "0.0.0.0", port: 0, payload: parity.payload }, wire));
    this.uploadBytes += parity.payload.length;
  }
  /** LGM3 needs the exit (and the entry of a mesh path) to understand it and a resolvable exit tag. */
  private dataVersion(route: Path): 0 | 2 | 3 {
    if (!route.modern) return 0;
    const exit = this.nodeCaps.get(route.exitNodeId); const entry = this.nodeCaps.get(route.entryNodeId);
    return exit?.lgm3 && (route.entryNodeId === route.exitNodeId || entry?.lgm3)
      && this.resolve(nodeTag(route.exitNodeId).toString("hex")) === route.exitNodeId ? 3 : 2;
  }
  private envelope(route: Path, packet: Packet, wire?: Wire): Buffer {
    const version = this.dataVersion(route);
    const instance = wire ? Buffer.from(wire.instance, "hex") : route.instance ? Buffer.from(route.instance, "hex") : undefined;
    return encode({ ...packet, path: route.pathSlot,
      ...(version ? { version, exitNodeId: route.exitNodeId, hops: 0, ...(instance && packet.kind !== Kind.Ping ? { instance } : {}) } : {}) },
      route.transport.prefix);
  }
  private transmit(route: Path, data: Buffer): void {
    if (route.transport.prefix && route.transport.sendPrefixed) route.transport.sendPrefixed(data); else route.transport.send(data);
  }
  private decideExit(target: ProbeTarget, counted: boolean, gameId = this.options.gameId, connection?: Connection) {
    const estimates = this.estimates(target, true);
    const history = this.options.history?.filter((item) => item.gameId === gameId && item.subnet === subnet24(target.address))
      .sort((a, b) => b.updatedAt - a.updatedAt)[0];
    const historyId = estimates.every((item) => item.confidence === "access" || item.confidence === "unavailable") ? history?.nodeId : null;
    const preference = this.options.preferredExitId ? this.canonical(this.options.preferredExitId) : null;
    const fallbackHistory = historyId ? this.canonical(historyId) : null;
    const selected = chooseExit(estimates, this.lastExit, preference ?? fallbackHistory);
    const pinned = !counted ? null : this.options.exitScope === "session" ? this.sessionExit ?? this.primaryExitId
      : this.options.exitScope === "socket" ? connection?.exitId ?? null : null;
    // A session exit that is draining makes new flows wait for the game's restart;
    // one without any live path is gone and must not black-hole the game.
    if (pinned && Boolean(this.node(pinned) && this.node(pinned)!.state !== "enabled")) return null;
    const session = pinned && this.hasLivePath(pinned) ? pinned : null;
    const exitId = session ?? selected?.nodeId; if (!exitId) return null;
    const estimate = estimates.find((item) => item.nodeId === exitId) ?? null;
    const source: GameRouteDecision["source"] = session ? "session" : exitId === preference ? "manual" : exitId === fallbackHistory ? "history"
      : estimate?.evidence === "access" || estimate?.evidence === "unavailable" ? "access" : "measured";
    const reason = source === "session" ? this.options.exitScope === "socket" ? "Сохранён выход этого сокета игры: адрес для P2P не меняется" : "Сохранён выход текущего запуска игры"
      : source === "manual" ? "Выход выбран вручную при открытии UDP-потока"
      : source === "history" ? "Выход выбран по сохранённой истории игры: полных замеров при открытии потока ещё не было"
      : source === "access" ? "При открытии потока замеров до сервера ещё не было; выход выбран по задержке A"
      : estimate?.confidence === "operator" ? "Выход выбран по замерам до дата-центра этой игры"
      : estimate?.evidence === "lower-bound" ? "При открытии потока доступна только оценка до последнего отвечающего узла"
      : "Выход выбран по доступным замерам до сервера при открытии UDP-потока";
    const decision: GameRouteDecision = { exitId, exitName: exitId === "direct" ? "Напрямую, без VPN" : this.node(exitId)?.name ?? "Игровой узел", source, reason };
    return { estimate, decision };
  }
  private admitTarget(target: ProbeTarget): void {
    if (!publicIPv4(target.address) || [25, 53, 853].includes(target.port)) return;
    const key = `${target.address}:${target.port}`;
    if (!this.destinations.has(key) && this.destinations.size >= 32) {
      const activeMatches = new Set([...this.flows.values()].filter((flow) => flow.kind === "match").map((flow) => `${flow.address}:${flow.port}`));
      const evict = [...this.destinations.keys()].find((candidate) => !activeMatches.has(candidate));
      if (evict) this.destinations.delete(evict); else return;
    }
    this.destinations.set(key, { address: target.address, port: target.port });
  }
  private async openDirect(flow: Flow): Promise<void> {
    if (!this.options.directSocksPort) return;
    try {
      const transport = await openRelayPath(this.options.directSocksPort, this.password, (payload) => {
        if (!this.flows.has(flow.id) || flow.exitId !== "direct") return;
        flow.received++; flow.touched = Date.now(); if (flow.counted) this.received++; this.deliver(flow, payload);
      }, this.abort.signal, { address: flow.address, port: flow.port });
      if (this.abort.signal.aborted || !this.flows.has(flow.id) || flow.exitId !== "direct") { transport.close(); return; }
      flow.direct = transport; for (const payload of flow.pending) transport.send(payload); flow.pending = []; flow.maxPathCount = 1;
    } catch { flow.pending = []; /* Keep this flow pinned, fail closed. */ }
  }
  private estimates(target: ProbeTarget, prospective = false): PathEstimate[] {
    const candidates: ExitCandidate[] = [];
    const exitIds = new Set(this.paths.filter((path) => path?.accepted).map((path) => path.exitNodeId));
    for (const nodeId of exitIds) {
      const paths = this.paths.filter((path) => path?.accepted && path.exitNodeId === nodeId && !path.transport.closed
        && this.fresh(path) && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples);
      const best = paths.sort(byLatency)[0]; if (!best) continue;
      const node = this.node(nodeId);
      candidates.push({ nodeId, state: node?.state ?? "enabled", access: best.quality.snapshot(),
        egress: this.measurements.get(nodeId) ?? [], cpuPercent: this.paths.find((path) => path?.entryNodeId === nodeId && path.entryNodeId === path.exitNodeId)?.cpuPercent ?? best.cpuPercent,
        processingNodes: best.entryNodeId === best.exitNodeId ? 1 : 2, networkBytesPerSecond: best.networkBytesPerSecond, activeFlows: best.activeFlows });
    }
    const direct = this.directMeasurements.get(`${target.address}:${target.port}`);
    if (direct && this.options.directSocksPort) candidates.push({ nodeId: "direct", state: "enabled", access: null, egress: [], direct });
    const regions = [...new Set([...this.measurements.values()].flatMap((items) => items.flatMap((item) => item.metric.region ? [item.metric.region] : [])))];
    const metadata = [...this.measurements.values()].flat().find((item) => item.address === target.address && item.port === target.port && item.metric.routeKey)?.metric
      ?? [...this.measurements.values()].flat().find((item) => item.address === target.address && item.port === target.port)?.metric;
    const destination = { ...target, ...(metadata?.routeKey ? { routeKey: metadata.routeKey } : {}), ...(metadata?.region ? { region: metadata.region } : {}) };
    return candidates.map((candidate) => {
      const anchors = this.anchors.get(candidate.nodeId) ?? [];
      const available = [estimateExit(candidate, destination, regions, Date.now(), anchors)];
      if (prospective && candidate.nodeId !== "direct") for (const entry of this.paths) {
        if (!entry?.accepted || !entry.modern || !entry.mesh || entry.entryNodeId !== entry.exitNodeId || entry.entryNodeId === candidate.nodeId
          || entry.transport.closed || !this.fresh(entry)) continue;
        const row = this.meshRows.get(entry.entryNodeId)?.find((item) => item.nodeId === candidate.nodeId);
        if (!row) continue;
        available.push(estimateExit({ ...candidate, access: entry.quality.snapshot(), mesh: row.quality, processingNodes: 2 }, destination, regions, Date.now(), anchors));
      }
      return chooseExit(available) ?? available[0]!;
    });
  }
  private comparisons(target: ProbeTarget): GameExitComparison[] {
    return this.estimates(target).map((estimate) => {
      const node = this.node(estimate.nodeId);
      const path = this.paths.filter((item) => item?.exitNodeId === estimate.nodeId).sort(byLatency)[0];
      return { nodeId: estimate.nodeId, name: estimate.nodeId === "direct" ? "Напрямую, без VPN" : node?.name ?? "Игровой узел",
        state: node?.state ?? "enabled", access: path?.quality.snapshot() ?? null, egress: estimate.egress,
        direct: this.directMeasurements.get(`${target.address}:${target.port}`) ?? null, estimatedRttMs: estimate.confidence === "access" ? null : estimate.latencyMs,
        jitterMs: estimate.jitterMs, lossPercent: estimate.confidence === "access" ? null : estimate.lossPercent,
        confidence: estimate.confidence, evidence: estimate.evidence, approximate: estimate.approximate,
        ...(estimate.nodeId !== "direct" ? { egressStatus: this.egressStatus(estimate.nodeId, target, estimate.egress) } : {}),
        reason: estimate.nodeId === "direct" ? estimate.evidence === "lower-bound"
          ? "Прямой путь отвечает только до маршрутизатора провайдера; автоматически не выбирается" : "Прямой путь через физический интерфейс, без VPN"
          : estimate.confidence === "access" ? "Замер до сервера ещё не готов; выбран вход с наименьшей задержкой"
          : estimate.confidence === "operator" ? "Оценка по A + замеру до дата-центра этой игры" : "Оценка до этого сервера по A + B; текущие потоки сохраняют выход" };
    });
  }
  private egressStatus(nodeId: string, target: ProbeTarget, egress: Segment | null): NonNullable<GameExitComparison["egressStatus"]> {
    const paths = this.paths.filter((path) => path?.accepted && path.exitNodeId === nodeId);
    if (!paths.some((path) => path.modern)) return "legacy";
    if (!paths.some((path) => path.probe) || this.probeStates.get(nodeId) === "service-unavailable") return "service-unavailable";
    if (this.probeStates.get(nodeId) === "collecting") return "collecting";
    if (egress && egress.latencyMs !== null) return "ready";
    const values = this.measurements.get(nodeId) ?? [];
    const raw = values.find((item) => item.address === target.address && item.port === target.port)
      ?? values.find((item) => subnet24(item.address) === subnet24(target.address));
    if (!raw || raw.metric.samples < GAME_POLICY.minimumSamples) return "collecting";
    if (Date.now() - raw.metric.measuredAt >= GAME_POLICY.expiryMs) return "stale";
    return "unavailable";
  }
  private selectActive(): void {
    const previous = new Set(this.paths.filter((path) => path?.active));
    for (const path of this.paths) if (path) { path.active = false; path.spread = false; }
    // Distinct relay instances are independent exits even when an operator
    // accidentally gives them the same nodeId. Never mix their copies.
    const groups = new Map<string, Path[]>();
    for (const path of this.paths) if (path?.accepted && path.instance && !path.transport.closed
      && this.fresh(path) && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples && path.misses < 3) {
      const key = `${path.exitNodeId}:${path.instance}`;
      groups.set(key, [...(groups.get(key) ?? []), path]);
    }
    for (const paths of groups.values()) {
      const chosen = chooseIngress(paths.map((path) => ({ path, latencyMs: path.latencyMs, entryNodeId: path.entryNodeId,
        rankMs: path.fast.rankMs, reliable: path.reliable, wins: path.recentWins })), this.options.protection, this.limitedByUpload);
      const primary = chosen[0]?.path;
      for (const { path } of chosen) {
        path.active = true;
        // A copy over the same entry node shares its route: send it a little later.
        path.spread = Boolean(primary && path !== primary && path.entryNodeId === primary.entryNodeId);
      }
    }
    // The relay answers a game only over active paths: an exit that carries flows
    // keeps its most recently answering path active even while every path misses pings.
    for (const wire of this.wires.values()) {
      const paths = this.exitPaths(wire);
      if (!paths.length || paths.some((path) => path.active)) continue;
      paths.sort((a, b) => b.lastReply - a.lastReply)[0]!.active = true;
    }
    for (const path of this.paths) if (path && path.active !== previous.has(path)) path.misses = 0;
  }
  private async repair(slot: number): Promise<void> {
    const route = this.paths[slot]; if (!route || this.abort.signal.aborted) return;
    route.repairing = true; route.active = false; route.lastReply = -Infinity; route.awaitingSince = null;
    const epoch = ++route.epoch; route.sent.clear(); route.transport.close();
    try {
      const transport = await openRelayPath(route.port, this.password, (data) => { if (route.epoch === epoch) this.receive(slot, data); }, this.abort.signal);
      if (this.abort.signal.aborted || this.paths[slot] !== route) { transport.close(); return; } route.transport = transport; this.pingOne(route);
    } catch { /* Surviving paths retain their exit and flow identity. */ } finally { route.repairing = false; }
  }
  private ping(): void {
    if (this.abort.signal.aborted) return;
    for (const route of this.paths) if (route) this.pingOne(route);
  }
  private pingOne(route: Path): void {
    if (this.abort.signal.aborted || route.transport.closed) return;
    const now = performance.now();
    for (const [key, sent] of route.sent) if (now - sent >= 1500) { route.quality.push(null); route.fast.push(null); route.misses++; route.sent.delete(key); }
    const sequence = this.pingSequence++ >>> 0;
    route.sent.set(sequence, now); route.awaitingSince ??= now;
    const fec = route.active && this.options.protection && this.nodeCaps.get(route.exitNodeId)?.fec;
    const flags = (route.active ? PING_ACTIVE : 0) | (route.active && route.spread && route.caps.spread ? PING_SPREAD : 0) | (fec ? PING_FEC : 0);
    const version = this.dataVersion(route);
    this.transmit(route, encode({ kind: Kind.Ping, path: route.pathSlot, session: route.session, flow: Buffer.alloc(8), sequence,
      address: "0.0.0.0", port: 0, payload: Buffer.from([flags]),
      ...(version ? { version, exitNodeId: route.exitNodeId, hops: 0 } : {}) }, route.transport.prefix));
  }
  private control(route: Path, kind: Kind.NodeInfo | Kind.ProbeRequest | Kind.MeshRow | Kind.Regions, body: unknown): void {
    const query = this.queries.get(route.exitNodeId);
    const session = query?.session ?? route.session;
    if (query && !query.handshake) {
      const sequence = this.controlSequence++ >>> 0; route.sent.set(sequence, performance.now());
      route.transport.send(encode({ kind: Kind.Ping, path: route.pathSlot, session, flow: Buffer.alloc(8), sequence,
        address: "0.0.0.0", port: 0, version: 2, exitNodeId: route.exitNodeId, hops: 0, payload: Buffer.from([0]) }));
    }
    route.transport.send(encode({ kind, path: route.pathSlot, session, flow: Buffer.alloc(8), sequence: this.controlSequence++ >>> 0,
      address: "0.0.0.0", port: 0, version: 2, exitNodeId: route.modern ? route.exitNodeId : "", hops: 0, payload: controlPayload(body) }));
  }
  private requestMeasurements(only?: ProbeTarget[]): void {
    const targets = only ?? [...this.destinations.values()]; if (!targets.length || this.abort.signal.aborted) return;
    const nodes = new Set<string>();
    for (const route of this.paths) if (route?.accepted && !route.transport.closed && this.fresh(route) && !nodes.has(route.exitNodeId)) {
      nodes.add(route.exitNodeId);
      const keys = targets.map((target) => `${target.address}:${target.port}`);
      let query = this.queries.get(route.exitNodeId);
      if (!query) query = { session: route.session, targets: new Set(), handshake: true };
      if (new Set([...query.targets, ...keys]).size > 32) query = { session: newSession(randomBytes(8)), targets: new Set(), handshake: false };
      for (const key of keys) query.targets.add(key);
      this.queries.set(route.exitNodeId, query);
      if (only) { if (route.modern && route.probe) this.control(route, Kind.ProbeRequest, { targets: targets.map(({ address, port }) => ({ address, port })) }); continue; }
      this.control(route, Kind.NodeInfo, {});
      if (route.modern && route.probe) this.control(route, Kind.ProbeRequest, { targets });
      if (route.modern && route.mesh) this.control(route, Kind.MeshRow, {});
      if (route.modern && route.caps.regions && Date.now() - (this.regionsRequestedAt.get(route.exitNodeId) ?? -Infinity) >= REGIONS_INTERVAL_MS) {
        this.regionsRequestedAt.set(route.exitNodeId, Date.now()); this.control(route, Kind.Regions, {});
      }
    }
    if (only) return;
    if (this.options.measureDirect && !this.measuringDirect && Date.now() - this.lastDirectProbeAt >= GAME_POLICY.directProbeIntervalMs) {
      this.measuringDirect = true; this.lastDirectProbeAt = Date.now();
      const matchTargets = [...this.flows.values()].filter((flow) => flow.kind === "match").map((flow) => `${flow.address}:${flow.port}`);
      const directTargets = [...targets].sort((a, b) => Number(matchTargets.includes(`${b.address}:${b.port}`)) - Number(matchTargets.includes(`${a.address}:${a.port}`))
        || (this.directMeasurements.get(`${a.address}:${a.port}`)?.measuredAt ?? 0) - (this.directMeasurements.get(`${b.address}:${b.port}`)?.measuredAt ?? 0)).slice(0, 4);
      void this.options.measureDirect(directTargets, this.abort.signal).then((results) => {
        if (this.abort.signal.aborted) return;
        // A batch of sub-3ms targets is likely the TUN answering ICMP locally.
        const good = results.filter((item) => item.medianMs !== null);
        if (good.length >= 1 && good.every((item) => item.medianMs! < 3)) { this.directMeasurements.clear(); this.directHistory.clear(); return; }
        for (const raw of results) {
          const item = parseMeasurement(raw); if (!item || !directTargets.some((target) => target.address === item.address && target.port === item.port)) continue;
          const key = `${item.address}:${item.port}`;
          let history = this.directHistory.get(key);
          if (!history) {
            if (this.directHistory.size >= 32) {
              const evict = [...this.directHistory.keys()].filter((candidate) => !matchTargets.includes(candidate))
                .sort((a, b) => (this.directMeasurements.get(a)?.measuredAt ?? 0) - (this.directMeasurements.get(b)?.measuredAt ?? 0))[0];
              if (!evict) continue; this.directHistory.delete(evict); this.directMeasurements.delete(evict);
            }
            history = new MeasurementHistory(); this.directHistory.set(key, history);
          }
          history.push(this.segment(item)); const metric = item.medianMs === null ? this.segment(item) : history.snapshot(); if (metric) this.directMeasurements.set(key, metric);
        }
      }).catch(() => {}).finally(() => { this.measuringDirect = false; });
    }
  }
  private segment(item: ProbeMeasurement): Segment {
    return { latencyMs: item.medianMs, p95Ms: item.p95Ms, jitterMs: item.jitterMs, lossPercent: item.lossPercent,
      samples: item.sampleCount, measuredAt: Date.parse(item.measuredAt), method: item.method === "unavailable" ? "unknown" : item.method,
      approximate: item.approximate === true || item.method === "ttl-hop", ...(item.region ? { region: item.region } : {}),
      ...(item.routeKey ? { routeKey: item.routeKey } : {}), ...(item.operator ? { operator: item.operator } : {}), ...(item.scope ? { scope: item.scope } : {}) };
  }
  /** A restarted relay is a new exit process: its old flows are gone, but the path is fine. */
  private instanceChanged(route: Path, next: string): void {
    const previous = route.instance!; const exit = route.exitNodeId;
    const siblings = this.paths.filter((path) => path?.exitNodeId === exit && path.instance === previous);
    let canonical = exit;
    if (exit.startsWith("legacy-")) { canonical = `legacy-${next}`; this.alias(exit, canonical); }
    for (const path of siblings) {
      path.instance = next; path.entryNodeId = path.entryNodeId === exit ? canonical : path.entryNodeId; path.exitNodeId = canonical;
    }
    for (const wire of [...this.wires.values()]) if (wire.exitId === canonical && wire.instance === previous)
      for (const flow of [...wire.flows.values()]) this.reopen(flow, "Узел выхода перезапустился; поток открыт заново");
    this.nodeCaps.delete(canonical); this.measurements.delete(canonical); this.anchors.delete(canonical); this.regionsRequestedAt.delete(canonical);
    for (const path of siblings) if (path.entryNodeId === path.exitNodeId || !path.modern) { this.control(path, Kind.NodeInfo, {}); break; }
  }
  private receive(path: number, data: Buffer): void {
    const packet = decode(data, this.resolve); const route = this.paths[path];
    if (!packet || !route || packet.path !== route.pathSlot) return;
    const query = this.queries.get(route.exitNodeId);
    const queryReply = packet.kind !== Kind.Down && packet.kind !== Kind.Parity && query?.session.equals(packet.session);
    const wire = packet.kind === Kind.Down || packet.kind === Kind.Parity ? this.wires.get(packet.flow.toString("hex")) : undefined;
    const flowSession = Boolean(wire?.session?.equals(packet.session));
    if (!packet.session.equals(route.session) && !queryReply && !flowSession) return;
    if (packet.kind === Kind.Pong && packet.payload.length === 16) {
      const started = route.sent.get(packet.sequence); if (started === undefined) return;
      const instance = packet.payload.toString("hex");
      if (route.instance && route.instance !== instance) this.instanceChanged(route, instance);
      if (queryReply && query) query.handshake = true;
      route.sent.delete(packet.sequence); route.instance = instance; route.misses = 0;
      route.lastLatencyMs = performance.now() - started; route.quality.push(route.lastLatencyMs); route.fast.push(route.lastLatencyMs);
      route.latencyMs = route.quality.snapshot().latencyMs;
      route.lastReply = performance.now(); route.awaitingSince = null; if (route.modern) route.accepted = true; return;
    }
    if (packet.version === 2 && packet.kind >= Kind.NodeInfo && packet.kind !== Kind.Parity) {
      if (route.instance && packet.instance?.toString("hex") !== route.instance) return;
      const body = parseControl(packet.payload); if (!isRecord(body) || body.version !== 2) return;
      if (packet.kind === Kind.NodeInfo && typeof body.nodeId === "string" && typeof body.instance === "string"
        && body.instance === route.instance && isRecord(body.capabilities)) {
        if (route.exitNodeId && !route.exitNodeId.startsWith("legacy-") && route.exitNodeId !== body.nodeId) return;
        if (!validNodeId(body.nodeId)) return;
        if (!route.modern || route.entryNodeId === route.exitNodeId) {
          this.alias(route.exitNodeId, body.nodeId);
          const used = new Set(this.paths.filter((path) => path && path !== route && path.exitNodeId === body.nodeId).map((path) => path.pathSlot));
          if (used.has(route.pathSlot)) { const free = Array.from({ length: MAX_PATHS }, (_, index) => index).find((index) => !used.has(index)); if (free === undefined) { route.accepted = false; route.transport.close(); return; } route.pathSlot = free; }
          this.exitSessions.set(body.nodeId, route.session);
          this.exitPathCounts.set(body.nodeId, Math.max(this.exitPathCounts.get(body.nodeId) ?? 0, this.exitPathCounts.get(route.exitNodeId) ?? 0));
          route.entryNodeId = route.exitNodeId = body.nodeId;
          this.rebuildResolver();
        }
        const caps = parseCapabilities(body.capabilities);
        route.modern = true; route.mesh = caps.mesh; route.probe = caps.probe; route.caps = caps;
        this.nodeCaps.set(route.exitNodeId, caps);
        if (!route.probe) { this.measurements.delete(route.exitNodeId); this.probeStates.set(route.exitNodeId, "service-unavailable"); }
        const load = isRecord(body.load) ? body.load : {};
        const finite = (key: string): number => typeof load[key] === "number" && Number.isFinite(load[key]) ? Math.max(0, load[key]) : 0;
        route.cpuPercent = Math.min(100, finite("cpuPercent"));
        route.networkBytesPerSecond = Math.max(finite("networkRxBytesPerSecond"), finite("networkTxBytesPerSecond"));
        route.activeFlows = Math.min(4096, finite("activeFlows"));
      } else if (packet.kind === Kind.MeshRow && Array.isArray(body.neighbors)) {
        const neighbors = body.cursor === 0 || !body.cursor ? [] : this.meshRows.get(route.exitNodeId) ?? [];
        for (const item of body.neighbors.slice(0, 16)) {
          if (!isRecord(item) || typeof item.nodeId !== "string" || !validNodeId(item.nodeId)
            || !this.node(item.nodeId)) continue;
          // Mesh addresses are private by design; only trusted known-node rows
          // use this numeric validator, never the public target probe boundary.
          const metric = parseMeasurement({ ...item, address: "1.1.1.1", port: 37080 });
          if (!metric) continue;
          const previous = neighbors.findIndex((entry) => entry.nodeId === item.nodeId);
          const neighbor = { nodeId: item.nodeId, quality: this.segment(metric) };
          if (previous < 0) neighbors.push(neighbor); else neighbors[previous] = neighbor;
        }
        this.meshRows.set(route.exitNodeId, neighbors.slice(0, 64));
        if (Number.isInteger(body.nextCursor) && Number(body.nextCursor) > 0 && Number(body.nextCursor) < 64)
          this.control(route, Kind.MeshRow, { cursor: Number(body.nextCursor) });
      } else if (packet.kind === Kind.Regions && Array.isArray(body.regions)) {
        const anchors = body.cursor === 0 || !body.cursor ? [] : this.anchors.get(route.exitNodeId) ?? [];
        for (const value of body.regions.slice(0, 16)) {
          const item = parseMeasurement(value); if (!item?.routeKey) continue;
          const metric = { address: item.address, port: item.port, metric: this.segment(item) };
          const index = anchors.findIndex((entry) => entry.address === item.address && entry.port === item.port);
          if (index < 0) anchors.push(metric); else anchors[index] = metric;
        }
        this.anchors.set(route.exitNodeId, anchors.slice(0, 256));
        if (Number.isInteger(body.nextCursor) && Number(body.nextCursor) > 0 && Number(body.nextCursor) < 16)
          this.control(route, Kind.Regions, { cursor: Number(body.nextCursor) });
      } else if (packet.kind === Kind.ProbeResult && Array.isArray(body.results)) {
        if (body.status === "service-unavailable" || !body.results.length) {
          this.measurements.delete(route.exitNodeId);
          this.probeStates.set(route.exitNodeId, body.status === "service-unavailable" ? "service-unavailable" : "collecting");
          this.answerHolds(route.exitNodeId, null); return;
        }
        const existing = this.measurements.get(route.exitNodeId) ?? [];
        const named = new Set<string>(); let accepted = false;
        for (const value of body.results.slice(0, 32)) {
          const item = parseMeasurement(value);
          if (!item || !this.destinations.has(`${item.address}:${item.port}`)) continue;
          const index = existing.findIndex((entry) => entry.address === item.address && entry.port === item.port);
          const metric = { address: item.address, port: item.port, metric: this.segment(item) };
          accepted = true; named.add(`${item.address}:${item.port}`);
          if (index < 0) existing.push(metric); else existing[index] = metric;
        }
        if (accepted) this.probeStates.delete(route.exitNodeId);
        this.measurements.set(route.exitNodeId, existing.slice(-32));
        this.answerHolds(route.exitNodeId, named);
      }
      return;
    }
    if (packet.kind !== Kind.Down && packet.kind !== Kind.Parity) return;
    if (!wire || wire.exitId !== route.exitNodeId || wire.instance !== route.instance) return;
    route.lastReply = performance.now(); route.awaitingSince = null;
    if (packet.kind === Kind.Parity) {
      const recovered = wire.decoder.parity(packet.sequence, packet.payload);
      if (recovered) this.accept(wire, recovered.sequence, recovered.address, recovered.port, recovered.payload, true);
      return;
    }
    const active = this.activePaths(wire).sort(byLatency);
    wire.evidence.observe(packet.sequence, route.pathSlot, active[0]?.pathSlot ?? route.pathSlot, active.length);
    if (this.accept(wire, packet.sequence, packet.address, packet.port, packet.payload, false)) {
      route.wins++; route.recentWins++;
      const flow = wire.flows.get(`${packet.address}:${packet.port}`); const key = `${route.index}:${route.entryNodeId}`;
      const counter = flow?.pathPackets.get(key);
      if (counter) counter.packets++; else flow?.pathPackets.set(key, { routeIndex: route.index, entryNodeId: route.entryNodeId, packets: 1 });
    }
    const recovered = wire.decoder.data({ sequence: packet.sequence, address: packet.address, port: packet.port, payload: packet.payload });
    if (recovered) this.accept(wire, recovered.sequence, recovered.address, recovered.port, recovered.payload, true);
  }
  private accept(wire: Wire, sequence: number, address: string, port: number, payload: Buffer, recovered: boolean): boolean {
    const flow = wire.flows.get(`${address}:${port}`);
    if (!wire.seen.accept(sequence)) { if (!recovered && flow?.counted) this.duplicates++; return false; }
    if (!flow || flow.finished) return false;
    flow.received++; flow.touched = Date.now(); if (recovered) flow.recovered++;
    if (flow.counted) { this.received++; if (recovered) this.recovered++; }
    this.deliver(flow, payload); return true;
  }
  /** A ProbeResult frame from an exit answers the held flows it names; an empty or
   * service-unavailable frame answers all of them (the node has nothing cached). */
  private answerHolds(exitId: string, named: Set<string> | null): void {
    for (const flow of [...this.holds]) {
      if (!flow.hold || (named && !named.has(`${flow.address}:${flow.port}`))) continue;
      flow.hold.waiting.delete(exitId);
      if (!flow.hold.waiting.size) this.releaseHold(flow);
    }
  }
  private deliver(flow: Flow, payload: Buffer): void {
    const socket = flow.connection.socket;
    const header = flow.connection.xudp ? 16 : 2;
    const frame = Buffer.allocUnsafe(header + payload.length);
    if (flow.connection.xudp) { frame.writeUInt16BE(12, 0); frame[2] = 0; frame[3] = 0; frame[4] = 2; frame[5] = 1; frame[6] = 2;
      frame.writeUInt16BE(flow.port, 7); frame[9] = 1; const parts = flow.address.split("."); for (let i = 0; i < 4; i++) frame[10 + i] = Number(parts[i]); }
    frame.writeUInt16BE(payload.length, header - 2); payload.copy(frame, header);
    if (socket.writableLength > 128 * 1024) { socket.destroy(); return; }
    socket.write(frame);
  }
  private finishFlow(flow: Flow, final = true): void {
    if (flow.finished) return; if (final) flow.finished = true;
    if (flow.hold) { clearTimeout(flow.hold.timer); flow.hold = null; this.holds.delete(flow); }
    if (final) { flow.direct?.close(); flow.pending = []; }
    if (flow.kind !== "match" || (this.matchReport && this.matchReport.endedAt > flow.touched)) return;
    this.lastMatch = this.matchServer(flow);
    this.matchReport = this.report(flow);
  }
  private matchServer(flow: Flow): GameMatchServer {
    const metric = this.measurements.get(flow.exitId)?.find((item) => item.address === flow.address && item.port === flow.port)?.metric;
    return { address: flow.address, port: flow.port, ...(metric?.region ? { region: metric.region } : {}), ...(metric?.operator ? { operator: metric.operator } : {}) };
  }
  private report(flow: Flow): GameMatchReport {
    const sorted = [...flow.latencyHistory].sort((a, b) => a - b); const now = flow.touched;
    return { startedAt: flow.startedAt, endedAt: now, durationMs: now - flow.startedAt,
      averageRttMs: sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null,
      p95RttMs: sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? null,
      jitterMs: flow.latencyHistory.length > 1 ? flow.latencyHistory.slice(1).reduce((sum, value, index) => sum + Math.abs(value - flow.latencyHistory[index]!), 0) / (flow.latencyHistory.length - 1) : null,
      ...(flow.wire?.evidence ?? flow.evidence).snapshot(), receivedPackets: flow.received, approximate: true, gameId: flow.gameId,
      server: this.matchServer(flow), exitId: flow.exitId, exitName: flow.decision?.exitName ?? this.node(flow.exitId)?.name ?? "Игровой узел",
      ...(flow.decision ? { routeDecision: { ...flow.decision } } : {}),
      protection: { enabled: flow.protectionRequested, pathCount: flow.maxPathCount }, lowerBound: flow.lowerBoundSamples,
      minRttMs: sorted[0] ?? null, sentPackets: flow.sent, recoveredPackets: flow.recovered,
      paths: [...flow.pathPackets.values()].sort((a, b) => b.packets - a.packets).map((path) => ({ ...path })) };
  }
  async stop(): Promise<void> {
    this.password = ""; this.abort.abort(); if (this.timer) clearInterval(this.timer); this.timer = null;
    if (this.fastTimer) clearInterval(this.fastTimer); this.fastTimer = null; this.delays.clear();
    for (const flow of this.flows.values()) { this.finishFlow(flow); if (flow.wire?.flushTimer) clearTimeout(flow.wire.flushTimer); }
    this.paths.forEach((path) => path?.transport.close()); this.paths = [];
    this.connections.forEach((connection) => connection.socket.destroy()); this.connections.clear(); this.flows.clear(); this.wires.clear();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve())); this.server = null;
  }
}
