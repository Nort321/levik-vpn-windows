import { createServer, type Server, type Socket } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { DeliveryEvidence } from "./delivery";
import { openRelayPath, type RelayPath } from "./socks";
import { decode, encode, Kind, MAX_PAYLOAD, MAX_PATHS, SequenceWindow, controlPayload, parseControl,
  parseMeasurement, isRecord, publicIPv4, validNodeId, type Packet, type ProbeTarget, type ProbeMeasurement } from "./wire";
import { QualityWindow, MeasurementHistory, chooseExit, chooseIngress, classifyFlow, estimateExit, GAME_POLICY, UploadQueueGuard, subnet24,
  type DestinationMetric, type FlowKind, type ExitCandidate, type Segment } from "../gameEngine";
import type { GameMultipathStats, GameNode, GameRuntimeSnapshot, GameExitComparison, GameMatchReport, GameRouteQuality, GameRouteDecision } from "../../../shared/contracts";

export interface GameRuntimeOptions {
  nodes: GameNode[]; preferredExitId: string | null; protection: boolean; exitScope: "flow" | "session"; gameId?: string;
  directSourceAddress?: string; directSocksPort?: number;
  measureDirect?: (targets: ProbeTarget[], signal: AbortSignal) => Promise<ProbeMeasurement[]>;
  history?: Array<{ gameId: string; subnet: string; region: string | null; nodeId: string; updatedAt: number }>;
}
interface Path { index: number; slot: number; pathSlot: number; session: Buffer; port: number; epoch: number; accepted: boolean; active: boolean; repairing: boolean;
  transport: RelayPath; instance: string | null; latencyMs: number | null; lastReply: number; lastLatencyMs: number | null; sent: Map<number, number>; wins: number;
  entryNodeId: string; exitNodeId: string; modern: boolean; mesh: boolean; quality: QualityWindow; cpuPercent: number; networkBytesPerSecond: number; activeFlows: number; probe: boolean }
interface Flow { socket: Socket; address: string; port: number; id: Buffer; sequence: number; seen: SequenceWindow; counted: boolean; xudp: boolean;
  startedAt: number; touched: number; sent: number; received: number; exitId: string; instance: string | null; direct: RelayPath | null;
  pending: Buffer[]; kind: FlowKind; rescued: number; latencyHistory: number[]; lowerBoundSamples: boolean; evidence: DeliveryEvidence; gameId: string;
  decision: (GameRouteDecision & { selectedAt: number }) | null; protectionRequested: boolean; maxPathCount: number;
  cleanup: () => void; finished: boolean; session: Buffer | null }
const emptyOptions = (): GameRuntimeOptions => ({ nodes: [], preferredExitId: null, protection: true, exitScope: "flow" });
const ACTIVE_MATCH_MS = 5_000;

/** UDP observation, selection and replication share one bridge in both protection modes. */
export class GameMultipath {
  constructor(private counting = true) {}
  startCounting(): void { this.counting = true; }
  private readonly session = randomBytes(32);
  private readonly exitSessions = new Map<string, Buffer>();
  private readonly nodeAliases = new Map<string, string>();
  private readonly openingSlots = new Set<number>();
  private readonly preparingMesh = new Set<string>();
  private readonly exitPathCounts = new Map<string, number>();
  private readonly flows = new Map<string, Flow>();
  private readonly connections = new Set<Socket>();
  private acceptingNewFlows = true;
  private paths: Path[] = [];
  private abort = new AbortController();
  private server: Server | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private pingSequence = 0; private controlSequence = 0x80000000;
  private received = 0; private duplicates = 0; private uploaded = 0;
  private relayInstance: string | null = null; private password = "";
  private options = emptyOptions(); private playing = false; private lastProbeAt = 0;
  private readonly destinations = new Map<string, ProbeTarget>();
  private readonly meshRows = new Map<string, Array<{ nodeId: string; quality: Segment }>>();
  private readonly measurements = new Map<string, DestinationMetric[]>();
  private readonly probeStates = new Map<string, "collecting" | "service-unavailable">();
  private readonly queries = new Map<string, { session: Buffer; targets: Set<string>; handshake: boolean }>();
  private readonly directMeasurements = new Map<string, Segment>();
  private readonly directHistory = new Map<string, MeasurementHistory>();
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
    for (const flow of this.flows.values()) if (flow.exitId === previous) {
      flow.exitId = canonical;
      if (flow.decision) flow.decision.exitId = canonical;
    }
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
      const ranked = values.sort((a, b) => a.latencyMs! - b.latencyMs!);
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
    if (active && !this.playing) this.lastProbeAt = 0;
    this.playing = active;
  }
  configure(options: Partial<Pick<GameRuntimeOptions, "protection" | "preferredExitId" | "exitScope" | "gameId" | "history" | "nodes">>): void {
    this.options = { ...this.options, ...options }; this.selectActive();
  }
  pauseNewFlowsIfIdle(): boolean {
    if ([...this.flows.values()].some((flow) => flow.counted && flow.exitId)) return false;
    this.acceptingNewFlows = false; return true;
  }
  resumeNewFlows(): void { this.acceptingNewFlows = true; }
  setPrimaryRoute(index: number): void {
    const path = this.paths.find((path) => path?.index === index && path.entryNodeId === path.exitNodeId && path.accepted);
    if (path) this.primaryExitId = path.exitNodeId;
  }
  routeQualities(): Record<number, GameRouteQuality> {
    return Object.fromEntries(this.paths.filter((path) => path?.accepted && !path.transport.closed && performance.now() - path.lastReply < (this.playing ? 6000 : 65000)
      && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples && path.entryNodeId === path.exitNodeId)
      .map((path) => [path.index, path.quality.snapshot()]));
  }
  refreshMeasurements(): void {
    if (this.abort.signal.aborted || Date.now() - this.lastProbeAt < 1000) return;
    this.lastProbeAt = Date.now(); this.selectActive(); this.ping(); this.requestMeasurements();
  }
  snapshot(): GameMultipathStats {
    const paths = this.paths.filter((path) => path !== undefined);
    const fresh = this.playing ? 6_000 : 65_000;
    const activeCounts = new Map<string, number>();
    for (const path of paths) if (path.active && performance.now() - path.lastReply < fresh)
      activeCounts.set(`${path.exitNodeId}:${path.instance}`, (activeCounts.get(`${path.exitNodeId}:${path.instance}`) ?? 0) + 1);
    const copies = this.lastExit === "direct" ? Number([...this.flows.values()].some((flow) => flow.direct && !flow.direct.closed))
      : this.lastExit ? Math.max(0, ...[...activeCounts].filter(([key]) => key.startsWith(`${this.lastExit}:`)).map(([, count]) => count)) : Math.max(0, ...activeCounts.values());
    return { state: copies >= 2 ? "protected" : copies === 1 ? "single" : "unavailable",
      paths: paths.map((p) => ({ routeIndex: p.index, latencyMs: p.latencyMs,
        responding: p.accepted && performance.now() - p.lastReply < fresh, active: p.active, firstReplies: p.wins })),
      receivedPackets: this.received, duplicateReplies: this.duplicates, uploadedPackets: this.uploaded };
  }
  private activeMatchFlows(): Flow[] {
    const now = Date.now();
    return [...this.flows.values()].filter((flow) => flow.counted && flow.kind === "match" && now - flow.touched < ACTIVE_MATCH_MS)
      .sort((a, b) => b.received - a.received);
  }
  private activePaths(flow: Flow): Path[] {
    return this.paths.filter((path) => path?.accepted && path.active && path.exitNodeId === flow.exitId && path.instance === flow.instance
      && !path.transport.closed && performance.now() - path.lastReply < (this.playing ? 6_000 : 65_000));
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
    const currentPaths = current ? this.activePaths(current) : [];
    const pathCount = current ? current.exitId === "direct" ? Number(Boolean(current.direct && !current.direct.closed)) : currentPaths.length : 0;
    const protectionReason = !current ? "Нет активного UDP-потока матча"
      : current.exitId === "direct" ? "Прямой путь: резервные копии через Levik не используются"
      : !this.options.protection ? "Дублирование выключено"
      : this.limitedByUpload ? "Похоже на очередь отдачи: временно оставлен один путь, затем защита проверится снова"
      : pathCount < 2 ? "Для текущего потока нет двух рабочих путей" : null;
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
        effective: this.options.protection && pathCount >= 2, pathCount, reason: protectionReason },
      shadowAlternative: better && selected && selected.evidence === "endpoint" && better.evidence === "endpoint" && selected.confidence === better.confidence
        && better.nodeId !== selected.nodeId && selected.latencyMs !== null && better.latencyMs !== null
        && selected.latencyMs > better.latencyMs
        ? { nodeId: better.nodeId, name: exits.find((exit) => exit.nodeId === better.nodeId)?.name ?? better.nodeId,
          savingMs: Math.max(0, Math.round(selected.latencyMs - better.latencyMs)) } : null,
      matchReport: this.matchReport, estimateHistory: [...this.estimateHistory],
      compatibility: current?.exitId === "direct" || this.paths.some((path) => (!current || path.exitNodeId === current.exitId) && path.modern) ? "full" : "legacy",
      meshRows: [...this.meshRows].map(([nodeId, neighbors]) => ({ nodeId, neighbors: [...neighbors] })) };
  }
  async listen(): Promise<{ port: number; uuid: string }> {
    const uuid = randomUUID(); const identity = Buffer.from(uuid.replaceAll("-", ""), "hex");
    this.server = createServer((socket) => {
      if (this.connections.size >= 64) { socket.destroy(); return; }
      this.connections.add(socket); socket.setNoDelay(true); socket.setTimeout(60_000, () => socket.destroy());
      let buffer = Buffer.alloc(0); let mode: "udp" | "xudp" | null = null;
      let target: { address: string; port: number } | null = null;
      const localFlows = new Map<string, Flow>();
      socket.on("error", () => {});
      socket.on("close", () => {
        this.connections.delete(socket);
        for (const flow of localFlows.values()) { this.finishFlow(flow); this.flows.delete(flow.id.toString("hex")); }
      });
      const forward = (payload: Buffer): void => {
        if (!target) { socket.destroy(); return; }
        const key = `${target.address}:${target.port}`;
        let flow = localFlows.get(key);
        if (!flow || !this.flows.has(flow.id.toString("hex"))) {
          if (!this.acceptingNewFlows) return;
          if (this.flows.size >= 32) { socket.destroy(); return; }
          flow = { socket, ...target, id: randomBytes(8), sequence: 0, seen: new SequenceWindow(),
            counted: this.counting, xudp: mode === "xudp", startedAt: Date.now(), touched: Date.now(), sent: 0, received: 0, exitId: "", instance: null, direct: null, pending: [], kind: "service", rescued: 0, latencyHistory: [], lowerBoundSamples: false, evidence: new DeliveryEvidence(), gameId: this.options.gameId ?? "custom", finished: false, session: null,
            decision: null, protectionRequested: this.options.protection, maxPathCount: 0,
            cleanup: () => { if (localFlows.get(key) === flow) localFlows.delete(key); } };
          localFlows.set(key, flow); this.flows.set(flow.id.toString("hex"), flow);
        }
        if (flow.sequence >= 0xffffffff) { socket.destroy(); return; }
        this.forward(flow, payload);
      };
      socket.on("data", (data: Buffer) => {
        buffer = Buffer.concat([buffer, data]);
        if (buffer.length > 128 * 1024) { socket.destroy(); return; }
        if (!mode) {
          if (buffer.length < 19) return;
          if (buffer[0] !== 0 || !buffer.subarray(1, 17).equals(identity) || buffer[17] !== 0) { socket.destroy(); return; }
          if (buffer[18] === 3) {
            // Xray's default cone mode uses XUDP for game ports even with mux disabled.
            mode = "xudp"; buffer = buffer.subarray(19);
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
      this.server!.listen(0, "127.0.0.1", () => { this.server!.removeListener("error", reject); resolve(); });
    });
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("Game listener unavailable");
    return { port: address.port, uuid };
  }


  async connect(candidates: Array<{ index: number; port: number; nodeId?: string }>, password: string, options?: GameRuntimeOptions): Promise<void> {
    this.password = password; this.options = options ?? emptyOptions();
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
    this.selectActive(); this.ping();
    this.timer = setInterval(() => this.tick(), 1_000); this.timer.unref();
  }
  private async openPath(candidate: { index: number; port: number; nodeId?: string }, slot: number, exitNodeId: string, modern: boolean): Promise<void> {
    this.openingSlots.add(slot);
    try {
      const pathSlot = this.exitPathCounts.get(exitNodeId) ?? 0;
      if (pathSlot >= MAX_PATHS) return;
      this.exitPathCounts.set(exitNodeId, pathSlot + 1);
      let session = this.exitSessions.get(exitNodeId);
      if (!session) { session = exitNodeId ? randomBytes(32) : this.session; this.exitSessions.set(exitNodeId, session); }
      const transport = await openRelayPath(candidate.port, this.password, (data) => this.receive(slot, data), this.abort.signal);
      if (this.abort.signal.aborted) { transport.close(); return; }
      this.paths[slot] = { index: candidate.index, slot, pathSlot, session, port: candidate.port, epoch: 0, accepted: modern, active: false,
        repairing: false, transport, instance: null, latencyMs: null, lastReply: -Infinity, lastLatencyMs: null, sent: new Map(), wins: 0,
        entryNodeId: candidate.nodeId ?? "", exitNodeId, modern, mesh: modern, quality: new QualityWindow(), cpuPercent: 0, networkBytesPerSecond: 0, activeFlows: 0, probe: false };
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
      if (!previous || path.latencyMs! < previous.latencyMs!) entries.set(path.entryNodeId, path);
    }
    const ranked = [...entries.values()].sort((a, b) => {
      const cost = (entry: Path): number => (entry.latencyMs ?? Infinity)
        + (this.meshRows.get(entry.entryNodeId)?.find((item) => item.nodeId === exitNodeId)?.quality.latencyMs ?? 1000);
      return cost(a) - cost(b);
    }).slice(0, 3);
    this.preparingMesh.add(exitNodeId);
    try {
      for (const entry of ranked) {
        if (this.paths.some((path) => path?.entryNodeId === entry.entryNodeId && path.exitNodeId === exitNodeId)) continue;
        if ((this.exitPathCounts.get(exitNodeId) ?? 0) >= MAX_PATHS) break;
        let slot = this.paths.findIndex((path, index) => !path && !this.openingSlots.has(index));
        if (slot < 0) { slot = this.paths.length; while (this.openingSlots.has(slot)) slot++; }
        await this.openPath({ index: entry.index, port: entry.port, nodeId: entry.entryNodeId }, slot, exitNodeId, true);
        const created = this.paths[slot]; if (created) this.pingOne(created);
      }
    } finally {
      this.preparingMesh.delete(exitNodeId);
      this.exitPathCounts.set(exitNodeId, Math.max(-1, ...this.paths.filter((path) => path?.exitNodeId === exitNodeId).map((path) => path.pathSlot)) + 1);
    }
  }
  private tick(): void {
    const now = Date.now();
    for (const flow of this.flows.values()) {
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
      if (now - flow.touched > 60_000) { this.finishFlow(flow); this.flows.delete(flow.id.toString("hex")); }
    }
    const principal = this.activeMatchFlows()[0]; const principalId = principal?.id.toString("hex") ?? null;
    if (principalId !== this.estimateFlowId) { this.estimateFlowId = principalId; this.estimateHistory.length = 0; }
    if (principal) {
      const estimate = this.estimates(principal).find((item) => item.nodeId === principal.exitId);
      const comparable = estimate && estimate.confidence !== "access" && estimate.confidence !== "unavailable";
      this.estimateHistory.push({ measuredAt: now, latencyMs: comparable ? estimate.latencyMs : null,
        approximate: estimate?.approximate ?? true, lowerBound: estimate?.evidence === "lower-bound" });
      while (this.estimateHistory.length > 120) this.estimateHistory.shift();
    }
    const activeExits = new Set([...this.flows.values()].filter((flow) => flow.counted && flow.exitId !== "direct").map((flow) => flow.exitId));
    for (const exit of activeExits) void this.ensureMeshPaths(exit);
    for (const [slot, path] of this.paths.entries()) if (path && path.entryNodeId !== path.exitNodeId
      && !activeExits.has(path.exitNodeId) && !this.preparingMesh.has(path.exitNodeId)) {
      path.accepted = false; path.epoch++; path.transport.close(); delete this.paths[slot];
      this.exitPathCounts.set(path.exitNodeId, Math.max(-1, ...this.paths.filter((item) => item?.exitNodeId === path.exitNodeId).map((item) => item.pathSlot)) + 1);
    }
    for (const [key, target] of this.destinations) if (![...this.flows.values()].some((flow) => flow.address === target.address && flow.port === target.port)) this.destinations.delete(key);
    const active = this.playing || [...this.flows.values()].some((flow) => now - flow.touched < 5_000);
    if (now - this.lastProbeAt >= (active ? 1_000 : 60_000)) {
      this.selectActive(); this.ping(); this.requestMeasurements(); this.lastProbeAt = now;
      const carrying = [...this.flows.values()].filter((flow) => flow.counted && flow.exitId !== "direct")
        .sort((a, b) => b.sent - a.sent)[0];
      const best = this.paths.filter((path) => path?.active && path.exitNodeId === carrying?.exitId && path.instance === carrying.instance)
        .sort((a, b) => a.latencyMs! - b.latencyMs!)[0];
      if (best?.latencyMs !== null && best?.latencyMs !== undefined) this.limitedByUpload = this.uploadGuard.update(best.lastLatencyMs ?? best.latencyMs, this.uploadBytes,
        this.paths.filter((path) => path?.active && path.exitNodeId === best.exitNodeId && path.instance === best.instance).length, now);
      this.uploadBytes = 0;
    }
    for (const [slot, route] of this.paths.entries()) if (route?.accepted && !route.repairing && (route.transport.closed || performance.now() - route.lastReply >= (active ? 6_000 : 65_000))) void this.repair(slot);
  }
  private forward(flow: Flow, payload: Buffer): void {
    flow.touched = Date.now(); flow.sent++;
    if (!flow.exitId) {
      this.selectActive();
      if (flow.counted) this.admitTarget(flow);
      const selected = this.decideExit(flow, flow.counted, flow.gameId);
      if (!selected) return;
      flow.exitId = selected.decision.exitId; flow.decision = { ...selected.decision, selectedAt: Date.now() };
      if (flow.counted && this.options.exitScope === "session") this.sessionExit = flow.exitId;
      if (flow.counted) this.lastExit = flow.exitId;
      const route = this.paths.filter((path) => path?.exitNodeId === flow.exitId && path.accepted && path.active && !path.transport.closed
        && performance.now() - path.lastReply < (this.playing ? 6000 : 65000)).sort((a, b) => a.latencyMs! - b.latencyMs!)[0];
      flow.instance = route?.instance ?? null; flow.session = route?.session ?? null;
      if (flow.counted && flow.exitId !== "direct") void this.ensureMeshPaths(flow.exitId);
      this.requestMeasurements();
      if (flow.exitId === "direct") {
        flow.pending.push(Buffer.from(payload));
        if (flow.counted) this.uploaded++;
        void this.openDirect(flow); return;
      }
    }
    if (flow.exitId === "direct") {
      if (flow.direct) flow.direct.send(payload);
      else if (flow.pending.length < 8) flow.pending.push(Buffer.from(payload));
    } else {
      const packet: Packet = { kind: Kind.Up, path: 0, session: this.session, flow: flow.id,
        sequence: flow.sequence++, address: flow.address, port: flow.port, payload };
      const paths = this.activePaths(flow); flow.maxPathCount = Math.max(flow.maxPathCount, paths.length);
      for (const route of paths) {
        route.transport.send(encode({ ...packet, session: flow.session ?? route.session, path: route.pathSlot, ...(route.modern ? { version: 2 as const, exitNodeId: flow.exitId,
          hops: 0, instance: Buffer.from(flow.instance!, "hex") } : {}) })); this.uploadBytes += payload.length;
      }
    }
    if (flow.counted) this.uploaded++;
  }
  private decideExit(target: ProbeTarget, counted: boolean, gameId = this.options.gameId) {
    const estimates = this.estimates(target, true);
    const history = this.options.history?.filter((item) => item.gameId === gameId && item.subnet === subnet24(target.address))
      .sort((a, b) => b.updatedAt - a.updatedAt)[0];
    const historyId = estimates.every((item) => item.confidence === "access" || item.confidence === "unavailable") ? history?.nodeId : null;
    const preference = this.options.preferredExitId ? this.canonical(this.options.preferredExitId) : null;
    const fallbackHistory = historyId ? this.canonical(historyId) : null;
    const selected = chooseExit(estimates, this.lastExit, preference ?? fallbackHistory);
    const session = counted && this.options.exitScope === "session" ? this.sessionExit ?? this.primaryExitId : null;
    if (session && Boolean(this.node(session) && this.node(session)!.state !== "enabled")) return null;
    const exitId = session ?? selected?.nodeId; if (!exitId) return null;
    const estimate = estimates.find((item) => item.nodeId === exitId) ?? null;
    const source: GameRouteDecision["source"] = session ? "session" : exitId === preference ? "manual" : exitId === fallbackHistory ? "history"
      : estimate?.evidence === "access" || estimate?.evidence === "unavailable" ? "access" : "measured";
    const reason = source === "session" ? "Сохранён выход текущего запуска игры"
      : source === "manual" ? "Выход выбран вручную при открытии UDP-потока"
      : source === "history" ? "Выход выбран по сохранённой истории игры: полных замеров при открытии потока ещё не было"
      : source === "access" ? "При открытии потока замеров до сервера ещё не было; выход выбран по задержке A"
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
        if (!this.flows.has(flow.id.toString("hex"))) return;
        flow.received++; flow.touched = Date.now(); if (flow.counted) this.received++; this.deliver(flow, payload);
      }, this.abort.signal, { address: flow.address, port: flow.port });
      if (this.abort.signal.aborted || !this.flows.has(flow.id.toString("hex"))) { transport.close(); return; }
      flow.direct = transport; for (const payload of flow.pending) transport.send(payload); flow.pending = []; flow.maxPathCount = 1;
    } catch { flow.pending = []; /* Keep this flow pinned, fail closed. */ }
  }
  private estimates(target: ProbeTarget, prospective = false) {
    const candidates: ExitCandidate[] = [];
    const exitIds = new Set(this.paths.filter((path) => path?.accepted).map((path) => path.exitNodeId));
    for (const nodeId of exitIds) {
      const paths = this.paths.filter((path) => path?.accepted && path.exitNodeId === nodeId && !path.transport.closed
        && performance.now() - path.lastReply < (this.playing ? 6_000 : 65_000) && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples);
      const best = paths.sort((a, b) => a.latencyMs! - b.latencyMs!)[0]; if (!best) continue;
      const node = this.node(nodeId);
      candidates.push({ nodeId, state: node?.state ?? "enabled", access: best.quality.snapshot(),
        egress: this.measurements.get(nodeId) ?? [], cpuPercent: this.paths.find((path) => path?.entryNodeId === nodeId && path.entryNodeId === path.exitNodeId)?.cpuPercent ?? best.cpuPercent,
        processingNodes: best.entryNodeId === best.exitNodeId ? 1 : 2, networkBytesPerSecond: best.networkBytesPerSecond, activeFlows: best.activeFlows });
    }
    const direct = this.directMeasurements.get(`${target.address}:${target.port}`);
    if (direct && this.options.directSocksPort) candidates.push({ nodeId: "direct", state: "enabled", access: null, egress: [], direct });
    const regions = [...new Set([...this.measurements.values()].flatMap((items) => items.flatMap((item) => item.metric.region ? [item.metric.region] : [])))];
    const metadata = [...this.measurements.values()].flat().find((item) => item.address === target.address && item.port === target.port)?.metric;
    const destination = { ...target, ...(metadata?.routeKey ? { routeKey: metadata.routeKey } : {}), ...(metadata?.region ? { region: metadata.region } : {}) };
    return candidates.map((candidate) => {
      const available = [estimateExit(candidate, destination, regions)];
      if (prospective && candidate.nodeId !== "direct") for (const entry of this.paths) {
        if (!entry?.accepted || !entry.modern || !entry.mesh || entry.entryNodeId !== entry.exitNodeId || entry.entryNodeId === candidate.nodeId
          || entry.transport.closed || performance.now() - entry.lastReply >= (this.playing ? 6000 : 65000)) continue;
        const row = this.meshRows.get(entry.entryNodeId)?.find((item) => item.nodeId === candidate.nodeId);
        if (!row) continue;
        available.push(estimateExit({ ...candidate, access: entry.quality.snapshot(), mesh: row.quality, processingNodes: 2 }, destination, regions));
      }
      return chooseExit(available) ?? available[0]!;
    });
  }
  private comparisons(target: ProbeTarget): GameExitComparison[] {
    return this.estimates(target).map((estimate) => {
      const node = this.node(estimate.nodeId);
      const path = this.paths.filter((item) => item?.exitNodeId === estimate.nodeId).sort((a, b) => a.latencyMs! - b.latencyMs!)[0];
      return { nodeId: estimate.nodeId, name: estimate.nodeId === "direct" ? "Напрямую, без VPN" : node?.name ?? "Игровой узел",
        state: node?.state ?? "enabled", access: path?.quality.snapshot() ?? null, egress: estimate.egress,
        direct: this.directMeasurements.get(`${target.address}:${target.port}`) ?? null, estimatedRttMs: estimate.confidence === "access" ? null : estimate.latencyMs,
        jitterMs: estimate.jitterMs, lossPercent: estimate.confidence === "access" ? null : estimate.lossPercent,
        confidence: estimate.confidence, evidence: estimate.evidence, approximate: estimate.approximate,
        ...(estimate.nodeId !== "direct" ? { egressStatus: this.egressStatus(estimate.nodeId, target, estimate.egress) } : {}),
        reason: estimate.nodeId === "direct" ? "Прямой путь через физический интерфейс, без VPN" : estimate.confidence === "access"
          ? "Замер до сервера ещё не готов; выбран вход с наименьшей задержкой" : "Оценка до этого сервера по A + B; текущие потоки сохраняют выход" };
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
    for (const path of this.paths) if (path) path.active = false;
    // Distinct relay instances are independent exits even when an operator
    // accidentally gives them the same nodeId. Never mix their copies.
    const groups = new Map<string, Path[]>();
    for (const path of this.paths) if (path?.accepted && path.instance && !path.transport.closed
      && performance.now() - path.lastReply < (this.playing ? 6000 : 65000) && path.quality.snapshot().samples >= GAME_POLICY.minimumSamples) {
      const key = `${path.exitNodeId}:${path.instance}`;
      groups.set(key, [...(groups.get(key) ?? []), path]);
    }
    for (const paths of groups.values()) for (const path of chooseIngress(paths, this.options.protection, this.limitedByUpload)) path.active = true;
  }
  private async repair(slot: number): Promise<void> {
    const route = this.paths[slot]; if (!route || this.abort.signal.aborted) return;
    route.repairing = true; route.active = false; route.lastReply = -Infinity;
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
    const sequence = this.pingSequence++ >>> 0;
    for (const [key, sent] of route.sent) if (performance.now() - sent >= 1500) { route.quality.push(null); route.sent.delete(key); }
    route.sent.set(sequence, performance.now());
    route.transport.send(encode({ kind: Kind.Ping, path: route.pathSlot, session: route.session, flow: Buffer.alloc(8), sequence,
      address: "0.0.0.0", port: 0, payload: Buffer.from([route.active ? 1 : 0]),
      ...(route.modern ? { version: 2 as const, exitNodeId: route.exitNodeId, hops: 0 } : {}) }));
  }
  private control(route: Path, kind: Kind.NodeInfo | Kind.ProbeRequest | Kind.MeshRow, body: unknown): void {
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
  private requestMeasurements(): void {
    const targets = [...this.destinations.values()]; if (!targets.length || this.abort.signal.aborted) return;
    const nodes = new Set<string>();
    for (const route of this.paths) if (route?.accepted && !route.transport.closed && performance.now() - route.lastReply < (this.playing ? 6000 : 65000) && !nodes.has(route.exitNodeId)) {
      nodes.add(route.exitNodeId);
      const keys = targets.map((target) => `${target.address}:${target.port}`);
      let query = this.queries.get(route.exitNodeId);
      if (!query) query = { session: route.session, targets: new Set(), handshake: true };
      if (new Set([...query.targets, ...keys]).size > 32) query = { session: randomBytes(32), targets: new Set(), handshake: false };
      for (const key of keys) query.targets.add(key);
      this.queries.set(route.exitNodeId, query);
      this.control(route, Kind.NodeInfo, {});
      if (route.modern && route.probe) this.control(route, Kind.ProbeRequest, { targets });
      if (route.modern && route.mesh) this.control(route, Kind.MeshRow, {});
    }
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
  private receive(path: number, data: Buffer): void {
    const packet = decode(data); const route = this.paths[path];
    if (!packet || !route || packet.path !== route.pathSlot) return;
    const query = this.queries.get(route.exitNodeId);
    const queryReply = packet.kind !== Kind.Down && query?.session.equals(packet.session);
    const flowSession = packet.kind === Kind.Down && this.flows.get(packet.flow.toString("hex"))?.session?.equals(packet.session);
    if (!packet.session.equals(route.session) && !queryReply && !flowSession) return;
    if (packet.kind === Kind.Pong && packet.payload.length === 16) {
      const started = route.sent.get(packet.sequence); if (started === undefined) return;
      if (route.instance && route.instance !== packet.payload.toString("hex")) {
        route.lastReply = -Infinity; route.accepted = false; route.transport.close(); return;
      }
      if (queryReply && query) query.handshake = true;
      route.sent.delete(packet.sequence); route.instance = packet.payload.toString("hex");
      route.lastLatencyMs = performance.now() - started; route.quality.push(route.lastLatencyMs); route.latencyMs = route.quality.snapshot().latencyMs;
      route.lastReply = performance.now(); if (route.modern) route.accepted = true; return;
    }
    if (packet.version === 2 && packet.kind >= Kind.NodeInfo) {
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
        }
        route.modern = true; route.mesh = body.capabilities.mesh === true; route.probe = body.capabilities.probe === true;
        if (!route.probe) { this.measurements.delete(route.exitNodeId); this.probeStates.set(route.exitNodeId, "service-unavailable"); }
        const load = isRecord(body.load) ? body.load : {};
        const finite = (key: string): number => typeof load[key] === "number" && Number.isFinite(load[key]) ? Math.max(0, load[key]) : 0;
        route.cpuPercent = Math.min(100, finite("cpuPercent"));
        route.networkBytesPerSecond = Math.max(finite("networkRxBytesPerSecond"), finite("networkTxBytesPerSecond"));
        route.activeFlows = Math.min(1024, finite("activeFlows"));
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
      } else if (packet.kind === Kind.ProbeResult && Array.isArray(body.results)) {
        if (body.status === "service-unavailable") {
          this.measurements.delete(route.exitNodeId); this.probeStates.set(route.exitNodeId, "service-unavailable"); return;
        }
        if (!body.results.length) {
          this.measurements.delete(route.exitNodeId); this.probeStates.set(route.exitNodeId, "collecting"); return;
        }
        const existing = this.measurements.get(route.exitNodeId) ?? [];
        let accepted = false;
        for (const value of body.results.slice(0, 32)) {
          const item = parseMeasurement(value);
          if (!item || !this.destinations.has(`${item.address}:${item.port}`)) continue;
          const index = existing.findIndex((entry) => entry.address === item.address && entry.port === item.port);
          const metric = { address: item.address, port: item.port, metric: this.segment(item) };
          accepted = true;
          if (index < 0) existing.push(metric); else existing[index] = metric;
        }
        if (accepted) this.probeStates.delete(route.exitNodeId);
        this.measurements.set(route.exitNodeId, existing.slice(-32));
      }
      return;
    }
    if (packet.kind !== Kind.Down) return;
    const flow = this.flows.get(packet.flow.toString("hex"));
    if (!flow || flow.address !== packet.address || flow.port !== packet.port || flow.exitId !== route.exitNodeId || flow.instance !== route.instance) return;
    const active = this.paths.filter((item) => item?.exitNodeId === flow.exitId && item.instance === flow.instance && item.active).sort((a, b) => a.latencyMs! - b.latencyMs!);
    flow.evidence.observe(packet.sequence, route.pathSlot, active[0]?.pathSlot ?? route.pathSlot, active.length);
    if (!flow.seen.accept(packet.sequence)) { if (flow.counted) this.duplicates++; return; }
    flow.received++; flow.touched = Date.now();
    if (flow.counted) { this.received++; route.wins++; }
    route.lastReply = performance.now(); this.deliver(flow, packet.payload);
  }
  private deliver(flow: Flow, payload: Buffer): void {
    const header = Buffer.alloc(flow.xudp ? 16 : 2);
    if (flow.xudp) { header.writeUInt16BE(12, 0); header[4] = 2; header[5] = 1; header[6] = 2;
      header.writeUInt16BE(flow.port, 7); header[9] = 1; Buffer.from(flow.address.split(".").map(Number)).copy(header, 10); }
    header.writeUInt16BE(payload.length, header.length - 2);
    if (flow.socket.writableLength > 128 * 1024) { flow.socket.destroy(); return; }
    flow.socket.write(Buffer.concat([header, payload]));
  }
  private finishFlow(flow: Flow): void {
    if (flow.finished) return; flow.finished = true; flow.cleanup();
    flow.direct?.close(); flow.pending = [];
    if (flow.kind !== "match" || (this.matchReport && this.matchReport.endedAt > flow.touched)) return;
    const metric = this.measurements.get(flow.exitId)?.find((item) => item.address === flow.address && item.port === flow.port)?.metric;
    this.lastMatch = { address: flow.address, port: flow.port, ...(metric?.region ? { region: metric.region } : {}), ...(metric?.operator ? { operator: metric.operator } : {}) };
    const sorted = [...flow.latencyHistory].sort((a, b) => a - b); const now = flow.touched;
    this.matchReport = { startedAt: flow.startedAt, endedAt: now, durationMs: now - flow.startedAt,
      averageRttMs: sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null,
      p95RttMs: sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? null,
      jitterMs: flow.latencyHistory.length > 1 ? flow.latencyHistory.slice(1).reduce((sum, value, index) => sum + Math.abs(value - flow.latencyHistory[index]!), 0) / (flow.latencyHistory.length - 1) : null,
      ...flow.evidence.snapshot(), receivedPackets: flow.received, approximate: true, gameId: flow.gameId,
      server: { ...this.lastMatch }, exitId: flow.exitId, exitName: flow.decision?.exitName ?? this.node(flow.exitId)?.name ?? "Игровой узел",
      ...(flow.decision ? { routeDecision: { ...flow.decision } } : {}),
      protection: { enabled: flow.protectionRequested, pathCount: flow.maxPathCount }, lowerBound: flow.lowerBoundSamples };
  }
  async stop(): Promise<void> {
    this.password = ""; this.abort.abort(); if (this.timer) clearInterval(this.timer); this.timer = null;
    for (const flow of this.flows.values()) this.finishFlow(flow);
    this.paths.forEach((path) => path?.transport.close()); this.paths = [];
    this.connections.forEach((socket) => socket.destroy()); this.connections.clear(); this.flows.clear();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve())); this.server = null;
  }
}
