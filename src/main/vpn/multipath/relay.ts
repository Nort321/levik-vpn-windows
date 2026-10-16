import { createSocket, type Socket, type RemoteInfo } from "node:dgram";
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { decode, encode, HEADER_V3, MAX_PAYLOAD, Kind, publicIPv4, RELAY_PORT, SequenceWindow, PING_ACTIVE, PING_FEC, PING_SPREAD,
  controlPayload, instanceMatches, isRecord, nodeTag, parseControl, parseMeasurement, tagResolver, validNodeId,
  type Packet, type ProbeTarget, type TagResolver } from "./wire";
import { DelayQueue, FecDecoder, FecEncoder, FEC_FLUSH_MS } from "./fec";
import { probeService } from "./probeService";

export const RELAY_LIMITS = Object.freeze({ sessions: 256, flowsPerSession: 64, flows: 4096, peersPerFlow: 64,
  idleMs: 60_000, spreadMs: 2 });
interface Endpoint { address: string; port: number; touched: number; active: boolean; spread: boolean; mesh: boolean; exitNodeId: string; version: 0 | 2 | 3 }
interface Flow { socket: Socket; seen: SequenceWindow; sequence: number; touched: number; flow: Buffer; session: Buffer;
  /** Endpoint-independent mapping: one external port per client socket; replies only from contacted peers. */
  peers: Map<string, number>; decoder: FecDecoder; encoder: FecEncoder; flushTimer: ReturnType<typeof setTimeout> | null }
interface Session { paths: Map<number, Endpoint>; flows: Map<string, Flow>; touched: number; tokens: number; refilled: number;
  targets: Set<string>; controls: number; controlRefilled: number; pending: number; fec: boolean }
export interface RelayOptions {
  port?: number; nodeId?: string; probeSocket?: string; excludedAddresses?: string[];
  mesh?: { address: string; port: number; peers: Array<{ nodeId: string; address: string; port: number }> };
  /** In-process integration tests only. Never accepted by the production entry point. */
  allowTestLoopback?: boolean;
}

/** Reference relay: protocol semantics shared with the production Go relay
 * (levik_game_node). The public Game inbounds authenticate clients before reaching this loopback listener. */
export async function startRelay(options: RelayOptions = {}) {
  const nodeId = options.nodeId ?? "legacy";
  if (!validNodeId(nodeId)) throw new Error("Invalid Game node configuration");
  const validPeers = (peers: NonNullable<RelayOptions["mesh"]>["peers"]): boolean => peers.length <= 64
    && !peers.some((peer) => !validNodeId(peer.nodeId) || peer.nodeId === nodeId || isIP(peer.address) !== 4
      || (!options.allowTestLoopback && !/^10\.77\.0\.\d+$/.test(peer.address))
      || !Number.isInteger(peer.port) || peer.port < 1 || peer.port > 65535)
    && new Set(peers.map((peer) => peer.nodeId)).size === peers.length;
  if (options.mesh && ((!options.allowTestLoopback && !/^10\.77\.0\.\d+$/.test(options.mesh.address))
    || isIP(options.mesh.address) !== 4 || !validPeers(options.mesh.peers))) throw new Error("Invalid Game mesh configuration");
  const socket = createSocket("udp4"); const meshSocket = options.mesh ? createSocket("udp4") : null;
  const instance = randomBytes(16); const sessions = new Map<string, Session>();
  const peers = new Map(options.mesh?.peers.map((peer) => [peer.nodeId, peer]));
  let resolve: TagResolver = tagResolver([nodeId, ...peers.keys()]);
  const excluded = new Set([...(options.excludedAddresses ?? []), ...(options.mesh ? [options.mesh.address, ...options.mesh.peers.map((peer) => peer.address)] : [])]);
  let flowCount = 0; let closing = false; let pending = 0; let probeRegions = false;
  const counts = { forwarded: 0, duplicates: 0, rejected: 0, recovered: 0 };
  const delays = new DelayQueue(() => performance.now());
  const send = (data: Buffer, peer: { address: string; port: number; mesh?: boolean }): void => {
    const transport = peer.mesh ? meshSocket : socket;
    if (!closing && transport) transport.send(data, peer.port, peer.address, () => {});
  };
  const charge = (session: Session, bytes: number, now: number): boolean => {
    session.tokens = Math.min(4_000, session.tokens + Math.max(0, now - session.refilled) * 4); session.refilled = now;
    const cost = Math.max(1, bytes / 1500); if (session.tokens < cost) return false;
    session.tokens -= cost; return true;
  };
  const closeFlow = (flow: Flow): void => { if (flow.flushTimer) clearTimeout(flow.flushTimer); flow.socket.close(); flowCount--; };
  const remove = (key: string, session: Session): void => {
    for (const flow of session.flows.values()) closeFlow(flow); sessions.delete(key);
  };
  const validTarget = (address: string, port: number): boolean => Number.isInteger(port) && port > 0 && port <= 65535 && port !== 25
    && (Boolean(options.allowTestLoopback && address === "127.0.0.1") || (!excluded.has(address) && publicIPv4(address)));
  const capabilities = (serviceAvailable: boolean, result: Record<string, unknown> | null) => ({
    probe: Boolean(serviceAvailable && result?.nodeId === nodeId && isRecord(result?.capabilities) && result.capabilities.probe === true),
    mesh: Boolean(meshSocket), lgm3: true, eim: true, fec: true, spread: true,
    regions: Boolean(serviceAvailable && isRecord(result?.capabilities) && result.capabilities.regions === true) });
  const controls = async (packet: Packet, session: Session, endpoint: Endpoint): Promise<void> => {
    if (packet.version !== 2 || pending >= 16 || session.pending >= 2) return;
    const now = Date.now();
    session.controls = Math.min(8, session.controls + Math.max(0, now - session.controlRefilled) / 125); session.controlRefilled = now;
    if (session.controls < 1) return; session.controls--;
    const body = parseControl(packet.payload); if (!isRecord(body)) { counts.rejected++; return; }
    let request: Record<string, unknown>;
    if (packet.kind === Kind.ProbeRequest) {
      if (!Array.isArray(body.targets) || body.targets.length > 32 || !body.targets.length) { counts.rejected++; return; }
      const targets: ProbeTarget[] = [];
      for (const item of body.targets) {
        if (!isRecord(item) || typeof item.address !== "string" || typeof item.port !== "number" || !validTarget(item.address, item.port)) { counts.rejected++; return; }
        targets.push({ address: item.address, port: item.port });
      }
      const keys = targets.map((target) => `${target.address}:${target.port}`);
      if (new Set([...session.targets, ...keys]).size > 32) { counts.rejected++; return; }
      for (const key of keys) session.targets.add(key);
      request = { version: 2, op: "probe", targets };
    } else if (packet.kind === Kind.NodeInfo) request = { version: 2, op: "health", activeSessions: Math.min(sessions.size, 1024), activeFlows: Math.min(flowCount, 1024) };
    else if (packet.kind === Kind.MeshRow || packet.kind === Kind.Regions) {
      if (body.cursor !== undefined && (!Number.isInteger(body.cursor) || Number(body.cursor) < 0 || Number(body.cursor) > 255)) return;
      request = { version: 2, op: packet.kind === Kind.MeshRow ? "mesh" : "regions", cursor: Number(body.cursor ?? 0) };
    }
    else return;
    session.pending++; pending++;
    try {
      const result = options.probeSocket ? await probeService(options.probeSocket, request) : null;
      if (closing || !sessions.has(packet.session.toString("hex"))) return;
      const serviceAvailable = Boolean(result && !result.error);
      let payload: unknown;
      if (packet.kind === Kind.NodeInfo) {
        const load = isRecord(result?.load) ? result.load : {};
        const caps = capabilities(serviceAvailable, result); probeRegions = caps.regions;
        payload = { version: 2, nodeId, instance: instance.toString("hex"), load: {
          cpuPercent: typeof load.cpuPercent === "number" && Number.isFinite(load.cpuPercent) ? Math.min(100, Math.max(0, load.cpuPercent)) : 0,
          activeSessions: sessions.size, activeFlows: flowCount,
          networkRxBytesPerSecond: typeof load.networkRxBytesPerSecond === "number" && Number.isFinite(load.networkRxBytesPerSecond) ? Math.max(0, load.networkRxBytesPerSecond) : 0,
          networkTxBytesPerSecond: typeof load.networkTxBytesPerSecond === "number" && Number.isFinite(load.networkTxBytesPerSecond) ? Math.max(0, load.networkTxBytesPerSecond) : 0 },
          capabilities: caps };
      } else if (packet.kind === Kind.ProbeRequest) {
        const allowed = new Set(session.targets);
        const results = serviceAvailable && Array.isArray(result?.results) ? result.results.map(parseMeasurement)
          .filter((item) => item !== null && allowed.has(`${item.address}:${item.port}`)).slice(0, 32) : [];
        // Split replies so a batch with offline labels cannot exceed the
        // control-frame budget. All frames retain the request sequence.
        for (let index = 0; index < Math.max(1, results.length); index += 8) send(encode({ ...packet,
          kind: Kind.ProbeResult, exitNodeId: nodeId, instance,
          payload: controlPayload({ version: 2, status: serviceAvailable && Array.isArray(result?.results) ? "ok" : "service-unavailable",
            results: results.slice(index, index + 8) }) }), endpoint);
        return;
      } else if (packet.kind === Kind.Regions) {
        if (!probeRegions && !(serviceAvailable && Array.isArray(result?.regions))) return;
        payload = { version: 2, nodeId, cursor: request.cursor ?? 0, ...(Number.isInteger(result?.nextCursor) ? { nextCursor: result!.nextCursor } : {}),
          regions: serviceAvailable && Array.isArray(result?.regions) ? result.regions.map(parseMeasurement)
            .filter((item) => item !== null && Boolean(item.routeKey)).slice(0, 16) : [] };
      } else {
        payload = { version: 2, nodeId, cursor: request.cursor ?? 0, ...(Number.isInteger(result?.nextCursor) ? { nextCursor: result!.nextCursor } : {}), neighbors: Array.isArray(result?.neighbors) ? result.neighbors.filter((item: unknown) =>
          isRecord(item) && typeof item.nodeId === "string" && peers.has(item.nodeId)
          && typeof item.medianMs === "number" && Number.isFinite(item.medianMs) && item.medianMs >= 0).slice(0, 16) : [] };
      }
      send(encode({ ...packet,
        exitNodeId: nodeId, instance, payload: controlPayload(payload) }), endpoint);
    } finally { session.pending--; pending--; }
  };
  /** Down copies go to every active path; a "spread" path gets its copy a little later. */
  const sendDown = (session: Session, flow: Flow, kind: Kind.Down | Kind.Parity, sequence: number, address: string, port: number, payload: Buffer, now: number): void => {
    const activePaths: Array<[number, Endpoint]> = [];
    for (const entry of session.paths) if (entry[1].active && entry[1].exitNodeId === nodeId && now - entry[1].touched < 10_000) activePaths.push(entry);
    if (!activePaths.length || !charge(session, (payload.length + HEADER_V3) * activePaths.length, now)) return;
    // Parity rides on one path only: the last active one, which is a backup when two or more exist.
    const targets = kind === Kind.Parity ? activePaths.slice(-1) : activePaths;
    for (const [path, destination] of targets) {
      const data = encode({ kind, path, session: flow.session, flow: flow.flow, sequence, address, port, payload,
        ...(destination.version ? { version: destination.version, exitNodeId: nodeId, instance, hops: destination.mesh ? 1 : 0 } : {}) });
      if (destination.spread && kind === Kind.Down) delays.push(RELAY_LIMITS.spreadMs, () => send(data, destination)); else send(data, destination);
    }
  };
  const forwardUp = (flow: Flow, address: string, port: number, payload: Buffer, now: number): void => {
    const key = `${address}:${port}`;
    if (!flow.peers.has(key) && flow.peers.size >= RELAY_LIMITS.peersPerFlow) {
      let oldest: string | null = null; let at = Infinity;
      for (const [peer, touched] of flow.peers) if (touched < at) { at = touched; oldest = peer; }
      if (oldest) flow.peers.delete(oldest);
    }
    flow.peers.set(key, now); flow.touched = now; counts.forwarded++;
    flow.socket.send(payload, port, address, () => {});
  };
  const receive = (data: Buffer, remote: RemoteInfo, fromMesh: boolean): void => {
    if (!fromMesh && remote.address !== "127.0.0.1") return;
    const packet = decode(data, resolve); if (!packet) { counts.rejected++; return; }
    const peer = fromMesh ? [...peers.values()].find((item) => item.address === remote.address && item.port === remote.port) : null;
    if (fromMesh && (!peer || !packet.version || packet.hops !== 1)) { counts.rejected++; return; }
    const key = packet.session.toString("hex"); const now = Date.now();
    let session = sessions.get(key);
    const reply = packet.kind === Kind.Pong || packet.kind === Kind.Down || packet.kind === Kind.ProbeResult
      || (fromMesh && packet.kind === Kind.Parity && session?.paths.get(packet.path)?.exitNodeId === peer?.nodeId && packet.exitNodeId === peer?.nodeId)
      || ((packet.kind === Kind.NodeInfo || packet.kind === Kind.MeshRow || packet.kind === Kind.Regions) && packet.payload.length > 2);
    if (fromMesh && reply) {
      const endpoint = session?.paths.get(packet.path);
      if (!endpoint || endpoint.mesh || endpoint.exitNodeId !== peer!.nodeId || packet.exitNodeId !== peer!.nodeId
        || !charge(session!, data.length, now)) return;
      if (endpoint.spread && packet.kind === Kind.Down) delays.push(RELAY_LIMITS.spreadMs, () => send(data, endpoint)); else send(data, endpoint);
      return;
    }
    if (![Kind.Ping, Kind.Up, Kind.Parity, Kind.NodeInfo, Kind.ProbeRequest, Kind.MeshRow, Kind.Regions].includes(packet.kind)) return;
    if (!session) {
      if (packet.kind !== Kind.Ping || packet.payload.length > 32 || sessions.size >= RELAY_LIMITS.sessions) return;
      session = { paths: new Map(), flows: new Map(), touched: now, tokens: 4_000, refilled: now,
        targets: new Set(), controls: 8, controlRefilled: now, pending: 0, fec: false }; sessions.set(key, session);
    }
    if (!charge(session, data.length, now)) return;
    session.touched = now;
    const flags = packet.kind === Kind.Ping ? packet.payload[0] ?? 0 : 0;
    const previous = session.paths.get(packet.path);
    const endpoint: Endpoint = { address: remote.address, port: remote.port, touched: now,
      active: packet.kind === Kind.Up || packet.kind === Kind.Parity ? previous?.active ?? true : (flags & PING_ACTIVE) !== 0,
      spread: packet.kind === Kind.Ping ? (flags & PING_SPREAD) !== 0 : previous?.spread ?? false,
      mesh: fromMesh, exitNodeId: packet.exitNodeId || nodeId, version: packet.version ?? 0 };
    if (packet.kind === Kind.Ping) session.fec = (flags & PING_FEC) !== 0;
    if (packet.kind === Kind.Ping || packet.kind === Kind.Up || packet.kind === Kind.Parity) session.paths.set(packet.path, endpoint);
    if (!fromMesh && packet.version && packet.exitNodeId && packet.exitNodeId !== nodeId) {
      const exit = peers.get(packet.exitNodeId);
      if (!exit || !meshSocket || packet.hops !== 0) { counts.rejected++; return; }
      send(encode({ ...packet, hops: 1 }), { ...exit, mesh: true }); return;
    }
    if (fromMesh && packet.exitNodeId !== nodeId) { counts.rejected++; return; }
    if (!instanceMatches(packet.instance, instance)) { counts.rejected++; return; }
    if (packet.kind === Kind.Ping) {
      if (packet.payload.length <= 32) send(encode({ ...packet, kind: Kind.Pong, payload: instance,
        ...(packet.version ? { exitNodeId: nodeId, instance } : {}) }), endpoint); return;
    }
    if (packet.kind !== Kind.Up && packet.kind !== Kind.Parity) { void controls(packet, session, endpoint).catch(() => { counts.rejected++; }); return; }
    if (packet.kind === Kind.Up && (!validTarget(packet.address, packet.port) || packet.payload.length > MAX_PAYLOAD)) { counts.rejected++; return; }
    const flowId = packet.flow.toString("hex"); let flow = session.flows.get(flowId);
    if (!flow) {
      if (packet.kind === Kind.Parity) return;
      if (session.flows.size >= RELAY_LIMITS.flowsPerSession || flowCount >= RELAY_LIMITS.flows) return;
      const upstream = createSocket("udp4");
      flow = { socket: upstream, seen: new SequenceWindow(), sequence: 0, touched: now, flow: Buffer.from(packet.flow), session: Buffer.from(packet.session),
        peers: new Map(), decoder: new FecDecoder(), encoder: new FecEncoder(), flushTimer: null };
      session.flows.set(flowId, flow); flowCount++;
      const targetFlow = flow; const targetSession = session;
      upstream.on("error", () => {});
      upstream.on("message", (payload, source) => {
        const at = Date.now();
        if (!targetFlow.peers.has(`${source.address}:${source.port}`) || payload.length > MAX_PAYLOAD || targetFlow.sequence >= 0xffffffff) return;
        targetFlow.touched = at; targetFlow.peers.set(`${source.address}:${source.port}`, at);
        const sequence = targetFlow.sequence++;
        sendDown(targetSession, targetFlow, Kind.Down, sequence, source.address, source.port, payload, at);
        if (!targetSession.fec) return;
        const parity = targetFlow.encoder.add({ sequence, address: source.address, port: source.port, payload });
        if (parity) sendDown(targetSession, targetFlow, Kind.Parity, parity.sequence, "0.0.0.0", 0, parity.payload, at);
        if (targetFlow.flushTimer) clearTimeout(targetFlow.flushTimer);
        targetFlow.flushTimer = targetFlow.encoder.open ? setTimeout(() => {
          targetFlow.flushTimer = null; const late = targetFlow.encoder.flush();
          if (late) sendDown(targetSession, targetFlow, Kind.Parity, late.sequence, "0.0.0.0", 0, late.payload, Date.now());
        }, FEC_FLUSH_MS) : null;
      });
    }
    if (packet.kind === Kind.Parity) {
      const recovered = flow.decoder.parity(packet.sequence, packet.payload);
      if (recovered && validTarget(recovered.address, recovered.port) && flow.seen.accept(recovered.sequence)) { counts.recovered++; forwardUp(flow, recovered.address, recovered.port, recovered.payload, now); }
      return;
    }
    if (!flow.seen.accept(packet.sequence)) { counts.duplicates++; return; }
    forwardUp(flow, packet.address, packet.port, packet.payload, now);
    const recovered = flow.decoder.data({ sequence: packet.sequence, address: packet.address, port: packet.port, payload: packet.payload });
    if (recovered && validTarget(recovered.address, recovered.port) && flow.seen.accept(recovered.sequence)) { counts.recovered++; forwardUp(flow, recovered.address, recovered.port, recovered.payload, now); }
  };
  socket.on("error", () => {}); socket.on("message", (data, remote) => receive(data, remote, false));
  meshSocket?.on("error", () => {}); meshSocket?.on("message", (data, remote) => receive(data, remote, true));
  const bind = async (transport: Socket, port: number, address: string): Promise<void> => new Promise((resolve, reject) => {
    transport.once("error", reject); transport.bind(port, address, () => { transport.removeListener("error", reject); resolve(); });
  });
  try { await bind(socket, options.port ?? RELAY_PORT, "127.0.0.1"); if (meshSocket && options.mesh) await bind(meshSocket, options.mesh.port, options.mesh.address); }
  catch (error) { socket.close(); try { meshSocket?.close(); } catch { /* Not bound. */ } throw error; }
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, session] of sessions) {
      if (now - session.touched > RELAY_LIMITS.idleMs) { remove(key, session); continue; }
      for (const [id, flow] of session.flows) if (now - flow.touched > RELAY_LIMITS.idleMs) { closeFlow(flow); session.flows.delete(id); }
    }
  }, 10_000); timer.unref();
  return { port: socket.address().port, meshPort: meshSocket?.address().port ?? null, counts, overheadBytes: HEADER_V3, tag: nodeTag(nodeId),
    get activeFlows(): number { return flowCount; },
    reloadPeers(next: NonNullable<RelayOptions["mesh"]>["peers"]): void {
      if (!meshSocket || !validPeers(next)) throw new Error("Invalid Game mesh configuration");
      const nextResolve = tagResolver([nodeId, ...next.map((peer) => peer.nodeId)]);
      peers.clear(); for (const peer of next) { peers.set(peer.nodeId, peer); excluded.add(peer.address); }
      resolve = nextResolve;
    },
    close: async (): Promise<void> => { closing = true; clearInterval(timer); delays.clear(); for (const [key, session] of sessions) remove(key, session);
      await Promise.all([socket, ...(meshSocket ? [meshSocket] : [])].map((transport) => new Promise<void>((resolve) => transport.close(() => resolve())))); } };
}
