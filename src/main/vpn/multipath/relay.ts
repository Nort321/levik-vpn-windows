import { createSocket, type Socket, type RemoteInfo } from "node:dgram";
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { decode, encode, HEADER, MAX_PAYLOAD, Kind, publicIPv4, RELAY_PORT, SequenceWindow,
  controlPayload, isRecord, parseControl, parseMeasurement, validNodeId, type Packet, type ProbeTarget } from "./wire";
import { probeService } from "./probeService";

interface Endpoint { address: string; port: number; touched: number; active: boolean; mesh: boolean; exitNodeId: string }
interface Flow { socket: Socket; seen: SequenceWindow; sequence: number; address: string; port: number; touched: number }
interface Session { paths: Map<number, Endpoint>; flows: Map<string, Flow>; touched: number; tokens: number; refilled: number;
  targets: Set<string>; controls: number; controlRefilled: number; pending: number }
export interface RelayOptions {
  port?: number; nodeId?: string; probeSocket?: string; excludedAddresses?: string[];
  mesh?: { address: string; port: number; peers: Array<{ nodeId: string; address: string; port: number }> };
  /** In-process integration tests only. Never accepted by the production entry point. */
  allowTestLoopback?: boolean;
}

/** The public Game inbounds authenticate clients before reaching this loopback listener. */
export async function startRelay(options: RelayOptions = {}) {
  const nodeId = options.nodeId ?? "legacy";
  if (!validNodeId(nodeId)) throw new Error("Invalid Game node configuration");
  if (options.mesh && ((!options.allowTestLoopback && !/^10\.77\.0\.\d+$/.test(options.mesh.address))
    || isIP(options.mesh.address) !== 4 || options.mesh.peers.length > 64
    || options.mesh.peers.some((peer) => !validNodeId(peer.nodeId) || peer.nodeId === nodeId || isIP(peer.address) !== 4
      || (!options.allowTestLoopback && !/^10\.77\.0\.\d+$/.test(peer.address))
      || !Number.isInteger(peer.port) || peer.port < 1 || peer.port > 65535)
    || new Set(options.mesh.peers.map((peer) => peer.nodeId)).size !== options.mesh.peers.length)) throw new Error("Invalid Game mesh configuration");
  const socket = createSocket("udp4"); const meshSocket = options.mesh ? createSocket("udp4") : null;
  const instance = randomBytes(16); const sessions = new Map<string, Session>();
  const peers = new Map(options.mesh?.peers.map((peer) => [peer.nodeId, peer]));
  const excluded = new Set([...(options.excludedAddresses ?? []), ...(options.mesh ? [options.mesh.address, ...options.mesh.peers.map((peer) => peer.address)] : [])]);
  let flowCount = 0; let closing = false; let pending = 0;
  const counts = { forwarded: 0, duplicates: 0, rejected: 0 };
  const send = (data: Buffer, peer: Endpoint | { address: string; port: number; mesh?: boolean }): void => {
    const transport = peer.mesh ? meshSocket : socket;
    if (!closing && transport) transport.send(data, peer.port, peer.address, () => {});
  };
  const charge = (session: Session, bytes: number, now: number): boolean => {
    session.tokens = Math.min(2_000, session.tokens + Math.max(0, now - session.refilled) * 2); session.refilled = now;
    const cost = Math.max(1, bytes / 1500); if (session.tokens < cost) return false;
    session.tokens -= cost; return true;
  };
  const remove = (key: string, session: Session): void => {
    for (const flow of session.flows.values()) { flow.socket.close(); flowCount--; } sessions.delete(key);
  };
  const validTarget = (address: string, port: number): boolean => Number.isInteger(port) && port > 0 && port <= 65535 && port !== 25
    && (Boolean(options.allowTestLoopback && address === "127.0.0.1") || (!excluded.has(address) && publicIPv4(address)));
  const controls = async (packet: Packet, session: Session, endpoint: Endpoint): Promise<void> => {
    if (packet.version !== 2 || pending >= 8 || session.pending >= 2) return;
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
    } else if (packet.kind === Kind.NodeInfo) request = { version: 2, op: "health", activeSessions: sessions.size, activeFlows: flowCount };
    else if (packet.kind === Kind.MeshRow) {
      if (body.cursor !== undefined && (!Number.isInteger(body.cursor) || Number(body.cursor) < 0 || Number(body.cursor) > 63)) return;
      request = { version: 2, op: "mesh", cursor: Number(body.cursor ?? 0) };
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
        payload = { version: 2, nodeId, instance: instance.toString("hex"), load: {
          cpuPercent: typeof load.cpuPercent === "number" && Number.isFinite(load.cpuPercent) ? Math.min(100, Math.max(0, load.cpuPercent)) : 0,
          activeSessions: sessions.size, activeFlows: flowCount,
          networkRxBytesPerSecond: typeof load.networkRxBytesPerSecond === "number" && Number.isFinite(load.networkRxBytesPerSecond) ? Math.max(0, load.networkRxBytesPerSecond) : 0,
          networkTxBytesPerSecond: typeof load.networkTxBytesPerSecond === "number" && Number.isFinite(load.networkTxBytesPerSecond) ? Math.max(0, load.networkTxBytesPerSecond) : 0 },
          capabilities: { probe: Boolean(serviceAvailable && result?.nodeId === nodeId
            && isRecord(result?.capabilities) && result.capabilities.probe === true), mesh: Boolean(meshSocket) } };
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
      } else {
        payload = { version: 2, nodeId, cursor: request.cursor ?? 0, ...(Number.isInteger(result?.nextCursor) ? { nextCursor: result!.nextCursor } : {}), neighbors: Array.isArray(result?.neighbors) ? result.neighbors.filter((item: unknown) =>
          isRecord(item) && typeof item.nodeId === "string" && peers.has(item.nodeId)
          && typeof item.medianMs === "number" && Number.isFinite(item.medianMs) && item.medianMs >= 0).slice(0, 16) : [] };
      }
      send(encode({ ...packet,
        exitNodeId: nodeId, instance, payload: controlPayload(payload) }), endpoint);
    } finally { session.pending--; pending--; }
  };
  const receive = (data: Buffer, remote: RemoteInfo, fromMesh: boolean): void => {
    if (!fromMesh && remote.address !== "127.0.0.1") return;
    const packet = decode(data); if (!packet) { counts.rejected++; return; }
    const peer = fromMesh ? [...peers.values()].find((item) => item.address === remote.address && item.port === remote.port) : null;
    if (fromMesh && (!peer || packet.version !== 2 || packet.hops !== 1)) { counts.rejected++; return; }
    const key = packet.session.toString("hex"); const now = Date.now();
    let session = sessions.get(key);
    const reply = packet.kind === Kind.Pong || packet.kind === Kind.Down || packet.kind === Kind.ProbeResult
      || ((packet.kind === Kind.NodeInfo || packet.kind === Kind.MeshRow) && packet.payload.length > 2);
    if (fromMesh && reply) {
      const endpoint = session?.paths.get(packet.path);
      if (!endpoint || endpoint.mesh || endpoint.exitNodeId !== peer!.nodeId || packet.exitNodeId !== peer!.nodeId
        || !charge(session!, data.length, now)) return;
      send(data, endpoint); return;
    }
    if (![Kind.Ping, Kind.Up, Kind.NodeInfo, Kind.ProbeRequest, Kind.MeshRow].includes(packet.kind)) return;
    if (!session) {
      if (packet.kind !== Kind.Ping || packet.payload.length > 32 || sessions.size >= 128) return;
      session = { paths: new Map(), flows: new Map(), touched: now, tokens: 2_000, refilled: now,
        targets: new Set(), controls: 8, controlRefilled: now, pending: 0 }; sessions.set(key, session);
    }
    if (!charge(session, data.length, now)) return;
    session.touched = now;
    const endpoint: Endpoint = { address: remote.address, port: remote.port, touched: now, active: packet.kind === Kind.Up || packet.payload[0] !== 0,
      mesh: fromMesh, exitNodeId: packet.exitNodeId || nodeId };
    if (packet.kind === Kind.Ping || packet.kind === Kind.Up) session.paths.set(packet.path, endpoint);
    if (!fromMesh && packet.version === 2 && packet.exitNodeId && packet.exitNodeId !== nodeId) {
      const exit = peers.get(packet.exitNodeId);
      if (!exit || !meshSocket || packet.hops !== 0) { counts.rejected++; return; }
      send(encode({ ...packet, hops: 1 }), { ...exit, mesh: true }); return;
    }
    if (fromMesh && packet.exitNodeId !== nodeId) { counts.rejected++; return; }
    if (packet.instance && packet.instance.some((byte) => byte !== 0) && !packet.instance.equals(instance)) { counts.rejected++; return; }
    if (packet.kind === Kind.Ping) {
      if (packet.payload.length <= 32) send(encode({ ...packet, kind: Kind.Pong, payload: instance,
        ...(packet.version ? { exitNodeId: nodeId, instance } : {}) }), endpoint); return;
    }
    if (packet.kind !== Kind.Up) { void controls(packet, session, endpoint).catch(() => { counts.rejected++; }); return; }
    if (!validTarget(packet.address, packet.port) || packet.payload.length > MAX_PAYLOAD) { counts.rejected++; return; }
    const flowId = packet.flow.toString("hex"); let flow = session.flows.get(flowId);
    if (!flow) {
      if (session.flows.size >= 32 || flowCount >= 1024) return;
      const upstream = createSocket("udp4");
      flow = { socket: upstream, seen: new SequenceWindow(), sequence: 0, address: packet.address, port: packet.port, touched: now };
      session.flows.set(flowId, flow); flowCount++;
      const targetFlow = flow; const targetSession = session;
      const envelope: Packet = { ...packet, session: Buffer.from(packet.session), flow: Buffer.from(packet.flow), payload: Buffer.alloc(0),
        ...(packet.version ? { exitNodeId: nodeId, instance } : {}) };
      upstream.on("error", () => {});
      upstream.on("message", (payload, source) => {
        if (source.address !== targetFlow.address || source.port !== targetFlow.port || payload.length > MAX_PAYLOAD || targetFlow.sequence >= 0xffffffff) return;
        const activePaths = [...targetSession.paths].filter(([, path]) => path.active && path.exitNodeId === nodeId && Date.now() - path.touched < 10_000);
        if (!charge(targetSession, payload.length * activePaths.length, Date.now())) return;
        targetFlow.touched = Date.now();
        const response: Packet = { ...envelope, kind: Kind.Down, sequence: targetFlow.sequence++, payload };
        for (const [path, destination] of activePaths) send(encode({ ...response, path,
          ...(packet.version ? { hops: destination.mesh ? 1 : 0 } : {}) }), destination);
      });
    }
    if (flow.address !== packet.address || flow.port !== packet.port || !flow.seen.accept(packet.sequence)) { counts.duplicates++; return; }
    flow.touched = now; counts.forwarded++; flow.socket.send(packet.payload, packet.port, packet.address, () => {});
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
      if (now - session.touched > 60_000) { remove(key, session); continue; }
      for (const [id, flow] of session.flows) if (now - flow.touched > 60_000) { flow.socket.close(); session.flows.delete(id); flowCount--; }
    }
  }, 10_000); timer.unref();
  return { port: socket.address().port, meshPort: meshSocket?.address().port ?? null, counts, overheadBytes: HEADER,
    reloadPeers(next: NonNullable<RelayOptions["mesh"]>["peers"]): void {
      if (!meshSocket || next.length > 64 || new Set(next.map((peer) => peer.nodeId)).size !== next.length
        || next.some((peer) => !validNodeId(peer.nodeId) || peer.nodeId === nodeId || isIP(peer.address) !== 4
          || (!options.allowTestLoopback && !/^10\.77\.0\.\d+$/.test(peer.address))
          || !Number.isInteger(peer.port) || peer.port < 1 || peer.port > 65535)) throw new Error("Invalid Game mesh configuration");
      peers.clear(); for (const peer of next) { peers.set(peer.nodeId, peer); excluded.add(peer.address); }
    },
    close: async (): Promise<void> => { closing = true; clearInterval(timer); for (const [key, session] of sessions) remove(key, session);
      await Promise.all([socket, ...(meshSocket ? [meshSocket] : [])].map((transport) => new Promise<void>((resolve) => transport.close(() => resolve())))); } };
}
