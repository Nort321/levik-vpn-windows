import { createSocket, type Socket, type RemoteInfo } from "node:dgram";
import { randomBytes } from "node:crypto";
import { decode, encode, HEADER, MAX_PAYLOAD, Kind, publicIPv4, RELAY_PORT, SequenceWindow, type Packet } from "./wire";

interface Flow { socket: Socket; seen: SequenceWindow; sequence: number; address: string; port: number; touched: number }
interface Session { paths: Map<number, { address: string; port: number; touched: number; active: boolean }>; flows: Map<string, Flow>; touched: number; tokens: number; refilled: number }

/** Loopback-only egress. Access is granted by the node's Game inbound rule. */
export async function startRelay(options: { port?: number; allowTestLoopback?: boolean } = {}) {
  const socket = createSocket("udp4");
  const instance = randomBytes(16);
  const sessions = new Map<string, Session>();
  let flowCount = 0;
  let closing = false;
  const counts = { forwarded: 0, duplicates: 0, rejected: 0 };
  const send = (data: Buffer, peer: { address: string; port: number }): void => { if (!closing) socket.send(data, peer.port, peer.address, () => {}); };
  const charge = (session: Session, bytes: number, now: number): boolean => {
    session.tokens = Math.min(2_000, session.tokens + Math.max(0, now - session.refilled) * 2); session.refilled = now;
    const cost = Math.max(1, bytes / 1500);
    if (session.tokens < cost) return false;
    session.tokens -= cost; return true;
  };
  const remove = (key: string, session: Session): void => {
    for (const flow of session.flows.values()) { flow.socket.close(); flowCount--; }
    sessions.delete(key);
  };
  socket.on("error", () => { /* Datagram errors are counted by the client as missing replies. */ });
  socket.on("message", (data: Buffer, remote: RemoteInfo) => {
    if (remote.address !== "127.0.0.1") return;
    const packet = decode(data);
    if (!packet || (packet.kind !== Kind.Ping && packet.kind !== Kind.Up)) { counts.rejected++; return; }
    const now = Date.now();
    const key = packet.session.toString("hex");
    let session = sessions.get(key);
    if (!session) {
      // Handshake first, preventing unsolicited data from allocating UDP sockets.
      if (packet.kind !== Kind.Ping || packet.payload.length > 32 || sessions.size >= 128) return;
      session = { paths: new Map(), flows: new Map(), touched: now, tokens: 2_000, refilled: now };
      sessions.set(key, session);
    }
    if (!charge(session, data.length, now)) return;
    session.touched = now;
    session.paths.set(packet.path, { address: remote.address, port: remote.port, touched: now, active: packet.kind === Kind.Up || packet.payload[0] !== 0 });
    if (packet.kind === Kind.Ping) {
      if (packet.payload.length <= 32) send(encode({ ...packet, kind: Kind.Pong, payload: instance }), remote);
      return;
    }
    if (!packet.port || packet.port === 25 || packet.payload.length > MAX_PAYLOAD
      || !(publicIPv4(packet.address) || (options.allowTestLoopback && packet.address === "127.0.0.1"))) { counts.rejected++; return; }
    const flowId = packet.flow.toString("hex");
    let flow = session.flows.get(flowId);
    if (!flow) {
      if (session.flows.size >= 32 || flowCount >= 1024) return;
      const upstream = createSocket("udp4");
      flow = { socket: upstream, seen: new SequenceWindow(), sequence: 0, address: packet.address, port: packet.port, touched: now };
      session.flows.set(flowId, flow);
      flowCount++;
      const targetFlow = flow; const targetSession = session;
      const envelope = { ...packet, session: Buffer.from(packet.session), flow: Buffer.from(packet.flow), payload: Buffer.alloc(0) };
      upstream.on("error", () => {});
      upstream.on("message", (payload, peer) => {
        if (peer.address !== targetFlow.address || peer.port !== targetFlow.port || payload.length > MAX_PAYLOAD || targetFlow.sequence >= 0xffffffff) return;
        const activePaths = [...targetSession.paths].filter(([, endpoint]) => endpoint.active && Date.now() - endpoint.touched < 10_000);
        if (!charge(targetSession, payload.length * activePaths.length, Date.now())) return;
        targetFlow.touched = Date.now();
        const response: Packet = { ...envelope, kind: Kind.Down, sequence: targetFlow.sequence++, payload };
        for (const [path, endpoint] of activePaths) send(encode({ ...response, path }), endpoint);
      });
    }
    if (flow.address !== packet.address || flow.port !== packet.port || !flow.seen.accept(packet.sequence)) { counts.duplicates++; return; }
    flow.touched = now; counts.forwarded++;
    flow.socket.send(packet.payload, packet.port, packet.address, () => {});
  });
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(options.port ?? RELAY_PORT, "127.0.0.1", () => { socket.removeListener("error", reject); resolve(); });
  });
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, session] of sessions) {
      if (now - session.touched > 60_000) { remove(key, session); continue; }
      for (const [id, flow] of session.flows) if (now - flow.touched > 60_000) { flow.socket.close(); session.flows.delete(id); flowCount--; }
    }
  }, 10_000);
  timer.unref();
  return { port: socket.address().port, counts, overheadBytes: HEADER,
    close: async (): Promise<void> => { closing = true; clearInterval(timer); for (const [key, session] of sessions) remove(key, session); await new Promise<void>((resolve) => socket.close(() => resolve())); } };
}
