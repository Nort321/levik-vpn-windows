import { createServer, type Server, type Socket } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { openRelayPath, type RelayPath } from "./socks";
import { decode, encode, Kind, MAX_PAYLOAD, SequenceWindow, type Packet } from "./wire";
import type { GameMultipathStats } from "../../../shared/contracts";

interface Path { index: number; transport: RelayPath; instance: string | null; latencyMs: number | null; lastReply: number; sent: Map<number, number>; wins: number }
interface Flow { socket: Socket; address: string; port: number; id: Buffer; sequence: number; seen: SequenceWindow }

/** Two encrypted transports converge on a single relay UDP socket per game flow. */
export class GameMultipath {
  private readonly session = randomBytes(32);
  private readonly flows = new Map<string, Flow>();
  private readonly connections = new Set<Socket>();
  private paths: Path[] = [];
  private abort = new AbortController();
  private server: Server | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private pingSequence = 0;
  private received = 0;
  private duplicates = 0;
  private uploaded = 0;

  snapshot(): GameMultipathStats {
    const paths = this.paths.filter((path) => path !== undefined);
    return { state: paths.filter((p) => performance.now() - p.lastReply < 6_000).length >= 2 ? "protected"
      : paths.some((p) => performance.now() - p.lastReply < 6_000) ? "single" : "unavailable",
    paths: paths.map((p) => ({ routeIndex: p.index, latencyMs: p.latencyMs,
      responding: performance.now() - p.lastReply < 6_000, firstReplies: p.wins })),
    receivedPackets: this.received, duplicateReplies: this.duplicates, uploadedPackets: this.uploaded };
  }

  async listen(): Promise<{ port: number; uuid: string }> {
    const uuid = randomUUID(); const identity = Buffer.from(uuid.replaceAll("-", ""), "hex");
    this.server = createServer((socket) => {
      if (this.connections.size >= 64) { socket.destroy(); return; }
      this.connections.add(socket); socket.setNoDelay(true); socket.setTimeout(60_000, () => socket.destroy());
      let buffer = Buffer.alloc(0); let flow: Flow | null = null;
      socket.on("error", () => {});
      socket.on("close", () => { this.connections.delete(socket); if (flow) this.flows.delete(flow.id.toString("hex")); });
      socket.on("data", (data: Buffer) => {
        buffer = Buffer.concat([buffer, data]);
        if (buffer.length > 128 * 1024) { socket.destroy(); return; }
        if (!flow) {
          if (buffer.length < 18) return;
          if (buffer[0] !== 0 || !buffer.subarray(1, 17).equals(identity) || buffer[17] !== 0) { socket.destroy(); return; }
          if (buffer.length < 26) return;
          // Native UDP VLESS command, numeric IPv4 only. TCP and IPv6 use the ordinary Game route.
          if (buffer[18] !== 2 || buffer[21] !== 1 || !buffer.readUInt16BE(19)) { socket.destroy(); return; }
          flow = { socket, address: [...buffer.subarray(22, 26)].join("."), port: buffer.readUInt16BE(19),
            id: randomBytes(8), sequence: 0, seen: new SequenceWindow() };
          this.flows.set(flow.id.toString("hex"), flow); buffer = buffer.subarray(26); socket.write(Buffer.from([0, 0]));
        }
        while (buffer.length >= 2) {
          const length = buffer.readUInt16BE(0);
          if (length > MAX_PAYLOAD || flow.sequence >= 0xffffffff) { socket.destroy(); return; }
          if (buffer.length < 2 + length) return;
          const packet: Packet = { kind: Kind.Up, path: 0, session: this.session, flow: flow.id,
            sequence: flow.sequence++, address: flow.address, port: flow.port, payload: buffer.subarray(2, 2 + length) };
          for (const [path, route] of this.paths.entries()) route.transport.send(encode({ ...packet, path }));
          this.uploaded++; buffer = buffer.subarray(2 + length);
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

  async connect(candidates: Array<{ index: number; port: number }>, password: string): Promise<void> {
    // Try bounded pairs. Never combine different relay instances / exit sockets.
    for (let first = 0; first < candidates.length && !this.abort.signal.aborted; first++) {
      for (let second = first + 1; second < candidates.length && !this.abort.signal.aborted; second++) {
        this.paths.forEach((p) => p.transport.close()); this.paths = [];
        const chosen = [candidates[first]!, candidates[second]!];
        await Promise.all(chosen.map(async (candidate, slot) => {
          try {
            const transport = await openRelayPath(candidate.port, password, (data) => this.receive(slot, data), this.abort.signal);
            this.paths[slot] = { index: candidate.index, transport, instance: null, latencyMs: null, lastReply: -Infinity, sent: new Map(), wins: 0 };
          } catch { /* Try another eligible pair. */ }
        }));
        // A failed association can leave a sparse array; don't send slot 1 as slot 0.
        if (!this.paths[0] || !this.paths[1]) { this.paths.forEach((p) => p?.transport.close()); this.paths = []; continue; }
        for (let attempt = 0; attempt < 20 && !this.abort.signal.aborted; attempt++) {
          this.ping();
          await new Promise<void>((resolve) => setTimeout(resolve, 200));
          if (this.paths[0].instance && this.paths[0].instance === this.paths[1].instance) break;
        }
        if (this.paths[0].instance && this.paths[0].instance === this.paths[1].instance) {
          this.timer = setInterval(() => this.ping(), 2_000); this.timer.unref(); return;
        }
      }
    }
    this.paths.forEach((p) => p.transport.close()); this.paths = [];
    throw new Error("Два совместимых туннеля Game не найдены. Выберите режим минимальной задержки.");
  }

  private ping(): void {
    if (this.abort.signal.aborted) return;
    const sequence = this.pingSequence++ >>> 0;
    this.paths.forEach((route, path) => {
      route.sent.set(sequence, performance.now());
      while (route.sent.size > 4) route.sent.delete(route.sent.keys().next().value!);
      route.transport.send(encode({ kind: Kind.Ping, path, session: this.session, flow: Buffer.alloc(8),
        sequence, address: "0.0.0.0", port: 0, payload: Buffer.alloc(0) }));
    });
  }

  private receive(path: number, data: Buffer): void {
    const packet = decode(data); const route = this.paths[path];
    if (!packet || !route || packet.path !== path || !packet.session.equals(this.session)) return;
    if (packet.kind === Kind.Pong && packet.payload.length === 16) {
      const started = route.sent.get(packet.sequence); if (started === undefined) return;
      if (route.instance && route.instance !== packet.payload.toString("hex")) {
        route.lastReply = -Infinity; route.transport.close(); return;
      }
      route.sent.delete(packet.sequence); route.instance = packet.payload.toString("hex");
      route.latencyMs = Math.round(performance.now() - started); route.lastReply = performance.now(); return;
    }
    if (packet.kind !== Kind.Down) return;
    const flow = this.flows.get(packet.flow.toString("hex"));
    if (!flow || flow.address !== packet.address || flow.port !== packet.port) return;
    if (!flow.seen.accept(packet.sequence)) { this.duplicates++; return; }
    this.received++; route.wins++;
    const header = Buffer.alloc(2); header.writeUInt16BE(packet.payload.length);
    // Bound a stalled local reader; do not accumulate an unbounded game queue.
    if (flow.socket.writableLength > 128 * 1024) { flow.socket.destroy(); return; }
    flow.socket.write(Buffer.concat([header, packet.payload]));
  }

  async stop(): Promise<void> {
    this.abort.abort(); if (this.timer) clearInterval(this.timer); this.timer = null;
    this.paths.forEach((p) => p.transport.close()); this.paths = [];
    this.connections.forEach((socket) => socket.destroy()); this.connections.clear(); this.flows.clear();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }
}
