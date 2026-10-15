import { createServer, type Server, type Socket } from "node:net";
import { randomBytes, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { openRelayPath, type RelayPath } from "./socks";
import { decode, encode, Kind, MAX_PAYLOAD, MAX_PATHS, SequenceWindow, type Packet } from "./wire";
import type { GameMultipathStats } from "../../../shared/contracts";

interface Path { index: number; port: number; epoch: number; accepted: boolean; active: boolean; repairing: boolean; transport: RelayPath; instance: string | null; latencyMs: number | null; lastReply: number; sent: Map<number, number>; wins: number }
interface Flow { socket: Socket; address: string; port: number; id: Buffer; sequence: number; seen: SequenceWindow; counted: boolean; xudp: boolean }

/** Multiple encrypted transports converge on a single relay UDP socket per game flow. */
export class GameMultipath {
  constructor(private counting = true) {}

  startCounting(): void { this.counting = true; }
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
  private relayInstance: string | null = null;
  private password = "";

  snapshot(): GameMultipathStats {
    const paths = this.paths.filter((path) => path !== undefined);
    return { state: paths.filter((p) => p.active && performance.now() - p.lastReply < 6_000).length >= 2 ? "protected"
      : paths.some((p) => p.active && performance.now() - p.lastReply < 6_000) ? "single" : "unavailable",
    paths: paths.map((p) => ({ routeIndex: p.index, latencyMs: p.latencyMs,
      responding: p.accepted && performance.now() - p.lastReply < 6_000, active: p.active, firstReplies: p.wins })),
    receivedPackets: this.received, duplicateReplies: this.duplicates, uploadedPackets: this.uploaded };
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
        for (const flow of localFlows.values()) this.flows.delete(flow.id.toString("hex"));
      });
      const forward = (payload: Buffer): void => {
        if (!target) { socket.destroy(); return; }
        const key = `${target.address}:${target.port}`;
        let flow = localFlows.get(key);
        if (!flow) {
          if (this.flows.size >= 32) { socket.destroy(); return; }
          flow = { socket, ...target, id: randomBytes(8), sequence: 0, seen: new SequenceWindow(),
            counted: this.counting, xudp: mode === "xudp" };
          localFlows.set(key, flow); this.flows.set(flow.id.toString("hex"), flow);
        }
        if (flow.sequence >= 0xffffffff) { socket.destroy(); return; }
        const packet: Packet = { kind: Kind.Up, path: 0, session: this.session, flow: flow.id,
          sequence: flow.sequence++, address: flow.address, port: flow.port, payload };
        this.paths.forEach((route, path) => { if (route.active) route.transport.send(encode({ ...packet, path })); });
        if (flow.counted) this.uploaded++;
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

  async connect(candidates: Array<{ index: number; port: number }>, password: string): Promise<void> {
    this.password = password;
    await Promise.all(candidates.slice(0, MAX_PATHS).map(async (candidate, slot) => {
      try {
        const transport = await openRelayPath(candidate.port, password, (data) => this.receive(slot, data), this.abort.signal);
        this.paths[slot] = { index: candidate.index, port: candidate.port, epoch: 0, accepted: false, active: false,
          repairing: false, transport, instance: null, latencyMs: null, lastReply: -Infinity, sent: new Map(), wins: 0 };
      } catch { /* Other candidates can still carry the game. */ }
    }));
    // Probe all candidates concurrently; warm up cold transports before comparing.
    for (let attempt = 0; attempt < 10 && !this.abort.signal.aborted; attempt++) {
      this.ping(); await new Promise<void>((resolve) => setTimeout(resolve, 200));
    }
    const groups = new Map<string, Path[]>();
    this.paths.forEach((route) => {
      if (route.instance && route.latencyMs !== null && performance.now() - route.lastReply < 2_000) {
        groups.set(route.instance, [...(groups.get(route.instance) ?? []), route]);
      }
    });
    const ranked = [...groups.entries()].sort((a, b) =>
      Math.min(...a[1].map((p) => p.latencyMs!)) - Math.min(...b[1].map((p) => p.latencyMs!)) || b[1].length - a[1].length);
    this.relayInstance = ranked[0]?.[0] ?? null;
    if (!this.relayInstance || this.abort.signal.aborted) {
      this.paths.forEach((route) => route.transport.close());
      throw new Error("Game relay unavailable");
    }
    this.paths.forEach((route) => {
      route.accepted = route.instance === this.relayInstance;
      if (!route.accepted) route.transport.close();
    });
    this.selectActive(); this.ping();
    this.timer = setInterval(() => {
      this.selectActive(); this.ping();
      this.paths.forEach((route, slot) => {
        if (route.accepted && !route.repairing && (route.transport.closed || performance.now() - route.lastReply >= 6_000)) void this.repair(slot);
      });
    }, 2_000);
    this.timer.unref();
  }

  private selectActive(): void {
    const healthy = this.paths.filter((p) => p.accepted && !p.transport.closed && performance.now() - p.lastReply < 6_000)
      .sort((a, b) => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity));
    // Keep at least two useful copies; extra near-fastest paths provide redundancy
    // without multiplying every packet across arbitrarily slow transports.
    const selected = new Set(healthy.filter((p, i) => i < 2 || p.latencyMs! <= healthy[0]!.latencyMs! + 25).slice(0, 4));
    this.paths.forEach((route) => { route.active = selected.has(route); });
  }

  private async repair(slot: number): Promise<void> {
    const route = this.paths[slot]; if (!route || this.abort.signal.aborted) return;
    route.repairing = true; route.active = false; route.lastReply = -Infinity;
    const epoch = ++route.epoch; route.sent.clear(); route.transport.close();
    try {
      const transport = await openRelayPath(route.port, this.password, (data) => {
        if (route.epoch === epoch) this.receive(slot, data);
      }, this.abort.signal);
      if (this.abort.signal.aborted) { transport.close(); return; }
      route.transport = transport; this.ping();
    } catch { /* Retry on the next health tick; surviving paths keep their flows. */ }
    finally { route.repairing = false; }
  }

  private ping(): void {
    if (this.abort.signal.aborted) return;
    const sequence = this.pingSequence++ >>> 0;
    this.paths.forEach((route, path) => {
      route.sent.set(sequence, performance.now());
      while (route.sent.size > 4) route.sent.delete(route.sent.keys().next().value!);
      route.transport.send(encode({ kind: Kind.Ping, path, session: this.session, flow: Buffer.alloc(8),
        sequence, address: "0.0.0.0", port: 0, payload: Buffer.from([route.active ? 1 : 0]) }));
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
    if (!flow.seen.accept(packet.sequence)) { if (flow.counted) this.duplicates++; return; }
    if (flow.counted) { this.received++; route.wins++; }
    route.lastReply = performance.now();
    const header = Buffer.alloc(flow.xudp ? 16 : 2);
    if (flow.xudp) {
      header.writeUInt16BE(12, 0); header[4] = 2; header[5] = 1; header[6] = 2;
      header.writeUInt16BE(flow.port, 7); header[9] = 1;
      Buffer.from(flow.address.split(".").map(Number)).copy(header, 10);
    }
    header.writeUInt16BE(packet.payload.length, header.length - 2);
    // Bound a stalled local reader; do not accumulate an unbounded game queue.
    if (flow.socket.writableLength > 128 * 1024) { flow.socket.destroy(); return; }
    flow.socket.write(Buffer.concat([header, packet.payload]));
  }

  async stop(): Promise<void> {
    this.password = ""; this.abort.abort(); if (this.timer) clearInterval(this.timer); this.timer = null;
    this.paths.forEach((p) => p.transport.close()); this.paths = [];
    this.connections.forEach((socket) => socket.destroy()); this.connections.clear(); this.flows.clear();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }
}
