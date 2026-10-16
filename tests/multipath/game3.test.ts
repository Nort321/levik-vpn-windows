import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { once } from "node:events";
import { Socket } from "node:net";
import { afterEach, expect, it, vi } from "vitest";

/** Lossy loopback "tunnels": every path is its own UDP socket towards the relay, like
 * distinct Xray associations. `drop` decides per datagram and direction. */
const network = vi.hoisted(() => ({ relayPorts: new Map<number, number>(),
  drop: (_direction: "up" | "down", _data: Buffer): boolean => false, wire: [] as string[] }));
vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { createSocket: socket } = await import("node:dgram");
  return { openRelayPath: async (port: number, _password: string, receive: (data: Buffer) => void) => {
    const udp = socket("udp4"); let closed = false; udp.on("error", () => {});
    await new Promise<void>((done) => udp.bind(0, "127.0.0.1", () => done()));
    udp.on("message", (data) => { if (!closed && !network.drop("down", data)) receive(data); });
    return { get closed() { return closed; }, close() { if (!closed) { closed = true; udp.close(); } },
      send(data: Buffer) { if (closed) return; network.wire.push(data.toString("ascii", 0, 4)); if (!network.drop("up", data)) udp.send(data, network.relayPorts.get(port)!, "127.0.0.1"); } };
  } };
});
import { GameMultipath, type GameRuntimeOptions } from "../../src/main/vpn/multipath/client";
import { startRelay } from "../../src/main/vpn/multipath/relay";
import { decode, Kind, tagResolver } from "../../src/main/vpn/multipath/wire";

afterEach(() => { network.relayPorts.clear(); network.drop = () => false; network.wire = []; });
const nodes: GameRuntimeOptions["nodes"] = [{ nodeId: "exit-a", name: "Exit A", countryCode: "SE", city: null, mesh: null, state: "enabled" }];
const resolve = tagResolver(["exit-a"]);
const pause = (milliseconds: number): Promise<void> => new Promise((done) => setTimeout(done, milliseconds));

class Server {
  readonly payloads: string[] = []; readonly sources = new Set<string>();
  private constructor(readonly socket: DatagramSocket) {
    socket.on("message", (data, peer) => { this.payloads.push(data.toString()); this.sources.add(`${peer.address}:${peer.port}`); socket.send(Buffer.from(`echo:${data}`), peer.port, peer.address); });
  }
  static async start(): Promise<Server> { const socket = createSocket("udp4"); socket.bind(0, "127.0.0.1"); await once(socket, "listening"); return new Server(socket); }
  get port(): number { return this.socket.address().port; }
  close(): Promise<void> { return new Promise((done) => this.socket.close(() => done())); }
}
/** One XUDP VLESS connection: one game socket that talks to several servers. */
class GameSocket {
  readonly replies: Array<{ port: number; payload: string }> = []; private buffer = Buffer.alloc(0);
  private constructor(readonly socket: Socket) {
    socket.on("data", (data) => {
      this.buffer = Buffer.concat([this.buffer, data]);
      if (this.buffer.length >= 2 && this.buffer[0] === 0 && this.buffer[1] === 0 && !this.replies.length && this.buffer.length === 2) { this.buffer = Buffer.alloc(0); return; }
      while (this.buffer.length >= 16) {
        const length = this.buffer.readUInt16BE(14); if (this.buffer.length < 16 + length) return;
        this.replies.push({ port: this.buffer.readUInt16BE(7), payload: this.buffer.subarray(16, 16 + length).toString() });
        this.buffer = this.buffer.subarray(16 + length);
      }
    });
  }
  static async open(listener: { port: number; uuid: string }): Promise<GameSocket> {
    const socket = new Socket(); socket.on("error", () => {}); socket.connect(listener.port, "127.0.0.1"); await once(socket, "connect");
    const header = Buffer.alloc(19); Buffer.from(listener.uuid.replaceAll("-", ""), "hex").copy(header, 1); header[18] = 3;
    socket.write(header); await once(socket, "data");
    return new GameSocket(socket);
  }
  send(port: number, payload: string): void {
    const body = Buffer.from(payload); const frame = Buffer.alloc(16 + body.length);
    frame.writeUInt16BE(12, 0); frame[4] = 1; frame[5] = 1; frame[6] = 2; frame.writeUInt16BE(port, 7); frame[9] = 1;
    Buffer.from([127, 0, 0, 1]).copy(frame, 10); frame.writeUInt16BE(body.length, 14); body.copy(frame, 16);
    this.socket.write(frame);
  }
}
async function until(check: () => boolean, timeout = 3000): Promise<void> {
  for (let waited = 0; !check(); waited += 10) { if (waited > timeout) throw new Error("Timed out"); await pause(10); }
}

it("speaks LGM3, maps one game socket to one exit port and repairs single losses with parity both ways", async () => {
  const relay = await startRelay({ port: 0, nodeId: "exit-a", allowTestLoopback: true });
  network.relayPorts.set(1, relay.port); network.relayPorts.set(2, relay.port);
  const first = await Server.start(); const second = await Server.start();
  const client = new GameMultipath(); client.setPlaying(true);
  let game: GameSocket | undefined;
  try {
    const listener = await client.listen();
    await client.connect([{ index: 0, port: 1, nodeId: "exit-a" }, { index: 1, port: 2, nodeId: "exit-a" }], "test",
      { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await pause(400);
    expect(client.snapshot().state).toBe("protected");
    game = await GameSocket.open(listener);
    for (let index = 0; index < 4; index++) { game.send(first.port, `a-${index}`); game.send(second.port, `b-${index}`); }
    await until(() => first.payloads.length === 4 && second.payloads.length === 4);
    // Endpoint-independent mapping: both servers see the same exit IP:port.
    expect(new Set([...first.sources, ...second.sources]).size).toBe(1);
    expect(network.wire).toContain("LGM3");
    await until(() => game!.replies.length === 8);
    expect(new Set(game.replies.map((reply) => reply.port))).toEqual(new Set([first.port, second.port]));

    // Every copy of one upstream packet is lost: the relay rebuilds it from parity.
    let lostUp: number | null = null;
    network.drop = (direction, data) => {
      const packet = decode(data, resolve);
      if (direction !== "up" || packet?.kind !== Kind.Up || packet.payload.toString() !== "a-lost") return false;
      lostUp = packet.sequence; return true;
    };
    for (const payload of ["a-before", "a-lost", "a-after", "a-last"]) game.send(first.port, payload);
    await until(() => first.payloads.includes("a-lost"));
    expect(lostUp).not.toBeNull(); expect(relay.counts.recovered).toBeGreaterThanOrEqual(1);

    // Every copy of one downstream packet is lost: the client rebuilds it.
    network.drop = (direction, data) => direction === "down" && decode(data, resolve)?.kind === Kind.Down
      && decode(data, resolve)!.payload.toString() === "echo:b-lost";
    for (const payload of ["b-before", "b-lost", "b-after", "b-last"]) game.send(second.port, payload);
    await until(() => game!.replies.some((reply) => reply.payload === "echo:b-lost"));
    expect(client.snapshot().recoveredPackets).toBeGreaterThanOrEqual(1);
  } finally { game?.socket.destroy(); await client.stop(); await relay.close(); await first.close(); await second.close(); }
}, 20_000);

it("keeps the exit after a relay restart and opens the flow again on the new process", async () => {
  let relay = await startRelay({ port: 0, nodeId: "exit-a", allowTestLoopback: true });
  const port = relay.port; network.relayPorts.set(1, port);
  const server = await Server.start(); const client = new GameMultipath(); client.setPlaying(true);
  let game: GameSocket | undefined;
  try {
    const listener = await client.listen();
    await client.connect([{ index: 0, port: 1, nodeId: "exit-a" }], "test", { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await pause(300);
    game = await GameSocket.open(listener);
    game.send(server.port, "before-restart"); await until(() => server.payloads.includes("before-restart"));
    await relay.close(); relay = await startRelay({ port, nodeId: "exit-a", allowTestLoopback: true });
    // Pings reach the new process, report a new instance; the path stays usable.
    await until(() => client.snapshot().paths[0]?.responding === true && relay.counts.forwarded === 0 && client.runtimeSnapshot().ingressPaths.length === 1, 3000);
    await pause(1500);
    for (let attempt = 0; attempt < 20 && !server.payloads.includes("after-restart"); attempt++) { game.send(server.port, "after-restart"); await pause(100); }
    expect(server.payloads).toContain("after-restart");
    expect(client.snapshot().paths[0]).toMatchObject({ responding: true });
  } finally { game?.socket.destroy(); await client.stop(); await relay.close(); await server.close(); }
}, 20_000);

it("lets one game socket talk to hundreds of servers without losing the socket", async () => {
  const relay = await startRelay({ port: 0, nodeId: "exit-a", allowTestLoopback: true });
  network.relayPorts.set(1, relay.port);
  const server = await Server.start(); const client = new GameMultipath(); client.setPlaying(true);
  let game: GameSocket | undefined;
  try {
    const listener = await client.listen();
    await client.connect([{ index: 0, port: 1, nodeId: "exit-a" }], "test", { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await pause(300);
    game = await GameSocket.open(listener);
    for (let index = 0; index < 300; index++) game.send(20_000 + index, `scan-${index}`);
    await pause(300);
    game.send(server.port, "still-here");
    await until(() => game!.replies.some((reply) => reply.payload === "echo:still-here"));
    expect(game.socket.destroyed).toBe(false);
    expect(relay.activeFlows).toBe(1);
  } finally { game?.socket.destroy(); await client.stop(); await relay.close(); await server.close(); }
}, 20_000);

it("moves a flow off an exit that stopped answering", async () => {
  const exits = ["exit-a", "exit-b"];
  const relays = await Promise.all(exits.map((nodeId) => startRelay({ port: 0, nodeId, allowTestLoopback: true })));
  relays.forEach((relay, index) => network.relayPorts.set(index + 1, relay.port));
  const server = await Server.start(); const client = new GameMultipath(); client.setPlaying(true);
  let game: GameSocket | undefined; const open = new Set([0, 1]);
  try {
    const listener = await client.listen();
    await client.connect(exits.map((nodeId, index) => ({ index, port: index + 1, nodeId })), "test",
      { nodes: exits.map((nodeId) => ({ ...nodes[0]!, nodeId })), protection: true, preferredExitId: null, exitScope: "socket" });
    await pause(400);
    game = await GameSocket.open(listener);
    game.send(server.port, "first"); await until(() => server.payloads.includes("first"));
    const used = relays.findIndex((relay) => relay.counts.forwarded > 0);
    await relays[used]!.close(); open.delete(used);
    // The game keeps sending; within deadExitMs + pathSilentMs the flow reopens on the live exit.
    const lost = Date.now();
    for (let tick = 0; tick < 70 && relays[1 - used]!.counts.forwarded === 0; tick++) { game.send(server.port, `waiting-${tick}`); await pause(200); }
    expect(relays[1 - used]!.counts.forwarded).toBeGreaterThan(0);
    expect(Date.now() - lost).toBeLessThan(12_000);
    expect(server.payloads.at(-1)).toMatch(/^waiting-/);
  } finally { game?.socket.destroy(); await client.stop(); for (const index of open) await relays[index]!.close(); await server.close(); }
}, 30_000);
