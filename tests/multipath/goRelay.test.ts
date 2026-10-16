import { spawn, type ChildProcess } from "node:child_process";
import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

/** Cross-implementation check: the Windows client against the production Go relay
 * (levik_game_node, built with `go build -tags relaytest ./cmd/levik-game-relay`). */
const binary = process.env.LEVIK_TEST_GO_RELAY;
const network = vi.hoisted(() => ({ relayPort: 0, drop: (_direction: "up" | "down", _data: Buffer): boolean => false, wire: [] as string[] }));
vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { createSocket: socket } = await import("node:dgram");
  return { openRelayPath: async (_port: number, _password: string, receive: (data: Buffer) => void) => {
    const udp = socket("udp4"); let closed = false; udp.on("error", () => {});
    await new Promise<void>((done) => udp.bind(0, "127.0.0.1", () => done()));
    udp.on("message", (data) => { if (!closed && !network.drop("down", data)) receive(data); });
    return { get closed() { return closed; }, close() { if (!closed) { closed = true; udp.close(); } },
      send(data: Buffer) { if (closed) return; network.wire.push(data.toString("ascii", 0, 4)); if (!network.drop("up", data)) udp.send(data, network.relayPort, "127.0.0.1"); } };
  } };
});
import { GameMultipath, type GameRuntimeOptions } from "../../src/main/vpn/multipath/client";
import { decode, Kind, tagResolver } from "../../src/main/vpn/multipath/wire";

const nodes: GameRuntimeOptions["nodes"] = [{ nodeId: "exit-a", name: "Exit A", countryCode: "SE", city: null, mesh: null, state: "enabled" }];
const resolve = tagResolver(["exit-a"]);
const pause = (milliseconds: number): Promise<void> => new Promise((done) => setTimeout(done, milliseconds));
let child: ChildProcess | null = null; let directory: string | null = null;
afterEach(async () => { child?.kill("SIGTERM"); child = null; if (directory) await rm(directory, { recursive: true, force: true }); directory = null; network.drop = () => false; network.wire = []; });

async function startGoRelay(): Promise<number> {
  const probe = createSocket("udp4"); await new Promise<void>((done) => probe.bind(0, "127.0.0.1", () => done()));
  const port = probe.address().port; probe.close();
  directory = await mkdtemp(join(tmpdir(), "levik-go-relay-")); const config = join(directory, "relay.json");
  await writeFile(config, JSON.stringify({ nodeId: "exit-a", port }));
  child = spawn(binary!, ["-config", config], { env: { ...process.env, LEVIK_GAME_RELAY_TEST_LOOPBACK: "1" }, stdio: ["ignore", "pipe", "inherit"] });
  await once(child.stdout!, "data");
  return port;
}
class Server {
  readonly payloads: string[] = []; readonly sources = new Set<string>();
  private constructor(readonly socket: DatagramSocket) {
    socket.on("message", (data, peer) => { this.payloads.push(data.toString()); this.sources.add(`${peer.address}:${peer.port}`); socket.send(Buffer.from(`echo:${data}`), peer.port, peer.address); });
  }
  static async start(): Promise<Server> { const socket = createSocket("udp4"); socket.bind(0, "127.0.0.1"); await once(socket, "listening"); return new Server(socket); }
  get port(): number { return this.socket.address().port; }
  close(): Promise<void> { return new Promise((done) => this.socket.close(() => done())); }
}
class GameSocket {
  readonly replies: string[] = []; private buffer = Buffer.alloc(0);
  private constructor(readonly socket: Socket) {
    socket.on("data", (data) => {
      this.buffer = Buffer.concat([this.buffer, data]);
      if (this.buffer.length === 2 && !this.replies.length) { this.buffer = Buffer.alloc(0); return; }
      while (this.buffer.length >= 16) {
        const length = this.buffer.readUInt16BE(14); if (this.buffer.length < 16 + length) return;
        this.replies.push(this.buffer.subarray(16, 16 + length).toString()); this.buffer = this.buffer.subarray(16 + length);
      }
    });
  }
  static async open(listener: { port: number; uuid: string }): Promise<GameSocket> {
    const socket = new Socket(); socket.on("error", () => {}); socket.connect(listener.port, "127.0.0.1"); await once(socket, "connect");
    const header = Buffer.alloc(19); Buffer.from(listener.uuid.replaceAll("-", ""), "hex").copy(header, 1); header[18] = 3;
    socket.write(header); await once(socket, "data"); return new GameSocket(socket);
  }
  send(port: number, payload: string): void {
    const body = Buffer.from(payload); const frame = Buffer.alloc(16 + body.length);
    frame.writeUInt16BE(12, 0); frame[4] = 1; frame[5] = 1; frame[6] = 2; frame.writeUInt16BE(port, 7); frame[9] = 1;
    Buffer.from([127, 0, 0, 1]).copy(frame, 10); frame.writeUInt16BE(body.length, 14); body.copy(frame, 16); this.socket.write(frame);
  }
}
async function until(check: () => boolean, timeout = 3000): Promise<void> {
  for (let waited = 0; !check(); waited += 10) { if (waited > timeout) throw new Error("Timed out"); await pause(10); }
}

it.skipIf(!binary)("plays through the Go relay: LGM3, one exit port, parity repairs losses both ways", async () => {
  network.relayPort = await startGoRelay();
  const first = await Server.start(); const second = await Server.start();
  const client = new GameMultipath(); client.setPlaying(true); let game: GameSocket | undefined;
  try {
    const listener = await client.listen();
    await client.connect([{ index: 0, port: 1, nodeId: "exit-a" }, { index: 1, port: 2, nodeId: "exit-a" }], "test",
      { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await pause(400);
    expect(client.snapshot().state).toBe("protected");
    game = await GameSocket.open(listener);
    for (let index = 0; index < 4; index++) { game.send(first.port, `a-${index}`); game.send(second.port, `b-${index}`); }
    await until(() => first.payloads.length === 4 && second.payloads.length === 4 && game!.replies.length === 8);
    expect(new Set([...first.sources, ...second.sources]).size).toBe(1);
    expect(network.wire).toContain("LGM3");
    network.drop = (direction, data) => direction === "up" && decode(data, resolve)?.kind === Kind.Up && decode(data, resolve)!.payload.toString() === "a-lost";
    for (const payload of ["a-before", "a-lost", "a-after", "a-last"]) game.send(first.port, payload);
    await until(() => first.payloads.includes("a-lost"));
    network.drop = (direction, data) => direction === "down" && decode(data, resolve)?.kind === Kind.Down && decode(data, resolve)!.payload.toString() === "echo:b-lost";
    for (const payload of ["b-before", "b-lost", "b-after", "b-last"]) game.send(second.port, payload);
    await until(() => game!.replies.includes("echo:b-lost"));
    expect(client.snapshot().recoveredPackets).toBeGreaterThanOrEqual(1);
    expect(client.runtimeSnapshot().compatibility).toBe("full");
  } finally { game?.socket.destroy(); await client.stop(); await first.close(); await second.close(); }
}, 20_000);
