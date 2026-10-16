import { spawn, type ChildProcess } from "node:child_process";
import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

/** Cross-implementation check: the Windows client against the production Go relay
 * (levik_game_node, built with `go build -tags relaytest ./cmd/levik-game-relay`). */
const binary = process.env.LEVIK_TEST_GO_RELAY;
const network = vi.hoisted(() => ({ relayPort: 0, relayPorts: new Map<number, number>(),
  drop: (_direction: "up" | "down", _data: Buffer, _route: number): boolean => false, wire: [] as string[] }));
vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { createSocket: socket } = await import("node:dgram");
  // The route port picks the relay (one per node in the mesh test); the default is the single relay.
  return { openRelayPath: async (route: number, _password: string, receive: (data: Buffer) => void) => {
    const udp = socket("udp4"); let closed = false; udp.on("error", () => {});
    await new Promise<void>((done) => udp.bind(0, "127.0.0.1", () => done()));
    udp.on("message", (data) => { if (!closed && !network.drop("down", data, route)) receive(data); });
    return { get closed() { return closed; }, close() { if (!closed) { closed = true; udp.close(); } },
      send(data: Buffer) { if (closed) return; network.wire.push(data.toString("ascii", 0, 4)); if (!network.drop("up", data, route)) udp.send(data, network.relayPorts.get(route) ?? network.relayPort, "127.0.0.1"); } };
  } };
});
import { GameMultipath, type GameRuntimeOptions } from "../../src/main/vpn/multipath/client";
import { decode, Kind, tagResolver } from "../../src/main/vpn/multipath/wire";

const nodes: GameRuntimeOptions["nodes"] = [{ nodeId: "exit-a", name: "Exit A", countryCode: "SE", city: null, mesh: null, state: "enabled" }];
const resolve = tagResolver(["exit-a"]);
const pause = (milliseconds: number): Promise<void> => new Promise((done) => setTimeout(done, milliseconds));
const children: ChildProcess[] = []; let directory: string | null = null;
afterEach(async () => {
  for (const child of children.splice(0)) child.kill("SIGTERM");
  if (directory) await rm(directory, { recursive: true, force: true }); directory = null;
  network.drop = () => false; network.wire = []; network.relayPorts.clear();
});

async function freePort(): Promise<number> {
  const probe = createSocket("udp4"); await new Promise<void>((done) => probe.bind(0, "127.0.0.1", () => done()));
  const port = probe.address().port; probe.close(); return port;
}
async function startGoRelay(nodeId = "exit-a", mesh?: { port: number; key: string; peers: Array<{ nodeId: string; port: number; publicKey: string }> }): Promise<number> {
  const port = await freePort();
  directory ??= await mkdtemp(join(tmpdir(), "levik-go-relay-")); const config = join(directory, `${nodeId}.json`); const keyFile = join(directory, `${nodeId}.key`);
  await writeFile(config, JSON.stringify({ nodeId, port, ...(mesh ? { mesh: { address: "127.0.0.1", port: mesh.port, transport: "aead",
    peers: mesh.peers.map((peer) => ({ ...peer, address: "127.0.0.1" })) } } : {}) }));
  if (mesh) await writeFile(keyFile, `${mesh.key}\n`, { mode: 0o600 });
  const child = spawn(binary!, ["-config", config], { env: { ...process.env, LEVIK_GAME_RELAY_TEST_LOOPBACK: "1", ...(mesh ? { LEVIK_GAME_MESH_KEY_FILE: keyFile } : {}) },
    stdio: ["ignore", "pipe", "inherit"] });
  children.push(child);
  await once(child.stdout!, "data");
  return port;
}
/** Curve25519 key pair in the WireGuard text format the relay reads. */
function meshKeys(): { privateKey: string; publicKey: string } {
  const { privateKey } = generateKeyPairSync("x25519"); const jwk = privateKey.export({ format: "jwk" });
  return { privateKey: Buffer.from(jwk.d!, "base64url").toString("base64"), publicKey: Buffer.from(jwk.x!, "base64url").toString("base64") };
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

it.skipIf(!binary)("plays through the Go AEAD mesh: entry A carries a copy to exit B and survives B's own path dying", async () => {
  const keys = { a: meshKeys(), b: meshKeys() }; const mesh = { a: await freePort(), b: await freePort() };
  network.relayPorts.set(1, await startGoRelay("entry-a", { port: mesh.a, key: keys.a.privateKey, peers: [{ nodeId: "exit-b", port: mesh.b, publicKey: keys.b.publicKey }] }));
  network.relayPorts.set(2, await startGoRelay("exit-b", { port: mesh.b, key: keys.b.privateKey, peers: [{ nodeId: "entry-a", port: mesh.a, publicKey: keys.a.publicKey }] }));
  const meshNodes: GameRuntimeOptions["nodes"] = ["entry-a", "exit-b"].map((nodeId) => ({ nodeId, name: nodeId, countryCode: "FI", city: null, mesh: null, state: "enabled" }));
  const server = await Server.start(); const client = new GameMultipath(); client.setPlaying(true); let game: GameSocket | undefined;
  try {
    const listener = await client.listen();
    await client.connect([{ index: 0, port: 1, nodeId: "entry-a" }, { index: 1, port: 2, nodeId: "exit-b" }], "test",
      { nodes: meshNodes, protection: true, preferredExitId: "exit-b", exitScope: "flow" });
    game = await GameSocket.open(listener);
    for (let index = 0; index < 40 && !client.runtimeSnapshot().ingressPaths.some((path) => path.entryNodeId === "entry-a" && path.exitNodeId === "exit-b"); index++) {
      game.send(server.port, `warm-${index}`); await pause(100);
    }
    expect(client.runtimeSnapshot().ingressPaths.filter((path) => path.entryNodeId !== path.exitNodeId).map((path) => `${path.entryNodeId}>${path.exitNodeId}`)).toEqual(["entry-a>exit-b"]);
    // Match-rate traffic until the mesh copy has enough samples to carry the match next to B's own path.
    const carrying = (): string[] => client.runtimeSnapshot().ingressPaths.filter((path) => path.active && path.exitNodeId === "exit-b").map((path) => path.entryNodeId).sort();
    for (let index = 0; index < 300 && carrying().join() !== "entry-a,exit-b"; index++) { game.send(server.port, `match-${index}`); await pause(50); }
    expect(carrying()).toEqual(["entry-a", "exit-b"]);
    // Exit B's own route goes silent both ways: the match continues only through entry A and the mesh.
    network.drop = (_direction, _data, route) => route === 2;
    for (let index = 0; index < 4; index++) game.send(server.port, `mesh-${index}`);
    await until(() => ["mesh-0", "mesh-1", "mesh-2", "mesh-3"].every((payload) => game!.replies.includes(`echo:${payload}`)));
    // One exit socket: the game server never sees the entry node.
    expect(server.sources.size).toBe(1);
  } finally { game?.socket.destroy(); await client.stop(); await server.close(); }
}, 30_000);
