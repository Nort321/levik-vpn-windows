import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { GAME_PROBE_USER } from "../../src/main/vpn/gameRoutes";
import { startRelay } from "../../src/main/vpn/multipath/relay";
import { openRelayPath } from "../../src/main/vpn/multipath/socks";
import { controlPayload, decode, encode, isRecord, Kind, parseControl, type Packet } from "../../src/main/vpn/multipath/wire";

const pause = (milliseconds: number): Promise<void> => new Promise((done) => setTimeout(done, milliseconds));
const basePacket = (session = randomBytes(32)): Packet => ({ kind: Kind.Ping, session, flow: randomBytes(8), path: 0,
  sequence: 0, address: "0.0.0.0", port: 0, payload: Buffer.from([1]) });

class Inbox {
  readonly packets: Packet[] = [];
  constructor(readonly socket: DatagramSocket) {
    socket.on("message", (data) => this.receive(data));
  }
  receive(data: Buffer): void { const packet = decode(data); if (packet) this.packets.push(packet); }
  async take(kind: Kind, sequence?: number): Promise<Packet> {
    for (let attempt = 0; attempt < 200; attempt++) {
      const index = this.packets.findIndex((packet) => packet.kind === kind && (sequence === undefined || packet.sequence === sequence));
      if (index >= 0) return this.packets.splice(index, 1)[0]!;
      await pause(5);
    }
    throw new Error("Test relay response timed out");
  }
  send(packet: Packet, port: number): void { this.socket.send(encode(packet), port, "127.0.0.1"); }
}

async function udp(): Promise<Inbox> {
  const socket = createSocket("udp4");
  socket.on("error", () => {});
  const inbox = new Inbox(socket);
  socket.bind(0, "127.0.0.1"); await once(socket, "listening");
  return inbox;
}
async function closeUdp(socket: DatagramSocket): Promise<void> {
  await new Promise<void>((done) => { try { socket.close(() => done()); } catch { done(); } });
}
async function mockProbe(error = false) {
  // Unix socket paths have a small platform limit; macOS tmpdir may be long.
  const directory = await mkdtemp(join(process.platform === "win32" ? tmpdir() : "/tmp", "lgp-"));
  const path = join(directory, "probe.sock");
  const calls: Record<string, unknown>[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {});
    let buffered = "";
    socket.on("data", (data) => {
      buffered += data.toString(); if (!buffered.includes("\n")) return;
      const value: unknown = JSON.parse(buffered.split("\n")[0]!);
      if (!isRecord(value)) { socket.destroy(); return; }
      calls.push(value);
      if (error) { socket.end(JSON.stringify({ version: 2, error: "request rejected" }) + "\n"); return; }
      const targets = Array.isArray(value.targets) ? value.targets.filter(isRecord) : [];
      socket.end(JSON.stringify({ version: 2, nodeId: "game-exit", capabilities: { probe: true }, load: { cpuPercent: 12.5 }, neighbors: [], results: targets.map((target) => ({
        address: target.address, port: target.port, medianMs: 20, p95Ms: 22, jitterMs: 1, lossPercent: 0,
        sampleCount: 5, measuredAt: new Date().toISOString(), method: "icmp",
      })) }) + "\n");
    });
  });
  server.listen(path); await once(server, "listening");
  return { path, calls, async close(): Promise<void> {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  } };
}

describe.skipIf(process.platform === "win32")("Game 2.0 relay and private measurement service", () => {
  it("serves versioned NODE_INFO and bounded public-target measurements through Unix IPC", async () => {
    const probe = await mockProbe();
    const relay = await startRelay({ port: 0, nodeId: "game-exit", probeSocket: probe.path });
    const client = await udp();
    const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
    try {
      client.send(ping, relay.port);
      const pong = await client.take(Kind.Pong);
      expect(pong.payload).toHaveLength(16);
      client.send({ ...ping, kind: Kind.NodeInfo, sequence: 1, payload: controlPayload({}) }, relay.port);
      const info = parseControl((await client.take(Kind.NodeInfo, 1)).payload);
      expect(info).toMatchObject({ version: 2, nodeId: "game-exit", instance: pong.payload.toString("hex"),
        load: { cpuPercent: 12.5, activeSessions: 1 }, capabilities: { probe: true, mesh: false } });
      client.send({ ...ping, kind: Kind.ProbeRequest, sequence: 2, payload: controlPayload({ targets: [{ address: "8.8.8.8", port: 27015 }] }) }, relay.port);
      expect(parseControl((await client.take(Kind.ProbeResult, 2)).payload)).toMatchObject({ version: 2,
        results: [{ address: "8.8.8.8", port: 27015, medianMs: 20, method: "icmp", sampleCount: 5 }] });
      expect(probe.calls.map((call) => call.op)).toEqual(["health", "probe"]);
      expect(probe.calls[0]).toMatchObject({ version: 2, activeSessions: 1 });
    } finally { await closeUdp(client.socket); await relay.close(); await probe.close(); }
  });

  it("denies private, reserved, CGNAT and own-node probe targets before IPC", async () => {
    const probe = await mockProbe();
    const relay = await startRelay({ port: 0, nodeId: "game-exit", probeSocket: probe.path, excludedAddresses: ["8.8.4.4"] });
    const client = await udp();
    try {
      for (const address of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "192.0.2.1", "8.8.4.4"]) {
        const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
        client.send(ping, relay.port); await client.take(Kind.Pong);
        const rejected = relay.counts.rejected;
        client.send({ ...ping, kind: Kind.ProbeRequest, payload: controlPayload({ targets: [{ address, port: 27015 }] }) }, relay.port);
        await pause(15);
        expect(relay.counts.rejected).toBeGreaterThan(rejected);
      }
      expect(probe.calls).toHaveLength(0);
      expect(client.packets.filter((packet) => packet.kind === Kind.ProbeResult)).toHaveLength(0);
    } finally { await closeUdp(client.socket); await relay.close(); await probe.close(); }
  });

  it.each([false, true])("reports unavailable measurement service without hiding a working relay (error response: %s)", async (respondsWithError) => {
    const probe = respondsWithError ? await mockProbe(true) : null;
    const relay = await startRelay({ port: 0, nodeId: "game-exit", ...(probe ? { probeSocket: probe.path } : {}) });
    const client = await udp();
    const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
    try {
      client.send(ping, relay.port); await client.take(Kind.Pong);
      client.send({ ...ping, kind: Kind.NodeInfo, sequence: 1, payload: controlPayload({}) }, relay.port);
      expect(parseControl((await client.take(Kind.NodeInfo, 1)).payload)).toMatchObject({ capabilities: { probe: false } });
      client.send({ ...ping, kind: Kind.ProbeRequest, sequence: 2,
        payload: controlPayload({ targets: [{ address: "8.8.8.8", port: 27015 }] }) }, relay.port);
      expect(parseControl((await client.take(Kind.ProbeResult, 2)).payload)).toEqual({
        version: 2, status: "service-unavailable", results: [],
      });
    } finally { await closeUdp(client.socket); await relay.close(); await probe?.close(); }
  });

  it("enforces the lifetime quota of 32 targets and rejects oversized batches", async () => {
    const probe = await mockProbe(); const relay = await startRelay({ port: 0, nodeId: "game-exit", probeSocket: probe.path });
    const client = await udp();
    const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
    const targets = Array.from({ length: 32 }, (_, index) => ({ address: `8.8.8.${index + 1}`, port: 27015 }));
    try {
      client.send(ping, relay.port); await client.take(Kind.Pong);
      client.send({ ...ping, kind: Kind.ProbeRequest, sequence: 1, payload: controlPayload({ targets }) }, relay.port);
      const results: unknown[] = [];
      for (let chunk = 0; chunk < 4; chunk++) {
        const result = parseControl((await client.take(Kind.ProbeResult, 1)).payload);
        if (isRecord(result) && Array.isArray(result.results)) results.push(...result.results);
      }
      expect(results).toHaveLength(32);
      client.send({ ...ping, kind: Kind.ProbeRequest, sequence: 2, payload: controlPayload({ targets: [{ address: "1.1.1.1", port: 27015 }] }) }, relay.port);
      client.send({ ...ping, kind: Kind.ProbeRequest, sequence: 3, payload: controlPayload({ targets: [...targets, { address: "1.1.1.1", port: 27015 }] }) }, relay.port);
      await pause(30);
      expect(probe.calls).toHaveLength(1);
      expect(relay.counts.rejected).toBeGreaterThanOrEqual(2);
    } finally { await closeUdp(client.socket); await relay.close(); await probe.close(); }
  });

  it("bounds control floods and preserves old-client frames when measurement service is absent", async () => {
    const probe = await mockProbe(); const relay = await startRelay({ port: 0, nodeId: "game-exit", probeSocket: probe.path });
    const client = await udp();
    try {
      const legacy = basePacket();
      client.send(legacy, relay.port);
      const legacyPong = await client.take(Kind.Pong);
      expect(legacyPong.session).toEqual(legacy.session); expect(legacyPong).not.toHaveProperty("version");
      const modern = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
      client.send(modern, relay.port); await client.take(Kind.Pong);
      for (let sequence = 1; sequence <= 50; sequence++) client.send({ ...modern, kind: Kind.NodeInfo, sequence, payload: controlPayload({}) }, relay.port);
      await pause(100);
      expect(probe.calls.length).toBeGreaterThan(0);
      expect(probe.calls.length).toBeLessThanOrEqual(8);
      expect(client.packets.filter((packet) => packet.kind === Kind.NodeInfo).length).toBeLessThanOrEqual(8);
    } finally { await closeUdp(client.socket); await relay.close(); await probe.close(); }
    const fallback = await startRelay({ port: 0, nodeId: "game-exit" }); const old = await udp();
    try {
      const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
      old.send(ping, fallback.port); await old.take(Kind.Pong);
      old.send({ ...ping, kind: Kind.NodeInfo, payload: controlPayload({}) }, fallback.port);
      expect(parseControl((await old.take(Kind.NodeInfo)).payload)).toMatchObject({ capabilities: { probe: false, mesh: false } });
    } finally { await closeUdp(old.socket); await fallback.close(); }
  });
});

describe("Game 2.0 relay mesh egress identity", () => {
  it("keeps legacy LGM1 UDP clients working against the new relay", async () => {
    const relay = await startRelay({ port: 0, nodeId: "game-exit", allowTestLoopback: true });
    const client = await udp(); const game = await udp(); const ports = new Set<number>();
    game.socket.on("message", (data, peer) => { ports.add(peer.port); game.socket.send(data, peer.port, peer.address); });
    try {
      const ping = basePacket(); client.send(ping, relay.port);
      expect(await client.take(Kind.Pong)).not.toHaveProperty("version");
      for (let sequence = 0; sequence < 3; sequence++) {
        const payload = Buffer.from(`legacy-${sequence}`);
        client.send({ ...ping, kind: Kind.Up, sequence, address: "127.0.0.1", port: game.socket.address().port, payload }, relay.port);
        const response = await client.take(Kind.Down, sequence);
        expect(response.payload).toEqual(payload); expect(response).not.toHaveProperty("version");
      }
      expect(ports.size).toBe(1);
    } finally { await closeUdp(client.socket); await closeUdp(game.socket); await relay.close(); }
  });

  it("adds a peer live, deduplicates two entries and keeps the game source port across both entry outages", async () => {
    const exit = await startRelay({ port: 0, nodeId: "exit-y", allowTestLoopback: true, mesh: { address: "127.0.0.1", port: 0, peers: [] } });
    const entry = await startRelay({ port: 0, nodeId: "entry-x", allowTestLoopback: true,
      mesh: { address: "127.0.0.1", port: 0, peers: [{ nodeId: "exit-y", address: "127.0.0.1", port: exit.meshPort! }] } });
    const game = await udp(); const direct = await udp(); const viaEntry = await udp(); const recoveredDirect = await udp();
    const requests: string[] = []; const sourcePorts = new Set<number>();
    game.socket.on("message", (data, peer) => { requests.push(data.toString()); sourcePorts.add(peer.port); game.socket.send(data, peer.port, peer.address); });
    const ping = { ...basePacket(), version: 2 as const, exitNodeId: "exit-y", hops: 0 };
    const gamePort = game.socket.address().port;
    let closedEntry = false;
    try {
      direct.send(ping, exit.port); const original = await direct.take(Kind.Pong);
      const data = (sequence: number, payload: string, path = 0): Packet => ({ ...ping, kind: Kind.Up, path, sequence,
        address: "127.0.0.1", port: gamePort, instance: original.payload, payload: Buffer.from(payload) });
      direct.send(data(0, "before-mesh"), exit.port); await direct.take(Kind.Down, 0);
      const originalMeshPort = exit.meshPort;
      exit.reloadPeers([{ nodeId: "entry-x", address: "127.0.0.1", port: entry.meshPort! }]);
      expect(exit.meshPort).toBe(originalMeshPort);
      viaEntry.send({ ...ping, path: 1 }, entry.port);
      expect((await viaEntry.take(Kind.Pong)).payload).toEqual(original.payload);
      direct.send(data(1, "two-copies"), exit.port); viaEntry.send(data(1, "two-copies", 1), entry.port);
      await direct.take(Kind.Down, 1); await viaEntry.take(Kind.Down, 1);
      await closeUdp(direct.socket);
      viaEntry.send(data(2, "entry-only", 1), entry.port); await viaEntry.take(Kind.Down, 2);
      recoveredDirect.send(ping, exit.port);
      expect((await recoveredDirect.take(Kind.Pong)).payload).toEqual(original.payload);
      await entry.close(); closedEntry = true;
      recoveredDirect.send(data(3, "direct-only"), exit.port); await recoveredDirect.take(Kind.Down, 3);
      expect(requests).toEqual(["before-mesh", "two-copies", "entry-only", "direct-only"]);
      expect(sourcePorts.size).toBe(1);
      expect(exit.counts.forwarded).toBe(4);
      expect(exit.counts.duplicates).toBeGreaterThanOrEqual(1);
    } finally {
      for (const inbox of [game, direct, viaEntry, recoveredDirect]) await closeUdp(inbox.socket);
      if (!closedEntry) await entry.close(); await exit.close();
    }
  });

  it("rejects unknown mesh peers, extra hops, forwarding loops and mismatched relay instances", async () => {
    const knownPeer = await udp(); const attacker = await udp(); const client = await udp();
    const relay = await startRelay({ port: 0, nodeId: "exit-y", allowTestLoopback: true,
      mesh: { address: "127.0.0.1", port: 0, peers: [{ nodeId: "entry-x", address: "127.0.0.1", port: knownPeer.socket.address().port }] } });
    try {
      const ping = { ...basePacket(), version: 2 as const, exitNodeId: "exit-y", hops: 1 };
      attacker.send(ping, relay.meshPort!);
      knownPeer.send({ ...ping, exitNodeId: "entry-x" }, relay.meshPort!);
      const invalidHops = encode(ping); invalidHops[121] = 2;
      knownPeer.socket.send(invalidHops, relay.meshPort!, "127.0.0.1");
      client.send({ ...ping, exitNodeId: "entry-x" }, relay.port);
      const correct = { ...ping, hops: 0, session: randomBytes(32) };
      client.send(correct, relay.port); await client.take(Kind.Pong);
      client.send({ ...correct, kind: Kind.Up, address: "127.0.0.1", port: 12345, instance: randomBytes(16), payload: Buffer.from("rejected") }, relay.port);
      await pause(30);
      expect(relay.counts.rejected).toBeGreaterThanOrEqual(5);
      expect(relay.counts.forwarded).toBe(0);
      expect(knownPeer.packets).toHaveLength(0); expect(attacker.packets).toHaveLength(0);
    } finally { await relay.close(); for (const inbox of [knownPeer, attacker, client]) await closeUdp(inbox.socket); }
  });
});

const xrayExecutable = process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe");
it.skipIf(process.platform !== "win32" && !process.env.LEVIK_TEST_XRAY)("measures relay echo A through a real authenticated Xray UDP SOCKS path", async () => {
  const relay = await startRelay({ port: 0, nodeId: "game-exit" });
  const reservation = createServer(); reservation.listen(0, "127.0.0.1"); await once(reservation, "listening");
  const address = reservation.address(); if (!address || typeof address === "string") throw new Error("No test port");
  await new Promise<void>((done) => reservation.close(() => done()));
  let core: ChildProcessWithoutNullStreams | undefined;
  const abort = new AbortController(); const inbox = await udp();
  let path: Awaited<ReturnType<typeof openRelayPath>> | undefined;
  try {
    core = spawn(xrayExecutable, ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe", windowsHide: true });
    const ready = new Promise<void>((done, reject) => {
      const timer = setTimeout(() => reject(new Error("Test Xray startup timed out")), 5000);
      core!.stdout.on("data", (data: Buffer) => { if (data.toString().includes("started")) { clearTimeout(timer); done(); } });
      core!.once("error", (error) => { clearTimeout(timer); reject(error); });
      core!.once("exit", () => { clearTimeout(timer); reject(new Error("Test Xray exited")); });
    });
    core.stdin.end(JSON.stringify({ log: { loglevel: "warning" }, inbounds: [{ listen: "127.0.0.1", port: address.port, protocol: "socks",
      settings: { auth: "password", accounts: [{ user: GAME_PROBE_USER, pass: "game2-test-only" }], udp: true, ip: "127.0.0.1" } }],
      outbounds: [{ protocol: "freedom" }] }));
    await ready;
    await expect(openRelayPath(address.port, "wrong-password", () => {}, abort.signal, { address: "127.0.0.1", port: relay.port })).rejects.toThrow();
    path = await openRelayPath(address.port, "game2-test-only", (data) => inbox.receive(data), abort.signal, { address: "127.0.0.1", port: relay.port });
    const ping = { ...basePacket(), version: 2 as const, exitNodeId: "game-exit", hops: 0 };
    const started = performance.now(); path.send(encode(ping));
    const pong = await inbox.take(Kind.Pong);
    expect(pong.payload).toHaveLength(16); expect(performance.now() - started).toBeLessThan(1000);
    path.send(encode({ ...ping, kind: Kind.NodeInfo, sequence: 1, payload: controlPayload({}) }));
    expect(parseControl((await inbox.take(Kind.NodeInfo, 1)).payload)).toMatchObject({ nodeId: "game-exit", version: 2 });
  } finally {
    path?.close(); abort.abort(); await closeUdp(inbox.socket); await relay.close();
    if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
  }
}, 10_000);
