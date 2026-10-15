import { createServer, Socket } from "node:net";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";
import { networkInterfaces } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { bindXrayOutboundInterface } from "../../src/main/vpn/xrayConfig";
import { randomBytes } from "node:crypto";
import { expect, it, vi } from "vitest";

vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { decode, encode, Kind } = await import("../../src/main/vpn/multipath/wire.js");
  return { openRelayPath: async (_port: number, _password: string, receive: (packet: Buffer) => void) => ({
    close: () => {}, send: (data: Buffer) => {
      const packet = decode(data); if (!packet) return;
      receive(encode({ ...packet, kind: packet.kind === Kind.Ping ? Kind.Pong : Kind.Down,
        payload: packet.kind === Kind.Ping ? Buffer.alloc(16, 3) : packet.payload }));
    },
  }) };
});
import { GameMultipath } from "../../src/main/vpn/multipath/client";

async function freePort(): Promise<number> {
  const server = createServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); if (!address || typeof address === "string") throw new Error("port unavailable");
  server.close(); await once(server, "close"); return address.port;
}

async function roundtrip(proxyPort: number, destinationPort: number, payload: Buffer): Promise<Buffer> {
  const tcp = new Socket(); const udp = createSocket("udp4");
  let buffered = Buffer.alloc(0); let wake: (() => void) | undefined; let ended = false;
  const stop = (): void => { ended = true; tcp.destroy(); try { udp.close(); } catch {} wake?.(); };
  const timeout = setTimeout(stop, 2500);
  tcp.on("error", stop); tcp.on("close", () => { ended = true; wake?.(); });
  tcp.on("data", (data: Buffer) => { buffered = Buffer.concat([buffered, data]); wake?.(); });
  const read = async (n: number): Promise<Buffer> => {
    while (buffered.length < n && !ended) await new Promise<void>((done) => { wake = done; });
    if (ended) throw new Error("SOCKS test timeout");
    const data = buffered.subarray(0, n); buffered = buffered.subarray(n); return data;
  };
  try {
    tcp.connect(proxyPort, "127.0.0.1"); tcp.write(Buffer.from([5, 1, 0]));
    expect(await read(2)).toEqual(Buffer.from([5, 0]));
    tcp.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
    const response = await read(10);
    udp.connect(response.readUInt16BE(8), "127.0.0.1"); await once(udp, "connect");
    const header = Buffer.from([0, 0, 0, 1, 1, 1, 1, 1, destinationPort >> 8, destinationPort & 255]);
    let result: Buffer = Buffer.alloc(0);
    // Reuse the association to exercise both XUDP New and Keep frames.
    for (let attempt = 0; attempt < 3; attempt++) {
      const reply = new Promise<Buffer>((accept, reject) => {
        const closed = (): void => { reject(new Error(`No UDP response for port ${destinationPort}, ${payload.length} bytes`)); };
        udp.once("close", closed);
        udp.once("message", (data) => { udp.removeListener("close", closed); accept(data.subarray(10)); });
      });
      udp.send(Buffer.concat([header, payload])); result = await reply;
      expect(result).toEqual(payload);
    }
    return result;
  } finally { clearTimeout(timeout); stop(); }
}

it("carries game-size UDP and UDP/443 through the exact production VLESS outbound", async () => {
  const client = new GameMultipath(); let core: ChildProcessWithoutNullStreams | undefined;
  try {
    const local = await client.listen(); await client.connect([{ index: 0, port: 1 }, { index: 1, port: 2 }], "test-only");
    const port = await freePort();
    const config = { log: { loglevel: "warning" },
      inbounds: [{ listen: "127.0.0.1", port, protocol: "socks", settings: { auth: "noauth", udp: true, ip: "127.0.0.1" } }],
      outbounds: [{ protocol: "vless", mux: { enabled: false, xudpConcurrency: -1 },
        settings: { vnext: [{ address: "127.0.0.1", port: local.port, users: [{ id: local.uuid, encryption: "none" }] }] } }] };
    core = spawn(process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe"), ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe", windowsHide: true });
    const ready = new Promise<void>((accept, reject) => {
      const timer = setTimeout(() => reject(new Error("core startup timeout")), 5000);
      core!.stdout.on("data", (data: Buffer) => { if (data.toString().includes("started")) { clearTimeout(timer); accept(); } });
      core!.once("error", (error) => { clearTimeout(timer); reject(error); });
    });
    core.stdin.end(JSON.stringify(config)); await ready;
    for (const destination of [7000, 443]) for (const length of [64, 1200, 1472, 4096]) {
      const packet = randomBytes(length);
      expect(await roundtrip(port, destination, packet)).toEqual(packet);
    }
  } finally {
    await client.stop();
    if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
  }
}, 15_000);

// Opt-in Windows CI test: only the reserved test /32 is routed, never the internet.
it.skipIf(process.platform !== "win32" || process.env.LEVIK_TEST_NATIVE_TUN !== "1")("passes game UDP from a real Windows TUN into the local multipath bridge", async () => {
  const interfaces = Object.entries(networkInterfaces());
  const physical = interfaces.find(([, values]) => values?.some((value) => value.family === "IPv4" && !value.internal))?.[0];
  const loopback = interfaces.find(([, values]) => values?.some((value) => value.address === "127.0.0.1"))?.[0];
  expect(physical).toBeTruthy(); expect(loopback).toBeTruthy();
  const client = new GameMultipath(); const application = createSocket("udp4");
  let core: ChildProcessWithoutNullStreams | undefined;
  try {
    const local = await client.listen(); await client.connect([{ index: 0, port: 1 }, { index: 1, port: 2 }], "test-only");
    const config = bindXrayOutboundInterface({ log: { loglevel: "warning" },
      inbounds: [{ tag: "test-tun", protocol: "tun", settings: { name: "LevikGameCi", mtu: 1500,
        gateway: ["10.90.99.1/30"], autoSystemRoutingTable: ["198.18.0.1/32"], autoOutboundsInterface: physical } }],
      outbounds: [{ tag: "game", protocol: "vless", mux: { enabled: false, xudpConcurrency: -1 },
        settings: { vnext: [{ address: "127.0.0.1", port: local.port, users: [{ id: local.uuid, encryption: "none" }] }] } },
      { tag: "blocked", protocol: "blackhole" }],
      routing: { rules: [{ type: "field", inboundTag: ["test-tun"], process: ["node.exe"], network: "udp", outboundTag: "game" },
        { type: "field", inboundTag: ["test-tun"], outboundTag: "blocked" }] },
    }, physical!, false, loopback);
    core = spawn(process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe"), ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe", windowsHide: true });
    const ready = new Promise<void>((accept, reject) => {
      const timer = setTimeout(() => reject(new Error("Windows test TUN startup timeout")), 10_000);
      core!.stdout.on("data", (data: Buffer) => { if (data.toString().includes("started")) { clearTimeout(timer); accept(); } });
      core!.once("error", (error) => { clearTimeout(timer); reject(error); });
      core!.once("exit", () => { clearTimeout(timer); reject(new Error("Windows test TUN exited")); });
    });
    core.stderr.resume(); core.stdin.end(JSON.stringify(config)); await ready;
    application.bind(0); await once(application, "listening");
    for (const destination of [7000, 443]) for (const length of [64, 1200, 1472]) {
      const packet = randomBytes(length);
      const reply = new Promise<Buffer>((accept, reject) => {
        const onMessage = (data: Buffer): void => { clearTimeout(timer); accept(data); };
        const timer = setTimeout(() => { application.removeListener("message", onMessage); reject(new Error(`Windows TUN UDP/${destination} did not return ${length} bytes`)); }, 3000);
        application.once("message", onMessage);
      });
      application.send(packet, destination, "198.18.0.1"); expect(await reply).toEqual(packet);
    }
  } finally {
    try { application.close(); } catch { /* Never bound on startup failure. */ }
    await client.stop();
    if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
    await promisify(execFile)("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
      "Get-NetRoute -DestinationPrefix '198.18.0.1/32' -InterfaceAlias 'LevikGameCi' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"], { windowsHide: true, timeout: 10_000 });
  }
}, 35_000);
