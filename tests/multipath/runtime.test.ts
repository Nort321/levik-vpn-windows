import { createSocket } from "node:dgram";
import { Socket, createServer } from "node:net";
import { once } from "node:events";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { startRelay } from "../../src/main/vpn/multipath/relay";
import { GameMultipath } from "../../src/main/vpn/multipath/client";
import { GAME_PROBE_USER } from "../../src/main/vpn/gameRoutes";

async function port(): Promise<number> {
  const server = createServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); if (!address || typeof address === "string") throw new Error("port");
  server.close(); await once(server, "close"); return address.port;
}

it("duplicates through authenticated Xray paths, deduplicates both ways and keeps one game source port after a path fails", async () => {
  const relay = await startRelay({ port: 0, allowTestLoopback: true });
  const game = createSocket("udp4"); const links = [createSocket("udp4"), createSocket("udp4")];
  const client = new GameMultipath(); const application = new Socket();
  const sourcePorts = new Set<number>(); const requests: string[] = [];
  const enabled = [true, true]; const received: string[] = []; let core: ChildProcessWithoutNullStreams | undefined;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  try {
    game.bind(0, "127.0.0.1"); await once(game, "listening");
    game.on("message", (data, peer) => { requests.push(data.toString()); sourcePorts.add(peer.port); game.send(data, peer.port, peer.address); });
    for (const [index, link] of links.entries()) {
      link.bind(0, "127.0.0.1"); await once(link, "listening");
      let source = 0;
      link.on("message", (data, peer) => {
        if (!enabled[index]) return;
        if (peer.port === relay.port) {
          const timer = setTimeout(() => { timers.delete(timer); if (source) link.send(data, source, "127.0.0.1"); }, index === 0 ? 0 : 20);
          timers.add(timer);
        } else { source = peer.port; link.send(data, relay.port, "127.0.0.1"); }
      });
    }
    const ports = await Promise.all([port(), port()]);
    const executable = process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe");
    const config = { log: { loglevel: "warning" }, inbounds: ports.map((p, index) => ({ tag: `in${index}`, listen: "127.0.0.1", port: p, protocol: "socks",
      settings: { auth: "password", accounts: [{ user: GAME_PROBE_USER, pass: "test-only" }], udp: true, ip: "127.0.0.1" } })),
    outbounds: links.map((link, index) => ({ tag: `out${index}`, protocol: "freedom", settings: { redirect: `127.0.0.1:${link.address().port}` } })),
    routing: { rules: ports.map((_, index) => ({ type: "field", inboundTag: [`in${index}`], outboundTag: `out${index}` })) } };
    core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe", windowsHide: true });
    const ready = new Promise<void>((accept, reject) => {
      const timer = setTimeout(() => reject(new Error("core timeout")), 5_000);
      core!.stdout.on("data", (data: Buffer) => { if (data.toString().includes("started")) { clearTimeout(timer); accept(); } });
      core!.once("error", (error) => { clearTimeout(timer); reject(error); });
    });
    core.stdin.end(JSON.stringify(config)); await ready;
    const listener = await client.listen(); await client.connect(ports.map((p, index) => ({ index, port: p })), "test-only");
    expect(client.snapshot().state).toBe("protected");
    let buffer = Buffer.alloc(0); let responseHeader = false;
    application.on("data", (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);
      if (!responseHeader) { if (buffer.length < 2) return; buffer = buffer.subarray(2); responseHeader = true; }
      while (buffer.length >= 2 && buffer.length >= 2 + buffer.readUInt16BE(0)) {
        const length = buffer.readUInt16BE(0); received.push(buffer.subarray(2, 2 + length).toString()); buffer = buffer.subarray(2 + length);
      }
    });
    application.connect(listener.port, "127.0.0.1"); await once(application, "connect");
    const header = Buffer.alloc(26); Buffer.from(listener.uuid.replaceAll("-", ""), "hex").copy(header, 1);
    header[18] = 2; header.writeUInt16BE(game.address().port, 19); header[21] = 1; Buffer.from([127, 0, 0, 1]).copy(header, 22);
    application.write(header);
    const send = async (value: string): Promise<void> => {
      const payload = Buffer.from(value); const length = Buffer.alloc(2); length.writeUInt16BE(payload.length);
      application.write(Buffer.concat([length, payload]));
      for (let wait = 0; wait < 100 && !received.includes(value); wait++) await new Promise<void>((done) => setTimeout(done, 10));
      expect(received).toContain(value);
    };
    await send("before-loss");
    await new Promise<void>((done) => setTimeout(done, 50));
    expect(client.snapshot().duplicateReplies).toBeGreaterThan(0);
    enabled[0] = false;
    await send("after-loss"); await send("still-same-flow");
    expect(requests).toEqual(["before-loss", "after-loss", "still-same-flow"]);
    expect(received).toEqual(requests); expect(sourcePorts.size).toBe(1);
    expect(relay.counts.duplicates).toBeGreaterThan(0);
  } finally {
    application.destroy(); await client.stop();
    for (const timer of timers) clearTimeout(timer);
    if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
    for (const socket of [game, ...links]) { try { socket.close(); } catch { /* Startup failure. */ } }
    await relay.close();
  }
}, 15_000);
