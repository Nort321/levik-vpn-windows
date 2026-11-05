import { createServer, connect, type Socket, type Server } from "node:net";
import { createServer as createTlsServer } from "node:tls";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CoreTunnelHealth, type NativeTunnelProbe, type TunnelHealthOptions } from "../src/main/core/nativeTunnelHealth";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";

afterEach(() => vi.useRealTimers());
const passed = (durationMs: number | null = null) => JSON.stringify({ ok: true, value: { healthy: true, durationMs, codes: [], cancelled: false } });
const stopped = () => JSON.stringify({ ok: true, value: { healthy: false, durationMs: null, codes: [], cancelled: true } });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const core = new RustCore(null, () => {}, mode); const report = vi.fn();
  const native: NativeTunnelProbe = { read: vi.fn(async () => passed()), close: vi.fn() };
  const start = vi.fn(() => native); const health = new CoreTunnelHealth(() => core, "windows", report); health.useRustCore(start);
  const fallback = vi.fn(async (_options: TunnelHealthOptions) => false);
  return { core, report, native, start, health, fallback };
}

describe("native tunnel check adapter", () => {
  it.each(["ts", "shadow"] as const)("preserves the exact legacy Promise and avoids native work in %s mode", async (mode) => {
    const { health, start } = configured(mode); const answer = Promise.resolve(true); const fallback = vi.fn(() => answer);
    expect(health.check({}, fallback)).toBe(answer); expect(await answer).toBe(true);
    expect(fallback).toHaveBeenCalledOnce(); expect(start).not.toHaveBeenCalled();
  });
  it("carries Windows startup policy without arbitrary destinations and closes its owner", async () => {
    const { health, start, native, fallback, report } = configured();
    expect(await health.check({ startup: true }, fallback)).toBe(true);
    expect(start).toHaveBeenCalledWith('{"kind":"handshake","startup":true,"windows":true}');
    expect(fallback).not.toHaveBeenCalled(); expect(native.close).toHaveBeenCalledOnce(); expect(report).not.toHaveBeenCalled();
  });
  it("reports only allowlisted failure codes from a valid failed check", async () => {
    const { health, native, fallback, report } = configured(); const onFailure = vi.fn();
    native.read = vi.fn(async () => JSON.stringify({ ok: true, value: { healthy: false, cancelled: false, durationMs: null, codes: ["tls", "http_407"] } }));
    expect(await health.check({ onFailure }, fallback)).toBe(false); expect(onFailure).toHaveBeenCalledWith(["tls", "http_407"]);
    expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
  });
  it("uses the returned complete traffic duration without a second Node download", async () => {
    const { health, native, start } = configured(); native.read = vi.fn(async () => passed(123)); const fallback = vi.fn(async () => 999);
    expect(await health.traffic(() => true, fallback)).toBe(123); expect(fallback).not.toHaveBeenCalled();
    expect(start).toHaveBeenCalledWith('{"kind":"traffic","startup":false,"windows":true}');
  });
  it("falls back only before native network work when activation fails", async () => {
    const { health, start, fallback, report } = configured();
    start.mockImplementation(() => { throw new Error("PRIVATE native details"); });
    await health.check({}, fallback); await health.check({}, fallback);
    expect(start).toHaveBeenCalledOnce(); expect(fallback).toHaveBeenCalledTimes(2); expect(report).toHaveBeenCalledWith();
  });
  it.each(["reject", "malformed", "private code", "bad duration"])("does not replay an already started check on %s", async (failure) => {
    const { health, native, fallback, report } = configured(); const onFailure = vi.fn();
    native.read = failure === "reject" ? vi.fn(async () => { throw new Error("PRIVATE error"); })
      : vi.fn(async () => failure === "malformed" ? "broken" : JSON.stringify({ ok: true,
        value: { healthy: false, cancelled: false, durationMs: failure === "bad duration" ? 3 : null, codes: [failure === "private code" ? "PRIVATE token" : "tls"] } }));
    expect(await health.check({ onFailure }, fallback)).toBe(false); expect(onFailure).toHaveBeenCalledWith(["other"]);
    expect(fallback).not.toHaveBeenCalled(); expect(report).toHaveBeenCalledWith(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("does not start network work when its connection is already obsolete", async () => {
    const { health, start, fallback, report } = configured();
    expect(await health.check({ shouldContinue: () => false }, fallback)).toBe(false);
    expect(start).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
  });
  it("cancels on a connection change and removes the watcher without a failure callback", async () => {
    vi.useFakeTimers(); const { health, native, fallback, report } = configured(); let current = true;
    const reading = deferred<string>(); native.read = vi.fn(() => reading.promise); native.close = vi.fn(() => reading.resolve(stopped()));
    const onFailure = vi.fn(); const result = health.check({ shouldContinue: () => current, onFailure }, fallback);
    current = false; await vi.advanceTimersByTimeAsync(100); expect(await result).toBe(false);
    expect(onFailure).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("can cancel an active healthy answer without allowing it into a later connection", async () => {
    const { health, native, fallback, report } = configured(); const reading = deferred<string>(); const onFailure = vi.fn();
    native.read = vi.fn(() => reading.promise); const result = health.check({ onFailure }, fallback);
    health.cancel(); reading.resolve(passed()); expect(await result).toBe(false);
    expect(onFailure).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
  });
  it("finishes a started Rust check across a mode switch and uses Node for the next check", async () => {
    const { health, native, fallback, core } = configured(); const reading = deferred<string>(); native.read = vi.fn(() => reading.promise);
    const result = health.check({}, fallback); core.setMode("ts"); reading.resolve(passed()); expect(await result).toBe(true);
    expect(fallback).not.toHaveBeenCalled(); await health.check({}, fallback); expect(fallback).toHaveBeenCalledOnce();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
async function listen(server: Server): Promise<number> {
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address(); if (!address || typeof address === "string") throw new Error("TEST listener"); return address.port;
}
async function close(server: Server, sockets: ReadonlySet<Socket>): Promise<void> {
  for (const socket of sockets) socket.destroy(); await new Promise<void>((done) => server.close(() => done()));
}
describe.skipIf(!modulePath)("real native tunnel health boundary", () => {
  function factory() {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing"); const status = loadLevikCore(modulePath);
    if (status.state !== "loaded" || !status.module.startTunnelProbe) throw new Error("Native tunnel health unavailable");
    return status.module.startTunnelProbe;
  }
  it("cancels before reading and rejects arbitrary URLs and privileged ports", async () => {
    const start = factory(); const native = start('{"kind":"handshake"}'); native.close(); native.close();
    expect(JSON.parse(await native.read())).toEqual({ ok: true, value: { healthy: false, durationMs: null, codes: [], cancelled: true } });
    expect(() => start('{"kind":"traffic","port":22}')).toThrow("Rust tunnel health check failed");
    expect(() => start('{"kind":"handshake","url":"https://unused.invalid"}')).toThrow("Rust tunnel health check failed");
  });
  it("rejects an untrusted loopback TLS certificate through the production system verifier", async () => {
    const cert = await readFile(join(__dirname, "fixtures/health-test-cert.pem"));
    const key = await readFile(join(__dirname, "fixtures/health-test-key.pem"));
    const sockets = new Set<Socket>(); const track = (socket: Socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); return socket; };
    const tls = createTlsServer({ cert, key }); tls.on("connection", track); tls.on("tlsClientError", () => {});
    const tlsPort = await listen(tls); let requests = 0;
    const proxy = createServer((socket) => {
      track(socket); let buffered = Buffer.alloc(0);
      const receive = (data: Buffer) => {
        buffered = Buffer.concat([buffered, data]); if (!buffered.includes("\r\n\r\n")) return;
        socket.off("data", receive); requests++;
        expect(buffered.toString()).toMatch(/^CONNECT (?:cloudflare-dns\.com|www\.google\.com):443 HTTP\/1\.1/);
        expect(buffered.toString().toLowerCase()).not.toMatch(/authorization:|cookie:|x-levik-/);
        const peer = track(connect(tlsPort, "127.0.0.1")); peer.on("error", () => socket.destroy());
        peer.once("connect", () => { socket.write("HTTP/1.1 200 OK\r\n\r\n"); socket.pipe(peer).pipe(socket); });
        socket.on("error", () => peer.destroy()); socket.on("close", () => peer.destroy());
      };
      socket.on("data", receive);
    });
    const port = await listen(proxy); const native = factory()(JSON.stringify({ kind: "handshake", port }));
    try {
      const result = JSON.parse(await native.read()); expect(result.ok).toBe(true);
      expect(result.value.healthy).toBe(false); expect(result.value.cancelled).toBe(false);
      expect(result.value.codes).toEqual(["tls", "tls"]); expect(requests).toBe(2);
    } finally { native.close(); await close(proxy, sockets); await close(tls, sockets); }
  }, 15_000);
  it("closes both parallel traffic sockets when the native owner is cancelled", async () => {
    const sockets = new Set<Socket>(); const ready = deferred<void>(); const closed = deferred<void>(); let active = 0;
    const proxy = createServer((socket) => {
      sockets.add(socket); socket.on("close", () => { sockets.delete(socket); if (active === 2 && sockets.size === 0) closed.resolve(); });
      let buffered = Buffer.alloc(0);
      const receive = (data: Buffer) => {
        buffered = Buffer.concat([buffered,data]); if (!buffered.includes("\r\n\r\n")) return;
        socket.off("data", receive); socket.resume(); socket.write("HTTP/1.1 200 OK\r\n\r\n"); if (++active === 2) ready.resolve();
      };
      socket.on("data", receive); socket.on("error", () => {});
    });
    const port = await listen(proxy); const native = factory()(JSON.stringify({ kind: "traffic", port })); const reading = native.read();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([ready.promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("TEST traffic did not start")), 5000); })]);
      native.close(); const result = JSON.parse(await reading); expect(result.value.cancelled).toBe(true); expect(active).toBe(2);
      clearTimeout(timer);
      await Promise.race([closed.promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("TEST traffic sockets remained open")), 1000); })]);
      expect(sockets.size).toBe(0);
    } finally { clearTimeout(timer); native.close(); await close(proxy, sockets); }
  }, 10_000);
});
