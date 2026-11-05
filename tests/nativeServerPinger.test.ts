import { createServer } from "node:net";
import { createSocket } from "node:dgram";
import { describe, expect, it, vi } from "vitest";
import type { TunnelServer } from "../src/shared/contracts";
import { CoreServerPinger, type NativePingBatch } from "../src/main/core/nativeServerPinger";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";

function server(port = 443, protocol = "vless"): TunnelServer {
  return { id: "TEST-server", tag: "TEST", name: "TEST", countryCode: "",
    outbound: { protocol, settings: { vnext: [{ address: "127.0.0.1", port, users: [{ id: "PRIVATE protocol credential" }] }] } } };
}
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const batch: NativePingBatch = { read: vi.fn(async () => '{"ok":true,"value":{"TEST-server":12}}'), close: vi.fn() };
  const start = vi.fn(() => batch); const report = vi.fn(); const pinger = new CoreServerPinger(() => new RustCore(null, () => {}, mode), report);
  pinger.useRustCore(start); const fallback = vi.fn(async () => ({ "TEST-server": 99 }));
  return { batch, start, report, pinger, fallback };
}

describe("Rust server measurement adapter", () => {
  it.each(["ts", "shadow"] as const)("does not duplicate network probes in %s mode", async (mode) => {
    const { pinger, start, fallback } = configured(mode);
    expect(await pinger.measure([server()], fallback)).toEqual({ "TEST-server": 99 });
    expect(fallback).toHaveBeenCalledOnce(); expect(start).not.toHaveBeenCalled();
  });

  it("passes endpoints only, preserves UDP protocol selection and closes the native owner", async () => {
    const { pinger, start, fallback, batch } = configured();
    expect(await pinger.measure([server(8443, " Hysteria2 ")], fallback)).toEqual({ "TEST-server": 12 });
    expect(start).toHaveBeenCalledWith(JSON.stringify([{ id: "TEST-server", endpoint: { host: "127.0.0.1", port: 8443 }, udp: true }]));
    expect(fallback).not.toHaveBeenCalled(); expect(batch.close).toHaveBeenCalledOnce();
  });

  it("keeps legacy modules usable and falls back before any native network work if activation fails", async () => {
    const { pinger, start, fallback, report } = configured();
    start.mockImplementation(() => { throw new Error("PRIVATE module details"); });
    await pinger.measure([server()], fallback); await pinger.measure([server()], fallback);
    expect(start).toHaveBeenCalledOnce(); expect(fallback).toHaveBeenCalledTimes(2); expect(report).toHaveBeenCalledWith();
  });

  it("cancels an active batch without a fallback or failure report and releases it", async () => {
    const { pinger, batch, fallback, report } = configured();
    let resolve!: (value: string) => void;
    batch.read = vi.fn(() => new Promise<string>((done) => { resolve = done; }));
    batch.close = vi.fn(() => resolve('{"ok":false}'));
    const measuring = pinger.measure([server()], fallback);
    pinger.cancel(); expect(await measuring).toEqual({ "TEST-server": null });
    expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
    const closes = vi.mocked(batch.close).mock.calls.length; pinger.cancel();
    expect(batch.close).toHaveBeenCalledTimes(closes);
  });

  it("enforces native batch limits without bypassing them through Node fallback", async () => {
    const { pinger, start, fallback, report } = configured();
    const servers = Array.from({ length: 513 }, (_, index) => ({ ...server(), id: `TEST-${index}` }));
    expect(Object.keys(await pinger.measure(servers, fallback))).toHaveLength(513);
    expect(start).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled(); expect(report).toHaveBeenCalledOnce();
  });

  it.each(["reject", "bad JSON", "unexpected ID", "negative", "fraction"])("does not replay a started native batch on %s", async (failure) => {
    const { pinger, batch, fallback, report } = configured();
    batch.read = failure === "reject" ? vi.fn(async () => { throw new Error("TEST failed"); })
      : vi.fn(async () => failure === "bad JSON" ? "broken" : JSON.stringify({ ok: true, value:
        failure === "unexpected ID" ? { wrong: 12 } : { "TEST-server": failure === "negative" ? -1 : 1.5 } }));
    expect(await pinger.measure([server()], fallback)).toEqual({ "TEST-server": null });
    expect(fallback).not.toHaveBeenCalled(); expect(batch.close).toHaveBeenCalledOnce(); expect(report).toHaveBeenCalledWith();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real Rust server probes", () => {
  function pinger() {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded" || !status.module.startServerPings) throw new Error("Native server probes unavailable");
    const core = new RustCore(status.module, () => {}, "rust"); const report = vi.fn();
    const pinger = new CoreServerPinger(() => core, report); pinger.useRustCore(status.module.startServerPings);
    return { pinger, report, start: status.module.startServerPings };
  }

  it("measures exactly three TCP probes through the production loader and never calls Node fallback", async () => {
    const listener = createServer((socket) => socket.destroy()); let connections = 0;
    listener.on("connection", () => { connections++; });
    await new Promise<void>((done) => listener.listen(0, "127.0.0.1", done));
    try {
      const address = listener.address(); if (!address || typeof address === "string") throw new Error("TEST listener");
      const { pinger: native, report } = pinger(); const fallback = vi.fn(async () => ({}));
      expect((await native.measure([server(address.port)], fallback))["TEST-server"]).toBeGreaterThan(0);
      expect(connections).toBe(3); expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
    } finally { await new Promise<void>((done) => listener.close(() => done())); }
  });

  it("accepts matching UDP negotiation after invalid datagrams through the native adapter", async () => {
    const socket = createSocket("udp4"); await new Promise<void>((done) => socket.bind(0, "127.0.0.1", done));
    let packets = 0;
    socket.on("message", (probe, peer) => {
      packets++; expect(probe.length).toBe(1200); expect(probe.readUInt32BE(1)).toBe(0x0a0a0a0a);
      const valid = Buffer.concat([Buffer.from([0x80,0,0,0,0,8]), probe.subarray(15,23), Buffer.from([8]), probe.subarray(6,14), Buffer.from([0,0,0,1])]);
      const invalid = Buffer.from(valid); invalid[6] = invalid[6]! ^ 0xff;
      socket.send(invalid, peer.port, peer.address); socket.send(valid, peer.port, peer.address);
    });
    try {
      const { pinger: native, report } = pinger(); const fallback = vi.fn(async () => ({}));
      expect((await native.measure([server(socket.address().port, "hysteria2")], fallback))["TEST-server"]).toBeGreaterThan(0);
      expect(packets).toBe(3); expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled();
    } finally { await new Promise<void>((done) => socket.close(() => done())); }
  });

  it("can cancel before reading without opening a socket", async () => {
    const { start } = pinger(); const batch = start(JSON.stringify([{ id: "TEST", endpoint: { host: "unused.invalid", port: 443 }, udp: true }]));
    batch.close(); batch.close(); expect(JSON.parse(await batch.read())).toEqual({ ok: false });
    expect(() => start('[{"id":"TEST","endpoint":null,"udp":false,"accountToken":"PRIVATE"}]')).toThrow("Rust server latency measurement failed");
  });
});
