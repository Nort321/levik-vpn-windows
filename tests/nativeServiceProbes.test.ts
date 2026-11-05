import { CoreServiceProbes, type NativeServiceProbe, type StartServiceProbe } from "../src/main/core/nativeServiceProbes";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { probeServiceRouteDns } from "../src/main/vpn/serviceRouteTransport";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";
import { once } from "node:events";

const auth = { port: 47188, user: "levik-service", password: "a".repeat(48) };
const answer = (value: boolean) => JSON.stringify({ ok: true, value });
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const core = new RustCore(null, () => {}, mode); const report = vi.fn();
  const native: NativeServiceProbe = { read: vi.fn(async () => answer(true)), close: vi.fn() };
  const start = vi.fn((_input: string) => native); const probes = new CoreServiceProbes(); probes.useRustCore(() => core, start, report);
  return { probes, core, native, start, report };
}
function pending() { let resolve!: (value: string) => void; const promise = new Promise<string>((done) => { resolve = done; }); return { promise, resolve }; }

describe("service probe ownership and contract", () => {
  it.each(["ts", "shadow"] as const)("preserves the exact fallback promise in %s", async (mode) => {
    const { probes, start } = configured(mode); const promise = Promise.resolve(true); const fallback = vi.fn(() => promise);
    expect(probes.transport(47200, auth, fallback)).toBe(promise);
    expect(probes.dns(47200, auth, [], undefined, fallback)).toBe(promise);
    expect(start).not.toHaveBeenCalled();
  });
  it("supports an older module without this optional capability", () => {
    const probes = new CoreServiceProbes(); probes.useRustCore(() => new RustCore(null, () => {}, "rust"), undefined, () => {});
    const promise = Promise.resolve(false); expect(probes.transport(47200, auth, () => promise)).toBe(promise);
  });
  it("sends only the probe inputs and closes a successful handle", async () => {
    const { probes, start, native } = configured(); const fallback = vi.fn(async () => false);
    const extended = { ...auth, privateAccount: "PRIVATE" };
    expect(await probes.dns(47200, extended, ["tcp://resolver.test"], undefined, fallback)).toBe(true);
    expect(JSON.parse(start.mock.calls[0]![0])).toEqual({ kind: "dns", port: 47200, auth, resolvers: ["tcp://resolver.test"] });
    expect(fallback).not.toHaveBeenCalled(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("falls back only for activation failure and disables the broken factory", async () => {
    const { probes, start, report } = configured(); start.mockImplementation(() => { throw new Error("PRIVATE"); }); const fallback = vi.fn(async () => true);
    expect(await probes.transport(47200, auth, fallback)).toBe(true); expect(await probes.transport(47200, auth, fallback)).toBe(true);
    expect(start).toHaveBeenCalledOnce(); expect(fallback).toHaveBeenCalledTimes(2); expect(report).toHaveBeenCalledWith();
  });
  it.each(["reject", "bad JSON", "error", "missing value", "wrong type", "oversize"])("never replays after read starts: %s", async (kind) => {
    const { probes, native, report } = configured(); native.read = vi.fn(async () => {
      if (kind === "reject") throw new Error("PRIVATE");
      return kind === "bad JSON" ? "PRIVATE" : kind === "error" ? '{"ok":false}' : kind === "missing value" ? '{"ok":true}'
        : kind === "wrong type" ? '{"ok":true,"value":"yes"}' : "x".repeat(4097);
    });
    const fallback = vi.fn(async () => true); expect(await probes.transport(47200, auth, fallback)).toBe(false);
    expect(fallback).not.toHaveBeenCalled(); expect(report).toHaveBeenCalledWith(); expect(native.close).toHaveBeenCalledOnce();
  });
  it.each([22, 47199, 47232, 65536, 47200.5])( "rejects an unowned transport port %s before activation", async (port) => {
    const { probes, start } = configured(); const fallback = vi.fn(async () => true);
    expect(await probes.transport(port, auth, fallback)).toBe(false); expect(start).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled();
  });
  it("bounds credentials, resolver count and UTF-8 bytes before activation", async () => {
    const { probes, start } = configured(); const fallback = vi.fn(async () => true);
    expect(await probes.dns(47200, { ...auth, password: "PRIVATE" }, [], undefined, fallback)).toBe(false);
    expect(await probes.dns(47200, auth, Array(17).fill("tcp://resolver.test"), undefined, fallback)).toBe(false);
    expect(await probes.dns(47200, auth, ["я".repeat(2049)], undefined, fallback)).toBe(false);
    expect(start).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled();
  });
  it("does no work when already aborted", async () => {
    const { probes, start } = configured(); const abort = new AbortController(); abort.abort();
    expect(await probes.dns(47200, auth, [], abort.signal, async () => true)).toBe(false); expect(start).not.toHaveBeenCalled();
  });
  it.each(["abort", "stop"])("ignores a late result after %s and quietly closes the handle", async (kind) => {
    const { probes, native, report } = configured(); const result = pending(); native.read = vi.fn(() => result.promise); const abort = new AbortController();
    const reading = probes.dns(47200, auth, [], abort.signal, async () => { throw new Error("Unexpected replay"); });
    if (kind === "abort") abort.abort(); else probes.cancel();
    expect(native.close).toHaveBeenCalled(); result.resolve(answer(true)); expect(await reading).toBe(false); expect(report).not.toHaveBeenCalled();
  });
});

const servers = new Set<Server>(); const sockets = new Set<Socket>();
afterEach(async () => {
  for (const socket of sockets) socket.destroy(); sockets.clear();
  await Promise.all([...servers].map((server) => new Promise<void>((done) => server.close(() => done())))); servers.clear();
});
async function listen(server: Server): Promise<number> {
  servers.add(server); server.on("connection", (socket: Socket) => { sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket)); });
  server.listen(0, "127.0.0.1"); await once(server, "listening"); const address = server.address();
  if (!address || typeof address === "string") throw new Error("TEST listener"); return address.port;
}
const modulePath = process.env.LEVIK_TEST_CORE;
function nativeFactory(): StartServiceProbe {
  if (!modulePath) throw new Error("LEVIK_TEST_CORE missing"); const loaded = loadLevikCore(modulePath);
  if (loaded.state !== "loaded" || !loaded.module.startServiceProbe) throw new Error("Native service probe missing");
  return loaded.module.startServiceProbe;
}
const modes = modulePath ? ["node", "rust"] as const : ["node"] as const;
async function dns(mode: "node" | "rust", port: number, signal?: AbortSignal): Promise<boolean> {
  const credentials = { ...auth, port };
  if (mode === "node") return probeServiceRouteDns(port, credentials, ["tcp://resolver.test"], signal);
  const probes = new CoreServiceProbes(); probes.useRustCore(() => new RustCore(null, () => {}, "rust"), nativeFactory(), () => {});
  return probes.dns(port, credentials, ["tcp://resolver.test"], signal, async () => { throw new Error("Unexpected Node replay"); });
}
describe.each(modes)("real service DNS boundary (%s)", (mode) => {
  it.each(["valid", "uppercase", "different question", "one dotted label", "pointer cycle", "wrong ID", "truncated"])("validates a real authenticated wire reply: %s", async (kind) => {
    let requests = 0; let questions = 0;
    const server = createServer(); const port = await listen(server);
    server.on("connect", (req, socket) => {
      requests++; expect(req.url).toBe("resolver.test:53");
      expect(req.headers["proxy-authorization"]).toBe(`Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`);
      socket.write("HTTP/1.1 200 OK\r\n\r\n"); let buffered = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]); if (buffered.length < 2 || buffered.length < buffered.readUInt16BE(0) + 2) return;
        questions++; const question = buffered.subarray(2); expect(question.subarray(12)).toEqual(Buffer.from([7,...Buffer.from("example"),3,...Buffer.from("com"),0,0,1,0,1]));
        const reply = Buffer.concat([question, Buffer.from([0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,1])]); reply[2] = 0x81; reply[3] = 0x80; reply.writeUInt16BE(1,6);
        if (kind === "uppercase") Buffer.from("EXAMPLE").copy(reply,13);
        if (kind === "different question") reply[13] = 120;
        if (kind === "one dotted label") { reply[12] = 11; Buffer.from("example.com").copy(reply,13); }
        if (kind === "pointer cycle") { reply[12] = 0xc0; reply[13] = 12; }
        if (kind === "wrong ID") reply[0] = reply[0]! ^ 1;
        const bytes = kind === "truncated" ? reply.subarray(0,reply.length - 1) : reply;
        const frame = Buffer.alloc(bytes.length + 2); frame.writeUInt16BE(bytes.length); bytes.copy(frame,2); socket.end(frame);
      });
    });
    expect(await dns(mode,port)).toBe(kind === "valid" || kind === "uppercase"); expect(requests).toBe(1); expect(questions).toBe(1);
  });
  it("cancels a waiting CONNECT and releases the real socket", async () => {
    const server = createServer(); const port = await listen(server); const connected = once(server,"connect"); const abort = new AbortController();
    const reading = dns(mode,port,abort.signal); const [, socket] = await connected; const closed = once(socket,"close");
    socket.once("end", () => socket.end()); socket.resume(); abort.abort();
    expect(await reading).toBe(false); await closed;
  });
});
