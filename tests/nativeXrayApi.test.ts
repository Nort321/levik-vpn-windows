import { createServer as createH2Server, type Http2Server, type ServerHttp2Session, type ServerHttp2Stream, type IncomingHttpHeaders } from "node:http2";
import { createServer, type Server, type Socket } from "node:net";
import { once } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CoreXrayApi, type NativeXrayRequest } from "../src/main/core/nativeXrayApi";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";

const auth = { port: 47200, user: "levik-service", password: "a".repeat(48) };
const stats = { uplink: 1234, downlink: 5678, initialized: true };
const answer = (value: unknown) => JSON.stringify({ ok: true, value });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { resolve, promise }; }
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const core = new RustCore(null, () => {}, mode); const report = vi.fn();
  const native: NativeXrayRequest = { read: vi.fn(async () => answer(stats)), close: vi.fn() };
  const start = vi.fn((_input: string) => native); const api = new CoreXrayApi(); api.useRustCore(() => core, start, report);
  return { core, report, native, start, api };
}
describe("native local Xray API adapter", () => {
  it.each(["ts", "shadow"] as const)("preserves the exact legacy Promise in %s without duplicate requests", async (mode) => {
    const { api, start } = configured(mode); const promise = Promise.resolve(stats); const fallback = vi.fn(() => promise);
    expect(api.statistics(auth, fallback)).toBe(promise); await promise;
    expect(fallback).toHaveBeenCalledOnce(); expect(start).not.toHaveBeenCalled();
  });
  it("passes only local channel credentials and fixed statistics request", async () => {
    const { api, start, native, report } = configured(); const fallback = vi.fn(async () => stats);
    expect(await api.statistics({ ...auth, ...{ ignored: "PRIVATE profile" } }, fallback)).toEqual(stats);
    expect(JSON.parse(start.mock.calls[0]?.[0] ?? "{}")).toEqual({ request: { kind: "statistics" }, port: 47185, auth });
    expect(fallback).not.toHaveBeenCalled(); expect(native.close).toHaveBeenCalledOnce(); expect(report).not.toHaveBeenCalled();
  });
  it("requires a positive acknowledgement for the exact owned route", async () => {
    const { api, start, native } = configured(); native.read = vi.fn(async () => answer({ applied: true })); const fallback = vi.fn(async () => {});
    await api.override("levik-service-main", "levik-service-endpoint-0", auth, fallback);
    expect(JSON.parse(start.mock.calls[0]?.[0] ?? "{}").request).toEqual({ kind: "override", balancer: "levik-service-main", target: "levik-service-endpoint-0" });
    expect(fallback).not.toHaveBeenCalled(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("falls back once on activation failure before native socket work", async () => {
    const { api, start, report } = configured(); start.mockImplementation(() => { throw new Error("PRIVATE input"); }); const fallback = vi.fn(async () => {});
    await api.override("levik-service-main", "direct", auth, fallback); await api.override("levik-service-main", "direct", auth, fallback);
    expect(start).toHaveBeenCalledOnce(); expect(fallback).toHaveBeenCalledTimes(2); expect(report).toHaveBeenCalledWith();
  });
  it.each(["reject", "invalid JSON", "error", "missing ack", "wrong ack"])("never replays a possibly applied write on %s", async (kind) => {
    const { api, native, report } = configured(); const fallback = vi.fn(async () => {});
    native.read = vi.fn(async () => {
      if (kind === "reject") throw new Error("PRIVATE session secret");
      return kind === "invalid JSON" ? "PRIVATE not JSON" : kind === "error" ? '{"ok":false}' : answer(kind === "missing ack" ? stats : { applied: false });
    });
    await expect(api.override("levik-service-main", "direct", auth, fallback)).rejects.toThrow("Локальный API ядра не подтвердил запрос");
    expect(fallback).not.toHaveBeenCalled(); expect(report).toHaveBeenCalledWith(); expect(native.close).toHaveBeenCalledOnce();
  });
  it.each([Number.MAX_SAFE_INTEGER + 1, -1, 1.5, "123"])("rejects unsafe native counters: %s", async (uplink) => {
    const { api, native } = configured(); native.read = vi.fn(async () => answer({ ...stats, uplink })); const fallback = vi.fn(async () => stats);
    await expect(api.statistics(auth, fallback)).rejects.toThrow(); expect(fallback).not.toHaveBeenCalled();
  });
  it("rejects arbitrary endpoints, credentials and unowned targets before creating a handle", async () => {
    const { api, start } = configured(); const fallback = vi.fn(async () => stats);
    for (const endpoint of ["example.com:443", "127.0.0.1:22", "127.0.0.1:65536", "127.0.0.1:1234/private"]) await expect(api.statistics(auth, fallback, endpoint)).rejects.toThrow();
    await expect(api.statistics({ ...auth, password: "PRIVATE" }, fallback)).rejects.toThrow();
    await expect(api.override("game-balancer", "direct", auth, async () => {})).rejects.toThrow();
    expect(start).not.toHaveBeenCalled(); expect(fallback).not.toHaveBeenCalled();
  });
  it("does not apply an old acknowledgement after its session has stopped", async () => {
    const { api, native, report } = configured(); const pending = deferred<string>(); native.read = vi.fn(() => pending.promise); const fallback = vi.fn(async () => {});
    const result = api.override("levik-service-main", "direct", auth, fallback); api.cancel(); pending.resolve(answer({ applied: true }));
    await expect(result).rejects.toThrow(); expect(fallback).not.toHaveBeenCalled(); expect(report).not.toHaveBeenCalled(); expect(native.close).toHaveBeenCalled();
  });
  it("finishes an existing request across a mode change and uses Node next time", async () => {
    const { api, core, native } = configured(); const pending = deferred<string>(); native.read = vi.fn(() => pending.promise); const fallback = vi.fn(async () => stats);
    const result = api.statistics(auth, fallback); core.setMode("ts"); pending.resolve(answer(stats)); expect(await result).toEqual(stats);
    expect(fallback).not.toHaveBeenCalled(); await api.statistics(auth, fallback); expect(fallback).toHaveBeenCalledOnce();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
const servers = new Set<Server | Http2Server>(); const sessions = new Set<ServerHttp2Session>(); const sockets = new Set<Socket>();
afterEach(async () => {
  for (const session of sessions) session.destroy(); sessions.clear();
  for (const socket of sockets) socket.destroy(); sockets.clear();
  await Promise.all([...servers].map((server) => new Promise<void>((done) => server.close(() => done())))); servers.clear();
});
async function listen(server: Server | Http2Server): Promise<number> {
  servers.add(server); server.on("connection", (socket: Socket) => { sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => sockets.delete(socket)); });
  server.listen(0, "127.0.0.1"); await once(server, "listening"); const address = server.address();
  if (!address || typeof address === "string") throw new Error("TEST listener"); return address.port;
}
const frame = (message: Buffer) => { const head = Buffer.alloc(5); head.writeUInt32BE(message.length, 1); return Buffer.concat([head, message]); };
function stat(name: string, value: number): Buffer {
  const counter: number[] = []; let remaining = BigInt(value);
  do { const byte = Number(remaining & 127n); remaining >>= 7n; counter.push(byte | (remaining ? 128 : 0)); } while (remaining);
  const text = Buffer.from(name); const nested = Buffer.concat([Buffer.from([10, text.length]), text, Buffer.from([16, ...counter])]);
  return Buffer.concat([Buffer.from([10, nested.length]), nested]);
}
function respond(stream: ServerHttp2Stream, payload: Buffer, status: string | null = "0") {
  stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
  stream.once("wantTrailers", () => stream.sendTrailers({ ...(status === null ? {} : { "grpc-status": status }), "grpc-message": "PRIVATE server details" }));
  stream.on("error", () => {}); stream.end(payload);
}
async function h2Server(handler: (stream: ServerHttp2Stream, path: string, body: Buffer) => void): Promise<number> {
  const server = createH2Server(); server.on("session", (session) => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); });
  server.on("stream", (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
    stream.on("error", () => {});
    const chunks: Buffer[] = []; stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    stream.once("end", () => handler(stream, String(headers[":path"]), Buffer.concat(chunks)));
  });
  return listen(server);
}
function factory() {
  if (!modulePath) throw new Error("LEVIK_TEST_CORE missing"); const status = loadLevikCore(modulePath);
  if (status.state !== "loaded" || !status.module.startXrayRequest) throw new Error("Native Xray API unavailable"); return status.module.startXrayRequest;
}
describe.skipIf(!modulePath)("real native Xray HTTP/2 boundary", () => {
  it("reads real protobuf counters over HTTP/2 and acknowledges an owned override", async () => {
    let requests = 0;
    const port = await h2Server((stream, path, body) => {
      requests++; expect(body[0]).toBe(0); expect(body.readUInt32BE(1)).toBe(body.length - 5);
      if (path.endsWith("/QueryStats")) {
        expect(body.subarray(5)).toEqual(Buffer.concat([Buffer.from([10, Buffer.byteLength("inbound>>>levik-tun-in>>>traffic>>>")]), Buffer.from("inbound>>>levik-tun-in>>>traffic>>>")]));
        respond(stream, frame(Buffer.concat([stat("inbound>>>levik-tun-in>>>traffic>>>uplink", 1234), stat("inbound>>>levik-tun-in>>>traffic>>>downlink", 5678)])));
      } else { expect(path).toBe("/xray.app.router.command.RoutingService/OverrideBalancerTarget"); respond(stream, frame(Buffer.alloc(0))); }
    });
    const api = new CoreXrayApi(); api.useRustCore(() => new RustCore(null, () => {}, "rust"), factory(), () => {});
    const fallback = vi.fn(async () => stats); expect(await api.statistics(undefined, fallback, `127.0.0.1:${port}`)).toEqual(stats);
    await api.override("levik-service-rule-0", "direct", undefined, async () => { throw new Error("Unexpected replay"); }, `127.0.0.1:${port}`);
    expect(fallback).not.toHaveBeenCalled(); expect(requests).toBe(2);
  });
  it.each(["7", "missing", "malformed", "compressed", "oversize"])("rejects %s response without replay or private details", async (kind) => {
    let requests = 0;
    const port = await h2Server((stream) => { requests++; respond(stream,
      kind === "oversize" ? Buffer.alloc(256 * 1024 + 1) : kind === "malformed" ? Buffer.from([0]) : kind === "compressed" ? Buffer.from([1,0,0,0,0]) : frame(Buffer.alloc(0)),
      kind === "7" ? "7" : kind === "missing" ? null : "0"); });
    const api = new CoreXrayApi(); api.useRustCore(() => new RustCore(null, () => {}, "rust"), factory(), () => {}); const fallback = vi.fn(async () => stats);
    await expect(api.statistics(undefined, fallback, `127.0.0.1:${port}`)).rejects.toThrow("Локальный API ядра не подтвердил запрос");
    expect(fallback).not.toHaveBeenCalled(); expect(requests).toBe(1);
  });
  it("cancels before read and rejects arbitrary methods and remote hosts", async () => {
    let accepted = 0; const port = await listen(createServer(() => { accepted++; })); const start = factory();
    const request = start(JSON.stringify({ request: { kind: "statistics" }, port })); request.close(); request.close(); expect(JSON.parse(await request.read())).toEqual({ ok: false });
    expect(() => start('{"request":{"kind":"statistics","reset":true}}')).toThrow();
    expect(() => start('{"request":{"kind":"statistics"},"host":"example.com"}')).toThrow();
    expect(() => start('{"request":{"kind":"override","balancer":"game","target":"direct"}}')).toThrow();
    expect(accepted).toBe(0);
  });
  it("closes the actual HTTP/2 connection on cancellation before test cleanup", async () => {
    const ready = deferred<ServerHttp2Stream>(); const port = await h2Server((stream) => ready.resolve(stream));
    const request = factory()(JSON.stringify({ request: { kind: "statistics" }, port })); const reading = request.read(); const stream = await ready.promise;
    const closed = new Promise<void>((done) => stream.session!.once("close", done)); request.close(); expect(JSON.parse(await reading)).toEqual({ ok: false }); await closed;
  });
  it("closes a silent HTTP/2 session at the request deadline", async () => {
    const ready = deferred<ServerHttp2Stream>(); const port = await h2Server((stream) => ready.resolve(stream));
    const request = factory()(JSON.stringify({ request: { kind: "statistics" }, port })); const reading = request.read(); const stream = await ready.promise;
    const closed = new Promise<void>((done) => stream.session!.once("close", done));
    expect(JSON.parse(await reading)).toEqual({ ok: false }); await closed; request.close();
  }, 10_000);
  it.each([false, true])("handles private CONNECT refusal/cancellation without exposing its password (cancel=%s)", async (cancel) => {
    const accepted = deferred<Socket>();
    const port = await listen(createServer((socket) => {
      let head = ""; socket.on("data", (chunk: Buffer) => {
        head += chunk.toString(); if (!head.endsWith("\r\n\r\n")) return;
        expect(head).toContain("CONNECT levik-service-api:80 HTTP/1.1\r\n");
        expect(head).toContain(`Proxy-Authorization: Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}\r\n`);
        accepted.resolve(socket);
        if (!cancel) socket.end("HTTP/1.1 407 Authentication Required\r\n\r\n");
      });
    }));
    const request = factory()(JSON.stringify({ request: { kind: "statistics" }, auth: { ...auth, port } }));
    const reading = request.read(); const socket = await accepted.promise;
    const closed = new Promise<void>((done) => socket.once("close", done));
    if (cancel) request.close();
    expect(JSON.parse(await reading)).toEqual({ ok: false }); await closed; request.close();
  });
});
