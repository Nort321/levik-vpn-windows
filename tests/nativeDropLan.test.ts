import { afterEach, describe, expect, it, vi } from "vitest";
import { dropLanWithCore, type NativeLanDialer, type NativeLanListener } from "../src/main/core/nativeDropLan";
import type { NativeDropConnection } from "../src/main/core/nativeDropConnection";
import { RustCore } from "../src/main/core/rustCore";
import type { DropLan, LanAcceptor } from "../src/main/platform/levikDrop/lan";
import type { DropSocket } from "../src/main/platform/levikDrop/framing";
const attempts: DropLan[] = [], sockets: DropSocket[] = [];
afterEach(() => { for (const attempt of attempts.splice(0)) attempt.close(); for (const socket of sockets.splice(0)) socket.close(); });
const transfer = Buffer.alloc(16, 0x54), key = Buffer.alloc(32, 0x5a);
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const diagnostics: string[] = [], core = new RustCore(null, (line) => diagnostics.push(line), mode);
  const stream: NativeDropConnection = { read: vi.fn(async () => Buffer.from("TEST")), send: vi.fn(async () => {}), isClosed: vi.fn(() => false),
    startKeepalive: vi.fn(), watchIdle: vi.fn(), close: vi.fn(), closeGracefully: vi.fn() };
  const dialer: NativeLanDialer = { read: vi.fn(async () => stream), close: vi.fn() };
  const listener: NativeLanListener = { listen: vi.fn(async () => ({ addresses: ["127.0.0.1"], port: 47200 })), accepted: vi.fn(async () => stream), close: vi.fn() };
  const constructors = { dial: vi.fn(() => dialer), listen: vi.fn(() => listener) };
  const fallbackSocket: DropSocket = { closed: false, next: async () => Buffer.from("TEST"), send: async () => {}, startKeepalive: () => {}, watchIdle: () => {}, onClose: () => {}, close: vi.fn(), closeGracefully: () => {} };
  const fallbackListener: LanAcceptor = { addresses: ["127.0.0.1"], port: 47200, accepted: async () => fallbackSocket, close: vi.fn() };
  const typescript = { open: vi.fn(async () => fallbackListener), dial: vi.fn(async () => fallbackSocket) };
  const report = vi.fn();
  const attempt = dropLanWithCore(core, constructors, report, typescript, () => ["127.0.0.1"]);
  if (attempt) attempts.push(attempt);
  return { core, diagnostics, constructors, stream, dialer, listener, typescript, report, attempt, fallbackSocket };
}
describe("native LAN attempt ownership", () => {
  it.each(["ts", "shadow"] as const)("creates no native operation in %s", (mode) => {
    const c = configured(mode); expect(c.attempt).toBeNull(); expect(c.constructors.dial).not.toHaveBeenCalled(); expect(c.constructors.listen).not.toHaveBeenCalled();
  });
  it("keeps older modules on the existing path", () => { const c = configured(); expect(dropLanWithCore(c.core, undefined, c.report)).toBeNull(); });
  it("construction and close before use never bind or dial", () => {
    const c = configured(); c.attempt!.close(); c.attempt!.close(); expect(c.constructors.dial).not.toHaveBeenCalled(); expect(c.constructors.listen).not.toHaveBeenCalled();
  });
  it("falls back before native I/O when the lazy constructor refuses input", async () => {
    const c = configured(); c.constructors.dial.mockImplementation(() => { throw new Error("PRIVATE_TEST_KEY"); });
    expect(await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key)).toBe(c.fallbackSocket);
    expect(c.typescript.dial).toHaveBeenCalledOnce(); expect(c.dialer.read).not.toHaveBeenCalled(); expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_KEY");
  });
  it("never replays a native dial failure through Node", async () => {
    const c = configured(); c.dialer.read = vi.fn(async () => { throw new Error("PRIVATE_TEST_KEY"); });
    expect(await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key)).toBeNull();
    expect(c.typescript.dial).not.toHaveBeenCalled(); expect(c.dialer.close).toHaveBeenCalledOnce();
  });
  it("never rebinds through Node after native listen starts", async () => {
    const c = configured(); c.listener.listen = vi.fn(async () => { throw new Error("PRIVATE_TEST_KEY"); });
    expect(await c.attempt!.open(transfer, key)).toBeNull(); expect(c.typescript.open).not.toHaveBeenCalled(); expect(c.listener.close).toHaveBeenCalledOnce();
  });
  it("a native unavailable result does not activate the other implementation", async () => {
    const c = configured(); c.dialer.read = vi.fn(async () => null);
    expect(await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key)).toBeNull(); expect(c.typescript.dial).not.toHaveBeenCalled();
  });
  it("retires a late dial after abort without delivering its connection", async () => {
    const c = configured(); let ready: (socket: NativeDropConnection) => void = () => {};
    c.dialer.read = vi.fn(() => new Promise<NativeDropConnection>((done) => { ready = done; }));
    const pending = c.attempt!.dial(["127.0.0.1"], 47200, transfer, key); c.attempt!.close(); ready(c.stream);
    expect(await pending).toBeNull(); expect(c.stream.close).toHaveBeenCalledOnce(); expect(c.dialer.close).toHaveBeenCalledOnce(); expect(c.typescript.dial).not.toHaveBeenCalled();
  });
  it("a late listener result cannot survive attempt close", async () => {
    const c = configured(); let ready = () => {};
    c.listener.listen = vi.fn(() => new Promise<{ addresses: string[]; port: number }>((done) => { ready = () => done({ addresses: ["127.0.0.1"], port: 47200 }); }));
    const pending = c.attempt!.open(transfer, key); c.attempt!.close(); ready(); expect(await pending).toBeNull(); expect(c.listener.close).toHaveBeenCalledOnce();
  });
  it("closing the acceptor retires a late proof without closing unrelated state", async () => {
    const c = configured(); let ready: (socket: NativeDropConnection) => void = () => {};
    c.listener.accepted = vi.fn(() => new Promise<NativeDropConnection>((done) => { ready = done; }));
    const acceptor = await c.attempt!.open(transfer, key); expect(acceptor).not.toBeNull();
    const pending = acceptor!.accepted(); acceptor!.close(); ready(c.stream);
    expect(await pending).toBeNull(); expect(c.stream.close).toHaveBeenCalledOnce(); expect(c.listener.close).toHaveBeenCalledOnce();
  });
  it("discovery close leaves an adopted stream's final write intact across mode changes", async () => {
    const c = configured(); const socket = await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key); expect(socket).not.toBeNull(); sockets.push(socket!);
    c.core.setMode("ts"); c.attempt!.close(); await socket!.send(Buffer.from("TEST final")); socket!.closeGracefully();
    expect(c.stream.send).toHaveBeenCalledOnce(); expect(c.stream.closeGracefully).toHaveBeenCalledOnce(); expect(c.stream.close).not.toHaveBeenCalled(); expect(c.dialer.close).toHaveBeenCalledOnce();
  });
  it.each([
    { addresses: ["8.8.8.8"], port: 47200 }, { addresses: ["127.0.0.1"], port: 0.5 }, { addresses: [], port: 47200 },
  ])("refuses a foreign native listener address: %j", async (info) => {
    const c = configured(); c.listener.listen = vi.fn(async () => info);
    expect(await c.attempt!.open(transfer, key)).toBeNull(); expect(c.listener.close).toHaveBeenCalledOnce(); expect(c.typescript.open).not.toHaveBeenCalled();
  });
  it("closes an invalid stream ABI result instead of leaking its active transport", async () => {
    const c = configured(); const close = vi.fn(); Object.defineProperty(c.dialer, "read", { value: async () => ({ close }) });
    expect(await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key)).toBeNull(); expect(close).toHaveBeenCalledOnce(); expect(c.typescript.dial).not.toHaveBeenCalled();
  });
  it("contains a cleanup exception and records no key or address", async () => {
    const c = configured(); c.dialer.read = vi.fn(async () => null); c.dialer.close = vi.fn(() => { throw new Error("PRIVATE_TEST_KEY"); });
    expect(await c.attempt!.dial(["127.0.0.1"], 47200, transfer, key)).toBeNull(); expect(c.report).toHaveBeenCalledWith(); expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_KEY");
  });
});
