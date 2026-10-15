import { afterEach, expect, it, vi } from "vitest";

vi.mock("node:perf_hooks", () => ({ performance: { now: () => Date.now() } }));

const network = vi.hoisted(() => ({ routes: new Map<number, { instance: number; latency: number; down: boolean; opens: number }>() }));
vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { decode, encode, Kind } = await import("../../src/main/vpn/multipath/wire.js");
  return { openRelayPath: async (port: number, _password: string, receive: (packet: Buffer) => void) => {
    const route = network.routes.get(port)!; route.opens++;
    let closed = false;
    return { get closed() { return closed; }, close: () => { closed = true; }, send: (data: Buffer) => {
      const packet = decode(data); if (closed || route.down || !packet || packet.kind !== Kind.Ping) return;
      setTimeout(() => { if (!closed && !route.down) receive(encode({ ...packet, kind: Kind.Pong, payload: Buffer.alloc(16, route.instance) })); }, route.latency);
    } };
  } };
});
import { GameMultipath } from "../../src/main/vpn/multipath/client";

afterEach(() => { network.routes.clear(); vi.useRealTimers(); });
function routes(values: Array<{ instance: number; latency: number }>) {
  return values.map((route, index) => {
    network.routes.set(index + 1, { ...route, down: false, opens: 0 });
    return { index, port: index + 1 };
  });
}

it("probes all compatible routes and admits more than two without mixing exit relays", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath();
  try {
    const pending = client.connect(routes([{ instance: 1, latency: 20 }, { instance: 1, latency: 22 },
      { instance: 1, latency: 24 }, { instance: 1, latency: 70 }, { instance: 2, latency: 120 }]), "test");
    await vi.advanceTimersByTimeAsync(2200); await pending;
    const state = client.snapshot();
    expect(state.state).toBe("protected");
    expect(state.paths.filter((path) => path.active).map((path) => path.routeIndex)).toEqual([0, 1, 2]);
    expect(state.paths[3]).toMatchObject({ responding: true, active: false });
    expect(state.paths[4]).toMatchObject({ responding: false, active: false });
  } finally { await client.stop(); }
});

it("keeps a single working relay usable and repairs a previously working path", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath();
  try {
    const pending = client.connect(routes([{ instance: 1, latency: 20 }, { instance: 1, latency: 22 }]), "test");
    await vi.advanceTimersByTimeAsync(2200); await pending;
    network.routes.get(1)!.down = true;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(client.snapshot().state).toBe("single");
    expect(network.routes.get(1)!.opens).toBeGreaterThan(1);
    network.routes.get(1)!.down = false;
    await vi.advanceTimersByTimeAsync(4500);
    expect(client.snapshot().state).toBe("protected");
  } finally { await client.stop(); }
});
