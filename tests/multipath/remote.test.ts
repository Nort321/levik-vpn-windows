import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GameMultipath } from "../../src/main/vpn/multipath/client";
import type { DataPlaneEvent, DataPlaneRequest } from "../../src/main/vpn/multipath/dataPlane";
import { RemoteGameDataPlane } from "../../src/main/vpn/multipath/remote";

/** Stand-in utility process: answers the data-plane protocol like worker.ts. */
class FakeChild extends EventEmitter {
  pid = 4242;
  readonly received: DataPlaneRequest[] = [];
  killed = false;
  constructor(private readonly behaviour: { silent?: boolean; movedPort?: boolean }) {
    super();
    setImmediate(() => { this.emit("spawn"); if (!behaviour.silent) { this.send({ type: "ready" }); this.send(state(true)); } });
  }
  send(event: DataPlaneEvent): void { this.emit("message", event); }
  postMessage(message: DataPlaneRequest): void {
    this.received.push(message);
    if (message.type !== "call") return;
    const requested = message.method === "listen" ? message.args[0] : undefined;
    const value = message.method === "listen" ? requested && this.behaviour.movedPort ? { ...requested, port: requested.port + 1 }
      : (requested ?? { port: 41000, uuid: "00000000-0000-4000-8000-000000000001" }) : null;
    setImmediate(() => this.send({ type: "result", id: message.id, ok: true, value }));
  }
  kill(): boolean { this.killed = true; setImmediate(() => this.emit("exit", 0)); return true; }
  crash(): void { this.emit("exit", 1); }
}

const children: FakeChild[] = [];
let movedPort = false;
const fork = vi.fn((_path: string, _args: string[], _options: unknown) => {
  const child = new FakeChild({ silent: fork.mock.calls.length > 99, movedPort: movedPort && fork.mock.calls.length > 1 });
  children.push(child); return child;
});
vi.mock("electron", () => ({ utilityProcess: { fork: (...args: [string, string[], unknown]) => fork(...args) } }));

function state(idle: boolean): DataPlaneEvent {
  return { type: "state", idle, qualities: {}, runtime: { routes: [] } as never, snapshot: { state: "ready" } as never };
}

function child(index: number): FakeChild {
  const found = children[index];
  if (!found) throw new Error(`no child ${index}`);
  return found;
}

afterEach(() => { children.length = 0; fork.mockClear(); movedPort = false; });

describe("RemoteGameDataPlane", () => {
  it("serves calls, keeps the measure callback in main and restores the same loopback after a crash", async () => {
    const logs: string[] = [];
    const plane = await RemoteGameDataPlane.create((line) => logs.push(line));
    expect(plane).toBeInstanceOf(RemoteGameDataPlane);
    const identity = await plane.listen();
    const measureDirect = vi.fn(async () => [{ index: 0, rttMs: 12 }] as never);
    await plane.connect([{ index: 0, port: 1080, reliable: true }], "secret", { measureDirect, protection: "balanced" } as never);
    const connect = child(0).received.find((message) => message.type === "call" && message.method === "connect");
    expect(connect).toMatchObject({ args: [[{ index: 0, port: 1080, reliable: true }], "secret", { measureDirect: true, protection: "balanced" }] });

    child(0).send({ type: "measure", id: 7, targets: [] });
    await vi.waitFor(() => expect(child(0).received).toContainEqual({ type: "measured", id: 7, results: [{ index: 0, rttMs: 12 }] }));

    plane.setPlaying(true); plane.setPrimaryRoute(1);
    expect(plane.pauseNewFlowsIfIdle()).toBe(true);
    child(0).send(state(false));
    expect(plane.pauseNewFlowsIfIdle()).toBe(false);

    child(0).crash();
    await vi.waitFor(() => expect(children[1]?.received.some((message) => message.type === "call" && message.method === "connect")).toBe(true));
    const replay = child(1).received;
    expect(replay[0]).toMatchObject({ type: "call", method: "listen", args: [identity] });
    expect(replay).toContainEqual({ type: "notify", method: "setPlaying", args: [true] });
    expect(replay).toContainEqual({ type: "notify", method: "setPrimaryRoute", args: [1] });
    expect(logs.some((line) => line.includes("перезапущен"))).toBe(true);

    await plane.stop();
    expect(child(1).killed).toBe(true);
    await new Promise((resolve) => setImmediate(resolve));
    expect(children).toHaveLength(2);
  });

  it("stops restarting after repeated crashes and hands the game to its owner", async () => {
    const logs: string[] = []; const down = vi.fn();
    const plane = await RemoteGameDataPlane.create((line) => logs.push(line), down);
    await plane.listen();
    for (let crash = 0; crash < 4; crash += 1) {
      const current = child(children.length - 1);
      current.crash();
      if (crash < 3) await vi.waitFor(() => expect(children.at(-1)).not.toBe(current));
    }
    await new Promise((resolve) => setImmediate(resolve));
    expect(children).toHaveLength(4);
    expect(logs.at(-1)).toContain("завершился");
    expect(down).toHaveBeenCalledTimes(1);
    // No stale paths or flows, and reads never throw in main.
    expect(plane.snapshot()).toMatchObject({ state: "unavailable", paths: [] });
    expect(plane.runtimeSnapshot()).toMatchObject({ currentMatch: null, exits: [] });
    expect(plane.routeQualities()).toEqual({});
  });

  it("gives up when a restarted data plane cannot take the port Xray sends to", async () => {
    movedPort = true;
    const logs: string[] = []; const down = vi.fn();
    const plane = await RemoteGameDataPlane.create((line) => logs.push(line), down);
    await plane.listen();
    child(0).crash();
    await vi.waitFor(() => expect(down).toHaveBeenCalledTimes(1));
    expect(logs.at(-1)).toContain("не удалось перезапустить");
    expect(plane.snapshot().state).toBe("unavailable");
  });

  it("keeps the last state readable while a crashed data plane restarts", async () => {
    const plane = await RemoteGameDataPlane.create(() => {});
    await plane.listen();
    child(0).crash();
    expect(() => plane.snapshot()).not.toThrow();
    expect(plane.snapshot().state).toBe("ready");
    await vi.waitFor(() => expect(children).toHaveLength(2));
    await plane.stop();
  });

  it("falls back to the in-process data plane when the utility process cannot start", async () => {
    fork.mockImplementationOnce(() => { throw new Error("no utility process"); });
    const logs: string[] = [];
    const plane = await RemoteGameDataPlane.create((line) => logs.push(line));
    expect(plane).toBeInstanceOf(GameMultipath);
    expect(logs[0]).toContain("основном процессе");
    await plane.stop();
  });
});
