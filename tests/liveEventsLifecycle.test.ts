import { afterEach, describe, expect, it, vi } from "vitest";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { LiveEvents, retryPlan, type EventSourceStream, type LiveEvent } from "../src/main/platform/liveEvents";

afterEach(() => vi.useRealTimers());
function deferred<T>() {
  let resolve!: (value: T) => void; let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function stream(...events: LiveEvent[]): EventSourceStream {
  return new ReadableStream<LiveEvent[]>({ start(controller) { controller.enqueue(events); controller.close(); } });
}

describe("event stream ownership", () => {
  it.each([false, true])("ignores an old stream completed after stop/start (unauthorized: %s)", async (unauthorized) => {
    vi.useFakeTimers();
    const old = deferred<EventSourceStream>(); const rejected = new Error("TEST rejected old session");
    const open = vi.fn().mockReturnValueOnce(old.promise).mockResolvedValueOnce(stream("ready"));
    const live = new LiveEvents(open, (error) => error === rejected, () => 0);
    const received: LiveEvent[] = []; const denied = vi.fn();
    live.on("event", (event) => received.push(event)); live.on("unauthorized", denied);
    live.start(); live.stop(); live.start(); await vi.advanceTimersByTimeAsync(0);
    if (unauthorized) old.reject(rejected); else old.resolve(stream("config"));
    await vi.advanceTimersByTimeAsync(0);
    expect(received).toEqual(["ready"]); expect(denied).not.toHaveBeenCalled(); expect(live.active).toBe(true);
    live.stop();
  });

  it("stops delivery within a batch when the listener ends the session", async () => {
    vi.useFakeTimers(); const live = new LiveEvents(async () => stream("ready", "config"), () => false, () => 0);
    const received: LiveEvent[] = [];
    live.on("event", (event) => { received.push(event); live.stop(); });
    live.start(); await vi.advanceTimersByTimeAsync(0);
    expect(received).toEqual(["ready"]); expect(live.active).toBe(false);
  });

  it("reconnects immediately on a network change and never schedules the cancelled loop", async () => {
    vi.useFakeTimers();
    const open = vi.fn(async (signal: AbortSignal): Promise<EventSourceStream> => new ReadableStream<LiveEvent[]>({
      start(controller) { signal.addEventListener("abort", () => controller.error(new Error("TEST cancelled")), { once: true }); },
    }));
    const live = new LiveEvents(open, () => false, () => 0); live.start(); await vi.advanceTimersByTimeAsync(0);
    live.reconnectNow(); await vi.advanceTimersByTimeAsync(0); expect(open).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(60_000); expect(open).toHaveBeenCalledTimes(2);
    live.stop(); await vi.advanceTimersByTimeAsync(120_000); expect(open).toHaveBeenCalledTimes(2);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("Rust event reconnect decisions", () => {
  it("matches every retry tier and jitter sample through the production bridge", () => {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath); if (status.state !== "loaded") throw new Error("Module unavailable");
    const core = new RustCore(status.module, () => {}, "rust");
    for (const failures of [0, 1, 2, 3, 4, 100, Number.MAX_SAFE_INTEGER]) {
      for (const received of [false, true]) for (const random of [0, 0.1, 0.5, 0.9999999999999999]) {
        const expected = retryPlan(failures, received, random);
        const actual = core.run("liveEvents.retryPlan", { failures, received, random },
          () => { throw new Error("Rust retry decision unavailable"); }, (value): value is typeof expected =>
            typeof value === "object" && value !== null && "delay" in value && "failures" in value);
        expect(actual).toEqual(expected);
      }
    }
    expect(core.stats().failed).toBe(0); expect(core.stats().decided).toBe(56);
  });
});
