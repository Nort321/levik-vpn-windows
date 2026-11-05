import { afterEach, describe, expect, it, vi } from "vitest";
import { EventStreamParser, IDLE_TIMEOUT_MS, LiveEvents, presenceReport, samePresence } from "../src/main/platform/liveEvents";
import type { LiveEvent } from "../src/main/platform/liveEvents";
import type { TunnelServer } from "../src/shared/contracts";

afterEach(() => {
  vi.useRealTimers();
});

describe("event stream parser", () => {
  it("emits known events across chunk boundaries and line endings", () => {
    const parser = new EventStreamParser();
    expect(parser.push("retry: 5000\nevent: rea")).toEqual([]);
    expect(parser.push("dy\ndata: {}\n\n: ping\n\nevent: settings\r\ndata: {}\r\n\r\n")).toEqual(["ready", "settings"]);
    expect(parser.push("event: wipe\ndata: {}\n\n")).toEqual([]);
    expect(parser.push("event: rules\ndata: {}\n\n")).toEqual(["rules"]);
    expect(parser.push("data: {}\n\n")).toEqual([]);
  });

  it("rejects an endless line", () => {
    expect(() => new EventStreamParser().push("x".repeat(5_000))).toThrow("too long");
  });
});

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

describe("live events", () => {
  it("delivers events and reconnects after the stream ends", async () => {
    vi.useFakeTimers();
    const open = vi.fn()
      .mockResolvedValueOnce(streamOf("event: ready\ndata: {}\n\n", "event: config\ndata: {}\n\n"))
      .mockResolvedValueOnce(streamOf("event: ready\ndata: {}\n\n"))
      .mockImplementation(() => new Promise(() => {}));
    const live = new LiveEvents(open, () => false, () => 0);
    const events: LiveEvent[] = [];
    live.on("event", (event) => events.push(event));
    live.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(events).toEqual(["ready", "config"]);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(events).toEqual(["ready", "config", "ready"]);
    expect(open).toHaveBeenCalledTimes(2);
    live.stop();
  });

  it("backs off while the server is unreachable", async () => {
    vi.useFakeTimers();
    const open = vi.fn().mockRejectedValue(new Error("offline"));
    const live = new LiveEvents(open, () => false, () => 0);
    live.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(open).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(open).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(14_999);
    expect(open).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(open).toHaveBeenCalledTimes(3);
    live.stop();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(open).toHaveBeenCalledTimes(3);
  });

  it("stops and reports a rejected session", async () => {
    const rejected = new Error("401");
    const live = new LiveEvents(vi.fn().mockRejectedValue(rejected), (error) => error === rejected);
    const unauthorized = vi.fn();
    live.on("unauthorized", unauthorized);
    live.start();
    await vi.waitFor(() => expect(unauthorized).toHaveBeenCalledOnce());
    expect(live.active).toBe(false);
  });

  it("drops a silent connection", async () => {
    vi.useFakeTimers();
    let aborted = false;
    const open = vi.fn((signal: AbortSignal) => Promise.resolve(new ReadableStream<Uint8Array>({
      start(controller) {
        signal.addEventListener("abort", () => {
          aborted = true;
          controller.error(new Error("aborted"));
        });
      },
    })));
    const live = new LiveEvents(open, () => false, () => 0);
    live.start();
    await vi.advanceTimersByTimeAsync(IDLE_TIMEOUT_MS);
    expect(aborted).toBe(true);
    live.stop();
  });
});

describe("presence report", () => {
  const server: TunnelServer = {
    id: "a".repeat(64), tag: "proxy", name: "Германия", countryCode: "de",
    outbound: { protocol: "vless", settings: { vnext: [{ address: "de1.example.org", port: 443 }] } },
  };

  it("names the country and node only while connected", () => {
    const connected = presenceReport("connected", server);
    expect(connected.vpnConnected).toBe(true);
    expect(connected.country).toBe("DE");
    expect(connected.nodeId).toMatch(/^n1[0-9a-f]{20}$/);
    expect(presenceReport("connecting", server)).toEqual({ vpnConnected: false, nodeId: null, country: null });
    expect(presenceReport("connected", null)).toEqual({ vpnConnected: false, nodeId: null, country: null });
  });

  it("compares reports field by field", () => {
    const off = presenceReport("disconnected", null);
    expect(samePresence(null, off)).toBe(false);
    expect(samePresence(off, { ...off })).toBe(true);
    expect(samePresence(off, presenceReport("connected", server))).toBe(false);
  });
});
