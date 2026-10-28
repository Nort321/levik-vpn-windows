import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LIVE_AUTO_LIMITS, SmartAutoLiveRuntime, type LiveAutoCandidate, type LiveAutoControl, type LiveAutoDependencies } from "../src/main/vpn/smartAutoLiveRuntime";
import type { RouteMeasurement } from "../src/main/vpn/routeProbe";

type BodyMeasurement = RouteMeasurement & { dataVerified?: boolean };

const owned: SmartAutoLiveRuntime[] = [];
beforeEach(() => vi.useFakeTimers());
afterEach(() => { owned.splice(0).forEach((runtime) => runtime.stop()); vi.useRealTimers(); });

function measured(now: number, medianMs: number, extra: Partial<BodyMeasurement> = {}): BodyMeasurement {
  return { measuredAt: now, confidence: "measured", medianMs, jitterMs: 0, failureRate: 0,
    samples: 6, targets: 2, setupMs: 10, downMbps: null, upMbps: null, dataVerified: true, ...extra };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function harness(ids = ["a", "b", "c"]) {
  const candidates: LiveAutoCandidate[] = ids.map((id, index) => ({ id, tag: `live-${id}`, port: 21000 + index, routeKey: `route-${id}` }));
  const env = { now: 1_000_000, network: "wifi-a", idle: false, installed: "a",
    latencies: { a: 100, b: 60, c: 90 } as Record<string, number>,
    overrides: {} as Record<string, Partial<BodyMeasurement>>,
    controls: Object.fromEntries(ids.map((id) => [id, { eligible: true, state: "healthy", resourceHeadroom: 0.5 }])) as Record<string, LiveAutoControl>,
  };
  const observe = vi.fn<LiveAutoDependencies["observe"]>(async (batch) => Object.fromEntries(batch.map((candidate) =>
    [candidate.id, measured(env.now, env.latencies[candidate.id] ?? 100, env.overrides[candidate.id])])));
  const override = vi.fn<LiveAutoDependencies["override"]>().mockResolvedValue(undefined);
  const report = vi.fn<LiveAutoDependencies["report"]>();
  const canSwitch = vi.fn<LiveAutoDependencies["canSwitch"]>().mockResolvedValue(true);
  const deps: LiveAutoDependencies = { observe, override, report, canSwitch,
    controls: () => env.controls, canTransfer: () => env.idle, networkKey: () => env.network, clock: () => env.now };
  const runtime = new SmartAutoLiveRuntime(candidates, "a", deps); owned.push(runtime);
  const next = async (milliseconds = 30_000) => { env.now += milliseconds; await runtime.refresh(); };
  return { runtime, env, observe, override, report, canSwitch, deps, candidates, next };
}

describe("live Smart Auto decisions", () => {
  it("requires two fresh confirmations, then continues the same loop after switching", async () => {
    const h = harness();
    h.runtime.start(); await h.runtime.refresh();
    expect(h.override).not.toHaveBeenCalled();
    h.env.now += 30_000; await vi.advanceTimersByTimeAsync(30_000);
    expect(h.override).toHaveBeenCalledWith("live-b");
    expect(h.runtime.currentId).toBe("b");
    h.env.now += 30_000; await vi.advanceTimersByTimeAsync(30_000);
    expect(h.observe).toHaveBeenCalledTimes(3);
    expect(h.observe.mock.calls[2]?.[0][0]?.id).toBe("b");
    expect(h.report.mock.calls.at(-1)?.[0]).toMatchObject({ currentId: "b", switched: false });
  });

  it("covers current plus two rotating alternatives and keeps a pending challenger in the next batch", async () => {
    const h = harness(["a", "b", "c", "d", "e"]);
    h.env.latencies = { a: 100, b: 100, c: 100, d: 100, e: 100 };
    await h.runtime.refresh(); await h.next();
    expect(h.observe.mock.calls.map(([batch]) => batch.map(({ id }) => id))).toEqual([["a", "b", "c"], ["a", "d", "e"]]);
    h.env.latencies.b = 50;
    await h.next(); await h.next();
    expect(h.observe.mock.calls[3]?.[0].map(({ id }) => id)).toContain("b");
    expect(h.observe.mock.calls.every(([batch]) => batch.length <= 3)).toBe(true);
    expect(h.runtime.currentId).toBe("b");
  });

  it("keeps an incumbent for near-equal performance or less than ten milliseconds gain", async () => {
    for (const [current, challenger] of [[100, 85], [40, 31], [100, 81]]) {
      const h = harness(["a", "b"]);
      h.env.latencies = { a: current!, b: challenger! };
      await h.runtime.refresh(); await h.next();
      expect(h.override).not.toHaveBeenCalled();
    }
  });

  it("ignores unknown current quality, stale challengers and partial one-provider evidence", async () => {
    for (const extra of [{ confidence: "partial" as const, targets: 1, samples: 1 }, { targets: 1 }, { measuredAt: 0 }, { dataVerified: false }]) {
      const h = harness(["a", "b"]);
      h.env.overrides.b = extra;
      await h.runtime.refresh(); await h.next();
      expect(h.override).not.toHaveBeenCalled();
    }
    const h = harness(["a", "b"]);
    h.env.overrides.a = { confidence: "partial", targets: 1 };
    await h.runtime.refresh(); await h.next();
    expect(h.override).not.toHaveBeenCalled();
  });

  it("enforces the soft cooldown but bypasses it after two known body failures", async () => {
    const h = harness();
    await h.runtime.refresh(); await h.next();
    h.env.latencies.c = 20;
    await h.next(); await h.next();
    expect(h.override).toHaveBeenCalledTimes(1);
    h.env.overrides.b = { dataVerified: false };
    await h.next();
    expect(h.override).toHaveBeenCalledTimes(1);
    await h.next();
    expect(h.override).toHaveBeenLastCalledWith("live-c");
    expect(h.runtime.currentId).toBe("c");
  });

  it("allows a soft improvement again after the cooldown expires", async () => {
    const h = harness();
    await h.runtime.refresh(); await h.next();
    h.env.latencies.c = 20;
    await h.next(); await h.next();
    expect(h.override).toHaveBeenCalledTimes(1);
    await h.next(LIVE_AUTO_LIMITS.cooldownMs);
    expect(h.runtime.currentId).toBe("c");
  });

  it("uses two explicit full or ineligible rounds, not diagnostic pressure alone", async () => {
    for (const control of [{ eligible: true, state: "overloaded" as const }, { eligible: false, state: "healthy" as const }]) {
      const h = harness(["a", "b"]);
      h.env.latencies.b = 150;
      h.env.controls.a = { ...control, resourceHeadroom: null };
      await h.runtime.refresh(); expect(h.override).not.toHaveBeenCalled();
      await h.next(); expect(h.runtime.currentId).toBe("b");
    }
    const h = harness(["a", "b"]);
    h.env.latencies.b = 150;
    h.env.controls.a = { eligible: true, state: "degraded", resourceHeadroom: null };
    await h.runtime.refresh(); await h.next();
    expect(h.override).not.toHaveBeenCalled();
  });

  it("uses balanced throughput only with a bounded delay increase and caches speed separately", async () => {
    const h = harness(["a", "b"]);
    h.env.idle = true; h.env.latencies.b = 115;
    h.env.overrides = { a: { downMbps: 100, upMbps: 100 }, b: { downMbps: 130, upMbps: 130 } };
    await h.runtime.refresh();
    h.env.overrides = {}; h.env.idle = false;
    await h.next();
    expect(h.runtime.currentId).toBe("b");
    expect(h.observe.mock.calls.map(([, transfers]) => transfers)).toEqual([true, false]);
    expect(h.report.mock.calls.at(-1)?.[0].measurements.a?.downMbps).toBe(100);
    await h.next(LIVE_AUTO_LIMITS.bandwidthTtlMs);
    expect(h.report.mock.calls.at(-1)?.[0].measurements.a?.downMbps).toBeNull();
    const slow = harness(["a", "b"]);
    slow.env.idle = true; slow.env.latencies.b = 130;
    slow.env.overrides = { a: { downMbps: 100, upMbps: 100 }, b: { downMbps: 200, upMbps: 200 } };
    await slow.runtime.refresh(); await slow.next();
    expect(slow.override).not.toHaveBeenCalled();
  });

  it("improves balanced goodput when a much faster bottleneck offsets a small other-direction decrease", async () => {
    const h = harness(["a", "b"]);
    h.env.idle = true; h.env.latencies = { a: 100, b: 100 };
    h.env.overrides = { a: { downMbps: 10, upMbps: 100 }, b: { downMbps: 100, upMbps: 90 } };
    await h.runtime.refresh(); await h.next();
    expect(h.override).toHaveBeenCalledWith("live-b");
    const imbalance = harness(["a", "b"]);
    imbalance.env.idle = true; imbalance.env.latencies = { a: 100, b: 100 };
    imbalance.env.overrides = { a: { downMbps: 1, upMbps: 1000 }, b: { downMbps: 1000, upMbps: 1 } };
    await imbalance.runtime.refresh(); await imbalance.next();
    expect(imbalance.override).not.toHaveBeenCalled();
  });

  it("never repeats transfer attempts within five minutes and never starts them while busy", async () => {
    const h = harness(["a", "b"]);
    await h.runtime.refresh(); h.env.idle = true;
    await h.next(); await h.next(); await h.next();
    expect(h.observe.mock.calls.map(([, transfers]) => transfers)).toEqual([false, true, false, false]);
    await h.next(LIVE_AUTO_LIMITS.bandwidthTtlMs);
    expect(h.observe.mock.calls.at(-1)?.[1]).toBe(true);
  });

  it("coalesces concurrent refreshes and ignores cancelled or late observations", async () => {
    const h = harness(), observation = deferred<Record<string, RouteMeasurement>>();
    h.observe.mockReturnValueOnce(observation.promise);
    const first = h.runtime.refresh(), second = h.runtime.refresh();
    expect(second).toBe(first);
    await vi.waitFor(() => expect(h.observe).toHaveBeenCalledTimes(1));
    const signal = h.observe.mock.calls[0]![2];
    h.runtime.stop(); await first;
    expect(signal.aborted).toBe(true);
    observation.resolve({ a: measured(h.env.now, 100), b: measured(h.env.now, 1) });
    await Promise.resolve();
    expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
  });

  it("bounds a non-cooperative observer and keeps the loop usable", async () => {
    const h = harness();
    h.observe.mockReturnValueOnce(new Promise(() => {}));
    const first = h.runtime.refresh();
    await vi.advanceTimersByTimeAsync(LIVE_AUTO_LIMITS.observationMs);
    await first;
    expect(h.observe.mock.calls[0]?.[2].aborted).toBe(true);
    await h.next(); expect(h.observe).toHaveBeenCalledTimes(2);
    expect(h.override).not.toHaveBeenCalled();
  });

  it("discards an in-flight network result and clears challenger confirmation on the next network", async () => {
    const h = harness();
    await h.runtime.refresh();
    const observation = deferred<Record<string, RouteMeasurement>>();
    h.observe.mockReturnValueOnce(observation.promise);
    const old = h.runtime.refresh();
    await vi.waitFor(() => expect(h.observe).toHaveBeenCalledTimes(2));
    h.env.network = "wifi-b";
    observation.resolve({ a: measured(h.env.now, 100), b: measured(h.env.now, 1) });
    await old;
    await h.next(); expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("keeps the confirmed target on API failure and does not publish a successful switch", async () => {
    const h = harness(); h.override.mockRejectedValueOnce(new Error("No API"));
    await h.runtime.refresh(); await h.next();
    expect(h.runtime.currentId).toBe("a");
    expect(h.report.mock.calls.every(([update]) => !update.switched && update.currentId === "a")).toBe(true);
    await h.next(); expect(h.override).toHaveBeenCalledTimes(1);
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("publishes the installed route only after the serialized API acknowledges it", async () => {
    const h = harness(), ack = deferred<void>();
    await h.runtime.refresh(); h.override.mockReturnValueOnce(ack.promise);
    const switching = h.next();
    await vi.waitFor(() => expect(h.override).toHaveBeenCalledTimes(1));
    expect(h.runtime.currentId).toBe("a");
    expect(h.report.mock.calls.every(([update]) => !update.switched)).toBe(true);
    ack.resolve(); await switching;
    expect(h.report.mock.calls.at(-1)?.[0]).toMatchObject({ currentId: "b", switched: true });
  });

  it("drops stale API publication and reconciles the separately acknowledged installed target", async () => {
    const h = harness(), ack = deferred<void>();
    h.deps.installedCurrent = () => h.env.installed;
    h.override.mockReturnValueOnce(ack.promise);
    await h.runtime.refresh();
    const switching = h.next();
    await vi.waitFor(() => expect(h.override).toHaveBeenCalledTimes(1));
    h.runtime.setSuspended(true); h.env.installed = "b"; ack.resolve(); await switching;
    expect(h.runtime.currentId).toBe("a");
    expect(h.report.mock.calls.every(([update]) => !update.switched)).toBe(true);
    h.runtime.setSuspended(false); await h.next();
    expect(h.runtime.currentId).toBe("b"); expect(h.override).toHaveBeenCalledTimes(1);
  });

  it("freezes even emergency switches during activity and requires two new quiet confirmations", async () => {
    const h = harness();
    h.env.overrides.a = { confidence: "failed", medianMs: null, jitterMs: null, failureRate: 1, samples: 0, targets: 0 };
    h.canSwitch.mockResolvedValue(false);
    await h.runtime.refresh(); await h.next();
    expect(h.override).not.toHaveBeenCalled();
    h.canSwitch.mockResolvedValue(true);
    await h.next(); expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("checks activity right before commit and treats missing activity stats as protected", async () => {
    const h = harness(), activity = deferred<boolean>();
    await h.runtime.refresh(); h.canSwitch.mockReturnValueOnce(activity.promise);
    const switching = h.next();
    await vi.waitFor(() => expect(h.canSwitch).toHaveBeenCalledTimes(1));
    activity.resolve(false); await switching;
    expect(h.override).not.toHaveBeenCalled();
    h.canSwitch.mockRejectedValueOnce(new Error("Stats unavailable"));
    await h.next(); await h.next();
    expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("bounds a stuck activity reader and revalidates candidate eligibility after the fresh check", async () => {
    const h = harness();
    await h.runtime.refresh();
    h.canSwitch.mockReturnValueOnce(new Promise(() => {}));
    const blocked = h.next();
    await vi.waitFor(() => expect(h.canSwitch).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(LIVE_AUTO_LIMITS.switchGuardMs); await blocked;
    expect(h.override).not.toHaveBeenCalled();
    await h.next();
    const guard = deferred<boolean>(); h.canSwitch.mockReturnValueOnce(guard.promise);
    const changed = h.next();
    await vi.waitFor(() => expect(h.canSwitch).toHaveBeenCalledTimes(2));
    h.env.controls.b = { eligible: false, state: "healthy", resourceHeadroom: 0.5 };
    guard.resolve(true); await changed;
    expect(h.override).not.toHaveBeenCalled();
  });

  it("invalidates path-specific bandwidth and pending confirmation when a known route changes", async () => {
    const h = harness(["a", "b"]);
    h.env.controls.a!.routeId = "path-a"; h.env.controls.b!.routeId = "path-b";
    h.env.idle = true; h.env.latencies.b = 100;
    h.env.overrides = { a: { downMbps: 100, upMbps: 100 }, b: { downMbps: 150, upMbps: 150 } };
    await h.runtime.refresh();
    h.env.idle = false; h.env.overrides = {}; h.env.controls.b!.routeId = "path-b-new";
    await h.next();
    expect(h.override).not.toHaveBeenCalled();
    expect(h.report.mock.calls.at(-1)?.[0].measurements.b?.downMbps).toBeNull();
    h.env.latencies.b = 50;
    await h.next(); expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("retains known topology during missing metadata and invalidates unknown-to-known paths", async () => {
    const known = harness(["a", "b"]);
    known.env.controls.b!.routeId = "path-b";
    await known.runtime.refresh();
    delete known.env.controls.b!.routeId;
    await known.next(); expect(known.runtime.currentId).toBe("b");
    const discovered = harness(["a", "b"]);
    await discovered.runtime.refresh();
    discovered.env.controls.b!.routeId = "path-b";
    await discovered.next(); expect(discovered.override).not.toHaveBeenCalled();
    await discovered.next(); expect(discovered.runtime.currentId).toBe("b");
  });

  it("discards an in-flight result when the candidate's physical route changes", async () => {
    const h = harness(["a", "b"]);
    h.env.controls.b!.routeId = "path-b";
    await h.runtime.refresh();
    const observation = deferred<Record<string, RouteMeasurement>>();
    h.observe.mockReturnValueOnce(observation.promise);
    const old = h.next();
    await vi.waitFor(() => expect(h.observe).toHaveBeenCalledTimes(2));
    h.env.controls.b!.routeId = "path-b-new";
    observation.resolve({ a: measured(h.env.now, 100), b: measured(h.env.now, 1) });
    await old;
    expect(h.override).not.toHaveBeenCalled();
    expect(h.report.mock.calls.at(-1)?.[0].measurements.b).toBeUndefined();
    await h.next(); expect(h.override).not.toHaveBeenCalled();
    await h.next(); expect(h.runtime.currentId).toBe("b");
  });

  it("rechecks both incumbent and challenger topology after the fresh activity guard", async () => {
    for (const changed of ["a", "b"]) {
      const h = harness(["a", "b"]), guard = deferred<boolean>();
      h.env.controls.a!.routeId = "path-a"; h.env.controls.b!.routeId = "path-b";
      await h.runtime.refresh(); h.canSwitch.mockReturnValueOnce(guard.promise);
      const switching = h.next();
      await vi.waitFor(() => expect(h.canSwitch).toHaveBeenCalledTimes(1));
      h.env.controls[changed]!.routeId = `path-${changed}-new`;
      guard.resolve(true); await switching;
      expect(h.override).not.toHaveBeenCalled();
      await h.next(); expect(h.override).not.toHaveBeenCalled();
      await h.next(); expect(h.runtime.currentId).toBe("b");
    }
  });

  it("keeps an acknowledged installed target authoritative if topology changes after RPC dispatch", async () => {
    const h = harness(["a", "b"]), ack = deferred<void>();
    h.env.controls.b!.routeId = "path-b";
    await h.runtime.refresh(); h.override.mockReturnValueOnce(ack.promise);
    const switching = h.next();
    await vi.waitFor(() => expect(h.override).toHaveBeenCalledTimes(1));
    h.env.controls.b!.routeId = "path-b-new";
    ack.resolve(); await switching;
    expect(h.runtime.currentId).toBe("b");
    expect(h.report.mock.calls.at(-1)?.[0]).toMatchObject({ currentId: "b", switched: true });
    expect(h.report.mock.calls.at(-1)?.[0].measurements.b).toBeUndefined();
  });
});
