import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildRouteProbeConfig, diverseProbeCandidates, measureRouteCandidates, rankMeasuredRoutes,
  PARTIAL_ROUTE_TTL_MS, ROUTE_MEASUREMENT_TTL_MS, ROUTE_PROBE_LIMITS, type RouteMeasurement, type RouteProbeCandidate, type RouteProbeSession,
} from "../src/main/vpn/routeProbe";
import { rankSmart, type SmartCandidate } from "../src/main/vpn/smartAuto";
import { currentRouteResource, LiveLoadClient, mergeLiveLoad, parseLiveLoad } from "../src/main/platform/liveLoad";

const NOW = 1_000_000;
const node = (letter: string) => `n1${letter.repeat(20)}`;
function measurement(medianMs: number, extra: Partial<RouteMeasurement> = {}): RouteMeasurement {
  return { measuredAt: NOW, confidence: "measured", medianMs, jitterMs: 2, failureRate: 0, targets: 2, samples: 6,
    setupMs: 100, downMbps: 100, upMbps: 30, ...extra };
}
function candidate(id: string, latencyMs: number | null, route?: RouteMeasurement, extra: Partial<SmartCandidate> = {}): SmartCandidate {
  return { id, protocol: "vless-reality", latencyMs, silenceMeansDown: true, load: 0.1, verdict: "works", ...(route ? { route } : {}), ...extra };
}
function probe(id: string, entry = id, exit = id): RouteProbeCandidate {
  return { id, routeKey: id, tag: id, config: {}, path: [entry, exit], exitId: exit };
}

afterEach(() => vi.useRealTimers());

describe("full route choice", () => {
  it("beats a fast Moscow entry using the observed full cascade and never lets ping spreading replace it", () => {
    const routes = [candidate("moscow-cascade", 5, measurement(190)), candidate("direct", 60, measurement(55))];
    expect(rankSmart(routes, null, 0.99, NOW)[0]?.id).toBe("direct");
    expect(rankSmart(routes.map(({ route: _route, ...item }) => item), null, null, NOW)[0]?.id).toBe("moscow-cascade");
  });

  it("trusts a working authenticated VPN over a silent unauthenticated endpoint probe", () => {
    expect(rankSmart([candidate("works", null, measurement(45)), candidate("unknown", 2)], null, null, NOW)[0]?.id).toBe("works");
  });

  it("lets fresh path proof override yesterday's protocol block on this network", () => {
    expect(rankSmart([
      candidate("now-works", 1, measurement(30), { verdict: "blocked" }),
      candidate("old-working", 50, measurement(80)),
    ], null, null, NOW)[0]?.id).toBe("now-works");
  });

  it("takes the lowest stable latency within 90 percent of balanced measured throughput", () => {
    const observations = {
      fast: measurement(70, { downMbps: 100, upMbps: 100 }),
      near: measurement(25, { downMbps: 92, upMbps: 92 }),
      uploadBad: measurement(5, { downMbps: 500, upMbps: 1 }),
    };
    expect(rankMeasuredRoutes(Object.keys(observations).map((id) => ({ id })), observations, NOW)[0]?.id).toBe("near");
  });

  it("penalizes response variation and failures, then prefers healthy resources on a latency tie", () => {
    const observations = { noisy: measurement(10, { jitterMs: 80 }), stable: measurement(50), errors: measurement(20, { failureRate: 0.1 }) };
    expect(rankMeasuredRoutes(Object.keys(observations).map((id) => ({ id })), observations, NOW)[0]?.id).toBe("stable");
    const tied = [{ id: "hot", routeDegraded: true }, { id: "healthy", routeDegraded: false }];
    expect(rankMeasuredRoutes(tied, { hot: measurement(50), healthy: measurement(51) }, NOW)[0]?.id).toBe("healthy");
  });

  it("has the same winner for every input order when headroom breaks a latency bucket tie", () => {
    const routes = [{ id: "a", resourceHeadroom: 0.1 }, { id: "b", resourceHeadroom: null }, { id: "c", resourceHeadroom: 0.9 }];
    const values = { a: measurement(10, { jitterMs: 0 }), b: measurement(12, { jitterMs: 0 }), c: measurement(14, { jitterMs: 0 }) };
    for (const order of [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]) {
      expect(rankMeasuredRoutes(order.map((i) => routes[i]!), values, NOW)[0]?.id).toBe("c");
    }
  });

  it("excludes a fresh confirmed full route while unknown resources stay usable", () => {
    const full = candidate("full", 1, measurement(10), { full: true });
    const unknown = candidate("unknown-resources", 80, measurement(60), { resourceHeadroom: null });
    expect(rankSmart([full, unknown], null, null, NOW).map((item) => item.id)).toEqual(["unknown-resources"]);
    expect(rankSmart([full], null, null, NOW)[0]?.id).toBe("full");
  });

  it("does not turn stale or partial observations into measured bandwidth", () => {
    expect(rankMeasuredRoutes([{ id: "stale" }], { stale: measurement(1) }, NOW + ROUTE_MEASUREMENT_TTL_MS)).toEqual([]);
    const partial = measurement(1, { confidence: "partial", targets: 1, downMbps: null, upMbps: null });
    expect(rankMeasuredRoutes([{ id: "partial" }], { partial }, NOW)[0]?.id).toBe("partial");
    expect(rankMeasuredRoutes([{ id: "partial" }], { partial }, NOW + PARTIAL_ROUTE_TTL_MS)).toEqual([]);
    const values = { a: measurement(80, { downMbps: null, upMbps: null }), b: measurement(40, { downMbps: null, upMbps: null }) };
    expect(rankMeasuredRoutes([{ id: "a" }, { id: "b" }], values, NOW)[0]?.id).toBe("b");
  });

  it("keeps short real-path partial proof above entry ping while two-provider proof remains authoritative", () => {
    const partial = measurement(20, { confidence: "partial", targets: 1, downMbps: null, upMbps: null });
    const routes = [candidate("partial", 200, partial), candidate("fast-entry", 1)];
    expect(rankSmart(routes, null, null, NOW)[0]?.id).toBe("partial");
    expect(rankSmart([...routes, candidate("confirmed", 300, measurement(100))], null, null, NOW)[0]?.id).toBe("confirmed");
  });
});

describe("route resources", () => {
  const key = node("a"), fallback = node("b");
  const resource = { id: `r1${"c".repeat(20)}`, path: [key, fallback], complete: true, state: "healthy", ageSeconds: 20, resourceLoad: 0.2, resourceHeadroom: 0.8 };

  it("keeps a missing hop explicitly unknown and never fills in spare capacity", () => {
    const parsed = parseLiveLoad({ ok: true, v: 2, routes: { [key]: { ...resource, complete: false, state: "unknown" } } });
    expect(parsed?.routes?.[key]).toMatchObject({ complete: false, state: "unknown", resourceLoad: null, resourceHeadroom: null });
    expect(parseLiveLoad({ ok: true, v: 2, routes: { [key]: { ...resource, path: ["invalid"] } } })?.routes).toEqual({});
  });

  it("uses endpoint before host and does not renew agent freshness on HTTP 304", () => {
    const parsed = parseLiveLoad({ ok: true, v: 2, routes: { [key]: resource, [fallback]: { ...resource, state: "overloaded" } } })!;
    const state = mergeLiveLoad(null, { ...parsed, kind: "fresh", etag: null }, NOW, false);
    expect(currentRouteResource(state, [key, fallback], NOW)?.state).toBe("healthy");
    const same = mergeLiveLoad(state, { kind: "same" }, NOW + 30_000, true);
    expect(currentRouteResource(same, [key], NOW + 30_000)).toMatchObject({ state: "unknown", resourceHeadroom: null });
  });

  it("backs off server rate limits instead of hitting every origin on every poll", async () => {
    const fetcher = vi.fn(async () => new Response("", { status: 429, headers: { "Retry-After": "120" } }));
    const client = new LiveLoadClient("windows", "test", fetcher);
    expect(await client.fetch(null, NOW)).toBeNull();
    expect(await client.fetch(null, NOW + 30_000)).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
    await client.fetch(null, NOW + 120_000);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

describe("probe isolation and bounded work", () => {
  it("forces the exact candidate including its dialer dependency and strips every system routing bypass", () => {
    const config = buildRouteProbeConfig({
      api: { listen: "127.0.0.1:1" }, dns: { servers: ["localhost"] },
      inbounds: [{ protocol: "tun" }],
      outbounds: [
        { tag: "selected", protocol: "vless", streamSettings: { sockopt: { dialerProxy: "fragment" } } },
        { tag: "direct", protocol: "freedom" }, { tag: "fragment", protocol: "freedom" },
      ], routing: { rules: [{ domain: ["cloudflare.com"], outboundTag: "direct" }] },
    }, "selected", 20000, "a".repeat(48));
    expect(config).not.toHaveProperty("api");
    expect(config.dns).toEqual({ tag: "levik-route-probe-dns", servers: ["localhost"] });
    expect(config.inbounds).toEqual([expect.objectContaining({ protocol: "http", listen: "127.0.0.1", settings: expect.objectContaining({ users: [{ user: "probe", pass: "a".repeat(48) }] }) })]);
    expect(config.outbounds).toEqual([expect.objectContaining({ tag: "selected" }), expect.objectContaining({ tag: "fragment" })]);
    expect(config.routing).toEqual({ domainStrategy: "AsIs", rules: [
      { type: "field", inboundTag: ["levik-route-probe"], outboundTag: "selected" },
      { type: "field", inboundTag: ["levik-route-probe-dns"], outboundTag: "selected" },
    ] });
    expect(() => buildRouteProbeConfig({ outbounds: [] }, "missing", 20000, "a".repeat(48))).toThrow();
  });

  it("diversifies entries and exits before another fast protocol on the same Moscow cascade", () => {
    const routes = [probe("a", "moscow", "de"), probe("a2", "moscow", "de"), probe("b", "moscow", "nl"), probe("c", "direct", "fi")];
    expect(diverseProbeCandidates(routes, 3).map((candidate) => candidate.id)).toEqual(["a", "c", "b"]);
  });

  it("caps and deduplicates route tests, closes sessions and never runs transfers concurrently", async () => {
    let active = 0, maximum = 0, transfers = 0, transferMaximum = 0;
    const closed: string[] = []; const sampled: string[] = [];
    const results = await measureRouteCandidates({ executable: "test", candidates: [...Array.from({ length: 15 }, (_, i) => probe(String(i))), { ...probe("alias"), routeKey: "0" }] }, {
      now: () => NOW,
      open: async (_executable, candidate) => {
        active++; maximum = Math.max(maximum, active);
        return {
          latency: async () => { sampled.push(candidate.id); return { values: [50, 52, 51], failed: 0, setupMs: 200 }; },
          transfer: async () => { transfers++; transferMaximum = Math.max(transferMaximum, transfers); await Promise.resolve(); transfers--; return 100; },
          close: async () => { active--; closed.push(candidate.id); },
        };
      },
    });
    expect(maximum).toBeLessThanOrEqual(ROUTE_PROBE_LIMITS.parallel);
    expect(new Set(sampled).size).toBe(ROUTE_PROBE_LIMITS.candidates);
    expect(closed.length).toBe(ROUTE_PROBE_LIMITS.candidates + ROUTE_PROBE_LIMITS.finalists);
    expect(transferMaximum).toBe(1); expect(active).toBe(0);
    expect(results.alias).toBe(results["0"]);
  });

  it("reserves transfer time even when the remaining latency pool stalls", async () => {
    vi.useFakeTimers();
    const transfers: string[] = [];
    const operation = measureRouteCandidates({ executable: "test", candidates: [probe("fast-a"), probe("fast-b"), probe("stalled-a"), probe("stalled-b")] }, {
      now: Date.now,
      open: async (_executable, candidate, signal) => ({
        latency: async () => {
          if (candidate.id.startsWith("stalled")) return await new Promise<never>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true }));
          return { values: [30, 32, 31], failed: 0, setupMs: 100 };
        },
        transfer: async () => { transfers.push(candidate.id); return 100; },
        close: async () => {},
      }),
    });
    await vi.advanceTimersByTimeAsync(ROUTE_PROBE_LIMITS.latencyPhaseMs);
    const results = await operation;
    expect(transfers).toEqual(["fast-a", "fast-a", "fast-b", "fast-b"]);
    expect(results["fast-a"]?.downMbps).toBe(100);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("starts every bounded candidate even when the first ten routes blackhole both workers", async () => {
    vi.useFakeTimers();
    const opened = new Set<string>();
    const operation = measureRouteCandidates({ executable: "test", candidates: Array.from({ length: 12 }, (_, i) => probe(String(i))) }, {
      now: Date.now,
      open: async (_executable, candidate, signal) => {
        opened.add(candidate.id);
        return {
          latency: async () => {
            if (Number(candidate.id) < 10) return await new Promise<never>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true }));
            return { values: [40, 41, 42], failed: 0, setupMs: 100 };
          }, transfer: async () => 100, close: async () => {},
        };
      },
    });
    await vi.advanceTimersByTimeAsync(ROUTE_PROBE_LIMITS.latencyPhaseMs);
    const results = await operation;
    expect(opened.size).toBe(12);
    expect(results["10"]?.confidence).toBe("measured");
    expect(results["10"]?.upMbps).toBe(100);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("retains actual single-provider latency when the second provider is unreachable", async () => {
    let calls = 0;
    const results = await measureRouteCandidates({ executable: "test", candidates: [probe("a")] }, {
      now: () => NOW,
      open: async () => ({ latency: async () => { if (++calls === 2) throw new Error("provider down"); return { values: [30, 31, 32], failed: 0, setupMs: 100 }; }, transfer: async () => null, close: async () => {} }),
    });
    expect(results.a).toMatchObject({ confidence: "partial", targets: 1, failureRate: 0, downMbps: null, upMbps: null });
    expect(rankSmart([candidate("a", 200, results.a), candidate("edge", 1)], null, null, NOW)[0]?.id).toBe("a");
  });

  it("preserves already received path samples when that route's budget expires", async () => {
    vi.useFakeTimers();
    const operation = measureRouteCandidates({ executable: "test", candidates: [probe("a")] }, {
      now: Date.now,
      open: async (_executable, _candidate, signal) => ({
        latency: async () => await new Promise((resolve) => signal.addEventListener("abort", () => resolve({ values: [40, 42], failed: 0, setupMs: 100 }), { once: true })),
        transfer: async () => null, close: async () => {},
      }),
    });
    await vi.advanceTimersByTimeAsync(ROUTE_PROBE_LIMITS.latencyPhaseMs - 1000);
    const results = await operation;
    expect(results.a).toMatchObject({ confidence: "partial", medianMs: 42, samples: 2, targets: 1, failureRate: 0 });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels and closes in-flight sessions without publishing another network's results", async () => {
    const abort = new AbortController(); let opened = 0, closed = 0;
    let started: (() => void) | undefined;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    const operation = measureRouteCandidates({ executable: "test", candidates: [probe("a")], signal: abort.signal }, {
      now: () => NOW,
      open: async (_executable, _candidate, signal): Promise<RouteProbeSession> => {
        opened++; started?.();
        return { latency: async () => await new Promise<never>((_resolve, reject) => {
          if (signal.aborted) reject(new Error("cancelled"));
          else signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true });
        }), transfer: async () => null, close: async () => { closed++; } };
      },
    });
    await ready; abort.abort();
    expect(await operation).toEqual({}); expect(opened).toBe(1); expect(closed).toBe(1);
  });

  it("keeps unavailable probe engines an explicit failed observation with the established fallback", async () => {
    const results = await measureRouteCandidates({ executable: "missing", candidates: [probe("a")] }, { now: () => NOW, open: async () => { throw new Error("unavailable"); } });
    expect(results.a).toMatchObject({ confidence: "failed", medianMs: null, downMbps: null, upMbps: null });
    expect(rankSmart([candidate("a", 50, results.a)], null, null, NOW)[0]?.id).toBe("a");
  });
});
