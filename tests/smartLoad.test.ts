import { describe, expect, it } from "vitest";
import {
  agedLoad,
  LOAD_FORGET_MS,
  LOAD_TRUST_MS,
  loadFactor,
  OVERLOAD_CONFIRM_MS,
  overloadMoveDue,
  rankSmart,
  spreadSeed,
  spreadTop,
  type SmartCandidate,
} from "../src/main/vpn/smartAuto";
import { currentQuality, LiveLoadClient, mergeLiveLoad, parseLiveLoad } from "../src/main/platform/liveLoad";
import { robustLatency } from "../src/main/vpn/serverPinger";

const id = (digit: string) => `n1${digit.repeat(20)}`;

function candidate(overrides: Partial<SmartCandidate> = {}): SmartCandidate {
  return { id: "a", protocol: "vless-reality", latencyMs: 50, silenceMeansDown: true, load: 0, verdict: "unknown", ...overrides };
}

describe("Smart Auto load", () => {
  it("weighs load like a queue, capped for a full node", () => {
    expect(loadFactor(0)).toBe(1);
    expect(loadFactor(0.5)).toBe(2);
    expect(loadFactor(0.8)).toBeCloseTo(5);
    expect(loadFactor(1)).toBeCloseTo(20);
    expect(loadFactor(null)).toBeCloseTo(1 / 0.65);
  });

  it("prefers a free server a little farther away over a crowded near one", () => {
    const ranked = rankSmart([
      candidate({ id: "near-busy", latencyMs: 30, load: 0.8 }),
      candidate({ id: "far-free", latencyMs: 90, load: 0.1 }),
    ], null);
    expect(ranked[0]?.id).toBe("far-free");
  });

  it("leaves full nodes out while another remains", () => {
    expect(rankSmart([candidate({ id: "full", full: true }), candidate({ id: "slow", latencyMs: 400 })], null).map((item) => item.id)).toEqual(["slow"]);
    expect(rankSmart([candidate({ id: "full", full: true })], null).map((item) => item.id)).toEqual(["full"]);
  });

  it("uses operator quality as a factor within limits", () => {
    const ranked = rankSmart([
      candidate({ id: "slow-route", quality: 1.5 }),
      candidate({ id: "good-route", latencyMs: 60, quality: 0.8 }),
    ], null);
    expect(ranked[0]?.id).toBe("good-route");
  });

  it("lets an old reading fade into unknown", () => {
    expect(agedLoad(0.9, LOAD_TRUST_MS)).toBe(0.9);
    const halfway = agedLoad(0.9, (LOAD_TRUST_MS + LOAD_FORGET_MS) / 2)!;
    expect(halfway).toBeGreaterThan(0.35);
    expect(halfway).toBeLessThan(0.9);
    expect(agedLoad(0.9, LOAD_FORGET_MS)).toBeNull();
    expect(agedLoad(null, 0)).toBeNull();
  });

  it("spreads computers over near-equal servers but never picks a clearly worse one", () => {
    const ranked = [
      { id: "a", protocol: "p", score: 100 },
      { id: "b", protocol: "p", score: 110 },
      { id: "c", protocol: "p", score: 300 },
    ];
    expect(spreadTop(ranked, 0)[0]?.id).toBe("a");
    expect(spreadTop(ranked, 0.99)[0]?.id).toBe("b");
    const picks = new Set(Array.from({ length: 50 }, (_, index) => spreadTop(ranked, index / 50)[0]?.id));
    expect(picks).toEqual(new Set(["a", "b"]));
    expect(spreadTop(ranked, 0.7).map((item) => item.id).sort()).toEqual(["a", "b", "c"]);
  });

  it("keeps the spread stable for ten minutes on one computer", () => {
    const start = 1_700_000_400_000;
    expect(spreadSeed("salt", start)).toBe(spreadSeed("salt", start + 60_000));
    expect(spreadSeed("salt", start)).not.toBe(spreadSeed("other", start));
    expect(spreadSeed("salt", start)).toBeGreaterThanOrEqual(0);
    expect(spreadSeed("salt", start)).toBeLessThan(1);
  });
});

describe("leaving a full node", () => {
  const now = 10_000_000;
  const base = {
    fullSince: now - OVERLOAD_CONFIRM_MS,
    loadAgeMs: 30_000,
    idle: true,
    lastMoveAt: null,
    currentScore: 1_000,
    bestScore: 100,
    now,
  };

  it("moves an idle connection after five minutes full by fresh readings", () => {
    expect(overloadMoveDue(base)).toBe(true);
  });

  it("never cuts an active connection, a fresh alarm, stale data or a second move", () => {
    expect(overloadMoveDue({ ...base, idle: false })).toBe(false);
    expect(overloadMoveDue({ ...base, fullSince: now - 60_000 })).toBe(false);
    expect(overloadMoveDue({ ...base, fullSince: null })).toBe(false);
    expect(overloadMoveDue({ ...base, loadAgeMs: 10 * 60_000 })).toBe(false);
    expect(overloadMoveDue({ ...base, lastMoveAt: now - 60_000 })).toBe(false);
    expect(overloadMoveDue({ ...base, bestScore: 700 })).toBe(false);
  });
});

describe("live load", () => {
  it("parses only node ids and sane values", () => {
    expect(parseLiveLoad({
      ok: true,
      load: { [id("a")]: 0.4, bad: 0.1, [id("b")]: 3 },
      full: [id("a"), "x"],
      quality: { [id("a")]: 0.8, [id("b")]: 9 },
    })).toEqual({ load: { [id("a")]: 0.4 }, full: [id("a")], quality: { [id("a")]: 0.8 } });
    expect(parseLiveLoad({ ok: true, load: {}, full: [], quality: null })?.quality).toBeNull();
    expect(parseLiveLoad({ ok: false })).toBeNull();
  });

  it("keeps the operator's quality when an answer came through the tunnel", () => {
    const direct = mergeLiveLoad(null, { kind: "fresh", load: {}, full: [], quality: { [id("a")]: 0.8 }, etag: '"x"' }, 1_000, false);
    const tunnel = mergeLiveLoad(direct, { kind: "fresh", load: { [id("a")]: 0.2 }, full: [], quality: null, etag: '"y"' }, 2_000, true);
    expect(tunnel?.quality).toEqual({ [id("a")]: 0.8 });
    expect(tunnel?.qualityAt).toBe(1_000);
    expect(currentQuality(tunnel, 1_000 + 3 * 60 * 60_000)).toEqual({});
    const same = mergeLiveLoad(tunnel, { kind: "same" }, 5_000, true);
    expect(same?.fetchedAt).toBe(5_000);
    expect(same?.load).toEqual({ [id("a")]: 0.2 });
  });

  it("sends its ETag, takes a 304 as fresh and waits an hour after a 404", async () => {
    const seen: Array<string | null> = [];
    let status = 304;
    const client = new LiveLoadClient("windows", "1.2.3", ((_url: string, init: RequestInit) => {
      seen.push((init.headers as Record<string, string>)["If-None-Match"] ?? null);
      return Promise.resolve(new Response(status === 304 ? null : "", { status }));
    }) as typeof fetch);
    expect(await client.fetch('"abc"', 0)).toEqual({ kind: "same" });
    expect(seen[0]).toBe('"abc"');
    status = 404;
    expect(await client.fetch(null, 0)).toEqual({ kind: "unsupported" });
    const calls = seen.length;
    expect(await client.fetch(null, 30 * 60_000)).toEqual({ kind: "unsupported" });
    expect(seen.length).toBe(calls);
  });
});

describe("ping", () => {
  it("takes the median of three and ignores a lost packet", () => {
    expect(robustLatency([40, 1_040, 42])).toBe(42);
    expect(robustLatency([null, 1_040, 41])).toBe(41);
    expect(robustLatency([null, null, 60])).toBe(60);
    expect(robustLatency([null, null, null])).toBeNull();
  });
});
