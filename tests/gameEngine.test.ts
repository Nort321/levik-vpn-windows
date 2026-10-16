import { expect, it } from "vitest";
import { chooseExit, chooseIngress, classifyFlow, combineSegments, estimateExit, QualityWindow, MeasurementHistory, UploadQueueGuard, GAME_POLICY,
  type Segment, type ExitCandidate } from "../src/main/vpn/gameEngine";
const now = 1_000_000;
const metric = (latencyMs = 20, jitterMs = 3, lossPercent = 1): Segment => ({ latencyMs, p95Ms: latencyMs + 2, jitterMs,
  lossPercent, samples: 10, measuredAt: now, method: "icmp", approximate: false });
const node = (nodeId: string, a: number, b: number): ExitCandidate => ({ nodeId, state: "enabled", access: metric(a),
  egress: [{ address: "1.1.1.1", port: 7000, metric: metric(b) }] });
it("adds RTT, quadrature jitter and composed loss including node processing", () => {
  const result = combineSegments([metric(10, 3, 10), metric(20, 4, 20)], 2);
  expect(result.latencyMs).toBe(32); expect(result.jitterMs).toBe(5); expect(result.lossPercent).toBeCloseTo(28);
});
it("chooses destination B over A and draining never starts a new flow", () => {
  const target = { address: "1.1.1.1", port: 7000 };
  const nodes = [node("near", 10, 90), node("better", 30, 10), { ...node("draining", 1, 1), state: "draining" as const }];
  expect(chooseExit(nodes.map((item) => estimateExit(item, target, [], now)))?.nodeId).toBe("better");
});
it("uses bounded hysteresis and honors explicit preference among available exits", () => {
  const target = { address: "1.1.1.1", port: 7000 };
  const results = [node("old", 20, 20), node("new", 20, 18)].map((item) => estimateExit(item, target, [], now));
  expect(chooseExit(results, "old")?.nodeId).toBe("old");
  expect(chooseExit(results, "old", "new")?.nodeId).toBe("new");
});
it("falls through exact, /24, route identity, session regions then access", () => {
  const candidate = node("n", 10, 20); const target = { address: "1.1.1.2", port: 7000 };
  expect(estimateExit(candidate, target, [], now).confidence).toBe("subnet");
  candidate.egress[0]!.metric.routeKey = "route-a";
  expect(estimateExit(candidate, { address: "8.8.8.8", port: 7000, routeKey: "route-a" }, [], now).confidence).toBe("operator");
  candidate.egress[0]!.metric.region = "SE";
  expect(estimateExit(candidate, { address: "8.8.8.8", port: 7000 }, ["SE"], now).confidence).toBe("region");
  expect(estimateExit(candidate, { address: "8.8.8.8", port: 7000 }, [], now).confidence).toBe("access");
});
it("reduces confidence for stale data and never beats a destination metric by silently omitting B", () => {
  const target = { address: "1.1.1.1", port: 7000 }; const fresh = estimateExit(node("fresh", 20, 30), target, [], now);
  const stale = estimateExit(node("stale", 20, 30), target, [], now + 120_000);
  expect(stale.score).toBeGreaterThan(fresh.score);
  expect(estimateExit(node("expired", 1, 1), target, [], now + GAME_POLICY.expiryMs).score).toBe(Infinity);
  const unknown = { ...node("unknown", 1, 1), egress: [] };
  expect(chooseExit([fresh, estimateExit(unknown, target, [], now)])?.nodeId).toBe("fresh");
});
it("allows a measured physical direct exit", () => {
  const target = { address: "1.1.1.1", port: 7000 };
  const direct = estimateExit({ nodeId: "direct", state: "enabled", access: null, egress: [], direct: metric(5) }, target, [], now);
  expect(chooseExit([estimateExit(node("vpn", 20, 20), target, [], now), direct])?.nodeId).toBe("direct");
});
it("keeps rolling loss proportional rather than assigning 250 ms for one missed probe", () => {
  const window = new QualityWindow(); for (let i = 0; i < 8; i++) window.push(i === 3 ? null : 20, now + i);
  const result = window.snapshot(now + 8); expect(result.lossPercent).toBe(12.5);
  expect(result.samples).toBeGreaterThanOrEqual(GAME_POLICY.minimumSamples); expect(result.latencyMs).toBe(20);
});
it("classifies sustained bidirectional match and many short region bursts without payload inspection", () => {
  expect(classifyFlow({ startedAt: 0, now: 6000, sent: 120, received: 100, distinctTargets: 1 })).toBe("match");
  expect(classifyFlow({ startedAt: 0, now: 1000, sent: 4, received: 2, distinctTargets: 8 })).toBe("regions");
  expect(classifyFlow({ startedAt: 0, now: 6000, sent: 1, received: 0, distinctTargets: 1 })).toBe("service");
});
it("always takes two best paths and near paths, reduces copies on upload inflation then retries", () => {
  const paths = [10, 70, 20, 30, 90].map((latencyMs) => ({ latencyMs }));
  expect(chooseIngress(paths, true).map((item) => item.latencyMs)).toEqual([10, 20, 30]);
  expect(chooseIngress(paths, false)).toHaveLength(1); expect(chooseIngress(paths, true, true)).toHaveLength(1);
  const guard = new UploadQueueGuard(); guard.update(10, 0, 2, now);
  for (let i = 0; i < 4; i++) expect(guard.update(30, 64_000, 2, now + i * 1000)).toBe(false);
  expect(guard.update(30, 64_000, 2, now + 4000)).toBe(true);
  expect(guard.update(10, 0, 1, now + 35_000)).toBe(false);
});
it("rejects insufficient samples even for a plausible low RTT", () => {
  const candidate = node("early", 1, 1); candidate.access!.samples = 1;
  expect(estimateExit(candidate, { address: "1.1.1.1", port: 7000 }, [], now).score).toBe(Infinity);
});
it("scores an entry plus mesh route better than a slower direct entry without double counting", () => {
  const target = { address: "1.1.1.1", port: 7000 };
  const plain = estimateExit(node("exit", 80, 10), target, [], now);
  const mesh = estimateExit({ ...node("exit", 10, 10), mesh: metric(20) }, target, [], now);
  const echoOfWholeChain = estimateExit({ ...node("exit", 30, 10), processingNodes: 2 }, target, [], now);
  expect(mesh.latencyMs).toBe(42); expect(echoOfWholeChain.latencyMs).toBe(42); expect(mesh.score).toBeLessThan(plain.score);
});
it("smooths native batches using real sample counts and preserves fractional loss", () => {
  const history = new MeasurementHistory(); history.push({ ...metric(20, 1, 0), samples: 10 });
  history.push({ ...metric(22, 1, 20), samples: 5 });
  expect(history.snapshot(now)?.samples).toBe(15);
  expect(history.snapshot(now)?.lossPercent).toBeCloseTo(100 / 15);
  expect(history.snapshot(now + GAME_POLICY.expiryMs)).toBeNull();
});
it("prefers independent entry nodes when more than one can reach the pinned exit", () => {
  const result = chooseIngress([{ latencyMs: 10, entryNodeId: "a" }, { latencyMs: 11, entryNodeId: "a" },
    { latencyMs: 20, entryNodeId: "b" }], true);
  expect(result.slice(0, 2).map((item) => item.entryNodeId)).toEqual(["a", "b"]);
});
it("keeps exact-target TTL uncertainty separate from subnet fallback", () => {
  const candidate = node("ttl", 10, 20);
  Object.assign(candidate.egress[0]!.metric, { method: "ttl-hop", approximate: true, scope: "target" });
  expect(estimateExit(candidate, { address: "1.1.1.1", port: 7000 }, [], now)).toMatchObject({ confidence: "exact", approximate: true });
  candidate.egress[0]!.metric.scope = "subnet";
  expect(estimateExit(candidate, { address: "1.1.1.1", port: 7000 }, [], now).confidence).toBe("subnet");
});
