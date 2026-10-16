import type { GameMeasurement, GameNode } from "../../shared/contracts";

// All quality values use milliseconds and percentage points, never fractions.
export const GAME_POLICY = Object.freeze({ window: 60, minimumSamples: 5, jitterWeight: 1.5,
  lossWeightMs: 2, maxLossPercent: 25, freshMs: 15_000, expiryMs: 600_000,
  stalePenaltyMsPerSecond: 0.05, nodeProcessingMs: 1, loadWeightMs: 5,
  linkBytesPerSecond: 125_000_000, networkLoadWeightMs: 10, flowLoadWeightMs: 5,
  directProbeIntervalMs: 5_000,
  hysteresisMs: 3, hysteresisRatio: 0.05, extraPathMs: 25, maxCopies: 4,
  matchMinAgeMs: 5_000, matchPacketsPerSecond: 10, matchMinReplies: 20,
  lobbyMaxAgeMs: 5_000, uploadInflationMs: 15, uploadConfirmTicks: 5, uploadMinReplicatedBytes: 1024, uploadRetryMs: 30_000 });

export interface Segment extends GameMeasurement { routeKey?: string; region?: string; operator?: string; scope?: "target" | "subnet" }
export interface DestinationMetric { address: string; port: number; metric: Segment }
export interface ExitCandidate { nodeId: string; state: GameNode["state"]; access: Segment | null;
  egress: DestinationMetric[]; mesh?: Segment; cpuPercent?: number; direct?: Segment; processingNodes?: number;
  networkBytesPerSecond?: number; activeFlows?: number }
export type Confidence = "exact" | "subnet" | "operator" | "region" | "access" | "unavailable";
export interface PathEstimate { nodeId: string; latencyMs: number | null; jitterMs: number | null;
  lossPercent: number | null; score: number; confidence: Confidence; approximate: boolean; egress: Segment | null }
export const subnet24 = (address: string): string => address.split(".").slice(0, 3).join(".") + ".0/24";

export function combineSegments(segments: Segment[], nodes = 1): Pick<PathEstimate, "latencyMs" | "jitterMs" | "lossPercent"> {
  if (!segments.length || segments.some((item) => item.latencyMs === null)) return { latencyMs: null, jitterMs: null, lossPercent: null };
  return { latencyMs: segments.reduce((sum, item) => sum + item.latencyMs!, nodes * GAME_POLICY.nodeProcessingMs),
    jitterMs: Math.sqrt(segments.reduce((sum, item) => sum + (item.jitterMs ?? 0) ** 2, 0)),
    lossPercent: 100 * (1 - segments.reduce((survival, item) => survival * (1 - item.lossPercent / 100), 1)) };
}

export function estimateExit(candidate: ExitCandidate, target: { address: string; port: number; routeKey?: string; region?: string },
  sessionRegions: string[] = [], now = Date.now()): PathEstimate {
  const unavailable: PathEstimate = { nodeId: candidate.nodeId, latencyMs: null, jitterMs: null, lossPercent: null,
    score: Infinity, confidence: "unavailable", approximate: true, egress: null };
  if (candidate.state !== "enabled") return unavailable;
  const fresh = (item: Segment): boolean => item.samples >= GAME_POLICY.minimumSamples && item.latencyMs !== null && Number.isFinite(item.latencyMs)
    && now >= item.measuredAt - 5_000 && now - item.measuredAt < GAME_POLICY.expiryMs && item.lossPercent <= GAME_POLICY.maxLossPercent;
  if (candidate.direct) {
    if (!fresh(candidate.direct)) return unavailable;
    const metric = candidate.direct;
    return { nodeId: candidate.nodeId, latencyMs: metric.latencyMs, jitterMs: metric.jitterMs, lossPercent: metric.lossPercent,
      score: scoreMetric(metric, now), confidence: "exact", approximate: metric.approximate, egress: null };
  }
  if (!candidate.access || !fresh(candidate.access) || (candidate.mesh && !fresh(candidate.mesh))) return unavailable;
  const metrics = candidate.egress.filter((item) => fresh(item.metric));
  const exact = metrics.find((item) => item.address === target.address && item.port === target.port);
  const subnet = metrics.find((item) => subnet24(item.address) === subnet24(target.address));
  // Never infer an operator from numerical IP proximity. A route key must be
  // supplied by the measurement service's observed route/offline database.
  const operator = target.routeKey ? metrics.find((item) => item.metric.routeKey === target.routeKey) : undefined;
  const region = metrics.find((item) => item.metric.region && (item.metric.region === target.region || sessionRegions.includes(item.metric.region)));
  const chosen = exact ?? subnet ?? operator ?? region;
  const confidence: Confidence = exact ? (exact.metric.scope === "subnet" || (!exact.metric.scope && exact.metric.approximate && exact.metric.method !== "ttl-hop") ? "subnet" : "exact")
    : subnet ? "subnet" : operator ? "operator" : region ? "region" : "access";
  const segments = [candidate.access, ...(candidate.mesh ? [candidate.mesh] : []), ...(chosen ? [chosen.metric] : [])];
  const combined = combineSegments(segments, candidate.processingNodes ?? (candidate.mesh ? 2 : 1));
  const score = combined.latencyMs! + GAME_POLICY.jitterWeight * (combined.jitterMs ?? 0) + GAME_POLICY.lossWeightMs * (combined.lossPercent ?? 0)
    + segments.reduce((sum, item) => sum + Math.max(0, now - item.measuredAt - GAME_POLICY.freshMs) / 1000 * GAME_POLICY.stalePenaltyMsPerSecond, 0)
    + Math.max(0, Math.min(100, candidate.cpuPercent ?? 0)) / 100 * GAME_POLICY.loadWeightMs
    + Math.min(1, Math.max(0, candidate.networkBytesPerSecond ?? 0) / GAME_POLICY.linkBytesPerSecond) * GAME_POLICY.networkLoadWeightMs
    + Math.min(1, Math.max(0, candidate.activeFlows ?? 0) / 1024) * GAME_POLICY.flowLoadWeightMs;
  return { nodeId: candidate.nodeId, ...combined, score, confidence, approximate: true, egress: chosen?.metric ?? null };
}
function scoreMetric(metric: Segment, now: number): number {
  return metric.latencyMs! + GAME_POLICY.jitterWeight * (metric.jitterMs ?? 0) + GAME_POLICY.lossWeightMs * metric.lossPercent
    + Math.max(0, now - metric.measuredAt - GAME_POLICY.freshMs) / 1000 * GAME_POLICY.stalePenaltyMsPerSecond;
}

/** Compare within the best available evidence tier; unknown B must not beat a measured destination by omitting B. */
export function chooseExit(estimates: PathEstimate[], previousId: string | null = null, preferredId: string | null = null): PathEstimate | null {
  const tiers: Record<Confidence, number> = { exact: 0, subnet: 1, operator: 2, region: 3, access: 4, unavailable: 5 };
  const ranked = estimates.filter((item) => Number.isFinite(item.score)).sort((a, b) => tiers[a.confidence] - tiers[b.confidence] || a.score - b.score);
  const best = ranked.find((item) => item.nodeId === preferredId) ?? ranked[0];
  if (!best) return null;
  const previous = ranked.find((item) => item.nodeId === previousId);
  if (!preferredId && previous && tiers[previous.confidence] <= tiers[best.confidence]
    && previous.score - best.score < Math.max(GAME_POLICY.hysteresisMs, previous.score * GAME_POLICY.hysteresisRatio)) return previous;
  return best;
}
export function chooseIngress<T extends { latencyMs: number | null; entryNodeId?: string }>(paths: T[], protection: boolean, limitedByUpload = false): T[] {
  const ranked = paths.filter((path) => path.latencyMs !== null).sort((a, b) => a.latencyMs! - b.latencyMs!);
  if (!protection || limitedByUpload) return ranked.slice(0, 1);
  const first = ranked[0]; if (!first) return [];
  const second = ranked.find((path) => path !== first && first.entryNodeId && path.entryNodeId && path.entryNodeId !== first.entryNodeId) ?? ranked[1];
  const selected = [first, ...(second ? [second] : [])];
  for (const path of ranked) if (!selected.includes(path) && path.latencyMs! <= first.latencyMs! + GAME_POLICY.extraPathMs && selected.length < GAME_POLICY.maxCopies) selected.push(path);
  return selected;
}

export class QualityWindow {
  private readonly samples: Array<{ latency: number | null; at: number }> = [];
  push(latency: number | null, at = Date.now()): void {
    this.samples.push({ latency, at }); while (this.samples.length > GAME_POLICY.window) this.samples.shift();
  }
  snapshot(now = Date.now()): Segment {
    const samples = this.samples.filter((item) => now - item.at < GAME_POLICY.expiryMs);
    const good = samples.flatMap((item) => item.latency === null ? [] : [item.latency]);
    const sorted = [...good].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)] ?? null;
    const jitter = good.length < 2 ? null : good.slice(1).reduce((sum, item, index) => sum + Math.abs(item - good[index]!), 0) / (good.length - 1);
    return { latencyMs: median, p95Ms: sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? null, jitterMs: jitter,
      lossPercent: samples.length ? (samples.length - good.length) / samples.length * 100 : 100, samples: samples.length,
      measuredAt: samples.at(-1)?.at ?? now, method: "echo", approximate: false };
  }
}

/** Rolling native measurement batches, weighted by their actual probe count. */
export class MeasurementHistory {
  private readonly values: Segment[] = [];
  push(value: Segment): void {
    this.values.push(value); while (this.values.length > 12) this.values.shift();
  }
  snapshot(now = Date.now()): Segment | null {
    const values = this.values.filter((value) => now - value.measuredAt < GAME_POLICY.expiryMs);
    const last = values.at(-1); if (!last) return null;
    const good = values.filter((value) => value.latencyMs !== null);
    const sorted = good.map((value) => value.latencyMs!).sort((a, b) => a - b);
    const samples = values.reduce((sum, value) => sum + value.samples, 0);
    const mean = good.length ? good.reduce((sum, value) => sum + value.latencyMs!, 0) / good.length : 0;
    return { ...last, samples, latencyMs: sorted[Math.floor(sorted.length / 2)] ?? null,
      p95Ms: good.length ? Math.max(...good.map((value) => value.p95Ms ?? value.latencyMs!)) : null,
      jitterMs: good.length ? Math.sqrt(good.reduce((sum, value) => sum + (value.jitterMs ?? 0) ** 2 + (value.latencyMs! - mean) ** 2, 0) / good.length) : null,
      lossPercent: samples ? values.reduce((sum, value) => sum + value.lossPercent * value.samples, 0) / samples : 100,
      approximate: good.some((value) => value.approximate), method: good.some((value) => value.method === "ttl-hop") ? "ttl-hop" : last.method };
  }
}
export type FlowKind = "match" | "regions" | "service";
export interface FlowObservation { startedAt: number; now: number; sent: number; received: number; distinctTargets: number }
export function classifyFlow(flow: FlowObservation): FlowKind {
  const age = flow.now - flow.startedAt;
  if (age >= GAME_POLICY.matchMinAgeMs && flow.sent / Math.max(1, age / 1000) >= GAME_POLICY.matchPacketsPerSecond
    && flow.received >= GAME_POLICY.matchMinReplies) return "match";
  if (age <= GAME_POLICY.lobbyMaxAgeMs && flow.distinctTargets >= 3 && flow.sent <= 30) return "regions";
  return "service";
}

/** Detect inflation only under replicated upload, then periodically retry copies.
 * UI calls it a suspected upload queue, not a proven ISP diagnosis. */
export class UploadQueueGuard {
  private baseline = Infinity; private inflated = 0; private limitedAt: number | null = null;
  update(latencyMs: number, uploadedBytes: number, copies: number, now: number): boolean {
    if (copies <= 1 && this.limitedAt === null) this.baseline = Math.min(this.baseline, latencyMs);
    this.baseline = Math.min(this.baseline, latencyMs);
    if (this.limitedAt !== null) {
      if (now - this.limitedAt >= GAME_POLICY.uploadRetryMs) { this.limitedAt = null; this.inflated = 0; }
    } else {
      this.inflated = copies > 1 && uploadedBytes > GAME_POLICY.uploadMinReplicatedBytes && latencyMs > this.baseline + GAME_POLICY.uploadInflationMs ? this.inflated + 1 : 0;
      if (this.inflated >= GAME_POLICY.uploadConfirmTicks) this.limitedAt = now;
    }
    return this.limitedAt !== null;
  }
}
