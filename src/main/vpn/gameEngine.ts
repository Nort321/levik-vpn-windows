import type { GameMeasurement, GameNode } from "../../shared/contracts";

// All quality values use milliseconds and percentage points, never fractions.
export const GAME_POLICY = Object.freeze({ window: 60, minimumSamples: 5, jitterWeight: 1.5,
  /** One percent of unprotected loss costs more than a few milliseconds in a match. */
  lossWeightMs: 10, tailWeight: 0.25, maxLossPercent: 25, freshMs: 15_000, expiryMs: 600_000,
  stalePenaltyMsPerSecond: 0.05, nodeProcessingMs: 1, loadWeightMs: 5,
  linkBytesPerSecond: 125_000_000, networkLoadWeightMs: 10, flowLoadWeightMs: 5,
  directProbeIntervalMs: 5_000,
  hysteresisMs: 3, hysteresisRatio: 0.05, extraPathMs: 25, maxCopies: 4,
  /** A copy through another physical entry node is kept even this much slower (raw RTT, TCP
   * carriage included): it is a backup that only has to arrive when the first node's route fails. */
  diverseBackupMs: 60,
  matchMinAgeMs: 5_000, matchPacketsPerSecond: 10, matchMinReplies: 20,
  lobbyMaxAgeMs: 5_000, uploadInflationMs: 15, uploadConfirmTicks: 5, uploadMinReplicatedBytes: 1024, uploadRetryMs: 30_000,
  /** Per-path baseline is the minimum within this window, so it follows real route changes. */
  uploadBaselineWindowMs: 180_000,
  /** Active paths are echoed at 5 Hz while a game plays; the ranking reacts within a second or two. */
  fastPingIntervalMs: 200, fastAlpha: 0.25, fastLossAlpha: 0.1, fastLossWeightMs: 1,
  /** UDP carried in a TCP/HTTP stream stalls for a retransmission on loss. */
  reliablePenaltyMs: 40, winsTieMs: 2,
  /** No reply on any path of a pinned exit for this long: the exit is gone, so the flow is re-decided.
   * A game connection waits longer: re-deciding changes its source address, which ends the match. */
  deadExitMs: 8_000, deadMatchExitMs: 20_000,
  pathSilentMs: 1_500,
  /** A ping-like flow (lobby/relay pings) may move when a measured exit is better by this much. */
  migrateMinGainMs: 5, migrateQuietMs: 10_000,
  /** First packet of a new destination waits for cached B from nodes at most this long. */
  holdMinMs: 40, holdMaxMs: 200, holdMaxPackets: 16 });

export interface Segment extends GameMeasurement { routeKey?: string; region?: string; operator?: string; scope?: "target" | "subnet";
  /** A lower bound (ttl-hop) is timed to this router, not to the server. */
  hop?: string }
export interface DestinationMetric { address: string; port: number; metric: Segment }
export interface ExitCandidate { nodeId: string; state: GameNode["state"]; access: Segment | null;
  egress: DestinationMetric[]; mesh?: Segment; cpuPercent?: number; direct?: Segment; processingNodes?: number;
  networkBytesPerSecond?: number; activeFlows?: number }
export type Confidence = "exact" | "subnet" | "operator" | "region" | "access" | "unavailable";
export type MeasurementEvidence = "endpoint" | "lower-bound" | "access" | "unavailable";
export interface PathEstimate { nodeId: string; latencyMs: number | null; jitterMs: number | null;
  lossPercent: number | null; score: number; confidence: Confidence; evidence: MeasurementEvidence; approximate: boolean; egress: Segment | null;
  /** The score without B: what is known when lower bounds of exits cannot be compared. */
  accessScore: number }
export const subnet24 = (address: string): string => address.split(".").slice(0, 3).join(".") + ".0/24";
/** Ascending order with unknown values last; never produces NaN comparisons. */
export const byLatency = <T extends { latencyMs: number | null }>(a: T, b: T): number => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity) || 0;

/** A lower-bound (ttl-hop) segment is timed by a router's TTL-exceeded reply. Routers rate-limit
 * those replies and every trace packet may hash onto another ECMP path, so a missing reply is
 * not lost game traffic (35–55% observed towards Riot while the path itself lost nothing). */
export const pathLoss = (item: Segment): number => item.method === "ttl-hop" ? 0 : item.lossPercent;

export function combineSegments(segments: Segment[], nodes = 1): Pick<PathEstimate, "latencyMs" | "jitterMs" | "lossPercent"> {
  if (!segments.length || segments.some((item) => item.latencyMs === null)) return { latencyMs: null, jitterMs: null, lossPercent: null };
  return { latencyMs: segments.reduce((sum, item) => sum + item.latencyMs!, nodes * GAME_POLICY.nodeProcessingMs),
    jitterMs: Math.sqrt(segments.reduce((sum, item) => sum + (item.jitterMs ?? 0) ** 2, 0)),
    lossPercent: 100 * (1 - segments.reduce((survival, item) => survival * (1 - pathLoss(item) / 100), 1)) };
}
const tail = (segments: Segment[]): number => GAME_POLICY.tailWeight
  * Math.sqrt(segments.reduce((sum, item) => sum + Math.max(0, (item.p95Ms ?? item.latencyMs ?? 0) - (item.latencyMs ?? 0)) ** 2, 0));
const stale = (segments: Segment[], now: number): number => segments.reduce((sum, item) =>
  sum + Math.max(0, now - item.measuredAt - GAME_POLICY.freshMs) / 1000 * GAME_POLICY.stalePenaltyMsPerSecond, 0);

export function estimateExit(candidate: ExitCandidate, target: { address: string; port: number; routeKey?: string; region?: string },
  sessionRegions: string[] = [], now = Date.now(), anchors: DestinationMetric[] = []): PathEstimate {
  const unavailable: PathEstimate = { nodeId: candidate.nodeId, latencyMs: null, jitterMs: null, lossPercent: null,
    score: Infinity, confidence: "unavailable", evidence: "unavailable", approximate: true, egress: null, accessScore: Infinity };
  if (candidate.state !== "enabled") return unavailable;
  const fresh = (item: Segment): boolean => item.samples >= GAME_POLICY.minimumSamples && item.latencyMs !== null && Number.isFinite(item.latencyMs)
    && now >= item.measuredAt - 5_000 && now - item.measuredAt < GAME_POLICY.expiryMs && pathLoss(item) <= GAME_POLICY.maxLossPercent;
  if (candidate.direct) {
    if (!fresh(candidate.direct)) return unavailable;
    const metric = candidate.direct;
    const score = scoreMetric(metric, now);
    return { nodeId: candidate.nodeId, latencyMs: metric.latencyMs, jitterMs: metric.jitterMs, lossPercent: pathLoss(metric),
      score, confidence: "exact", evidence: metric.method === "ttl-hop" ? "lower-bound" : "endpoint",
      approximate: metric.approximate || metric.method === "ttl-hop", egress: null, accessScore: score };
  }
  if (!candidate.access || !fresh(candidate.access) || (candidate.mesh && !fresh(candidate.mesh))) return unavailable;
  const metrics = candidate.egress.filter((item) => fresh(item.metric));
  // At every level a measurement of the server itself precedes a trace lower bound.
  const endpointFirst = (items: DestinationMetric[]): DestinationMetric | undefined => items.find((item) => item.metric.method !== "ttl-hop") ?? items[0];
  const exact = endpointFirst(metrics.filter((item) => item.address === target.address && item.port === target.port));
  const subnet = endpointFirst(metrics.filter((item) => subnet24(item.address) === subnet24(target.address)));
  // Never infer an operator from numerical IP proximity. A route key must be
  // supplied by the measurement service's observed route/offline database.
  // Region anchors (game data-centre beacons measured continuously by the node)
  // share that route key, so a cold destination already has a measured route.
  const routed = target.routeKey ? [...metrics, ...anchors.filter((item) => fresh(item.metric))] : [];
  const operator = target.routeKey ? endpointFirst(routed.filter((item) => item.metric.routeKey === target.routeKey).sort((a, b) => byLatency(a.metric, b.metric))) : undefined;
  const region = endpointFirst(metrics.filter((item) => item.metric.region && (item.metric.region === target.region || sessionRegions.includes(item.metric.region))));
  const levels = [exact, subnet, operator, region];
  const chosen = levels.find((item) => item && item.metric.method !== "ttl-hop") ?? levels.find(Boolean);
  const confidence: Confidence = !chosen ? "access" : chosen === exact ? (exact.metric.scope === "subnet" || (!exact.metric.scope && exact.metric.approximate && exact.metric.method !== "ttl-hop") ? "subnet" : "exact")
    : chosen === subnet ? "subnet" : chosen === operator ? "operator" : "region";
  // A lower bound of this very server still holds when B comes from a nearby server.
  const bound = [exact, subnet].find((item) => item && item.metric.method === "ttl-hop");
  const egress = chosen && bound && chosen !== bound && chosen.metric.latencyMs! < bound.metric.latencyMs!
    ? { ...chosen.metric, latencyMs: bound.metric.latencyMs, p95Ms: Math.max(chosen.metric.p95Ms ?? 0, bound.metric.latencyMs!) } : chosen?.metric;
  const base = [candidate.access, ...(candidate.mesh ? [candidate.mesh] : [])];
  const segments = [...base, ...(egress ? [egress] : [])];
  const evidence: MeasurementEvidence = !egress ? "access" : segments.some((item) => item.method === "ttl-hop") ? "lower-bound" : "endpoint";
  const nodes = candidate.processingNodes ?? (candidate.mesh ? 2 : 1);
  const load = Math.max(0, Math.min(100, candidate.cpuPercent ?? 0)) / 100 * GAME_POLICY.loadWeightMs
    + Math.min(1, Math.max(0, candidate.networkBytesPerSecond ?? 0) / GAME_POLICY.linkBytesPerSecond) * GAME_POLICY.networkLoadWeightMs
    + Math.min(1, Math.max(0, candidate.activeFlows ?? 0) / 4096) * GAME_POLICY.flowLoadWeightMs;
  const scoreOf = (items: Segment[]): number => {
    const combined = combineSegments(items, nodes);
    return combined.latencyMs! + GAME_POLICY.jitterWeight * (combined.jitterMs ?? 0) + GAME_POLICY.lossWeightMs * (combined.lossPercent ?? 0)
      + tail(items) + stale(items, now) + load;
  };
  return { nodeId: candidate.nodeId, ...combineSegments(segments, nodes), score: scoreOf(segments), confidence, evidence, approximate: true,
    egress: egress ?? null, accessScore: scoreOf(base) };
}
function scoreMetric(metric: Segment, now: number): number {
  return metric.latencyMs! + GAME_POLICY.jitterWeight * (metric.jitterMs ?? 0) + GAME_POLICY.lossWeightMs * pathLoss(metric)
    + tail([metric]) + stale([metric], now);
}

/** Lower bounds of different exits compare only when all end at one router: past it the
 * remaining way to the server is the same. Ending at different routers (a node whose
 * upstream answers one hop and goes silent, another traced up to the server's network),
 * the bounds say nothing about which exit is faster. */
export function comparableBounds(estimates: PathEstimate[]): boolean {
  const bounds = estimates.filter((item) => item.evidence === "lower-bound" && item.nodeId !== "direct" && Number.isFinite(item.score));
  return bounds.length <= 1 || (bounds.every((item) => item.egress?.hop) && new Set(bounds.map((item) => item.egress!.hop)).size === 1);
}

/** Completed measurements precede lower-bound fallback; unknown B cannot win by omitting B.
 * A direct TTL lower bound ends at a router of the user's ISP, a relay one at a router
 * near the node: they are different points, so a direct lower bound is never chosen
 * automatically — only a completed direct measurement or an explicit preference.
 * Incomparable lower bounds are ranked without B, by what is known: A, mesh and load. */
export function chooseExit(estimates: PathEstimate[], previousId: string | null = null, preferredId: string | null = null): PathEstimate | null {
  const tiers: Record<Confidence, number> = { exact: 0, subnet: 1, operator: 2, region: 3, access: 4, unavailable: 5 };
  const evidence: Record<MeasurementEvidence, number> = { endpoint: 0, "lower-bound": 1, access: 2, unavailable: 3 };
  const comparable = comparableBounds(estimates);
  // Incomparable bounds form one tier: an exact bound must not beat a subnet one by depth.
  const tier = (item: PathEstimate): number => evidence[item.evidence] * 10 + (item.evidence === "lower-bound" && !comparable ? 0 : tiers[item.confidence]);
  const rank = (item: PathEstimate): number => item.evidence === "lower-bound" && !comparable ? item.accessScore : item.score;
  const ranked = estimates.filter((item) => Number.isFinite(item.score)
    && (item.nodeId !== "direct" || item.evidence === "endpoint" || item.nodeId === preferredId))
    .sort((a, b) => tier(a) - tier(b) || rank(a) - rank(b));
  const best = ranked.find((item) => item.nodeId === preferredId) ?? ranked[0];
  if (!best) return null;
  const previous = ranked.find((item) => item.nodeId === previousId);
  if (!preferredId && previous && tier(previous) === tier(best)
    && rank(previous) - rank(best) < Math.max(GAME_POLICY.hysteresisMs, rank(previous) * GAME_POLICY.hysteresisRatio)) return previous;
  return best;
}
export interface IngressCandidate { latencyMs: number | null; entryNodeId?: string; rankMs?: number | null; reliable?: boolean; wins?: number }
/** Ranks by the fast estimate when present; a stream transport is a last resort,
 * the second copy prefers an independent entry node, near paths are added. */
export function chooseIngress<T extends IngressCandidate>(paths: T[], protection: boolean, limitedByUpload = false): T[] {
  const rank = (path: T): number => (path.rankMs ?? path.latencyMs ?? Infinity) + (path.reliable ? GAME_POLICY.reliablePenaltyMs : 0);
  const ranked = paths.filter((path) => path.latencyMs !== null).sort((a, b) => {
    const difference = rank(a) - rank(b);
    return Math.abs(difference) < GAME_POLICY.winsTieMs ? (b.wins ?? 0) - (a.wins ?? 0) || difference : difference;
  });
  if (!protection || limitedByUpload) return ranked.slice(0, 1);
  const first = ranked[0]; if (!first) return [];
  const otherNode = (path: T): boolean => path !== first && Boolean(first.entryNodeId && path.entryNodeId && path.entryNodeId !== first.entryNodeId);
  // Copies through one node share its route: one copy always takes another physical node
  // when any reaches the exit, so the match survives that node's route failing.
  const second = ranked.find((path) => otherNode(path) && rank(path) <= rank(first) + GAME_POLICY.extraPathMs)
    ?? ranked.find((path) => otherNode(path) && path.latencyMs! <= first.latencyMs! + GAME_POLICY.diverseBackupMs)
    ?? ranked[1];
  const selected = [first, ...(second ? [second] : [])];
  for (const path of ranked) if (!selected.includes(path) && rank(path) <= rank(first) + GAME_POLICY.extraPathMs && selected.length < GAME_POLICY.maxCopies) selected.push(path);
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
/** Exponentially smoothed RTT, jitter and loss of one path, for live ingress ranking. */
export class FastQuality {
  private latency: number | null = null; private jitter = 0; private loss = 0; private last: number | null = null;
  push(latency: number | null): void {
    this.loss += GAME_POLICY.fastLossAlpha * ((latency === null ? 100 : 0) - this.loss);
    if (latency === null) return;
    if (this.last !== null) this.jitter += GAME_POLICY.fastAlpha * (Math.abs(latency - this.last) - this.jitter);
    this.latency = this.latency === null ? latency : this.latency + GAME_POLICY.fastAlpha * (latency - this.latency);
    this.last = latency;
  }
  get rankMs(): number | null {
    return this.latency === null ? null : this.latency + 2 * this.jitter + this.loss * GAME_POLICY.fastLossWeightMs;
  }
  get latencyMs(): number | null { return this.latency; }
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
 * The baseline belongs to one path (its key) and is the minimum of a sliding window:
 * a different exit or a lasting route change is never mistaken for a queue.
 * If one copy does not bring the latency down, duplication was not the cause and
 * the guard stays quiet for a whole window. UI calls it a suspected upload queue. */
export class UploadQueueGuard {
  private key: string | null = null; private readonly samples: Array<{ at: number; latency: number }> = [];
  private inflated = 0; private limitedAt: number | null = null; private limitedMin = Infinity; private quietUntil = -Infinity;
  update(key: string, latencyMs: number, uploadedBytes: number, copies: number, now: number): boolean {
    if (key !== this.key) { this.key = key; this.samples.length = 0; this.inflated = 0; this.limitedAt = null; this.limitedMin = Infinity; this.quietUntil = -Infinity; }
    while (this.samples.length && now - this.samples[0]!.at > GAME_POLICY.uploadBaselineWindowMs) this.samples.shift();
    const baseline = Math.min(latencyMs, ...this.samples.map((item) => item.latency));
    this.samples.push({ at: now, latency: latencyMs }); if (this.samples.length > 600) this.samples.shift();
    if (this.limitedAt !== null) {
      this.limitedMin = Math.min(this.limitedMin, latencyMs);
      if (now - this.limitedAt >= GAME_POLICY.uploadRetryMs) {
        if (this.limitedMin > baseline + GAME_POLICY.uploadInflationMs) this.quietUntil = now + GAME_POLICY.uploadBaselineWindowMs;
        this.limitedAt = null; this.inflated = 0; this.limitedMin = Infinity;
      }
    } else if (now >= this.quietUntil) {
      this.inflated = copies > 1 && uploadedBytes > GAME_POLICY.uploadMinReplicatedBytes && latencyMs > baseline + GAME_POLICY.uploadInflationMs ? this.inflated + 1 : 0;
      if (this.inflated >= GAME_POLICY.uploadConfirmTicks) this.limitedAt = now;
    }
    return this.limitedAt !== null;
  }
}
