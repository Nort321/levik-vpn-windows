import { rankMeasuredRoutes, type RouteMeasurement } from "./routeProbe";

export interface LiveAutoCandidate {
  id: string;
  tag: string;
  port: number;
  routeKey: string;
  path?: readonly string[];
  exitId?: string;
}
export interface LiveAutoControl {
  eligible: boolean;
  state: "healthy" | "degraded" | "overloaded" | "unknown";
  resourceHeadroom: number | null;
  routeId?: string;
}
export interface LiveAutoUpdate {
  currentId: string;
  measurements: Record<string, RouteMeasurement>;
  switched: boolean;
}
export interface LiveAutoDependencies {
  observe: (candidates: readonly LiveAutoCandidate[], transfers: boolean, signal: AbortSignal) => Promise<Record<string, RouteMeasurement>>;
  override: (tag: string) => Promise<void>;
  controls: () => Readonly<Record<string, LiveAutoControl>>;
  canTransfer: () => boolean;
  /** A fresh user-activity check; errors block optimization, not the VPN. */
  canSwitch: () => Promise<boolean>;
  networkKey: () => string | null;
  installedCurrent?: () => string;
  report: (update: LiveAutoUpdate) => void;
  clock?: () => number;
}

export const LIVE_AUTO_LIMITS = {
  intervalMs: 30_000,
  observationMs: 24_000,
  switchGuardMs: 5_000,
  latencyTtlMs: 2 * 60_000,
  bandwidthTtlMs: 5 * 60_000,
  cooldownMs: 5 * 60_000,
  alternatives: 2,
  confirmations: 2,
} as const;

type Bandwidth = { at: number; down: number; up: number };
function positive(value: number | null): value is number { return value !== null && Number.isFinite(value) && value > 0; }
function fresh(value: RouteMeasurement | undefined, now: number): value is RouteMeasurement {
  return value !== undefined && Number.isFinite(value.measuredAt) && now >= value.measuredAt && now - value.measuredAt < LIVE_AUTO_LIMITS.latencyTtlMs;
}
function bodyFailed(value: RouteMeasurement): boolean { return "dataVerified" in value && value.dataVerified === false; }
function confirmed(value: RouteMeasurement | undefined, now: number): value is RouteMeasurement {
  return fresh(value, now) && value.confidence === "measured" && value.targets >= 2 && value.samples >= 4
    && !bodyFailed(value) && value.medianMs !== null && Number.isFinite(value.medianMs) && value.medianMs >= 0
    && value.jitterMs !== null && Number.isFinite(value.jitterMs) && value.jitterMs >= 0
    && Number.isFinite(value.failureRate) && value.failureRate >= 0 && value.failureRate <= 0.2;
}
function failed(value: RouteMeasurement | undefined, now: number): boolean {
  return fresh(value, now) && (value.confidence === "failed" || bodyFailed(value));
}
function delayCost(value: RouteMeasurement): number {
  return (value.medianMs ?? Infinity) + (value.jitterMs ?? 0) + value.failureRate * 1000;
}
function improves(current: RouteMeasurement, candidate: RouteMeasurement): boolean {
  const oldDelay = delayCost(current), newDelay = delayCost(candidate);
  const latency = newDelay <= oldDelay * 0.8 && oldDelay - newDelay >= 10;
  let bandwidth = false;
  if (positive(current.downMbps) && positive(current.upMbps) && positive(candidate.downMbps) && positive(candidate.upMbps)) {
    const downBest = Math.max(current.downMbps, candidate.downMbps), upBest = Math.max(current.upMbps, candidate.upMbps);
    const oldFitness = Math.min(current.downMbps / downBest, current.upMbps / upBest);
    const newFitness = Math.min(candidate.downMbps / downBest, candidate.upMbps / upBest);
    bandwidth = newFitness >= oldFitness * 1.25 && newDelay <= oldDelay * 1.1 + 10;
  }
  return latency || bandwidth;
}

/**
 * Owns decisions for one immutable live-core candidate set. It never owns the
 * core/TUN/native helper lifecycle. The supplied override must be serialized by
 * the same coordinator that owns main-route health and manual changes.
 */
export class SmartAutoLiveRuntime {
  private readonly candidates: readonly LiveAutoCandidate[];
  private readonly byId: ReadonlyMap<string, LiveAutoCandidate>;
  private readonly clock: () => number;
  private current: string;
  private timer: ReturnType<typeof setInterval> | null = null;
  private inFlight: Promise<void> | null = null;
  private abort: AbortController | null = null;
  private stopped = false;
  private suspended = false;
  private epoch = 0;
  private haveNetwork = false;
  private network: string | null = null;
  private rotation = 0;
  private pending: { id: string; wins: number } | null = null;
  private failures = 0;
  private overloads = 0;
  private lastSwitchAt: number | null = null;
  private lastTransferAt: number | null = null;
  private readonly observations = new Map<string, RouteMeasurement>();
  private readonly bandwidth = new Map<string, Bandwidth>();
  private readonly routeIds = new Map<string, string>();
  private checkAfterFlight = false;

  constructor(candidates: readonly LiveAutoCandidate[], currentId: string, private readonly deps: LiveAutoDependencies) {
    if (!candidates.length || candidates.length > 64 || new Set(candidates.map((candidate) => candidate.id)).size !== candidates.length
      || candidates.some((candidate) => !candidate.id || candidate.id.length > 160 || !/^[A-Za-z0-9_.-]{1,127}$/.test(candidate.tag)
        || !Number.isInteger(candidate.port) || candidate.port < 1024 || candidate.port > 65535 || !candidate.routeKey || candidate.routeKey.length > 256)) {
      throw new Error("Invalid live Smart Auto candidates");
    }
    this.candidates = candidates.map((candidate) => ({ ...candidate, ...(candidate.path ? { path: [...candidate.path] } : {}) }));
    this.byId = new Map(this.candidates.map((candidate) => [candidate.id, candidate]));
    if (!this.byId.has(currentId)) throw new Error("Initial live Smart Auto route is unavailable");
    this.current = currentId;
    this.clock = deps.clock ?? Date.now;
  }

  get currentId(): string { return this.current; }

  start(): void {
    if (this.stopped || this.timer !== null) return;
    this.timer = setInterval(() => { void this.refresh(); }, LIVE_AUTO_LIMITS.intervalMs);
    this.timer.unref?.();
    void this.refresh();
  }

  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    this.invalidate();
  }

  setSuspended(suspended: boolean): void {
    if (this.stopped || this.suspended === suspended) return;
    this.suspended = suspended;
    this.invalidate();
    if (!suspended && this.timer !== null) this.requestCheck();
  }

  requestCheck(): void {
    if (this.stopped || this.suspended) return;
    if (this.inFlight) { this.checkAfterFlight = true; return; }
    void this.refresh();
  }

  /** Concurrent callers share one observation and one possible API operation. */
  refresh(): Promise<void> {
    if (this.stopped || this.suspended) return Promise.resolve();
    if (this.inFlight) return this.inFlight;
    const run = Promise.resolve().then(() => this.cycle()).catch(() => {
      // Missing probe/control infrastructure never changes the confirmed target.
      this.pending = null; this.failures = 0; this.overloads = 0;
    }).finally(() => {
      if (this.inFlight !== run) return;
      this.abort = null;
      this.inFlight = null;
      if (this.checkAfterFlight) { this.checkAfterFlight = false; this.requestCheck(); }
    });
    this.inFlight = run;
    return run;
  }

  private invalidate(): void {
    this.epoch++;
    this.abort?.abort();
    this.pending = null; this.failures = 0; this.overloads = 0;
    this.observations.clear(); this.bandwidth.clear();
    this.checkAfterFlight = false;
  }

  private sameEpoch(epoch: number, network: string | null): boolean {
    return !this.stopped && !this.suspended && epoch === this.epoch && this.deps.networkKey() === network;
  }

  /** Missing telemetry cannot turn a previously known physical path into a new path. */
  private synchronizeRoutes(controls: Readonly<Record<string, LiveAutoControl>>): void {
    for (const candidate of this.candidates) {
      const routeId = controls[candidate.id]?.routeId;
      if (!routeId || routeId === this.routeIds.get(candidate.id)) continue;
      this.routeIds.set(candidate.id, routeId);
      this.observations.delete(candidate.id); this.bandwidth.delete(candidate.id);
      if (candidate.id === this.current || candidate.id === this.pending?.id) this.pending = null;
      if (candidate.id === this.current) { this.failures = 0; this.overloads = 0; }
    }
  }

  private batch(controls: Readonly<Record<string, LiveAutoControl>>): LiveAutoCandidate[] {
    const result = [this.byId.get(this.current)!];
    const alternatives = this.candidates.filter((candidate) => candidate.id !== this.current && controls[candidate.id]?.eligible !== false);
    const challenger = alternatives.find((candidate) => candidate.id === this.pending?.id);
    if (challenger) result.push(challenger);
    for (let count = 0; count < alternatives.length && result.length <= LIVE_AUTO_LIMITS.alternatives; count++) {
      const candidate = alternatives[this.rotation % alternatives.length]!;
      this.rotation = (this.rotation + 1) % alternatives.length;
      if (!result.some((item) => item.id === candidate.id)) result.push(candidate);
    }
    return result;
  }

  private async observe(batch: readonly LiveAutoCandidate[], transfers: boolean, abort: AbortController): Promise<Record<string, RouteMeasurement>> {
    return await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (value?: Record<string, RouteMeasurement>): void => {
        if (settled) return;
        settled = true; clearTimeout(timer); abort.signal.removeEventListener("abort", cancel);
        if (value) resolve(value); else reject(new Error("Live Smart Auto observation cancelled"));
      };
      const cancel = (): void => finish();
      const timer = setTimeout(() => abort.abort(), LIVE_AUTO_LIMITS.observationMs);
      abort.signal.addEventListener("abort", cancel, { once: true });
      if (abort.signal.aborted) { cancel(); return; }
      void Promise.resolve().then(() => this.deps.observe(batch, transfers, abort.signal)).then((value) => finish(value), () => finish());
    });
  }

  private merged(now: number): Record<string, RouteMeasurement> {
    const result: Record<string, RouteMeasurement> = {};
    for (const [id, observation] of this.observations) {
      if (!fresh(observation, now)) { this.observations.delete(id); continue; }
      const speed = this.bandwidth.get(id);
      const recent = speed && now >= speed.at && now - speed.at < LIVE_AUTO_LIMITS.bandwidthTtlMs ? speed : null;
      if (!recent) this.bandwidth.delete(id);
      result[id] = { ...observation, downMbps: recent?.down ?? null, upMbps: recent?.up ?? null };
    }
    return result;
  }

  private async permitSwitch(abort: AbortController): Promise<boolean> {
    return await new Promise((resolve) => {
      let settled = false;
      const finish = (allowed: boolean): void => {
        if (settled) return;
        settled = true; clearTimeout(timer); abort.signal.removeEventListener("abort", cancel);
        resolve(allowed);
      };
      const cancel = (): void => finish(false);
      const timer = setTimeout(cancel, LIVE_AUTO_LIMITS.switchGuardMs);
      abort.signal.addEventListener("abort", cancel, { once: true });
      if (abort.signal.aborted) { cancel(); return; }
      void Promise.resolve().then(() => this.deps.canSwitch()).then((allowed) => finish(allowed === true), () => finish(false));
    });
  }

  private async cycle(): Promise<void> {
    if (this.stopped || this.suspended) return;
    const network = this.deps.networkKey();
    if (!this.haveNetwork || this.network !== network) {
      this.invalidate(); this.haveNetwork = true; this.network = network;
    }
    const installed = this.deps.installedCurrent?.();
    if (installed !== undefined) {
      if (!this.byId.has(installed)) return;
      if (installed !== this.current) {
        this.current = installed; this.pending = null; this.failures = 0; this.overloads = 0;
        this.lastSwitchAt = this.clock();
      }
    }
    const epoch = this.epoch;
    const initial = this.current;
    const controls = this.deps.controls();
    this.synchronizeRoutes(controls);
    const observedRoutes = new Map(this.routeIds);
    const batch = this.batch(controls);
    const now = this.clock();
    const transfers = this.deps.canTransfer() && (this.lastTransferAt === null || now - this.lastTransferAt >= LIVE_AUTO_LIMITS.bandwidthTtlMs);
    if (transfers) this.lastTransferAt = now;
    const abort = new AbortController(); this.abort = abort;
    let observed: Record<string, RouteMeasurement>;
    try { observed = await this.observe(batch, transfers, abort); }
    catch {
      if (this.sameEpoch(epoch, network)) { this.pending = null; this.failures = 0; this.overloads = 0; }
      return;
    }
    if (!this.sameEpoch(epoch, network)) {
      if (!this.stopped && !this.suspended && network !== this.deps.networkKey()) { this.invalidate(); this.network = this.deps.networkKey(); }
      return;
    }
    const at = this.clock();
    const latest = this.deps.controls();
    this.synchronizeRoutes(latest);
    const freshRound: Record<string, RouteMeasurement> = {};
    for (const candidate of batch) {
      if (observedRoutes.get(candidate.id) !== this.routeIds.get(candidate.id)) continue;
      const value = observed[candidate.id];
      if (!fresh(value, at)) continue;
      const copy = { ...value };
      freshRound[candidate.id] = copy; this.observations.set(candidate.id, copy);
      if (transfers && positive(copy.downMbps) && positive(copy.upMbps)) this.bandwidth.set(candidate.id, { at: copy.measuredAt, down: copy.downMbps, up: copy.upMbps });
    }
    const measurements = this.merged(at);
    const currentRound = freshRound[initial];
    const current = measurements[initial];
    this.failures = failed(currentRound, at) ? this.failures + 1 : 0;
    const unavailable = latest[initial]?.state === "overloaded" || latest[initial]?.eligible === false;
    this.overloads = unavailable ? this.overloads + 1 : 0;
    const emergency = this.failures >= LIVE_AUTO_LIMITS.confirmations || this.overloads >= LIVE_AUTO_LIMITS.confirmations;
    const evidenceOfTrouble = failed(currentRound, at) || unavailable;
    const alternatives = batch.filter((candidate) => candidate.id !== initial && latest[candidate.id]?.eligible !== false
      && latest[candidate.id]?.state !== "overloaded" && confirmed(freshRound[candidate.id], at)
      && (evidenceOfTrouble || confirmed(currentRound, at) && current !== undefined && improves(current, measurements[candidate.id]!)))
      .map((candidate) => ({ ...candidate, resourceHeadroom: latest[candidate.id]?.resourceHeadroom ?? null,
        routeDegraded: latest[candidate.id]?.state === "degraded" }));
    const best = rankMeasuredRoutes(alternatives, measurements, at)[0];
    if (!best) this.pending = null;
    else this.pending = { id: best.id, wins: this.pending?.id === best.id ? Math.min(LIVE_AUTO_LIMITS.confirmations, this.pending.wins + 1) : 1 };
    const due = this.lastSwitchAt === null || at - this.lastSwitchAt >= LIVE_AUTO_LIMITS.cooldownMs;
    if (best && this.pending && this.pending.wins >= LIVE_AUTO_LIMITS.confirmations && (due || emergency)) {
      // Even before the cooldown, a single failure/full sample does not prove an emergency.
      if (evidenceOfTrouble && !emergency && !(confirmed(currentRound, at) && current && improves(current, measurements[best.id]!))) return;
      const permitted = await this.permitSwitch(abort);
      if (!this.sameEpoch(epoch, network)) return;
      const commitControls = this.deps.controls();
      this.synchronizeRoutes(commitControls);
      if (!permitted) {
        this.pending = null;
        this.deps.report({ currentId: this.current, measurements: this.merged(this.clock()), switched: false });
        return;
      }
      const control = commitControls[best.id];
      if (observedRoutes.get(initial) !== this.routeIds.get(initial) || observedRoutes.get(best.id) !== this.routeIds.get(best.id)
        || control?.eligible === false || control?.state === "overloaded" || !confirmed(freshRound[best.id], this.clock())) {
        this.pending = null; return;
      }
      try { await this.deps.override(best.tag); } catch { this.pending = null; return; }
      if (!this.sameEpoch(epoch, network) || this.current !== initial) return;
      this.synchronizeRoutes(this.deps.controls());
      this.current = best.id; this.lastSwitchAt = this.clock();
      this.pending = null; this.failures = 0; this.overloads = 0;
      this.deps.report({ currentId: this.current, measurements: this.merged(this.clock()), switched: true });
      return;
    }
    if (this.sameEpoch(epoch, network)) this.deps.report({ currentId: this.current, measurements, switched: false });
  }
}
