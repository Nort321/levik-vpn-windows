import { compiledServiceRoutes, SERVICE_MAIN_BALANCER, ServiceRouteRuntime, type ServiceRouteStatus, type ServiceRoutePolicy, type ServiceRouteAuth } from "./serviceRoutes";
import { overrideServiceRoute, probeServiceRoute, probeServiceRouteDns, queryServiceRouteStatistics } from "./serviceRouteTransport";

import { measureRouteCandidates, openExistingRouteProbe } from "./routeProbe";
import { SmartAutoLiveRuntime, type LiveAutoCandidate, type LiveAutoControl, type LiveAutoUpdate } from "./smartAutoLiveRuntime";
import { SmartAutoActivity } from "./smartAutoActivity";

export interface SmartAutoSessionHooks {
  controls: () => Readonly<Record<string, LiveAutoControl>>;
  canTransfer: () => boolean;
  networkKey: () => string | null;
  report: (update: LiveAutoUpdate) => void;
}

/** Owns only routing API overrides; never starts/stops a core or modifies protected-mode settings. */
export class ServiceRouteSession {
  private runtime: ServiceRouteRuntime | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private generation = 0;
  private status: ServiceRouteStatus | null = null;
  private auth: ServiceRouteAuth | undefined;
  private mainExit: string | null = null;
  private installedMainId: string | null = null;
  private automatic: SmartAutoLiveRuntime | null = null;
  private automaticFactory: (() => SmartAutoLiveRuntime) | null = null;
  private automaticRequested = false;
  private automaticEpoch = 0;
  private mainWrites: Promise<void> = Promise.resolve();
  private mainPending = 0;
  private smartHooks: SmartAutoSessionHooks | undefined;
  private readonly activity: SmartAutoActivity;
  private readonly clock: () => number;
  private usingServicePolicy = false;
  private readonly verifiedBodies = new Map<string, number>();
  private readonly knownRouteIds = new Map<string, string>();
  private bodyNetwork: string | null | undefined;
  private mainContext: { candidates: readonly LiveAutoCandidate[]; publish: (update: LiveAutoUpdate) => void } | null = null;
  private suspended = false;
  private policySuspended = false;
  private readonly targets = new Map<string, string>();
  constructor(private readonly report: (status: ServiceRouteStatus) => void,
    options: { clock?: () => number; activityClock?: () => number } = {}) {
    this.clock = options.clock ?? Date.now;
    this.activity = new SmartAutoActivity(options.activityClock);
  }
  get active(): boolean { return this.runtime !== null && (this.usingServicePolicy || this.smartAutoActive); }
  get snapshot(): ServiceRouteStatus | null { return this.status; }
  get authentication(): ServiceRouteAuth | undefined { return this.auth; }
  get mainExitId(): string | null { return this.mainExit; }
  get mainServerId(): string | null { return this.installedMainId; }
  get smartAutoActive(): boolean { return this.automaticRequested && this.automatic !== null; }
  get automaticAvailable(): boolean { return this.automaticFactory !== null; }
  get policyActive(): boolean { return this.active && this.usingServicePolicy; }
  async probeCurrent(): Promise<boolean> {
    const tag = this.targets.get(SERVICE_MAIN_BALANCER);
    const candidate = this.mainContext?.candidates.find((item) => item.tag === tag);
    return Boolean(candidate && this.auth && await probeServiceRoute(candidate.port, this.auth));
  }
  configureSmartAuto(hooks: SmartAutoSessionHooks): void { this.smartHooks = hooks; }
  /** Hot mode changes preserve the core/TUN and freeze the last acknowledged
   * target. A previously dispatched RPC is serialized before a compensating pin. */
  async setAutomaticEnabled(enabled: boolean): Promise<boolean> {
    if (!this.automaticFactory) return false;
    if (enabled && this.smartAutoActive) return true;
    const generation = this.generation;
    const pin = this.targets.get(SERVICE_MAIN_BALANCER);
    this.automaticRequested = enabled; const epoch = ++this.automaticEpoch;
    this.automatic?.stop(); this.automatic = null; this.activity.reset(); this.verifiedBodies.clear();
    if (!enabled) {
      if (this.mainPending && pin) {
        try { await this.writeMain(pin, generation); }
        catch (error) {
          if (generation === this.generation && this.installedMainId) this.mainContext?.publish({ currentId: this.installedMainId, measurements: {}, switched: true });
          throw error;
        }
      }
      return generation === this.generation && epoch === this.automaticEpoch;
    }
    await this.mainWrites.catch(() => {});
    if (generation !== this.generation || epoch !== this.automaticEpoch || !this.automaticRequested) return false;
    this.automatic = this.automaticFactory();
    this.automatic.setSuspended(this.suspended); this.automatic.start();
    void this.queryStats().catch(() => {});
    return true;
  }

  private writeMain(tag: string, generation: number, epoch?: number): Promise<void> {
    const auth = this.auth;
    const context = this.mainContext;
    if (!auth || !context) return Promise.reject(new Error("Automatic main unavailable"));
    const target = context.candidates.find((candidate) => candidate.tag === tag);
    if (!target) return Promise.reject(new Error("Invalid automatic main target"));
    const controls = this.smartHooks?.controls();
    const network = this.smartHooks?.networkKey() ?? null;
    const sourceId = this.installedMainId;
    const sourceRoute = sourceId ? controls?.[sourceId]?.routeId ?? this.knownRouteIds.get(sourceId) : undefined;
    const targetRoute = controls?.[target.id]?.routeId ?? this.knownRouteIds.get(target.id);
    this.mainPending++;
    const write = this.mainWrites.catch(() => {}).then(async () => {
      if (generation !== this.generation || epoch !== undefined && (epoch !== this.automaticEpoch || !this.automaticRequested)) throw new Error("Automatic selection cancelled");
      if (epoch !== undefined) {
        // Queueing can take time. Read user activity again at the actual write
        // boundary; only an explicit manual compensating pin bypasses this gate.
        await this.queryStats();
        const latest = this.smartHooks?.controls();
        if (generation !== this.generation || epoch !== this.automaticEpoch || !this.automaticRequested || this.suspended
          || (this.smartHooks?.networkKey() ?? null) !== network
          || !this.activity.canSwitch() || !(this.smartHooks?.canTransfer() ?? true)
          || latest?.[target.id]?.eligible === false || latest?.[target.id]?.state === "overloaded"
          || latest?.[target.id]?.routeId !== undefined && latest[target.id]!.routeId !== targetRoute
          || sourceId && latest?.[sourceId]?.routeId !== undefined && latest[sourceId]!.routeId !== sourceRoute) throw new Error("Automatic selection is protected");
      }
      await overrideServiceRoute(SERVICE_MAIN_BALANCER, tag, undefined, auth);
      if (generation !== this.generation) throw new Error("Core changed");
      this.targets.set(SERVICE_MAIN_BALANCER, tag); this.installedMainId = target.id; this.mainExit = target.exitId ?? null;
      this.runtime?.setExternalMain(tag);
      if (epoch === undefined || epoch === this.automaticEpoch && this.automaticRequested) context.publish({ currentId: target.id, measurements: {}, switched: true });
    }).finally(() => { if (generation === this.generation) this.mainPending--; });
    this.mainWrites = write;
    return write;
  }

  async refreshAutomatic(suspectCurrent = false): Promise<void> {
    if (suspectCurrent) {
      const target = this.targets.get(SERVICE_MAIN_BALANCER);
      const candidate = this.mainContext?.candidates.find((item) => item.tag === target);
      if (candidate) this.verifiedBodies.delete(this.bodyProofKey(candidate));
    }
    await this.automatic?.refresh();
  }
  private bodyProofKey(candidate: LiveAutoCandidate): string {
    return `${candidate.routeKey}|${candidate.tag}|${this.knownRouteIds.get(candidate.id) ?? "unmapped"}`;
  }

  private synchronizeRouteIds(candidates: readonly LiveAutoCandidate[]): Map<string, string | undefined> {
    const controls = this.smartHooks?.controls();
    const ids = new Map<string, string | undefined>();
    for (const candidate of candidates) {
      const routeId = controls?.[candidate.id]?.routeId;
      if (routeId !== undefined && routeId !== this.knownRouteIds.get(candidate.id)) {
        this.verifiedBodies.delete(this.bodyProofKey(candidate)); this.knownRouteIds.set(candidate.id, routeId);
      }
      ids.set(candidate.id, this.knownRouteIds.get(candidate.id));
    }
    return ids;
  }
  async queryStats(): Promise<{ uplink: number; downlink: number }> {
    if (!this.auth) throw new Error("Нет активного сервисного API");
    const generation = this.generation;
    try {
      const stats = await queryServiceRouteStatistics(this.auth);
      if (generation !== this.generation) throw new Error("Подключение изменилось");
      if (stats.initialized) this.activity.observe(stats); else this.activity.reset();
      return { uplink: stats.uplink, downlink: stats.downlink };
    } catch (error) { if (generation === this.generation) this.activity.reset(); throw error; }
  }
  selectedTarget(balancerTag: string): string | undefined { return this.targets.get(balancerTag); }
  async start(config: Record<string, unknown>): Promise<void> {
    this.stop();
    const compiled = compiledServiceRoutes(config);
    if (!compiled) return;
    const generation = this.generation;
    this.status = compiled.status;
    this.report(this.status);
    if (!compiled.plans.length || !compiled.auth) return;
    const auth = compiled.auth; this.auth = auth;
    this.usingServicePolicy = compiled.policyActive ?? true;
    const ports = new Map(compiled.probes.map((probe) => [probe.tag, probe.port]));
    this.runtime = new ServiceRouteRuntime(compiled.plans,
      async (tag) => { const port = ports.get(tag); return port !== undefined && await probeServiceRoute(port, auth); },
      async (balancer, target) => {
        if (generation !== this.generation) return;
        // __main belongs only to SmartAuto when present; service rules retain
        // their own health/DNS owner and cannot overwrite ordinary selection.
        if (compiled.automatic && balancer === SERVICE_MAIN_BALANCER) throw new Error("Automatic main has a dedicated owner");
        await overrideServiceRoute(balancer, target, undefined, auth);
        if (generation === this.generation) this.targets.set(balancer, target);
      },
      (routes) => {
        if (generation !== this.generation) return;
        const byId = new Map(routes.map((route) => [route.id, route]));
        this.mainExit = byId.get("__main")?.exitId ?? null;
        if (!this.usingServicePolicy) return;
        const visible = compiled.policy.rules.map((rule) => byId.get(rule.id) ?? { id: rule.id,
          state: "active" as const, exitId: null });
        const previous = this.status ?? compiled.status;
        this.status = { revision: previous.revision, fingerprint: previous.fingerprint, state: visible.some((route) => route.state === "blocked") ? "unavailable" : "applied", routes: visible };
        this.report(this.status);
      },
      async (tag) => { const port = ports.get(tag); return port !== undefined && await probeServiceRouteDns(port, auth, compiled.resolvers ?? []); });
    this.runtime.setSuspended(this.suspended || this.policySuspended);
    if (compiled.automatic) {
      const candidates = compiled.automatic.candidates;
      this.installedMainId = compiled.automatic.selectedId;
      const selected = candidates.find((candidate) => candidate.id === this.installedMainId);
      if (selected) {
        this.targets.set(SERVICE_MAIN_BALANCER, selected.tag); this.mainExit = selected.exitId ?? null;
        this.runtime.setExternalMain(selected.tag);
      }
      const publish = (update: LiveAutoUpdate): void => {
        if (generation !== this.generation) return;
        this.smartHooks?.report(update);
      };
      this.mainContext = { candidates, publish };
      this.automaticFactory = () => {
      const epoch = this.automaticEpoch;
      return new SmartAutoLiveRuntime(candidates, this.installedMainId ?? compiled.automatic!.selectedId, {
        observe: async (pool, transfers, signal) => {
          if (generation !== this.generation) return {};
          const network = this.smartHooks?.networkKey() ?? null;
          if (network !== this.bodyNetwork) { this.verifiedBodies.clear(); this.bodyNetwork = network; }
          const byId = new Map(pool.map((candidate) => [candidate.id, candidate]));
          const snapshot = this.synchronizeRouteIds(pool);
          const verified = (key: string): boolean => { const at = this.verifiedBodies.get(key); return at !== undefined && this.clock() >= at && this.clock() - at < 5 * 60_000; };
          const measurements = await measureRouteCandidates({ executable: "", transfers,
            canTransfer: () => this.activity.canSwitch() && (this.smartHooks?.canTransfer() ?? false),
            candidates: pool.map((candidate) => ({ ...candidate, config: {} })), signal }, {
            open: async (_executable, candidate, childSignal) => {
              if (generation !== this.generation) throw new Error("Подключение изменилось");
              const route = byId.get(candidate.id); if (!route) throw new Error("Маршрут недоступен");
              return await openExistingRouteProbe(route.port, auth, childSignal, { verifyData: !verified(this.bodyProofKey(route)) });
            }, now: this.clock,
          });
          if (generation !== this.generation || signal.aborted) return {};
          const latest = this.synchronizeRouteIds(pool);
          for (const candidate of pool) {
            const measurement = measurements[candidate.id]; if (!measurement) continue;
            if (snapshot.get(candidate.id) !== latest.get(candidate.id)) { delete measurements[candidate.id]; continue; }
            const key = this.bodyProofKey(candidate);
            if (measurement.dataVerified === true) this.verifiedBodies.set(key, measurement.measuredAt);
            else if (measurement.dataVerified === false || measurement.confidence === "failed") this.verifiedBodies.delete(key);
            else if (verified(key)) measurement.dataVerified = true;
          }
          return measurements;
        },
        override: async (tag) => await this.writeMain(tag, generation, epoch),
        installedCurrent: () => this.installedMainId ?? compiled.automatic!.selectedId,
        controls: () => {
          const known = this.smartHooks?.controls();
          return Object.fromEntries(candidates.map((candidate) => [candidate.id, known?.[candidate.id]
            ?? { eligible: known === undefined && compiled.policy.exits.find((exit) => exit.exitId === candidate.exitId)?.state === "enabled",
              state: "unknown" as const, resourceHeadroom: null }]));
        },
        canTransfer: () => this.activity.canSwitch() && (this.smartHooks?.canTransfer() ?? false),
        canSwitch: async () => {
          if (generation !== this.generation || this.suspended) return false;
          try { await this.queryStats(); } catch { return false; }
          return generation === this.generation && !this.suspended && this.activity.canSwitch() && (this.smartHooks?.canTransfer() ?? true);
        },
        networkKey: () => this.smartHooks?.networkKey() ?? null, report: publish, clock: this.clock,
      });
      };
      await this.setAutomaticEnabled(compiled.automatic.enabled);

    }
    await this.refresh();
    if (generation === this.generation) this.timer = setInterval(() => void this.refresh(), 15_000);
  }
  acknowledgeRevision(policy: ServiceRoutePolicy): void {
    if (!this.status || this.status.fingerprint !== policy.fingerprint) return;
    this.status = { ...this.status, revision: policy.revision };
    this.report(this.status);
  }
  stop(): void {
    this.generation += 1;
    if (this.timer) clearInterval(this.timer);
    this.timer = null; this.automatic?.stop(); this.automatic = null; this.automaticFactory = null; this.mainContext = null;
    this.automaticRequested = false; this.automaticEpoch++; this.mainWrites = Promise.resolve(); this.mainPending = 0; this.activity.reset(); this.verifiedBodies.clear(); this.knownRouteIds.clear(); this.bodyNetwork = undefined; this.installedMainId = null; this.usingServicePolicy = false; this.runtime?.stop(); this.runtime = null; this.targets.clear(); this.status = null; this.auth = undefined; this.mainExit = null; this.policySuspended = false;
  }
  setSuspended(suspended: boolean): void {
    this.suspended = suspended; this.automatic?.setSuspended(suspended); this.activity.reset(); this.verifiedBodies.clear(); this.runtime?.setSuspended(suspended || this.policySuspended);
    if (!suspended) void this.refresh();
  }
  setPolicySuspended(suspended: boolean): void {
    this.policySuspended = suspended; this.runtime?.setSuspended(suspended || this.suspended);
    if (!suspended) void this.refresh();
  }
  async refresh(): Promise<void> {
    if (this.suspended || this.policySuspended) return;
    const generation = this.generation;
    try { await this.runtime?.refresh(); }
    catch {
      if (generation !== this.generation || this.suspended || this.policySuspended || !this.status || !this.runtime) return;
      this.status = { ...this.status, state: "error", detail: "routing_unavailable" };
      this.report(this.status);
    }
  }
}
