import { compiledServiceRoutes, ServiceRouteRuntime, type ServiceRouteStatus, type ServiceRoutePolicy, type ServiceRouteAuth } from "./serviceRoutes";
import { overrideServiceRoute, probeServiceRoute, probeServiceRouteDns, queryServiceRouteStats } from "./serviceRouteTransport";

/** Owns only routing API overrides; never starts/stops a core or modifies protected-mode settings. */
export class ServiceRouteSession {
  private runtime: ServiceRouteRuntime | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private generation = 0;
  private status: ServiceRouteStatus | null = null;
  private auth: ServiceRouteAuth | undefined;
  private mainExit: string | null = null;
  private suspended = false;
  private policySuspended = false;
  private readonly targets = new Map<string, string>();
  constructor(private readonly report: (status: ServiceRouteStatus) => void) {}
  get active(): boolean { return this.runtime !== null; }
  get snapshot(): ServiceRouteStatus | null { return this.status; }
  get authentication(): ServiceRouteAuth | undefined { return this.auth; }
  get mainExitId(): string | null { return this.mainExit; }
  async queryStats(): Promise<{ uplink: number; downlink: number }> {
    if (!this.auth) throw new Error("Нет активного сервисного API");
    return await queryServiceRouteStats(this.auth);
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
    const ports = new Map(compiled.probes.map((probe) => [probe.tag, probe.port]));
    this.runtime = new ServiceRouteRuntime(compiled.plans,
      async (tag) => { const port = ports.get(tag); return port !== undefined && await probeServiceRoute(port, auth); },
      async (balancer, target) => {
        if (generation !== this.generation) return;
        await overrideServiceRoute(balancer, target, undefined, auth);
        if (generation === this.generation) this.targets.set(balancer, target);
      },
      (routes) => {
        if (generation !== this.generation) return;
        const byId = new Map(routes.map((route) => [route.id, route]));
        this.mainExit = byId.get("__main")?.exitId ?? null;
        const visible = compiled.policy.rules.map((rule) => byId.get(rule.id) ?? { id: rule.id,
          state: "active" as const, exitId: null });
        const previous = this.status ?? compiled.status;
        this.status = { revision: previous.revision, fingerprint: previous.fingerprint, state: visible.some((route) => route.state === "blocked") ? "unavailable" : "applied", routes: visible };
        this.report(this.status);
      },
      async (tag) => { const port = ports.get(tag); return port !== undefined && await probeServiceRouteDns(port, auth, compiled.resolvers ?? []); });
    this.runtime.setSuspended(this.suspended || this.policySuspended);
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
    this.timer = null; this.runtime?.stop(); this.runtime = null; this.targets.clear(); this.status = null; this.auth = undefined; this.mainExit = null; this.policySuspended = false;
  }
  setSuspended(suspended: boolean): void {
    this.suspended = suspended; this.runtime?.setSuspended(suspended || this.policySuspended);
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
