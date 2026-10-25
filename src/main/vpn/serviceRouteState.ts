import { parseServiceRoutePolicy, type ServiceRoutePolicy, type ServiceRouteStatus } from "./serviceRoutes";

type Storage = { get(name: string): Promise<Buffer | null>; put(name: string, value: Uint8Array): Promise<void>; remove(name: string): Promise<void> };
type Entry = { policy: ServiceRoutePolicy; excluded: string[] };
const KEY = "service_routes_good";
const SUBSCRIPTION = /^[A-Za-z0-9._:-]{1,128}$/;

/** Only acknowledged last-good policies reach disk; desired changes stay in memory until applied. */
export class ServiceRouteState {
  private readonly entries = new Map<string, Entry>();
  private readonly desired = new Map<string, ServiceRoutePolicy>();
  private readonly exclusions = new Map<string, Set<string>>();
  private loaded: Promise<void> | null = null;
  private writing: Promise<void> = Promise.resolve();
  private generation = 0;
  constructor(private readonly storage: Storage) {}
  load(): Promise<void> { this.loaded ??= this.read(); return this.loaded; }
  private async read(): Promise<void> {
    const generation = this.generation; const bytes = await this.storage.get(KEY);
    if (!bytes) return;
    try {
      const document: unknown = JSON.parse(bytes.toString());
      if (!record(document) || document.version !== 1 || !Array.isArray(document.subscriptions) || document.subscriptions.length > 32) return;
      const entries = new Map<string, Entry>();
      for (const item of document.subscriptions) {
        if (!record(item) || typeof item.id !== "string" || !SUBSCRIPTION.test(item.id) || entries.has(item.id)
          || !Array.isArray(item.excluded) || item.excluded.length > 512
          || !item.excluded.every((key) => typeof key === "string" && key.length <= 300 && !/[\u0000-\u001f]/.test(key))) return;
        const policy = parseServiceRoutePolicy(item.policy);
        if (!policy) return;
        entries.set(item.id, { policy, excluded: [...item.excluded] as string[] });
      }
      if (generation === this.generation) for (const [id, entry] of entries) {
        this.entries.set(id, entry); this.exclusions.set(id, new Set(entry.excluded));
      }
    } catch { /* A corrupt new-feature cache does not change legacy/protected connectivity. */ }
    finally { bytes.fill(0); }
  }
  good(subscription: string): ServiceRoutePolicy | undefined { return this.entries.get(subscription)?.policy; }
  pending(subscription: string): ServiceRoutePolicy | undefined { return this.desired.get(subscription); }
  enrolled(subscription: string): boolean { return this.entries.has(subscription) || this.desired.has(subscription); }
  excluded(subscription: string, endpoint: string): boolean { return this.exclusions.get(subscription)?.has(endpoint) ?? false; }
  effective(subscription: string, endpoint: string): ServiceRoutePolicy | undefined {
    return this.excluded(subscription, endpoint) ? undefined : this.desired.get(subscription) ?? this.entries.get(subscription)?.policy;
  }
  propose(subscription: string, policy: ServiceRoutePolicy): void {
    if (!SUBSCRIPTION.test(subscription)) throw new Error("Некорректная подписка");
    this.desired.set(subscription, policy);
  }
  discard(subscription: string): void { this.desired.delete(subscription); }
  async classified(subscription: string, endpoint: string, ordinary: boolean): Promise<void> {
    const excluded = new Set(this.exclusions.get(subscription) ?? []);
    if (ordinary) excluded.delete(endpoint); else excluded.add(endpoint);
    this.exclusions.set(subscription, excluded);
    const generation = this.generation;
    await this.enqueue(async () => {
      if (generation !== this.generation) return;
      const entry = this.entries.get(subscription);
      if (!entry) return; // Never persist a desired-but-unapplied policy merely to save an exclusion.
      const currentExclusions = [...(this.exclusions.get(subscription) ?? [])];
      if (JSON.stringify(entry.excluded) === JSON.stringify(currentExclusions)) return;
      const next = new Map(this.entries); next.set(subscription, { ...entry, excluded: currentExclusions });
      await this.write(next, generation);
    });
  }
  async acknowledge(subscription: string, status: ServiceRouteStatus): Promise<ServiceRoutePolicy | undefined> {
    if (status.state !== "applied" && status.state !== "unavailable") return undefined;
    const generation = this.generation;
    return await this.enqueue(async () => {
      if (generation !== this.generation) return undefined;
      const desired = this.desired.get(subscription); const good = this.entries.get(subscription)?.policy;
      const candidate = [desired, good].find((policy) => policy?.fingerprint === status.fingerprint && policy.revision === status.revision);
      if (!candidate) return undefined;
      if (good?.fingerprint !== candidate.fingerprint || good.revision !== candidate.revision) {
        const next = new Map(this.entries);
        next.set(subscription, { policy: candidate, excluded: [...(this.exclusions.get(subscription) ?? [])] });
        await this.write(next, generation);
      }
      if (generation !== this.generation) return undefined;
      if (this.desired.get(subscription) === candidate) this.desired.delete(subscription);
      return candidate;
    });
  }
  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.writing.then(operation);
    this.writing = pending.then(() => {}, () => {});
    return pending;
  }
  private async write(next: Map<string, Entry>, generation: number): Promise<void> {
    if (next.size > 32) throw new Error("Слишком много сохранённых подписок");
    const bytes = Buffer.from(JSON.stringify({ version: 1, subscriptions: [...next].map(([id, entry]) => ({ id, ...entry })) }));
    try {
      if (generation !== this.generation) return;
      await this.storage.put(KEY, bytes);
      if (generation !== this.generation) return;
      this.entries.clear(); for (const [id, entry] of next) this.entries.set(id, entry);
    } finally { bytes.fill(0); }
  }
  async clear(): Promise<void> {
    this.generation += 1; this.entries.clear(); this.desired.clear(); this.exclusions.clear();
    await this.writing; await this.storage.remove(KEY); this.loaded = Promise.resolve();
  }
}
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
