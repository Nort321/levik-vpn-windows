import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { TunnelServer } from "../../shared/contracts";
import { extractServerEndpoint } from "./serverPinger";

import type { ServiceRoutePolicy, ServiceRouteTarget, ServiceRouteFallback, ServiceRouteRule, ServiceRouteExit, ServiceRouteSelection, ServiceRouteStatus } from "../../shared/serviceRoutes";
export type * from "../../shared/serviceRoutes";

const ID = /^[A-Za-z0-9._:-]{1,100}$/;
const COUNTRY = /^[A-Z]{2}$/;
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const PROTOCOL = /^[a-z0-9-]{1,24}$/;

export function parseServiceRoutePolicy(value: unknown): ServiceRoutePolicy | undefined {
  if (value === undefined) return undefined;
  const invalid = (): never => { throw new Error("Некорректная политика сервисных маршрутов"); };
  if (!record(value) || value.version !== 1 || !Number.isSafeInteger(value.revision) || Number(value.revision) < 0
    || typeof value.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(value.fingerprint)
    || !Array.isArray(value.rules) || value.rules.length > 500 || !Array.isArray(value.exits) || value.exits.length > 64) return invalid();
  const ruleIds = new Set<string>();
  const rules = value.rules.map((rule): ServiceRouteRule => {
    if (!record(rule) || typeof rule.id !== "string" || (rule.id.length < 1 || rule.id.length > 160 || /[\u0000-\u001f]/.test(rule.id)) || ruleIds.has(rule.id)
      || typeof rule.label !== "string" || rule.label.length > 300 || /[\u0000-\u001f]/.test(rule.label)
      || !["domain", "service", "category", "preset"].includes(String(rule.source))
      || !Array.isArray(rule.domains) || rule.domains.length === 0 || rule.domains.length > 500
      || !rule.domains.every(validDomain) || !record(rule.route) || !record(rule.fallback)) return invalid();
    const route = parseTarget(rule.route); const fallback = parseFallback(rule.fallback);
    if (!route || !fallback) return invalid();
    ruleIds.add(rule.id);
    return { id: rule.id, label: rule.label, source: rule.source as ServiceRouteRule["source"],
      domains: [...rule.domains] as string[], route, fallback };
  });
  const exitIds = new Set<string>(); const endpointOwners = new Map<string, string>();
  const exits = value.exits.map((exit): ServiceRouteExit => {
    if (!record(exit) || typeof exit.exitId !== "string" || !ID.test(exit.exitId) || exitIds.has(exit.exitId)
      || typeof exit.name !== "string" || exit.name.length < 1 || exit.name.length > 128 || /[\u0000-\u001f]/.test(exit.name)
      || typeof exit.countryCode !== "string" || !COUNTRY.test(exit.countryCode)
      || exit.role !== "ordinary" || !["enabled", "draining", "disabled"].includes(String(exit.state))
      || !Array.isArray(exit.endpoints) || exit.endpoints.length === 0 || exit.endpoints.length > 32) return invalid();
    const endpoints = exit.endpoints.map((endpoint): ServiceRouteExit["endpoints"][number] => {
      if (!record(endpoint) || typeof endpoint.address !== "string" || !validAddress(endpoint.address)
        || !Number.isInteger(endpoint.port) || Number(endpoint.port) < 1 || Number(endpoint.port) > 65535
        || typeof endpoint.protocol !== "string" || !PROTOCOL.test(endpoint.protocol)) return invalid();
      const item = { address: normalizeAddress(endpoint.address), port: Number(endpoint.port), protocol: endpoint.protocol };
      const key = endpointKey(item); const owner = endpointOwners.get(key);
      if (owner && owner !== exit.exitId) return invalid();
      endpointOwners.set(key, exit.exitId as string);
      return item;
    });
    exitIds.add(exit.exitId);
    return { exitId: exit.exitId, name: exit.name, countryCode: exit.countryCode,
      role: "ordinary", state: exit.state as ServiceRouteExit["state"], endpoints };
  });
  return { version: 1, revision: Number(value.revision), fingerprint: value.fingerprint, rules, exits };
}

function parseTarget(value: Record<string, unknown>): ServiceRouteTarget | null {
  const kind = value.kind;
  if (kind === "default" || kind === "direct" || kind === "main") return { kind };
  if (kind === "country" && typeof value.countryCode === "string" && COUNTRY.test(value.countryCode)) return { kind, countryCode: value.countryCode };
  if (kind === "exit" && typeof value.exitId === "string" && ID.test(value.exitId)) return { kind, exitId: value.exitId };
  return null;
}
function parseFallback(value: Record<string, unknown>): ServiceRouteFallback | null {
  const kind = value.kind;
  if (kind === "block" || kind === "direct" || kind === "main") return { kind };
  if (kind === "country" && typeof value.countryCode === "string" && COUNTRY.test(value.countryCode)) return { kind, countryCode: value.countryCode };
  return null;
}
function validDomain(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 1024 || /[\u0000-\u001f]/.test(value)) return false;
  if (value.startsWith("full:")) return HOST.test(value.slice(5)) && value.slice(5).includes(".");
  if (value.startsWith("domain:")) return HOST.test(value.slice(7));
  // Server-generated RE2 expressions implement masks. They are never executed as JavaScript.
  return value.startsWith("regexp:^") && value.endsWith("$") && value.length > 10;
}
function validAddress(value: string): boolean {
  const normalized = normalizeAddress(value);
  return normalized.length > 0 && normalized.length <= 253 && !/[\s\u0000-\u001f/@?#]/.test(normalized)
    && (HOST.test(normalized) || /^[0-9a-f:]+$/i.test(normalized));
}
function normalizeAddress(value: string): string { return value.toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, ""); }
function endpointKey(value: { address: string; port: number; protocol: string }): string {
  return `${value.protocol === "hysteria2" || value.protocol === "hy2" ? "hysteria" : value.protocol}|${normalizeAddress(value.address)}|${value.port}`;
}
export function serviceServerKey(server: TunnelServer): string | null {
  const endpoint = extractServerEndpoint(server.outbound);
  return endpoint ? endpointKey({ address: endpoint.host, port: endpoint.port, protocol: hasTuic(server) ? "tuic" : String(server.outbound.protocol) }) : null;
}
export function serviceExitForServer(policy: ServiceRoutePolicy, server: TunnelServer): ServiceRouteExit | null {
  const endpoint = extractServerEndpoint(server.outbound);
  if (!endpoint) return null;
  const key = endpointKey({ address: endpoint.host, port: endpoint.port, protocol: hasTuic(server) ? "tuic" : String(server.outbound.protocol) });
  return policy.exits.find((exit) => exit.role === "ordinary" && exit.endpoints.some((item) => endpointKey(item) === key)) ?? null;
}
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }

/** Probe-derived health controls only its own balancer; no tunnel lifecycle calls. */
export type RouteRuntimePlan = { id: string; balancerTag: string; primary: string[]; fallback: string[]; finalTag: string;
  exits: Readonly<Record<string, string>>; primaryRef?: string; fallbackRef?: string; requireDns?: boolean };
export class ServiceRouteRuntime {
  private readonly health = new Map<string, { healthy: boolean; failures: number; successes: number; down: boolean }>();
  private readonly dnsHealth = new Map<string, { healthy: boolean; failures: number; successes: number; down: boolean }>();
  private readonly current = new Map<string, { tag: string; fallback: boolean; since: number }>();
  private stopped = false;
  private suspended = false;
  private generation = 0;
  private updating = false;
  constructor(private readonly plans: readonly RouteRuntimePlan[], private readonly probe: (tag: string) => Promise<boolean>,
    private readonly override: (balancer: string, target: string) => Promise<void>,
    private readonly onChange: (routes: ServiceRouteSelection[]) => void = () => {},
    private readonly dnsProbe?: (tag: string) => Promise<boolean>, private readonly clock: () => number = Date.now) {
    const main = plans.find((plan) => plan.id === "__main"); const selected = main?.primary[0];
    if (main && selected) {
      // Config starts main on the selected ordinary exit; a first failed canary cannot globally block it.
      this.health.set(selected, { healthy: true, failures: 0, successes: 0, down: false });
      this.current.set(main.id, { tag: selected, fallback: false, since: this.clock() });
    }
  }
  private recordHealth(map: Map<string, { healthy: boolean; failures: number; successes: number; down: boolean }>, tag: string, passed: boolean): void {
    const previous = map.get(tag); const failures = passed ? 0 : (previous?.failures ?? 0) + 1;
    const successes = passed ? (previous?.successes ?? 0) + 1 : 0;
    const down = Boolean(previous?.down || failures >= 3);
    const healthy = passed ? !down || successes >= 2 : Boolean(previous?.healthy && failures < 3);
    map.set(tag, { healthy, failures, successes, down: down && !healthy });
  }
  stop(): void { this.stopped = true; this.generation += 1; }
  setSuspended(suspended: boolean): void { this.suspended = suspended; this.generation += 1; }
  async refresh(): Promise<void> {
    if (this.stopped || this.suspended || this.updating) return;
    const generation = this.generation;
    this.updating = true;
    try {
      const candidates = [...new Set(this.plans.flatMap((plan) => [...plan.primary, ...plan.fallback]))];
      await Promise.all(candidates.map(async (tag) => {
        const healthy = await this.probe(tag).catch(() => false);
        if (generation !== this.generation) return;
        this.recordHealth(this.health, tag, healthy);
        const dnsHealthy = healthy && (this.dnsProbe ? await this.dnsProbe(tag).catch(() => false) : true);
        if (generation !== this.generation) return;
        this.recordHealth(this.dnsHealth, tag, dnsHealthy);
      }));
      if (this.stopped || this.suspended || generation !== this.generation) return;
      for (const plan of this.plans) {
        const prior = this.current.get(plan.id);
        const available = (tag: string): boolean => this.health.get(tag)?.healthy === true && (!plan.requireDns || this.dnsHealth.get(tag)?.healthy === true);
        // A healthy selected server stays selected; a recovered primary does not bounce a live session.
        const referenced = plan.primaryRef ? this.current.get(plan.primaryRef)?.tag : plan.fallbackRef && prior?.fallback ? this.current.get(plan.fallbackRef)?.tag : undefined;
        const retained = prior && (available(prior.tag) || prior.tag === plan.finalTag && plan.finalTag !== "levik-block")
          && (!referenced || prior.tag === referenced) ? prior : null;
        const primary = plan.primaryRef ? this.current.get(plan.primaryRef)?.tag : plan.primary.find(available);
        const fallback = plan.fallbackRef ? this.current.get(plan.fallbackRef)?.tag : plan.fallback.find(available);
        const healthyPrimary = primary && available(primary) ? primary : undefined;
        const healthyFallback = fallback && available(fallback) ? fallback : undefined;
        const recovered = retained?.fallback && healthyPrimary && retained.tag !== healthyPrimary
          && (this.health.get(healthyPrimary)?.successes ?? 0) >= 2
          && (!plan.requireDns || (this.dnsHealth.get(healthyPrimary)?.successes ?? 0) >= 2)
          && this.clock() - retained.since >= 30000;
        const selected = recovered ? { tag: healthyPrimary, fallback: false, since: this.clock() } : retained
          ?? (healthyPrimary ? { tag: healthyPrimary, fallback: false, since: this.clock() } : healthyFallback
          ? { tag: healthyFallback, fallback: true, since: this.clock() } : { tag: plan.finalTag, fallback: plan.finalTag !== "levik-block", since: this.clock() });
        if (prior?.tag === selected.tag && prior.fallback === selected.fallback) continue;
        await this.override(plan.balancerTag, selected.tag);
        if (this.stopped || this.suspended || generation !== this.generation) return;
        this.current.set(plan.id, selected);
      }
      this.onChange(this.plans.map((plan) => {
        const current = this.current.get(plan.id);
        return { id: plan.id, state: !current || current.tag === "levik-block" ? "blocked"
          : current.fallback ? "fallback" : "active", exitId: current ? plan.exits[current.tag] ?? null : null };
      }));
    } finally { this.updating = false; }
  }
}

export const SERVICE_PROBE_BASE_PORT = 47200;
export const SERVICE_MAIN_BALANCER = "levik-service-main";
export type ServiceRouteAuth = { port: number; user: string; password: string };
export type CompiledServiceRoutes = { auth?: ServiceRouteAuth; resolvers?: string[]; policy: ServiceRoutePolicy; status: ServiceRouteStatus; plans: RouteRuntimePlan[];
  probes: Array<{ tag: string; port: number }> };
const compiledPolicies = new WeakMap<Record<string, unknown>, CompiledServiceRoutes>();
export function compiledServiceRoutes(config: Record<string, unknown>): CompiledServiceRoutes | undefined { return compiledPolicies.get(config); }

/** Leaves legacy/protected configs identical. Only proven ordinary endpoints enter the new core path. */
export function withServiceRoutes(base: Record<string, unknown>, input: {
  policy: ServiceRoutePolicy | undefined; selected: TunnelServer; servers: TunnelServer[]; gameOnly?: boolean | undefined;
  automaticServer: boolean; applicationFilterUnsupported?: boolean; bootstrapEndpoints?: boolean; onlyProcesses?: readonly string[]; insertionIndex?: number; directTag: string; prepareOutbound: (server: TunnelServer) => Record<string, unknown>;
}): Record<string, unknown> {
  const { policy } = input;
  if (!policy) return base;
  const status: ServiceRouteStatus = { revision: policy.revision, fingerprint: policy.fingerprint, state: "pending", routes: [] };
  const inactive = (state: ServiceRouteStatus["state"], detail?: string): Record<string, unknown> => {
    compiledPolicies.set(base, { policy, status: { ...status, state, ...(detail ? { detail } : {}) }, plans: [], probes: [] });
    return base;
  };
  if (!serviceExitForServer(policy, input.selected) || input.gameOnly) return inactive("suspended", "excluded_mode");
  if (!policy.rules.length) return inactive("applied");
  if (input.applicationFilterUnsupported) return inactive("unsupported", "app_filter_unsupported");
  if (input.onlyProcesses && input.onlyProcesses.length === 0) return inactive("unsupported", "no_included_apps");
  if (hasTuic(input.selected)) return inactive("unsupported", "unsupported_transport");
  const candidates = input.servers.filter((server) => !hasTuic(server) && serviceExitForServer(policy, server)?.state === "enabled");
  const selectedExit = serviceExitForServer(policy, input.selected)!;
  const ordered = [...(selectedExit.state === "enabled" ? [input.selected] : []), ...candidates.filter((server) => server.id !== input.selected.id)]
    .filter((server, index, list) => list.findIndex((other) => other.id === server.id) === index);
  if (ordered.length > 32) return inactive("unsupported", "route_limit");
  const candidateTags = new Map<string, string>();
  const candidateExits: Record<string, string> = {};
  const probes = ordered.map((server, index) => {
    const tag = `levik-service-endpoint-${index}`;
    candidateTags.set(server.id, tag);
    candidateExits[tag] = serviceExitForServer(policy, server)!.exitId;
    return { tag, port: SERVICE_PROBE_BASE_PORT + index };
  });
  const byExit = (exitId: string): string[] => ordered.filter((server) => serviceExitForServer(policy, server)?.exitId === exitId)
    .map((server) => candidateTags.get(server.id)!);
  const byCountry = (country: string): string[] => ordered.filter((server) => serviceExitForServer(policy, server)?.countryCode === country)
    .map((server) => candidateTags.get(server.id)!);
  const primaryMain = byExit(selectedExit.exitId);
  const otherMain = input.automaticServer ? ordered.filter((server) => serviceExitForServer(policy, server)?.exitId !== selectedExit.exitId)
    .map((server) => candidateTags.get(server.id)!) : [];
  const plans: RouteRuntimePlan[] = [{ id: "__main", balancerTag: SERVICE_MAIN_BALANCER, primary: primaryMain,
    fallback: otherMain, finalTag: "levik-block", exits: candidateExits }];
  const auth: ServiceRouteAuth = { port: 47187, user: "levik-service", password: randomBytes(24).toString("hex") };
  const config = structuredClone(base);
  const outbounds: Record<string, unknown>[] = Array.isArray(config.outbounds) ? config.outbounds.filter(record) : [];
  const selectedIndex = outbounds.findIndex((outbound) => outbound.tag === input.selected.tag);
  if (selectedIndex < 0 || !record(config.routing) || !Array.isArray(config.routing.rules) || !record(config.dns)
    || !Array.isArray(config.inbounds)) return inactive("error", "config_invalid");
  const nativeSelected = outbounds[selectedIndex]!;
  // All old selected-tag references, including default dispatch and health, now resolve through the ordinary-only main balancer.
  outbounds[selectedIndex] = { tag: input.selected.tag, protocol: "loopback", settings: { inboundTag: "levik-service-main-in" } };
  outbounds.push(...ordered.map((server, index) => ({ ...(server.id === input.selected.id ? nativeSelected : input.prepareOutbound(server)), tag: probes[index]!.tag })));
  const oldRules = config.routing.rules.filter(record);
  const dispatchRules: Record<string, unknown>[] = [
    { type: "field", inboundTag: ["levik-service-api-in"], outboundTag: "levik-api" },
    { type: "field", inboundTag: ["levik-service-main-in"], balancerTag: SERVICE_MAIN_BALANCER },
    ...probes.map((probe) => ({ type: "field", inboundTag: [`${probe.tag}-probe`], outboundTag: probe.tag })),
  ];
  const userRules: Record<string, unknown>[] = [];
  const dnsServers: Record<string, unknown>[] = [];
  const baseDns = config.dns.servers;
  const defaultDns = Array.isArray(baseDns) ? baseDns : [];
  const isBootstrap = (value: unknown): boolean => record(value) && typeof value.address === "string"
    && value.address.includes("+local://") && Array.isArray(value.domains) && value.domains.length > 0;
  const resolverAddresses = defaultDns.filter((resolver) => !isBootstrap(resolver)).map((resolver) => typeof resolver === "string"
    ? resolver : record(resolver) && typeof resolver.address === "string" ? resolver.address : "");
  const routeResolver = (address: string): string => isIP(address) ? `tcp://${address.includes(":") ? `[${address}]` : address}` : address;
  const healthResolvers = resolverAddresses.map(routeResolver);
  if (!healthResolvers.length || healthResolvers.some((address) => !/^(?:https|tcp):\/\//.test(address))) return inactive("unsupported", "unsupported_dns");
  let needsDefaultLoopback = false;
  policy.rules.forEach((rule, index) => {
    const balancerTag = `levik-service-rule-${index}`;
    const dnsTag = `${balancerTag}-dns`;
    const data: Record<string, unknown> = { type: "field", inboundTag: ["levik-tun-in"], domain: rule.domains,
      ...(input.onlyProcesses ? { process: [...input.onlyProcesses] } : {}) };
    const dns: Record<string, unknown> = { type: "field", inboundTag: [dnsTag] };
    if (rule.route.kind === "default") {
      needsDefaultLoopback = true;
      data.outboundTag = "levik-service-default";
      dns.balancerTag = SERVICE_MAIN_BALANCER;
    } else if (rule.route.kind === "direct") { data.outboundTag = input.directTag; dns.outboundTag = input.directTag; }
    else {
      const primary = rule.route.kind === "main" ? primaryMain
        : rule.route.kind === "country" ? byCountry(rule.route.countryCode!) : byExit(rule.route.exitId!);
      const fallback = rule.fallback.kind === "country" ? byCountry(rule.fallback.countryCode!)
        : rule.fallback.kind === "main" ? [...primaryMain, ...otherMain] : [];
      plans.push({ id: rule.id, balancerTag, primary, fallback: fallback.filter((tag) => !primary.includes(tag)),
        finalTag: rule.fallback.kind === "direct" ? input.directTag : "levik-block", exits: candidateExits, requireDns: true,
        ...(rule.route.kind === "main" ? { primaryRef: "__main" } : {}),
        ...(rule.fallback.kind === "main" ? { fallbackRef: "__main" } : {}) });
      data.balancerTag = balancerTag; dns.balancerTag = balancerTag;
    }
    userRules.push(data); if (rule.route.kind !== "default") dispatchRules.push(dns);
    // Keep the user's resolver/provider; constrain every resolver in this route to the same egress.
    const resolvers = defaultDns.filter((resolver) => !isBootstrap(resolver));
    resolvers.forEach((resolver, resolverIndex) => {
      const server = typeof resolver === "string" ? { address: resolver } : record(resolver) ? resolver : null;
      if (!server) return;
      dnsServers.push({ ...server, address: rule.route.kind === "default" || rule.route.kind === "direct" ? server.address : routeResolver(String(server.address)), domains: rule.domains, tag: rule.route.kind === "default" ? String(config.dns && record(config.dns) ? config.dns.tag ?? "levik-dns" : "levik-dns") : dnsTag,
        skipFallback: true, finalQuery: resolverIndex === resolvers.length - 1 });
    });
  });
  if (needsDefaultLoopback) outbounds.push({ tag: "levik-service-default", protocol: "loopback", settings: { inboundTag: "levik-service-default-in" } });
  const at = oldRules.findIndex((rule) => Array.isArray(rule.domain));
  const insertion = input.insertionIndex !== undefined && Number.isInteger(input.insertionIndex)
    && input.insertionIndex >= 0 && input.insertionIndex <= oldRules.length ? input.insertionIndex : at < 0 ? oldRules.length : at;
  config.routing.rules = [...dispatchRules, ...oldRules.slice(0, insertion), ...userRules, ...oldRules.slice(insertion)];
  const existingBalancers = Array.isArray(config.routing.balancers) ? config.routing.balancers : [];
  config.routing.balancers = [...existingBalancers, ...plans.map((plan) => ({ tag: plan.balancerTag,
    selector: [plan.id === "__main" && primaryMain[0] ? primaryMain[0] : "levik-block"], strategy: { type: "random" } }))];
  config.outbounds = outbounds;
  config.inbounds = [...config.inbounds.map((inbound: unknown) => record(inbound) && inbound.protocol === "http"
    ? { ...inbound, settings: { ...(record(inbound.settings) ? inbound.settings : {}), accounts: [{ user: auth.user, pass: auth.password }] } } : inbound), ...probes.map((probe) => ({ tag: `${probe.tag}-probe`, listen: "127.0.0.1",
    port: probe.port, protocol: "http", settings: { allowTransparent: false, accounts: [{ user: auth.user, pass: auth.password }] } })),
    { tag: "levik-service-api-in", listen: "127.0.0.1", port: auth.port, protocol: "http",
      settings: { allowTransparent: false, accounts: [{ user: auth.user, pass: auth.password }] } }];
  // Preserve endpoint/bootstrap DNS ahead of service DNS to avoid tunnelling the exit's own resolution through itself.
  const bootstrap = defaultDns.filter(isBootstrap);
  const rest = defaultDns.filter((server) => !bootstrap.includes(server));
  const endpointNames = [...new Set(ordered.flatMap((server) => { const endpoint = extractServerEndpoint(server.outbound);
    return endpoint && !isIP(endpoint.host) ? [`full:${normalizeAddress(endpoint.host)}`] : []; }))];
  if (input.bootstrapEndpoints !== false && endpointNames.length) bootstrap.unshift({ address: "https+local://1.1.1.1/dns-query", domains: endpointNames, skipFallback: true, finalQuery: true });
  config.dns = { ...config.dns, servers: [...bootstrap, ...dnsServers, ...rest], disableFallbackIfMatch: true };
  if (record(config.api)) { delete config.api.listen; config.api.services = [...new Set([...(Array.isArray(config.api.services) ? config.api.services : []), "RoutingService"])]; }
  compiledPolicies.set(config, { auth, resolvers: healthResolvers, policy, status, plans, probes });
  return config;
}

function hasTuic(server: TunnelServer): boolean { return "tuic" in server && server.tuic !== undefined; }
