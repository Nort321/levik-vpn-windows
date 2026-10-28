import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RouteProbeDependencies, RouteProbeSession } from "../src/main/vpn/routeProbe";
import { SERVICE_MAIN_BALANCER, compiledServiceRoutes, rememberAutomaticMain, withServiceRoutes } from "../src/main/vpn/serviceRoutes";
import { ServiceRouteSession } from "../src/main/vpn/serviceRouteSession";
import type { TunnelServer } from "../src/shared/contracts";

vi.mock("../src/main/vpn/serviceRouteTransport", () => ({
  overrideServiceRoute: vi.fn(async () => {}), probeServiceRoute: vi.fn(async () => true), probeServiceRouteDns: vi.fn(async () => true),
  queryServiceRouteStatistics: vi.fn(async () => ({ uplink: 0, downlink: 0, initialized: true })),
}));
vi.mock("../src/main/vpn/routeProbe", async (original) => ({
  ...await original<typeof import("../src/main/vpn/routeProbe")>(),
  openExistingRouteProbe: vi.fn(async (): Promise<RouteProbeSession> => ({ latency: async () => ({ values: [50, 51, 52], failed: 0, setupMs: 10 }), transfer: async () => null, close: async () => {} })),
  measureRouteCandidates: vi.fn(),
}));
import { measureRouteCandidates, openExistingRouteProbe } from "../src/main/vpn/routeProbe";
import { overrideServiceRoute, queryServiceRouteStatistics } from "../src/main/vpn/serviceRouteTransport";

const sessions: ServiceRouteSession[] = [];
beforeEach(() => { vi.clearAllMocks(); vi.mocked(overrideServiceRoute).mockReset().mockResolvedValue(undefined); });
afterEach(() => { sessions.splice(0).forEach((session) => session.stop()); vi.restoreAllMocks(); vi.useRealTimers(); });

function automaticConfig(count = 3, enabled = true) {
  const servers: TunnelServer[] = Array.from({ length: count }, (_, index) => ({ id: `s${index}`, tag: `node-${index}`,
    name: `DE ${index}`, countryCode: "DE", outbound: { tag: `node-${index}`, protocol: "vless", settings: { vnext: [{ address: `node${index}.example`, port: 443 }] } } }));
  const selected = servers[0]!;
  const config = withServiceRoutes({ api: { tag: "levik-api", listen: "127.0.0.1:47185", services: ["StatsService"] },
    dns: { tag: "levik-dns", servers: ["1.1.1.1"] },
    inbounds: [{ tag: "levik-tun-in", protocol: "tun", settings: {} }],
    outbounds: [selected.outbound, { tag: "direct", protocol: "freedom" }],
    routing: { rules: [{ type: "field", domain: ["domain:cloudflare.com"], outboundTag: "direct" }] } },
  { policy: undefined, selected, servers, automaticServer: enabled, directTag: "direct", prepareOutbound: (server) => server.outbound });
  return { config, servers, compiled: compiledServiceRoutes(config)! };
}

async function harness(enabled = true) {
  const env = { now: 1_000_000, uplink: 0, downlink: 0, initialized: true, network: "wifi", routeIds: { s0: "route-a", s1: "route-b", s2: "route-c" } as Record<string, string | undefined> };
  const { config, servers, compiled } = automaticConfig(3, enabled);
  vi.mocked(queryServiceRouteStatistics).mockImplementation(async () => { env.now++; return { uplink: env.uplink, downlink: env.downlink, initialized: env.initialized }; });
  vi.mocked(measureRouteCandidates).mockImplementation(async (options, dependencies) => {
    const result: Awaited<ReturnType<typeof measureRouteCandidates>> = {};
    for (const candidate of options.candidates) {
      const session = await (dependencies as RouteProbeDependencies).open("", candidate, options.signal ?? new AbortController().signal);
      const optionsForBody = vi.mocked(openExistingRouteProbe).mock.calls.at(-1)?.[3];
      await session.close();
      result[candidate.id] = { measuredAt: env.now, confidence: "measured", medianMs: candidate.id === "s0" ? 100 : 50,
        jitterMs: 0, failureRate: 0, targets: 2, samples: 6, setupMs: 10, downMbps: null, upMbps: null,
        ...(optionsForBody?.verifyData ? { dataVerified: true } : {}) };
    }
    return result;
  });
  const report = vi.fn();
  const session = new ServiceRouteSession(vi.fn(), { clock: () => env.now, activityClock: () => env.now }); sessions.push(session);
  session.configureSmartAuto({ controls: () => Object.fromEntries(servers.map((server) => [server.id,
    { eligible: true, state: "healthy" as const, resourceHeadroom: 0.5, ...(env.routeIds[server.id] ? { routeId: env.routeIds[server.id]! } : {}) }])), canTransfer: () => true, networkKey: () => env.network, report });
  await session.start(config); await session.refreshAutomatic();
  const quiet = async (milliseconds = 60_000) => { for (let elapsed = 0; elapsed < milliseconds; elapsed += 2000) { env.now += 2000; await session.queryStats(); } };
  return { env, session, compiled, config, report, quiet };
}

describe("same-core automatic selection", () => {
  it("compiles private candidate probes and one automatic main owner without a service policy or feature flag", () => {
    const { config, compiled } = automaticConfig();
    expect(compiled.automatic?.candidates).toHaveLength(3);
    expect(compiled.policyActive).toBe(false);
    expect(compiled.plans.find((plan) => plan.id === "__main")?.externallyManaged).toBe(true);
    expect(config.api).not.toHaveProperty("listen");
    expect(config.api).toMatchObject({ services: expect.arrayContaining(["RoutingService", "StatsService"]) });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    const privateRule = routing.rules.find((rule) => Array.isArray(rule.inboundTag) && rule.inboundTag.includes("levik-service-endpoint-00-probe"));
    expect(privateRule?.outboundTag).toBe("levik-service-endpoint-00");
    expect(routing.rules.indexOf(privateRule!)).toBeLessThan(routing.rules.findIndex((rule) => Array.isArray(rule.domain)));
  });

  it("keeps selectors exact at startup with twelve or more candidates", () => {
    const { compiled } = automaticConfig(12);
    const tags = compiled.automatic!.candidates.map((candidate) => candidate.tag);
    expect(tags.every((tag) => /levik-service-endpoint-\d{2}$/.test(tag))).toBe(true);
    for (const tag of tags) expect(tags.filter((candidate) => candidate.startsWith(tag))).toEqual([tag]);
  });

  it("changes only the acknowledged main balancer after two wins and a full quiet minute", async () => {
    const h = await harness();
    expect(h.session.mainServerId).toBe("s0");
    expect(overrideServiceRoute).not.toHaveBeenCalled();
    await h.quiet(); await h.session.refreshAutomatic();
    expect(overrideServiceRoute).toHaveBeenCalledTimes(1);
    expect(overrideServiceRoute).toHaveBeenCalledWith(SERVICE_MAIN_BALANCER, "levik-service-endpoint-01", undefined, h.compiled.auth);
    expect(h.session.mainServerId).toBe("s1");
    await h.session.refresh();
    expect(overrideServiceRoute).toHaveBeenCalledTimes(1); // The service-health timer cannot reset main.
    expect(h.report.mock.calls.at(-1)?.[0]).toMatchObject({ currentId: "s1", switched: true });
  });

  it("takes a fresh activity sample immediately before override and protects a new burst", async () => {
    const h = await harness(); await h.quiet();
    h.env.uplink = 128 * 1024;
    await h.session.refreshAutomatic();
    expect(overrideServiceRoute).not.toHaveBeenCalled();
    expect(h.session.mainServerId).toBe("s0");
  });

  it("blocks missing counters and preserves the previous installed route after API failure", async () => {
    const h = await harness(); await h.quiet(); h.env.initialized = false;
    await h.session.refreshAutomatic(); expect(overrideServiceRoute).not.toHaveBeenCalled();
    h.env.initialized = true; await h.quiet(62_000);
    vi.mocked(overrideServiceRoute).mockRejectedValueOnce(new Error("API unavailable"));
    await h.session.refreshAutomatic(); await h.quiet(2000); await h.session.refreshAutomatic();
    expect(h.session.mainServerId).toBe("s0");
  });

  it("reuses successful bounded body proof for five minutes and invalidates it for a suspected current freeze", async () => {
    const h = await harness();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.slice(0, 3).every((call) => call[3]?.verifyData === true)).toBe(true);
    vi.mocked(openExistingRouteProbe).mockClear();
    await h.session.refreshAutomatic();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.every((call) => call[3]?.verifyData === false)).toBe(true);
    vi.mocked(openExistingRouteProbe).mockClear();
    await h.session.refreshAutomatic(true);
    expect(vi.mocked(openExistingRouteProbe).mock.calls[0]?.[3]?.verifyData).toBe(true);
    expect(vi.mocked(openExistingRouteProbe).mock.calls.slice(1).every((call) => call[3]?.verifyData === false)).toBe(true);
    h.env.now += 5 * 60_000; vi.mocked(openExistingRouteProbe).mockClear();
    await h.session.refreshAutomatic();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.every((call) => call[3]?.verifyData === true)).toBe(true);
  });

  it("preloads dormant manual controls without probes and hot-enables only one owner", async () => {
    vi.useFakeTimers();
    const h = await harness(false);
    expect(h.session.automaticAvailable).toBe(true); expect(h.session.smartAutoActive).toBe(false); expect(h.session.active).toBe(false);
    expect(measureRouteCandidates).not.toHaveBeenCalled(); expect(overrideServiceRoute).not.toHaveBeenCalled();
    await Promise.all([h.session.setAutomaticEnabled(true), h.session.setAutomaticEnabled(true)]);
    await h.session.refreshAutomatic();
    expect(measureRouteCandidates).toHaveBeenCalledTimes(1);
    expect(h.session.smartAutoActive).toBe(true);
    await h.session.setAutomaticEnabled(false); h.session.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("handles ON/OFF/ON without orphaned timers or a second main writer", async () => {
    vi.useFakeTimers(); const h = await harness(false);
    await Promise.all([h.session.setAutomaticEnabled(true), h.session.setAutomaticEnabled(false), h.session.setAutomaticEnabled(true)]);
    await h.session.refreshAutomatic();
    expect(measureRouteCandidates).toHaveBeenCalledTimes(1); expect(overrideServiceRoute).not.toHaveBeenCalled();
    h.session.stop(); expect(vi.getTimerCount()).toBe(0);
  });

  it("freezes the acknowledged manual target even when an old automatic RPC completes after OFF", async () => {
    const h = await harness(); await h.quiet();
    let finish: (() => void) | undefined;
    vi.mocked(overrideServiceRoute).mockImplementationOnce(async () => await new Promise<void>((resolve) => { finish = resolve; }));
    const selecting = h.session.refreshAutomatic();
    await vi.waitFor(() => expect(overrideServiceRoute).toHaveBeenCalledTimes(1));
    const off = h.session.setAutomaticEnabled(false);
    expect(h.session.smartAutoActive).toBe(false);
    finish?.(); await Promise.all([selecting, off]);
    expect(vi.mocked(overrideServiceRoute).mock.calls.map(([balancer, target]) => [balancer, target])).toEqual([
      [SERVICE_MAIN_BALANCER, "levik-service-endpoint-01"], [SERVICE_MAIN_BALANCER, "levik-service-endpoint-00"],
    ]);
    expect(h.session.mainServerId).toBe("s0");
    expect(h.report.mock.calls.at(-1)?.[0].currentId).toBe("s0");
  });

  it("keeps recovery's initial selector and hot-mode intent aligned with the installed route", async () => {
    const h = await harness();
    rememberAutomaticMain(h.config, "s1", false);
    expect(h.compiled.automatic).toMatchObject({ selectedId: "s1", enabled: false });
    const routing = h.config.routing as { balancers: Array<{ tag: string; selector: string[] }> };
    expect(routing.balancers.find((balancer) => balancer.tag === SERVICE_MAIN_BALANCER)?.selector).toEqual(["levik-service-endpoint-01"]);
    const recovered = new ServiceRouteSession(vi.fn()); sessions.push(recovered);
    await recovered.start(h.config);
    expect(recovered.smartAutoActive).toBe(false); expect(recovered.mainServerId).toBe("s1");
  });

  it("rechecks fresh activity at the serialized API write boundary", async () => {
    const h = await harness(); await h.quiet();
    const before = vi.mocked(queryServiceRouteStatistics).mock.calls.length;
    vi.mocked(queryServiceRouteStatistics).mockImplementation(async () => {
      h.env.now++;
      if (vi.mocked(queryServiceRouteStatistics).mock.calls.length === before + 2) h.env.uplink = 128 * 1024;
      return { uplink: h.env.uplink, downlink: h.env.downlink, initialized: true };
    });
    await h.session.refreshAutomatic();
    expect(vi.mocked(queryServiceRouteStatistics).mock.calls.length).toBe(before + 2);
    expect(overrideServiceRoute).not.toHaveBeenCalled();
  });

  it("rejects an optimization if the network changes while the queued fresh guard query awaits", async () => {
    const h = await harness(); await h.quiet();
    const before = vi.mocked(queryServiceRouteStatistics).mock.calls.length;
    vi.mocked(queryServiceRouteStatistics).mockImplementation(async () => {
      h.env.now++;
      if (vi.mocked(queryServiceRouteStatistics).mock.calls.length === before + 2) h.env.network = "new-network";
      return { uplink: 0, downlink: 0, initialized: true };
    });
    await h.session.refreshAutomatic();
    expect(overrideServiceRoute).not.toHaveBeenCalled();
  });

  it("invalidates body proof on a changed physical path and retains its identity through missing metadata", async () => {
    const h = await harness(); h.env.routeIds.s1 = "new-route-b";
    vi.mocked(openExistingRouteProbe).mockClear(); await h.session.refreshAutomatic();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.find(([port]) => port === 47201)?.[3]?.verifyData).toBe(true);
    h.env.routeIds.s1 = undefined;
    vi.mocked(openExistingRouteProbe).mockClear(); await h.session.refreshAutomatic();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.every((call) => call[3]?.verifyData === false)).toBe(true);
  });

  it("does not stamp an old in-flight body check with a newly reported path identity", async () => {
    const h = await harness();
    const observe = vi.mocked(measureRouteCandidates).getMockImplementation()!;
    vi.mocked(measureRouteCandidates).mockImplementationOnce(async (options, dependencies) => {
      const result = await observe(options, dependencies); h.env.routeIds.s1 = "changed-mid-probe"; return result;
    });
    await h.session.refreshAutomatic();
    expect(h.report.mock.calls.at(-1)?.[0].measurements.s1).toBeUndefined();
    vi.mocked(openExistingRouteProbe).mockClear(); await h.session.refreshAutomatic();
    expect(vi.mocked(openExistingRouteProbe).mock.calls.find(([port]) => port === 47201)?.[3]?.verifyData).toBe(true);
  });
});
