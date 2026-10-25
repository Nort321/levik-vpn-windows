import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/main/vpn/serviceRouteTransport", () => ({ overrideServiceRoute: vi.fn(async () => {}),
  probeServiceRoute: vi.fn(async () => true), probeServiceRouteDns: vi.fn(async () => true),
  queryServiceRouteStats: vi.fn(async () => ({ uplink: 0, downlink: 0 })) }));
import { overrideServiceRoute, probeServiceRoute } from "../src/main/vpn/serviceRouteTransport";
import { ServiceRouteSession } from "../src/main/vpn/serviceRouteSession";
import { withServiceRoutes, type ServiceRoutePolicy } from "../src/main/vpn/serviceRoutes";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
const policy: ServiceRoutePolicy = { version: 1, revision: 1, fingerprint: "a".repeat(64), rules: [{ id: "one", domains: ["full:work.example"],
  source: "domain", label: "Work", route: { kind: "country", countryCode: "DE" }, fallback: { kind: "block" } }], exits: [
  { exitId: "de", name: "DE", countryCode: "DE", role: "ordinary", state: "enabled", endpoints: [{ address: "de.example", port: 443, protocol: "vless" }] }] };
function config() {
  const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "test", subscriptionId: "one", source: {
    content: "vless://11111111-1111-4111-8111-111111111111@de.example:443?security=tls#DE" } })), "one");
  const selected = profile.servers[0]!;
  return withServiceRoutes({ api: { tag: "levik-api", services: ["StatsService"] }, dns: { tag: "levik-dns", servers: ["1.1.1.1"] },
    inbounds: [], outbounds: [selected.outbound], routing: { rules: [] } },
    { policy, selected, servers: profile.servers, automaticServer: true, directTag: "direct", prepareOutbound: (server) => server.outbound });
}
const sessions: ServiceRouteSession[] = [];
afterEach(() => { sessions.forEach((session) => session.stop()); sessions.length = 0; vi.clearAllMocks(); });
describe("service route session lifetime", () => {
  it("ignores a late old-runtime rejection after a new session applied", async () => {
    let rejectOld: (error: Error) => void = () => {};
    vi.mocked(overrideServiceRoute).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectOld = reject; }));
    const report = vi.fn(); const session = new ServiceRouteSession(report); sessions.push(session);
    const old = session.start(config()); await new Promise<void>((resolve) => setImmediate(resolve));
    await session.start(config()); expect(session.snapshot?.state).toBe("applied");
    rejectOld(new Error("old API unavailable")); await old;
    expect(session.snapshot?.state).toBe("applied"); expect(report.mock.calls.at(-1)?.[0].state).toBe("applied");
  });
  it("clears a previous routing error after a successful retry", async () => {
    vi.mocked(overrideServiceRoute).mockRejectedValueOnce(new Error("temporary API failure"));
    const session = new ServiceRouteSession(vi.fn()); sessions.push(session); await session.start(config());
    expect(session.snapshot).toMatchObject({ state: "error", detail: "routing_unavailable" });
    await session.refresh(); expect(session.snapshot?.state).toBe("applied"); expect(session.snapshot?.detail).toBeUndefined();
  });
  it("freezes a reclassified policy without losing private stats authentication", async () => {
    const session = new ServiceRouteSession(vi.fn()); sessions.push(session); await session.start(config());
    const auth = session.authentication; const probes = vi.mocked(probeServiceRoute).mock.calls.length;
    session.setPolicySuspended(true); session.setSuspended(true); session.setSuspended(false); await session.refresh();
    expect(session.authentication).toBe(auth); expect(await session.queryStats()).toEqual({ uplink: 0, downlink: 0 });
    expect(probeServiceRoute).toHaveBeenCalledTimes(probes);
    session.setPolicySuspended(false); await new Promise<void>((resolve) => setImmediate(resolve));
    expect(vi.mocked(probeServiceRoute).mock.calls.length).toBeGreaterThan(probes);
  });
});
