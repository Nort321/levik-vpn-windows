import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-service-controller-test", getVersion: () => "1.2.3", isPackaged: true, setLoginItemSettings: vi.fn() } }));
vi.mock("../src/main/update/appUpdater", () => ({ AppUpdater: class { on(): this { return this; } } }));
vi.mock("../src/main/windows/killSwitch", async (original) => ({ ...await original<typeof import("../src/main/windows/killSwitch")>(), WindowsKillSwitch: class {} }));
import { AppController } from "../src/main/appController";
import { ServiceRouteState } from "../src/main/vpn/serviceRouteState";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import type { ServiceRoutePolicy, ServiceRouteStatus } from "../src/main/vpn/serviceRoutes";

const policy: ServiceRoutePolicy = { version: 1, revision: 1, fingerprint: "a".repeat(64), rules: [{ id: "rule", label: "Рабочий сервис", source: "domain",
  domains: ["full:work.example"], route: { kind: "country", countryCode: "DE" }, fallback: { kind: "block" } }],
  exits: [{ exitId: "de", name: "Германия", countryCode: "DE", role: "ordinary", state: "enabled", endpoints: [{ address: "de.example", port: 443, protocol: "vless" }] }] };
const receipt: ServiceRouteStatus = { revision: 1, fingerprint: policy.fingerprint, state: "applied", routes: [{ id: "rule", state: "active", exitId: "de" }] };
const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
async function fixture() {
  let bytes: Buffer | null = null;
  const disk = { get: vi.fn(async () => bytes ? Buffer.from(bytes) : null), put: vi.fn(async (_key: string, value: Uint8Array) => { bytes = Buffer.from(value); }), remove: vi.fn(async () => { bytes = null; }) };
  const cache = new ServiceRouteState(disk); cache.propose("one", policy); await cache.acknowledge("one", receipt);
  const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "test", subscriptionId: "one", source: { content:
    "vless://11111111-1111-4111-8111-111111111111@de.example:443?security=tls#DE\nvless://11111111-1111-4111-8111-111111111111@lte.example:443?security=tls&type=xhttp#LTE" } })), "one");
  profile.serviceRoutes = policy;
  const controller = new AppController(); Reflect.set(controller, "identity", { deviceId: () => "service-test-device" });
  Reflect.set(controller, "profile", profile); Reflect.set(controller, "serviceRouteState", cache); Reflect.set(controller, "accessToken", "token-a");
  Reflect.set(controller, "xray", { isRunning: () => true, serviceRoutes: { setPolicySuspended: vi.fn(), active: true, mainExitId: "de", snapshot: receipt } });
  const state = Reflect.get(controller, "state"); Object.assign(state, { status: "connected", busy: false, servers: profile.servers, selectedServerId: profile.servers[0]!.id, selectedSubscriptionId: "one" });
  return { controller, profile, cache, disk, state };
}
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });
describe("service policy lifecycle", () => {
  it("does not enroll or fetch the new resource while rollout is disabled", async () => {
    const { controller, profile, cache } = await fixture(); await cache.clear(); delete profile.serviceRoutes;
    const read = vi.fn(); Reflect.set(controller, "api", { serviceRouteProfile: read });
    const refresh = Reflect.get(controller, "refreshServiceRoutePolicy") as (server: typeof profile.servers[number]) => Promise<boolean>;
    expect(await refresh.call(controller, profile.servers[0]!)).toBe(false); expect(read).not.toHaveBeenCalled();
  });
  it("preserves legacy connectivity and never acknowledges first-enrollment API failure", async () => {
    const { controller, profile, cache } = await fixture(); await cache.clear(); delete profile.serviceRoutes;
    const report = vi.fn(); Reflect.set(controller, "api", { serviceRouteProfile: vi.fn(async () => { throw new Error("API unavailable"); }), reportServiceRoutes: report });
    Reflect.set(controller, "remoteStored", { config: { flags: { service_routes: { enabled: true, rolloutPercent: 100 } } } });
    const refresh = Reflect.get(controller, "refreshServiceRoutePolicy") as (server: typeof profile.servers[number]) => Promise<boolean>;
    expect(await refresh.call(controller, profile.servers[0]!)).toBe(false);
    expect(profile.serviceRoutes).toBeUndefined(); expect(cache.good("one")).toBeUndefined(); expect(cache.pending("one")).toBeUndefined();
    const current = Reflect.get(controller, "state");
    expect(current.status).toBe("connected"); expect(current.serviceRoutes?.state).not.toBe("applied"); expect(report).not.toHaveBeenCalled();
    expect(current.serviceRouteNotice).toContain("применение ещё не подтверждено");
  });
  it("refreshes an unchanged applied receipt after two minutes", async () => {
    const { controller } = await fixture(); let now = 1000; vi.spyOn(Date, "now").mockImplementation(() => now);
    const report = vi.fn(async () => {}); Reflect.set(controller, "api", { reportServiceRoutes: report });
    const changed = Reflect.get(controller, "serviceRouteStatusChanged") as (status: ServiceRouteStatus) => void;
    changed.call(controller, receipt); await flush(); expect(report).toHaveBeenCalledTimes(1);
    now += 15000; changed.call(controller, receipt); await flush(); expect(report).toHaveBeenCalledTimes(1);
    now += 120000; changed.call(controller, receipt); await flush(); expect(report).toHaveBeenCalledTimes(2);
  });
  it("does not let a late status 401 clear a newly signed-in account", async () => {
    const { controller } = await fixture(); let rejectReceipt: (error: Error) => void = () => {};
    const report = vi.fn(() => new Promise<void>((_resolve, reject) => { rejectReceipt = reject; }));
    const clear = vi.fn(async () => {}); Reflect.set(controller, "api", { reportServiceRoutes: report }); Reflect.set(controller, "clearLocalSession", clear);
    const changed = Reflect.get(controller, "serviceRouteStatusChanged") as (status: ServiceRouteStatus) => void;
    changed.call(controller, receipt); await flush(); expect(report).toHaveBeenCalledWith("token-a", receipt);
    Reflect.set(controller, "accessToken", "token-b"); rejectReceipt(new Error("401")); await flush();
    expect(Reflect.get(controller, "accessToken")).toBe("token-b"); expect(clear).not.toHaveBeenCalled();
  });
  it("rejects a late old-owner profile even before the profile object was replaced", async () => {
    const { controller, profile, cache } = await fixture(); let resolveProfile: (value: unknown) => void = () => {};
    const read = vi.fn(() => new Promise((resolve) => { resolveProfile = resolve; })); Reflect.set(controller, "api", { serviceRouteProfile: read });
    const refresh = Reflect.get(controller, "refreshServiceRoutePolicy") as (server: typeof profile.servers[number]) => Promise<boolean>;
    const pending = refresh.call(controller, profile.servers[0]!); await flush();
    Reflect.set(controller, "accessToken", "token-b"); resolveProfile({ ok: true, applicable: true, profile: { ...policy, revision: 2, fingerprint: "b".repeat(64) } });
    expect(await pending).toBe(false); expect(cache.pending("one")).toBeUndefined(); expect(cache.good("one")).toEqual(policy);
  });
  it("does not persist a fetched desired policy before successful application", async () => {
    const { controller, profile, cache, disk } = await fixture(); const next = { ...policy, revision: 2, fingerprint: "b".repeat(64) };
    Reflect.set(controller, "api", { serviceRouteProfile: vi.fn(async () => ({ ok: true, applicable: true, profile: next })) });
    const refresh = Reflect.get(controller, "refreshServiceRoutePolicy") as (server: typeof profile.servers[number]) => Promise<boolean>;
    expect(await refresh.call(controller, profile.servers[0]!)).toBe(true);
    expect(profile.serviceRoutes).toEqual(policy); expect(cache.pending("one")).toEqual(next); expect(disk.put).toHaveBeenCalledTimes(1);
    const restarted = new ServiceRouteState(disk); await restarted.load(); expect(restarted.good("one")).toEqual(policy);
  });
  it("keeps strict ordinary rules through a protected-mode round trip and API outage", async () => {
    const { controller, profile, cache, state } = await fixture(); const read = vi.fn(async () => ({ ok: true, applicable: false }));
    Reflect.set(controller, "api", { serviceRouteProfile: read, reportServiceRoutes: vi.fn(async () => {}) });
    const refresh = Reflect.get(controller, "refreshServiceRoutePolicy") as (server: typeof profile.servers[number]) => Promise<boolean>;
    const effective = Reflect.get(controller, "serviceProfileFor") as (server: typeof profile.servers[number]) => typeof profile;
    state.selectedServerId = profile.servers[1]!.id;
    await refresh.call(controller, profile.servers[1]!); expect(effective.call(controller, profile.servers[1]!).serviceRoutes).toBeUndefined();
    expect(Reflect.get(controller, "xray").serviceRoutes.setPolicySuspended).toHaveBeenCalledWith(true);
    read.mockRejectedValueOnce(new Error("unavailable")); state.selectedServerId = profile.servers[0]!.id;
    await refresh.call(controller, profile.servers[0]!);
    expect(effective.call(controller, profile.servers[0]!).serviceRoutes).toEqual(policy); expect(cache.good("one")).toEqual(policy);
  });
  it("queues a new-policy event received while the controller is busy", async () => {
    const { controller, state } = await fixture(); vi.useFakeTimers(); state.busy = true;
    const apply = vi.fn(async () => {}); Reflect.set(controller, "applyServiceRoutesOnce", apply);
    const event = Reflect.get(controller, "applyServiceRoutes") as () => Promise<void>;
    await event.call(controller); expect(apply).not.toHaveBeenCalled();
    state.busy = false; await vi.advanceTimersByTimeAsync(1000); expect(apply).toHaveBeenCalledOnce();
  });
});
