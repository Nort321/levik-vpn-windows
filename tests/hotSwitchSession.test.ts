import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TunnelServer } from "../src/shared/contracts";
import { ServiceRouteSession } from "../src/main/vpn/serviceRouteSession";
import { SERVICE_MAIN_BALANCER, ServiceRouteRuntime, withServiceRoutes } from "../src/main/vpn/serviceRoutes";

vi.mock("../src/main/vpn/serviceRouteTransport", () => ({
  overrideServiceRoute: vi.fn(async () => {}), probeServiceRoute: vi.fn(async () => true),
  probeServiceRouteDns: vi.fn(async () => true),
  queryServiceRouteStatistics: vi.fn(async () => ({ uplink: 0, downlink: 0, initialized: true })),
}));
vi.mock("../src/main/vpn/routeProbe", async (original) => ({
  ...await original<typeof import("../src/main/vpn/routeProbe")>(),
  measureRouteCandidates: vi.fn(async () => ({})),
  openExistingRouteProbe: vi.fn(async () => ({ latency: async () => ({ values: [10], failed: 0, setupMs: 1, dataVerified: true }),
    transfer: async () => null, close: async () => {} })),
}));
import { overrideServiceRoute, probeServiceRouteDns } from "../src/main/vpn/serviceRouteTransport";
import { openExistingRouteProbe } from "../src/main/vpn/routeProbe";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
const sessions: ServiceRouteSession[] = [];
beforeEach(() => {
  vi.mocked(overrideServiceRoute).mockReset().mockResolvedValue(undefined);
  vi.mocked(probeServiceRouteDns).mockReset().mockResolvedValue(true);
});
afterEach(() => { sessions.splice(0).forEach((session) => session.stop()); vi.clearAllMocks(); vi.restoreAllMocks(); vi.useRealTimers(); });

async function harness(verifyMain?: NonNullable<ConstructorParameters<typeof ServiceRouteSession>[1]>["verifyMain"]) {
  const servers: TunnelServer[] = ["DE", "NL", "FI"].map((countryCode, index) => ({ id: `s${index}`, tag: `source-${index}`,
    name: countryCode, countryCode, outbound: { tag: `source-${index}`, protocol: "vless",
      settings: { vnext: [{ address: `node${index}.example`, port: 443 }] } } }));
  const selected = servers[0]!;
  const config = withServiceRoutes({ api: { tag: "levik-api", services: ["StatsService"] },
    dns: { tag: "levik-dns", servers: ["1.1.1.1"] }, inbounds: [],
    outbounds: [selected.outbound, { tag: "direct", protocol: "freedom" }], routing: { rules: [] } },
  { policy: undefined, selected, servers, automaticServer: false, directTag: "direct", prepareOutbound: (server) => server.outbound });
  const env = { network: "wifi", eligible: true }, report = vi.fn();
  const session = new ServiceRouteSession(vi.fn(), verifyMain ? { verifyMain } : {}); sessions.push(session);
  session.configureSmartAuto({ controls: () => Object.fromEntries(servers.map((server) => [server.id,
    { eligible: env.eligible, state: "healthy" as const, resourceHeadroom: 1 }])),
  canTransfer: () => false, networkKey: () => env.network, report });
  await session.start(config);
  return { session, config, env, report };
}

describe("manual same-core HotSwitch", () => {
  it("publishes the new target only after the candidate passed verification and the core acknowledged it", async () => {
    const proof = deferred<boolean>(), ack = deferred<void>();
    const h = await harness(async () => await proof.promise);
    vi.mocked(overrideServiceRoute).mockImplementationOnce(async () => await ack.promise);
    const switching = h.session.selectMain("s1");
    expect(h.session.mainServerId).toBe("s0"); expect(overrideServiceRoute).not.toHaveBeenCalled();
    proof.resolve(true); await vi.waitFor(() => expect(overrideServiceRoute).toHaveBeenCalledTimes(1));
    expect(h.session.mainServerId).toBe("s0"); expect(h.report).not.toHaveBeenCalled();
    ack.resolve(); expect(await switching).toEqual({ status: "applied", serverId: "s1" });
    expect(h.session.mainServerId).toBe("s1"); expect(h.session.mainSelectionCertain).toBe(true);
    expect(h.report).toHaveBeenCalledWith({ currentId: "s1", measurements: {}, switched: true });
    expect(h.session.selectableMainIds).toEqual(["s0", "s1", "s2"]);
  });

  it("requires both real response data and DNS proof through the candidate's private route", async () => {
    const h = await harness();
    vi.mocked(probeServiceRouteDns).mockResolvedValueOnce(false);
    expect(await h.session.selectMain("s1")).toEqual({ status: "failed" });
    expect(openExistingRouteProbe).toHaveBeenCalledWith(47201, expect.any(Object), expect.any(AbortSignal), { verifyData: true });
    expect(probeServiceRouteDns).toHaveBeenCalledWith(47201, expect.any(Object), ["tcp://1.1.1.1"], expect.any(AbortSignal));
    expect(overrideServiceRoute).not.toHaveBeenCalled(); expect(h.session.mainServerId).toBe("s0");
    vi.mocked(openExistingRouteProbe).mockResolvedValueOnce({ latency: async () => ({ values: [], failed: 0, setupMs: 1, dataVerified: false }),
      transfer: async () => null, close: async () => {} });
    expect(await h.session.selectMain("s1")).toEqual({ status: "failed" });
    expect(overrideServiceRoute).not.toHaveBeenCalled();
  });

  it("keeps the old target after failed verification and rejects targets outside the installed pool", async () => {
    const verify = vi.fn(async () => false), h = await harness(verify);
    expect(await h.session.selectMain("s1")).toEqual({ status: "failed" });
    expect(await h.session.selectMain("outside-pool")).toEqual({ status: "unsupported" });
    expect(verify).toHaveBeenCalledTimes(1); expect(overrideServiceRoute).not.toHaveBeenCalled();
    expect(h.session.mainServerId).toBe("s0"); expect(h.report).not.toHaveBeenCalled();
  });

  it("compensates an applied write whose ACK was lost before reporting that the old route is preserved", async () => {
    const h = await harness(async () => true); let actual = "levik-service-endpoint-00";
    vi.mocked(overrideServiceRoute).mockImplementation(async (_balancer, target) => {
      actual = target;
      if (target === "levik-service-endpoint-01") throw new Error("lost ACK after apply");
    });
    expect(await h.session.selectMain("s1")).toEqual({ status: "failed" });
    expect(actual).toBe("levik-service-endpoint-00"); expect(h.session.mainServerId).toBe("s0");
    expect(h.session.mainSelectionCertain).toBe(true); expect(h.report).not.toHaveBeenCalled();
    expect(vi.mocked(overrideServiceRoute).mock.calls.map(([balancer, target]) => [balancer, target])).toEqual([
      [SERVICE_MAIN_BALANCER, "levik-service-endpoint-01"], [SERVICE_MAIN_BALANCER, "levik-service-endpoint-00"],
    ]);
  });

  it("exposes uncertainty when compensation is unconfirmed and lets an explicit retry confirm the old target", async () => {
    const h = await harness(async () => true);
    vi.mocked(overrideServiceRoute).mockRejectedValue(new Error("no ACK"));
    expect(await h.session.selectMain("s1")).toEqual({ status: "uncertain" });
    expect(h.session.mainSelectionCertain).toBe(false); expect(h.report).not.toHaveBeenCalled();
    vi.mocked(overrideServiceRoute).mockResolvedValue(undefined);
    expect(await h.session.selectMain("s0")).toEqual({ status: "applied", serverId: "s0" });
    expect(h.session.mainSelectionCertain).toBe(true);
    expect(overrideServiceRoute).toHaveBeenLastCalledWith(SERVICE_MAIN_BALANCER, "levik-service-endpoint-00", undefined, expect.any(Object));
  });

  it("cancels an older prepared choice when the user chooses the currently installed server", async () => {
    const proof = deferred<boolean>(), h = await harness(async () => await proof.promise);
    const old = h.session.selectMain("s1"); await Promise.resolve();
    expect(await h.session.selectMain("s0")).toEqual({ status: "applied", serverId: "s0" });
    proof.resolve(true); expect(await old).toEqual({ status: "cancelled" }); expect(overrideServiceRoute).not.toHaveBeenCalled();
  });

  it("commits only the latest prepared manual choice", async () => {
    const oldProof = deferred<boolean>();
    const h = await harness(async (candidate) => candidate.id === "s1" ? await oldProof.promise : true);
    const old = h.session.selectMain("s1"); await Promise.resolve();
    expect(await h.session.selectMain("s2")).toEqual({ status: "applied", serverId: "s2" });
    oldProof.resolve(true); expect(await old).toEqual({ status: "cancelled" });
    expect(h.session.mainServerId).toBe("s2"); expect(overrideServiceRoute).toHaveBeenCalledTimes(1);
  });

  it("invalidates proof on network changes or loss of eligibility before commit", async () => {
    const proof = deferred<boolean>(), h = await harness(async () => await proof.promise);
    const switching = h.session.selectMain("s1"); await Promise.resolve(); h.env.network = "other-wifi";
    proof.resolve(true); expect(await switching).toEqual({ status: "cancelled" });
    expect(overrideServiceRoute).not.toHaveBeenCalled();
    h.env.eligible = false; expect(h.session.canSelectMain("s1")).toBe(false);
  });

  it("never addresses a replacement core using an old operation's authentication", async () => {
    const proof = deferred<boolean>(), h = await harness(async () => await proof.promise);
    const old = h.session.selectMain("s1"); await Promise.resolve();
    await h.session.start(h.config); proof.resolve(true);
    expect(await old).toEqual({ status: "cancelled" });
    expect(overrideServiceRoute).not.toHaveBeenCalled(); expect(h.session.mainServerId).toBe("s0");
  });

  it("compensates an in-flight manual write cancelled by enabling Auto", async () => {
    const ack = deferred<void>(), h = await harness(async () => true);
    vi.mocked(overrideServiceRoute).mockImplementationOnce(async () => await ack.promise);
    const selecting = h.session.selectMain("s1");
    await vi.waitFor(() => expect(overrideServiceRoute).toHaveBeenCalledTimes(1));
    const auto = h.session.setAutomaticEnabled(true); ack.resolve();
    expect(await selecting).toEqual({ status: "cancelled" }); expect(await auto).toBe(true);
    expect(h.session.mainServerId).toBe("s0"); expect(h.session.smartAutoActive).toBe(true);
    expect(h.report.mock.calls.some(([update]) => update.currentId === "s1")).toBe(false);
  });

  it("bounds verification and reports a timed-out candidate as a failed switch", async () => {
    vi.useFakeTimers();
    const started = deferred<void>();
    const h = await harness(async (_candidate, _auth, _resolvers, signal) => {
      started.resolve();
      return await new Promise<boolean>((resolve) => signal.addEventListener("abort", () => resolve(false), { once: true }));
    });
    const switching = h.session.selectMain("s1"); await started.promise;
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await switching).toEqual({ status: "failed" });
    expect(h.session.mainServerId).toBe("s0"); expect(overrideServiceRoute).not.toHaveBeenCalled();
  });

  it("cancels overdue policy reconciliation and confirms compensation before reporting failure", async () => {
    vi.useFakeTimers();
    const h = await harness(async () => true), started = deferred<void>();
    let actual = "levik-service-endpoint-00";
    vi.mocked(overrideServiceRoute).mockImplementation(async (_balancer, target) => { actual = target; });
    vi.spyOn(ServiceRouteRuntime.prototype, "reconcileExternalMain").mockImplementationOnce(async (_tag, signal) => {
      started.resolve();
      await new Promise<void>((_resolve, reject) => signal?.addEventListener("abort", () => reject(new Error("cancelled")), { once: true }));
    });
    const switching = h.session.selectMain("s1"); await started.promise;
    expect(actual).toBe("levik-service-endpoint-01");
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await switching).toEqual({ status: "failed" });
    expect(actual).toBe("levik-service-endpoint-00"); expect(h.session.mainSelectionCertain).toBe(true);
    expect(h.report).not.toHaveBeenCalled();
  });
});
