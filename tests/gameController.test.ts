import { describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-game-test", getVersion: () => "1.3.0", getAppPath: () => "/tmp/levik-game-test", isPackaged: false } }));
vi.mock("../src/main/vpn/gameRoutes", async (load) => ({
  ...await load<typeof import("../src/main/vpn/gameRoutes")>(), measureGameDataRoute: vi.fn(),
}));
import { AppController } from "../src/main/appController";
import { app as electronApp } from "electron";
import { measureGameDataRoute, summarizeGameSamples } from "../src/main/vpn/gameRoutes";
import type { AppSnapshot, GameRuntimeSnapshot, TunnelServer } from "../src/shared/contracts";
import type { PreparedTunnelProfile } from "../src/main/vpn/tunnelProfile";

const server = (id: string): TunnelServer => ({ id, tag: id, name: id, countryCode: "RU", outbound: { protocol: "hysteria" } });
function controller() {
  const app = new AppController();
  const state = Reflect.get(app, "state") as AppSnapshot;
  state.status = "connected";
  state.settings = { ...state.settings, gameEnabled: true, gameIds: ["valorant"] };
  state.game = { available: true, routes: [server("a"), server("b")], quality: {}, activeRouteId: null, recommendedRouteId: null, phase: "idle", message: null };
  Reflect.set(app, "profile", { subscriptionId: "one", game: { enabled: true, servers: [server("a"), server("b")] } });
  Reflect.set(app, "gamePassword", "test-password");
  const selectGameRoute = vi.fn().mockResolvedValue(undefined);
  const quality: Record<number, ReturnType<typeof summarizeGameSamples>> = { 0: summarizeGameSamples(Array(8).fill(20)), 1: summarizeGameSamples(Array(8).fill(30)) };
  Reflect.set(app, "xray", { isRunning: () => true, selectGameRoute, refreshGameMeasurements: vi.fn(), gameRouteQualities: quality });
  return { app, state, selectGameRoute, quality };
}

describe("Game controller", () => {
  it("turns Game off as soon as the local entitlement expires", async () => {
    const { app } = controller();
    Reflect.set(app, "profile", { subscriptionExpiresAt: new Date(Date.now() - 1000).toISOString() });
    const updateSettings = vi.spyOn(app, "updateSettings").mockResolvedValue(undefined);
    const traffic = Reflect.get(app, "handleTrafficStats") as (download: number, upload: number) => void;
    traffic.call(app, 0, 0);
    expect(updateSettings).toHaveBeenCalledWith({ gameEnabled: false }, "sync");
    expect(app.snapshot().game?.available).toBe(false);
  });
  it.each([false, true])("preserves active Game flows when profile changes (new transport: %s)", async (transportAdded) => {
    const { app, state } = controller();
    const ordinary = server("ordinary");
    const existing = [{ ...server("a"), nodeId: "node-a" }, { ...server("b"), nodeId: "node-a" }];
    const node = { nodeId: "node-a", name: "Узел", city: null, countryCode: "RU", mesh: null, state: "enabled" as const };
    const current: PreparedTunnelProfile = { profileId: "p", subscriptionId: "one", subscriptionExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      servers: [ordinary], game: { enabled: true, servers: existing, nodes: [node] }, directCidrs: [], directDomains: [], proxyDomains: [] };
    const next: PreparedTunnelProfile = { ...current, subscriptionExpiresAt: new Date(Date.now() + 3_600_000).toISOString(), game: { enabled: true,
      servers: transportAdded ? [...existing, { ...server("c"), nodeId: "node-a" }] : existing,
      nodes: [{ ...node, state: "draining" }] } };
    Reflect.set(app, "profile", current); Reflect.set(app, "secureStore", { put: vi.fn().mockResolvedValue(undefined) });
    const updateGameOptions = vi.fn(); const stop = vi.fn();
    Reflect.set(app, "xray", { isRunning: () => true, updateGameOptions, stop, gameRuntimeSnapshot: { activeFlowCount: 1, currentMatch: { address: "8.8.8.8", port: 27015 } } });
    Reflect.set(app, "reconcileFavorites", vi.fn().mockResolvedValue(undefined)); Reflect.set(app, "pingServers", vi.fn().mockResolvedValue(undefined));
    state.game!.activeRouteId = "a";
    const apply = Reflect.get(app, "applyTunnelProfile") as (profile: PreparedTunnelProfile) => Promise<void>;
    await apply.call(app, next);
    expect(stop).not.toHaveBeenCalled();
    expect(app.snapshot().game?.activeRouteId).toBe("a");
    expect(updateGameOptions).toHaveBeenCalledWith({ nodes: [expect.objectContaining({ nodeId: "node-a", state: "draining" })] });
    expect(Reflect.get(app, "pendingGameProfile")).toBe(transportAdded ? next : null);
    expect((Reflect.get(app, "profile") as PreparedTunnelProfile).subscriptionExpiresAt).toBe(next.subscriptionExpiresAt);
    if (transportAdded) expect((Reflect.get(app, "profile") as PreparedTunnelProfile).game?.servers).toHaveLength(2);
  });
  it("requires separate explicit consent before sending country aggregates and never sends a match twice", () => {
    const { app, state } = controller();
    Reflect.set(electronApp, "isPackaged", true);
    try {
      const sendGameRegions = vi.fn();
      const runtime: GameRuntimeSnapshot = { currentMatch: null, lastMatch: { address: "8.8.8.8", port: 27015, region: "RU" },
        selectedExitId: null, selectionReason: null, exits: [], ingressPaths: [], protection: { enabled: true, limitedByUpload: false, reason: null },
        shadowAlternative: null, estimateHistory: [], compatibility: "full", matchReport: { startedAt: 100, endedAt: 1100,
          durationMs: 1000, averageRttMs: 20, p95RttMs: 22, jitterMs: 1, lossPercent: null, rescuedPackets: 0, receivedPackets: 50, approximate: true } };
      Reflect.set(app, "xray", { gameRuntimeSnapshot: runtime, gameMultipathStats: null });
      Reflect.set(app, "gameRegionTelemetry", { sendGameRegions });
      const traffic = Reflect.get(app, "handleTrafficStats") as (download: number, upload: number) => void;
      state.settings.gameRegionTelemetry = false; traffic.call(app, 0, 0);
      expect(sendGameRegions).not.toHaveBeenCalled();
      state.settings.gameRegionTelemetry = true; traffic.call(app, 0, 0); traffic.call(app, 0, 0);
      expect(sendGameRegions).toHaveBeenCalledExactlyOnceWith([{ region: "RU", matches: 1 }]);
      expect(JSON.stringify(sendGameRegions.mock.calls)).not.toContain("8.8.8.8");
    } finally { Reflect.set(electronApp, "isPackaged", false); }
  });
  it("updates protection and preferred exit live without replacing the tunnel", async () => {
    const { app, state, selectGameRoute } = controller();
    const updateGameOptions = vi.fn(); const stop = vi.fn();
    Reflect.set(app, "xray", { isRunning: () => true, selectGameRoute, updateGameOptions, stop });
    Reflect.set(app, "secureStore", { put: vi.fn().mockResolvedValue(undefined) });
    state.busy = false;
    await app.updateSettings({ gameProtection: false }, "sync");
    expect(updateGameOptions).toHaveBeenCalledWith(expect.objectContaining({ protection: false }));
    expect(stop).not.toHaveBeenCalled();
  });
  it("applies selected process rules live before updating runtime options", async () => {
    const { app, state, selectGameRoute } = controller();
    const updateGameProcesses = vi.fn().mockResolvedValue(undefined); const updateGameOptions = vi.fn(); const stop = vi.fn();
    Reflect.set(app, "xray", { isRunning: () => true, selectGameRoute, updateGameProcesses, updateGameOptions, stop });
    Reflect.set(app, "secureStore", { put: vi.fn().mockResolvedValue(undefined) });
    state.busy = false;
    await app.updateSettings({ gameIds: ["valorant", "cs2"] }, "sync");
    expect(updateGameProcesses).toHaveBeenCalledWith(expect.objectContaining({ gameIds: ["valorant", "cs2"] }));
    expect(stop).not.toHaveBeenCalled();
  });
  it.each([false, true])("migrates legacy multipath=%s to enabled protection and preserves v2 routing", async (gameMultipath) => {
    const app = new AppController();
    const defaults = app.snapshot().settings;
    const put = vi.fn().mockResolvedValue(undefined);
    Reflect.set(app, "secureStore", { get: vi.fn().mockResolvedValue(Buffer.from(JSON.stringify({ ...defaults,
      settingsSchemaVersion: 2, routingMode: "bypassRu", gameMultipath, gameProtection: undefined }))), put });
    const load = Reflect.get(app, "loadSettings") as () => Promise<typeof defaults>;
    const migrated = await load.call(app);
    expect(migrated).toMatchObject({ gameProtection: true, gameRegionTelemetry: false, routingMode: "bypassRu" });
    expect(put).toHaveBeenCalledOnce();
  });
  it("preserves the new explicit protection opt-out", async () => {
    const app = new AppController(); const defaults = app.snapshot().settings;
    Reflect.set(app, "secureStore", { get: vi.fn().mockResolvedValue(Buffer.from(JSON.stringify({ ...defaults,
      settingsSchemaVersion: 3, gameProtection: false }))), put: vi.fn() });
    const load = Reflect.get(app, "loadSettings") as () => Promise<typeof defaults>;
    expect((await load.call(app)).gameProtection).toBe(false);
  });
  it.each([false, true])("requires full-size UDP through multipath before activation (data works: %s)", async (working) => {
    vi.mocked(measureGameDataRoute).mockResolvedValue(summarizeGameSamples(Array(8).fill(working ? 25 : null)));
    const { app, state, selectGameRoute, quality } = controller();
    state.settings.gameMultipath = true;
    const selectGameUdpRoute = vi.fn().mockResolvedValue(undefined);
    Reflect.set(app, "xray", { isRunning: () => true, start: vi.fn(), stop: vi.fn(), selectGameRoute,
      selectGameUdpRoute, connectGameMultipath: vi.fn(), gameRouteQualities: quality, gameMultipathStats: {
        state: "protected", paths: [{ routeIndex: 0, responding: true, latencyMs: 20 }],
      } });
    Reflect.set(app, "killSwitch", { allowTunnel: vi.fn() });
    const start = Reflect.get(app, "startXray") as (config: Record<string, unknown>, generation: number) => Promise<void>;
    await start.call(app, {}, Reflect.get(app, "connectionGeneration") as number);
    expect(vi.mocked(measureGameDataRoute).mock.calls.at(-1)?.[3]).toBe(1200);
    if (working) expect(selectGameUdpRoute).toHaveBeenCalledWith(null);
    else {
      expect(selectGameUdpRoute).not.toHaveBeenCalled();
      expect(app.snapshot().game?.message).toContain("не прошёл проверку");
    }
  });
  it("rejects renderer attempts to enable Game without an authorized profile", async () => {
    const app = new AppController();
    await expect(app.updateSettings({ gameEnabled: true, gameIds: ["valorant"] })).rejects.toThrow("Game Squad");
  });
  it("pins the selected route across later measurements while updating the recommendation", async () => {
    const { app, selectGameRoute, quality } = controller();
    await app.measureGameRoutes();
    expect(selectGameRoute).toHaveBeenCalledWith(0);
    expect(app.snapshot().game?.activeRouteId).toBe("a");
    quality[0] = summarizeGameSamples(Array(8).fill(50));
    quality[1] = summarizeGameSamples(Array(8).fill(10));
    await app.measureGameRoutes();
    expect(selectGameRoute).toHaveBeenCalledTimes(1);
    expect(app.snapshot().game).toMatchObject({ activeRouteId: "a", recommendedRouteId: "b" });
  });
  it("chooses current-game history at launch only before real UDP flows have pinned an exit", async () => {
    const { app, state, selectGameRoute } = controller();
    const routes = [{ ...server("a"), nodeId: "node-a" }, { ...server("b"), nodeId: "node-b" }];
    state.game!.routes = routes; state.game!.activeRouteId = "a";
    Reflect.set(app, "profile", { subscriptionId: "one", game: { enabled: true, servers: routes } });
    Reflect.set(app, "currentGameId", "cs2");
    const preferredExit = vi.fn().mockReturnValue("node-b");
    Reflect.set(app, "gameHistory", { preferredExit });
    const runtime = { activeFlowCount: 0 };
    Reflect.set(Reflect.get(app, "xray"), "gameRuntimeSnapshot", runtime);

    // A routine measurement updates quality without changing the active TCP exit.
    await app.measureGameRoutes();
    expect(selectGameRoute).not.toHaveBeenCalled();
    expect(app.snapshot().game?.activeRouteId).toBe("a");
    // B is healthy but slower by access RTT; this game's history takes priority.
    await app.measureGameRoutes(true);
    expect(preferredExit).toHaveBeenCalledWith("cs2");
    expect(selectGameRoute).toHaveBeenCalledExactlyOnceWith(1);
    expect(app.snapshot().game).toMatchObject({ activeRouteId: "b", recommendedRouteId: "a" });

    runtime.activeFlowCount = 1; preferredExit.mockReturnValue("node-a");
    await app.measureGameRoutes(true);
    expect(selectGameRoute).toHaveBeenCalledTimes(1);
    expect(app.snapshot().game?.activeRouteId).toBe("b");
  });
  it("never silently falls back to ordinary VPN when all game routes fail", async () => {
    const { app, selectGameRoute, quality } = controller();
    quality[0] = summarizeGameSamples(Array(8).fill(null));
    quality[1] = summarizeGameSamples(Array(8).fill(null));
    await app.measureGameRoutes();
    expect(selectGameRoute).not.toHaveBeenCalled();
    expect(app.snapshot()).toMatchObject({ status: "connected", game: { phase: "degraded", activeRouteId: null } });
  });
  it("discards in-flight results after the connection generation changes", async () => {
    let complete!: () => void;
    const { app, selectGameRoute } = controller();
    selectGameRoute.mockImplementation(() => new Promise<void>((resolve) => { complete = resolve; }));
    const pending = app.measureGameRoutes();
    Reflect.set(app, "connectionGeneration", 99);
    complete();
    await pending;
    expect(app.snapshot().game?.activeRouteId).toBeNull();
  });
});
