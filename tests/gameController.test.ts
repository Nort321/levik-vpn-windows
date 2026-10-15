import { describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-game-test", getVersion: () => "1.3.0", getAppPath: () => "/tmp/levik-game-test", isPackaged: false } }));
vi.mock("../src/main/vpn/gameRoutes", async (load) => ({
  ...await load<typeof import("../src/main/vpn/gameRoutes")>(), measureGameRoute: vi.fn(),
}));
import { AppController } from "../src/main/appController";
import { measureGameRoute, summarizeGameSamples } from "../src/main/vpn/gameRoutes";
import type { AppSnapshot, TunnelServer } from "../src/shared/contracts";

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
  Reflect.set(app, "xray", { isRunning: () => true, selectGameRoute });
  return { app, state, selectGameRoute };
}

describe("Game controller", () => {
  it.each([false, true])("requires full-size UDP through multipath before activation (data works: %s)", async (working) => {
    vi.mocked(measureGameRoute).mockReset();
    vi.mocked(measureGameRoute).mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(20)))
      .mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(30)))
      .mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(working ? 25 : null)));
    const { app, state, selectGameRoute } = controller();
    state.settings.gameMultipath = true;
    const selectGameUdpRoute = vi.fn().mockResolvedValue(undefined);
    Reflect.set(app, "xray", { isRunning: () => true, start: vi.fn(), stop: vi.fn(), selectGameRoute,
      selectGameUdpRoute, connectGameMultipath: vi.fn(), gameMultipathStats: {
        state: "protected", paths: [{ routeIndex: 0, responding: true, latencyMs: 20 }],
      } });
    Reflect.set(app, "killSwitch", { allowTunnel: vi.fn() });
    const start = Reflect.get(app, "startXray") as (config: Record<string, unknown>, generation: number) => Promise<void>;
    await start.call(app, {}, Reflect.get(app, "connectionGeneration") as number);
    expect(vi.mocked(measureGameRoute).mock.calls.at(-1)?.[3]).toBe(1200);
    expect(selectGameUdpRoute).toHaveBeenCalledWith(working ? null : 0);
    if (!working) expect(app.snapshot().game?.message).toContain("основной игровой туннель");
  });
  it("rejects renderer attempts to enable Game without an authorized profile", async () => {
    const app = new AppController();
    await expect(app.updateSettings({ gameEnabled: true, gameIds: ["valorant"] })).rejects.toThrow("Game Squad");
  });
  it("pins the selected route across later measurements while updating the recommendation", async () => {
    vi.mocked(measureGameRoute).mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(20)))
      .mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(30)));
    const { app, selectGameRoute } = controller();
    await app.measureGameRoutes();
    expect(selectGameRoute).toHaveBeenCalledWith(0);
    expect(app.snapshot().game?.activeRouteId).toBe("a");
    vi.mocked(measureGameRoute).mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(50)))
      .mockResolvedValueOnce(summarizeGameSamples(Array(8).fill(10)));
    await app.measureGameRoutes();
    expect(selectGameRoute).toHaveBeenCalledTimes(1);
    expect(app.snapshot().game).toMatchObject({ activeRouteId: "a", recommendedRouteId: "b" });
  });
  it("never silently falls back to ordinary VPN when all game routes fail", async () => {
    vi.mocked(measureGameRoute).mockResolvedValue(summarizeGameSamples(Array(8).fill(null)));
    const { app, selectGameRoute } = controller();
    await app.measureGameRoutes();
    expect(selectGameRoute).not.toHaveBeenCalled();
    expect(app.snapshot()).toMatchObject({ status: "connected", game: { phase: "degraded", activeRouteId: null } });
  });
  it("discards in-flight results after the connection generation changes", async () => {
    let complete!: (value: ReturnType<typeof summarizeGameSamples>) => void;
    vi.mocked(measureGameRoute).mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    const { app, selectGameRoute } = controller();
    Reflect.set(app, "profile", { subscriptionId: "one", game: { enabled: true, servers: [server("a")] } });
    const pending = app.measureGameRoutes();
    Reflect.set(app, "connectionGeneration", 99);
    complete(summarizeGameSamples(Array(8).fill(10)));
    await pending;
    expect(selectGameRoute).not.toHaveBeenCalled();
  });
});
