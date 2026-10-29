import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthChallengeResponse } from "../src/main/api/models";

// The real updater loads the electron package outside vi.mock, which downloads its binary mid-test on CI.
vi.mock("../src/main/update/appUpdater", () => ({ AppUpdater: class AppUpdater { on(): this { return this; } } }));

vi.mock("electron", () => ({
  app: {
    getPath: () => "/tmp/levik-vpn-windows-test",
    getVersion: () => "1.2.3",
    isPackaged: true,
    setLoginItemSettings: vi.fn(),
  },
}));

vi.mock("../src/main/update/appUpdater", () => ({
  AppUpdater: class AppUpdater {
    on(): this {
      return this;
    }
  },
}));

vi.mock("../src/main/windows/killSwitch", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/main/windows/killSwitch")>(),
  WindowsKillSwitch: class WindowsKillSwitch {},
}));

import { AppController } from "../src/main/appController";
import { CoreStartError } from "../src/main/vpn/xrayManager";
import { nodeIdForHost } from "../src/main/platform/favoriteNodes";
import { buildXrayConfig } from "../src/main/vpn/xrayConfig";
import { compiledServiceRoutes } from "../src/main/vpn/serviceRoutes";
import type { MainSwitchResult } from "../src/main/vpn/serviceRouteSession";

describe("AppController login lifecycle", () => {
  it("does not resume login after cancellation while the challenge is pending", async () => {
    let resolveChallenge: ((challenge: AuthChallengeResponse) => void) | undefined;
    const createChallenge = vi.fn(
      () => new Promise<AuthChallengeResponse>((resolve) => {
        resolveChallenge = resolve;
      }),
    );
    const pollStatus = vi.fn();
    const controller = new AppController();
    Reflect.set(controller, "api", { createChallenge, pollStatus });
    Reflect.set(controller, "identity", {
      publicKeySpkiBase64Url: () => "public-key",
    });
    Reflect.set(controller, "secureStore", { get: vi.fn(() => Promise.resolve(null)), put: vi.fn() });
    controller.cancelLogin();

    const changed = vi.fn();
    controller.on("changed", changed);
    const login = controller.beginLogin();
    await vi.waitFor(() => expect(createChallenge).toHaveBeenCalledOnce());
    controller.cancelLogin();
    const snapshotAfterCancellation = controller.snapshot();
    const changesAfterCancellation = changed.mock.calls.length;

    resolveChallenge?.({
      ok: true,
      loginToken: "login-token",
      activationUriComplete: "https://leviknet.com/activate?code=ABCD-EFGH",
      activationCode: "ABCD-EFGH",
      pollIntervalSeconds: 2,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    await expect(login).rejects.toThrow("Вход отменён");
    expect(createChallenge).toHaveBeenCalledWith(expect.objectContaining({ numberMatchSupported: true }));
    expect(createChallenge).not.toHaveBeenCalledWith(expect.objectContaining({ accountHint: expect.anything() }));
    expect(pollStatus).not.toHaveBeenCalled();
    expect(controller.snapshot()).toEqual(snapshotAfterCancellation);
    expect(changed).toHaveBeenCalledTimes(changesAfterCancellation);
  });

  it("moves off a server before its maintenance and says so", async () => {
    const server = (id: string, address: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    Reflect.set(controller, "remoteStored", {
      config: { maintenance: [{ nodeId: nodeIdForHost("de1.example.net"), startsAt: now + 60_000, endsAt: now + 3_600_000 }], nodeLoad: {} },
      fetchedAt: now,
    });
    Reflect.set(controller, "xray", { isRunning: () => true });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net"), server("de2", "de2.example.net"), server("nl1", "nl1.example.net")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, de2: 60, nl1: 40 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    const notify = vi.fn();
    controller.on("notify", notify);

    await (Reflect.get(controller, "checkMaintenance") as () => Promise<void>).call(controller);

    expect(selectServer).toHaveBeenCalledWith("nl1");
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ title: "Сервер «DE1» уходит на обслуживание" }));
    expect(controller.snapshot().serverMaintenance).toEqual({ de1: now + 3_600_000 });
  });

  it("moves to the same country before maintenance, abroad when it has no other server", async () => {
    const server = (id: string, address: string, countryCode: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode, outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    const windows = ["de1.example.net", "de2.example.net"].map((host) => ({ nodeId: nodeIdForHost(host), startsAt: now + 60_000, endsAt: now + 3_600_000 }));
    Reflect.set(controller, "remoteStored", { config: { maintenance: windows, nodeLoad: {} }, fetchedAt: now });
    Reflect.set(controller, "xray", { isRunning: () => true });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net", "DE"), server("de2", "de2.example.net", "DE"), server("nl1", "nl1.example.net", "NL")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, de2: 60, nl1: 40 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    const check = Reflect.get(controller, "checkMaintenance") as () => Promise<void>;

    await check.call(controller);
    expect(selectServer).toHaveBeenCalledWith("nl1");

    // Only de1 is under maintenance now: slower de2 wins over faster nl1 abroad.
    Reflect.set(controller, "remoteStored", { config: { maintenance: windows.slice(0, 1), nodeLoad: {} }, fetchedAt: now });
    selectServer.mockClear();
    await check.call(controller);
    expect(selectServer).toHaveBeenCalledWith("de2");
  });

  it("chooses the best server of a country and keeps one already selected", async () => {
    const server = (id: string, address: string, countryCode: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode, outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      servers: [server("nl1", "nl1.example.net", "NL"), server("de1", "de1.example.net", "DE"), server("de2", "de2.example.net", "DE")],
      selectedServerId: "nl1",
      serverLatencies: { nl1: 10, de1: 90, de2: 30 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();

    await controller.selectCountry("de");
    expect(selectServer).toHaveBeenCalledWith("de2");

    state.selectedServerId = "de1";
    selectServer.mockClear();
    await controller.selectCountry("DE");
    expect(selectServer).not.toHaveBeenCalled();
    await expect(controller.selectCountry("FI")).rejects.toThrow("Страна не найдена");
  });

  it("keeps a live match on its server even right before maintenance", async () => {
    const server = (id: string, address: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    Reflect.set(controller, "remoteStored", {
      config: { maintenance: [{ nodeId: nodeIdForHost("de1.example.net"), startsAt: now + 60_000, endsAt: now + 3_600_000 }], nodeLoad: {} },
      fetchedAt: now,
    });
    Reflect.set(controller, "xray", { isRunning: () => true, gameFallback: null, gameRuntimeSnapshot: { currentMatch: { address: "203.0.113.7", port: 7100 } } });
    const state = Reflect.get(controller, "state") as Record<string, unknown> & { settings: Record<string, unknown> };
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net"), server("nl1", "nl1.example.net")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, nl1: 40 },
      settings: { ...state.settings, gameEnabled: true },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();

    await (Reflect.get(controller, "checkMaintenance") as () => Promise<void>).call(controller);

    expect(selectServer).not.toHaveBeenCalled();
  });

  it("ends a declined sign-in so it can start again", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AppController();
      const put = vi.fn();
      Reflect.set(controller, "secureStore", { get: vi.fn(() => Promise.resolve(null)), put });
      Reflect.set(controller, "identity", { publicKeySpkiBase64Url: () => "public-key" });
      Reflect.set(controller, "api", {
        createChallenge: vi.fn(() => Promise.resolve({
          ok: true,
          loginToken: "login-token",
          activationUriComplete: "https://leviknet.org/activate?code=ABCD-EFGH",
          activationCode: "ABCD-EFGH",
          pollIntervalSeconds: 2,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          matchNumber: 37,
          approvalRequested: true,
          telegramUriComplete: "https://t.me.example.net/levikvpnbot?start=web_" + "x".repeat(43),
        })),
        pollStatus: vi.fn(() => Promise.resolve({ ok: true, state: "declined" })),
      });
      controller.cancelLogin();

      const challenge = await controller.beginLogin();
      expect(challenge).toMatchObject({ matchNumber: 37, approvalRequested: true, telegramUri: null });
      expect(controller.snapshot().loginPending).toBe(true);

      await vi.advanceTimersByTimeAsync(2_000);
      expect(controller.snapshot()).toMatchObject({ loginPending: false, sessionAvailable: false });
      expect(controller.snapshot().statusDetail).toContain("Вход отменён");
      expect(put).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});

vi.mock("../src/main/vpn/tunnelHealth", () => ({ isTunnelHealthy: vi.fn(), TUNNEL_HEALTH_TAG: "levik-health", TUNNEL_HEALTH_PORT: 47186 }));
vi.mock("../src/main/vpn/serverPinger", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/main/vpn/serverPinger")>(),
  measureServerLatencies: vi.fn(),
}));

import { isTunnelHealthy } from "../src/main/vpn/tunnelHealth";
import { measureServerLatencies } from "../src/main/vpn/serverPinger";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { KillSwitchError } from "../src/main/windows/killSwitch";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConnectionTelemetry } from "../src/main/telemetry/connectionTelemetry";
import type { SessionRecorder } from "../src/main/telemetry/sessionRecorder";
import type { TelemetryClient } from "../src/main/telemetry/telemetryClient";

function tunnelController() {
  const controller = new AppController();
  const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "recovery", subscriptionId: "sub", issuedAt: new Date().toISOString(),
    source: {
      mediaType: "text/plain",
      content: "vless://11111111-1111-4111-8111-111111111111@first.example:443#DE\nvless://11111111-1111-4111-8111-111111111111@second.example:443#NL",
    },
  })), "sub");
  const [first, second] = profile.servers;
  if (!first || !second) throw new Error("Missing test servers");
  let running = false;
  const xray = {
    isRunning: vi.fn(() => running), isHealthy: vi.fn(async () => running),
    start: vi.fn(async (_config: Record<string, unknown>) => { running = true; }),
    stop: vi.fn(async () => { running = false; }),
  };
  let protectedTraffic = false;
  const killSwitch = {
    enable: vi.fn(async () => { protectedTraffic = true; }), allowTunnel: vi.fn(async () => {}),
    disable: vi.fn(async () => { protectedTraffic = false; }), isActive: vi.fn(() => protectedTraffic),
  };
  const dns = { enable: vi.fn(async () => {}), disable: vi.fn(async () => {}) };
  Reflect.set(controller, "profile", profile);
  Reflect.set(controller, "xray", xray);
  Reflect.set(controller, "killSwitch", killSwitch);
  Reflect.set(controller, "dnsLeakProtection", dns);
  Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
  // No live load in tests: Smart Auto ranks by the config's load, as with an older website.
  Reflect.set(controller, "liveLoadClient", { fetch: vi.fn(async () => ({ kind: "unsupported" })) });
  Reflect.set(controller, "state", {
    ...controller.snapshot(), busy: false, servers: profile.servers,
    selectedServerId: first.id, selectedSubscriptionId: "sub",
    serverLatencies: { [first.id]: 10, [second.id]: 20 },
  });
  vi.mocked(measureServerLatencies).mockResolvedValue({ [first.id]: 10, [second.id]: 20 });
  return { controller, xray, killSwitch, dns, first, second };
}

function exited(controller: AppController): void {
  Reflect.apply(Reflect.get(controller, "handleXrayExit"), controller, [1, false]);
}

async function checkTunnel(controller: AppController, immediate = false): Promise<void> {
  await Reflect.apply(Reflect.get(controller, "verifyTunnelHealth"), controller, [immediate]);
}

describe("AppController tunnel recovery", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(isTunnelHealthy).mockReset().mockResolvedValue(true);
  });
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("releases DNS and WFP after initial adapter authorization fails", async () => {
    const { controller, xray, killSwitch, dns } = tunnelController();
    killSwitch.allowTunnel.mockRejectedValueOnce(new Error("adapter unavailable"));
    await expect(controller.connect()).rejects.toThrow("adapter unavailable");
    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.disable).toHaveBeenCalledOnce();
    expect(dns.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("error");
    exited(controller);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(xray.start).toHaveBeenCalledOnce();
  });

  it("connects without the Kill Switch when Windows refuses the tunnel permit", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    killSwitch.allowTunnel.mockRejectedValueOnce(new KillSwitchError("Kill Switch не удалось allow-tunnel: код 1168", 1168));
    await controller.connect();
    expect(xray.isRunning()).toBe(true);
    expect(killSwitch.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "connected" });
    expect(controller.snapshot().statusDetail).toContain("Kill Switch не включился (ошибка Windows 1168)");

    await controller.disconnect();
    killSwitch.disable.mockClear();
    await controller.connect();
    expect(controller.snapshot().statusDetail).not.toContain("Kill Switch");
  });

  it("does not leave connecting status when protection cleanup fails", async () => {
    const { controller, killSwitch, dns } = tunnelController();
    killSwitch.allowTunnel.mockRejectedValueOnce(new Error("adapter unavailable"));
    killSwitch.disable.mockRejectedValueOnce(new Error("disable failed"));
    await expect(controller.connect()).rejects.toThrow("disable failed");
    expect(dns.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "error", busy: false });
  });

  it("an automatic connection tries the next server when one does not carry traffic", async () => {
    const { controller, xray, second } = tunnelController();
    const update = vi.fn(async () => undefined);
    Reflect.set(controller, "protocolHistory", {
      networkKey: () => "0123456789abcdef", current: () => ({ networks: [], winners: {} }), localSalt: () => "salt", update,
    });
    Reflect.set(controller, "latenciesMeasuredAt", Date.now());
    vi.mocked(isTunnelHealthy).mockResolvedValueOnce(false);

    await controller.connect();

    expect(xray.start).toHaveBeenCalledTimes(2);
    expect(update).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });
  });

  it("keeps a server chosen by hand and stays put without a network of its own", async () => {
    const { controller, xray } = tunnelController();
    Reflect.set(controller, "protocolHistory", {
      networkKey: () => null, current: () => ({ networks: [], winners: {} }), localSalt: () => "salt", update: vi.fn(),
    });
    Reflect.set(controller, "latenciesMeasuredAt", Date.now());
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await expect(controller.connect()).rejects.toThrow("Не удалось подтвердить доступ");
    expect(xray.start).toHaveBeenCalledOnce();

    Reflect.set(controller, "protocolHistory", {
      networkKey: () => "0123456789abcdef", current: () => ({ networks: [], winners: {} }), localSalt: () => "salt", update: vi.fn(),
    });
    await controller.updateSettings({ automaticServer: false });
    await expect(controller.connect()).rejects.toThrow("Не удалось подтвердить доступ");
    expect(xray.start).toHaveBeenCalledTimes(2);
  });

  it("does not try another server when the core fails on this computer", async () => {
    const { controller, xray } = tunnelController();
    const update = vi.fn(async () => undefined);
    Reflect.set(controller, "protocolHistory", {
      networkKey: () => "0123456789abcdef", current: () => ({ networks: [], winners: {} }), localSalt: () => "salt", update,
    });
    Reflect.set(controller, "latenciesMeasuredAt", Date.now());
    vi.mocked(isTunnelHealthy).mockImplementationOnce(async () => { await xray.stop(); return false; });
    await expect(controller.connect()).rejects.toThrow("Ядро VPN завершилось");
    expect(xray.start).toHaveBeenCalledOnce();
    expect(update).not.toHaveBeenCalled();
  });

  it("keeps the last direct pings while the tunnel would answer them itself", async () => {
    const { controller, first, second } = tunnelController();
    await controller.connect();
    vi.mocked(measureServerLatencies).mockClear();
    await controller.pingServers();
    expect(measureServerLatencies).not.toHaveBeenCalled();
    expect(controller.snapshot().serverLatencies).toEqual({ [first.id]: 10, [second.id]: 20 });
  });

  it.each([
    ["server", "startup"], ["server", "authorization"], ["server", "health"],
    ["settings", "startup"], ["settings", "authorization"], ["settings", "health"],
  ] as const)("retains WFP after %s replacement fails during %s until explicit disconnect", async (replacement, failure) => {
    const { controller, xray, killSwitch, dns, second } = tunnelController();
    await controller.updateSettings({ automaticServer: false });
    await controller.connect();
    if (failure === "startup") xray.start.mockRejectedValueOnce(new Error("startup failed"));
    if (failure === "authorization") killSwitch.allowTunnel.mockRejectedValueOnce(new Error("adapter unavailable"));
    if (failure === "health") vi.mocked(isTunnelHealthy).mockResolvedValueOnce(false);

    await expect(replacement === "server"
      ? controller.selectServer(second.id)
      : controller.updateSettings({ routingMode: "bypassRu" })).rejects.toThrow();

    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.isActive()).toBe(true);
    expect(killSwitch.disable).not.toHaveBeenCalled();
    expect(dns.disable).not.toHaveBeenCalled();
    expect(controller.snapshot()).toMatchObject({
      status: "error", busy: false, sessionStartedAt: null, settings: { killSwitch: true },
    });
    expect(controller.snapshot().statusDetail).toBeTruthy();

    // Retrying a failed replacement must preserve the same boundary too.
    vi.mocked(isTunnelHealthy).mockResolvedValueOnce(false);
    await expect(controller.connect()).rejects.toThrow("подтвердить доступ");
    expect(killSwitch.isActive()).toBe(true);
    expect(killSwitch.disable).not.toHaveBeenCalled();

    await controller.disconnect();
    expect(killSwitch.disable).toHaveBeenCalledOnce();
    expect(killSwitch.isActive()).toBe(false);
    expect(dns.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("releases protection when a settings replacement explicitly disables the kill switch", async () => {
    const { controller, killSwitch, dns } = tunnelController();
    await controller.connect();
    vi.mocked(isTunnelHealthy).mockResolvedValueOnce(false);
    await expect(controller.updateSettings({ killSwitch: false })).rejects.toThrow("подтвердить доступ");
    expect(killSwitch.isActive()).toBe(false);
    expect(dns.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "error", settings: { killSwitch: false } });
  });

  it("requires actual VPN traffic before reporting connected", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await expect(controller.connect()).rejects.toThrow("подтвердить доступ");
    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("error");
  });

  it("restores directly to a real VPN and keeps WFP enabled throughout", async () => {
    const { controller, xray, killSwitch, second } = tunnelController();
    await controller.connect();
    exited(controller);
    exited(controller); // Duplicate notifications cannot spawn parallel restores.
    expect(xray.start).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(xray.start).toHaveBeenCalledTimes(2);
    const config = xray.start.mock.calls[1]![0];
    expect(config.outbounds).toEqual(expect.arrayContaining([expect.objectContaining({ protocol: "vless" })]));
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });
    expect(killSwitch.disable).not.toHaveBeenCalled();
  });

  it("detects a live process with a dead VPN, tolerates transient failures, and rotates servers", async () => {
    const { controller, xray, second } = tunnelController();
    await controller.connect();
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await checkTunnel(controller);
    await checkTunnel(controller);
    expect(controller.snapshot().status).toBe("connected");
    await checkTunnel(controller);
    expect(controller.snapshot().status).toBe("reconnecting");
    expect(xray.isRunning()).toBe(true);
    vi.mocked(isTunnelHealthy).mockResolvedValue(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });
  });

  it("holds recovery while a match crosses the game nodes and recovers after it", async () => {
    const { controller, xray, second } = tunnelController();
    await controller.connect();
    let match: { address: string; port: number } | null = { address: "203.0.113.7", port: 7100 };
    Object.defineProperties(xray, {
      gameFallback: { value: null },
      gameRuntimeSnapshot: { get: () => ({ currentMatch: match }) },
    });
    const state = Reflect.get(controller, "state") as { settings: Record<string, unknown> };
    state.settings = { ...state.settings, gameEnabled: true };
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    for (let check = 0; check < 5; check++) await checkTunnel(controller);
    expect(controller.snapshot().status).toBe("connected");
    expect(controller.snapshot().statusDetail).toContain("после матча");
    expect(xray.start).toHaveBeenCalledOnce();

    match = null;
    await checkTunnel(controller);
    expect(controller.snapshot().status).toBe("reconnecting");
    vi.mocked(isTunnelHealthy).mockResolvedValue(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });
  });

  it("measures stale latencies again before a new automatic session", async () => {
    const { controller, xray, second } = tunnelController();
    vi.mocked(measureServerLatencies).mockResolvedValue({ [second.id]: 5 });
    await controller.connect();
    expect(measureServerLatencies).toHaveBeenCalled();
    expect(controller.snapshot().selectedServerId).toBe(second.id);
    expect(xray.start).toHaveBeenCalledOnce();
  });

  it("backs off failed recovery without blackhole cores and cancels its timer on disconnect", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    await controller.connect();
    exited(controller);
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot().status).toBe("reconnecting");
    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.disable).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(xray.start).toHaveBeenCalledTimes(3);
    await controller.disconnect();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(xray.start).toHaveBeenCalledTimes(3);
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("does not complete an in-flight restore after disconnect", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    await controller.connect();
    let finishStart: (() => void) | undefined;
    xray.start.mockImplementationOnce(() => new Promise<void>((resolve) => { finishStart = resolve; }));
    exited(controller);
    await vi.advanceTimersByTimeAsync(1_000);
    const disconnect = controller.disconnect();
    finishStart?.();
    await disconnect;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(controller.snapshot().status).toBe("disconnected");
    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.allowTunnel).toHaveBeenCalledOnce();
    expect(killSwitch.disable).toHaveBeenCalledOnce();
  });

  it("does not reconnect after shutdown while no core is running", async () => {
    const { controller, xray } = tunnelController();
    await controller.connect();
    exited(controller);
    await xray.stop();
    await controller.shutdown();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(xray.start).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("ignores a stale health failure after a new connection", async () => {
    const { controller } = tunnelController();
    await controller.connect();
    let finishProbe: ((healthy: boolean) => void) | undefined;
    vi.mocked(isTunnelHealthy).mockImplementationOnce(() => new Promise<boolean>((resolve) => { finishProbe = resolve; }));
    const health = checkTunnel(controller, true);
    await Promise.resolve();
    await controller.disconnect();
    await controller.connect();
    finishProbe?.(false);
    await health;
    expect(controller.snapshot().status).toBe("connected");
  });

  it.each([true, false])("ignores a deferred probe spanning automatic recovery (immediate=%s)", async (immediate) => {
    const { controller, xray, second } = tunnelController();
    await controller.connect();
    let finishProbe: ((healthy: boolean) => void) | undefined;
    vi.mocked(isTunnelHealthy).mockImplementationOnce(() => new Promise<boolean>((resolve) => { finishProbe = resolve; }));
    const health = checkTunnel(controller, immediate);
    await Promise.resolve();
    expect(finishProbe).toBeDefined();

    exited(controller);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });
    finishProbe?.(false);
    await health;
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id });

    // Stale periodic results must not count toward the new tunnel's threshold.
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await checkTunnel(controller);
    await checkTunnel(controller);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot().status).toBe("connected");
    expect(xray.start).toHaveBeenCalledTimes(2);
    await checkTunnel(controller);
    expect(controller.snapshot().status).toBe("reconnecting");
  });

  it("preserves a manually selected server during recovery", async () => {
    const { controller, first } = tunnelController();
    await controller.updateSettings({ automaticServer: false });
    await controller.connect();
    exited(controller);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: first.id });
  });

  it("honors autoReconnect off and exposes a recoverable error", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    await controller.updateSettings({ autoReconnect: false });
    await controller.connect();
    exited(controller);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(xray.start).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("error");
    expect(xray.isRunning()).toBe(false);
    expect(killSwitch.disable).not.toHaveBeenCalled();
    await controller.disconnect();
    expect(killSwitch.disable).toHaveBeenCalledOnce();
  });

  it("cancels an initial connection while Xray is still starting without reporting it as a failure", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    let finishStart: (() => void) | undefined;
    xray.start.mockImplementationOnce(() => new Promise<void>((resolve) => { finishStart = resolve; }));
    const connecting = controller.connect();
    await vi.advanceTimersByTimeAsync(0);
    const disconnect = controller.disconnect();
    finishStart?.();
    await expect(Promise.all([connecting, disconnect])).resolves.toBeDefined();
    expect(controller.snapshot().status).toBe("disconnected");
    expect(killSwitch.allowTunnel).not.toHaveBeenCalled();
  });

  it("ends a core left from a crash and starts again when the new core cannot take the adapter", async () => {
    const { controller, xray } = tunnelController();
    xray.start.mockRejectedValueOnce(new CoreStartError("Windows ещё не освободил сетевой адаптер Levik VPN.", true));
    const stopLeftoverCores = vi.fn(async () => true);
    Reflect.set(controller, "stopLeftoverCores", stopLeftoverCores);
    await controller.connect();
    expect(stopLeftoverCores).toHaveBeenCalledOnce();
    expect(xray.start).toHaveBeenCalledTimes(2);
    expect(controller.snapshot().status).toBe("connected");
  });

  it("reports the core's own start failure when no leftover core is in the way", async () => {
    const { controller, xray } = tunnelController();
    xray.start.mockRejectedValueOnce(new CoreStartError("Windows ещё не освободил сетевой адаптер Levik VPN.", true));
    Reflect.set(controller, "stopLeftoverCores", vi.fn(async () => false));
    Reflect.set(controller, "explainFailureByConflicts", vi.fn(async () => {}));
    await expect(controller.connect()).rejects.toThrow("сетевой адаптер");
    expect(xray.start).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "error", statusDetail: expect.stringContaining("сетевой адаптер") });
  });

  it("never blames other apps when the server, not this computer, failed", async () => {
    const { controller } = tunnelController();
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    const explain = vi.fn(async () => {});
    Reflect.set(controller, "explainFailureByConflicts", explain);
    const failed = expect(controller.connect()).rejects.toThrow("доступ в интернет");
    await vi.runAllTimersAsync();
    await failed;
    expect(explain).not.toHaveBeenCalled();
  });

  it("does not deadlock if profile refresh disconnects an expired session", async () => {
    const { controller } = tunnelController();
    Reflect.set(controller, "profile", null);
    Reflect.set(controller, "loadTunnelProfile", async () => {
      await controller.disconnect();
      throw new Error("expired session");
    });
    await expect(controller.connect()).rejects.toThrow("expired session");
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("keeps cleanup failures actionable so disconnect can be retried", async () => {
    const { controller, killSwitch } = tunnelController();
    await controller.connect();
    killSwitch.disable.mockRejectedValueOnce(new Error("disable failed"));
    await expect(controller.disconnect()).rejects.toThrow("disable failed");
    expect(controller.snapshot()).toMatchObject({ status: "error", busy: false });
    await controller.disconnect();
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("does not restart a settings replacement after disconnect", async () => {
    const { controller, xray } = tunnelController();
    await controller.connect();
    let finishStop: (() => void) | undefined;
    xray.stop.mockImplementationOnce(() => new Promise<void>((resolve) => { finishStop = resolve; }));
    const settings = controller.updateSettings({ routingMode: "bypassRu" });
    await vi.advanceTimersByTimeAsync(0);
    const disconnect = controller.disconnect();
    finishStop?.();
    await Promise.all([settings, disconnect]);
    expect(xray.start).toHaveBeenCalledOnce();
    expect(controller.snapshot().status).toBe("disconnected");
  });

  it("keeps protection and reports an error when the core cannot be stopped", async () => {
    const { controller, xray, killSwitch, dns } = tunnelController();
    await controller.connect();
    xray.stop.mockRejectedValueOnce(new Error("core still running"));
    await expect(controller.disconnect()).rejects.toThrow("core still running");
    expect(killSwitch.disable).not.toHaveBeenCalled();
    expect(dns.disable).not.toHaveBeenCalled();
    expect(controller.snapshot()).toMatchObject({ status: "error", busy: false });
    await controller.disconnect();
    expect(killSwitch.disable).toHaveBeenCalledOnce();
  });

  it("rejects invalid DNS octets without disrupting a connected tunnel", async () => {
    const { controller, xray } = tunnelController();
    await controller.connect();
    await expect(controller.updateSettings({ dnsServer: "999.1.1.1" })).rejects.toThrow("DNS");
    expect(xray.stop).not.toHaveBeenCalled();
    expect(controller.snapshot().status).toBe("connected");
  });

  it("reconnects when another server is selected after a protected replacement failure", async () => {
    const { controller, killSwitch, first, second } = tunnelController();
    await controller.updateSettings({ automaticServer: false });
    await controller.connect();
    vi.mocked(isTunnelHealthy).mockResolvedValueOnce(false);
    await expect(controller.selectServer(second.id)).rejects.toThrow("подтвердить доступ");
    expect(killSwitch.isActive()).toBe(true);
    await controller.selectServer(first.id);
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: first.id });
    expect(killSwitch.disable).not.toHaveBeenCalled();
  });

  it("uses end-to-end health after resume even when the stats API still works", async () => {
    const { controller } = tunnelController();
    await controller.connect();
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    const resumed = controller.restoreAfterSystemResume();
    await vi.advanceTimersByTimeAsync(1_500);
    await resumed;
    expect(controller.snapshot().status).toBe("reconnecting");
  });
});

describe("AppController connection telemetry", () => {
  let directory: string;
  let telemetry: ConnectionTelemetry | null = null;
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "levik-controller-telemetry-"));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
    vi.mocked(isTunnelHealthy).mockReset().mockResolvedValue(true);
  });
  afterEach(async () => {
    vi.clearAllTimers();
    vi.useRealTimers();
    // Switching off waits for queued writes and removes the queue.
    await telemetry?.setEnabled(false);
    telemetry = null;
    await rm(directory, { recursive: true, force: true });
  });

  async function withTelemetry(controller: AppController) {
    const http = {
      send: vi.fn(async () => "sent" as const),
      networkToken: vi.fn(async () => ({ token: "net.token", expiresAt: Date.now() + 60_000 })),
    };
    const instance = new ConnectionTelemetry(directory, { platform: "windows", app: "1.2.3", os: "11" }, http as unknown as TelemetryClient);
    telemetry = instance;
    await instance.setEnabled(true);
    Reflect.set(controller, "telemetry", instance);
    const current = () => Reflect.get(instance, "session") as SessionRecorder | null;
    return Object.assign(current, { http });
  }

  it("records a drop detected by health checks, the failover and a user disconnect", async () => {
    const { controller, first, second } = tunnelController();
    const current = await withTelemetry(controller);
    await controller.connect();
    const session = current();
    expect(session).not.toBeNull();
    vi.mocked(isTunnelHealthy).mockImplementation(async (options) => {
      options?.onFailure?.(["timeout", "tls"]);
      return false;
    });
    await checkTunnel(controller);
    await checkTunnel(controller);
    await checkTunnel(controller);
    vi.mocked(isTunnelHealthy).mockReset().mockResolvedValue(true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot().status).toBe("connected");
    await controller.disconnect();

    const body = session!.snapshot();
    expect(body).toMatchObject({ final: true, trigger: "user", net: { token: "net.token" }, end: { by: "user", code: "user" } });
    expect(body.timeline.map((event) => event.e)).toEqual([
      "attempt", "connected", "probe_fail", "probe_fail", "probe_fail", "recovery", "attempt", "connected",
    ]);
    expect(body.timeline[0]).toMatchObject({ node: first.name, proto: "vless-tcp", cause: "initial" });
    expect(body.timeline[2]).toMatchObject({ codes: ["timeout", "tls"], n: 1 });
    expect(body.timeline[5]).toMatchObject({ action: "failover" });
    expect(body.timeline[6]).toMatchObject({ node: second.name, cause: "failover" });
  });

  it("ends a failed first attempt with the stage that failed", async () => {
    const { controller, xray } = tunnelController();
    const current = await withTelemetry(controller);
    xray.start.mockRejectedValueOnce(new Error("startup failed"));
    const pending = controller.connect();
    await Promise.resolve();
    await expect(pending).rejects.toThrow("startup failed");
    expect((Reflect.get(controller, "telemetry") as ConnectionTelemetry).active).toBe(false);
    // The finished session is saved and then sent.
    await vi.waitFor(() => expect(current.http.send).toHaveBeenCalled());
    const [request] = current.http.send.mock.calls.at(-1) as unknown as [string];
    const body = (JSON.parse(request) as { sessions: ReturnType<SessionRecorder["snapshot"]>[] }).sessions[0]!;
    expect(body).toMatchObject({ final: true, end: { by: "error", code: "core_start_failed" } });
    expect(body.timeline.at(-1)).toMatchObject({ e: "attempt_failed", stage: "core", code: "core_start_failed" });
  });

  it("names the reason the core gave for not starting", async () => {
    const { controller, xray } = tunnelController();
    const current = await withTelemetry(controller);
    xray.start.mockImplementationOnce(async () => {
      Reflect.apply(Reflect.get(controller, "handleCoreLog"), controller, [
        "Failed to start: main: failed to create server > listen tcp 127.0.0.1:47186: bind: An attempt was made to access a socket in a way forbidden by its access permissions.",
      ]);
      throw new Error("startup failed");
    });
    await expect(controller.connect()).rejects.toThrow("startup failed");
    await vi.waitFor(() => expect(current.http.send).toHaveBeenCalled());
    const [request] = current.http.send.mock.calls.at(-1) as unknown as [string];
    const body = (JSON.parse(request) as { sessions: ReturnType<SessionRecorder["snapshot"]>[] }).sessions[0]!;
    expect(body).toMatchObject({ end: { by: "error", code: "core_start_failed:port_unavailable" } });
    expect(body.timeline.at(-1)).toMatchObject({ e: "attempt_failed", stage: "core", code: "core_start_failed:port_unavailable" });
  });

  it("suggests a TCP server when a manually chosen UDP server keeps failing", () => {
    const controller = new AppController();
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "udp", subscriptionId: "sub", issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "hysteria2://secret@hy.example:443?sni=hy.example#Hysteria2\nvless://11111111-1111-4111-8111-111111111111@tcp.example:443#Prime",
      },
    })), "sub");
    const [udp, tcp] = profile.servers;
    if (!udp || !tcp) throw new Error("Missing test servers");
    const state = controller.snapshot();
    Reflect.set(controller, "state", {
      ...state, servers: profile.servers, selectedServerId: udp.id,
      serverLatencies: { [tcp.id]: 30 }, settings: { ...state.settings, automaticServer: false },
    });
    Reflect.set(controller, "reconnectAttempts", 2);
    Reflect.apply(Reflect.get(controller, "suggestServerOutsideUdp"), controller, []);
    expect(controller.snapshot().statusDetail).toContain("блокирует UDP");
    expect(controller.snapshot().statusDetail).toContain("Prime");
    expect(controller.snapshot().selectedServerId).toBe(udp.id);
  });

  it("marks a server change as a switch within the same session", async () => {
    const { controller, second } = tunnelController();
    const current = await withTelemetry(controller);
    await controller.updateSettings({ automaticServer: false });
    await controller.connect();
    const session = current();
    await controller.selectServer(second.id);
    expect(current()).toBe(session);
    const attempts = session!.snapshot().timeline.filter((event) => event.e === "attempt");
    expect(attempts.map((event) => event.cause)).toEqual(["initial", "server_switch"]);
  });
});


describe("Smart Auto full-route controller integration", () => {
  it("ranks and displays actual cascade latency, keeps endpoint refresh from overriding it and invalidates on a new network", () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = (id: string, address: string) => ({ id, tag: id, name: id, countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address, port: 443 }] } } });
    const cascade = server("cascade", "moscow.example"), direct = server("direct", "de.example");
    let network = "network-one";
    Reflect.set(controller, "protocolHistory", { current: () => ({ networks: [], winners: {} }), networkKey: () => network, localSalt: () => "local-salt" });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { servers: [cascade, direct], serverLatencies: { cascade: 5, direct: 60 } });
    Reflect.set(controller, "endpointLatencies", { cascade: 5, direct: 60 });
    const now = Date.now();
    const observation = (medianMs: number) => ({ measuredAt: now, confidence: "measured", medianMs, jitterMs: 2, failureRate: 0, targets: 2, samples: 6, setupMs: 100, downMbps: 100, upMbps: 30 });
    Reflect.set(controller, "routeMeasurements", { cascade: observation(190), direct: observation(55) });
    Reflect.set(controller, "routeMeasurementNetwork", network);
    const key = Reflect.get(controller, "routeMeasurementKey") as (server: typeof cascade) => string;
    Reflect.set(controller, "routeMeasurementKeys", { cascade: key.call(controller, cascade), direct: key.call(controller, direct) });
    const rank = Reflect.get(controller, "rankServers") as (servers: Array<typeof cascade>) => Array<{ id: string }>;
    const display = Reflect.get(controller, "displayedRouteLatencies") as (raw: Record<string, number | null>) => Record<string, number | null>;
    expect(rank.call(controller, [cascade, direct])[0]?.id).toBe("direct");
    expect(display.call(controller, { cascade: 1, direct: 2 })).toEqual({ cascade: 190, direct: 55 });
    network = "network-two";
    expect(display.call(controller, { cascade: 1, direct: 2 })).toEqual({ cascade: 1, direct: 2 });
  });

  it("does not begin a stale session when OFF happens during the post-probe selection write", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = { id: "a", tag: "a", name: "a", countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address: "de.example", port: 443 }] } } };
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>;
    Object.assign(settings, { automaticServer: true, gameEnabled: false });
    Object.assign(state, { status: "disconnected", servers: [server], serverLatencies: { a: 30 }, selectedServerId: "a", elevated: true });
    Reflect.set(controller, "profile", { profileId: "test", subscriptionId: "test", subscriptionExpiresAt: null, servers: [server], directDomains: [], proxyDomains: [], directCidrs: [] });
    Reflect.set(controller, "xray", { isRunning: () => false });
    Reflect.set(controller, "latenciesMeasuredAt", Date.now());
    Reflect.set(controller, "refreshLiveLoad", vi.fn(async () => {}));
    Reflect.set(controller, "refreshRouteMeasurements", vi.fn(async () => true));
    Reflect.set(controller, "stopConnection", vi.fn(async () => {}));
    const begin = vi.fn();
    Reflect.set(controller, "telemetry", { active: false, begin });
    let release: (() => void) | undefined;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const follow = vi.fn(async () => await pending);
    Reflect.set(controller, "followBestServer", follow);
    const operation = controller.connect();
    await vi.waitFor(() => expect(follow).toHaveBeenCalledOnce());
    await controller.disconnect();
    release?.();
    await operation;
    expect(begin).not.toHaveBeenCalled();
  });
});


describe("Smart Auto probe cancellation boundaries", () => {
  it("aborts preflight immediately when a manual server is selected", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const abort = new AbortController();
    Reflect.set(controller, "routeProbeAbort", abort);
    Reflect.set(controller, "xray", { isRunning: () => false });
    Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { servers: [{ id: "manual", tag: "manual", name: "manual", countryCode: "DE", outbound: {} }] });
    const intent = Reflect.get(controller, "connectionIntent");
    await controller.selectServer("manual");
    expect(abort.signal.aborted).toBe(true);
    expect(Reflect.get(controller, "connectionIntent")).toBeGreaterThan(intent);
    expect(controller.snapshot().selectedServerId).toBe("manual");
  });

  it("invalidates effective transport measurements when settings or profile scope changes", () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = { id: "a", tag: "a", name: "a", countryCode: "DE", outbound: { protocol: "vless" } };
    const key = Reflect.get(controller, "routeMeasurementKey") as (input: typeof server) => string;
    const first = key.call(controller, server);
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>;
    settings.antiDpiEnabled = !settings.antiDpiEnabled;
    expect(key.call(controller, server)).not.toBe(first);
    const abort = new AbortController();
    Reflect.set(controller, "routeProbeAbort", abort);
    Reflect.set(controller, "routeMeasurements", { a: { medianMs: 50 } });
    const invalidate = Reflect.get(controller, "invalidateRouteMeasurements") as () => void;
    invalidate.call(controller);
    expect(abort.signal.aborted).toBe(true);
    expect(Reflect.get(controller, "routeMeasurements")).toEqual({});
  });
});


describe("Smart Auto hot mode controller", () => {
  it("enables the existing ordinary owner without selecting/restarting the connected server", async () => {
    const controller = new AppController(); controller.cancelLogin();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>; settings.automaticServer = false;
    Object.assign(state, { status: "connected", selectedServerId: "manual" });
    const enabled = vi.fn(async () => true), refresh = vi.fn(async () => {}), start = vi.fn(), stop = vi.fn();
    Reflect.set(controller, "xray", { isRunning: () => true, start, stop,
      serviceRoutes: { automaticAvailable: true, smartAutoActive: true, setAutomaticEnabled: enabled, refreshAutomatic: refresh, mainServerId: "manual" } });
    Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
    Reflect.set(controller, "applyLoginItemSettings", vi.fn());
    Reflect.set(controller, "refreshLiveLoad", vi.fn(async () => {}));
    Reflect.set(controller, "recordSyncedChanges", vi.fn(async () => {}));
    Reflect.set(controller, "emitChanged", vi.fn());
    Reflect.set(controller, "telemetry", { record: vi.fn() });
    const select = vi.spyOn(controller, "selectServer").mockResolvedValue();
    await controller.selectAutomatic();
    expect(enabled).toHaveBeenCalledWith(true); expect(refresh).toHaveBeenCalledOnce();
    expect(select).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled(); expect(stop).not.toHaveBeenCalled();
    expect(controller.snapshot().selectedServerId).toBe("manual");
  });
});


describe("Smart Auto control failure isolation", () => {
  it("retains a live core after repeated API failures but leaves dead-core recovery intact", async () => {
    const controller = new AppController(); controller.cancelLogin();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { status: "connected", selectedServerId: "a" });
    let running = true;
    const recheck = vi.fn(async () => {}), recover = vi.fn();
    const data = vi.fn(async () => true);
    Reflect.set(controller, "xray", { isRunning: () => running, isHealthy: async () => false,
      serviceRoutes: { active: true, smartAutoActive: true, authentication: {}, probeCurrent: data, refreshAutomatic: recheck } });
    Reflect.set(controller, "telemetry", { record: vi.fn() });
    Reflect.set(controller, "beginTunnelRecovery", recover);
    const check = Reflect.get(controller, "verifyTunnelHealth") as (immediate?: boolean) => Promise<void>;
    for (let i = 0; i < 4; i++) await check.call(controller, true);
    expect(recover).not.toHaveBeenCalled(); expect(recheck).toHaveBeenCalledTimes(4);
    expect(data).toHaveBeenCalledTimes(4);
    expect(controller.snapshot().status).toBe("connected");
    running = false; await check.call(controller, true);
    expect(recover).toHaveBeenCalledOnce();
  });
});

async function hotSwitchController() {
  const fixture = tunnelController();
  const { controller, xray, first, second } = fixture;
  await xray.start({});
  xray.start.mockClear();
  const profile = Reflect.get(controller, "profile") as ReturnType<typeof prepareTunnelProfile>;
  const previous = controller.snapshot();
  const settings = { ...previous.settings, automaticServer: false, gameEnabled: false };
  Reflect.set(controller, "state", { ...previous, status: "connected", statusDetail: "Защищено через первый сервер",
    settings, sessionStartedAt: 123_000, downloadBytes: 12_345, uploadBytes: 678 });
  const config = buildXrayConfig(profile, first, settings, "test-game-password");
  Reflect.apply(Reflect.get(controller, "rememberInstalledMainSources"), controller, [config]);
  Reflect.set(controller, "lastConfig", config);
  const put = vi.fn(async (_key: string, _value: Uint8Array) => {});
  Reflect.set(controller, "secureStore", { put });
  let installed = first.id;
  const routes = {
    automaticAvailable: true, active: false, policyActive: false, smartAutoActive: false,
    mainSelectionCertain: true, selectableMainIds: [first.id, second.id],
    get mainServerId() { return installed; },
    canSelectMain: vi.fn((id: string) => id === first.id || id === second.id),
    setAutomaticEnabled: vi.fn(async (_enabled: boolean) => true),
    selectMain: vi.fn(async (id: string): Promise<MainSwitchResult> => { installed = id; return { status: "applied", serverId: id }; }),
  };
  Reflect.set(xray, "serviceRoutes", routes);
  return { ...fixture, routes, put, config };
}

function pendingMainSelection() {
  let resolve: (result: MainSwitchResult) => void = () => { throw new Error("Missing pending switch"); };
  const promise = new Promise<MainSwitchResult>((complete) => { resolve = complete; });
  return { promise, resolve };
}

describe("manual HotSwitch controller", () => {
  it("publishes and persists the new server only after acknowledgement without replacing the tunnel", async () => {
    const { controller, routes, xray, killSwitch, dns, first, second, put, config } = await hotSwitchController();
    const pending = pendingMainSelection();
    routes.selectMain.mockReturnValueOnce(pending.promise);
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalledWith(second.id));
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: first.id,
      hotSwitch: { phase: "preparing", targetServerId: second.id }, sessionStartedAt: 123_000 });
    expect(put).not.toHaveBeenCalled();
    pending.resolve({ status: "applied", serverId: second.id });
    await operation;
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id,
      hotSwitch: { phase: "applied", targetServerId: second.id }, sessionStartedAt: 123_000, downloadBytes: 12_345, uploadBytes: 678 });
    expect(put).toHaveBeenCalledWith("selected_server", Buffer.from(second.id));
    expect(compiledServiceRoutes(config)?.automatic?.selectedId).toBe(second.id);
    expect(xray.start).not.toHaveBeenCalled(); expect(xray.stop).not.toHaveBeenCalled();
    expect(killSwitch.enable).not.toHaveBeenCalled(); expect(killSwitch.disable).not.toHaveBeenCalled();
    expect(dns.enable).not.toHaveBeenCalled(); expect(dns.disable).not.toHaveBeenCalled();
  });

  it("retains the connected selection and never falls back to a restart after a failed hot attempt", async () => {
    const { controller, routes, xray, first, second, put } = await hotSwitchController();
    routes.selectMain.mockResolvedValueOnce({ status: "failed" });
    const replacement = vi.spyOn(controller, "selectServer");
    await expect(controller.chooseServer(second.id)).rejects.toThrow("Предыдущее подключение сохранено");
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: first.id,
      hotSwitch: { phase: "failed" }, sessionStartedAt: 123_000 });
    expect(replacement).not.toHaveBeenCalled(); expect(xray.stop).not.toHaveBeenCalled(); expect(put).not.toHaveBeenCalled();
  });

  it("reports an uncertain route without claiming that the previous exit was retained", async () => {
    const { controller, routes, first, second, xray, put } = await hotSwitchController();
    routes.mainSelectionCertain = false;
    routes.selectMain.mockResolvedValueOnce({ status: "uncertain" });
    await expect(controller.chooseServer(second.id)).rejects.toThrow("Не удалось подтвердить маршрут");
    const state = controller.snapshot();
    expect(state).toMatchObject({ status: "connected", selectedServerId: first.id, hotSwitch: { phase: "uncertain" } });
    expect(state.statusDetail).toContain("маршрут не подтверждён");
    expect(state.hotSwitch?.message).not.toContain("сохранено");
    expect(xray.stop).not.toHaveBeenCalled(); expect(put).not.toHaveBeenCalled();
  });

  it("uses the legacy selection only when the target was not offered as HotSwitch", async () => {
    const { controller, routes, second } = await hotSwitchController();
    routes.canSelectMain.mockImplementation((id) => id !== second.id);
    const replacement = vi.spyOn(controller, "selectServer").mockResolvedValue();
    expect(controller.snapshot().hotSwitchServerIds).not.toContain(second.id);
    await controller.chooseServer(second.id);
    expect(replacement).toHaveBeenCalledWith(second.id); expect(routes.selectMain).not.toHaveBeenCalled();
  });

  it("uses HotSwitch for a manual country choice and disables Auto without resetting the session", async () => {
    const { controller, routes, second } = await hotSwitchController();
    const state = controller.snapshot();
    Reflect.set(controller, "state", { ...state, settings: { ...state.settings, automaticServer: true } });
    await controller.chooseCountry(second.countryCode);
    expect(routes.setAutomaticEnabled).toHaveBeenCalledWith(false);
    expect(routes.selectMain).toHaveBeenCalledWith(second.id);
    expect(controller.snapshot()).toMatchObject({ selectedServerId: second.id, settings: { automaticServer: false }, sessionStartedAt: 123_000 });
  });

  it("does nothing for the confirmed current server but allows retrying an uncertain current server", async () => {
    const { controller, routes, first, xray } = await hotSwitchController();
    await controller.chooseServer(first.id);
    expect(routes.selectMain).not.toHaveBeenCalled(); expect(xray.stop).not.toHaveBeenCalled();
    routes.mainSelectionCertain = false;
    await controller.chooseServer(first.id);
    expect(routes.selectMain).toHaveBeenCalledWith(first.id);
  });

  it("ignores an old switch result and Auto report after a newer manual click", async () => {
    const { controller, routes, first, second, put } = await hotSwitchController();
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    const old = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalledWith(second.id));
    await controller.chooseServer(first.id);
    expect(routes.selectMain).toHaveBeenLastCalledWith(first.id);
    pending.resolve({ status: "applied", serverId: second.id }); await old;
    Reflect.apply(Reflect.get(controller, "smartAutoLiveChanged"), controller,
      [{ currentId: second.id, measurements: {}, switched: true }]);
    expect(controller.snapshot()).toMatchObject({ selectedServerId: first.id, hotSwitch: { phase: "applied", targetServerId: first.id } });
    expect(put).not.toHaveBeenCalledWith("selected_server", Buffer.from(second.id));
  });

  it("does not revive the selection or connection when OFF happens during verification", async () => {
    const { controller, routes, first, second, put } = await hotSwitchController();
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalled());
    await controller.disconnect();
    pending.resolve({ status: "applied", serverId: second.id }); await operation;
    expect(controller.snapshot()).toMatchObject({ status: "disconnected", selectedServerId: first.id, hotSwitch: null, sessionStartedAt: null });
    expect(put).not.toHaveBeenCalledWith("selected_server", Buffer.from(second.id));
  });

  it("keeps a successful switch active when saving the preference fails", async () => {
    const { controller, routes, second, put, config, xray } = await hotSwitchController();
    put.mockRejectedValueOnce(new Error("storage unavailable"));
    await controller.chooseServer(second.id);
    expect(routes.selectMain).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id, hotSwitch: { phase: "applied" } });
    expect(controller.snapshot().hotSwitch?.message).toContain("сохранить выбор не удалось");
    expect(compiledServiceRoutes(config)?.automatic?.selectedId).toBe(second.id); expect(xray.stop).not.toHaveBeenCalled();
  });

  it.each(["endpoint", "credentials"] as const)("requires a reconnect when a refreshed target reuses its id with different %s", async (change) => {
    const { controller, routes, second } = await hotSwitchController();
    const state = controller.snapshot();
    const profile = Reflect.get(controller, "profile") as ReturnType<typeof prepareTunnelProfile>;
    const changed = { ...second, outbound: { ...second.outbound, settings: change === "endpoint"
      ? { vnext: [{ address: "new.example", port: 8443 }] } : { vnext: [{ address: "second.example", port: 443,
        users: [{ id: "22222222-2222-4222-8222-222222222222", encryption: "none" }] }] } } };
    const servers = state.servers.map((server) => server.id === second.id ? changed : server);
    Reflect.set(controller, "profile", { ...profile, servers });
    Reflect.set(controller, "state", { ...state, servers });
    const replacement = vi.spyOn(controller, "selectServer").mockResolvedValue();
    expect(controller.snapshot().hotSwitchServerIds).not.toContain(second.id);
    await controller.chooseServer(second.id);
    expect(replacement).toHaveBeenCalledWith(second.id); expect(routes.selectMain).not.toHaveBeenCalled();
  });

  it("cancels a pending manual display when Auto is chosen and ignores the late result", async () => {
    const { controller, routes, first, second } = await hotSwitchController();
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    Reflect.set(routes, "refreshAutomatic", vi.fn(async () => {}));
    Reflect.set(controller, "refreshLiveLoad", vi.fn(async () => {}));
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalled());
    await controller.selectAutomatic();
    pending.resolve({ status: "applied", serverId: second.id }); await operation;
    expect(routes.setAutomaticEnabled).toHaveBeenCalledWith(true);
    expect(controller.snapshot()).toMatchObject({ settings: { automaticServer: true }, selectedServerId: first.id, hotSwitch: null });
  });

  it("cancels the owner selection before replacing the profile during verification", async () => {
    const { controller, routes, second, first } = await hotSwitchController();
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalled());
    const profile = Reflect.get(controller, "profile") as ReturnType<typeof prepareTunnelProfile>;
    Reflect.set(controller, "reconcileFavorites", vi.fn(async () => {}));
    await Reflect.apply(Reflect.get(controller, "applyTunnelProfile"), controller, [{ ...profile }]);
    pending.resolve({ status: "applied", serverId: second.id }); await operation;
    expect(routes.setAutomaticEnabled).toHaveBeenCalledWith(false);
    expect(controller.snapshot()).toMatchObject({ selectedServerId: first.id, hotSwitch: null });
  });

  it("captures the immutable source pool when starting a newly built recovery config", async () => {
    const { controller, first, second } = await hotSwitchController();
    const profile = Reflect.get(controller, "profile") as ReturnType<typeof prepareTunnelProfile>;
    const config = buildXrayConfig(profile, first, controller.snapshot().settings, "test-game-password");
    Reflect.set(controller, "lastConfig", config);
    expect(controller.snapshot().hotSwitchServerIds).toEqual([]);
    await Reflect.apply(Reflect.get(controller, "startXray"), controller,
      [config, Reflect.get(controller, "connectionGeneration")]);
    expect(controller.snapshot().hotSwitchServerIds).toContain(second.id);
  });

  it("does not relabel an old retained recovery config with a refreshed profile's credentials", async () => {
    const { controller, second, config } = await hotSwitchController();
    const profile = Reflect.get(controller, "profile") as ReturnType<typeof prepareTunnelProfile>;
    const changed = { ...second, outbound: { ...second.outbound, settings: { vnext: [{ address: "replacement.example", port: 443 }] } } };
    const servers = profile.servers.map((server) => server.id === second.id ? changed : server);
    Reflect.set(controller, "profile", { ...profile, servers });
    Reflect.set(controller, "state", { ...controller.snapshot(), servers });
    await Reflect.apply(Reflect.get(controller, "startXray"), controller,
      [config, Reflect.get(controller, "connectionGeneration")]);
    expect(controller.snapshot().hotSwitchServerIds).not.toContain(second.id);
  });

  it("keeps route uncertainty visible even if another action cleared the local notice", async () => {
    const { controller, routes } = await hotSwitchController();
    routes.mainSelectionCertain = false;
    const snapshot = controller.snapshot();
    expect(snapshot.hotSwitch).toMatchObject({ phase: "uncertain" });
    expect(snapshot.hotSwitch?.message).toContain("Переподключитесь или повторите выбор");
  });

  it("clears preparation when eligibility is withdrawn during verification without changing the core generation", async () => {
    const { controller, routes, second, first } = await hotSwitchController();
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalled());
    routes.canSelectMain.mockReturnValue(false);
    pending.resolve({ status: "cancelled" }); await operation;
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: first.id, hotSwitch: null });
  });
});

async function controlledHealth(active: boolean) {
  const fixture = await hotSwitchController();
  const { controller, routes, xray } = fixture;
  routes.active = active;
  const data = vi.fn(async () => true), recover = vi.fn();
  Reflect.set(routes, "authentication", {});
  Reflect.set(routes, "probeCurrent", data);
  const originalRecovery = Reflect.get(controller, "beginTunnelRecovery");
  Reflect.set(controller, "beginTunnelRecovery", recover);
  xray.isHealthy.mockResolvedValue(false);
  return { ...fixture, data, recover, originalRecovery };
}

describe("HotSwitch health and control failure isolation", () => {
  it.each([true, false])("uses independent data proof to retain a manual core despite API failure (service policy=%s)", async (active) => {
    const { controller, data, recover, xray } = await controlledHealth(active);
    for (let i = 0; i < 4; i++) await checkTunnel(controller, true);
    expect(data).toHaveBeenCalledTimes(4);
    expect(xray.isHealthy).toHaveBeenCalledTimes(active ? 4 : 0);
    expect(recover).not.toHaveBeenCalled(); expect(xray.stop).not.toHaveBeenCalled();
    expect(controller.snapshot().status).toBe("connected");
    if (active) expect(controller.snapshot().statusDetail).toContain("Управление маршрутами временно недоступно");
  });

  it.each([true, false])("recovers genuinely failed data even when the control API replies (service policy=%s)", async (active) => {
    const { controller, data, recover, xray } = await controlledHealth(active);
    xray.isHealthy.mockResolvedValue(true); data.mockResolvedValue(false);
    await checkTunnel(controller); await checkTunnel(controller);
    expect(recover).not.toHaveBeenCalled();
    await checkTunnel(controller);
    expect(recover).toHaveBeenCalledOnce(); expect(data).toHaveBeenCalledTimes(3);
  });

  it("does not infer an uncertain live route from the last acknowledged target, but still detects core death", async () => {
    const { controller, routes, data, recover, xray } = await controlledHealth(true);
    routes.mainSelectionCertain = false;
    for (let i = 0; i < 4; i++) await checkTunnel(controller, true);
    expect(data).not.toHaveBeenCalled(); expect(xray.isHealthy).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled();
    expect(controller.snapshot()).toMatchObject({ status: "connected", hotSwitch: { phase: "uncertain" } });
    expect(controller.snapshot().statusDetail).toContain("маршрут не подтверждён");
    await xray.stop(); await checkTunnel(controller, true);
    expect(recover).toHaveBeenCalledOnce();
  });

  it("defers health work to an in-flight manual selection while preserving dead-core recovery", async () => {
    const { controller, routes, data, recover, originalRecovery, xray, second } = await controlledHealth(true);
    const pending = pendingMainSelection(); routes.selectMain.mockReturnValueOnce(pending.promise);
    const operation = controller.chooseServer(second.id);
    await vi.waitFor(() => expect(routes.selectMain).toHaveBeenCalled());
    await checkTunnel(controller, true);
    expect(data).not.toHaveBeenCalled(); expect(xray.isHealthy).not.toHaveBeenCalled(); expect(recover).not.toHaveBeenCalled();
    expect(controller.snapshot().hotSwitch?.phase).toBe("preparing");
    recover.mockImplementation((...args: unknown[]) => Reflect.apply(originalRecovery, controller, args));
    await xray.stop(); await checkTunnel(controller, true);
    expect(recover).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "reconnecting", hotSwitch: null });
    pending.resolve({ status: "cancelled" }); await operation;
    await controller.disconnect();
  });

  it("discards a late failed probe of the old target after a successful manual switch", async () => {
    const { controller, data, recover, xray, second } = await controlledHealth(true);
    let complete: (value: boolean) => void = () => { throw new Error("Missing probe"); };
    data.mockImplementationOnce(() => new Promise<boolean>((resolve) => { complete = resolve; }));
    xray.isHealthy.mockResolvedValue(true);
    const check = checkTunnel(controller, true);
    await vi.waitFor(() => expect(data).toHaveBeenCalled());
    await controller.chooseServer(second.id);
    complete(false); await check;
    expect(recover).not.toHaveBeenCalled();
    expect(controller.snapshot()).toMatchObject({ status: "connected", selectedServerId: second.id, hotSwitch: { phase: "applied" } });
  });
});
