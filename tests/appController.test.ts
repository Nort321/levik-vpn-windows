import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthChallengeResponse } from "../src/main/api/models";

vi.mock("electron", () => ({
  app: {
    getPath: () => "/tmp/levik-vpn-windows-test",
    getVersion: () => "1.2.3",
    isPackaged: true,
  },
}));

vi.mock("../src/main/update/appUpdater", () => ({
  AppUpdater: class AppUpdater {
    on(): this {
      return this;
    }
  },
}));

vi.mock("../src/main/windows/killSwitch", () => ({
  WindowsKillSwitch: class WindowsKillSwitch {},
}));

import { AppController } from "../src/main/appController";

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
    controller.cancelLogin();

    const changed = vi.fn();
    controller.on("changed", changed);
    const login = controller.beginLogin();
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
    expect(pollStatus).not.toHaveBeenCalled();
    expect(controller.snapshot()).toEqual(snapshotAfterCancellation);
    expect(changed).toHaveBeenCalledTimes(changesAfterCancellation);
  });
});

vi.mock("../src/main/vpn/tunnelHealth", () => ({ isTunnelHealthy: vi.fn(), TUNNEL_HEALTH_TAG: "levik-health", TUNNEL_HEALTH_PORT: 47186 }));
vi.mock("../src/main/vpn/serverPinger", () => ({ measureServerLatencies: vi.fn() }));

import { isTunnelHealthy } from "../src/main/vpn/tunnelHealth";
import { measureServerLatencies } from "../src/main/vpn/serverPinger";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";

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
  const killSwitch = {
    enable: vi.fn(async () => {}), allowTunnel: vi.fn(async () => {}),
    disable: vi.fn(async () => {}), isActive: vi.fn(() => true),
  };
  const dns = { enable: vi.fn(async () => {}), disable: vi.fn(async () => {}) };
  Reflect.set(controller, "profile", profile);
  Reflect.set(controller, "xray", xray);
  Reflect.set(controller, "killSwitch", killSwitch);
  Reflect.set(controller, "dnsLeakProtection", dns);
  Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
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

  it("does not leave connecting status when protection cleanup fails", async () => {
    const { controller, killSwitch, dns } = tunnelController();
    killSwitch.allowTunnel.mockRejectedValueOnce(new Error("adapter unavailable"));
    killSwitch.disable.mockRejectedValueOnce(new Error("disable failed"));
    await expect(controller.connect()).rejects.toThrow("disable failed");
    expect(dns.disable).toHaveBeenCalledOnce();
    expect(controller.snapshot()).toMatchObject({ status: "error", busy: false });
  });

  it("requires actual VPN traffic before reporting connected", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    vi.mocked(isTunnelHealthy).mockResolvedValue(false);
    await expect(controller.connect()).rejects.toThrow("не передаёт трафик");
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

  it("cancels an initial connection while Xray is still starting", async () => {
    const { controller, xray, killSwitch } = tunnelController();
    let finishStart: (() => void) | undefined;
    xray.start.mockImplementationOnce(() => new Promise<void>((resolve) => { finishStart = resolve; }));
    const connecting = expect(controller.connect()).rejects.toThrow("отменено");
    await vi.advanceTimersByTimeAsync(0);
    const disconnect = controller.disconnect();
    finishStart?.();
    await Promise.all([connecting, disconnect]);
    expect(controller.snapshot().status).toBe("disconnected");
    expect(killSwitch.allowTunnel).not.toHaveBeenCalled();
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
