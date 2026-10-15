import { describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({
  app: {
    getPath: () => "/tmp/levik-vpn-windows-test",
    getVersion: () => "1.0.0",
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
import {
  allowedFromFamily,
  createReplyKey,
  openReply,
  parseDeliveredCommands,
  parseIssuedCommands,
  parseRemoteDevices,
  sealForReply,
} from "../src/main/platform/remoteCommands";
import { remoteStatusText } from "../src/shared/remote";

const ID = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const NOTE = "https://note.leviknet.org/abcDEF123#key_-9";

describe("remote command parsing", () => {
  it("keeps well-formed items and drops the rest", () => {
    expect(parseDeliveredCommands([
      { id: ID(1), command: "connect", replyKey: null },
      { id: ID(2), command: "disconnect" },
      { id: ID(6), command: "refresh_profile", via: "family" },
      { id: "not-a-uuid", command: "connect" },
      "junk",
    ])).toEqual([
      { id: ID(1), command: "connect", replyKey: null, fromFamily: false },
      { id: ID(2), command: "disconnect", replyKey: null, fromFamily: false },
      { id: ID(6), command: "refresh_profile", replyKey: null, fromFamily: true },
    ]);
    // The family owner only repairs.
    expect(["connect", "collect_diagnostics", "disconnect"].some(allowedFromFamily)).toBe(false);
    expect(["auto_server", "refresh_profile", "check_update"].every(allowedFromFamily)).toBe(true);
    expect(parseIssuedCommands([
      { id: ID(3), deviceId: "phone", command: "check_update", state: "done", detail: "available:2.8.0" },
      { id: ID(4), deviceId: "phone", command: "disconnect", state: "done", detail: null },
      { id: ID(5), deviceId: "phone", command: "connect", state: "lost", detail: null },
    ])).toEqual([{ id: ID(3), deviceId: "phone", command: "check_update", state: "done", detail: "available:2.8.0" }]);
    expect(parseRemoteDevices([
      { deviceId: "phone", name: "Pixel", platform: "android", appVersion: "2.7.30", current: false, remote: true, presence: { online: true, vpnConnected: true, country: "DE" } },
      { deviceId: "tv", name: "TV", platform: "tizen" },
      { deviceId: "mac", name: "MacBook", platform: "macos", presence: { online: true, country: "<script>" } },
    ])).toEqual([
      { deviceId: "phone", name: "Pixel", platform: "android", appVersion: "2.7.30", current: false, remote: true, online: true, vpnConnected: true, country: "DE" },
      { deviceId: "mac", name: "MacBook", platform: "macos", appVersion: null, current: false, remote: false, online: true, vpnConnected: false, country: null },
    ]);
  });

  it("seals the diagnostics link so only the sender opens it", () => {
    const { replyKey, privateKey } = createReplyKey();
    const sealed = sealForReply(replyKey, NOTE);
    expect(sealed).not.toContain("note.leviknet");
    expect(openReply(privateKey, sealed)).toBe(NOTE);
    expect(openReply(createReplyKey().privateKey, sealed)).toBeNull();
    // Anything other than a note link is not opened.
    expect(openReply(privateKey, sealForReply(replyKey, "https://evil.example/x#y"))).toBeNull();
  });

  it("describes what happened", () => {
    const phone = { deviceId: "phone", name: "Pixel", platform: "android" as const, appVersion: null, current: false, remote: true, online: false, vpnConnected: false, country: null };
    expect(remoteStatusText({ id: ID(1), deviceId: "phone", command: "connect", state: "pending", detail: null }, phone))
      .toContain("когда откроет Levik VPN");
    expect(remoteStatusText({ id: ID(1), deviceId: "phone", command: "check_update", state: "done", detail: "available:2.8.0" }, phone))
      .toContain("2.8.0");
  });
});

describe("AppController remote", () => {
  function controllerWith(commands: unknown[]) {
    const controller = new AppController();
    controller.cancelLogin();
    const results: Array<{ id: string; result: string; detail: string | null }> = [];
    Reflect.set(controller, "accessToken", "token");
    Reflect.set(controller, "api", {
      takeCommands: vi.fn(() => Promise.resolve({ ok: true, commands })),
      commandResult: vi.fn((_token: string, id: string, result: string, detail: string | null) => {
        results.push({ id, result, detail });
        return Promise.resolve();
      }),
    });
    return { controller, results };
  }
  const runCommands = (controller: AppController) => {
    (Reflect.get(controller, "runCommands") as () => void).call(controller);
    return Reflect.get(controller, "commandChain") as Promise<void>;
  };

  it("runs each command once and never disconnects", async () => {
    const reply = createReplyKey();
    const { controller, results } = controllerWith([
      { id: ID(1), command: "connect", replyKey: null },
      { id: ID(2), command: "disconnect", replyKey: null },
      { id: ID(3), command: "refresh_profile", replyKey: null },
      { id: ID(4), command: "collect_diagnostics", replyKey: reply.replyKey },
    ]);
    Reflect.set(controller, "xray", { isRunning: () => false });
    const connect = vi.spyOn(controller, "connect").mockResolvedValue();
    const disconnect = vi.spyOn(controller, "disconnect").mockResolvedValue();
    const refreshAccount = vi.spyOn(controller, "refreshAccount").mockResolvedValue();
    vi.spyOn(controller, "createSupportReport").mockResolvedValue(NOTE);
    const notify = vi.fn();
    controller.on("notify", notify);

    await runCommands(controller);
    await runCommands(controller);

    expect(connect).toHaveBeenCalledOnce();
    expect(refreshAccount).toHaveBeenCalledOnce();
    expect(disconnect).not.toHaveBeenCalled();
    expect(results.map((item) => [item.id, item.result])).toEqual([
      [ID(1), "done"], [ID(2), "unsupported"], [ID(3), "done"], [ID(4), "done"],
    ]);
    expect(openReply(reply.privateKey, results[3]?.detail ?? "")).toBe(NOTE);
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it("answers connect without reconnecting when already connected", async () => {
    const { controller, results } = controllerWith([{ id: ID(7), command: "connect", replyKey: null }]);
    Reflect.set(controller, "xray", { isRunning: () => true });
    const connect = vi.spyOn(controller, "connect").mockResolvedValue();
    await runCommands(controller);
    expect(connect).not.toHaveBeenCalled();
    expect(results).toEqual([{ id: ID(7), result: "done", detail: "already_connected" }]);
  });

  it("opens only diagnostics it decrypted itself", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const { replyKey, privateKey } = createReplyKey();
    Reflect.set(controller, "accessToken", "token");
    (Reflect.get(controller, "replyKeys") as Map<string, unknown>).set(ID(9), privateKey);
    Reflect.set(controller, "api", {
      remoteDevices: vi.fn(() => Promise.resolve({
        ok: true,
        devices: [],
        commands: [{ id: ID(9), deviceId: "phone", command: "collect_diagnostics", state: "done", detail: sealForReply(replyKey, NOTE) }],
      })),
    });
    await controller.refreshRemote();
    expect(controller.remoteNote(ID(9))).toBe(NOTE);
    expect(() => controller.remoteNote(ID(8))).toThrow();
  });
});
