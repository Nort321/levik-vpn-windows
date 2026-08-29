import { beforeEach, describe, expect, it, vi } from "vitest";

type UpdateListener = (...args: unknown[]) => void;

const updaterMock = vi.hoisted(() => {
  const listeners = new Map<string, UpdateListener[]>();
  const autoUpdater = {
    autoDownload: true,
    autoInstallOnAppQuit: true,
    allowPrerelease: true,
    setFeedURL: vi.fn(),
    checkForUpdates: vi.fn(async () => null),
    downloadUpdate: vi.fn(async () => ["update.exe"]),
    quitAndInstall: vi.fn(),
    on: vi.fn((event: string, listener: UpdateListener) => {
      listeners.set(event, [...(listeners.get(event) ?? []), listener]);
      return autoUpdater;
    }),
  };
  return {
    autoUpdater,
    emit(event: string, ...args: unknown[]) {
      for (const listener of listeners.get(event) ?? []) listener(...args);
    },
    reset() {
      listeners.clear();
      autoUpdater.setFeedURL.mockClear();
      autoUpdater.checkForUpdates.mockClear();
      autoUpdater.downloadUpdate.mockClear();
      autoUpdater.quitAndInstall.mockClear();
      autoUpdater.on.mockClear();
      autoUpdater.downloadUpdate.mockResolvedValue(["update.exe"]);
    },
  };
});

vi.mock("electron", () => ({
  app: { isPackaged: true, getVersion: () => "1.2.7" },
}));

vi.mock("electron-updater", () => ({ autoUpdater: updaterMock.autoUpdater }));

import { AppUpdater } from "../src/main/update/appUpdater";

describe("Windows OTA updater", () => {
  beforeEach(() => {
    delete process.env.LEVIK_UPDATE_URL;
    updaterMock.reset();
  });

  it("requires explicit download and prepares the app before installation", async () => {
    const updater = new AppUpdater();
    expect(updaterMock.autoUpdater.autoDownload).toBe(false);
    expect(updaterMock.autoUpdater.autoInstallOnAppQuit).toBe(false);
    expect(updaterMock.autoUpdater.setFeedURL).not.toHaveBeenCalled();

    updaterMock.emit("update-available", { version: "1.2.8" });
    expect(updater.snapshot()).toEqual(expect.objectContaining({ status: "available", version: "1.2.8" }));

    updaterMock.autoUpdater.downloadUpdate.mockImplementationOnce(async () => {
      updaterMock.emit("download-progress", { percent: 47 });
      updaterMock.emit("update-downloaded", { version: "1.2.8" });
      return ["update.exe"];
    });
    await updater.download();
    expect(updater.snapshot()).toEqual(expect.objectContaining({ status: "downloaded", progress: 100 }));

    const prepare = vi.fn(async () => undefined);
    const beforeQuit = vi.fn();
    await updater.install(prepare, beforeQuit);
    expect(prepare).toHaveBeenCalledOnce();
    expect(beforeQuit).toHaveBeenCalledOnce();
    expect(updaterMock.autoUpdater.quitAndInstall).toHaveBeenCalledWith(false, true);
  });
});
