import { dialog, ipcMain, shell } from "electron";
import type { BrowserWindow } from "electron";
import { IPC } from "../shared/contracts";
import type { AppSettings } from "../shared/contracts";
import { AppController } from "./appController";
import { listWindowsProcesses, windowsProcessFromPath } from "./windows/processes";

export function registerIpc(controller: AppController, window: BrowserWindow): void {
  ipcMain.handle(IPC.snapshot, () => controller.snapshot());
  ipcMain.handle(IPC.login, async () => {
    const challenge = await controller.beginLogin();
    await openAllowedExternal(challenge.verificationUri);
    return challenge;
  });
  ipcMain.handle(IPC.cancelLogin, () => controller.cancelLogin());
  ipcMain.handle(IPC.logout, () => controller.logout());
  ipcMain.handle(IPC.refreshAccount, () => controller.refreshAccount());
  ipcMain.handle(IPC.selectSubscription, (_event, subscriptionId: unknown) => {
    if (typeof subscriptionId !== "string") throw new Error("Некорректная подписка");
    return controller.selectSubscription(subscriptionId);
  });
  ipcMain.handle(IPC.selectServer, (_event, serverId: unknown) => {
    if (typeof serverId !== "string") throw new Error("Некорректный сервер");
    return controller.selectServer(serverId);
  });
  ipcMain.handle(IPC.connect, () => controller.connect());
  ipcMain.handle(IPC.disconnect, () => controller.disconnect());
  ipcMain.handle(IPC.updateSettings, (_event, patch: unknown) => {
    if (!isSettingsPatch(patch)) throw new Error("Некорректные настройки");
    return controller.updateSettings(patch);
  });
  ipcMain.handle(IPC.openExternal, (_event, url: unknown) => {
    if (typeof url !== "string") throw new Error("Некорректная ссылка");
    return openAllowedExternal(url);
  });
  ipcMain.handle(IPC.listProcesses, () => listWindowsProcesses());
  ipcMain.handle(IPC.selectExecutable, async () => {
    const result = await dialog.showOpenDialog(window, {
      title: "Выберите приложение Windows",
      buttonLabel: "Добавить",
      properties: ["openFile", "dontAddToRecent"],
      filters: [{ name: "Приложения Windows", extensions: ["exe"] }],
    });
    const filePath = result.filePaths[0];
    if (result.canceled || !filePath) return null;
    const selected = windowsProcessFromPath(filePath);
    if (!selected) throw new Error("Выбран некорректный EXE-файл");
    return selected;
  });
  ipcMain.handle(IPC.pingServers, () => controller.pingServers());
  ipcMain.handle(IPC.revokeDevice, (_event, subscriptionId: unknown, deviceId: unknown) => {
    if (typeof subscriptionId !== "string" || typeof deviceId !== "string") throw new Error("Некорректное устройство");
    return controller.revokeDevice(subscriptionId, deviceId);
  });
  ipcMain.handle(IPC.setSubscriptionShield, (_event, subscriptionId: unknown, enabled: unknown) => {
    if (typeof subscriptionId !== "string" || typeof enabled !== "boolean") throw new Error("Некорректные настройки Shield");
    return controller.setSubscriptionShield(subscriptionId, enabled);
  });
  ipcMain.handle(IPC.checkForUpdates, () => controller.checkForUpdates());
  ipcMain.handle(IPC.downloadUpdate, () => controller.downloadUpdate());
  ipcMain.handle(IPC.installUpdate, () => controller.installUpdate());
  controller.on("changed", (snapshot) => {
    if (!window.isDestroyed()) window.webContents.send(IPC.snapshotChanged, snapshot);
  });
}

async function openAllowedExternal(rawUrl: string): Promise<void> {
  const url = new URL(rawUrl);
  const allowedHttpsHosts = new Set(["leviknet.com", "www.leviknet.com", "t.me"]);
  if (url.protocol === "https:" && allowedHttpsHosts.has(url.hostname)) {
    await shell.openExternal(url.toString());
    return;
  }
  if (url.protocol === "tg:") {
    await shell.openExternal(url.toString());
    return;
  }
  throw new Error("Открытие внешней ссылки запрещено");
}

function isSettingsPatch(value: unknown): value is Partial<AppSettings> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
