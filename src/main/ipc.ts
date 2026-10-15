import { clipboard, dialog, ipcMain, shell } from "electron";
import type { BrowserWindow } from "electron";
import { IPC } from "../shared/contracts";
import { isRemoteCommand } from "../shared/remote";
import type { AppSettings, CabinetTarget } from "../shared/contracts";
import { AppController } from "./appController";
import { listWindowsProcesses, windowsProcessFromPath } from "./windows/processes";
import { isAllowedExternalUrl, isCabinetTarget } from "./platform/links";

export function registerIpc(controller: AppController, window: BrowserWindow): void {
  ipcMain.handle(IPC.snapshot, () => controller.snapshot());
  ipcMain.handle(IPC.login, async (_event, shouldOpenExternal: unknown = true) => {
    if (typeof shouldOpenExternal !== "boolean") throw new Error("Некорректный способ входа");
    const challenge = await controller.beginLogin();
    // A remembered account is asked on its other apps first; the browser stays a fallback.
    if (shouldOpenExternal && !challenge.approvalRequested) await openAllowedExternal(challenge.verificationUri);
    return challenge;
  });
  ipcMain.handle(IPC.cancelLogin, () => controller.cancelLogin());
  ipcMain.handle(IPC.logout, () => controller.logout());
  ipcMain.handle(IPC.answerApproval, (_event, id: unknown, number: unknown) => {
    if (typeof id !== "string" || (number !== null && typeof number !== "number")) {
      throw new Error("Некорректный ответ на запрос входа");
    }
    return controller.answerApproval(id, number);
  });
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
  ipcMain.handle(IPC.measureGameRoutes, () => controller.measureGameRoutes());
  ipcMain.handle(IPC.revokeDevice, (_event, subscriptionId: unknown, deviceId: unknown) => {
    if (typeof subscriptionId !== "string" || typeof deviceId !== "string") throw new Error("Некорректное устройство");
    return controller.revokeDevice(subscriptionId, deviceId);
  });
  ipcMain.handle(IPC.setSubscriptionShield, (_event, subscriptionId: unknown, enabled: unknown) => {
    if (typeof subscriptionId !== "string" || typeof enabled !== "boolean") throw new Error("Некорректные настройки Shield");
    return controller.setSubscriptionShield(subscriptionId, enabled);
  });
  ipcMain.handle(IPC.authorizeActivation, (_event, code: unknown) => {
    if (typeof code !== "string") throw new Error("Некорректный код активации");
    return controller.authorizeActivation(code);
  });
  ipcMain.handle(IPC.checkForUpdates, () => controller.checkForUpdates());
  ipcMain.handle(IPC.downloadUpdate, () => controller.downloadUpdate());
  ipcMain.handle(IPC.installUpdate, () => controller.installUpdate());
  ipcMain.handle(IPC.createSupportReport, async () => {
    const url = await controller.createSupportReport();
    clipboard.writeText(url);
    return url;
  });
  ipcMain.handle(IPC.dismissAnnouncement, (_event, id: unknown) => {
    if (typeof id !== "string") throw new Error("Некорректное сообщение");
    return controller.dismissAnnouncement(id);
  });
  ipcMain.handle(IPC.openCabinet, async (_event, target: unknown) => {
    if (!isCabinetTarget(target)) throw new Error("Некорректная страница кабинета");
    await openCabinet(controller, target);
  });
  ipcMain.handle(IPC.refreshRemote, () => controller.refreshRemote());
  ipcMain.handle(IPC.sendRemoteCommand, (_event, deviceId: unknown, command: unknown) => {
    if (typeof deviceId !== "string" || deviceId.length > 160 || !isRemoteCommand(command)) throw new Error("Некорректная команда");
    return controller.sendRemoteCommand(deviceId, command);
  });
  ipcMain.handle(IPC.openRemoteNote, async (_event, commandId: unknown) => {
    if (typeof commandId !== "string") throw new Error("Некорректная команда");
    // Only a note link this app decrypted itself (remoteCommands.ts checks its form).
    const link = controller.remoteNote(commandId);
    clipboard.writeText(link);
    await shell.openExternal(new URL(link).toString());
  });
  controller.on("navigate", (tab) => {
    if (!window.isDestroyed()) window.webContents.send(IPC.navigate, tab);
  });
  controller.on("changed", (snapshot) => {
    if (!window.isDestroyed()) window.webContents.send(IPC.snapshotChanged, snapshot);
  });
}

/** A cabinet page in the browser, signed in when the app can: for the window and the tray. */
export async function openCabinet(controller: AppController, target: CabinetTarget): Promise<void> {
  await openAllowedExternal(await controller.cabinetUrl(target));
}

async function openAllowedExternal(rawUrl: string): Promise<void> {
  if (!isAllowedExternalUrl(rawUrl)) throw new Error("Открытие внешней ссылки запрещено");
  await shell.openExternal(new URL(rawUrl).toString());
}

function isSettingsPatch(value: unknown): value is Partial<AppSettings> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
