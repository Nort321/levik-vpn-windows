import { app, BrowserWindow, dialog, Menu, nativeImage, powerMonitor, Tray } from "electron";
import { join } from "node:path";
import type { AppSnapshot, ConnectionStatus } from "../shared/contracts";
import { AppController } from "./appController";
import { registerIpc } from "./ipc";

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let controller: AppController | null = null;
let quitting = false;
let lastTrayKey = "";

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();

app.on("second-instance", () => showWindow());

app.whenReady().then(async () => {
  controller = new AppController();
  mainWindow = createWindow();
  registerIpc(controller, mainWindow);
  createTray();
  controller.on("changed", updateTray);
  powerMonitor.on("resume", () => void controller?.restoreAfterSystemResume());
  powerMonitor.on("unlock-screen", () => void controller?.restoreAfterSystemResume());
  await controller.initialize();
  mainWindow.show();
}).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error("Levik VPN startup failed", message);
  dialog.showErrorBox("Levik VPN не удалось запустить", message);
  app.quit();
});

app.on("activate", () => showWindow());

app.on("before-quit", (event) => {
  if (quitting || !controller) return;
  event.preventDefault();
  quitting = true;
  void controller.shutdown().finally(() => app.quit());
});

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({
    width: 1120,
    height: 760,
    minWidth: 900,
    minHeight: 640,
    show: false,
    backgroundColor: "#07101f",
    title: "Levik VPN",
    icon: applicationIconPath(),
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
    },
  });
  window.loadFile(join(__dirname, "..", "renderer", "index.html"));
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.on("close", (event) => {
    if (quitting) return;
    event.preventDefault();
    if (controller?.snapshot().settings.closeToTray ?? true) window.hide();
    else requestQuit();
  });
  window.on("show", refreshTrayMenu);
  window.on("hide", refreshTrayMenu);
  return window;
}

function createTray(): void {
  const icon = trayIcon("disconnected");
  if (icon.isEmpty()) {
    console.error("Levik VPN tray icon is unavailable; continuing without tray");
    return;
  }
  tray = new Tray(icon);
  tray.setToolTip("Levik VPN — не подключено");
  tray.on("click", () => toggleWindow());
  updateTray(controller?.snapshot());
}

function updateTray(snapshot?: AppSnapshot): void {
  if (!tray) return;
  const status = snapshot?.status ?? "disconnected";
  const server = snapshot?.servers.find((item) => item.id === snapshot.selectedServerId);
  const key = `${status}\0${server?.id ?? ""}`;
  if (key === lastTrayKey) return;
  lastTrayKey = key;
  tray.setImage(trayIcon(status));
  const statusText = trayStatus(status);
  tray.setToolTip(`Levik VPN — ${statusText}${server ? ` · ${server.name}` : ""}`);
  const transitional = ["connecting", "reconnecting", "disconnecting"].includes(status);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: mainWindow?.isVisible() ? "Скрыть Levik VPN" : "Открыть Levik VPN", click: () => toggleWindow() },
    { type: "separator" },
    { label: "Подключить", enabled: !transitional && status !== "connected", click: () => void controller?.connect() },
    { label: "Отключить", enabled: !transitional && status === "connected", click: () => void controller?.disconnect() },
    { type: "separator" },
    { label: "Выход", click: requestQuit },
  ]));
}

function trayIcon(status: ConnectionStatus): Electron.NativeImage {
  const tone = status === "connected" ? "connected" : ["connecting", "reconnecting", "disconnecting"].includes(status) ? "connecting" : status === "error" ? "error" : "disconnected";
  const statusIcon = nativeImage.createFromPath(join(__dirname, "..", "assets", `tray-${tone}.png`));
  if (!statusIcon.isEmpty()) return statusIcon.resize({ width: 16, height: 16 });
  return nativeImage.createFromPath(applicationIconPath()).resize({ width: 16, height: 16 });
}

function trayStatus(status: ConnectionStatus): string {
  return ({ disconnected: "не подключено", connecting: "подключение", connected: "подключено", reconnecting: "восстановление", disconnecting: "отключение", error: "ошибка" })[status];
}

function applicationIconPath(): string {
  return join(__dirname, "..", "assets", "icon.ico");
}

function showWindow(): void {
  if (!mainWindow) return;
  mainWindow.show();
  mainWindow.focus();
}

function toggleWindow(): void {
  if (!mainWindow) return;
  if (mainWindow.isVisible()) mainWindow.hide();
  else showWindow();
}

function refreshTrayMenu(): void {
  lastTrayKey = "";
  updateTray(controller?.snapshot());
}

function requestQuit(): void {
  if (!quitting) app.quit();
}
