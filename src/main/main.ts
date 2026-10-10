import { app, BrowserWindow, dialog, Menu, nativeImage, Notification, powerMonitor, Tray } from "electron";
import { join } from "node:path";
import type { AppSnapshot, AppTab, ConnectionStatus } from "../shared/contracts";
import { AppController } from "./appController";
import { registerIpc } from "./ipc";
import { DEEP_LINK_SCHEME, deepLinkFromArgv } from "./platform/links";
import type { AppNotice } from "./platform/notices";

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let controller: AppController | null = null;
let quitting = false;
let lastTrayKey = "";
/** A levik:// link that arrived before the window was ready. */
let pendingLink: AppTab | null = deepLinkFromArgv(process.argv);

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();

app.on("second-instance", (_event, argv) => {
  showWindow();
  const tab = deepLinkFromArgv(argv);
  if (tab) openLink(tab);
});

app.whenReady().then(async () => {
  app.setAppUserModelId("com.leviknet.vpn.windows");
  // Installed builds only: a development run would register electron.exe instead.
  if (app.isPackaged) app.setAsDefaultProtocolClient(DEEP_LINK_SCHEME);
  controller = new AppController();
  mainWindow = createWindow();
  registerIpc(controller, mainWindow);
  createTray();
  controller.on("changed", updateTray);
  controller.on("updateInstalling", () => { quitting = true; });
  controller.on("notify", showNotice);
  powerMonitor.on("suspend", () => controller?.recordPowerEvent("suspend"));
  powerMonitor.on("resume", () => {
    controller?.recordPowerEvent("resume");
    void controller?.restoreAfterSystemResume();
  });
  powerMonitor.on("unlock-screen", () => void controller?.restoreAfterSystemResume());
  await controller.initialize();
  mainWindow.show();
  if (pendingLink) {
    const tab = pendingLink;
    pendingLink = null;
    // The renderer listens for navigation once its page has loaded.
    if (mainWindow.webContents.isLoading()) mainWindow.webContents.once("did-finish-load", () => openLink(tab));
    else openLink(tab);
  }
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
  void controller.shutdown().then(() => app.quit()).catch(() => {
    quitting = false;
    showWindow();
    dialog.showErrorBox("Не удалось снять защиту сети", "Повторите отключение VPN перед выходом, чтобы не оставить сеть заблокированной.");
  });
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
    { label: "Подключить", enabled: !transitional && status !== "connected", click: () => runTrayAction(() => controller?.connect()) },
    { label: "Отключить", enabled: ["connecting", "connected", "reconnecting", "error"].includes(status), click: () => runTrayAction(() => controller?.disconnect()) },
    { type: "separator" },
    { label: "Выход", click: requestQuit },
  ]));
}

function trayIcon(status: ConnectionStatus): Electron.NativeImage {
  const tone = status === "connected" ? "connected" : "disconnected";
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

function openLink(tab: AppTab): void {
  if (!controller || !mainWindow) {
    pendingLink = tab;
    return;
  }
  showWindow();
  controller.handleDeepLink(tab);
}

function showNotice(notice: AppNotice): void {
  if (!Notification.isSupported()) return;
  const notification = new Notification({ title: notice.title, body: notice.body, icon: applicationIconPath() });
  notification.on("click", () => openLink(notice.tab));
  notification.show();
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

function runTrayAction(action: () => Promise<void> | undefined): void {
  void action()?.catch(() => showWindow());
}
