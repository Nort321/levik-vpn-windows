import { contextBridge, ipcRenderer } from "electron";
import { IPC } from "../shared/contracts";
import type { AppSettings, AppSnapshot, AppTab, LevikDesktopApi } from "../shared/contracts";

const api: LevikDesktopApi = {
  snapshot: () => ipcRenderer.invoke(IPC.snapshot) as Promise<AppSnapshot>,
  login: (openExternal = true) => ipcRenderer.invoke(IPC.login, openExternal),
  cancelLogin: () => ipcRenderer.invoke(IPC.cancelLogin),
  logout: () => ipcRenderer.invoke(IPC.logout),
  refreshAccount: () => ipcRenderer.invoke(IPC.refreshAccount),
  selectSubscription: (subscriptionId) => ipcRenderer.invoke(IPC.selectSubscription, subscriptionId),
  selectServer: (serverId) => ipcRenderer.invoke(IPC.selectServer, serverId),
  connect: () => ipcRenderer.invoke(IPC.connect),
  disconnect: () => ipcRenderer.invoke(IPC.disconnect),
  updateSettings: (patch: Partial<AppSettings>) => ipcRenderer.invoke(IPC.updateSettings, patch),
  openExternal: (url) => ipcRenderer.invoke(IPC.openExternal, url),
  listProcesses: () => ipcRenderer.invoke(IPC.listProcesses),
  selectExecutable: () => ipcRenderer.invoke(IPC.selectExecutable),
  pingServers: () => ipcRenderer.invoke(IPC.pingServers),
  revokeDevice: (subscriptionId, deviceId) => ipcRenderer.invoke(IPC.revokeDevice, subscriptionId, deviceId),
  setSubscriptionShield: (subscriptionId, enabled) => ipcRenderer.invoke(IPC.setSubscriptionShield, subscriptionId, enabled),
  authorizeActivation: (code) => ipcRenderer.invoke(IPC.authorizeActivation, code),
  checkForUpdates: () => ipcRenderer.invoke(IPC.checkForUpdates),
  downloadUpdate: () => ipcRenderer.invoke(IPC.downloadUpdate),
  installUpdate: () => ipcRenderer.invoke(IPC.installUpdate),
  createSupportReport: () => ipcRenderer.invoke(IPC.createSupportReport) as Promise<string>,
  dismissAnnouncement: (id) => ipcRenderer.invoke(IPC.dismissAnnouncement, id),
  openCabinet: (target) => ipcRenderer.invoke(IPC.openCabinet, target),
  onSnapshot(listener) {
    const wrapped = (_event: Electron.IpcRendererEvent, snapshot: AppSnapshot) => listener(snapshot);
    ipcRenderer.on(IPC.snapshotChanged, wrapped);
    return () => ipcRenderer.removeListener(IPC.snapshotChanged, wrapped);
  },
  onNavigate(listener) {
    const wrapped = (_event: Electron.IpcRendererEvent, tab: AppTab) => listener(tab);
    ipcRenderer.on(IPC.navigate, wrapped);
    return () => ipcRenderer.removeListener(IPC.navigate, wrapped);
  },
};

contextBridge.exposeInMainWorld("levik", Object.freeze(api));
