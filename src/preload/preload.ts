import { contextBridge, ipcRenderer } from "electron";
import { IPC } from "../shared/contracts";
import type { AppSettings, AppSnapshot, LevikDesktopApi } from "../shared/contracts";

const api: LevikDesktopApi = {
  snapshot: () => ipcRenderer.invoke(IPC.snapshot) as Promise<AppSnapshot>,
  login: () => ipcRenderer.invoke(IPC.login),
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
  checkForUpdates: () => ipcRenderer.invoke(IPC.checkForUpdates),
  downloadUpdate: () => ipcRenderer.invoke(IPC.downloadUpdate),
  installUpdate: () => ipcRenderer.invoke(IPC.installUpdate),
  onSnapshot(listener) {
    const wrapped = (_event: Electron.IpcRendererEvent, snapshot: AppSnapshot) => listener(snapshot);
    ipcRenderer.on(IPC.snapshotChanged, wrapped);
    return () => ipcRenderer.removeListener(IPC.snapshotChanged, wrapped);
  },
};

contextBridge.exposeInMainWorld("levik", Object.freeze(api));
