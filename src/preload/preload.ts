import { contextBridge, ipcRenderer, webUtils } from "electron";
import { IPC } from "../shared/contracts";
import type { AppSettings, AppSnapshot, AppTab, DiagnosisSummary, LevikDesktopApi } from "../shared/contracts";

const api: LevikDesktopApi = {
  snapshot: () => ipcRenderer.invoke(IPC.snapshot) as Promise<AppSnapshot>,
  login: (openExternal = true) => ipcRenderer.invoke(IPC.login, openExternal),
  cancelLogin: () => ipcRenderer.invoke(IPC.cancelLogin),
  logout: () => ipcRenderer.invoke(IPC.logout),
  answerApproval: (id: string, number: number | null) => ipcRenderer.invoke(IPC.answerApproval, id, number),
  refreshAccount: () => ipcRenderer.invoke(IPC.refreshAccount),
  selectSubscription: (subscriptionId) => ipcRenderer.invoke(IPC.selectSubscription, subscriptionId),
  selectServer: (serverId) => ipcRenderer.invoke(IPC.selectServer, serverId),
  selectCountry: (countryCode) => ipcRenderer.invoke(IPC.selectCountry, countryCode),
  selectAutomatic: () => ipcRenderer.invoke(IPC.selectAutomatic),
  connect: () => ipcRenderer.invoke(IPC.connect),
  disconnect: () => ipcRenderer.invoke(IPC.disconnect),
  updateSettings: (patch: Partial<AppSettings>) => ipcRenderer.invoke(IPC.updateSettings, patch),
  openExternal: (url) => ipcRenderer.invoke(IPC.openExternal, url),
  listProcesses: () => ipcRenderer.invoke(IPC.listProcesses),
  selectExecutable: () => ipcRenderer.invoke(IPC.selectExecutable),
  pingServers: () => ipcRenderer.invoke(IPC.pingServers),
  measureGameRoutes: () => ipcRenderer.invoke(IPC.measureGameRoutes),
  revokeDevice: (subscriptionId, deviceId) => ipcRenderer.invoke(IPC.revokeDevice, subscriptionId, deviceId),
  setSubscriptionShield: (subscriptionId, enabled) => ipcRenderer.invoke(IPC.setSubscriptionShield, subscriptionId, enabled),
  authorizeActivation: (code) => ipcRenderer.invoke(IPC.authorizeActivation, code),
  checkForUpdates: () => ipcRenderer.invoke(IPC.checkForUpdates),
  downloadUpdate: () => ipcRenderer.invoke(IPC.downloadUpdate),
  installUpdate: () => ipcRenderer.invoke(IPC.installUpdate),
  createSupportReport: () => ipcRenderer.invoke(IPC.createSupportReport) as Promise<string>,
  diagnose: () => ipcRenderer.invoke(IPC.diagnose) as Promise<DiagnosisSummary>,
  applyDiagnosisAction: (action) => ipcRenderer.invoke(IPC.applyDiagnosisAction, action),
  dismissAnnouncement: (id) => ipcRenderer.invoke(IPC.dismissAnnouncement, id),
  openCabinet: (target) => ipcRenderer.invoke(IPC.openCabinet, target),
  refreshRemote: () => ipcRenderer.invoke(IPC.refreshRemote),
  sendRemoteCommand: (deviceId, command) => ipcRenderer.invoke(IPC.sendRemoteCommand, deviceId, command),
  openRemoteNote: (commandId) => ipcRenderer.invoke(IPC.openRemoteNote, commandId),
  setHomeRoad: (enabled) => ipcRenderer.invoke(IPC.setHomeRoad, enabled),
  refreshDrop: () => ipcRenderer.invoke(IPC.refreshDrop),
  sendDropFiles: (deviceId, paths) => ipcRenderer.invoke(IPC.sendDropFiles, deviceId, paths),
  // Paths only exist for files from the system (Explorer); the main process checks each one.
  dropFilePaths: (files) => files.map((file) => webUtils.getPathForFile(file)).filter((path) => path !== ""),
  answerDrop: (transferId, answer, code) => ipcRenderer.invoke(IPC.answerDrop, transferId, answer, code),
  controlDrop: (transferId, action) => ipcRenderer.invoke(IPC.controlDrop, transferId, action),
  chooseDropFolder: () => ipcRenderer.invoke(IPC.chooseDropFolder),
  showDropFiles: (transferId) => ipcRenderer.invoke(IPC.showDropFiles, transferId),
  relaunchAsAdmin: () => ipcRenderer.invoke(IPC.relaunchAsAdmin),
  checkConflicts: () => ipcRenderer.invoke(IPC.checkConflicts),
  closeConflicts: () => ipcRenderer.invoke(IPC.closeConflicts) as Promise<number>,
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
