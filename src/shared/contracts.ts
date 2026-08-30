export type AppTab = "home" | "servers" | "stats" | "profile";
export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "reconnecting" | "disconnecting" | "error";
export type RoutingMode = "global" | "bypassRu" | "blockedOnly";
export type ThemeMode = "system" | "dark" | "light" | "amoled";
export type SplitTunnelMode = "off" | "bypass" | "only";
export type UpdateStatus = "idle" | "checking" | "available" | "downloading" | "downloaded" | "installing" | "upToDate" | "error";

export interface WindowsProcess {
  name: string;
  path: string | null;
}

export interface DeviceItem {
  id: string;
  label: string;
}

export interface SubscriptionSummary {
  uuid: string;
  title: string;
  status: string;
  expireAt: string | null;
  traffic: { usedBytes: number; limitBytes: number };
  devices: { used: number; limit: number; items: DeviceItem[] };
  shield: { supported: boolean; enabled: boolean };
  actions: { renew: boolean; revokeDevice: boolean };
}

export interface AccountSummary {
  userLabel: string;
  subscriptions: SubscriptionSummary[];
}

export interface TunnelServer {
  id: string;
  tag: string;
  name: string;
  countryCode: string;
  outbound: Record<string, unknown>;
}

export interface AppSettings {
  routingMode: RoutingMode;
  automaticServer: boolean;
  autoReconnect: boolean;
  killSwitch: boolean;
  useDoh: boolean;
  dnsServer: string;
  theme: ThemeMode;
  launchAtLogin: boolean;
  autoConnectOnLaunch: boolean;
  closeToTray: boolean;
  preventDnsLeaks: boolean;
  favoriteServerIds: string[];
  antiDpiEnabled: boolean;
  antiDpiPackets: string;
  antiDpiLength: string;
  antiDpiInterval: string;
  splitTunnelMode: SplitTunnelMode;
  splitTunnelProcesses: string[];
}

export interface AppSnapshot {
  appVersion: string;
  tab: AppTab;
  status: ConnectionStatus;
  statusDetail: string | null;
  sessionAvailable: boolean;
  account: AccountSummary | null;
  servers: TunnelServer[];
  serverLatencies: Record<string, number | null>;
  selectedServerId: string | null;
  selectedSubscriptionId: string | null;
  settings: AppSettings;
  sessionStartedAt: number | null;
  downloadBytes: number;
  uploadBytes: number;
  logs: string[];
  busy: boolean;
  update: {
    status: UpdateStatus;
    version: string | null;
    progress: number | null;
    message: string | null;
  };
}

export interface LoginChallenge {
  verificationUri: string;
  verificationCode: string | null;
  expiresAt: string;
}

export interface LevikDesktopApi {
  snapshot(): Promise<AppSnapshot>;
  login(): Promise<LoginChallenge>;
  cancelLogin(): Promise<void>;
  logout(): Promise<void>;
  refreshAccount(): Promise<void>;
  selectSubscription(subscriptionId: string): Promise<void>;
  selectServer(serverId: string): Promise<void>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  updateSettings(patch: Partial<AppSettings>): Promise<void>;
  openExternal(url: string): Promise<void>;
  listProcesses(): Promise<WindowsProcess[]>;
  selectExecutable(): Promise<WindowsProcess | null>;
  pingServers(): Promise<void>;
  revokeDevice(subscriptionId: string, deviceId: string): Promise<void>;
  setSubscriptionShield(subscriptionId: string, enabled: boolean): Promise<void>;
  checkForUpdates(): Promise<void>;
  downloadUpdate(): Promise<void>;
  installUpdate(): Promise<void>;
  onSnapshot(listener: (snapshot: AppSnapshot) => void): () => void;
}

export const IPC = {
  snapshot: "levik:snapshot",
  login: "levik:login",
  cancelLogin: "levik:cancel-login",
  logout: "levik:logout",
  refreshAccount: "levik:refresh-account",
  selectSubscription: "levik:select-subscription",
  selectServer: "levik:select-server",
  connect: "levik:connect",
  disconnect: "levik:disconnect",
  updateSettings: "levik:update-settings",
  openExternal: "levik:open-external",
  listProcesses: "levik:list-processes",
  selectExecutable: "levik:select-executable",
  pingServers: "levik:ping-servers",
  revokeDevice: "levik:revoke-device",
  setSubscriptionShield: "levik:set-subscription-shield",
  checkForUpdates: "levik:check-for-updates",
  downloadUpdate: "levik:download-update",
  installUpdate: "levik:install-update",
  snapshotChanged: "levik:snapshot-changed",
} as const;
