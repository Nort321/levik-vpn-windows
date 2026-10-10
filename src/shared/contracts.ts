export type AppTab = "home" | "servers" | "stats" | "profile";
export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "reconnecting" | "disconnecting" | "error";
export type RoutingMode = "global" | "bypassRu" | "blockedOnly";
export type ThemeMode = "system" | "dark" | "light" | "amoled";
export type SplitTunnelMode = "off" | "bypass" | "only";
export type UpdateStatus = "idle" | "checking" | "available" | "downloading" | "downloaded" | "installing" | "upToDate" | "error";

/** A message from Levik VPN shown in every app, docs/app-platform.md. */
export interface AppAnnouncement {
  id: string;
  level: "info" | "warning" | "critical";
  title: string;
  body: string;
  /** Only Levik website or Telegram links; others are dropped. */
  linkUrl: string | null;
  notify: boolean;
  startsAt: number;
  endsAt: number;
}

/** Pages of the website's personal cabinet the app can open signed in. */
export type CabinetTarget =
  | "/dashboard"
  | "/dashboard/subscriptions"
  | "/dashboard/plans"
  | "/dashboard/orders"
  | "/dashboard/devices"
  | "/dashboard/support"
  | "/dashboard/account-security";

export interface WindowsProcess {
  name: string;
  path: string | null;
  running: boolean | null;
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

/** TUIC v5 endpoint. Xray has no TUIC support; a bundled sing-box carries it. */
export interface TuicEndpoint {
  address: string;
  port: number;
  uuid: string;
  password: string;
  serverName: string;
  alpn: string[];
  congestionControl: "bbr" | "cubic" | "new_reno";
  udpRelayMode: "native" | "quic";
  /** PEM trust anchor pinned by the Levik profile; system roots are never used. */
  caCertificatePem: string;
}

export interface TunnelServer {
  id: string;
  tag: string;
  name: string;
  countryCode: string;
  outbound: Record<string, unknown>;
  tuic?: TuicEndpoint;
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
  /** Anonymous connection quality reports, docs/connection-telemetry.md. */
  connectionTelemetry: boolean;
  telemetryNoticeShown: boolean;
  /** Share routing, protection and Anti-DPI settings with the user's other apps. */
  syncSettings: boolean;
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
  announcements: AppAnnouncement[];
  /** When the shared settings last matched the account. */
  settingsSyncedAt: number | null;
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
  login(openExternal?: boolean): Promise<LoginChallenge>;
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
  authorizeActivation(code: string): Promise<void>;
  checkForUpdates(): Promise<void>;
  downloadUpdate(): Promise<void>;
  installUpdate(): Promise<void>;
  /** Creates the note, copies its link and returns it. */
  createSupportReport(): Promise<string>;
  dismissAnnouncement(id: string): Promise<void>;
  /** Opens the page in the browser, signed in to the same account when possible. */
  openCabinet(target: CabinetTarget): Promise<void>;
  onSnapshot(listener: (snapshot: AppSnapshot) => void): () => void;
  /** A levik:// link or a notification asks for a tab. */
  onNavigate(listener: (tab: AppTab) => void): () => void;
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
  authorizeActivation: "levik:authorize-activation",
  checkForUpdates: "levik:check-for-updates",
  downloadUpdate: "levik:download-update",
  installUpdate: "levik:install-update",
  createSupportReport: "levik:create-support-report",
  dismissAnnouncement: "levik:dismiss-announcement",
  openCabinet: "levik:open-cabinet",
  snapshotChanged: "levik:snapshot-changed",
  navigate: "levik:navigate",
} as const;
