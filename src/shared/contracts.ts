import type { RemoteCommand, RemoteSnapshot } from "./remote";

export type AppTab = "home" | "servers" | "game" | "stats" | "profile";
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
  | "/dashboard/account-security"
  | "/dashboard/rules";

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
  gameEnabled?: boolean;
  gameIds?: string[];
  gameProcesses?: string[];
  /** null selects the best measured Game route. Local to this computer. */
  gameRouteId?: string | null;
  gameMultipath?: boolean;
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
  /** The account's favourite node list as last reconciled; null before the first reconcile. */
  favoriteNodes: string | null;
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
  /** Show this computer as online on the devices page and in the user's other apps. */
  sharePresence: boolean;
}

export interface AppSnapshot {
  game?: GameSnapshot;
  appVersion: string;
  tab: AppTab;
  status: ConnectionStatus;
  statusDetail: string | null;
  sessionAvailable: boolean;
  account: AccountSummary | null;
  servers: TunnelServer[];
  serverLatencies: Record<string, number | null>;
  /** Servers going into maintenance: server id → end of the work (ms since epoch). */
  serverMaintenance: Record<string, number>;
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
  /** Sign-ins on the user's other devices waiting for this app to approve them. */
  pendingApprovals: PendingApproval[];
  /** The user's other apps for the remote, docs/app-platform.md "Remote". */
  remote: RemoteSnapshot;
  /** A sign-in started on this computer is waiting for approval. */
  loginPending: boolean;
  update: {
    status: UpdateStatus;
    version: string | null;
    progress: number | null;
    message: string | null;
  };
}

/** The one button under a diagnosis; docs/app-platform.md "Diagnosis". */
export type DiagnosisAction = "retry" | "networkSettings" | "connect" | "bestServer" | "servers" | "support";

export const DIAGNOSIS_ACTIONS: readonly DiagnosisAction[] = ["retry", "networkSettings", "connect", "bestServer", "servers", "support"];

export function isDiagnosisAction(value: unknown): value is DiagnosisAction {
  return typeof value === "string" && (DIAGNOSIS_ACTIONS as readonly string[]).includes(value);
}

/** "It's not the VPN": one sentence and at most one button. */
export interface DiagnosisSummary {
  /** A stable code for support, such as SERVICE_RESTRICTED. */
  verdict: string;
  text: string;
  action: DiagnosisAction | null;
  actionLabel: string | null;
}

export interface LoginChallenge {
  verificationUri: string;
  verificationCode: string | null;
  expiresAt: string;
  /** Shown large: the user picks it on a signed-in device, in Telegram or on the website. */
  matchNumber: number | null;
  /** The bot asks for the number there. */
  telegramUri: string | null;
  /** The account this computer was signed in to was asked on its other apps. */
  approvalRequested: boolean;
}

export interface PendingApproval {
  id: string;
  deviceName: string;
  platformLabel: string;
  /** Three numbers; the new device shows one of them. */
  choices: number[];
  expiresAt: string;
}

export type ApprovalAnswerResult = "approved" | "declined";

export interface LevikDesktopApi {
  measureGameRoutes(): Promise<void>;
  snapshot(): Promise<AppSnapshot>;
  login(openExternal?: boolean): Promise<LoginChallenge>;
  cancelLogin(): Promise<void>;
  logout(): Promise<void>;
  /** A number of the approval's choices, or null for "this is not me". */
  answerApproval(id: string, number: number | null): Promise<ApprovalAnswerResult>;
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
  /** Checks the network, the VPN and popular services; the support report includes the result. */
  diagnose(): Promise<DiagnosisSummary>;
  applyDiagnosisAction(action: DiagnosisAction): Promise<void>;
  dismissAnnouncement(id: string): Promise<void>;
  /** Opens the page in the browser, signed in to the same account when possible. */
  openCabinet(target: CabinetTarget): Promise<void>;
  /** Loads the user's other apps; live events keep the list current for a while. */
  refreshRemote(): Promise<void>;
  /** Sends a command to another app of the account; disconnecting is not one. */
  sendRemoteCommand(deviceId: string, command: RemoteCommand): Promise<void>;
  /** Opens a diagnostics report collected for this app and copies its link. */
  openRemoteNote(commandId: string): Promise<void>;
  onSnapshot(listener: (snapshot: AppSnapshot) => void): () => void;
  /** A levik:// link or a notification asks for a tab. */
  onNavigate(listener: (tab: AppTab) => void): () => void;
}

export const IPC = {
  measureGameRoutes: "levik:measure-game-routes",
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
  diagnose: "levik:diagnose",
  applyDiagnosisAction: "levik:apply-diagnosis-action",
  dismissAnnouncement: "levik:dismiss-announcement",
  openCabinet: "levik:open-cabinet",
  answerApproval: "levik:answer-approval",
  refreshRemote: "levik:refresh-remote",
  sendRemoteCommand: "levik:send-remote-command",
  openRemoteNote: "levik:open-remote-note",
  snapshotChanged: "levik:snapshot-changed",
  navigate: "levik:navigate",
} as const;

export interface GameRouteQuality {
  latencyMs: number | null;
  jitterMs: number | null;
  lossPercent: number;
  samples: number;
  measuredAt: number;
}

export interface GameSnapshot {
  available: boolean;
  routes: Array<Pick<TunnelServer, "id" | "name" | "countryCode">>;
  quality: Record<string, GameRouteQuality>;
  activeRouteId: string | null;
  recommendedRouteId: string | null;
  phase: "idle" | "probing" | "ready" | "degraded";
  message: string | null;
  history?: Record<string, GameRouteQuality[]>;
  multipath?: GameMultipathStats | null;
}

export interface GameMultipathStats {
  state: "protected" | "single" | "unavailable" | "fallback";
  paths: Array<{ routeIndex: number; latencyMs: number | null; responding: boolean; active?: boolean; firstReplies: number }>;
  receivedPackets: number;
  duplicateReplies: number;
  uploadedPackets: number;
}
