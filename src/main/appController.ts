import { app, net } from "electron";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { platform, release } from "node:os";
import { isIPv4 } from "node:net";
import { join } from "node:path";
import type {
  AccountSummary,
  AppAnnouncement,
  AppSettings,
  AppSnapshot,
  AppTab,
  ApprovalAnswerResult,
  CabinetTarget,
  DiagnosisAction,
  HomeRoadSnapshot,
  DiagnosisSummary,
  LoginChallenge,
  PendingApproval,
  TunnelServer,
  TuicEndpoint,
  GameSnapshot,
} from "../shared/contracts";
import { isAuthenticationRejected, MobileApiClient, MobileApiError } from "./api/mobileApiClient";
import type { AuthChallengeResponse, MobileAccountResponse, RoadExitResponse } from "./api/models";
import { DeviceIdentity } from "./security/deviceIdentity";
import type { SerializedIdentity } from "./security/deviceIdentity";
import { RequestSigner } from "./security/requestSigner";
import { SecureStore } from "./security/secureStore";
import { decryptTunnelProfile, prepareTunnelProfile, ruleRoutingKey } from "./vpn/tunnelProfile";
import type { PreparedTunnelProfile } from "./vpn/tunnelProfile";
import { buildXrayConfig } from "./vpn/xrayConfig";
import { XrayManager } from "./vpn/xrayManager";
import { isTunnelHealthy } from "./vpn/tunnelHealth";
import { measureServerLatencies } from "./vpn/serverPinger";
import { DnsLeakProtection } from "./windows/dnsLeakProtection";
import { WindowsKillSwitch } from "./windows/killSwitch";
import { AppUpdater } from "./update/appUpdater";
import { normalizeProcessSelection } from "../shared/processes";
import { classifyCoreLogLine, networkTypeOfInterface, protocolOf } from "./telemetry/codes";
import { ConnectionTelemetry } from "./telemetry/connectionTelemetry";
import { DiskLog } from "./diagnostics/diskLog";
import { createSupportNote, MAX_SUPPORT_NOTE_BYTES, supportNoteText } from "./diagnostics/supportNote";
import { supportReportText } from "./diagnostics/supportReport";
import type { AttemptCause, AttemptStage, EndBy, PowerState, SessionSettings, SessionTrigger } from "./telemetry/sessionRecorder";
import { cabinetFallbackUrl, isAllowedExternalUrl, isHandoffUrl } from "./platform/links";
import { serviceEndpoints, ServiceEndpointsStore, websiteHosts } from "./platform/serviceEndpoints";
import { createRoadKey, HomeRoadExit, isHomeRoadServer, parseRoadExit, roadKeyFrom, type RoadKey } from "./platform/homeRoad";
import { findWindowsOutboundInterface } from "./windows/outboundInterface";
import { DEFAULT_API_ORIGIN } from "./api/apiEndpoints";
import { parseAccountNotices } from "./platform/accountNotices";
import { beaconFresh, HomeSleepPolicy, localAddresses, parseSighting, protects, scanHomes } from "./platform/levikHome";
import type { HomeAction, HomeBeacon, VerifiedHome } from "./platform/levikHome";
import { expiryNotices, NoticeState } from "./platform/notices";
import type { AppNotice } from "./platform/notices";
import {
  adviceCandidates,
  currentAdvice,
  mergeFetched,
  RemoteConfigClient,
  RemoteConfigStore,
  visibleAnnouncements,
} from "./platform/remoteConfig";
import type { StoredRemoteConfig } from "./platform/remoteConfig";
import {
  parsePending,
  parseSettingsDocument,
  portableSettings,
  remotePatch,
  syncedChanges,
  withoutConfirmed,
} from "./platform/settingsSync";
import type { SyncedSettings } from "./platform/settingsSync";
import { LiveEvents, presenceReport, samePresence } from "./platform/liveEvents";
import type { LiveEvent, PresenceReport } from "./platform/liveEvents";
import { isAccountHint, isApprovalAnswer, isTelegramLink, matchNumber, parseApprovals } from "./platform/loginApproval";
import {
  canonicalNodeList,
  isCanonicalNodeList,
  nodeIdForServer,
  parseNodeList,
  reconcileFavorites,
  serversByNode,
  unionNodeLists,
} from "./platform/favoriteNodes";
import { avoidMaintenance, IdleMeter, maintenanceFor, maintenanceMove } from "./platform/maintenance";
import { captivePortal, checkServices, diagnosisSummary, diagnosisVerdict, parseDiagnoseReport, vpnPhase } from "./platform/diagnosis";
import { gameExitScope, gameProcesses, GAMES, normalizeGameIds } from "../shared/games";
import { discoverInstalledGames } from "./windows/installedGames";
import { listWindowsProcesses } from "./windows/processes";
import { measureDirectGameTargets, physicalGameSourceAddress } from "./windows/gameProbe";
import { GameHistory } from "./vpn/gameHistory";
import { TelemetryClient } from "./telemetry/telemetryClient";
import type { ProbeMeasurement } from "./vpn/multipath/wire";
import { bestGameRoute, measureGameDataRoute, GAME_PROBE_PORT, GAME_DATA_PROBE_PORT, GAME_DIRECT_PORT, gameTag } from "./vpn/gameRoutes";
import {
  allowedFromFamily,
  createReplyKey,
  FAMILY_HELP_TEXT,
  openReply,
  parseDeliveredCommands,
  parseIssuedCommands,
  parseRemoteDevices,
  sealForReply,
} from "./platform/remoteCommands";
import type { DeliveredCommand } from "./platform/remoteCommands";
import { isFinalState, isRemoteCommand, REMOTE_COMMAND_LABELS } from "../shared/remote";
import type { RemoteCommand, RemoteSnapshot } from "../shared/remote";
import type { KeyObject } from "node:crypto";

interface AppControllerEvents {
  changed: [snapshot: AppSnapshot];
  updateInstalling: [];
  notify: [notice: AppNotice];
  navigate: [tab: AppTab];
}

const BACKGROUND_TICK_MS = 5 * 60_000;
/** Levik Home: how often to listen for the home router while awake with the VPN on, asleep, or with it off. */
const HOME_TICK_MS = 60_000;
const HOME_CONNECTED_SCAN_MS = 2 * 60_000;
const HOME_IDLE_SCAN_MS = 10 * 60_000;
/** How often a connected app checks whether its server goes into maintenance. */
const MAINTENANCE_CHECK_MS = 15_000;
/** After the remote list was shown, events keep it current this long. */
const REMOTE_WATCH_MS = 10 * 60_000;
const MAX_HANDLED_COMMANDS = 200;
const ACCOUNT_CHECK_INTERVAL_MS = 6 * 60 * 60_000;
const SETTINGS_SYNC_INTERVAL_MS = 30 * 60_000;
const SETTINGS_PUSH_DELAY_MS = 1_500;
/** The server forgets a device three minutes after its last report. */
const PRESENCE_REFRESH_MS = 2 * 60_000;
const PRESENCE_DEBOUNCE_MS = 1_500;
const LINK_REFRESH_INTERVAL_MS = 30_000;
/** Signed host list: checked twice a day, and at most once a minute when every host fails. */
const ENDPOINTS_REFRESH_MS = 12 * 60 * 60_000;
const ENDPOINTS_RETRY_MS = 60_000;
/** «Дорога домой»: the exit's relay token is renewed long before its 30 days run out. */
const HOME_ROAD_REFRESH_MS = 6 * 60 * 60_000;

const DEFAULT_SETTINGS: AppSettings = {
  gameEnabled: false,
  gameIds: [],
  gameProcesses: [],
  gameRouteId: null,
  gameMultipath: false,
  gameProtection: true,
  gameRegionTelemetry: false,
  routingMode: "global",
  automaticServer: true,
  autoReconnect: true,
  killSwitch: true,
  useDoh: true,
  dnsServer: "1.1.1.1",
  theme: "system",
  launchAtLogin: false,
  autoConnectOnLaunch: false,
  closeToTray: true,
  preventDnsLeaks: true,
  favoriteServerIds: [],
  favoriteNodes: null,
  antiDpiEnabled: false,
  antiDpiPackets: "tlshello",
  antiDpiLength: "100-200",
  antiDpiInterval: "10-20",
  splitTunnelMode: "off",
  splitTunnelProcesses: [],
  connectionTelemetry: true,
  telemetryNoticeShown: false,
  syncSettings: true,
  sharePresence: true,
  sleepAtHome: true,
};

const SETTINGS_SCHEMA_VERSION = 3;

type PersistedSettings = Partial<AppSettings> & {
  settingsSchemaVersion?: number;
};

export class AppController extends EventEmitter<AppControllerEvents> {
  private gamePassword: string | undefined;
  private gameProbeAbort: AbortController | null = null;
  private gameProbePromise: Promise<void> | null = null;
  private gameMonitor: ReturnType<typeof setInterval> | null = null;
  private gameValidatedAt = 0;
  private gamePlaying = false;
  private currentGameId = "custom";
  private gameProcessCheckAt = 0;
  private gameProcessCheckRunning = false;
  private gameLastHistoryKey: string | null = null;
  private gameLastRegionReportAt = 0;
  private readonly gameHistory = new GameHistory(join(app.getPath("userData"), "game-history.json"));
  private readonly gameRegionTelemetry = new TelemetryClient();
  private pendingGameProfile: PreparedTunnelProfile | null = null;
  private applyingPendingGameProfile = false;
  private enforcingGameExpiry = false;
  private readonly secureStore = new SecureStore();
  private readonly xray = new XrayManager();
  private readonly dnsLeakProtection = new DnsLeakProtection(this.secureStore);
  private readonly killSwitch = new WindowsKillSwitch(() => this.xray.executablePath(), {
    tuicExecutablePath: () => this.xray.tuicExecutablePath(),
  });
  // The Kill Switch lets xray.exe out, so «past the VPN» works with it on.
  private readonly homeRoad = new HomeRoadExit({
    xrayPath: () => this.xray.executablePath(),
    log: (line) => this.diskLog?.write(line),
    roadKey: () => this.homeRoadKey(),
    findInterface: async () => (await findWindowsOutboundInterface()).name,
  });
  private homeRoadAvailable = false;
  private homeRoadKeyPair: Promise<RoadKey> | null = null;
  private homeRoadChain: Promise<void> = Promise.resolve();
  private lastHomeRoadAt = 0;
  private readonly updater: AppUpdater | null;
  private identity!: DeviceIdentity;
  private api!: MobileApiClient;
  private accessToken: string | null = null;
  private profile: PreparedTunnelProfile | null = null;
  private loginGeneration = 0;
  private reconnectAttempts = 0;
  private lastConfig: Record<string, unknown> | null = null;
  private lastTuic: TuicEndpoint | undefined;
  private connectionGeneration = 0;
  private tunnelOperation: Promise<void> = Promise.resolve();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private tunnelHealthTimer: ReturnType<typeof setInterval> | null = null;
  private tunnelHealthCheckRunning = false;
  private tunnelHealthFailures = 0;
  private coreFailure: string | null = null;
  private readonly failedServerIds = new Set<string>();
  private trafficDownloadOffset = 0;
  private trafficUploadOffset = 0;
  private lastRawDownload = 0;
  private lastRawUpload = 0;
  private pingPromise: Promise<void> | null = null;
  private resumePromise: Promise<void> | null = null;
  private diagnosisPromise: Promise<DiagnosisSummary> | null = null;
  private lastDiagnosis: { at: number; summary: DiagnosisSummary } | null = null;
  private killSwitchHealthTimer: ReturnType<typeof setInterval> | null = null;
  private killSwitchHealthCheckRunning = false;
  private readonly telemetry = new ConnectionTelemetry(join(app.getPath("userData"), "telemetry"), {
    platform: "windows",
    app: app.getVersion(),
    os: windowsMajorVersion(release()),
  });
  private diskLog: DiskLog | null = null;
  private readonly remoteConfig = new RemoteConfigClient("windows", app.getVersion());
  private readonly remoteConfigStore = new RemoteConfigStore(join(app.getPath("userData"), "remote-config.json"));
  private readonly endpointsStore = new ServiceEndpointsStore(join(app.getPath("userData"), "service-endpoints.json"));
  private remoteStored: StoredRemoteConfig | null = null;
  private remoteRefresh: Promise<void> | null = null;
  private readonly notices = new NoticeState(join(app.getPath("userData"), "notices.json"));
  private settingsRevision = 0;
  /** Whether this computer's favourites were joined with the account's list (favoriteNodes.ts). */
  private favoritesJoined = false;
  private favoriteReconciledLocal = new Set<string>();
  private reconcilingFavorites = false;
  private pendingSync: SyncedSettings = {};
  private settingsSyncChain: Promise<void> = Promise.resolve();
  private settingsPushTimer: ReturnType<typeof setTimeout> | null = null;
  private backgroundTimer: ReturnType<typeof setInterval> | null = null;
  private homeTimer: ReturnType<typeof setInterval> | null = null;
  private readonly homePolicy = new HomeSleepPolicy();
  private homeChain: Promise<void> = Promise.resolve();
  /** The server's answer per home for the window it was given in. */
  private readonly homeAnswers = new Map<string, { window: number; home: VerifiedHome | null }>();
  /** The computer's addresses when the VPN fell asleep: another network means it left home. */
  private homeAddresses: string | null = null;
  private lastHomeScanAt = 0;
  private maintenanceTimer: ReturnType<typeof setInterval> | null = null;
  private maintenanceMoving = false;
  private commandChain: Promise<void> = Promise.resolve();
  private readonly handledCommands = new Set<string>();
  private noticeChain: Promise<void> = Promise.resolve();
  private readonly shownNotices = new Set<string>();
  /** Private keys of diagnostics requests sent from here, by command id. */
  private readonly replyKeys = new Map<string, KeyObject>();
  private remoteWatchedUntil = 0;
  private readonly idleMeter = new IdleMeter();
  private liveEvents: LiveEvents | null = null;
  /** What the server holds for this computer; null when it holds nothing. */
  private sentPresence: PresenceReport | null = null;
  private sentPresenceAt = 0;
  private presenceTimer: ReturnType<typeof setTimeout> | null = null;
  private approvalsTimer: ReturnType<typeof setTimeout> | null = null;
  private presenceKeepalive: ReturnType<typeof setInterval> | null = null;
  private presenceChain: Promise<void> = Promise.resolve();
  private lastAccountCheckAt = 0;
  private lastSettingsSyncAt = 0;
  private lastLinkRefreshAt = 0;
  private nextAttemptCause: AttemptCause = "initial";
  private recoveryCause: AttemptCause | null = null;
  private recoveryReason: "core_exited" | "probe" = "probe";
  private state: AppSnapshot = {
    appVersion: app.getVersion(),
    tab: "home",
    status: "disconnected",
    statusDetail: null,
    sessionAvailable: false,
    account: null,
    servers: [],
    serverLatencies: {},
    serverMaintenance: {},
    remote: { devices: [], commands: [], notes: {}, loadedAt: null },
    selectedServerId: null,
    selectedSubscriptionId: null,
    settings: DEFAULT_SETTINGS,
    sessionStartedAt: null,
    downloadBytes: 0,
    uploadBytes: 0,
    logs: [],
    busy: true,
    update: { status: "idle", version: null, progress: null, message: null },
    announcements: [],
    pendingApprovals: [],
    loginPending: false,
    settingsSyncedAt: null,
    homeRoad: null,
  };

  constructor() {
    super();
    this.homeRoad.on("status", (status, detail) => {
      if (status === "error" && detail) this.addLog(`Дорога домой: ${detail}`);
      this.patch({ homeRoad: this.homeRoadSnapshot() });
    });
    try {
      this.updater = new AppUpdater();
      this.updater.on("changed", (update) => this.patch({ update }));
    } catch (error) {
      this.updater = null;
      this.state.update = { status: "error", version: null, progress: null, message: `Модуль обновлений недоступен: ${messageOf(error)}` };
    }
  }

  async initialize(): Promise<void> {
    this.diskLog = new DiskLog(join(app.getPath("userData"), "logs"));
    this.diskLog.write(`Levik VPN ${app.getVersion()} started on Windows ${release()}`);
    await this.killSwitch.cleanupLegacyConfig(app.getPath("userData"));
    await this.dnsLeakProtection.disable();
    this.identity = await this.loadIdentity();
    // Signed hosts from the last run first, so a blocked domain is not even tried.
    await this.endpointsStore.load();
    this.api = new MobileApiClient(
      process.env.LEVIK_API_ORIGIN ?? DEFAULT_API_ORIGIN,
      new RequestSigner(this.identity),
      app.getVersion(),
      () => this.endpointsStore.refresh(ENDPOINTS_RETRY_MS),
    );
    this.xray.on("log", (line) => this.handleCoreLog(line));
    this.xray.on("exit", (code, expected) => this.handleXrayExit(code, expected));
    this.xray.on("stats", (downloadBytes, uploadBytes) => this.handleTrafficStats(downloadBytes, uploadBytes));
    this.liveEvents = new LiveEvents(
      (signal) => this.api.openEvents(this.requireToken(), signal),
      isAuthenticationRejected,
    );
    this.liveEvents.on("event", (event) => this.handleLiveEvent(event));
    // The stream does not clear the session itself; a regular request decides.
    this.liveEvents.on("unauthorized", () => void this.checkAccount(true));
    this.accessToken = await this.loadString("access_token");
    this.state.sessionAvailable = this.accessToken !== null;
    this.state.settings = await this.loadSettings();
    await this.gameHistory.load();
    if (process.platform === "win32") void discoverInstalledGames().then((installedGames) => this.updateGame({ installedGames })).catch(() => {});
    await this.loadSyncState();
    await this.notices.load();
    this.remoteStored = await this.remoteConfigStore.load();
    this.state.announcements = this.announcements();
    await this.telemetry.setEnabled(telemetryAllowed(this.state.settings)).catch((error: unknown) => {
      this.addLog(`Статистика подключений: ${messageOf(error)}`);
    });
    const recoveredKillSwitch = await this.killSwitch.recover();
    if (recoveredKillSwitch && !this.state.settings.killSwitch) {
      await this.killSwitch.disable();
    } else if (recoveredKillSwitch) {
      this.addLog("Kill Switch: восстановлена защита после предыдущего завершения приложения");
      this.patch({ status: "error", statusDetail: "Kill Switch защищает трафик после сбоя. Подключите VPN или нажмите Отключить, чтобы снять блокировку." });
    }
    this.startKillSwitchHealthMonitor();
    this.tunnelHealthTimer = setInterval(() => void this.verifyTunnelHealth(), 15_000);
    this.gameMonitor = setInterval(() => {
      if (this.state.status === "connected" && this.state.settings.gameEnabled) {
        void this.measureGameRoutes().catch(() => {});
      }
    }, 60_000);
    this.profile = await this.loadProfile();
    if (this.profile) {
      await this.migrateGamePreference(this.profile);
      // Keep the Game switch reachable during an API outage so the user can
      // disable it and connect with the ordinary cached profile. Connecting
      // with Game still requires a fresh server-side profile below.
      const cachedGame = this.profile.game;
      this.updateGame({ available: cachedGame?.enabled === true && this.state.sessionAvailable
        && (!this.profile.subscriptionExpiresAt || Date.parse(this.profile.subscriptionExpiresAt) > Date.now()),
        nodes: (cachedGame?.nodes ?? []).map(({ nodeId, name, countryCode, state }) => ({ nodeId, name, countryCode, state })),
        routes: (cachedGame?.servers ?? []).map((server) => ({ id: server.id, name: server.name, countryCode: server.countryCode, ...(server.nodeId ? { nodeId: server.nodeId } : {}) })),
      });
      this.state.servers = this.profile.servers;
      this.state.selectedSubscriptionId = this.profile.subscriptionId;
      this.state.selectedServerId = await this.loadString("selected_server")
        ?? this.bestServer(this.profile.servers)?.id
        ?? null;
    }
    this.applyLoginItemSettings();
    this.state.busy = false;
    this.emitChanged();
    void this.reconcileFavorites();
    // Before any tunnel: protocol advice describes the user's own operator.
    void this.refreshRemoteConfig();
    void this.endpointsStore.refresh();
    this.backgroundTimer = setInterval(() => void this.backgroundTick(), BACKGROUND_TICK_MS);
    this.homeTimer = setInterval(() => this.checkHomeSoon(), HOME_TICK_MS);
    this.maintenanceTimer = setInterval(() => void this.checkMaintenance(), MAINTENANCE_CHECK_MS);
    this.presenceKeepalive = setInterval(() => this.reportPresenceSoon(), PRESENCE_REFRESH_MS);
    this.startLiveEvents();
    if (this.accessToken) {
      try {
        await this.refreshAccount();
      } catch (error) {
        this.addLog(`Синхронизация аккаунта: ${messageOf(error)}`);
      }
      this.refreshHomeRoadSoon();
    }
    if (this.profile) {
      if (this.state.settings.autoConnectOnLaunch) {
        try {
          await this.pingServers();
          await this.connect("auto_connect");
        } catch (error) {
          this.addLog(`Автоподключение: ${messageOf(error)}`);
        }
      } else {
        void this.pingServers();
      }
    }
    void this.updater?.check(true);
  }

  snapshot(): AppSnapshot {
    return structuredClone(this.state);
  }

  async beginLogin(): Promise<LoginChallenge> {
    if (this.state.busy) throw new Error("Дождитесь завершения текущей операции");
    let generation = this.loginGeneration;
    this.patch({ busy: true, statusDetail: null });
    try {
      const accountHint = await this.loadString("account_hint");
      const challenge = await this.api.createChallenge({
        accountActivationSupported: true,
        numberMatchSupported: true,
        ...(isAccountHint(accountHint) ? { accountHint } : {}),
        publicKeySpki: this.identity.publicKeySpkiBase64Url(),
        deviceLabel: "Levik VPN for Windows",
        deviceModel: `${platform()} ${process.arch}`.slice(0, 128),
        deviceOs: `Windows ${release()}`.slice(0, 128),
        appVersion: app.getVersion(),
        requestSigningAlgorithm: "RS256",
        profileEncryptionAlgorithm: "RSA-OAEP+A256GCM",
      });
      if (generation !== this.loginGeneration) throw new Error("Вход отменён");
      generation = ++this.loginGeneration;
      void this.pollLogin(challenge, generation);
      const verificationUri = challenge.activationUriComplete ?? challenge.verificationUriComplete;
      if (!verificationUri) throw new Error("Сервер не вернул ссылку авторизации");
      const telegramUri = challenge.telegramUriComplete;
      return {
        verificationUri,
        verificationCode: challenge.activationCode ?? challenge.verificationCode ?? null,
        expiresAt: challenge.expiresAt,
        matchNumber: matchNumber(challenge.matchNumber),
        telegramUri: typeof telegramUri === "string" && isTelegramLink(telegramUri) ? telegramUri : null,
        approvalRequested: challenge.approvalRequested === true,
      };
    } finally {
      if (generation === this.loginGeneration) this.patch({ busy: false });
    }
  }

  cancelLogin(): void {
    this.loginGeneration += 1;
    this.patch({ busy: false, statusDetail: null, loginPending: false });
  }

  async logout(): Promise<void> {
    this.loginGeneration += 1;
    this.homePolicy.stopped();
    await this.stopConnection("user", "user");
    const token = this.accessToken;
    if (token) {
      await this.withdrawPresence();
      try {
        await this.api.logout(token);
      } catch (error) {
        this.addLog(`Выход на сервере: ${messageOf(error)}`);
      }
    }
    await this.clearLocalSession(null);
  }

  async refreshAccount(): Promise<void> {
    this.patch({ busy: true });
    try {
      const response = await this.withSession((token) => this.api.account(token));
      const account = mapAccount(response);
      const preferred = this.state.selectedSubscriptionId;
      const subscriptionId = account.subscriptions.some((item) => item.uuid === preferred)
        ? preferred
        : account.subscriptions.find((item) => item.status.toLowerCase() === "active")?.uuid
          ?? account.subscriptions[0]?.uuid
          ?? null;
      this.patch({ account, selectedSubscriptionId: subscriptionId });
      this.lastAccountCheckAt = Date.now();
      void this.syncSettingsNow();
      void this.checkExpiry();
      if (subscriptionId) await this.loadTunnelProfile(subscriptionId);
    } finally {
      this.patch({ busy: false });
    }
  }

  async selectSubscription(subscriptionId: string): Promise<void> {
    if (!this.state.account?.subscriptions.some((item) => item.uuid === subscriptionId)) {
      throw new Error("Подписка не найдена");
    }
    const reconnect = this.connectionRequested();
    const generation = this.connectionGeneration + (reconnect ? 1 : 0);
    if (reconnect) await this.stopTunnelForReplacement();
    this.patch({ selectedSubscriptionId: subscriptionId, busy: true });
    try {
      await this.loadTunnelProfile(subscriptionId);
      if (reconnect && generation === this.connectionGeneration) await this.connect();
    } catch (error) {
      if (reconnect && generation === this.connectionGeneration) this.patch({ status: "error", statusDetail: messageOf(error), sessionStartedAt: null });
      throw error;
    } finally {
      this.patch({ busy: false });
    }
  }

  async selectServer(serverId: string): Promise<void> {
    const server = this.state.servers.find((item) => item.id === serverId);
    if (!server) throw new Error("Сервер не найден");
    const reconnect = this.connectionRequested();
    const generation = this.connectionGeneration + (reconnect ? 1 : 0);
    if (reconnect) await this.stopTunnelForReplacement();
    try {
      this.state.selectedServerId = serverId;
      await this.secureStore.put("selected_server", Buffer.from(serverId));
      this.emitChanged();
      if (reconnect && generation === this.connectionGeneration) await this.connect();
    } catch (error) {
      if (reconnect && generation === this.connectionGeneration) this.patch({ status: "error", statusDetail: messageOf(error), sessionStartedAt: null });
      throw error;
    }
  }

  async connect(trigger: SessionTrigger = "user"): Promise<void> {
    if (this.xray.isRunning() || this.state.status === "connecting") return;
    // Connecting by hand at home: the VPN stays on until the next arrival.
    if (trigger === "user" && this.homePolicy.asleep) this.homePolicy.resumedByUser();
    const generation = this.connectionGeneration;
    if (this.state.settings.gameEnabled && Date.now() - this.gameValidatedAt > 5 * 60_000 && this.state.selectedSubscriptionId) {
      await this.loadTunnelProfile(this.state.selectedSubscriptionId);
    }
    // Profile refresh can expire the session and call disconnect(), so perform
    // it outside the serialized process lifecycle to avoid waiting on ourselves.
    if (!this.profile) {
      const subscriptionId = this.state.selectedSubscriptionId;
      if (!subscriptionId) throw new Error("Выберите активную подписку");
      await this.loadTunnelProfile(subscriptionId);
    }
    if (this.state.settings.automaticServer && !hasMeasuredLatency(this.state.serverLatencies)) {
      await this.pingServers();
    }
    if (!this.telemetry.active) {
      // Before Kill Switch: the operator is only visible outside the tunnel.
      await this.telemetry.prepareNetwork();
      this.telemetry.begin(trigger, sessionSettings(this.state.settings));
      this.nextAttemptCause = "initial";
    }
    return this.runTunnelOperation(() => this.connectTunnel(generation));
  }

  private async connectTunnel(generation: number): Promise<void> {
    if (generation !== this.connectionGeneration || this.xray.isRunning()) return;
    const server = this.selectedServer();
    if (!server || !this.profile) throw new Error("Выберите VPN-сервер");
    // A replacement or retry inherits the existing fail-closed boundary.
    // Only a fresh connection may release protection on startup failure.
    const retainProtectionOnFailure = this.state.settings.killSwitch && this.killSwitch.isActive();
    this.resetTrafficStats();
    this.patch({ status: "connecting", statusDetail: `Подключение через ${server.name}…`, busy: true, downloadBytes: 0, uploadBytes: 0 });
    const progress = this.recordAttempt(server, this.nextAttemptCause);
    this.nextAttemptCause = "reconnect";
    try {
      if (this.state.settings.killSwitch) await this.killSwitch.enable();
      if (this.state.settings.preventDnsLeaks) await this.dnsLeakProtection.enable();
      progress.reach("profile", "config_invalid");
      this.gamePassword = randomBytes(24).toString("hex");
      const config = buildXrayConfig(this.profile, server, this.state.settings, this.gamePassword);
      this.lastConfig = config;
      this.lastTuic = server.tuic;
      progress.reach("core", "core_start_failed");
      await this.startXray(config, generation);
      this.recordNetwork();
      progress.reach("verify", "timeout");
      await this.verifyTunnelReadiness(generation, (codes) => progress.reach("verify", codes[0] ?? "other"));
      this.assertCurrentConnection(generation);
      this.tunnelHealthFailures = 0;
      this.failedServerIds.clear();
      this.reconnectAttempts = 0;
      this.patch({
        status: "connected",
        statusDetail: `Защищено через ${server.name}`,
        sessionStartedAt: Date.now(),
      });
      this.recordConnected();
    } catch (error) {
      this.lastConfig = null;
      this.lastTuic = undefined;
      let failure: unknown = error;
      try {
        await this.xray.stop();
        if (!retainProtectionOnFailure) await this.releaseProtection();
      } catch (cleanupError) {
        failure = cleanupError;
      }
      if (generation === this.connectionGeneration) {
        this.patch({ status: "error", statusDetail: messageOf(failure), sessionStartedAt: null });
        progress.fail();
        void this.telemetry.finish("error", progress.code);
      }
      throw failure;
    } finally {
      this.patch({ busy: false });
    }
  }

  disconnect(): Promise<void> {
    return this.stopConnection("user", "user");
  }

  private stopConnection(by: EndBy, code: string | null): Promise<void> {
    void this.telemetry.finish(by, code);
    this.cancelTunnelRecovery();
    this.lastConfig = null;
    this.lastTuic = undefined;
    this.patch({ status: "disconnecting", statusDetail: "Отключение…" });
    return this.runTunnelOperation(async () => {
      try {
        await this.xray.stop();
        await this.releaseProtection();
        this.patch({ status: "disconnected", statusDetail: null, sessionStartedAt: null, busy: false });
      } catch (error) {
        this.patch({ status: "error", statusDetail: messageOf(error), sessionStartedAt: null, busy: false });
        throw error;
      }
    });
  }

  private async releaseProtection(): Promise<void> {
    const results = await Promise.allSettled([
      this.dnsLeakProtection.disable(), this.killSwitch.disable(),
    ]);
    for (const result of results) {
      if (result.status === "rejected") this.addLog(`Снятие защиты: ${messageOf(result.reason)}`);
    }
    const failure = results.find((result) => result.status === "rejected");
    if (failure?.status === "rejected") throw failure.reason;
  }

  /** Settings changed here ("user") or by another device of the account ("sync"). */
  async updateSettings(patch: Partial<AppSettings>, origin: "user" | "sync" = "user"): Promise<void> {
    const previous = this.state.settings;
    const next = validateSettings({ ...previous, ...patch });
    if (next.gameEnabled && (patch.gameEnabled === true || patch.gameProtection === true || patch.gameIds || patch.gameProcesses || patch.gameRouteId)) {
      if (!this.profile?.game?.enabled || !this.state.game?.available) throw new Error("Game Squad недоступен для выбранной подписки");
      if (!gameProcesses(next).length) throw new Error("Сначала выберите игру");
      if (next.gameRouteId && !this.profile.game.servers.some((server) => server.id === next.gameRouteId || server.nodeId === next.gameRouteId)) throw new Error("Игровой узел недоступен");
      if (patch.gameRouteId && this.profile.game.nodes?.some((node) => node.nodeId === next.gameRouteId && node.state !== "enabled")) throw new Error("Игровой узел на обслуживании. Выберите другой выход.");
    }
    const gameRulesChanged = gameProcesses(previous).join("\0") !== gameProcesses(next).join("\0");
    const hotGameRules = previous.gameEnabled === true && next.gameEnabled === true && this.state.status === "connected" && !this.state.busy;
    let reconnect = this.connectionRequested() && (affectsTunnel(previous, next) || (gameRulesChanged && !hotGameRules));
    const generation = this.connectionGeneration;
    this.state.settings = next;
    await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(next))));
    this.applyLoginItemSettings();
    this.emitChanged();
    if (origin === "user") await this.recordSyncedChanges(previous, next);
    if (previous.favoriteNodes !== next.favoriteNodes || previous.favoriteServerIds.join("\0") !== next.favoriteServerIds.join("\0")) {
      await this.reconcileFavorites();
    }
    if (previous.sharePresence !== next.sharePresence) this.reportPresenceSoon(true);
    if (telemetryAllowed(previous) !== telemetryAllowed(next)) await this.telemetry.setEnabled(telemetryAllowed(next));
    this.telemetry.record((session) => session.updateSettings(sessionSettings(next)));
    if (!previous.automaticServer && next.automaticServer) void this.pingServers();
    if (previous.killSwitch && !next.killSwitch) await this.killSwitch.disable();
    if (previous.preventDnsLeaks && !next.preventDnsLeaks) await this.dnsLeakProtection.disable();
    if (!reconnect && hotGameRules && gameRulesChanged && generation === this.connectionGeneration) {
      try { await this.xray.updateGameProcesses(next); }
      catch {
        this.updateGame({ message: "Ядро не применило новые игровые правила. Переподключаем VPN, чтобы добавить выбранные игры." });
        reconnect = true;
      }
    }
    if (!reconnect && hotGameRules && generation === this.connectionGeneration) {
      const preference = next.gameRouteId;
      this.xray.updateGameOptions({ protection: next.gameProtection !== false,
        preferredExitId: this.profile?.game?.servers.find((server) => server.id === preference)?.nodeId ?? preference ?? null,
        exitScope: gameExitScope(next) });
    }
    if (reconnect && generation === this.connectionGeneration) {
      await this.stopTunnelForReplacement();
      if (generation + 1 === this.connectionGeneration) await this.connect();
    }
  }

  async shutdown(reason: "quit" | "app_update" = "quit"): Promise<void> {
    this.loginGeneration += 1;
    const saved = this.telemetry.finish("system", reason === "app_update" ? "app_update" : null);
    await this.stopConnection("system", null);
    this.stopKillSwitchHealthMonitor();
    if (this.tunnelHealthTimer) clearInterval(this.tunnelHealthTimer);
    this.tunnelHealthTimer = null;
    if (this.gameMonitor) clearInterval(this.gameMonitor);
    this.gameMonitor = null;
    if (this.backgroundTimer) clearInterval(this.backgroundTimer);
    this.backgroundTimer = null;
    if (this.homeTimer) clearInterval(this.homeTimer);
    this.homeTimer = null;
    if (this.maintenanceTimer) clearInterval(this.maintenanceTimer);
    this.maintenanceTimer = null;
    this.stopPresence();
    this.liveEvents?.stop();
    await Promise.race([this.withdrawPresence(), delay(2_000)]);
    // Unsent setting changes are kept on disk and sent after the next start.
    if (this.settingsPushTimer) clearTimeout(this.settingsPushTimer);
    this.settingsPushTimer = null;
    await this.homeRoad.stop();
    await saved;
    this.telemetry.dispose();
    await this.diskLog?.flush();
  }

  async pingServers(): Promise<void> {
    if (this.pingPromise) return this.pingPromise;
    const servers = [...this.state.servers];
    this.pingPromise = (async () => {
      const latencies = await measureServerLatencies(servers);
      if (!sameServers(servers, this.state.servers)) return;
      this.patch({ serverLatencies: latencies });
      if (this.state.settings.automaticServer && !this.xray.isRunning()) {
        const best = this.bestServer(servers);
        if (best && best.id !== this.state.selectedServerId) {
          this.state.selectedServerId = best.id;
          await this.secureStore.put("selected_server", Buffer.from(best.id));
          this.emitChanged();
        }
      }
    })().finally(() => { this.pingPromise = null; });
    return this.pingPromise;
  }

  async measureGameRoutes(forGameStart = false): Promise<void> {
    if (this.gameProbePromise) return this.gameProbePromise;
    const profile = this.profile;
    const game = this.state.game;
    const password = this.gamePassword;
    if (!profile?.game?.enabled || !game?.available || !password || !this.state.settings.gameEnabled || !this.xray.isRunning()) return;
    const servers = profile.game.servers;
    const generation = this.connectionGeneration;
    const abort = new AbortController();
    this.gameProbeAbort = abort;
    const current = (): boolean => !abort.signal.aborted && generation === this.connectionGeneration
      && profile.subscriptionId === this.profile?.subscriptionId && sameServers(servers, this.profile?.game?.servers ?? []);
    this.updateGame({ phase: "probing", message: null });
    this.gameProbePromise = (async () => {
      const quality: NonNullable<AppSnapshot["game"]>["quality"] = {};
      this.xray.refreshGameMeasurements();
      const measuredRoutes = this.xray.gameRouteQualities;
      servers.forEach((server, index) => {
        const measured = measuredRoutes[index];
        if (measured) quality[server.id] = measured;
      });
      if (!current()) return;
      const enabled = servers.filter((server) => !profile.game?.nodes?.some((node) => node.nodeId === server.nodeId && node.state !== "enabled"));
      const best = bestGameRoute(enabled, quality);
      const activeId = this.state.game?.activeRouteId;
      // Ordinary scans keep the TCP exit. A newly observed game can select it
      // again only before UDP flows have pinned that process session's exit.
      const selectAtStart = forGameStart && (this.xray.gameRuntimeSnapshot?.activeFlowCount ?? 0) === 0;
      const pinnedId = selectAtStart ? null : activeId;
      const historyId = this.gameHistory.preferredExit(this.currentGameId);
      const selected = pinnedId ? servers.find((server) => server.id === pinnedId)
        : this.state.settings.gameRouteId ? enabled.find((server) => server.id === this.state.settings.gameRouteId || server.nodeId === this.state.settings.gameRouteId)
        : enabled.find((server) => server.nodeId === historyId && quality[server.id]?.latencyMs != null && (quality[server.id]?.lossPercent ?? 100) <= 25) ?? best;
      const measured = selected ? quality[selected.id] : null;
      const healthy = measured?.latencyMs !== null && measured?.latencyMs !== undefined && measured.lossPercent <= 25;
      if ((!activeId || selectAtStart) && selected && healthy) {
        await this.xray.selectGameRoute(servers.indexOf(selected));
        if (!current()) return;
      }
      this.updateGame({ quality, recommendedRouteId: best?.id ?? null,
        activeRouteId: pinnedId ?? (healthy ? selected?.id ?? null : null),
        phase: healthy ? "ready" : "degraded",
        message: healthy ? null : activeId
          ? "Игровой маршрут нестабилен. Завершите матч и переподключите VPN для повторного выбора."
          : "Рабочий UDP-маршрут не найден. Игровой трафик приостановлен; обычный VPN работает.",
      });
    })().catch(() => {
      if (current()) this.updateGame({ phase: "degraded", message: "Не удалось проверить игровой маршрут. Повторите проверку." });
    }).finally(() => {
      if (this.gameProbeAbort === abort) { this.gameProbePromise = null; this.gameProbeAbort = null; }
    });
    return this.gameProbePromise;
  }

  private updateGame(patch: Partial<GameSnapshot>): void {
    this.patch({ game: { available: false, routes: [], quality: {}, activeRouteId: null,
      recommendedRouteId: null, phase: "idle", message: null, ...this.state.game, ...patch } });
  }

  private async migrateGamePreference(profile: PreparedTunnelProfile): Promise<void> {
    const previous = this.state.settings.gameRouteId;
    const nodeId = profile.game?.servers.find((server) => server.id === previous)?.nodeId;
    if (nodeId && nodeId !== previous) {
      this.state.settings = { ...this.state.settings, gameRouteId: nodeId };
      await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(this.state.settings))));
    }
  }

  private cancelGameProbes(): void {
    this.gameProbeAbort?.abort();
    this.gameProbeAbort = null;
    this.gameProbePromise = null;
    this.gameLastHistoryKey = null;
    this.pendingGameProfile = null;
    if (this.state.game) this.updateGame({ activeRouteId: null, phase: "idle", message: null, multipath: null, runtime: null });
  }

  async revokeDevice(subscriptionId: string, deviceId: string): Promise<void> {
    const subscription = this.state.account?.subscriptions.find((item) => item.uuid === subscriptionId);
    if (!subscription || !subscription.devices.items.some((item) => item.id === deviceId)) throw new Error("Устройство не найдено");
    if (!subscription.actions.revokeDevice) throw new Error("Отзыв устройства недоступен для этой подписки");
    if (deviceId === this.identity.deviceId()) throw new Error("Нельзя отвязать текущее устройство");
    await this.withSession((token) => this.api.revokeDevice(token, subscriptionId, deviceId));
    await this.refreshAccount();
  }

  async setSubscriptionShield(subscriptionId: string, enabled: boolean): Promise<void> {
    const subscription = this.state.account?.subscriptions.find((item) => item.uuid === subscriptionId);
    if (!subscription?.shield.supported) throw new Error("Levik Shield недоступен для этой подписки");
    await this.withSession((token) => this.api.setSubscriptionShield(token, subscriptionId, enabled));
    await this.refreshAccount();
  }

  async authorizeActivation(code: string): Promise<void> {
    const normalized = normalizeActivationCode(code);
    await this.withSession((token) => this.api.authorizeActivation(token, normalized));
  }

  /** A one-time encrypted note with the state and the redacted log, for support. */
  async createSupportReport(): Promise<string> {
    const log = (await this.diskLog?.read(MAX_SUPPORT_NOTE_BYTES)) ?? "";
    const now = new Date();
    const diagnosis = this.lastDiagnosis && now.getTime() - this.lastDiagnosis.at < DIAGNOSIS_REPORT_MS ? this.lastDiagnosis.summary : null;
    const report = supportReportText(this.state, { system: `Windows ${release()} (${process.arch})`, now, diagnosis });
    return createSupportNote(supportNoteText(report, log));
  }

  /** "It's not the VPN": one sentence for the support dialog, docs/app-platform.md "Diagnosis". */
  diagnose(): Promise<DiagnosisSummary> {
    this.diagnosisPromise ??= this.runDiagnosis().finally(() => { this.diagnosisPromise = null; });
    return this.diagnosisPromise;
  }

  async applyDiagnosisAction(action: DiagnosisAction): Promise<void> {
    switch (action) {
      case "connect":
        await this.connect("user");
        return;
      case "bestServer":
        await this.useBestServer();
        return;
      case "servers":
        this.emit("navigate", "servers");
        return;
      default:
        // Retrying and the report run in the window; the system settings open from ipc.ts.
        return;
    }
  }

  async dismissAnnouncement(id: string): Promise<void> {
    if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("Сообщение не найдено");
    await this.notices.dismiss(id);
    this.patch({ announcements: this.announcements() });
  }

  /** A signed-in link to the website; the plain page when the app cannot sign in. */
  async cabinetUrl(target: CabinetTarget): Promise<string> {
    if (!this.accessToken) return cabinetFallbackUrl(target);
    try {
      const response = await this.withSession((token) => this.api.webHandoff(token, target));
      if (isHandoffUrl(response.url)) return response.url;
      this.addLog("Личный кабинет: сервер вернул некорректную ссылку");
    } catch (error) {
      this.addLog(`Личный кабинет: ${messageOf(error)}`);
    }
    return cabinetFallbackUrl(target);
  }

  /** levik://open from the website, usually after a payment. */
  handleDeepLink(tab: AppTab): void {
    this.emit("navigate", tab);
    const now = Date.now();
    if (!this.accessToken || this.state.busy || now - this.lastLinkRefreshAt < LINK_REFRESH_INTERVAL_MS) return;
    this.lastLinkRefreshAt = now;
    void this.refreshAccount().catch((error: unknown) => this.addLog(`Обновление аккаунта: ${messageOf(error)}`));
  }

  checkForUpdates(): Promise<void> {
    if (!this.updater) throw new Error("Модуль обновлений недоступен");
    return this.updater.check(false);
  }

  downloadUpdate(): Promise<void> {
    if (!this.updater) throw new Error("Модуль обновлений недоступен");
    return this.updater.download();
  }

  async installUpdate(): Promise<void> {
    if (!this.updater) throw new Error("Модуль обновлений недоступен");
    await this.updater.install(
      () => this.shutdown("app_update"),
      () => this.emit("updateInstalling"),
    );
  }

  async restoreAfterSystemResume(): Promise<void> {
    if (this.resumePromise) return this.resumePromise;
    const generation = this.connectionGeneration;
    this.resumePromise = (async () => {
      await delay(1_500);
      if (generation === this.connectionGeneration) await this.verifyTunnelHealth(true, "resume");
    })().finally(() => { this.resumePromise = null; });
    return this.resumePromise;
  }

  /** Sleep explains drops that are not the server's fault. */
  recordPowerEvent(state: Extract<PowerState, "suspend" | "resume">): void {
    this.telemetry.record((session) => session.power(state));
    if (state === "suspend") void this.telemetry.persist();
  }

  private async pollLogin(challenge: AuthChallengeResponse, generation: number): Promise<void> {
    this.patch({ loginPending: true });
    try {
      await this.waitForLogin(challenge, generation);
    } finally {
      // The sign-in screen offers to start again once this attempt is over.
      if (generation === this.loginGeneration) this.patch({ loginPending: false });
    }
  }

  private async waitForLogin(challenge: AuthChallengeResponse, generation: number): Promise<void> {
    let intervalSeconds = clamp(challenge.pollIntervalSeconds, 2, 10);
    const expiresAt = Date.parse(challenge.expiresAt);
    while (generation === this.loginGeneration && Date.now() < expiresAt) {
      await delay(intervalSeconds * 1_000);
      if (generation !== this.loginGeneration) return;
      try {
        const status = await this.api.pollStatus(challenge.loginToken);
        intervalSeconds = clamp(status.pollIntervalSeconds ?? intervalSeconds, 2, 10);
        if (status.state === "pending") continue;
        if (status.state === "declined") {
          this.patch({ statusDetail: "Вход отменён: выбрано другое число или нажато «Это не я»" });
          return;
        }
        if (status.state !== "authenticated" || !status.accessToken) {
          this.patch({ statusDetail: status.state === "denied" ? "Вход отклонён" : "Срок входа истёк" });
          return;
        }
        if (status.accessToken.length < 32 || status.accessToken.length > 4_096) throw new Error("Некорректная сессия");
        this.accessToken = status.accessToken;
        await this.secureStore.put("access_token", Buffer.from(status.accessToken));
        if (isAccountHint(status.accountHint)) await this.secureStore.put("account_hint", Buffer.from(status.accountHint));
        this.patch({ sessionAvailable: true });
        this.startLiveEvents();
        try {
          await this.refreshAccount();
        } catch (error) {
          if (!this.accessToken) throw error;
          this.addLog(`Синхронизация аккаунта: ${messageOf(error)}`);
        }
        this.refreshHomeRoadSoon();
        this.patch({ statusDetail: "Вход выполнен" });
        return;
      } catch (error) {
        this.addLog(`Ожидание входа: ${messageOf(error)}`);
      }
    }
    if (generation === this.loginGeneration) this.patch({ statusDetail: "Срок входа истёк" });
  }

  private async loadTunnelProfile(subscriptionId: string): Promise<void> {
    const response = await this.withSession((token) => this.api.tunnelProfile(token, subscriptionId));
    const plaintext = decryptTunnelProfile(this.identity, response.profile);
    try {
      const profile = prepareTunnelProfile(plaintext, subscriptionId);
      await this.applyTunnelProfile(profile);
    } finally {
      plaintext.fill(0);
    }
  }

  private async applyTunnelProfile(profile: PreparedTunnelProfile): Promise<void> {
    if (profile.game?.enabled && profile.subscriptionExpiresAt && !(Date.parse(profile.subscriptionExpiresAt) > Date.now())) {
      profile = { ...profile, game: { ...profile.game, enabled: false } };
    }
    const oldGame = JSON.stringify(this.profile?.game ?? null);
    const gameTransportChanged = this.profile?.game?.enabled !== profile.game?.enabled
      || !sameServers(this.profile?.game?.servers ?? [], profile.game?.servers ?? [])
      || (this.profile?.game?.servers ?? []).some((server, index) => server.nodeId !== profile.game?.servers[index]?.nodeId);
    const runtime = this.xray.gameRuntimeSnapshot;
    if (gameTransportChanged && this.state.settings.gameEnabled && this.connectionRequested()
      && profile.game?.enabled && this.profile?.subscriptionId === profile.subscriptionId
      && (!profile.subscriptionExpiresAt || Date.parse(profile.subscriptionExpiresAt) > Date.now())
      && ((runtime?.activeFlowCount ?? 0) > 0 || runtime?.currentMatch || !this.xray.pauseNewGameFlowsIfIdle())) {
      this.pendingGameProfile = profile;
      this.gameValidatedAt = Date.now();
      const nodes = profile.game.nodes ?? [];
      const liveNodes = [...nodes, ...(this.profile.game?.nodes ?? []).filter((old) => !nodes.some((node) => node.nodeId === old.nodeId))
        .map((old) => ({ ...old, state: "draining" as const }))];
      if (this.profile.game) this.profile = { ...this.profile, subscriptionExpiresAt: profile.subscriptionExpiresAt,
        game: { ...this.profile.game, nodes: liveNodes } };
      this.xray.updateGameOptions({ nodes: liveNodes });
      await this.secureStore.put("tunnel_profile", Buffer.from(JSON.stringify(profile)));
      this.updateGame({ nodes: liveNodes.map(({ nodeId, name, countryCode, state }) => ({ nodeId, name, countryCode, state })),
        message: "Список игровых узлов обновлён. Новые подключения подготовятся после завершения текущих игровых потоков." });
      return;
    }
    this.pendingGameProfile = null;
    const replacingGame = this.connectionRequested() && this.state.settings.gameEnabled
      && gameTransportChanged;
    if (replacingGame) await this.stopTunnelForReplacement();
    this.profile = profile;
    this.gameValidatedAt = Date.now();
    await this.migrateGamePreference(profile);
    if (!replacingGame && this.state.settings.gameEnabled && this.xray.isRunning() && oldGame !== JSON.stringify(profile.game ?? null)) {
      this.xray.updateGameOptions({ nodes: profile.game?.nodes ?? [] });
    }
    const routeRemoved = this.state.settings.gameRouteId && !profile.game?.servers.some((server) => server.id === this.state.settings.gameRouteId || server.nodeId === this.state.settings.gameRouteId);
    if ((!profile.game?.enabled && this.state.settings.gameEnabled) || routeRemoved) {
      this.state.settings = { ...this.state.settings, gameEnabled: profile.game?.enabled === true && this.state.settings.gameEnabled === true, gameRouteId: null };
      await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(this.state.settings))));
    }
    this.updateGame({ available: profile.game?.enabled === true,
      nodes: (profile.game?.nodes ?? []).map(({ nodeId, name, countryCode, state }) => ({ nodeId, name, countryCode, state })),
      routes: (profile.game?.servers ?? []).map((server) => ({ id: server.id, name: server.name, countryCode: server.countryCode, ...(server.nodeId ? { nodeId: server.nodeId } : {}) })),
      ...(gameTransportChanged ? { quality: {}, activeRouteId: null, recommendedRouteId: null, phase: "idle" as const } : {}),
    });
    const selected = this.state.selectedServerId;
    const serverId = profile.servers.some((item) => item.id === selected)
      ? selected
      : this.bestServer(profile.servers)?.id ?? null;
    await this.secureStore.put("tunnel_profile", Buffer.from(JSON.stringify(profile)));
    if (serverId) await this.secureStore.put("selected_server", Buffer.from(serverId));
    this.patch({ servers: profile.servers, serverLatencies: {}, selectedServerId: serverId, selectedSubscriptionId: profile.subscriptionId });
    await this.reconcileFavorites();
    void this.pingServers();
    if (replacingGame) await this.connect();
  }

  private async backgroundTick(): Promise<void> {
    const now = Date.now();
    void this.endpointsStore.refresh(ENDPOINTS_REFRESH_MS);
    const stored = this.remoteStored;
    if (!stored || now - stored.fetchedAt >= stored.config.refreshAfterSeconds * 1_000) await this.refreshRemoteConfig();
    else await this.updateAnnouncements();
    if (!this.accessToken) return;
    if (this.state.settings.gameEnabled && this.state.selectedSubscriptionId && !this.state.busy) {
      await this.loadTunnelProfile(this.state.selectedSubscriptionId).catch(() => {});
    }
    if (now - this.lastAccountCheckAt >= ACCOUNT_CHECK_INTERVAL_MS) await this.checkAccount();
    if (!this.liveEvents?.active) this.startLiveEvents();
    if (now - this.lastHomeRoadAt >= HOME_ROAD_REFRESH_MS) this.refreshHomeRoadSoon();
    else this.recheckHomeRoad();
    if (Object.keys(this.pendingSync).length || now - this.lastSettingsSyncAt >= SETTINGS_SYNC_INTERVAL_MS) {
      await this.syncSettingsNow();
    }
  }

  private checkHomeSoon(): void {
    this.homeChain = this.homeChain.then(() => this.checkHome()).catch((error: unknown) => {
      this.addLog(`Levik Home: ${messageOf(error)}`);
    });
  }

  /**
   * Levik Home, docs/app-platform.md "Levik Home": tells the server that the
   * computer is at the account's home (it then takes no slot), and while the
   * home router's VPN protects the network, keeps the computer's VPN off
   * until it leaves.
   */
  private async checkHome(): Promise<void> {
    if (!this.accessToken) return;
    const now = Date.now();
    const asleep = this.homePolicy.asleep;
    const addresses = localAddresses().join(",");
    if (asleep && addresses !== this.homeAddresses) {
      await this.applyHome(this.homePolicy.left());
      return;
    }
    const connected = this.state.status === "connected";
    const interval = asleep ? HOME_TICK_MS : connected ? HOME_CONNECTED_SCAN_MS : HOME_IDLE_SCAN_MS;
    if (now - this.lastHomeScanAt < interval - 5_000 || !addresses) {
      await this.applyHome(this.homePolicy.silence(now));
      return;
    }
    this.lastHomeScanAt = now;
    const home = await this.listenForHome(now);
    await this.applyHome(this.homePolicy.heard(home, Date.now(), this.state.status === "connected", this.state.settings.sleepAtHome));
  }

  /** The account's home heard on this network, preferring one whose router protects it. */
  private async listenForHome(now: number): Promise<VerifiedHome | null> {
    const homes: VerifiedHome[] = [];
    for (const beacon of (await scanHomes()).filter((item) => beaconFresh(item, now))) {
      const home = await this.verifyHome(beacon);
      if (home) homes.push(home);
    }
    return homes.find(protects) ?? homes[0] ?? null;
  }

  /** One report per home and window: the answer does not change within it. */
  private async verifyHome(beacon: HomeBeacon): Promise<VerifiedHome | null> {
    const known = this.homeAnswers.get(beacon.homeId);
    if (known?.window === beacon.window) return known.home;
    let home: VerifiedHome | null;
    try {
      home = parseSighting(await this.withSession((token) => this.api.reportHomeSighting(token, beacon)));
    } catch (error) {
      this.addLog(`Levik Home: ${messageOf(error)}`);
      return null;
    }
    if (this.homeAnswers.size >= 16) this.homeAnswers.clear();
    this.homeAnswers.set(beacon.homeId, { window: beacon.window, home });
    return home;
  }

  private async applyHome(action: HomeAction): Promise<void> {
    if (action.kind === "sleep") {
      this.homeAddresses = localAddresses().join(",");
      this.addLog(`Levik Home: дома «${action.home}» VPN включён на роутере, Levik VPN отключается`);
      await this.stopConnection("system", "home");
      this.patch({ statusDetail: `Дома: «${action.home}» защищает VPN роутера. Levik VPN подключится, когда вы уйдёте` });
    } else if (action.kind === "wake") {
      this.homeAddresses = null;
      if (this.state.status !== "disconnected" || this.xray.isRunning()) return;
      this.addLog("Levik Home: вы ушли из дома, Levik VPN подключается");
      await this.connect("resume");
    }
  }

  /** «Пускать ко мне домой», docs/app-platform.md "Home road". */
  async setHomeRoad(enabled: boolean): Promise<void> {
    const task = this.homeRoadChain.then(async () => {
      const key = enabled ? (await this.homeRoadKey()).publicKey : null;
      const response = await this.withSession((token) => this.api.setRoadExit(token, key));
      await this.applyHomeRoad(response);
    });
    this.homeRoadChain = task.catch(() => {});
    await task;
  }

  private refreshHomeRoadSoon(): void {
    this.homeRoadChain = this.homeRoadChain.then(() => this.refreshHomeRoad()).catch((error: unknown) => {
      // The running exit keeps its token (valid for 30 days) until the website answers again.
      this.addLog(`Дорога домой: ${messageOf(error)}`);
    });
  }

  private async refreshHomeRoad(): Promise<void> {
    if (!this.accessToken) return;
    await this.applyHomeRoad(await this.withSession((token) => this.api.roadExit(token)));
  }

  private async applyHomeRoad(response: RoadExitResponse, rekeyed = false): Promise<void> {
    if (!this.accessToken) return;
    this.lastHomeRoadAt = Date.now();
    this.homeRoadAvailable = response.available === true;
    const hosts = new Set([...websiteHosts(), ...serviceEndpoints().apiOrigins.map((origin) => new URL(origin).hostname)]);
    const config = response.exit == null ? null : parseRoadExit(response.exit, hosts);
    if (response.exit != null && !config) this.addLog("Дорога домой: сайт прислал выход, который приложение не принимает");
    if (config && !rekeyed) {
      const key = await this.homeRoadKey();
      if (config.key !== key.publicKey) {
        // A new install or a new key: the website learns the public half, the devices' links follow.
        await this.applyHomeRoad(await this.withSession((token) => this.api.setRoadExit(token, key.publicKey)), true);
        return;
      }
    }
    await this.homeRoad.apply(config);
    this.patch({ homeRoad: this.homeRoadSnapshot() });
  }

  /** Another network may mean another interface for the «past the VPN» exit. */
  private recheckHomeRoad(): void {
    if (this.homeRoad.config?.mode !== "direct") return;
    this.homeRoadChain = this.homeRoadChain.then(async () => {
      const config = this.homeRoad.config;
      if (config?.mode === "direct") await this.homeRoad.apply(config);
    }).catch(() => {});
  }

  /** This computer's exit key: made once, kept in the secure store; the website gets the public half only. */
  private homeRoadKey(): Promise<RoadKey> {
    if (!this.homeRoadKeyPair) {
      const pair = (async () => {
        const stored = await this.secureStore.get("home_road_key");
        const restored = stored ? roadKeyFrom(stored.toString("utf8")) : null;
        if (restored) return restored;
        const created = createRoadKey();
        await this.secureStore.put("home_road_key", Buffer.from(created.privateKey));
        return created;
      })();
      this.homeRoadKeyPair = pair;
      pair.catch(() => {
        if (this.homeRoadKeyPair === pair) this.homeRoadKeyPair = null;
      });
    }
    return this.homeRoadKeyPair;
  }

  private homeRoadSnapshot(): HomeRoadSnapshot | null {
    if (!this.accessToken) return null;
    const config = this.homeRoad.config;
    return {
      available: this.homeRoadAvailable,
      enabled: config !== null,
      name: config?.name ?? null,
      mode: config?.mode ?? null,
      lanAccess: config?.lanAccess ?? false,
      status: this.homeRoad.status,
      detail: this.homeRoad.statusDetail,
    };
  }

  private async checkAccount(force = false): Promise<void> {
    if (!this.accessToken) return;
    if (!force && Date.now() - this.lastAccountCheckAt < 10_000) return;
    try {
      const response = await this.withSession((token) => this.api.account(token));
      this.lastAccountCheckAt = Date.now();
      this.patch({ account: mapAccount(response) });
      await this.checkExpiry();
    } catch (error) {
      this.addLog(`Проверка подписки: ${messageOf(error)}`);
    }
  }

  private startLiveEvents(): void {
    if (this.accessToken) this.liveEvents?.start();
  }

  /** docs/app-platform.md "Live events": every event names what to fetch again. */
  private handleLiveEvent(event: LiveEvent): void {
    switch (event) {
      case "ready":
      case "resync":
        this.runCommands();
        this.refreshNotices();
        this.refreshRemoteIfWatched();
        void this.refreshApprovals();
        void this.syncSettingsNow();
        void this.refreshRemoteConfig();
        void this.checkAccount();
        this.reportPresenceSoon(true);
        this.refreshHomeRoadSoon();
        break;
      case "settings":
        void this.syncSettingsNow();
        break;
      case "config":
        void this.refreshRemoteConfig();
        break;
      case "devices":
        void this.checkAccount(true);
        this.refreshRemoteIfWatched();
        this.refreshHomeRoadSoon();
        break;
      case "road":
        this.refreshHomeRoadSoon();
        break;
      case "presence":
        this.refreshRemoteIfWatched();
        break;
      case "approvals":
        void this.refreshApprovals();
        break;
      case "commands":
        this.runCommands();
        this.refreshRemoteIfWatched();
        break;
      case "rules":
        void this.applyAccountRules();
        break;
      case "notifications":
        this.refreshNotices();
        break;
    }
  }

  /**
   * The account's rules changed, docs/app-platform.md "Account rules". The
   * server folds them into the tunnel profile: fetch it and, while connected,
   * reconnect when the routing it carries changed.
   */
  private async applyAccountRules(): Promise<void> {
    const subscriptionId = this.state.selectedSubscriptionId;
    if (!this.accessToken || !subscriptionId || this.state.busy) return;
    const before = ruleRoutingKey(this.profile);
    try {
      await this.loadTunnelProfile(subscriptionId);
      if (ruleRoutingKey(this.profile) === before || !this.xray.isRunning()) return;
      this.addLog("Правила аккаунта изменились: переподключение");
      await this.stopTunnelForReplacement();
      await this.connect();
    } catch (error) {
      this.addLog(`Правила аккаунта: ${messageOf(error)}`);
    }
  }

  /** The account's apps for the remote; events keep the list current for a while. */
  async refreshRemote(watch = true): Promise<void> {
    if (!this.accessToken) return;
    if (watch) this.remoteWatchedUntil = Date.now() + REMOTE_WATCH_MS;
    const response = await this.withSession((token) => this.api.remoteDevices(token));
    const commands = parseIssuedCommands(response.commands);
    const notes = { ...this.state.remote.notes };
    for (const command of commands) {
      const key = this.replyKeys.get(command.id);
      if (!key || !isFinalState(command.state)) continue;
      this.replyKeys.delete(command.id);
      const link = command.state === "done" && command.detail ? openReply(key, command.detail) : null;
      if (link) notes[command.id] = link;
    }
    this.patch({ remote: { devices: parseRemoteDevices(response.devices), commands, notes, loadedAt: Date.now() } });
  }

  private refreshRemoteIfWatched(): void {
    if (Date.now() >= this.remoteWatchedUntil) return;
    void this.refreshRemote(false).catch((error: unknown) => this.addLog(`Пульт: ${messageOf(error)}`));
  }

  /** Asks another app of the account to do something; there is no command to disconnect. */
  async sendRemoteCommand(deviceId: string, command: RemoteCommand): Promise<void> {
    if (!isRemoteCommand(command)) throw new Error("Неизвестная команда");
    if (!this.state.remote.devices.some((item) => item.deviceId === deviceId && item.remote)) {
      throw new Error("Устройство недоступно для пульта");
    }
    const reply = command === "collect_diagnostics" ? createReplyKey() : null;
    const response = await this.withSession((token) => this.api.issueCommand(token, deviceId, command, reply?.replyKey ?? null));
    const [issued] = parseIssuedCommands([response.command]);
    if (issued && reply) this.replyKeys.set(issued.id, reply.privateKey);
    await this.refreshRemote(false);
  }

  /** A diagnostics link opened with this app's key; nothing else can be opened this way. */
  remoteNote(commandId: string): string {
    const link = this.state.remote.notes[commandId];
    if (!link) throw new Error("Диагностика недоступна");
    return link;
  }

  /**
   * Takes the account's due notices, docs/app-platform.md "Notifications",
   * and shows each once. Taking them is what keeps Telegram from repeating them.
   */
  private refreshNotices(): void {
    this.noticeChain = this.noticeChain
      .then(() => this.takeNotices())
      .catch((error: unknown) => this.addLog(`Уведомления: ${messageOf(error)}`));
  }

  private async takeNotices(): Promise<void> {
    if (!this.accessToken) return;
    const response = await this.withSession((token) => this.api.takeNotifications(token));
    for (const notice of parseAccountNotices(response.notifications)) {
      if (this.shownNotices.has(notice.id)) continue;
      this.shownNotices.add(notice.id);
      if (this.shownNotices.size > MAX_HANDLED_COMMANDS) {
        const oldest = this.shownNotices.values().next().value;
        if (oldest !== undefined) this.shownNotices.delete(oldest);
      }
      this.emit("notify", { title: notice.title, body: notice.body, tab: "profile", cabinet: notice.cabinet });
    }
  }

  /** Runs the commands sent to this компьютер, one at a time, docs/app-platform.md "Remote". */
  private runCommands(): void {
    this.commandChain = this.commandChain
      .then(() => this.takeAndRunCommands())
      .catch((error: unknown) => this.addLog(`Пульт: ${messageOf(error)}`));
  }

  private async takeAndRunCommands(): Promise<void> {
    if (!this.accessToken) return;
    const response = await this.withSession((token) => this.api.takeCommands(token));
    for (const command of parseDeliveredCommands(response.commands)) {
      if (this.handledCommands.has(command.id)) continue;
      this.handledCommands.add(command.id);
      if (this.handledCommands.size > MAX_HANDLED_COMMANDS) {
        const oldest = this.handledCommands.values().next().value;
        if (oldest !== undefined) this.handledCommands.delete(oldest);
      }
      const outcome = await this.executeCommand(command);
      await this.withSession((token) => this.api.commandResult(token, command.id, outcome.result, outcome.detail))
        .catch((error: unknown) => this.addLog(`Пульт: ${messageOf(error)}`));
      const helped = command.fromFamily && outcome.result === "done" ? FAMILY_HELP_TEXT[command.command] : undefined;
      if (helped) this.emit("notify", { title: "Владелец семьи помог", body: helped, tab: "home" });
    }
  }

  private async executeCommand(command: DeliveredCommand): Promise<{ result: "done" | "failed" | "unsupported"; detail: string | null }> {
    // Only the fixed list runs; a disconnect or anything else is refused here too.
    if (!isRemoteCommand(command.command)) return { result: "unsupported", detail: null };
    if (command.fromFamily && !allowedFromFamily(command.command)) return { result: "unsupported", detail: null };
    this.addLog(`Пульт: ${REMOTE_COMMAND_LABELS[command.command]}`);
    try {
      switch (command.command) {
        case "connect":
          if (this.state.status === "connected" || this.state.status === "connecting" || this.xray.isRunning()) {
            return { result: "done", detail: "already_connected" };
          }
          if (this.state.busy) return { result: "failed", detail: "busy" };
          await this.connect("user");
          this.emit("notify", { title: "Levik VPN подключён", body: "Подключение включено с другого вашего устройства.", tab: "home" });
          return { result: "done", detail: null };
        case "auto_server": {
          if (!this.state.settings.automaticServer) await this.updateSettings({ automaticServer: true });
          if (this.xray.isRunning()) {
            await this.pingServers();
            const best = this.bestServer(this.state.servers);
            if (best && best.id !== this.state.selectedServerId) await this.selectServer(best.id);
          }
          return { result: "done", detail: null };
        }
        case "refresh_profile":
          if (this.state.busy) return { result: "failed", detail: "busy" };
          await this.refreshAccount();
          return { result: "done", detail: null };
        case "check_update": {
          if (!this.updater) return { result: "unsupported", detail: null };
          await this.updater.check(false);
          const update = this.state.update;
          if ((update.status === "available" || update.status === "downloaded") && update.version) {
            return { result: "done", detail: `available:${update.version}` };
          }
          return update.status === "upToDate"
            ? { result: "done", detail: "up_to_date" }
            : { result: "failed", detail: "update_check_failed" };
        }
        case "collect_diagnostics": {
          if (!command.replyKey) return { result: "failed", detail: null };
          const link = await this.createSupportReport();
          this.emit("notify", {
            title: "Собрана диагностика",
            body: "Её запросили с другого вашего устройства. Отчёт зашифрован и откроется только там.",
            tab: "profile",
          });
          return { result: "done", detail: sealForReply(command.replyKey, link) };
        }
      }
    } catch (error) {
      this.addLog(`Пульт: ${messageOf(error)}`);
      return { result: "failed", detail: null };
    }
  }

  /** Fetches sign-ins waiting for approval; a new one also gets a notification. */
  private async refreshApprovals(): Promise<void> {
    if (!this.accessToken) return;
    if (this.approvalsTimer) clearTimeout(this.approvalsTimer);
    this.approvalsTimer = null;
    let approvals: PendingApproval[];
    try {
      approvals = parseApprovals((await this.withSession((token) => this.api.approvals(token))).approvals);
    } catch (error) {
      this.addLog(`Запросы на вход: ${messageOf(error)}`);
      return;
    }
    const known = new Set(this.state.pendingApprovals.map((approval) => approval.id));
    this.patch({ pendingApprovals: approvals });
    for (const approval of approvals) {
      if (known.has(approval.id)) continue;
      this.emit("notify", {
        title: "Подтвердите вход в Levik VPN",
        body: `${approval.platformLabel} · ${approval.deviceName}. Выберите число, которое показано на этом устройстве.`,
        tab: "home",
      });
    }
    // Drop each request when it expires, even without another event.
    const next = Math.min(...approvals.map((approval) => Date.parse(approval.expiresAt)));
    if (Number.isFinite(next)) {
      this.approvalsTimer = setTimeout(() => void this.refreshApprovals(), Math.max(1_000, next - Date.now() + 1_000));
    }
  }

  async answerApproval(id: string, number: number | null): Promise<ApprovalAnswerResult> {
    const approval = this.state.pendingApprovals.find((item) => item.id === id);
    if (!approval || !isApprovalAnswer(approval, number)) throw new Error("Запрос на вход уже обработан или истёк");
    try {
      const response = await this.withSession((token) => this.api.decideApproval(token, id, number));
      return response.state === "approved" ? "approved" : "declined";
    } catch (error) {
      if (error instanceof MobileApiError && error.status === 404) throw new Error("Запрос на вход уже обработан или истёк");
      throw error;
    } finally {
      this.patch({ pendingApprovals: this.state.pendingApprovals.filter((item) => item.id !== id) });
      void this.refreshApprovals();
    }
  }

  /** Coalesces state changes; "force" also repeats an unchanged report. */
  private reportPresenceSoon(force = false): void {
    // Only between initialize() and shutdown().
    if (!this.presenceKeepalive) return;
    if (this.presenceTimer) clearTimeout(this.presenceTimer);
    this.presenceTimer = setTimeout(() => {
      this.presenceTimer = null;
      this.presenceChain = this.presenceChain.then(() => this.sendPresence(force)).catch((error: unknown) => {
        this.addLog(`Статус устройства: ${messageOf(error)}`);
      });
    }, PRESENCE_DEBOUNCE_MS);
  }

  private async sendPresence(force: boolean): Promise<void> {
    if (!this.accessToken) return;
    if (!this.state.settings.sharePresence) {
      await this.withdrawPresence();
      return;
    }
    const report = presenceReport(this.state.status, this.selectedServer());
    const fresh = Date.now() - this.sentPresenceAt < PRESENCE_REFRESH_MS - 10_000;
    if (!force && fresh && samePresence(this.sentPresence, report)) return;
    const result = await this.withSession((token) => this.api.reportPresence(token, report));
    this.sentPresence = result.shared ? report : null;
    this.sentPresenceAt = Date.now();
  }

  /** Best effort: the server forgets this computer on its own three minutes later. */
  private async withdrawPresence(): Promise<void> {
    const token = this.accessToken;
    if (!token || !this.sentPresence) return;
    this.sentPresence = null;
    await this.api.clearPresence(token).catch(() => {});
  }

  private stopPresence(): void {
    if (this.presenceTimer) clearTimeout(this.presenceTimer);
    this.presenceTimer = null;
    if (this.presenceKeepalive) clearInterval(this.presenceKeepalive);
    this.presenceKeepalive = null;
  }

  private refreshRemoteConfig(): Promise<void> {
    this.remoteRefresh ??= (async () => {
      const outside = !this.tunnelActive();
      const fetched = await this.remoteConfig.fetch();
      if (!fetched) return;
      this.remoteStored = mergeFetched(this.remoteStored, fetched, Date.now(), !outside || this.tunnelActive());
      await this.remoteConfigStore.save(this.remoteStored);
      await this.updateAnnouncements();
      void this.checkMaintenance();
    })().catch((error: unknown) => {
      this.addLog(`Конфигурация приложения: ${messageOf(error)}`);
    }).finally(() => {
      this.remoteRefresh = null;
    });
    return this.remoteRefresh;
  }

  private tunnelActive(): boolean {
    return this.xray.isRunning() || this.killSwitch.isActive() ||
      ["connecting", "connected", "reconnecting", "disconnecting"].includes(this.state.status);
  }

  private announcements(): AppAnnouncement[] {
    return visibleAnnouncements(this.remoteStored?.config ?? null, this.notices.dismissed(), Date.now())
      .map((item) => item.linkUrl && !isAllowedExternalUrl(item.linkUrl) ? { ...item, linkUrl: null } : item);
  }

  private async updateAnnouncements(): Promise<void> {
    const visible = this.announcements();
    if (JSON.stringify(visible) !== JSON.stringify(this.state.announcements)) this.patch({ announcements: visible });
    const notified = this.notices.notified();
    const fresh = visible.filter((item) => item.notify && !notified.has(`announcement:${item.id}`));
    if (!fresh.length) return;
    await this.notices.remember(fresh.map((item) => `announcement:${item.id}`));
    for (const item of fresh) this.emit("notify", { title: item.title, body: item.body, tab: "home" });
  }

  private async checkExpiry(): Promise<void> {
    // Signed in, the account's reminders before the end come from the notification center.
    const due = expiryNotices(this.state.account?.subscriptions ?? [], this.notices.notified(), Date.now())
      .filter((item) => !this.accessToken || item.milestone === "expired");
    if (!due.length) return;
    await this.notices.remember(due.map((item) => item.key));
    for (const item of due) this.emit("notify", item.notice);
  }

  private async loadSyncState(): Promise<void> {
    const raw = await this.loadString("settings_sync");
    if (!raw) return;
    try {
      const value: unknown = JSON.parse(raw);
      const record = typeof value === "object" && value !== null ? value as Record<string, unknown> : {};
      const revision = record.revision;
      this.settingsRevision = typeof revision === "number" && Number.isSafeInteger(revision) && revision >= 0 ? revision : 0;
      this.pendingSync = parsePending(record.pending);
      this.favoritesJoined = record.favoritesJoined === true;
      this.favoriteReconciledLocal = new Set(Array.isArray(record.favoriteLocal)
        ? record.favoriteLocal.filter((id): id is string => typeof id === "string").slice(0, 200)
        : []);
    } catch {
      await this.secureStore.remove("settings_sync");
    }
  }

  private async saveSyncState(): Promise<void> {
    await this.secureStore.put("settings_sync", Buffer.from(JSON.stringify({
      revision: this.settingsRevision,
      pending: this.pendingSync,
      favoritesJoined: this.favoritesJoined,
      favoriteLocal: [...this.favoriteReconciledLocal],
    })));
  }

  private async recordSyncedChanges(previous: AppSettings, next: AppSettings): Promise<void> {
    if (previous.syncSettings !== next.syncSettings) {
      // Turning sync on joins the account's settings; turning it off forgets unsent edits.
      this.settingsRevision = 0;
      this.pendingSync = {};
      this.favoritesJoined = false;
      await this.saveSyncState();
      this.patch({ settingsSyncedAt: null });
      if (next.syncSettings) void this.syncSettingsNow();
      return;
    }
    if (!next.syncSettings) return;
    const changes = syncedChanges(previous, next);
    // Until the first exchange joins them, favourites are not edits of the account's list.
    if (!this.favoritesJoined) delete changes.favoriteNodes;
    if (!Object.keys(changes).length) return;
    this.pendingSync = { ...this.pendingSync, ...changes };
    await this.saveSyncState();
    if (this.settingsPushTimer) clearTimeout(this.settingsPushTimer);
    this.settingsPushTimer = setTimeout(() => {
      this.settingsPushTimer = null;
      void this.syncSettingsNow();
    }, SETTINGS_PUSH_DELAY_MS);
  }

  /** One exchange with the account at a time; failures wait for the next attempt. */
  private syncSettingsNow(): Promise<void> {
    this.settingsSyncChain = this.settingsSyncChain
      .then(() => this.exchangeSettings())
      .catch((error: unknown) => this.addLog(`Синхронизация настроек: ${messageOf(error)}`));
    return this.settingsSyncChain;
  }

  private async exchangeSettings(): Promise<void> {
    if (!this.state.settings.syncSettings || !this.accessToken) return;
    const sent = { ...this.pendingSync };
    let document = parseSettingsDocument(Object.keys(sent).length
      ? await this.withSession((token) => this.api.updateSettings(token, sent))
      : await this.withSession((token) => this.api.settings(token)));
    if (document?.revision === 0) {
      // Nothing saved for this account yet: this computer's settings become the shared ones.
      const seed = portableSettings(this.state.settings);
      document = parseSettingsDocument(await this.withSession((token) => this.api.updateSettings(token, seed)));
    }
    if (!document) throw new Error("Сервер вернул некорректные настройки");
    this.pendingSync = withoutConfirmed(this.pendingSync, sent);
    if (!this.favoritesJoined) await this.joinFavorites(document.settings.favoriteNodes ?? undefined);
    this.settingsRevision = document.revision;
    await this.saveSyncState();
    this.lastSettingsSyncAt = Date.now();
    if (!this.state.settings.syncSettings) return;
    const patch = remotePatch(this.state.settings, document.settings, this.pendingSync);
    if (Object.keys(patch).length) {
      this.addLog(`Настройки синхронизированы с аккаунтом: ${Object.keys(patch).join(", ")}`);
      await this.updateSettings(patch, "sync");
    }
    this.patch({ settingsSyncedAt: Date.now() });
    if (Object.keys(this.pendingSync).length) this.schedulePushIfIdle();
  }

  /**
   * The first exchange that includes this computer's favourites keeps those of
   * both sides; before this computer has a list, the account's becomes its own.
   */
  private async joinFavorites(theirs: string | undefined): Promise<void> {
    const mine = this.state.settings.favoriteNodes;
    if (mine === null) {
      if (theirs !== undefined) await this.updateSettings({ favoriteNodes: theirs }, "sync");
      return;
    }
    const joined = theirs === undefined ? mine : unionNodeLists(mine, theirs);
    if (joined !== mine) await this.updateSettings({ favoriteNodes: joined }, "sync");
    if (joined !== theirs) this.pendingSync = { ...this.pendingSync, favoriteNodes: joined };
    this.favoritesJoined = true;
    await this.saveSyncState();
  }

  private schedulePushIfIdle(): void {
    if (this.settingsPushTimer) return;
    this.settingsPushTimer = setTimeout(() => {
      this.settingsPushTimer = null;
      void this.syncSettingsNow();
    }, SETTINGS_PUSH_DELAY_MS);
  }

  /** Brings this computer's favourites and the account's node list together (favoriteNodes.ts). */
  private async reconcileFavorites(): Promise<void> {
    if (this.reconcilingFavorites || !this.state.servers.length) return;
    this.reconcilingFavorites = true;
    try {
      const settings = this.state.settings;
      const result = reconcileFavorites(
        { nodes: parseNodeList(settings.favoriteNodes), reconciledLocal: this.favoriteReconciledLocal },
        new Set(settings.favoriteServerIds),
        serversByNode(this.state.servers),
      );
      const nodes = canonicalNodeList(result.nodes);
      const ids = [...result.local];
      this.favoriteReconciledLocal = result.local;
      await this.saveSyncState();
      const sameIds = ids.length === settings.favoriteServerIds.length && settings.favoriteServerIds.every((id) => result.local.has(id));
      if (nodes === settings.favoriteNodes && sameIds) return;
      await this.updateSettings({ favoriteServerIds: ids, favoriteNodes: nodes });
    } finally {
      this.reconcilingFavorites = false;
    }
  }

  private async loadIdentity(): Promise<DeviceIdentity> {
    const raw = await this.secureStore.get("device_identity");
    if (raw) {
      try {
        return DeviceIdentity.restore(JSON.parse(raw.toString("utf8")) as SerializedIdentity);
      } finally {
        raw.fill(0);
      }
    }
    const identity = DeviceIdentity.create();
    await this.secureStore.put("device_identity", Buffer.from(JSON.stringify(identity.serialize())));
    return identity;
  }

  private async loadProfile(): Promise<PreparedTunnelProfile | null> {
    const raw = await this.secureStore.get("tunnel_profile");
    if (!raw) return null;
    try {
      const value = JSON.parse(raw.toString("utf8")) as PreparedTunnelProfile;
      return Array.isArray(value.servers) && typeof value.subscriptionId === "string" ? value : null;
    } catch {
      await this.secureStore.remove("tunnel_profile");
      return null;
    } finally {
      raw.fill(0);
    }
  }

  private async loadSettings(): Promise<AppSettings> {
    const raw = await this.secureStore.get("settings");
    if (!raw) return DEFAULT_SETTINGS;
    try {
      const persisted = JSON.parse(raw.toString("utf8")) as PersistedSettings;
      const migrated = persisted.settingsSchemaVersion === SETTINGS_SCHEMA_VERSION || persisted.settingsSchemaVersion === 2
        ? persisted
        : { ...persisted, routingMode: "global" as const };
      const settings = validateSettings({ ...DEFAULT_SETTINGS, ...migrated });
      if (persisted.settingsSchemaVersion !== SETTINGS_SCHEMA_VERSION) {
        await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(settings))));
      }
      return settings;
    } catch {
      return DEFAULT_SETTINGS;
    } finally {
      raw.fill(0);
    }
  }

  private async loadString(name: string): Promise<string | null> {
    const raw = await this.secureStore.get(name);
    if (!raw) return null;
    try {
      return raw.toString("utf8");
    } finally {
      raw.fill(0);
    }
  }

  private async clearLocalSession(statusDetail: string | null): Promise<void> {
    this.cancelGameProbes();
    this.gameValidatedAt = 0;
    this.updateGame({ available: false, routes: [], quality: {}, activeRouteId: null, recommendedRouteId: null });
    this.liveEvents?.stop();
    this.homeRoadAvailable = false;
    this.lastHomeRoadAt = 0;
    await this.homeRoad.stop();
    this.replyKeys.clear();
    this.remoteWatchedUntil = 0;
    if (this.approvalsTimer) clearTimeout(this.approvalsTimer);
    this.approvalsTimer = null;
    this.sentPresence = null;
    this.accessToken = null;
    this.profile = null;
    this.lastConfig = null;
    this.lastTuic = undefined;
    this.settingsRevision = 0;
    this.pendingSync = {};
    // The next account's list takes over; favourites starred here join it as edits.
    this.favoritesJoined = false;
    this.favoriteReconciledLocal = new Set();
    if (this.state.settings.favoriteNodes !== null) {
      this.state.settings = { ...this.state.settings, favoriteNodes: null };
      await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(this.state.settings))));
    }
    if (this.settingsPushTimer) clearTimeout(this.settingsPushTimer);
    this.settingsPushTimer = null;
    // The next account's exit gets a key of its own.
    this.homeRoadKeyPair = null;
    await Promise.all([
      this.secureStore.remove("access_token"),
      this.secureStore.remove("home_road_key"),
      this.secureStore.remove("tunnel_profile"),
      this.secureStore.remove("selected_server"),
      this.secureStore.remove("settings_sync"),
    ]);
    this.patch({
      settingsSyncedAt: null,
      pendingApprovals: [],
      remote: { devices: [], commands: [], notes: {}, loadedAt: null },
      loginPending: false,
      sessionAvailable: false,
      account: null,
      servers: [],
      serverLatencies: {},
      selectedServerId: null,
      selectedSubscriptionId: null,
      statusDetail,
      homeRoad: null,
    });
  }

  private handleCoreLog(line: string): void {
    this.addLog(line);
    const code = classifyCoreLogLine(line);
    if (!code) return;
    if (CORE_FAILURE_CODES.has(code)) this.coreFailure = code;
    this.telemetry.record((session) => session.coreLog(code));
  }

  private handleXrayExit(code: number | null, expected: boolean): void {
    if (!expected) this.telemetry.record((session) => session.coreExit(code, false));
    // Startup/recovery failures are handled by the operation awaiting start().
    if (expected || this.state.status !== "connected" || !this.lastConfig) return;
    this.recoveryReason = "core_exited";
    this.beginTunnelRecovery(`Туннель остановлен (код ${code ?? "?"}). Восстановление…`);
  }

  /**
   * Some networks drop UDP, which TUIC and Hysteria2 need. With a manually
   * chosen server the app keeps the user's choice and only suggests another.
   */
  private suggestServerOutsideUdp(): void {
    const server = this.selectedServer();
    if (!server || this.state.settings.automaticServer || this.reconnectAttempts < 2) return;
    if (!UDP_PROTOCOLS.has(protocolOf(server))) return;
    const alternative = this.bestServer(this.state.servers.filter((candidate) => !UDP_PROTOCOLS.has(protocolOf(candidate))));
    this.patch({
      statusDetail: `${server.name} не отвечает: похоже, эта сеть блокирует UDP.${alternative ? ` Попробуйте сервер ${alternative.name}.` : " Попробуйте другой сервер."}`,
    });
  }

  private beginTunnelRecovery(detail: string, cause: AttemptCause | null = null): void {
    this.cancelGameProbes();
    this.recoveryCause = cause;
    // In-flight probes belong to the failed tunnel, not its replacement.
    this.connectionGeneration += 1;
    if (this.state.selectedServerId) this.failedServerIds.add(this.state.selectedServerId);
    this.patch({ status: "reconnecting", statusDetail: detail });
    this.scheduleTunnelRestore(1_000);
  }

  private scheduleTunnelRestore(delayMs: number): void {
    if (this.reconnectTimer) return;
    const generation = this.connectionGeneration;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.runTunnelOperation(async () => {
        if (generation !== this.connectionGeneration || this.state.status !== "reconnecting" || !this.lastConfig) return;
        let progress: AttemptProgress | null = null;
        try {
          // WFP retains the fail-closed boundary while the TUN is absent.
          // Starting a blackhole core here races Wintun teardown and resets TCP.
          await this.xray.stop();
          this.assertCurrentConnection(generation);
          if (!this.state.settings.autoReconnect) {
            this.patch({ status: "error", statusDetail: "VPN-соединение потеряно. Подключитесь снова или нажмите Отключить, чтобы снять блокировку.", sessionStartedAt: null });
            this.telemetry.record((session) => session.recovery(this.state.settings.killSwitch ? "lockdown" : "gave_up"));
            void this.telemetry.finish("error", this.recoveryReason === "core_exited" ? "core_exited" : "gave_up");
            return;
          }
          const previousServerId = this.state.selectedServerId;
          if (this.state.settings.automaticServer && this.profile) {
            await this.pingServers();
            this.assertCurrentConnection(generation);
            let candidates = this.state.servers.filter((server) => !this.failedServerIds.has(server.id));
            if (!candidates.length) {
              this.failedServerIds.clear();
              candidates = this.state.servers;
            }
            const reachable = candidates.filter((server) => this.state.serverLatencies[server.id] != null);
            const server = this.bestServer(reachable.length ? reachable : candidates);
            if (server) {
              this.patch({ selectedServerId: server.id });
              await this.secureStore.put("selected_server", Buffer.from(server.id));
              this.lastConfig = buildXrayConfig(this.profile, server, this.state.settings, this.gamePassword);
              this.lastTuic = server.tuic;
            }
          }
          this.assertCurrentConnection(generation);
          const failover = this.state.selectedServerId !== previousServerId;
          this.telemetry.record((session) => session.recovery(failover ? "failover" : "reconnect_same"));
          const server = this.selectedServer();
          progress = server ? this.recordAttempt(server, failover ? "failover" : this.recoveryCause ?? "reconnect") : null;
          if (this.state.settings.killSwitch) await this.killSwitch.enable();
          if (this.state.settings.preventDnsLeaks) await this.dnsLeakProtection.enable();
          progress?.reach("core", "core_start_failed");
          await this.startXray(this.lastConfig, generation);
          this.recordNetwork();
          progress?.reach("verify", "timeout");
          await this.verifyTunnelReadiness(generation, (codes) => progress?.reach("verify", codes[0] ?? "other"));
          this.assertCurrentConnection(generation);
          this.reconnectAttempts = 0;
          this.tunnelHealthFailures = 0;
          this.failedServerIds.clear();
          this.recoveryCause = null;
          this.patch({ status: "connected", statusDetail: `Защищено через ${this.selectedServer()?.name ?? "VPN"}` });
          this.recordConnected();
        } catch (error) {
          try {
            await this.xray.stop();
          } catch (stopError) {
            this.addLog(`Остановка туннеля: ${messageOf(stopError)}`);
          }
          if (generation !== this.connectionGeneration) return;
          progress?.fail();
          if (this.state.selectedServerId) this.failedServerIds.add(this.state.selectedServerId);
          this.addLog(`Переподключение: ${messageOf(error)}`);
          this.scheduleTunnelRestore(Math.min(30_000, 1_000 * 2 ** Math.min(++this.reconnectAttempts, 5)));
          this.suggestServerOutsideUdp();
        }
      }).catch((error: unknown) => this.addLog(`Восстановление туннеля: ${messageOf(error)}`));
    }, delayMs);
  }

  private async verifyTunnelHealth(immediate = false, cause: AttemptCause | null = null): Promise<void> {
    if (this.tunnelHealthCheckRunning || this.state.status !== "connected") return;
    const generation = this.connectionGeneration;
    this.tunnelHealthCheckRunning = true;
    try {
      let codes = ["no_vpn_network"];
      const healthy = await this.xray.isHealthy() && await isTunnelHealthy({ onFailure: (failures) => { codes = failures; } });
      if (generation !== this.connectionGeneration || this.state.status !== "connected") return;
      this.tunnelHealthFailures = healthy ? 0 : this.tunnelHealthFailures + 1;
      this.telemetry.record((session) => {
        if (healthy) session.probeSucceeded();
        else session.probeFailed(codes);
      });
      if (!healthy && (immediate || this.tunnelHealthFailures >= 3)) {
        this.recoveryReason = "probe";
        this.beginTunnelRecovery("VPN-сервер перестал передавать трафик. Восстановление…", cause);
      }
    } catch (error) {
      this.addLog(`Проверка туннеля: ${messageOf(error)}`);
    } finally {
      this.tunnelHealthCheckRunning = false;
    }
  }

  private async verifyTunnelReadiness(generation: number, onFailure?: (codes: string[]) => void): Promise<void> {
    const healthy = await isTunnelHealthy({
      startup: true,
      shouldContinue: () => generation === this.connectionGeneration && this.xray.isRunning(),
      onFailure,
    });
    this.assertCurrentConnection(generation);
    if (!healthy) throw new Error("Не удалось подтвердить доступ в интернет через VPN. Повторите подключение или выберите другой сервер.");
  }

  private runTunnelOperation(operation: () => Promise<void>): Promise<void> {
    const pending = this.tunnelOperation.then(operation);
    this.tunnelOperation = pending.catch(() => {});
    return pending;
  }

  private cancelTunnelRecovery(): void {
    this.cancelGameProbes();
    this.recoveryCause = null;
    this.connectionGeneration += 1;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.tunnelHealthFailures = 0;
    this.failedServerIds.clear();
  }

  private assertCurrentConnection(generation: number): void {
    if (generation !== this.connectionGeneration) throw new Error("Подключение отменено");
  }

  private handleTrafficStats(downloadBytes: number, uploadBytes: number): void {
    if (this.state.settings.gameEnabled && this.profile?.subscriptionExpiresAt
      && !(Date.parse(this.profile.subscriptionExpiresAt) > Date.now()) && !this.enforcingGameExpiry) {
      this.enforcingGameExpiry = true;
      this.updateGame({ available: false, message: "Срок игрового доступа истёк. Game отключается." });
      void this.updateSettings({ gameEnabled: false }, "sync").catch(async () => {
        await this.xray.stop().catch(() => {});
        this.patch({ status: "error", statusDetail: "Игровой доступ истёк. Обновите подписку и подключите VPN снова." });
      }).finally(() => { this.enforcingGameExpiry = false; });
    }
    if (this.state.settings.gameEnabled) {
      const runtime = this.xray.gameRuntimeSnapshot;
      const routeQualities = this.xray.gameRouteQualities;
      const quality = Object.fromEntries((this.profile?.game?.servers ?? []).flatMap((server, index) => {
        const measured = routeQualities?.[index]; return measured ? [[server.id, measured]] : [];
      }));
      if (this.pendingGameProfile && !this.applyingPendingGameProfile && !this.state.busy
        && (runtime?.activeFlowCount ?? 0) === 0 && !runtime?.currentMatch && this.xray.pauseNewGameFlowsIfIdle()) {
        const pending = this.pendingGameProfile; this.pendingGameProfile = null;
        this.applyingPendingGameProfile = true;
        void this.applyTunnelProfile(pending).catch(() => {
          this.xray.resumeNewGameFlows();
          this.updateGame({ message: "Не удалось применить обновлённый список игровых узлов. Переподключите VPN." });
        }).finally(() => { this.applyingPendingGameProfile = false; });
      }
      this.updateGame({ multipath: this.xray.gameMultipathStats, runtime: runtime ?? null, quality });
      void this.checkPlayingGames();
      if (runtime?.currentMatch && runtime.selectedExitId) {
        const gameId = runtime.gameId ?? this.currentGameId;
        const bestExitId = runtime.shadowAlternative?.nodeId ?? runtime.selectedExitId;
        const comparison = runtime.exits.find((exit) => exit.nodeId === bestExitId);
        const key = `${gameId}:${runtime.currentMatch.address}:${bestExitId}`;
        if (comparison && comparison.confidence !== "access" && comparison.confidence !== "unavailable" && key !== this.gameLastHistoryKey) {
          this.gameLastHistoryKey = key;
          void this.gameHistory.record(gameId, runtime.currentMatch.address, runtime.currentMatch.region, bestExitId).catch(() => {});
        }
      }
      const report = runtime?.matchReport;
      const region = runtime?.lastMatch?.region;
      if (app.isPackaged && this.state.settings.gameRegionTelemetry === true && report && report.endedAt > this.gameLastRegionReportAt
        && region && /^[A-Z]{2}$/.test(region)) {
        this.gameLastRegionReportAt = report.endedAt;
        void this.gameRegionTelemetry.sendGameRegions([{ region, matches: 1 }]);
      }
    }
    if (downloadBytes < this.lastRawDownload) this.trafficDownloadOffset += this.lastRawDownload;
    if (uploadBytes < this.lastRawUpload) this.trafficUploadOffset += this.lastRawUpload;
    this.lastRawDownload = downloadBytes;
    this.lastRawUpload = uploadBytes;
    const totalDownload = this.trafficDownloadOffset + downloadBytes;
    const totalUpload = this.trafficUploadOffset + uploadBytes;
    this.idleMeter.record(totalDownload + totalUpload, Date.now());
    if (totalDownload !== this.state.downloadBytes || totalUpload !== this.state.uploadBytes) {
      this.patch({ downloadBytes: totalDownload, uploadBytes: totalUpload });
    }
  }

  private async startXray(config: Record<string, unknown>, generation: number): Promise<void> {
    this.assertCurrentConnection(generation);
    const gameTuic = this.state.settings.gameEnabled && this.profile?.game?.enabled
      ? this.profile.game.servers.flatMap((server, index) => server.tuic ? [{ tag: gameTag(index), endpoint: server.tuic }] : []) : [];
    await this.xray.start(config, this.lastTuic, gameTuic);
    try {
      this.assertCurrentConnection(generation);
      await this.killSwitch.allowTunnel();
      this.assertCurrentConnection(generation);
      if (this.state.settings.gameEnabled) {
        this.cancelGameProbes();
        this.assertCurrentConnection(generation);
        if (this.gamePassword) {
          const quality = this.state.game?.quality ?? {};
          const candidates = (this.profile?.game?.servers ?? []).map((server, index) => ({ server, index }))
            .filter(({ server }) => ["hysteria", "tuic", "vless"].includes(String(server.outbound.protocol)))
            .sort((a, b) => (quality[a.server.id]?.latencyMs ?? Infinity) - (quality[b.server.id]?.latencyMs ?? Infinity))
            .map(({ server, index }) => ({ index, port: GAME_PROBE_PORT + index, ...(server.nodeId ? { nodeId: server.nodeId } : {}) }));
          try {
            const ids = this.state.settings.gameIds ?? [];
            const gameId = ids.length === 1 && !this.state.settings.gameProcesses?.length ? ids[0]! : "custom";
            this.currentGameId = gameId;
            const preference = this.state.settings.gameRouteId;
            const preferredExitId = this.profile?.game?.servers.find((server) => server.id === preference)?.nodeId ?? preference ?? null;
            const source = physicalGameSourceAddress(this.xray.outboundInterfaceName);
            await this.xray.connectGameMultipath(candidates, this.gamePassword, {
              nodes: this.profile?.game?.nodes ?? [], preferredExitId, protection: this.state.settings.gameProtection !== false,
              gameId, exitScope: gameExitScope(this.state.settings), history: this.gameHistory.snapshot(gameId),
              directSocksPort: GAME_DIRECT_PORT,
              ...(source ? { measureDirect: async (targets, signal): Promise<ProbeMeasurement[]> =>
                (await measureDirectGameTargets(targets, source, signal)).map(({ address, port, quality: measurement }) => ({
                  address, port, medianMs: measurement.latencyMs, p95Ms: measurement.p95Ms, jitterMs: measurement.jitterMs,
                  lossPercent: measurement.lossPercent, method: measurement.method === "unknown" ? "unavailable" : measurement.method === "echo" ? "icmp" : measurement.method,
                  sampleCount: measurement.samples, measuredAt: new Date(measurement.measuredAt).toISOString(),
                })) } : {}),
            });
            this.assertCurrentConnection(generation);
            const dataAbort = new AbortController();
            this.gameProbeAbort = dataAbort;
            const dataCheck = await measureGameDataRoute(GAME_DATA_PROBE_PORT, this.gamePassword,
              AbortSignal.any([dataAbort.signal, AbortSignal.timeout(12_000)]), 1200).finally(() => {
                if (this.gameProbeAbort === dataAbort) this.gameProbeAbort = null;
              });
            this.assertCurrentConnection(generation);
            if (dataCheck.latencyMs === null || dataCheck.lossPercent > 25) throw new Error("Game UDP validation failed");
            const healthy = (this.profile?.game?.servers ?? []).flatMap((server, routeIndex) => {
              const measured = this.xray.gameRouteQualities[routeIndex];
              return measured?.latencyMs != null && measured.lossPercent <= 25
                && !this.profile?.game?.nodes?.some((node) => node.nodeId === server.nodeId && node.state !== "enabled")
                ? [{ routeIndex, latencyMs: measured.latencyMs }] : [];
            }).sort((a, b) => a.latencyMs - b.latencyMs);
            const tcpPreference = preferredExitId ?? this.gameHistory.preferredExit(gameId);
            const primary = healthy.find((path) => this.profile?.game?.servers[path.routeIndex]?.nodeId === tcpPreference) ?? healthy[0];
            if (!primary) throw new Error("No Game path");
            await this.xray.selectGameRoute(primary.routeIndex);
            await this.xray.selectGameUdpRoute(null);
            this.updateGame({ activeRouteId: this.profile?.game?.servers[primary.routeIndex]?.id ?? null, phase: "ready", message: null });
          } catch {
            this.assertCurrentConnection(generation);
            // No bypass around the flow observer: otherwise an ongoing match
            // could silently move to a different exit after a later retry.
            this.updateGame({ phase: "degraded", message: "Игровой UDP не прошёл проверку. Завершите матч и переподключите VPN; обычный VPN работает." });
          }
          this.assertCurrentConnection(generation);
          this.updateGame({ multipath: this.xray.gameMultipathStats, runtime: this.xray.gameRuntimeSnapshot ?? null });
          void this.checkPlayingGames(true);
        }
      }
    } catch (error) {
      await this.xray.stop();
      throw error;
    }
  }

  private async checkPlayingGames(force = false): Promise<void> {
    if (process.platform !== "win32" || this.gameProcessCheckRunning || (!force && Date.now() - this.gameProcessCheckAt < 15_000)) return;
    this.gameProcessCheckAt = Date.now(); this.gameProcessCheckRunning = true;
    const generation = this.connectionGeneration;
    try {
      const selected = new Set(gameProcesses(this.state.settings).map((name) => name.toLowerCase()));
      const processes = await listWindowsProcesses();
      if (generation !== this.connectionGeneration || !this.state.settings.gameEnabled) return;
      const playing = processes.some((entry) => entry.running && selected.has(entry.name.toLowerCase()));
      const runningNames = new Set(processes.filter((entry) => entry.running).map((entry) => entry.name.toLowerCase()));
      const activeGames = GAMES.filter((game) => this.state.settings.gameIds?.includes(game.id)
        && game.processes.some((name) => runningNames.has(name.toLowerCase())));
      const customRunning = this.state.settings.gameProcesses?.some((name) => runningNames.has(name.toLowerCase()));
      const gameId = activeGames.length === 1 && !customRunning ? activeGames[0]!.id : "custom";
      if (gameId !== this.currentGameId) {
        this.currentGameId = gameId;
        this.xray.updateGameOptions({ gameId, history: this.gameHistory.snapshot(gameId) });
      }
      this.xray.setGamePlaying(playing);
      if (playing && !this.gamePlaying) void this.measureGameRoutes(true);
      this.gamePlaying = playing;
    } catch { /* Process list may be unavailable; traffic observation still works. */ }
    finally { this.gameProcessCheckRunning = false; }
  }

  private startKillSwitchHealthMonitor(): void {
    if (this.killSwitchHealthTimer) return;
    this.killSwitchHealthTimer = setInterval(() => void this.verifyKillSwitchBoundary(), 2_000);
  }

  private stopKillSwitchHealthMonitor(): void {
    if (this.killSwitchHealthTimer) clearInterval(this.killSwitchHealthTimer);
    this.killSwitchHealthTimer = null;
  }

  private async verifyKillSwitchBoundary(): Promise<void> {
    if (this.killSwitchHealthCheckRunning || !this.killSwitchProtectionRequired() || !this.killSwitch.isActive()) return;
    this.killSwitchHealthCheckRunning = true;
    try {
      const restored = await this.killSwitch.ensureActive(() => this.killSwitchProtectionRequired());
      if (!restored) return;
      if (!this.killSwitchProtectionRequired()) {
        await this.killSwitch.disable();
        return;
      }
      if (this.xray.isRunning()) await this.killSwitch.allowTunnel();
      this.addLog("Kill Switch: системная защита восстановлена");
    } catch (error) {
      this.addLog(`Проверка Kill Switch: ${messageOf(error)}`);
    } finally {
      this.killSwitchHealthCheckRunning = false;
    }
  }

  private killSwitchProtectionRequired(): boolean {
    return this.killSwitchHealthTimer !== null
      && this.state.settings.killSwitch
      && ["connecting", "connected", "reconnecting", "error"].includes(this.state.status);
  }

  private async stopTunnelForReplacement(): Promise<void> {
    this.cancelTunnelRecovery();
    this.nextAttemptCause = "server_switch";
    this.patch({ status: "reconnecting", statusDetail: "Применение изменений соединения…" });
    await this.runTunnelOperation(() => this.xray.stop());
    this.lastConfig = null;
    this.lastTuic = undefined;
  }

  private connectionRequested(): boolean {
    return this.xray.isRunning() || ["connecting", "connected", "reconnecting"].includes(this.state.status)
      || (this.state.status === "error" && this.killSwitch.isActive());
  }

  private resetTrafficStats(): void {
    this.idleMeter.reset();
    this.trafficDownloadOffset = 0;
    this.trafficUploadOffset = 0;
    this.lastRawDownload = 0;
    this.lastRawUpload = 0;
  }

  private selectedServer(): TunnelServer | null {
    return this.state.servers.find((item) => item.id === this.state.selectedServerId)
      ?? this.bestServer(this.state.servers)
      ?? null;
  }

  private maintenanceWindows() {
    return this.remoteStored?.config.maintenance ?? [];
  }

  /** Servers the list marks as under maintenance, with the end of the work. */
  private serverMaintenance(now: number): Record<string, number> {
    const marked: Record<string, number> = {};
    for (const server of this.state.servers) {
      const window = maintenanceFor(this.maintenanceWindows(), nodeIdForServer(server), now);
      if (window) marked[server.id] = window.endsAt;
    }
    return marked;
  }

  /**
   * Moves off a server before its maintenance starts: as soon as the connection
   * is idle, and two minutes before the start at the latest. docs/app-platform.md.
   */
  private async checkMaintenance(): Promise<void> {
    const now = Date.now();
    const marked = this.serverMaintenance(now);
    if (JSON.stringify(marked) !== JSON.stringify(this.state.serverMaintenance)) this.patch({ serverMaintenance: marked });
    if (this.maintenanceMoving || this.state.busy || this.state.status !== "connected" || !this.xray.isRunning()) return;
    const current = this.selectedServer();
    if (!current) return;
    const move = maintenanceMove(maintenanceFor(this.maintenanceWindows(), nodeIdForServer(current), now), now);
    if (move === "stay" || (move === "when-idle" && !this.idleMeter.idle(now))) return;
    const target = this.bestServer(this.state.servers.filter((item) => item.id !== current.id));
    if (!target || maintenanceFor(this.maintenanceWindows(), nodeIdForServer(target), now)) return;
    this.maintenanceMoving = true;
    try {
      this.addLog(`Обслуживание сервера ${current.name}: переключение на ${target.name}`);
      await this.selectServer(target.id);
      this.emit("notify", {
        title: `Сервер «${current.name}» уходит на обслуживание`,
        body: `Levik VPN заранее переключился на «${target.name}».`,
        tab: "home",
      });
    } catch (error) {
      this.addLog(`Переключение перед обслуживанием: ${messageOf(error)}`);
    } finally {
      this.maintenanceMoving = false;
    }
  }

  private async runDiagnosis(): Promise<DiagnosisSummary> {
    const vpn = vpnPhase(this.state.status);
    // Chromium's network stack follows the system's routing and proxy, as the user's apps do.
    const viaSystem = (url: string, init: RequestInit) => net.fetch(url, init);
    const online = net.isOnline();
    const [checks, captive, raw] = await Promise.all([
      online ? checkServices(viaSystem) : Promise.resolve([]),
      online && vpn === "off" ? captivePortal(viaSystem, CAPTIVE_PROBE) : Promise.resolve(false),
      online ? this.remoteConfig.diagnose().catch(() => null) : Promise.resolve(null),
    ]);
    const server = this.selectedServer();
    const verdict = diagnosisVerdict({
      network: !online ? "none" : captive ? "captive" : "ok",
      cellular: false,
      vpn,
      serverCountry: server?.countryCode.toUpperCase() ?? null,
      serverNodeId: server ? nodeIdForServer(server) : null,
      protocol: server ? protocolOf(server) : null,
      failingServices: checks.filter((item) => !item.ok).map((item) => item.slug),
      anyServiceWorks: checks.some((item) => item.ok),
      report: parseDiagnoseReport(raw),
      now: Date.now(),
    });
    const summary = diagnosisSummary(verdict, { networkSettings: true });
    this.lastDiagnosis = { at: Date.now(), summary };
    this.addLog(`Диагностика: ${summary.verdict}`);
    return summary;
  }

  /** To the fastest server other than the current one; connects when the VPN is off. */
  private async useBestServer(): Promise<void> {
    const current = this.selectedServer();
    await this.pingServers();
    const others = this.state.servers.filter((item) => item.id !== current?.id);
    const target = this.bestServer(others.length ? others : this.state.servers);
    if (target && target.id !== this.state.selectedServerId) await this.selectServer(target.id);
    if (!this.xray.isRunning()) await this.connect("user");
  }

  private bestServer(servers: TunnelServer[]): TunnelServer | null {
    // A home exit («🏠») is only ever the user's own choice.
    const ordinary = servers.filter((item) => !isHomeRoadServer(item.name));
    const offered = ordinary.length ? ordinary : servers;
    // TUIC is an explicit per-server choice; automatic selection keeps Xray protocols.
    const xrayServers = offered.filter((item) => !item.tuic);
    const pool = xrayServers.length ? xrayServers : offered;
    const nonRussian = pool.filter((item) => item.countryCode.toUpperCase() !== "RU");
    // Servers going into maintenance are left out while others remain.
    const eligible = avoidMaintenance(nonRussian.length ? nonRussian : pool, this.maintenanceWindows(), nodeIdForServer, Date.now());
    // Protocols that work on the user's operator first, unless none of them answers.
    const advised = adviceCandidates(eligible, currentAdvice(this.remoteStored, Date.now()), protocolOf);
    const measured = (items: TunnelServer[]) => items.some((item) => this.state.serverLatencies[item.id] != null);
    const candidates = measured(advised) || !measured(eligible) ? advised : eligible;
    return candidates.reduce<TunnelServer | null>((best, candidate) => {
      if (!best) return candidate;
      const bestLatency = this.state.serverLatencies[best.id];
      const candidateLatency = this.state.serverLatencies[candidate.id];
      if (candidateLatency !== null && candidateLatency !== undefined && (bestLatency === null || bestLatency === undefined || candidateLatency < bestLatency)) {
        return candidate;
      }
      return best;
    }, null);
  }

  private requireToken(): string {
    if (!this.accessToken) throw new Error("Войдите в Levik Account");
    return this.accessToken;
  }

  private async withSession<Result>(operation: (accessToken: string) => Promise<Result>): Promise<Result> {
    try {
      return await operation(this.requireToken());
    } catch (error) {
      if (isAuthenticationRejected(error)) {
        try {
          await this.stopConnection("error", "auth_deadline");
        } catch (cleanupError) {
          this.addLog(`Завершение истёкшей сессии: ${messageOf(cleanupError)}`);
        }
        await this.clearLocalSession("Сессия истекла. Войдите снова.");
      }
      throw error;
    }
  }

  /** Records an attempt; the returned progress names the step that failed. */
  private recordAttempt(server: TunnelServer, cause: AttemptCause): AttemptProgress {
    this.telemetry.record((session) => session.attempt(server.name, protocolOf(server), cause));
    this.coreFailure = null;
    let stage: AttemptStage = "tun";
    let code = "helper_failed";
    // Why the core could not start or died, when it said so in its output.
    const detailed = () => stage !== "profile" && stage !== "tun" && this.coreFailure ? `${code}:${this.coreFailure}` : code;
    return {
      get code() { return detailed(); },
      reach: (nextStage, nextCode) => { stage = nextStage; code = nextCode; },
      fail: () => this.telemetry.record((session) => session.attemptFailed(stage, detailed())),
    };
  }

  private recordNetwork(): void {
    const type = networkTypeOfInterface(this.xray.outboundInterfaceName ?? null);
    this.telemetry.record((session) => session.setNetwork(type));
  }

  private recordConnected(): void {
    this.telemetry.record((session) => session.connected());
    // Reports leave through the working tunnel, after it has settled.
    this.telemetry.flushSoon();
  }

  private addLog(line: string): void {
    const cleaned = line.replace(/[\r\n]/g, " ").slice(0, 1_000);
    this.diskLog?.write(cleaned);
    this.state.logs = [`${new Date().toLocaleTimeString("ru-RU")}  ${cleaned}`, ...this.state.logs].slice(0, 200);
    this.emitChanged();
  }

  private patch(patch: Partial<AppSnapshot>): void {
    const statusChanged = patch.status !== undefined && patch.status !== this.state.status;
    if (patch.status && statusChanged) {
      const detail = patch.statusDetail ?? null;
      this.diskLog?.write(`Состояние: ${patch.status}${detail ? ` — ${detail}` : ""}`);
    }
    this.state = { ...this.state, ...patch };
    this.emitChanged();
    if (statusChanged) this.reportPresenceSoon();
  }

  private emitChanged(): void {
    this.emit("changed", this.snapshot());
  }

  private applyLoginItemSettings(): void {
    if (process.platform === "win32") {
      app.setLoginItemSettings?.({ openAtLogin: this.state.settings.launchAtLogin });
    }
  }
}

interface AttemptProgress {
  readonly code: string;
  reach(stage: AttemptStage, code: string): void;
  fail(): void;
}

const UDP_PROTOCOLS: ReadonlySet<string> = new Set(["tuic", "hysteria2"]);
const CORE_FAILURE_CODES: ReadonlySet<string> = new Set(["port_unavailable", "tun_failed", "core_start", "core_panic"]);

// Development runs are the developer's tests, not users' connections.
function telemetryAllowed(settings: AppSettings): boolean {
  return app.isPackaged && settings.connectionTelemetry && settings.telemetryNoticeShown;
}

function sessionSettings(settings: AppSettings): SessionSettings {
  return {
    killSwitch: settings.killSwitch,
    autoRecovery: settings.autoReconnect,
    splitTunnel: settings.splitTunnelMode !== "off" || settings.routingMode !== "global",
  };
}

/** Windows 11 still reports 10.0; its builds start at 22000. */
function windowsMajorVersion(version: string): string {
  const [major, , build] = version.split(".").map(Number);
  if (major === 10 && (build ?? 0) >= 22_000) return "11";
  return Number.isInteger(major) ? String(major) : "unknown";
}

function normalizeActivationCode(value: string): string {
  const normalized = value.normalize("NFKC").trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}$/.test(normalized)) {
    throw new Error("Введите код в формате XXXX-XXXX-XXXX-XXXX");
  }
  return normalized;
}

function serializeSettings(settings: AppSettings): AppSettings & { settingsSchemaVersion: number } {
  return { ...settings, settingsSchemaVersion: SETTINGS_SCHEMA_VERSION };
}

function mapAccount(response: MobileAccountResponse): AccountSummary {
  return {
    userLabel: response.user.userLabel,
    subscriptions: response.subscriptions.map((item) => ({
      uuid: item.uuid,
      title: item.title,
      status: item.status,
      expireAt: item.expireAt ?? null,
      traffic: item.traffic,
      devices: item.devices,
      shield: { supported: Boolean(item.shield?.supported), enabled: Boolean(item.shield?.enabled) },
      actions: { renew: Boolean(item.actions?.renew), revokeDevice: Boolean(item.actions?.revokeDevice) },
    })),
  };
}

function validateSettings(value: AppSettings): AppSettings {
  if (!(["global", "bypassRu", "blockedOnly"] as const).includes(value.routingMode)) throw new Error("Некорректный режим маршрутизации");
  if (!(["system", "dark", "light", "amoled"] as const).includes(value.theme)) throw new Error("Некорректная тема");
  if (!isIPv4(value.dnsServer)) throw new Error("Некорректный DNS-сервер");
  return {
    routingMode: value.routingMode,
    gameEnabled: value.gameEnabled === true,
    gameIds: normalizeGameIds(value.gameIds),
    gameProcesses: normalizeProcessSelection(value.gameProcesses).slice(0, 32),
    gameRouteId: typeof value.gameRouteId === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value.gameRouteId) ? value.gameRouteId : null,
    gameMultipath: value.gameMultipath === true,
    gameProtection: value.gameProtection !== false,
    gameRegionTelemetry: value.gameRegionTelemetry === true,
    automaticServer: Boolean(value.automaticServer),
    autoReconnect: Boolean(value.autoReconnect),
    killSwitch: Boolean(value.killSwitch),
    useDoh: Boolean(value.useDoh),
    dnsServer: value.dnsServer,
    theme: value.theme,
    launchAtLogin: Boolean(value.launchAtLogin),
    autoConnectOnLaunch: Boolean(value.autoConnectOnLaunch),
    closeToTray: Boolean(value.closeToTray),
    preventDnsLeaks: Boolean(value.preventDnsLeaks),
    favoriteServerIds: [...new Set(value.favoriteServerIds.filter((id) => /^[a-f0-9]{64}$/.test(id)))].slice(0, 200),
    favoriteNodes: typeof value.favoriteNodes === "string" && isCanonicalNodeList(value.favoriteNodes) ? value.favoriteNodes : null,
    antiDpiEnabled: Boolean(value.antiDpiEnabled),
    antiDpiPackets: validateAntiDpi(value.antiDpiPackets, "tlshello"),
    antiDpiLength: validateAntiDpi(value.antiDpiLength, "100-200"),
    antiDpiInterval: validateAntiDpi(value.antiDpiInterval, "10-20"),
    splitTunnelMode: (["off", "bypass", "only"] as const).includes(value.splitTunnelMode) ? value.splitTunnelMode : "off",
    splitTunnelProcesses: normalizeProcessSelection(value.splitTunnelProcesses),
    connectionTelemetry: Boolean(value.connectionTelemetry),
    telemetryNoticeShown: Boolean(value.telemetryNoticeShown),
    syncSettings: Boolean(value.syncSettings),
    // Settings saved before this field existed mean "on".
    sharePresence: value.sharePresence !== false,
    sleepAtHome: value.sleepAtHome !== false,
  };
}

function affectsTunnel(before: AppSettings, after: AppSettings): boolean {
  if (before.gameEnabled !== after.gameEnabled) return true;
  return before.routingMode !== after.routingMode || before.killSwitch !== after.killSwitch || before.useDoh !== after.useDoh || before.dnsServer !== after.dnsServer || before.preventDnsLeaks !== after.preventDnsLeaks || before.antiDpiEnabled !== after.antiDpiEnabled || before.antiDpiPackets !== after.antiDpiPackets || before.antiDpiLength !== after.antiDpiLength || before.antiDpiInterval !== after.antiDpiInterval || before.splitTunnelMode !== after.splitTunnelMode || before.splitTunnelProcesses.join("\0") !== after.splitTunnelProcesses.join("\0");
}

function hasMeasuredLatency(latencies: Record<string, number | null>): boolean {
  return Object.values(latencies).some((latency) => latency !== null);
}

function sameServers(left: TunnelServer[], right: TunnelServer[]): boolean {
  return left.length === right.length && left.every((server, index) => server.id === right[index]?.id);
}

function validateAntiDpi(value: string, fallback: string): string {
  return /^[A-Za-z0-9,-]{1,32}$/.test(value) ? value : fallback;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "Неизвестная ошибка";
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

/** A diagnosis older than this says little about the problem in the report. */
const DIAGNOSIS_REPORT_MS = 30 * 60_000;
/** The check Windows itself uses to find a sign-in page. */
const CAPTIVE_PROBE = { url: "http://www.msftconnecttest.com/connecttest.txt", expect: "Microsoft Connect Test" };
