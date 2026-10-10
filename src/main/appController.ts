import { app } from "electron";
import { EventEmitter } from "node:events";
import { platform, release } from "node:os";
import { isIPv4 } from "node:net";
import { join } from "node:path";
import type {
  AccountSummary,
  AppSettings,
  AppSnapshot,
  LoginChallenge,
  TunnelServer,
  TuicEndpoint,
} from "../shared/contracts";
import { isAuthenticationRejected, MobileApiClient } from "./api/mobileApiClient";
import type { AuthChallengeResponse, MobileAccountResponse } from "./api/models";
import { DeviceIdentity } from "./security/deviceIdentity";
import type { SerializedIdentity } from "./security/deviceIdentity";
import { RequestSigner } from "./security/requestSigner";
import { SecureStore } from "./security/secureStore";
import { decryptTunnelProfile, prepareTunnelProfile } from "./vpn/tunnelProfile";
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
import type { AttemptCause, AttemptStage, EndBy, PowerState, SessionSettings, SessionTrigger } from "./telemetry/sessionRecorder";

interface AppControllerEvents {
  changed: [snapshot: AppSnapshot];
  updateInstalling: [];
}

const DEFAULT_SETTINGS: AppSettings = {
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
  antiDpiEnabled: false,
  antiDpiPackets: "tlshello",
  antiDpiLength: "100-200",
  antiDpiInterval: "10-20",
  splitTunnelMode: "off",
  splitTunnelProcesses: [],
  connectionTelemetry: true,
  telemetryNoticeShown: false,
};

const SETTINGS_SCHEMA_VERSION = 2;

type PersistedSettings = Partial<AppSettings> & {
  settingsSchemaVersion?: number;
};

export class AppController extends EventEmitter<AppControllerEvents> {
  private readonly secureStore = new SecureStore();
  private readonly xray = new XrayManager();
  private readonly dnsLeakProtection = new DnsLeakProtection(this.secureStore);
  private readonly killSwitch = new WindowsKillSwitch(() => this.xray.executablePath(), {
    tuicExecutablePath: () => this.xray.tuicExecutablePath(),
  });
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
  private readonly failedServerIds = new Set<string>();
  private trafficDownloadOffset = 0;
  private trafficUploadOffset = 0;
  private lastRawDownload = 0;
  private lastRawUpload = 0;
  private pingPromise: Promise<void> | null = null;
  private resumePromise: Promise<void> | null = null;
  private killSwitchHealthTimer: ReturnType<typeof setInterval> | null = null;
  private killSwitchHealthCheckRunning = false;
  private readonly telemetry = new ConnectionTelemetry(join(app.getPath("userData"), "telemetry"), {
    platform: "windows",
    app: app.getVersion(),
    os: windowsMajorVersion(release()),
  });
  private diskLog: DiskLog | null = null;
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
    selectedServerId: null,
    selectedSubscriptionId: null,
    settings: DEFAULT_SETTINGS,
    sessionStartedAt: null,
    downloadBytes: 0,
    uploadBytes: 0,
    logs: [],
    busy: true,
    update: { status: "idle", version: null, progress: null, message: null },
  };

  constructor() {
    super();
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
    this.api = new MobileApiClient(
      process.env.LEVIK_API_ORIGIN ?? "https://api.leviknet.org",
      new RequestSigner(this.identity),
      app.getVersion(),
    );
    this.xray.on("log", (line) => this.handleCoreLog(line));
    this.xray.on("exit", (code, expected) => this.handleXrayExit(code, expected));
    this.xray.on("stats", (downloadBytes, uploadBytes) => this.handleTrafficStats(downloadBytes, uploadBytes));
    this.accessToken = await this.loadString("access_token");
    this.state.sessionAvailable = this.accessToken !== null;
    this.state.settings = await this.loadSettings();
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
    this.profile = await this.loadProfile();
    if (this.profile) {
      this.state.servers = this.profile.servers;
      this.state.selectedSubscriptionId = this.profile.subscriptionId;
      this.state.selectedServerId = await this.loadString("selected_server")
        ?? this.bestServer(this.profile.servers)?.id
        ?? null;
    }
    this.applyLoginItemSettings();
    this.state.busy = false;
    this.emitChanged();
    if (this.accessToken) {
      try {
        await this.refreshAccount();
      } catch (error) {
        this.addLog(`Синхронизация аккаунта: ${messageOf(error)}`);
      }
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
      const challenge = await this.api.createChallenge({
        accountActivationSupported: true,
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
      return {
        verificationUri,
        verificationCode: challenge.activationCode ?? challenge.verificationCode ?? null,
        expiresAt: challenge.expiresAt,
      };
    } finally {
      if (generation === this.loginGeneration) this.patch({ busy: false });
    }
  }

  cancelLogin(): void {
    this.loginGeneration += 1;
    this.patch({ busy: false, statusDetail: null });
  }

  async logout(): Promise<void> {
    this.loginGeneration += 1;
    await this.stopConnection("user", "user");
    const token = this.accessToken;
    if (token) {
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
    const generation = this.connectionGeneration;
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
      const config = buildXrayConfig(this.profile, server, this.state.settings);
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

  async updateSettings(patch: Partial<AppSettings>): Promise<void> {
    const previous = this.state.settings;
    const next = validateSettings({ ...previous, ...patch });
    const reconnect = this.connectionRequested() && affectsTunnel(previous, next);
    const generation = this.connectionGeneration;
    this.state.settings = next;
    await this.secureStore.put("settings", Buffer.from(JSON.stringify(serializeSettings(next))));
    this.applyLoginItemSettings();
    this.emitChanged();
    if (telemetryAllowed(previous) !== telemetryAllowed(next)) await this.telemetry.setEnabled(telemetryAllowed(next));
    this.telemetry.record((session) => session.updateSettings(sessionSettings(next)));
    if (!previous.automaticServer && next.automaticServer) void this.pingServers();
    if (previous.killSwitch && !next.killSwitch) await this.killSwitch.disable();
    if (previous.preventDnsLeaks && !next.preventDnsLeaks) await this.dnsLeakProtection.disable();
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
    let intervalSeconds = clamp(challenge.pollIntervalSeconds, 2, 10);
    const expiresAt = Date.parse(challenge.expiresAt);
    while (generation === this.loginGeneration && Date.now() < expiresAt) {
      await delay(intervalSeconds * 1_000);
      if (generation !== this.loginGeneration) return;
      try {
        const status = await this.api.pollStatus(challenge.loginToken);
        intervalSeconds = clamp(status.pollIntervalSeconds ?? intervalSeconds, 2, 10);
        if (status.state === "pending") continue;
        if (status.state !== "authenticated" || !status.accessToken) {
          this.patch({ statusDetail: status.state === "denied" ? "Вход отклонён" : "Срок входа истёк" });
          return;
        }
        if (status.accessToken.length < 32 || status.accessToken.length > 4_096) throw new Error("Некорректная сессия");
        this.accessToken = status.accessToken;
        await this.secureStore.put("access_token", Buffer.from(status.accessToken));
        this.patch({ sessionAvailable: true });
        try {
          await this.refreshAccount();
        } catch (error) {
          if (!this.accessToken) throw error;
          this.addLog(`Синхронизация аккаунта: ${messageOf(error)}`);
        }
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
      this.profile = profile;
      const selected = this.state.selectedServerId;
      const serverId = profile.servers.some((item) => item.id === selected)
        ? selected
        : this.bestServer(profile.servers)?.id ?? null;
      await this.secureStore.put("tunnel_profile", Buffer.from(JSON.stringify(profile)));
      if (serverId) await this.secureStore.put("selected_server", Buffer.from(serverId));
      this.patch({ servers: profile.servers, serverLatencies: {}, selectedServerId: serverId, selectedSubscriptionId: subscriptionId });
      void this.pingServers();
    } finally {
      plaintext.fill(0);
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
      const migrated = persisted.settingsSchemaVersion === SETTINGS_SCHEMA_VERSION
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
    this.accessToken = null;
    this.profile = null;
    this.lastConfig = null;
    this.lastTuic = undefined;
    await Promise.all([
      this.secureStore.remove("access_token"),
      this.secureStore.remove("tunnel_profile"),
      this.secureStore.remove("selected_server"),
    ]);
    this.patch({
      sessionAvailable: false,
      account: null,
      servers: [],
      serverLatencies: {},
      selectedServerId: null,
      selectedSubscriptionId: null,
      statusDetail,
    });
  }

  private handleCoreLog(line: string): void {
    this.addLog(line);
    const code = classifyCoreLogLine(line);
    if (code) this.telemetry.record((session) => session.coreLog(code));
  }

  private handleXrayExit(code: number | null, expected: boolean): void {
    if (!expected) this.telemetry.record((session) => session.coreExit(code, false));
    // Startup/recovery failures are handled by the operation awaiting start().
    if (expected || this.state.status !== "connected" || !this.lastConfig) return;
    this.recoveryReason = "core_exited";
    this.beginTunnelRecovery(`Туннель остановлен (код ${code ?? "?"}). Восстановление…`);
  }

  private beginTunnelRecovery(detail: string, cause: AttemptCause | null = null): void {
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
              this.lastConfig = buildXrayConfig(this.profile, server, this.state.settings);
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
    if (downloadBytes < this.lastRawDownload) this.trafficDownloadOffset += this.lastRawDownload;
    if (uploadBytes < this.lastRawUpload) this.trafficUploadOffset += this.lastRawUpload;
    this.lastRawDownload = downloadBytes;
    this.lastRawUpload = uploadBytes;
    const totalDownload = this.trafficDownloadOffset + downloadBytes;
    const totalUpload = this.trafficUploadOffset + uploadBytes;
    if (totalDownload !== this.state.downloadBytes || totalUpload !== this.state.uploadBytes) {
      this.patch({ downloadBytes: totalDownload, uploadBytes: totalUpload });
    }
  }

  private async startXray(config: Record<string, unknown>, generation: number): Promise<void> {
    this.assertCurrentConnection(generation);
    await this.xray.start(config, this.lastTuic);
    try {
      this.assertCurrentConnection(generation);
      await this.killSwitch.allowTunnel();
      this.assertCurrentConnection(generation);
    } catch (error) {
      await this.xray.stop();
      throw error;
    }
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

  private bestServer(servers: TunnelServer[]): TunnelServer | null {
    // TUIC is an explicit per-server choice; automatic selection keeps Xray protocols.
    const xrayServers = servers.filter((item) => !item.tuic);
    const pool = xrayServers.length ? xrayServers : servers;
    const nonRussian = pool.filter((item) => item.countryCode.toUpperCase() !== "RU");
    const candidates = nonRussian.length ? nonRussian : pool;
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
    let stage: AttemptStage = "tun";
    let code = "helper_failed";
    return {
      get code() { return code; },
      reach: (nextStage, nextCode) => { stage = nextStage; code = nextCode; },
      fail: () => this.telemetry.record((session) => session.attemptFailed(stage, code)),
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
    if (patch.status && patch.status !== this.state.status) {
      const detail = patch.statusDetail ?? null;
      this.diskLog?.write(`Состояние: ${patch.status}${detail ? ` — ${detail}` : ""}`);
    }
    this.state = { ...this.state, ...patch };
    this.emitChanged();
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

function telemetryAllowed(settings: AppSettings): boolean {
  return settings.connectionTelemetry && settings.telemetryNoticeShown;
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
    antiDpiEnabled: Boolean(value.antiDpiEnabled),
    antiDpiPackets: validateAntiDpi(value.antiDpiPackets, "tlshello"),
    antiDpiLength: validateAntiDpi(value.antiDpiLength, "100-200"),
    antiDpiInterval: validateAntiDpi(value.antiDpiInterval, "10-20"),
    splitTunnelMode: (["off", "bypass", "only"] as const).includes(value.splitTunnelMode) ? value.splitTunnelMode : "off",
    splitTunnelProcesses: normalizeProcessSelection(value.splitTunnelProcesses),
    connectionTelemetry: Boolean(value.connectionTelemetry),
    telemetryNoticeShown: Boolean(value.telemetryNoticeShown),
  };
}

function affectsTunnel(before: AppSettings, after: AppSettings): boolean {
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
