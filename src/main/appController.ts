import { app } from "electron";
import { EventEmitter } from "node:events";
import { platform, release } from "node:os";
import type {
  AccountSummary,
  AppSettings,
  AppSnapshot,
  LoginChallenge,
  TunnelServer,
} from "../shared/contracts";
import { MobileApiClient } from "./api/mobileApiClient";
import type { AuthChallengeResponse, MobileAccountResponse } from "./api/models";
import { DeviceIdentity } from "./security/deviceIdentity";
import type { SerializedIdentity } from "./security/deviceIdentity";
import { RequestSigner } from "./security/requestSigner";
import { SecureStore } from "./security/secureStore";
import { decryptTunnelProfile, prepareTunnelProfile } from "./vpn/tunnelProfile";
import type { PreparedTunnelProfile } from "./vpn/tunnelProfile";
import { buildLockdownConfig, buildXrayConfig } from "./vpn/xrayConfig";
import { XrayManager } from "./vpn/xrayManager";
import { measureServerLatencies } from "./vpn/serverPinger";
import { DnsLeakProtection } from "./windows/dnsLeakProtection";
import { AppUpdater } from "./update/appUpdater";

interface AppControllerEvents {
  changed: [snapshot: AppSnapshot];
}

const DEFAULT_SETTINGS: AppSettings = {
  routingMode: "bypassRu",
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
};

export class AppController extends EventEmitter<AppControllerEvents> {
  private readonly secureStore = new SecureStore();
  private readonly xray = new XrayManager();
  private readonly dnsLeakProtection = new DnsLeakProtection();
  private readonly updater: AppUpdater | null;
  private identity!: DeviceIdentity;
  private api!: MobileApiClient;
  private accessToken: string | null = null;
  private profile: PreparedTunnelProfile | null = null;
  private loginGeneration = 0;
  private reconnectAttempts = 0;
  private lastConfig: Record<string, unknown> | null = null;
  private lockdownActive = false;
  private trafficDownloadOffset = 0;
  private trafficUploadOffset = 0;
  private lastRawDownload = 0;
  private lastRawUpload = 0;
  private pingPromise: Promise<void> | null = null;
  private resumePromise: Promise<void> | null = null;
  private state: AppSnapshot = {
    appVersion: app.getVersion(),
    tab: "home",
    status: "disconnected",
    statusDetail: null,
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
    this.identity = await this.loadIdentity();
    this.api = new MobileApiClient(
      process.env.LEVIK_API_ORIGIN ?? "https://leviknet.com",
      new RequestSigner(this.identity),
      app.getVersion(),
    );
    this.xray.on("log", (line) => this.addLog(line));
    this.xray.on("exit", (code, expected) => this.handleXrayExit(code, expected));
    this.xray.on("stats", (downloadBytes, uploadBytes) => this.handleTrafficStats(downloadBytes, uploadBytes));
    this.accessToken = await this.loadString("access_token");
    this.state.settings = await this.loadSettings();
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
          await this.connect();
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
      const generation = ++this.loginGeneration;
      void this.pollLogin(challenge, generation);
      const verificationUri = challenge.activationUriComplete ?? challenge.verificationUriComplete;
      if (!verificationUri) throw new Error("Сервер не вернул ссылку авторизации");
      return {
        verificationUri,
        verificationCode: challenge.activationCode ?? challenge.verificationCode ?? null,
        expiresAt: challenge.expiresAt,
      };
    } finally {
      this.patch({ busy: false });
    }
  }

  cancelLogin(): void {
    this.loginGeneration += 1;
    this.patch({ busy: false, statusDetail: null });
  }

  async logout(): Promise<void> {
    this.loginGeneration += 1;
    await this.disconnect();
    const token = this.accessToken;
    if (token) {
      try {
        await this.api.logout(token);
      } catch (error) {
        this.addLog(`Выход на сервере: ${messageOf(error)}`);
      }
    }
    this.accessToken = null;
    this.profile = null;
    await Promise.all([
      this.secureStore.remove("access_token"),
      this.secureStore.remove("tunnel_profile"),
      this.secureStore.remove("selected_server"),
    ]);
    this.patch({
      account: null,
      servers: [],
      serverLatencies: {},
      selectedServerId: null,
      selectedSubscriptionId: null,
      statusDetail: null,
    });
  }

  async refreshAccount(): Promise<void> {
    const token = this.requireToken();
    this.patch({ busy: true });
    try {
      const response = await this.api.account(token);
      const account = mapAccount(response);
      const preferred = this.state.selectedSubscriptionId;
      const subscriptionId = account.subscriptions.some((item) => item.uuid === preferred)
        ? preferred
        : account.subscriptions.find((item) => item.status.toLowerCase() === "active")?.uuid
          ?? account.subscriptions[0]?.uuid
          ?? null;
      this.patch({ account, selectedSubscriptionId: subscriptionId });
      if (subscriptionId) await this.loadTunnelProfile(subscriptionId);
    } catch (error) {
      if (isUnauthorized(error)) {
        this.accessToken = null;
        await this.secureStore.remove("access_token");
        this.patch({ account: null, statusDetail: "Сессия истекла. Войдите снова." });
      }
      throw error;
    } finally {
      this.patch({ busy: false });
    }
  }

  async selectSubscription(subscriptionId: string): Promise<void> {
    if (!this.state.account?.subscriptions.some((item) => item.uuid === subscriptionId)) {
      throw new Error("Подписка не найдена");
    }
    if (this.xray.isRunning()) await this.disconnect();
    this.patch({ selectedSubscriptionId: subscriptionId, busy: true });
    try {
      await this.loadTunnelProfile(subscriptionId);
    } finally {
      this.patch({ busy: false });
    }
  }

  async selectServer(serverId: string): Promise<void> {
    const server = this.state.servers.find((item) => item.id === serverId);
    if (!server) throw new Error("Сервер не найден");
    const reconnect = this.xray.isRunning();
    if (reconnect) await this.disconnect();
    this.state.selectedServerId = serverId;
    await this.secureStore.put("selected_server", Buffer.from(serverId));
    this.emitChanged();
    if (reconnect) await this.connect();
  }

  async connect(): Promise<void> {
    if (this.xray.isRunning() || this.state.status === "connecting") return;
    if (!this.profile) {
      const subscriptionId = this.state.selectedSubscriptionId;
      if (!subscriptionId) throw new Error("Выберите активную подписку");
      await this.loadTunnelProfile(subscriptionId);
    }
    if (this.state.settings.automaticServer && !hasMeasuredLatency(this.state.serverLatencies)) {
      await this.pingServers();
    }
    const server = this.selectedServer();
    if (!server || !this.profile) throw new Error("Выберите VPN-сервер");
    this.resetTrafficStats();
    this.patch({ status: "connecting", statusDetail: `Подключение через ${server.name}…`, busy: true, downloadBytes: 0, uploadBytes: 0 });
    try {
      if (this.state.settings.preventDnsLeaks) await this.dnsLeakProtection.enable();
      const config = buildXrayConfig(this.profile, server, this.state.settings);
      this.lastConfig = config;
      await this.xray.start(config);
      this.lockdownActive = false;
      this.reconnectAttempts = 0;
      this.patch({
        status: "connected",
        statusDetail: `Защищено через ${server.name}`,
        sessionStartedAt: Date.now(),
      });
    } catch (error) {
      await this.dnsLeakProtection.disable().catch((cleanupError: unknown) => this.addLog(`DNS-защита: ${messageOf(cleanupError)}`));
      this.patch({ status: "error", statusDetail: messageOf(error), sessionStartedAt: null });
      throw error;
    } finally {
      this.patch({ busy: false });
    }
  }

  async disconnect(): Promise<void> {
    if (!this.xray.isRunning()) {
      await this.dnsLeakProtection.disable();
      this.patch({ status: "disconnected", statusDetail: null, sessionStartedAt: null });
      return;
    }
    this.patch({ status: "disconnecting", statusDetail: "Отключение…" });
    try {
      await this.xray.stop();
    } finally {
      await this.dnsLeakProtection.disable();
    }
    this.lockdownActive = false;
    this.lastConfig = null;
    this.patch({ status: "disconnected", statusDetail: null, sessionStartedAt: null });
  }

  async updateSettings(patch: Partial<AppSettings>): Promise<void> {
    const previous = this.state.settings;
    const next = validateSettings({ ...previous, ...patch });
    const reconnect = this.xray.isRunning() && affectsTunnel(previous, next);
    this.state.settings = next;
    await this.secureStore.put("settings", Buffer.from(JSON.stringify(next)));
    this.applyLoginItemSettings();
    this.emitChanged();
    if (!previous.automaticServer && next.automaticServer) void this.pingServers();
    if (reconnect) {
      await this.disconnect();
      await this.connect();
    }
  }

  async shutdown(): Promise<void> {
    this.loginGeneration += 1;
    try {
      await this.xray.stop();
    } finally {
      await this.dnsLeakProtection.disable();
    }
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
    await this.api.revokeDevice(this.requireToken(), subscriptionId, deviceId);
    await this.refreshAccount();
  }

  async setSubscriptionShield(subscriptionId: string, enabled: boolean): Promise<void> {
    const subscription = this.state.account?.subscriptions.find((item) => item.uuid === subscriptionId);
    if (!subscription?.shield.supported) throw new Error("Levik Shield недоступен для этой подписки");
    await this.api.setSubscriptionShield(this.requireToken(), subscriptionId, enabled);
    await this.refreshAccount();
  }

  checkForUpdates(): Promise<void> {
    if (!this.updater) throw new Error("Модуль обновлений недоступен");
    return this.updater.check(false);
  }

  installUpdate(): void {
    if (!this.updater) throw new Error("Модуль обновлений недоступен");
    this.updater.install();
  }

  async restoreAfterSystemResume(): Promise<void> {
    if (this.resumePromise) return this.resumePromise;
    if (!this.lastConfig || !["connected", "reconnecting"].includes(this.state.status)) return;
    this.resumePromise = (async () => {
      await delay(1_500);
      if (await this.xray.isHealthy()) return;
      const config = this.lastConfig;
      if (!config || !["connected", "reconnecting"].includes(this.state.status)) return;
      this.patch({ status: "reconnecting", statusDetail: "Восстановление после сна или разблокировки…" });
      if (this.state.settings.preventDnsLeaks) await this.dnsLeakProtection.enable();
      await this.xray.start(config);
      this.lockdownActive = false;
      this.reconnectAttempts = 0;
      this.patch({ status: "connected", statusDetail: "Защищённое соединение восстановлено" });
    })().catch((error: unknown) => {
      this.addLog(`Восстановление после сна: ${messageOf(error)}`);
      this.handleXrayExit(null, false);
    }).finally(() => { this.resumePromise = null; });
    return this.resumePromise;
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
        await this.refreshAccount();
        this.patch({ statusDetail: "Вход выполнен" });
        return;
      } catch (error) {
        this.addLog(`Ожидание входа: ${messageOf(error)}`);
      }
    }
    if (generation === this.loginGeneration) this.patch({ statusDetail: "Срок входа истёк" });
  }

  private async loadTunnelProfile(subscriptionId: string): Promise<void> {
    const response = await this.api.tunnelProfile(this.requireToken(), subscriptionId);
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
      return validateSettings({ ...DEFAULT_SETTINGS, ...JSON.parse(raw.toString("utf8")) as Partial<AppSettings> });
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

  private handleXrayExit(code: number | null, expected: boolean): void {
    if (expected) return;
    this.patch({ status: "reconnecting", statusDetail: `Туннель остановлен (код ${code ?? "?"}). Восстановление…` });
    if (!this.state.settings.autoReconnect || !this.lastConfig) {
      this.patch({ status: "error", statusDetail: "VPN-туннель неожиданно остановлен", sessionStartedAt: null });
      return;
    }
    const delayMs = Math.min(30_000, 1_000 * 2 ** Math.min(this.reconnectAttempts++, 5));
    if (this.state.settings.killSwitch && !this.lockdownActive) {
      void this.xray.start(buildLockdownConfig(this.state.settings)).then(() => {
        this.lockdownActive = true;
        this.addLog("Kill Switch: аварийная блокировка трафика активна");
      }).catch((error: unknown) => {
        this.addLog(`Kill Switch: ${messageOf(error)}`);
      }).finally(() => this.scheduleTunnelRestore(delayMs));
    } else {
      this.scheduleTunnelRestore(delayMs);
    }
  }

  private scheduleTunnelRestore(delayMs: number): void {
    setTimeout(() => {
      if (this.state.status !== "reconnecting" || !this.lastConfig) return;
      void this.xray.start(this.lastConfig).then(() => {
        this.lockdownActive = false;
        this.reconnectAttempts = 0;
        this.patch({ status: "connected", statusDetail: "Защищённое соединение восстановлено" });
      }).catch((error: unknown) => {
        this.addLog(`Переподключение: ${messageOf(error)}`);
        this.handleXrayExit(null, false);
      });
    }, delayMs);
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
    const nonRussian = servers.filter((item) => item.countryCode.toUpperCase() !== "RU");
    const candidates = nonRussian.length ? nonRussian : servers;
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

  private addLog(line: string): void {
    const cleaned = line.replace(/[\r\n]/g, " ").slice(0, 1_000);
    this.state.logs = [`${new Date().toLocaleTimeString("ru-RU")}  ${cleaned}`, ...this.state.logs].slice(0, 200);
    this.emitChanged();
  }

  private patch(patch: Partial<AppSnapshot>): void {
    this.state = { ...this.state, ...patch };
    this.emitChanged();
  }

  private emitChanged(): void {
    this.emit("changed", this.snapshot());
  }

  private applyLoginItemSettings(): void {
    if (process.platform === "win32") {
      app.setLoginItemSettings({ openAtLogin: this.state.settings.launchAtLogin });
    }
  }
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
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value.dnsServer)) throw new Error("Некорректный DNS-сервер");
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
    splitTunnelProcesses: [...new Set(value.splitTunnelProcesses.flatMap((name) => {
      const normalized = normalizeSplitTunnelProcess(name);
      return normalized ? [normalized] : [];
    }))].slice(0, 200),
  };
}

function affectsTunnel(before: AppSettings, after: AppSettings): boolean {
  return before.routingMode !== after.routingMode || before.useDoh !== after.useDoh || before.dnsServer !== after.dnsServer || before.preventDnsLeaks !== after.preventDnsLeaks || before.antiDpiEnabled !== after.antiDpiEnabled || before.antiDpiPackets !== after.antiDpiPackets || before.antiDpiLength !== after.antiDpiLength || before.antiDpiInterval !== after.antiDpiInterval || before.splitTunnelMode !== after.splitTunnelMode || before.splitTunnelProcesses.join("\0") !== after.splitTunnelProcesses.join("\0");
}

function normalizeSplitTunnelProcess(value: string): string | null {
  const trimmed = value.trim();
  const name = /\.exe$/i.test(trimmed) ? trimmed : `${trimmed}.exe`;
  return /^[^<>:"/\\|?*\u0000-\u001f]{1,128}\.exe$/i.test(name) ? name : null;
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

function isUnauthorized(error: unknown): boolean {
  return typeof error === "object" && error !== null && "status" in error && error.status === 401;
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
