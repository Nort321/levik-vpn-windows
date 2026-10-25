import { EventEmitter } from "node:events";
import { describeSources, freeBytes, planTargets, removePartials, TargetFiles, TransferFailure } from "./files";
import type { MarkDownloaded } from "./files";
import { RelayLink } from "./link";
import type { LinkHost, LinkStatus } from "./link";
import { MAX_FILES, MAX_TOTAL } from "./protocol";
import type { ManifestFile } from "./protocol";
import { joinRelay, parseEndpoints } from "./relay";
import type { RelayEndpoint } from "./relay";
import type { DropPlatform, ReceiverWork, SenderWork, SessionOutcome, Trust } from "./session";
import { DropStore, loadIdentity, Pins } from "./store";
import type { Secrets, StoredReceiver, StoredSender } from "./store";
import type { Identity } from "./session";
import { dropFileCount, isOpenDropState } from "../../../shared/drop";
import type { DropAnswer, DropControl, DropDevice, DropPrompt, DropSnapshot, DropState, DropTransfer } from "../../../shared/drop";

/**
 * LevikDrop in a desktop app, docs/levik-drop.md: presence, the website's
 * transfers, one relay link per open transfer, the user's answers.
 */

export interface DropApi {
  presence(key: string): Promise<unknown>;
  clearPresence(): Promise<void>;
  devices(): Promise<unknown>;
  transfers(): Promise<unknown>;
  create(offer: { receiverDeviceId: string; fileCount: number; totalBytes: number }): Promise<unknown>;
  update(step: { id: string; action: string; reason?: string }): Promise<unknown>;
}

export interface DropEngineOptions {
  api: DropApi;
  secrets: Secrets;
  statePath: string;
  platform: DropPlatform;
  defaultFolder: string;
  markDownloaded: MarkDownloaded;
  /** The website's error code of a failed request, if it gave one. */
  errorCode(error: unknown): string | null;
  log(line: string): void;
  /** Tests join a plain relay; apps always use TLS with the pin. */
  join?: typeof joinRelay;
}

export interface DropEngineEvents {
  changed: [];
  notify: [{ title: string; body: string }];
}

const PRESENCE_MS = 60_000;
const PRESENCE_RETRY_MS = 5 * 60_000;
/** While a transfer is open the list is fetched this often anyway (missed events, retries). */
const OPEN_REFRESH_MS = 30_000;
const PROTOCOL_FAILURES = 5;
const RATE_WINDOW_MS = 4_000;
const PLATFORMS: readonly DropPlatform[] = ["android", "windows", "macos", "linux"];
const STATES: readonly DropState[] = ["offered", "active", "paused", "done", "declined", "cancelled", "failed", "expired"];

interface WebTransfer {
  id: string;
  role: "sender" | "receiver";
  peerDeviceId: string;
  peerName: string;
  peerPlatform: DropPlatform | null;
  state: DropState;
  reason: string | null;
  fileCount: number;
  totalBytes: number;
  createdAt: number;
  finishedAt: number | null;
}

interface Live {
  done: number;
  samples: Array<[number, number]>;
  path: "relay" | "lan" | null;
  link: LinkStatus | null;
  verificationCode: string | null;
}

type Answer = "yes" | "no" | "superseded";

interface PendingPrompt extends DropPrompt {
  peerKey: Buffer;
  resolve(answer: Answer): void;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function time(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function parseWebTransfer(value: unknown): WebTransfer | null {
  if (!record(value) || typeof value.id !== "string" || !UUID.test(value.id)) return null;
  if (value.role !== "sender" && value.role !== "receiver") return null;
  if (typeof value.peerDeviceId !== "string" || typeof value.peerName !== "string") return null;
  const state = STATES.find((item) => item === value.state);
  const createdAt = time(value.createdAt);
  if (!state || createdAt === null) return null;
  if (typeof value.fileCount !== "number" || typeof value.totalBytes !== "number") return null;
  return {
    id: value.id,
    role: value.role,
    peerDeviceId: value.peerDeviceId,
    peerName: value.peerName.slice(0, 80),
    peerPlatform: PLATFORMS.find((item) => item === value.peerPlatform) ?? null,
    state,
    reason: typeof value.reason === "string" ? value.reason.slice(0, 40) : null,
    fileCount: value.fileCount,
    totalBytes: value.totalBytes,
    createdAt,
    finishedAt: time(value.finishedAt),
  };
}

export function parseDropDevices(value: unknown): DropDevice[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item): DropDevice[] => {
    if (!record(item) || typeof item.deviceId !== "string" || typeof item.name !== "string" || item.current === true) return [];
    const platform = PLATFORMS.find((entry) => entry === item.platform);
    if (!platform) return [];
    return [{ deviceId: item.deviceId, name: item.name.slice(0, 80), platform, ready: item.ready === true, supported: typeof item.keyId === "string" }];
  });
}

function parseConnection(value: unknown): { token: string; endpoints: RelayEndpoint[] } | null {
  if (!record(value) || !record(value.connection)) return null;
  const { token, endpoints } = value.connection;
  if (typeof token !== "string" || token.length > 2_048) return null;
  const parsed = parseEndpoints(endpoints);
  return parsed.length > 0 ? { token, endpoints: parsed } : null;
}

export class DropEngine extends EventEmitter<DropEngineEvents> {
  private readonly store: DropStore;
  private readonly pins: Pins;
  private identity: Identity | null = null;
  private loaded: Promise<void> | null = null;
  private running = false;
  private generation = 0;
  private stopping: Promise<void> | null = null;
  private signingOut: Promise<void> | null = null;
  private presenceTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshing: Promise<void> | null = null;
  private refreshAgain = false;
  private creating = 0;
  private web = new Map<string, WebTransfer>();
  private webLoaded = false;
  private devices: DropDevice[] = [];
  private available = false;
  private loadedAt: number | null = null;
  private quota: DropSnapshot["quota"] = null;
  private limits = { maxFiles: MAX_FILES, maxBytes: MAX_TOTAL };
  private error: string | null = null;
  private readonly links = new Map<string, RelayLink>();
  private readonly live = new Map<string, Live>();
  private readonly prompts = new Map<string, PendingPrompt>();
  private readonly targets = new Map<string, TargetFiles>();
  private readonly protocolFailures = new Map<string, number>();
  private readonly resuming = new Set<string>();
  private readonly announced = new Set<string>();
  private changedTimer: ReturnType<typeof setTimeout> | null = null;
  private savedAt = 0;

  constructor(private readonly options: DropEngineOptions) {
    super();
    this.store = new DropStore(options.statePath);
    this.pins = new Pins(options.secrets);
  }

  private load(): Promise<void> {
    this.loaded ??= (async () => {
      await this.store.load();
      await this.pins.load();
      this.identity = await loadIdentity(this.options.secrets);
    })();
    return this.loaded;
  }

  /** Signed in: ready to receive, links for open transfers. */
  async start(): Promise<void> {
    const requested = this.generation;
    await this.signingOut;
    await this.stopping;
    if (requested !== this.generation) return;
    if (this.running) return;
    const generation = ++this.generation;
    this.running = true;
    try {
      await this.load();
    } catch (error) {
      if (!this.current(generation)) return;
      this.running = false;
      this.options.log(`LevikDrop: ${error instanceof Error ? error.message : "ключ недоступен"}`);
      return;
    }
    if (!this.current(generation)) return;
    this.reportPresence();
    this.refresh();
  }

  /** Quit or sign-out: links stop, the website hears this app is gone. */
  async stop(): Promise<void> {
    const wasRunning = this.running;
    this.running = false;
    this.generation++;
    this.refreshing = null;
    this.refreshAgain = false;
    this.creating = 0;
    // Dispatch before awaiting file cleanup, while the caller still owns its session.
    const presence = wasRunning ? this.options.api.clearPresence().catch(() => {}) : Promise.resolve();
    if (this.presenceTimer) clearTimeout(this.presenceTimer);
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.presenceTimer = null;
    this.refreshTimer = null;
    for (const id of [...this.links.keys()]) this.stopLink(id);
    for (const prompt of this.prompts.values()) prompt.resolve("superseded");
    this.prompts.clear();
    const previous = this.stopping;
    const files = [...this.targets.values()];
    const stopping = (async () => {
      await previous;
      await this.loaded?.catch(() => {});
      for (const file of files) await file.closeWriting();
      await presence;
      await this.store.flush();
    })();
    this.stopping = stopping;
    try { await stopping; }
    finally { if (this.stopping === stopping) this.stopping = null; }
  }

  /** Sign-out ends this app's transfers on the website; partial files go here. */
  signedOut(): Promise<void> {
    if (this.signingOut) return this.signingOut;
    const pending = this.clearSignedOut();
    this.signingOut = pending.finally(() => { this.signingOut = null; });
    return this.signingOut;
  }

  private async clearSignedOut(): Promise<void> {
    await this.stop();
    for (const stored of this.store.transfers) {
      if (stored.role === "receiver" && stored.targets && !stored.finished) await removePartials(stored.targets);
      this.store.remove(stored.id);
    }
    this.web.clear();
    this.webLoaded = false;
    this.devices = [];
    this.available = false;
    this.loadedAt = null;
    this.quota = null;
    this.error = null;
    this.resuming.clear();
    this.protocolFailures.clear();
    this.announced.clear();
    this.live.clear();
    this.targets.clear();
    await this.store.flush();
    this.changed();
  }

  /** The `drop` live event, a new stream, or the window showing the list. */
  refresh(): void {
    if (!this.running) return;
    if (this.refreshing) {
      this.refreshAgain = true;
      return;
    }
    const generation = this.generation;
    this.refreshing = this.load()
      .then(() => { if (this.current(generation)) return this.fetch(generation); })
      .catch((error: unknown) => {
        if (this.current(generation)) this.error = this.errorText(error);
      })
      .finally(() => {
        if (!this.current(generation)) return;
        this.refreshing = null;
        this.changed();
        if (this.refreshAgain) {
          this.refreshAgain = false;
          this.refresh();
        } else {
          this.scheduleRefresh();
        }
      });
  }

  /** Waits for the refresh in flight (the window's "Обновить"). */
  async refreshNow(): Promise<void> {
    this.refresh();
    await this.refreshing;
  }

  set folder(folder: string) {
    void this.load().then(() => {
      this.store.folder = folder;
      this.changed();
    });
  }

  snapshot(): DropSnapshot {
    const transfers = [...this.web.values()]
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((transfer) => this.view(transfer));
    return {
      available: this.available,
      loadedAt: this.loadedAt,
      devices: this.devices,
      transfers,
      quota: this.quota,
      limits: this.limits,
      folder: this.store.folder ?? this.options.defaultFolder,
      error: this.error,
    };
  }

  // Sending --------------------------------------------------------------------------

  async send(deviceId: string, paths: readonly string[]): Promise<void> {
    if (!this.running) throw new Error("Войдите в Levik Account");
    const generation = this.generation;
    await this.load();
    this.assertCurrent(generation);
    if ([...this.web.values()].some((transfer) => isOpenDropState(transfer.state))) {
      throw new Error("Дождитесь окончания текущей передачи: за раз передаётся один набор файлов.");
    }
    const unique = [...new Set(paths)];
    if (unique.length < 1) return;
    if (unique.length > this.limits.maxFiles) throw new Error(`За раз можно передать до ${this.limits.maxFiles} файлов.`);
    const files = await describeSources(unique);
    this.assertCurrent(generation);
    const total = files.reduce((sum, file) => sum + file.size, 0);
    if (total > this.limits.maxBytes) throw new Error("За раз можно передать до 2 ГБ.");
    this.creating++;
    try {
      const response = await this.options.api.create({ receiverDeviceId: deviceId, fileCount: files.length, totalBytes: total });
      this.assertCurrent(generation);
      const transfer = record(response) ? parseWebTransfer(response.transfer) : null;
      if (!transfer) throw new Error("Сайт ответил непонятно. Попробуйте ещё раз.");
      const stored: StoredSender = { id: transfer.id, role: "sender", peerDeviceId: transfer.peerDeviceId, files, finished: false };
      this.store.put(stored);
      this.web.set(transfer.id, transfer);
      this.ensureLink(transfer.id);
    } finally {
      if (this.current(generation)) { this.creating--; this.changed(); }
    }
  }

  // The user's answers and buttons ---------------------------------------------------

  async answer(id: string, answer: DropAnswer, code: string | null): Promise<void> {
    const prompt = this.prompts.get(id);
    const transfer = this.web.get(id);
    if (!prompt) {
      // The other app is not connected: an offer can still be declined.
      if (answer === "decline" && transfer?.role === "receiver" && transfer.state === "offered") {
        await this.decline(id);
        return;
      }
      throw new Error("Запрос уже неактуален.");
    }
    if (prompt.code && code !== prompt.code && (answer === "accept" || answer === "confirm")) {
      throw new Error("Код изменился: сверьте новый код на обоих устройствах.");
    }
    const yes = answer === "accept" || answer === "confirm";
    if ((prompt.kind === "offer") !== (answer === "accept" || answer === "decline")) throw new Error("Запрос уже неактуален.");
    this.prompts.delete(id);
    prompt.resolve(yes ? "yes" : "no");
    this.changed();
  }

  async control(id: string, action: DropControl): Promise<void> {
    const transfer = this.web.get(id);
    if (!transfer) throw new Error("Передача не найдена.");
    const session = this.links.get(id)?.current;
    switch (action) {
      case "pause":
        if (session && !session.finished) {
          session.pause();
          return;
        }
        this.stopLink(id);
        await this.step(id, "pause", "user");
        return;
      case "resume":
        this.resuming.add(id);
        this.ensureLink(id);
        this.changed();
        return;
      case "cancel":
        if (session && !session.finished) {
          session.cancel();
          return;
        }
        this.stopLink(id);
        await this.discard(id);
        await this.step(id, "cancel");
        return;
    }
  }

  /** The first finished file of a received transfer, to show in its folder. */
  savedFile(id: string): string | null {
    const stored = this.store.find(id);
    if (stored?.role !== "receiver") return null;
    return stored.targets?.find((target) => target.final)?.final ?? null;
  }

  // Website --------------------------------------------------------------------------

  private async fetch(generation: number): Promise<void> {
    const [list, devices] = await Promise.all([
      this.options.api.transfers(),
      this.options.api.devices().catch((error: unknown) => {
        const code = this.options.errorCode(error);
        if (this.current(generation) && (code === "drop_unavailable" || code?.startsWith("http_4"))) this.available = false;
        return null;
      }),
    ]);
    if (!this.current(generation)) return;
    if (record(devices)) {
      this.available = devices.available === true;
      this.devices = parseDropDevices(devices.devices);
      if (record(devices.limits)) {
        const { maxFiles, maxBytes } = devices.limits;
        if (typeof maxFiles === "number" && typeof maxBytes === "number") {
          this.limits = { maxFiles: Math.min(maxFiles, MAX_FILES), maxBytes: Math.min(maxBytes, MAX_TOTAL) };
        }
      }
    }
    if (record(list)) {
      if (Array.isArray(list.transfers)) {
        this.web = new Map(list.transfers.flatMap((item) => {
          const transfer = parseWebTransfer(item);
          return transfer ? [[transfer.id, transfer] as const] : [];
        }));
        this.webLoaded = true;
      }
      if (record(list.quota)) {
        const { limitBytes, usedBytes, resetsAt } = list.quota;
        const resets = time(resetsAt);
        if (typeof limitBytes === "number" && typeof usedBytes === "number" && resets !== null) this.quota = { limitBytes, usedBytes, resetsAt: resets };
      }
    }
    this.loadedAt = Date.now();
    this.error = null;
    await this.reconcile(generation);
  }

  private async step(id: string, action: string, reason?: string, generation = this.generation): Promise<void> {
    this.assertCurrent(generation);
    try {
      const response = await this.options.api.update({ id, action, ...(reason ? { reason } : {}) });
      this.assertCurrent(generation);
      const transfer = record(response) ? parseWebTransfer(response.transfer) : null;
      if (transfer) this.web.set(id, transfer);
    } catch (error) {
      if (!this.current(generation)) return;
      const code = this.options.errorCode(error);
      // Already over on the website: the list says how.
      if (code !== "transfer_ended" && code !== "transfer_not_found" && code !== "invalid_action") throw error;
      this.refresh();
    } finally {
      if (this.current(generation)) this.changed();
    }
  }

  private quietStep(id: string, action: string, reason?: string): void {
    void this.step(id, action, reason).catch((error: unknown) => this.options.log(`LevikDrop: ${this.errorText(error)}`));
  }

  private async reconcile(generation: number): Promise<void> {
    for (const transfer of this.web.values()) {
      if (!this.current(generation)) return;
      const stored = this.store.find(transfer.id);
      if (isOpenDropState(transfer.state)) {
        if (transfer.role === "sender") {
          if (!stored) {
            // The files of this offer are not known here (another installation): it cannot go on.
            if (this.creating === 0) this.quietStep(transfer.id, "fail", "source_unreadable");
            continue;
          }
        } else if (!stored) {
          this.store.put({
            id: transfer.id, role: "receiver", peerDeviceId: transfer.peerDeviceId, manifest: null, folder: null, targets: null,
            decision: transfer.state === "offered" ? null : "accepted", finished: false,
          });
        } else if (stored.role === "receiver" && stored.decision === "declined") {
          this.quietStep(transfer.id, "decline");
          continue;
        }
        if (transfer.state === "paused" && !this.resuming.has(transfer.id)) this.stopLink(transfer.id);
        else this.ensureLink(transfer.id);
        continue;
      }
      this.stopLink(transfer.id);
      this.resuming.delete(transfer.id);
      if (stored && !stored.finished) {
        if (transfer.state !== "done") await this.discard(transfer.id);
        else if (stored.role === "receiver" && !this.announced.has(transfer.id)) {
          this.announced.add(transfer.id);
          this.emit("notify", { title: "Файлы получены", body: `${dropFileCount(transfer.fileCount)} от «${transfer.peerName}». Они в папке «${stored.folder ?? this.options.defaultFolder}».` });
        }
        if (!this.current(generation)) return;
        stored.finished = true;
        this.store.save();
        this.targets.delete(transfer.id);
      }
    }
    if (!this.webLoaded) return;
    for (const stored of [...this.store.transfers]) {
      if (!this.current(generation)) return;
      if (this.web.has(stored.id)) continue;
      if (stored.role === "receiver" && stored.targets && !stored.finished) await removePartials(stored.targets);
      if (!this.current(generation)) return;
      this.store.remove(stored.id);
    }
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.refreshTimer = null;
    if (!this.running || ![...this.web.values()].some((transfer) => isOpenDropState(transfer.state))) return;
    this.refreshTimer = setTimeout(() => this.refresh(), OPEN_REFRESH_MS);
  }

  private reportPresence(): void {
    if (!this.running) return;
    const identity = this.identity;
    if (!identity) return;
    const generation = this.generation;
    void this.options.api.presence(identity.spki.toString("base64url")).then(
      () => { if (this.current(generation)) this.schedulePresence(PRESENCE_MS); },
      (error: unknown) => {
        if (!this.current(generation)) return;
        const code = this.options.errorCode(error);
        if (code !== "drop_unavailable" && !code?.startsWith("http_404")) this.options.log(`LevikDrop: ${this.errorText(error)}`);
        this.schedulePresence(code === "drop_unavailable" || code?.startsWith("http_4") ? PRESENCE_RETRY_MS : PRESENCE_MS);
      },
    );
  }

  private schedulePresence(ms: number): void {
    if (!this.running) return;
    if (this.presenceTimer) clearTimeout(this.presenceTimer);
    this.presenceTimer = setTimeout(() => this.reportPresence(), ms);
  }

  // Links ----------------------------------------------------------------------------

  private ensureLink(id: string): void {
    if (!this.running || this.links.has(id)) return;
    const link = new RelayLink(this.hostFor(id), this.options.join);
    this.links.set(id, link);
    link.start();
  }

  private stopLink(id: string): void {
    const link = this.links.get(id);
    if (!link) return;
    this.links.delete(id);
    link.stop();
    this.supersede(id);
    const live = this.live.get(id);
    if (live) {
      live.path = null;
      live.link = null;
      live.verificationCode = null;
    }
  }

  private supersede(id: string): void {
    const prompt = this.prompts.get(id);
    this.prompts.delete(id);
    prompt?.resolve("superseded");
  }

  private liveFor(id: string): Live {
    let live = this.live.get(id);
    if (!live) {
      live = { done: 0, samples: [], path: null, link: null, verificationCode: null };
      this.live.set(id, live);
    }
    return live;
  }

  private hostFor(id: string): LinkHost {
    const generation = this.generation;
    return {
      connect: async () => {
        this.assertCurrent(generation);
        const response = await this.options.api.update({ id, action: "connect" });
        this.assertCurrent(generation);
        this.resuming.delete(id);
        const transfer = record(response) ? parseWebTransfer(response.transfer) : null;
        if (transfer) this.web.set(id, transfer);
        const connection = parseConnection(response);
        if (!connection) throw new Error("no relay connection");
        return connection;
      },
      work: (allowLan) => { this.assertCurrent(generation); return this.workFor(id, allowLan); },
      status: (status) => {
        if (!this.current(generation)) return;
        const live = this.liveFor(id);
        live.link = status;
        if (status !== "session") live.verificationCode = null;
        if (status !== "session") live.path = null;
        if (status !== "session") this.supersede(id);
        this.changed();
      },
      outcome: (outcome) => { if (this.current(generation)) void this.onOutcome(id, outcome); },
      stopped: (reason, error) => { if (this.current(generation)) void this.onStopped(id, reason, error); },
    };
  }

  private workFor(id: string, allowLan: boolean): SenderWork | ReceiverWork {
    const generation = this.generation;
    const stored = this.store.find(id);
    const transfer = this.web.get(id);
    const identity = this.identity;
    if (!stored || !transfer || !identity) throw new Error("unknown transfer");
    let peerKey: Buffer | null = null;
    const common = {
      transferId: id,
      identity,
      peerDeviceId: stored.peerDeviceId,
      ownPlatform: this.options.platform,
      peerPlatform: transfer.peerPlatform,
      allowLan,
      trust: (key: Buffer): Trust => this.pins.trust(stored.peerDeviceId, key),
      confirm: async (code: string, trust: Trust): Promise<boolean> => {
        if (!peerKey) return false;
        const answer = await this.ask(id, { kind: "confirm", code, trust }, peerKey);
        if (!this.current(generation)) return false;
        if (answer === "yes") await this.pins.pin(stored.peerDeviceId, peerKey);
        return answer === "yes";
      },
      events: {
        keyed: (code: string, _trust: Trust, key: Buffer) => {
          if (!this.current(generation)) return;
          peerKey = key;
          this.protocolFailures.delete(id);
          this.liveFor(id).verificationCode = code;
          this.changed();
        },
        path: (path: "relay" | "lan") => {
          if (!this.current(generation)) return;
          this.liveFor(id).path = path;
          this.changed();
        },
        progress: (done: number) => { if (this.current(generation)) this.progress(id, done); },
      },
    };
    if (stored.role === "sender") return { ...common, role: "sender", files: stored.files };
    return {
      ...common,
      role: "receiver",
      manifest: stored.manifest,
      targets: this.targetFilesFor(stored),
      decide: async (manifest, code, trust) => {
        if (!this.current(generation)) return null;
        stored.manifest = manifest;
        this.store.save();
        this.changed();
        if (stored.decision !== "accepted") {
          if (!peerKey) return null;
          this.announceOffer(id, manifest);
          const answer = await this.ask(id, { kind: "offer", code: trust === "trusted" ? null : code, trust }, peerKey);
          if (!this.current(generation)) return null;
          if (answer === "superseded") return null;
          if (answer === "no") {
            await this.decline(id);
            return null;
          }
          if (trust !== "trusted") await this.pins.pin(stored.peerDeviceId, peerKey);
        }
        const files = await this.prepareTargets(stored, manifest, generation);
        if (!this.current(generation)) return null;
        if (stored.decision !== "accepted") {
          await this.step(id, "accept", undefined, generation);
          if (!this.current(generation)) return null;
          stored.decision = "accepted";
          this.store.save();
        }
        return files;
      },
    };
  }

  private targetFilesFor(stored: StoredReceiver): TargetFiles | null {
    if (!stored.targets || !stored.folder) return null;
    let files = this.targets.get(stored.id);
    if (!files) {
      // A file in place is written down at once: a restart must not offer it again.
      files = new TargetFiles(stored.folder, stored.targets, async (path) => {
        this.store.save();
        await this.options.markDownloaded(path);
      });
      this.targets.set(stored.id, files);
    }
    return files;
  }

  private async prepareTargets(stored: StoredReceiver, manifest: ManifestFile[], generation: number): Promise<TargetFiles> {
    const folder = this.store.folder ?? this.options.defaultFolder;
    const needed = manifest.reduce((sum, file) => sum + file.size, 0);
    const free = await freeBytes(folder);
    this.assertCurrent(generation);
    if (free !== null && free < needed + 64 * 1024 * 1024) throw new TransferFailure("storage_full");
    stored.folder = folder;
    stored.targets = await planTargets(folder, manifest);
    if (!this.current(generation)) { await removePartials(stored.targets); this.assertCurrent(generation); }
    this.store.save();
    const files = this.targetFilesFor(stored);
    if (!files) throw new Error("no target files");
    return files;
  }

  private ask(id: string, prompt: DropPrompt, peerKey: Buffer): Promise<Answer> {
    this.supersede(id);
    return new Promise((resolve) => {
      this.prompts.set(id, { ...prompt, peerKey, resolve });
      this.changed();
    });
  }

  private announceOffer(id: string, manifest: ManifestFile[]): void {
    const transfer = this.web.get(id);
    if (!transfer || this.announced.has(`offer:${id}`)) return;
    this.announced.add(`offer:${id}`);
    const names = manifest.length === 1 ? `«${manifest[0]?.name ?? "файл"}»` : dropFileCount(manifest.length);
    this.emit("notify", { title: `Файлы с «${transfer.peerName}»`, body: `${names}. Откройте Levik VPN, чтобы принять или отклонить.` });
  }

  private async decline(id: string): Promise<void> {
    const stored = this.store.find(id);
    if (stored?.role === "receiver") {
      stored.decision = "declined";
      this.store.save();
    }
    await this.step(id, "decline");
  }

  private async discard(id: string): Promise<void> {
    const stored = this.store.find(id);
    if (stored?.role !== "receiver" || !stored.targets) return;
    const files = this.targets.get(id);
    if (files) await files.discardPartials();
    else await removePartials(stored.targets);
    this.targets.delete(id);
  }

  private progress(id: string, done: number): void {
    const live = this.liveFor(id);
    const now = Date.now();
    live.done = done;
    live.samples = [...live.samples.filter(([at]) => now - at <= RATE_WINDOW_MS), [now, done]];
    this.links.get(id)?.progressed();
    // Finished files must survive a crash; progress alone is re-read from disk.
    if (now - this.savedAt > 2_000) {
      this.savedAt = now;
      this.store.save();
    }
    this.changed();
  }

  private async onOutcome(id: string, outcome: SessionOutcome): Promise<void> {
    const generation = this.generation;
    this.supersede(id);
    const live = this.liveFor(id);
    live.path = null;
    live.samples = [];
    live.verificationCode = null;
    const stored = this.store.find(id);
    try {
      switch (outcome.kind) {
        case "lost": {
          if (!outcome.detail.startsWith("protocol")) return;
          const failures = (this.protocolFailures.get(id) ?? 0) + 1;
          this.protocolFailures.set(id, failures);
          this.options.log(`LevikDrop: сессия прервана (${outcome.detail})`);
          if (failures >= PROTOCOL_FAILURES) {
            this.stopLink(id);
            await this.discard(id);
            await this.step(id, "fail", "protocol", generation);
          }
          return;
        }
        case "done":
          this.links.delete(id);
          await this.step(id, "complete", undefined, generation);
          return;
        case "declined":
          this.links.delete(id);
          return;
        case "paused":
          this.links.delete(id);
          if (outcome.by === "self") await this.step(id, "pause", "user", generation);
          return;
        case "cancelled":
          this.links.delete(id);
          await this.discard(id);
          await this.step(id, "cancel", undefined, generation);
          return;
        case "failed":
          this.links.delete(id);
          await this.discard(id);
          await this.step(id, "fail", outcome.reason, generation);
          return;
      }
    } catch (error) {
      if (this.current(generation)) this.options.log(`LevikDrop: ${this.errorText(error)}`);
    } finally {
      if (this.current(generation)) { if (stored) this.store.save(); this.refresh(); }
    }
  }

  private async onStopped(id: string, reason: string, error?: unknown): Promise<void> {
    const generation = this.generation;
    this.links.delete(id);
    const live = this.liveFor(id);
    live.link = null;
    live.path = null;
    live.verificationCode = null;
    const transfer = this.web.get(id);
    const code = error === undefined ? null : this.options.errorCode(error);
    try {
      if ((reason === "limit" || code === "quota_exceeded") && transfer?.role === "sender" && transfer.state === "active") {
        await this.step(id, "pause", "quota", generation);
      } else if (code === "subscription_required") {
        this.error = this.errorText(error);
      } else if (error !== undefined && code !== "transfer_ended" && code !== "transfer_not_found") {
        // The website is out of reach: the next refresh tries again.
        this.options.log(`LevikDrop: ${this.errorText(error)}`);
      }
    } catch (stepError) {
      this.options.log(`LevikDrop: ${this.errorText(stepError)}`);
    }
    if (!this.current(generation)) return;
    this.resuming.delete(id);
    this.changed();
    this.scheduleRefresh();
  }

  // Snapshot -------------------------------------------------------------------------

  private view(transfer: WebTransfer): DropTransfer {
    const stored = this.store.find(transfer.id);
    const live = this.live.get(transfer.id);
    const prompt = this.prompts.get(transfer.id);
    const files = stored?.role === "sender"
      ? stored.files.map((file) => ({ name: file.name, size: file.size }))
      : stored?.role === "receiver" ? stored.manifest : null;
    const samples = live?.samples ?? [];
    const first = samples[0];
    const last = samples[samples.length - 1];
    const rate = first && last && last[0] - first[0] >= 1_000 ? Math.max(0, ((last[1] - first[1]) * 1_000) / (last[0] - first[0])) : null;
    const done = transfer.state === "done" ? transfer.totalBytes : live?.done ?? 0;
    return {
      id: transfer.id,
      role: transfer.role,
      peerDeviceId: transfer.peerDeviceId,
      peerName: transfer.peerName,
      peerPlatform: transfer.peerPlatform,
      state: transfer.state,
      reason: transfer.reason,
      fileCount: transfer.fileCount,
      totalBytes: transfer.totalBytes,
      files,
      doneBytes: Math.min(done, transfer.totalBytes),
      bytesPerSecond: isOpenDropState(transfer.state) ? rate : null,
      path: live?.path ?? null,
      link: this.links.has(transfer.id) ? live?.link ?? "connecting" : null,
      prompt: prompt ? { kind: prompt.kind, code: prompt.code, trust: prompt.trust } : null,
      verificationCode: live?.verificationCode ?? null,
      folder: stored?.role === "receiver" ? stored.folder : null,
      saved: stored?.role === "receiver" ? stored.targets?.some((target) => target.final !== null) ?? false : false,
      createdAt: transfer.createdAt,
      finishedAt: transfer.finishedAt,
    };
  }

  private errorText(error: unknown): string {
    return error instanceof Error ? error.message : "ошибка LevikDrop";
  }

  private current(generation: number): boolean { return this.running && generation === this.generation; }
  private assertCurrent(generation: number): void {
    if (!this.current(generation)) throw new Error("Сессия передачи файлов изменилась");
  }

  /** Coalesced: progress comes many times a second. */
  private changed(): void {
    if (this.changedTimer) return;
    this.changedTimer = setTimeout(() => {
      this.changedTimer = null;
      this.emit("changed");
    }, 250);
  }
}
