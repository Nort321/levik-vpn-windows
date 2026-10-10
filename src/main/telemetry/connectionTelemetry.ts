import { buildBatches, TelemetryClient, type NetworkToken } from "./telemetryClient";
import { TelemetryQueue } from "./telemetryQueue";
import {
  SessionRecorder,
  type EndBy,
  type SessionClient,
  type SessionSettings,
  type SessionTrigger,
} from "./sessionRecorder";

const PERSIST_DELAY_MS = 5_000;
const CHECKPOINT_INTERVAL_MS = 30 * 60_000;
const FLUSH_INTERVAL_MS = 15 * 60_000;
const NETWORK_TOKEN_REUSE_MS = 10 * 60_000;
const NETWORK_TOKEN_WAIT_MS = 1_500;

/**
 * Anonymous connection quality reports (docs/connection-telemetry.md in the
 * public repository). Nothing is recorded, stored or sent while disabled.
 */
export class ConnectionTelemetry {
  private enabled = false;
  private session: SessionRecorder | null = null;
  private readonly queue: TelemetryQueue;
  private persistTimer: ReturnType<typeof setTimeout> | null = null;
  private checkpointTimer: ReturnType<typeof setInterval> | null = null;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushing: Promise<void> | null = null;
  private networkToken: { value: NetworkToken; fetchedAt: number } | null = null;

  constructor(
    directory: string,
    private readonly client: SessionClient,
    private readonly http = new TelemetryClient(),
    private readonly now: () => number = Date.now,
  ) {
    this.queue = new TelemetryQueue(directory, now);
  }

  async setEnabled(enabled: boolean): Promise<void> {
    if (enabled === this.enabled) return;
    this.enabled = enabled;
    if (!enabled) {
      this.session = null;
      this.networkToken = null;
      this.stopTimers();
      await this.queue.clear();
      return;
    }
    this.flushTimer = setInterval(() => void this.flush(), FLUSH_INTERVAL_MS);
    await this.finishInterrupted();
    void this.flush();
  }

  /**
   * Learns the operator of the current network over the regular connection.
   * Call before the tunnel and Kill Switch take over; bounded so a slow network
   * does not delay connecting. A late answer still labels the new session.
   */
  async prepareNetwork(): Promise<void> {
    if (!this.enabled) return;
    if (this.networkToken && this.now() - this.networkToken.fetchedAt < NETWORK_TOKEN_REUSE_MS) return;
    this.networkToken = null;
    const request = this.http.networkToken().then((value) => {
      if (!value || !this.enabled) return;
      this.networkToken = { value, fetchedAt: this.now() };
      if (this.session && !this.session.finished && !this.session.hasNetworkToken) this.session.setNetworkToken(value.token);
    }).catch(() => {});
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([request, new Promise<void>((resolve) => { timer = setTimeout(resolve, NETWORK_TOKEN_WAIT_MS); })]);
    clearTimeout(timer);
  }

  /** Starts a session unless one is already running. */
  begin(trigger: SessionTrigger, settings: SessionSettings): void {
    if (!this.enabled || (this.session && !this.session.finished)) return;
    const session = new SessionRecorder(this.client, trigger, settings, this.now);
    const token = this.networkToken;
    session.setNetworkToken(token && token.value.expiresAt > this.now() ? token.value.token : null);
    this.session = session;
    if (this.checkpointTimer) clearInterval(this.checkpointTimer);
    this.checkpointTimer = setInterval(() => {
      void this.persist().then(() => this.flush());
    }, CHECKPOINT_INTERVAL_MS);
  }

  get active(): boolean {
    return this.enabled && this.session !== null && !this.session.finished;
  }

  record(update: (session: SessionRecorder) => void): void {
    const session = this.session;
    if (!this.enabled || !session || session.finished) return;
    update(session);
    this.schedulePersist();
  }

  /** Ends the session; resolves once it is saved, before it is sent. */
  finish(by: EndBy, code: string | null): Promise<void> {
    const session = this.session;
    if (!this.enabled || !session || session.finished) return Promise.resolve();
    session.end(by, code);
    if (this.checkpointTimer) clearInterval(this.checkpointTimer);
    this.checkpointTimer = null;
    const saved = this.persist();
    void saved.then(() => {
      if (this.session === session) this.session = null;
      return this.flush();
    });
    return saved;
  }

  /** Sends shortly, e.g. once a tunnel is up and can carry the request. */
  flushSoon(delayMs = 10_000): void {
    if (!this.enabled) return;
    setTimeout(() => void this.flush(), delayMs).unref?.();
  }

  flush(): Promise<void> {
    if (!this.enabled) return Promise.resolve();
    this.flushing ??= this.sendQueued().catch(() => {}).finally(() => { this.flushing = null; });
    return this.flushing;
  }

  /** Writes the current state now; used before the app quits. */
  async persist(): Promise<void> {
    if (this.persistTimer) clearTimeout(this.persistTimer);
    this.persistTimer = null;
    const session = this.session;
    if (!this.enabled || !session) return;
    await this.queue.put({ startedAt: session.startedAt, savedAt: this.now(), body: session.snapshot() }).catch(() => {});
  }

  dispose(): void {
    this.stopTimers();
  }

  private schedulePersist(): void {
    if (this.persistTimer) return;
    this.persistTimer = setTimeout(() => void this.persist(), PERSIST_DELAY_MS);
    this.persistTimer.unref?.();
  }

  private async sendQueued(): Promise<void> {
    const pending = await this.queue.pending();
    if (!pending.length) return;
    const install = await this.queue.installId();
    for (const batch of buildBatches(install, pending, this.now())) {
      if (!this.enabled) return;
      const outcome = await this.http.send(batch.body);
      if (outcome === "retry" || !this.enabled) return;
      await this.queue.acknowledge(batch.sessions);
    }
  }

  /** A checkpoint left by an app that stopped without ending its session. */
  private async finishInterrupted(): Promise<void> {
    const pending = await this.queue.pending();
    for (const entry of pending) {
      if (entry.body.final || entry.body.sid === this.session?.sid) continue;
      const lastT = entry.body.timeline.at(-1)?.t ?? 0;
      await this.queue.put({
        ...entry,
        body: {
          ...entry.body,
          seq: entry.body.seq + 1,
          final: true,
          end: { by: "unknown", code: null, durationS: Math.floor(lastT / 1_000) },
        },
      });
    }
  }

  private stopTimers(): void {
    for (const timer of [this.persistTimer, this.checkpointTimer]) if (timer) clearTimeout(timer);
    if (this.flushTimer) clearInterval(this.flushTimer);
    this.persistTimer = null;
    this.checkpointTimer = null;
    this.flushTimer = null;
  }
}
