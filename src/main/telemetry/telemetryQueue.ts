import { isNativeTelemetryQueue, type NativeTelemetryQueue, type OpenTelemetryQueue } from "../core/nativeTelemetry";
import type { CoreMode, RustCore } from "../core/rustCore";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { TelemetrySessionBody } from "./sessionRecorder";

export interface QueuedSession {
  /** Wall-clock session start, for ageS at send time. */
  startedAt: number;
  savedAt: number;
  body: TelemetrySessionBody;
  /** The checkpoint the server already has; kept until a final report replaces it. */
  sentSeq?: number;
}

interface QueueFile {
  version: 1;
  install: { id: string; day: string };
  sessions: QueuedSession[];
}

export const MAX_QUEUE_AGE_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_QUEUED_SESSIONS = 300;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function utcDay(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Anonymous reports waiting to be sent. The file holds no account or device
 * data, so it is plain JSON; writes are serialized and atomic.
 */
class TypeScriptTelemetryQueue implements QueueBackend {
  private state: QueueFile | null = null;
  private writing: Promise<void> = Promise.resolve();
  // Bumped by clear(): operations that started earlier must not write again.
  private epoch = 0;

  constructor(private readonly directory: string, private readonly now: () => number = Date.now, initial?: QueueFile) {
    if (initial) this.state = structuredClone(initial);
  }

  async snapshot(): Promise<string> { return JSON.stringify(await this.load()); }

  /** A random identifier replaced every UTC day; see "Identifiers" in the contract. */
  async installId(): Promise<string> {
    const epoch = this.epoch;
    const state = await this.load();
    const day = utcDay(this.now());
    if (state.install.day !== day) {
      state.install = { id: randomUUID(), day };
      await this.save(epoch);
    }
    return state.install.id;
  }

  /** Keeps only the latest checkpoint of each session. */
  async put(entry: QueuedSession): Promise<void> {
    const epoch = this.epoch;
    const state = await this.load();
    if (epoch !== this.epoch) return;
    const index = state.sessions.findIndex((item) => item.body.sid === entry.body.sid);
    if (index >= 0) {
      if (state.sessions[index]!.body.seq >= entry.body.seq) return;
      state.sessions[index] = entry;
    } else {
      state.sessions.push(entry);
    }
    this.prune(state);
    await this.save(epoch);
  }

  /** Checkpoints the server does not have yet. */
  async pending(): Promise<QueuedSession[]> {
    return (await this.all()).filter((entry) => entry.sentSeq === undefined || entry.body.seq > entry.sentSeq);
  }

  /** Sessions never ended, sent or not: an app killed after a send must still finalize them. */
  async unfinished(): Promise<QueuedSession[]> {
    return (await this.all()).filter((entry) => !entry.body.final);
  }

  /**
   * Final reports leave the queue once sent. A sent non-final checkpoint stays,
   * marked as sent, so a later start can finish the session it belongs to.
   */
  async acknowledge(sent: ReadonlyArray<{ sid: string; seq: number }>): Promise<void> {
    const epoch = this.epoch;
    const state = await this.load();
    const sentSeq = new Map(sent.map((item) => [item.sid, item.seq]));
    let changed = false;
    state.sessions = state.sessions.filter((entry) => {
      const seq = sentSeq.get(entry.body.sid);
      if (seq === undefined || entry.body.seq > seq) return true;
      changed = true;
      if (entry.body.final) return false;
      entry.sentSeq = entry.body.seq;
      return true;
    });
    if (changed) await this.save(epoch);
  }

  private async all(): Promise<QueuedSession[]> {
    const epoch = this.epoch;
    const state = await this.load();
    if (this.prune(state)) await this.save(epoch);
    return state.sessions.map((entry) => structuredClone(entry));
  }

  async clear(): Promise<void> {
    this.epoch++;
    this.state = emptyQueue(this.now());
    await this.enqueueWrite(() => rm(this.path(), { force: true }));
  }

  private prune(state: QueueFile): boolean {
    const before = state.sessions.length;
    const oldest = this.now() - MAX_QUEUE_AGE_MS;
    state.sessions = state.sessions.filter((entry) => entry.savedAt >= oldest).slice(-MAX_QUEUED_SESSIONS);
    return state.sessions.length !== before;
  }

  private async load(): Promise<QueueFile> {
    if (this.state) return this.state;
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(await readFile(this.path(), "utf8")) as unknown;
    } catch {
      // Missing or damaged: start over, the data is disposable.
    }
    // clear() may have replaced the state while the file was being read.
    this.state ??= isQueueFile(parsed) ? parsed : emptyQueue(this.now());
    return this.state;
  }

  private save(epoch: number): Promise<void> {
    const state = this.state;
    if (!state || epoch !== this.epoch) return Promise.resolve();
    const contents = JSON.stringify(state);
    return this.enqueueWrite(async () => {
      await mkdir(this.directory, { recursive: true });
      const temporary = `${this.path()}.${process.pid}.tmp`;
      await writeFile(temporary, contents, { mode: 0o600 });
      await rename(temporary, this.path());
    });
  }

  private enqueueWrite(write: () => Promise<void>): Promise<void> {
    const next = this.writing.then(write);
    this.writing = next.catch(() => {});
    return next;
  }

  private path(): string {
    return join(this.directory, "queue.json");
  }
}

function emptyQueue(now: number): QueueFile {
  return { version: 1, install: { id: randomUUID(), day: utcDay(now) }, sessions: [] };
}

function isQueueFile(value: unknown): value is QueueFile {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<QueueFile>;
  return candidate.version === 1
    && typeof candidate.install?.id === "string" && UUID.test(candidate.install.id)
    && typeof candidate.install.day === "string"
    && Array.isArray(candidate.sessions)
    && candidate.sessions.every(isQueuedSession);
}


function isQueuedSession(value: unknown): value is QueuedSession {
  if (typeof value !== "object" || value === null) return false;
  // The persisted queue is a JSON interoperability boundary. Keep the same
  // minimum fields as the existing format; additive report fields survive.
  const entry = value as Partial<QueuedSession>;
  return typeof entry.startedAt === "number" && typeof entry.savedAt === "number"
    && typeof entry.body === "object" && entry.body !== null && typeof entry.body.sid === "string"
    && typeof entry.body.seq === "number" && (entry.sentSeq === undefined || typeof entry.sentSeq === "number");
}

interface QueueBackend {
  installId(): Promise<string>;
  put(entry: QueuedSession): Promise<void>;
  pending(): Promise<QueuedSession[]>;
  unfinished(): Promise<QueuedSession[]>;
  acknowledge(sent: ReadonlyArray<{ sid: string; seq: number }>): Promise<void>;
  clear(): Promise<void>;
  snapshot(): Promise<string>;
}

class RustQueueBackend implements QueueBackend {
  constructor(private readonly native: NativeTelemetryQueue, private readonly now: () => number) {}
  snapshot(): Promise<string> { return this.native.snapshot(this.now()); }
  async installId(): Promise<string> {
    const id: unknown = await this.native.installId(this.now());
    if (typeof id !== "string" || !UUID.test(id)) throw queueFailure();
    return id;
  }
  put(entry: QueuedSession): Promise<void> { return this.native.put(JSON.stringify(entry), this.now()); }
  acknowledge(sent: ReadonlyArray<{ sid: string; seq: number }>): Promise<void> {
    return this.native.acknowledge(JSON.stringify(sent), this.now());
  }
  clear(): Promise<void> { return this.native.clear(); }
  async pending(): Promise<QueuedSession[]> { return this.entries(await this.native.pending(this.now())); }
  async unfinished(): Promise<QueuedSession[]> { return this.entries(await this.native.unfinished(this.now())); }
  private entries(text: string): QueuedSession[] {
    if (typeof text !== "string" || text.length > 64 * 1024 * 1024) throw queueFailure();
    let value: unknown;
    try { value = JSON.parse(text); } catch { throw queueFailure(); }
    if (!Array.isArray(value) || value.length > MAX_QUEUED_SESSIONS || !value.every(isQueuedSession)) throw queueFailure();
    return value;
  }
}

/** One owner at a time. A mode change transfers the *current in-memory state*,
 * including an unsaved daily id, after older writes finish. The other backend
 * never resumes an obsolete cached checkpoint. */
export class TelemetryQueue {
  private implementation: QueueBackend;
  private kind: "ts" | "rust" = "ts";
  private mode: () => CoreMode = () => "ts";
  private open: OpenTelemetryQueue | undefined;
  private unavailable = false;
  private report: () => void = () => {};
  private operation: Promise<unknown> = Promise.resolve();

  constructor(private readonly directory: string, private readonly now: () => number = Date.now) {
    this.implementation = new TypeScriptTelemetryQueue(directory, now);
  }

  useRustCore(core: RustCore, open: OpenTelemetryQueue | undefined, report: () => void): void {
    this.mode = () => core.mode; this.open = open; this.report = report; this.unavailable = false;
  }

  private async backend(): Promise<QueueBackend> {
    const desired = this.mode() === "rust" && this.open && !this.unavailable ? "rust" : "ts";
    if (desired === this.kind) return this.implementation;
    let initial: unknown;
    try { initial = JSON.parse(await this.implementation.snapshot()); if (!isQueueFile(initial)) throw queueFailure(); }
    catch {
      this.unavailable = true; this.report();
      if (this.kind === "rust") { this.implementation = new TypeScriptTelemetryQueue(this.directory, this.now); this.kind = "ts"; }
      return this.implementation;
    }
    if (desired === "ts") {
      if (this.mode() !== "rust" || !this.open || this.unavailable) { this.implementation = new TypeScriptTelemetryQueue(this.directory, this.now, initial); this.kind = "ts"; }
    } else {
      try {
        const native: unknown = await this.open?.(this.directory, JSON.stringify(initial));
        if (!isNativeTelemetryQueue(native)) throw queueFailure();
        if (this.mode() === "rust" && this.open && !this.unavailable) { this.implementation = new RustQueueBackend(native, this.now); this.kind = "rust"; }
      } catch { this.unavailable = true; this.report(); }
    }
    return this.implementation;
  }

  installId(): Promise<string> { return this.enqueue(async () => (await this.backend()).installId()); }
  async put(entry: QueuedSession): Promise<void> {
    const copy = structuredClone(entry);
    return this.enqueue(async () => (await this.backend()).put(copy));
  }
  pending(): Promise<QueuedSession[]> { return this.enqueue(async () => (await this.backend()).pending()); }
  unfinished(): Promise<QueuedSession[]> { return this.enqueue(async () => (await this.backend()).unfinished()); }
  async acknowledge(sent: ReadonlyArray<{ sid: string; seq: number }>): Promise<void> {
    const copy = sent.map((entry) => ({ ...entry }));
    return this.enqueue(async () => (await this.backend()).acknowledge(copy));
  }
  clear(): Promise<void> {
    return this.enqueue(async () => {
      try { await this.implementation.clear(); }
      catch (error) {
        if (this.kind === "ts") throw error;
        // Local deletion is idempotent. Consent withdrawal must remain usable
        // even when the optional bridge fails; all earlier writes are finished.
        const node = new TypeScriptTelemetryQueue(this.directory, this.now);
        await node.clear(); this.implementation = node; this.kind = "ts";
        this.unavailable = true; this.report();
      }
    });
  }
  private enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
    const next = this.operation.then(operation); this.operation = next.catch(() => {}); return next;
  }
}

function queueFailure(): Error { return new Error("Не удалось обработать очередь анонимных отчётов"); }
