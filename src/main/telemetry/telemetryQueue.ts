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
export class TelemetryQueue {
  private state: QueueFile | null = null;
  private writing: Promise<void> = Promise.resolve();
  // Bumped by clear(): operations that started earlier must not write again.
  private epoch = 0;

  constructor(private readonly directory: string, private readonly now: () => number = Date.now) {}

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
    && candidate.sessions.every((entry) => typeof entry === "object" && entry !== null
      && typeof entry.startedAt === "number" && typeof entry.savedAt === "number"
      && typeof entry.body === "object" && entry.body !== null && typeof entry.body.sid === "string"
      && typeof entry.body.seq === "number"
      && (entry.sentSeq === undefined || typeof entry.sentSeq === "number"));
}
