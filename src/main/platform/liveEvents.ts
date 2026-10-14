import { EventEmitter } from "node:events";
import { nodeIdForServer } from "./favoriteNodes";
import type { ConnectionStatus, TunnelServer } from "../../shared/contracts";

/**
 * Live hints from /api/mobile/v1/events, docs/app-platform.md "Live events".
 * An event only names what changed; the app fetches it. "ready" (every new
 * stream) and "resync" mean: fetch everything, something may have been missed.
 */
export const LIVE_EVENTS = ["ready", "resync", "settings", "devices", "presence", "config"] as const;
export type LiveEvent = (typeof LIVE_EVENTS)[number];

const MAX_LINE = 4_096;

/** Incremental text/event-stream parser; returns the names of completed events. */
export class EventStreamParser {
  private buffer = "";
  private name = "message";

  push(chunk: string): LiveEvent[] {
    this.buffer += chunk;
    const events: LiveEvent[] = [];
    for (;;) {
      const end = this.buffer.search(/\r\n|\r|\n/);
      if (end < 0) break;
      const line = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(this.buffer.startsWith("\r\n", end) ? end + 2 : end + 1);
      if (line === "") {
        if ((LIVE_EVENTS as readonly string[]).includes(this.name)) events.push(this.name as LiveEvent);
        this.name = "message";
      } else if (line.startsWith("event:")) {
        this.name = line.slice(6).trim();
      }
    }
    // A line longer than any event the server sends means a broken stream.
    if (this.buffer.length > MAX_LINE) throw new Error("event stream line too long");
    return events;
  }
}

/** The server pings every 25 s; this long without a byte means the connection is gone. */
export const IDLE_TIMEOUT_MS = 70_000;
const RETRY_DELAYS_MS = [2_000, 5_000, 15_000, 30_000, 60_000];

export type OpenStream = (signal: AbortSignal) => Promise<ReadableStream<Uint8Array>>;

export interface LiveEventsEvents {
  event: [LiveEvent];
  /** The server rejected the session; the stream stays stopped. */
  unauthorized: [];
}

/**
 * Keeps one event stream open while started. Each new stream starts with
 * "ready"; failures reconnect with a growing delay.
 */
export class LiveEvents extends EventEmitter<LiveEventsEvents> {
  private controller: AbortController | null = null;
  private running = false;
  private failures = 0;
  private retry: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly open: OpenStream,
    private readonly isUnauthorized: (error: unknown) => boolean,
    private readonly random: () => number = Math.random,
  ) {
    super();
  }

  get active(): boolean {
    return this.running;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.failures = 0;
    void this.loop();
  }

  stop(): void {
    this.running = false;
    if (this.retry) clearTimeout(this.retry);
    this.retry = null;
    this.controller?.abort();
    this.controller = null;
  }

  /** After a network change: drop the stream at once instead of waiting for the idle timeout. */
  reconnectNow(): void {
    if (!this.running) return;
    this.failures = 0;
    if (this.retry) {
      clearTimeout(this.retry);
      this.retry = null;
      void this.loop();
    } else {
      this.controller?.abort();
    }
  }

  private async loop(): Promise<void> {
    if (!this.running) return;
    const controller = new AbortController();
    this.controller = controller;
    let received = false;
    try {
      const stream = await this.open(controller.signal);
      const reader = stream.getReader();
      const decoder = new TextDecoder();
      const parser = new EventStreamParser();
      let idle = setTimeout(() => controller.abort(), IDLE_TIMEOUT_MS);
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          clearTimeout(idle);
          idle = setTimeout(() => controller.abort(), IDLE_TIMEOUT_MS);
          for (const event of parser.push(decoder.decode(chunk.value, { stream: true }))) {
            received = true;
            this.emit("event", event);
          }
        }
      } finally {
        clearTimeout(idle);
        reader.releaseLock();
      }
    } catch (error) {
      if (this.isUnauthorized(error)) {
        this.running = false;
        this.emit("unauthorized");
        return;
      }
    } finally {
      if (this.controller === controller) this.controller = null;
    }
    if (!this.running) return;
    // A stream that delivered events ended normally (lifetime) or broke later: retry soon.
    this.failures = received ? 0 : this.failures + 1;
    const base = RETRY_DELAYS_MS[Math.min(this.failures, RETRY_DELAYS_MS.length - 1)] ?? 60_000;
    this.retry = setTimeout(() => {
      this.retry = null;
      void this.loop();
    }, base + Math.floor(this.random() * base * 0.3));
  }
}

export interface PresenceReport {
  vpnConnected: boolean;
  nodeId: string | null;
  country: string | null;
}

/** What the devices page shows for this computer. No address, no server name. */
export function presenceReport(status: ConnectionStatus, server: TunnelServer | null): PresenceReport {
  if (status !== "connected" || !server) return { vpnConnected: false, nodeId: null, country: null };
  const country = /^[A-Za-z]{2}$/.test(server.countryCode) ? server.countryCode.toUpperCase() : null;
  return { vpnConnected: true, nodeId: nodeIdForServer(server), country };
}

export function samePresence(left: PresenceReport | null, right: PresenceReport): boolean {
  return left !== null && left.vpnConnected === right.vpnConnected &&
    left.nodeId === right.nodeId && left.country === right.country;
}
