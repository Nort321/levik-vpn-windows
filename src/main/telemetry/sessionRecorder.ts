import { randomUUID } from "node:crypto";
import type { ProtocolName } from "./codes";

export type TelemetryPlatform = "android" | "windows" | "macos" | "linux";
export type NetworkType = "wifi" | "cellular" | "ethernet" | "other" | "unknown";
export type SessionTrigger = "user" | "auto_connect" | "boot" | "always_on" | "tile" | "widget" | "untrusted_wifi" | "resume" | "unknown";
export type AttemptCause = "initial" | "reconnect" | "failover" | "network_change" | "resume" | "server_switch" | "rollback";
export type AttemptStage = "profile" | "core" | "tun" | "handshake" | "verify";
export type RecoveryAction = "reconnect_same" | "failover" | "rollback" | "lockdown" | "gave_up";
export type PowerState = "suspend" | "resume" | "doze_on" | "doze_off" | "screen_off" | "screen_on";
export type EndBy = "user" | "system" | "error" | "os_killed" | "unknown";

export type TimelineEvent =
  | { t: number; e: "attempt"; node: string; proto: ProtocolName; cause: AttemptCause }
  | { t: number; e: "connected" }
  | { t: number; e: "attempt_failed"; stage: AttemptStage; code: string }
  | { t: number; e: "probe_fail"; codes: string[]; n: number }
  | { t: number; e: "probe_ok"; afterFailures: number }
  | { t: number; e: "core_log"; code: string; count: number }
  | { t: number; e: "core_exit"; code: number | null; expected: boolean }
  | { t: number; e: "net"; type: NetworkType; state: "available" | "lost" | "changed" }
  | { t: number; e: "power"; state: PowerState }
  | { t: number; e: "recovery"; action: RecoveryAction }
  | { t: number; e: "pause" }
  | { t: number; e: "unpause" };

export interface SessionSettings {
  killSwitch: boolean;
  autoRecovery: boolean;
  splitTunnel: boolean;
  batteryUnrestricted?: boolean;
}

export interface SessionClient {
  platform: TelemetryPlatform;
  app: string;
  os: string;
  oem?: string;
}

/** Wire format, docs/connection-telemetry.md. */
export interface TelemetrySessionBody {
  v: 1;
  sid: string;
  seq: number;
  final: boolean;
  ageS: number;
  client: SessionClient;
  net: { type: NetworkType; token: string | null };
  trigger: SessionTrigger;
  settings: SessionSettings;
  timeline: TimelineEvent[];
  end?: { by: EndBy; code: string | null; durationS: number };
}

export const MAX_TIMELINE_EVENTS = 200;
// The first events explain how a session started; the rest keeps the latest.
const KEPT_HEAD_EVENTS = 120;
const CODE = /^[a-z0-9_.:-]{1,48}$/;

function safeCode(code: string): string {
  return CODE.test(code) ? code : "other";
}

/** One connection session, from Connect until the tunnel is given up. */
export class SessionRecorder {
  readonly sid = randomUUID();
  /** Wall-clock start; ageS is recomputed from it when a queued report is sent. */
  readonly startedAt: number;
  private readonly timeline: TimelineEvent[] = [];
  private readonly pendingCoreLogs = new Map<string, number>();
  private seq = 0;
  private netType: NetworkType = "unknown";
  private token: string | null = null;
  private probeFailures = 0;
  private ended: TelemetrySessionBody["end"] | undefined;

  constructor(
    private readonly client: SessionClient,
    private readonly trigger: SessionTrigger,
    private settings: SessionSettings,
    private readonly now: () => number = Date.now,
  ) {
    this.startedAt = now();
  }

  get finished(): boolean {
    return this.ended !== undefined;
  }

  setNetwork(type: NetworkType): void {
    this.netType = type;
  }

  get hasNetworkToken(): boolean {
    return this.token !== null;
  }

  setNetworkToken(token: string | null): void {
    this.token = token;
  }

  updateSettings(settings: SessionSettings): void {
    this.settings = settings;
  }

  attempt(node: string, proto: ProtocolName, cause: AttemptCause): void {
    this.push({ t: 0, e: "attempt", node: node.slice(0, 160), proto, cause });
  }

  connected(): void {
    this.probeFailures = 0;
    this.push({ t: 0, e: "connected" });
  }

  attemptFailed(stage: AttemptStage, code: string): void {
    this.push({ t: 0, e: "attempt_failed", stage, code: safeCode(code) });
  }

  probeFailed(codes: readonly string[]): void {
    this.probeFailures++;
    const unique = [...new Set(codes.map(safeCode))].slice(0, 4);
    this.push({ t: 0, e: "probe_fail", codes: unique.length ? unique : ["other"], n: Math.min(this.probeFailures, 1_000) });
  }

  probeSucceeded(): void {
    if (this.probeFailures === 0) return;
    this.push({ t: 0, e: "probe_ok", afterFailures: Math.min(this.probeFailures, 1_000) });
    this.probeFailures = 0;
  }

  /** Core log codes are counted and written as one event before the next one. */
  coreLog(code: string): void {
    if (this.ended) return;
    const safe = safeCode(code);
    this.pendingCoreLogs.set(safe, Math.min((this.pendingCoreLogs.get(safe) ?? 0) + 1, 100_000));
  }

  coreExit(code: number | null, expected: boolean): void {
    this.push({ t: 0, e: "core_exit", code, expected });
  }

  network(type: NetworkType, state: "available" | "lost" | "changed"): void {
    this.push({ t: 0, e: "net", type, state });
  }

  power(state: PowerState): void {
    this.push({ t: 0, e: "power", state });
  }

  recovery(action: RecoveryAction): void {
    this.push({ t: 0, e: "recovery", action });
  }

  end(by: EndBy, code: string | null): void {
    if (this.ended) return;
    this.flushCoreLogs();
    this.ended = { by, code: code === null ? null : safeCode(code), durationS: this.elapsedSeconds() };
  }

  /** A checkpoint; every call gets a higher seq so the server keeps the latest. */
  snapshot(): TelemetrySessionBody {
    if (!this.ended) this.flushCoreLogs();
    const body: TelemetrySessionBody = {
      v: 1,
      sid: this.sid,
      seq: this.seq++,
      final: this.ended !== undefined,
      ageS: this.elapsedSeconds(),
      client: { ...this.client },
      net: { type: this.netType, token: this.token },
      trigger: this.trigger,
      settings: { ...this.settings },
      timeline: this.timeline.map((event) => ({ ...event })),
    };
    if (this.ended) body.end = { ...this.ended };
    return body;
  }

  private elapsedSeconds(): number {
    return Math.max(0, Math.floor((this.now() - this.startedAt) / 1_000));
  }

  private flushCoreLogs(): void {
    if (this.pendingCoreLogs.size === 0) return;
    const t = this.offset();
    for (const [code, count] of this.pendingCoreLogs) this.append({ t, e: "core_log", code, count });
    this.pendingCoreLogs.clear();
  }

  private push(event: TimelineEvent): void {
    if (this.ended) return;
    this.flushCoreLogs();
    this.append({ ...event, t: this.offset() });
  }

  private append(event: TimelineEvent): void {
    if (this.timeline.length >= MAX_TIMELINE_EVENTS) this.timeline.splice(KEPT_HEAD_EVENTS, 1);
    this.timeline.push(event);
  }

  private offset(): number {
    const previous = this.timeline.at(-1)?.t ?? 0;
    return Math.max(previous, this.now() - this.startedAt);
  }
}
