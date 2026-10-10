import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AppAnnouncement } from "../../shared/contracts";
import { TELEMETRY_ORIGINS } from "../telemetry/telemetryClient";

/**
 * Anonymous app configuration from the website, docs/app-platform.md:
 * switches, announcements and the protocols that work best on the current
 * operator. Requests carry only the platform and version, never an account,
 * device or install identifier.
 */

export type DesktopPlatform = "windows" | "macos" | "linux";

export interface RemoteFlag {
  enabled: boolean;
  rolloutPercent: number;
}

export interface ProtocolAdvice {
  preferred: string[];
  avoid: string[];
}

export interface RemoteConfig {
  flags: Record<string, RemoteFlag>;
  announcements: AppAnnouncement[];
  protocols: ProtocolAdvice | null;
  refreshAfterSeconds: number;
}

export interface StoredRemoteConfig {
  /** The server response as received; parsed again on load. */
  response: unknown;
  config: RemoteConfig;
  fetchedAt: number;
  /** Advice measured outside the tunnel; through it the server sees a Levik node. */
  advice: ProtocolAdvice | null;
  adviceAt: number | null;
}

/** Advice describes the operator at the time; an old one may be about another network. */
export const PROTOCOL_ADVICE_TTL_MS = 6 * 60 * 60 * 1_000;
const MIN_REFRESH_S = 5 * 60;
const MAX_REFRESH_S = 24 * 60 * 60;
const MAX_RESPONSE_BYTES = 64 * 1024;
const PROTOCOL = /^[a-z0-9-]{1,24}$/;
const FLAG_KEY = /^[a-z][a-z0-9_]{1,47}$/;
const ANNOUNCEMENT_ID = /^[0-9a-f-]{36}$/;

type Fetch = typeof fetch;

export function parseRemoteConfig(value: unknown): RemoteConfig | null {
  if (!isRecord(value) || value.ok !== true) return null;
  const refresh = typeof value.refreshAfterSeconds === "number" && Number.isFinite(value.refreshAfterSeconds)
    ? Math.min(MAX_REFRESH_S, Math.max(MIN_REFRESH_S, Math.round(value.refreshAfterSeconds)))
    : 15 * 60;
  const flags: Record<string, RemoteFlag> = {};
  if (isRecord(value.flags)) {
    for (const [key, flag] of Object.entries(value.flags)) {
      if (!FLAG_KEY.test(key) || !isRecord(flag) || typeof flag.enabled !== "boolean") continue;
      const percent = typeof flag.rolloutPercent === "number" ? Math.round(flag.rolloutPercent) : 100;
      flags[key] = { enabled: flag.enabled, rolloutPercent: Math.min(100, Math.max(0, percent)) };
    }
  }
  const announcements = Array.isArray(value.announcements)
    ? value.announcements.slice(0, 20).flatMap((item) => parseAnnouncement(item) ?? [])
    : [];
  return { flags, announcements, protocols: parseAdvice(value.protocols), refreshAfterSeconds: refresh };
}

function parseAnnouncement(value: unknown): AppAnnouncement | null {
  if (!isRecord(value)) return null;
  const { id, level, title, body, linkUrl, notify, startsAt, endsAt } = value;
  if (typeof id !== "string" || !ANNOUNCEMENT_ID.test(id)) return null;
  if (level !== "info" && level !== "warning" && level !== "critical") return null;
  if (typeof title !== "string" || !title.trim() || title.length > 80) return null;
  if (typeof body !== "string" || !body.trim() || body.length > 600) return null;
  if (typeof startsAt !== "string" || typeof endsAt !== "string") return null;
  const starts = Date.parse(startsAt);
  const ends = Date.parse(endsAt);
  if (!Number.isFinite(starts) || !Number.isFinite(ends) || ends <= starts) return null;
  return {
    id,
    level,
    title: title.trim(),
    body: body.trim(),
    linkUrl: typeof linkUrl === "string" && isHttpsUrl(linkUrl) ? linkUrl : null,
    notify: notify === true,
    startsAt: starts,
    endsAt: ends,
  };
}

function parseAdvice(value: unknown): ProtocolAdvice | null {
  if (!isRecord(value) || !Array.isArray(value.preferred) || !Array.isArray(value.avoid)) return null;
  const list = (items: unknown[]) => items.filter((item): item is string => typeof item === "string" && PROTOCOL.test(item)).slice(0, 16);
  return { preferred: list(value.preferred), avoid: list(value.avoid) };
}

/** Announcements to show now, without the ones the user closed. */
export function visibleAnnouncements(config: RemoteConfig | null, dismissed: ReadonlySet<string>, now: number): AppAnnouncement[] {
  return (config?.announcements ?? []).filter((item) => item.startsAt <= now && now < item.endsAt && !dismissed.has(item.id));
}

/**
 * A gradual rollout: the bucket comes from a random salt that never leaves
 * the computer, so the server cannot tell which installs got a feature.
 */
export function flagEnabled(config: RemoteConfig | null, key: string, salt: string): boolean {
  const flag = config?.flags[key];
  if (!flag?.enabled) return false;
  if (flag.rolloutPercent >= 100) return true;
  const bucket = createHash("sha256").update(`${salt}:${key}`).digest().readUInt16BE(0) % 100;
  return bucket < flag.rolloutPercent;
}

/** Advice is used only while it is fresh. */
export function currentAdvice(stored: StoredRemoteConfig | null, now: number): ProtocolAdvice | null {
  if (!stored?.advice || stored.adviceAt === null) return null;
  return now - stored.adviceAt < PROTOCOL_ADVICE_TTL_MS ? stored.advice : null;
}

/** Keeps the previous advice when this response came through the tunnel or had none. */
export function mergeFetched(
  previous: StoredRemoteConfig | null,
  fetched: { response: unknown; config: RemoteConfig },
  now: number,
  throughTunnel: boolean,
): StoredRemoteConfig {
  const fresh = !throughTunnel && fetched.config.protocols !== null;
  return {
    response: fetched.response,
    config: fetched.config,
    fetchedAt: now,
    advice: fresh ? fetched.config.protocols : previous?.advice ?? null,
    adviceAt: fresh ? now : previous?.adviceAt ?? null,
  };
}

/**
 * Narrows the automatic choice: protocols that mostly fail on this operator
 * are skipped, and those that work well are tried first. Latency still picks
 * the server within the narrowed set.
 */
export function adviceCandidates<Server>(
  servers: readonly Server[],
  advice: ProtocolAdvice | null,
  protocolOf: (server: Server) => string,
): Server[] {
  if (!advice) return [...servers];
  const avoid = new Set(advice.avoid);
  const usable = servers.filter((server) => !avoid.has(protocolOf(server)));
  const pool = usable.length ? usable : [...servers];
  const preferred = new Set(advice.preferred);
  const good = pool.filter((server) => preferred.has(protocolOf(server)));
  return good.length ? good : pool;
}

export class RemoteConfigClient {
  constructor(
    private readonly platform: DesktopPlatform,
    private readonly version: string,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  /** Tries the main domain, then the reserve one. Null when both are unreachable. */
  async fetch(): Promise<{ response: unknown; config: RemoteConfig } | null> {
    for (const origin of TELEMETRY_ORIGINS) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15_000);
      try {
        const reply = await this.fetchImpl(`${origin}/api/app/v1/config`, {
          method: "GET",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          signal: controller.signal,
          headers: { Accept: "application/json", "X-Levik-Client": `${this.platform}/${this.version}` },
        });
        if (!reply.ok) {
          // A rejected request would be rejected by the other domain too.
          if (reply.status >= 400 && reply.status < 500) return null;
          continue;
        }
        const text = await reply.text();
        if (text.length > MAX_RESPONSE_BYTES) return null;
        const response: unknown = JSON.parse(text);
        const config = parseRemoteConfig(response);
        return config ? { response, config } : null;
      } catch {
        continue;
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  }
}

/** Last configuration on disk, so announcements and advice survive a restart offline. */
export class RemoteConfigStore {
  constructor(private readonly path: string) {}

  async load(): Promise<StoredRemoteConfig | null> {
    try {
      const value: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (!isRecord(value) || typeof value.fetchedAt !== "number") return null;
      const config = parseRemoteConfig(value.response);
      if (!config) return null;
      const advice = parseAdvice(value.advice);
      return {
        response: value.response,
        config,
        fetchedAt: value.fetchedAt,
        advice,
        adviceAt: advice && typeof value.adviceAt === "number" ? value.adviceAt : null,
      };
    } catch {
      return null;
    }
  }

  async save(stored: StoredRemoteConfig): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.tmp`;
    const { response, fetchedAt, advice, adviceAt } = stored;
    await writeFile(temporary, JSON.stringify({ response, fetchedAt, advice, adviceAt }), { mode: 0o600 });
    await rename(temporary, this.path);
  }
}

function isHttpsUrl(value: string): boolean {
  if (value.length > 300) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
