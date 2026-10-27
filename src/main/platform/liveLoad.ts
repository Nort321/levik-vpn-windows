import { serviceEndpoints } from "./serviceEndpoints";

/**
 * The live part of the app configuration, docs/app-platform.md "Node load":
 * how busy each node is now, which nodes stayed full, and how each node works
 * from the user's operator. About a kilobyte; asked for before an automatic
 * connection and while one runs, never in the background otherwise.
 */

export interface LiveLoad {
  /** 0..1 by node id. */
  load: Record<string, number>;
  /** Node ids that take no new automatic connections. */
  full: string[];
  /** Factor by node id, 1 typical; kept from the last answer outside the tunnel. */
  quality: Record<string, number>;
  fetchedAt: number;
  /** When [quality] was measured on the user's own network; null without one. */
  qualityAt: number | null;
  etag: string | null;
}

/** A load answer is asked for again after this. */
export const LIVE_LOAD_MAX_AGE_MS = 60_000;
/** While an automatic connection runs: often enough to notice a full node, rarely enough to cost nothing. */
export const LIVE_LOAD_CONNECTED_EVERY_MS = 10 * 60_000;
/** Quality describes the operator at the time; an old one may be about another network. */
export const QUALITY_TTL_MS = 2 * 60 * 60_000;
/** A website without the endpoint is asked again only after this. */
const UNSUPPORTED_RETRY_MS = 60 * 60_000;
const MAX_RESPONSE_BYTES = 32 * 1024;
const NODE_ID = /^n1[0-9a-f]{20}$/;
const MAX_NODES = 200;
const ETAG = /^"[A-Za-z0-9_-]{1,64}"$/;

type Fetch = typeof fetch;

export type LiveLoadAnswer =
  | { kind: "fresh"; load: Record<string, number>; full: string[]; quality: Record<string, number> | null; etag: string | null }
  | { kind: "same" }
  | { kind: "unsupported" };

export function parseLiveLoad(value: unknown): { load: Record<string, number>; full: string[]; quality: Record<string, number> | null } | null {
  if (!isRecord(value) || value.ok !== true) return null;
  return {
    load: numbers(value.load, 0, 1),
    full: Array.isArray(value.full)
      ? value.full.filter((item): item is string => typeof item === "string" && NODE_ID.test(item)).slice(0, MAX_NODES)
      : [],
    // null: the answer came through the tunnel and says nothing about the operator.
    quality: value.quality === null || value.quality === undefined ? null : numbers(value.quality, 0.5, 2),
  };
}

function numbers(value: unknown, min: number, max: number): Record<string, number> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(Object.entries(value)
    .filter((entry): entry is [string, number] => NODE_ID.test(entry[0]) && typeof entry[1] === "number" && entry[1] >= min && entry[1] <= max)
    .slice(0, MAX_NODES));
}

/** The next state after an answer; [throughTunnel] answers keep the previous quality. */
export function mergeLiveLoad(previous: LiveLoad | null, answer: LiveLoadAnswer, now: number, throughTunnel: boolean): LiveLoad | null {
  if (answer.kind === "unsupported") return previous;
  if (answer.kind === "same") return previous ? { ...previous, fetchedAt: now } : null;
  const fresh = !throughTunnel && answer.quality !== null;
  return {
    load: answer.load,
    full: answer.full,
    quality: fresh ? answer.quality! : previous?.quality ?? {},
    fetchedAt: now,
    qualityAt: fresh ? now : previous?.qualityAt ?? null,
    etag: answer.etag,
  };
}

/** Quality while it is fresh. */
export function currentQuality(state: LiveLoad | null, now: number): Record<string, number> {
  if (!state || state.qualityAt === null || now - state.qualityAt >= QUALITY_TTL_MS) return {};
  return state.quality;
}

export class LiveLoadClient {
  private unsupportedUntil = 0;

  constructor(
    private readonly platform: string,
    private readonly version: string,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  /** Null when no host answered; "unsupported" while the website does not have the endpoint yet. */
  async fetch(etag: string | null, now = Date.now()): Promise<LiveLoadAnswer | null> {
    if (now < this.unsupportedUntil) return { kind: "unsupported" };
    for (const origin of serviceEndpoints().apiOrigins) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8_000);
      try {
        const headers: Record<string, string> = { Accept: "application/json", "X-Levik-Client": `${this.platform}/${this.version}` };
        if (etag) headers["If-None-Match"] = etag;
        const reply = await this.fetchImpl(`${origin}/api/app/v1/load`, {
          method: "GET",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          signal: controller.signal,
          headers,
        });
        if (reply.status === 304) return { kind: "same" };
        if (reply.status === 404) {
          // An older website: the config's node load still works meanwhile.
          this.unsupportedUntil = now + UNSUPPORTED_RETRY_MS;
          return { kind: "unsupported" };
        }
        if (!reply.ok) {
          if (reply.status >= 400 && reply.status < 500) return null;
          continue;
        }
        const text = await reply.text();
        if (text.length > MAX_RESPONSE_BYTES) return null;
        const parsed = parseLiveLoad(JSON.parse(text) as unknown);
        if (!parsed) return null;
        const tag = reply.headers.get("etag");
        return { kind: "fresh", ...parsed, etag: tag && ETAG.test(tag) ? tag : null };
      } catch {
        continue;
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
