import type { QueuedSession } from "./telemetryQueue";
import type { TelemetrySessionBody } from "./sessionRecorder";

export const TELEMETRY_ORIGINS = ["https://leviknet.org", "https://leviknet.com"] as const;
export const MAX_BATCH_SESSIONS = 20;
export const MAX_BATCH_BYTES = 128 * 1024;
const MAX_AGE_S = (31 + 7) * 24 * 60 * 60;

export type SendOutcome = "sent" | "rejected" | "retry";

export interface NetworkToken {
  token: string;
  expiresAt: number;
}

type Fetch = typeof fetch;

/** Builds request bodies that respect the server's count and size limits. */
export function buildBatches(install: string, entries: readonly QueuedSession[], now: number): Array<{
  body: string;
  sessions: Array<{ sid: string; seq: number }>;
}> {
  const batches: Array<{ body: string; sessions: Array<{ sid: string; seq: number }> }> = [];
  let current: TelemetrySessionBody[] = [];
  const flush = () => {
    if (!current.length) return;
    batches.push({
      body: JSON.stringify({ install, sessions: current }),
      sessions: current.map((session) => ({ sid: session.sid, seq: session.seq })),
    });
    current = [];
  };
  const envelopeBytes = Buffer.byteLength(JSON.stringify({ install, sessions: [] }));
  let bytes = envelopeBytes;
  for (const entry of entries) {
    const session: TelemetrySessionBody = {
      ...entry.body,
      ageS: Math.min(MAX_AGE_S, Math.max(0, Math.floor((now - entry.startedAt) / 1_000))),
    };
    const size = Buffer.byteLength(JSON.stringify(session)) + 1;
    if (size + envelopeBytes > MAX_BATCH_BYTES) continue;
    if (current.length >= MAX_BATCH_SESSIONS || bytes + size > MAX_BATCH_BYTES) {
      flush();
      bytes = envelopeBytes;
    }
    current.push(session);
    bytes += size;
  }
  flush();
  return batches;
}

/**
 * Anonymous requests: no cookies, credentials or device signatures, so a
 * report cannot be tied to an account.
 */
export class TelemetryClient {
  constructor(private readonly fetchImpl: Fetch = fetch) {}

  async send(body: string): Promise<SendOutcome> {
    for (const origin of TELEMETRY_ORIGINS) {
      try {
        const response = await this.fetchImpl(new URL("/api/telemetry/v1/sessions", origin), {
          method: "POST",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(15_000),
        });
        if (response.status === 202 || response.ok) return "sent";
        if (response.status === 400 || response.status === 413 || response.status === 415) return "rejected";
        if (response.status === 429) return "retry";
      } catch {
        // Try the next origin.
      }
    }
    return "retry";
  }

  /**
   * Asks the server which operator this network belongs to. Must run before
   * the tunnel is up; through the tunnel the server answers with null.
   */
  async networkToken(): Promise<NetworkToken | null> {
    for (const origin of TELEMETRY_ORIGINS) {
      try {
        const response = await this.fetchImpl(new URL("/api/telemetry/v1/network", origin), {
          method: "GET",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          headers: { Accept: "application/json" },
          signal: AbortSignal.timeout(4_000),
        });
        if (!response.ok) continue;
        const text = await response.text();
        if (text.length > 1_024) return null;
        const value: unknown = JSON.parse(text);
        if (typeof value !== "object" || value === null || !("token" in value) || !("expiresAt" in value)) return null;
        const { token, expiresAt } = value;
        if (typeof token !== "string" || token.length > 400 || typeof expiresAt !== "string") return null;
        const expires = Date.parse(expiresAt);
        return Number.isFinite(expires) ? { token, expiresAt: expires } : null;
      } catch {
        // Try the next origin.
      }
    }
    return null;
  }
}
