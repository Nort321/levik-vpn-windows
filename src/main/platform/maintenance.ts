/**
 * Planned work on a server, docs/app-platform.md "Server maintenance": the
 * app stops choosing the server and moves off it before the window starts,
 * while the connection is idle or two minutes before the start at the latest.
 */

export interface MaintenanceWindow {
  nodeId: string;
  startsAt: number;
  endsAt: number;
}

/** From this long before the start the server is not chosen and an idle connection moves. */
export const MAINTENANCE_LEAD_MS = 15 * 60_000;
/** From this long before the start the connection moves even while busy. */
export const MAINTENANCE_FORCE_MS = 2 * 60_000;
/** A connection counts as idle below this many bytes per second, both ways together. */
export const IDLE_BYTES_PER_SECOND = 4 * 1024;
/** ...for this long. */
export const IDLE_WINDOW_MS = 20_000;

const NODE_ID = /^n1[0-9a-f]{20}$/;
const MAX_WINDOWS = 50;
const MAX_WINDOW_MS = 24 * 60 * 60_000;

export function parseMaintenance(value: unknown): MaintenanceWindow[] {
  if (!Array.isArray(value)) return [];
  const windows: MaintenanceWindow[] = [];
  for (const item of value.slice(0, MAX_WINDOWS)) {
    if (typeof item !== "object" || item === null) continue;
    const { nodeId, startsAt, endsAt } = item as Record<string, unknown>;
    if (typeof nodeId !== "string" || !NODE_ID.test(nodeId)) continue;
    if (typeof startsAt !== "string" || typeof endsAt !== "string") continue;
    const starts = Date.parse(startsAt);
    const ends = Date.parse(endsAt);
    if (!Number.isFinite(starts) || !Number.isFinite(ends) || ends <= starts || ends - starts > MAX_WINDOW_MS) continue;
    windows.push({ nodeId, startsAt: starts, endsAt: ends });
  }
  return windows;
}

/** The window that keeps the app off this node now: from the lead time before it until its end. */
export function maintenanceFor(
  windows: readonly MaintenanceWindow[],
  nodeId: string | null,
  now: number,
): MaintenanceWindow | null {
  if (!nodeId) return null;
  return windows.find((item) => item.nodeId === nodeId && now >= item.startsAt - MAINTENANCE_LEAD_MS && now < item.endsAt) ?? null;
}

/** Leaves out servers under maintenance, unless that would leave none. */
export function avoidMaintenance<Server>(
  servers: readonly Server[],
  windows: readonly MaintenanceWindow[],
  nodeIdOf: (server: Server) => string | null,
  now: number,
): Server[] {
  const usable = servers.filter((server) => !maintenanceFor(windows, nodeIdOf(server), now));
  return usable.length ? usable : [...servers];
}

export type MaintenanceMove = "stay" | "when-idle" | "now";

export function maintenanceMove(window: MaintenanceWindow | null, now: number): MaintenanceMove {
  if (!window) return "stay";
  return now >= window.startsAt - MAINTENANCE_FORCE_MS ? "now" : "when-idle";
}

/** Byte counters over the last seconds; tells whether the connection carries anything. */
export class IdleMeter {
  private samples: Array<{ at: number; bytes: number }> = [];

  record(totalBytes: number, now: number): void {
    const last = this.samples.at(-1);
    // Counters restart with a new connection.
    if (last && totalBytes < last.bytes) this.samples = [];
    this.samples.push({ at: now, bytes: totalBytes });
    const keepFrom = now - IDLE_WINDOW_MS * 2;
    while (this.samples.length > 2 && (this.samples[1]?.at ?? now) <= keepFrom) this.samples.shift();
  }

  reset(): void {
    this.samples = [];
  }

  idle(now: number): boolean {
    const first = this.samples.find((sample) => sample.at >= now - IDLE_WINDOW_MS - 1_000);
    const last = this.samples.at(-1);
    if (!first || !last || last.at - first.at < IDLE_WINDOW_MS) return false;
    const seconds = (last.at - first.at) / 1_000;
    return (last.bytes - first.bytes) / seconds < IDLE_BYTES_PER_SECOND;
  }
}
