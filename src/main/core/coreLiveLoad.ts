import type { ConnectionStatus, TunnelServer } from "../../shared/contracts";
import { currentQuality, currentRouteResource, mergeLiveLoad, parseLiveLoad, type LiveLoad, type LiveLoadAnswer, type RouteResource } from "../platform/liveLoad";
import { presenceReport, type PresenceReport } from "../platform/liveEvents";
import type { RustCore } from "./rustCore";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function numericMap(value: unknown, min = Number.NEGATIVE_INFINITY, max = Number.POSITIVE_INFINITY): value is Record<string, number> {
  return record(value) && Object.keys(value).length <= 200 && Object.entries(value).every(([key, item]) => /^n1[0-9a-f]{20}$/.test(key)
    && typeof item === "number" && Number.isFinite(item) && item >= min && item <= max);
}

function route(value: unknown): value is RouteResource {
  return record(value) && typeof value.id === "string" && /^r1[0-9a-f]{20}$/.test(value.id)
    && Array.isArray(value.path) && value.path.length >= 1 && value.path.length <= 16
    && value.path.every((id: unknown) => typeof id === "string" && /^n1[0-9a-f]{20}$/.test(id))
    && typeof value.complete === "boolean" && typeof value.state === "string" && ["healthy", "degraded", "overloaded", "unknown"].includes(value.state)
    && [value.ageSeconds, value.resourceLoad, value.resourceHeadroom].every((item) => item === null || (typeof item === "number" && Number.isFinite(item)));
}

function routes(value: unknown): boolean {
  return record(value) && Object.entries(value).every(([key, item]) => /^n1[0-9a-f]{20}$/.test(key) && route(item));
}

type ParsedLoad = NonNullable<ReturnType<typeof parseLiveLoad>>;
function parsedLoad(value: unknown): value is ParsedLoad {
  return record(value) && numericMap(value.load, 0, 1) && Array.isArray(value.full) && value.full.length <= 200
    && value.full.every((id: unknown) => typeof id === "string" && /^n1[0-9a-f]{20}$/.test(id))
    && (value.quality === null || numericMap(value.quality, 0.5, 2)) && (value.routes === undefined || routes(value.routes));
}

function loadState(value: unknown): value is LiveLoad | null {
  return value === null || (record(value) && numericMap(value.quality, 0.5, 2)
    && typeof value.fetchedAt === "number" && Number.isFinite(value.fetchedAt)
    && (value.qualityAt === null || (typeof value.qualityAt === "number" && Number.isFinite(value.qualityAt)))
    && (value.etag === null || typeof value.etag === "string")
    && (value.routesAt === undefined || (typeof value.routesAt === "number" && Number.isFinite(value.routesAt))) && parsedLoad(value));
}

/** Only decisions cross this bridge; the caller keeps one network request and its timers. */
export class CoreLiveLoad {
  constructor(private readonly current: () => RustCore) {}

  parse(value: unknown): ReturnType<typeof parseLiveLoad> {
    return this.current().run("liveLoad.parseLiveLoad", value, () => parseLiveLoad(value),
      (item): item is ReturnType<typeof parseLiveLoad> => item === null || parsedLoad(item));
  }

  merge(previous: LiveLoad | null, answer: LiveLoadAnswer, now: number, throughTunnel: boolean): LiveLoad | null {
    return this.current().run("liveLoad.mergeLiveLoad", { previous, answer, now, throughTunnel },
      () => mergeLiveLoad(previous, answer, now, throughTunnel), loadState);
  }

  currentQuality(state: LiveLoad | null, now: number): Record<string, number> {
    return this.current().run("liveLoad.currentQuality", { state, now }, () => currentQuality(state, now), (value): value is Record<string, number> => numericMap(value, 0.5, 2));
  }

  currentRouteResource(state: LiveLoad | null, keys: readonly (string | null)[], now: number): RouteResource | null {
    return this.current().run("liveLoad.currentRouteResource", { state, keys, now }, () => currentRouteResource(state, keys, now),
      (item): item is RouteResource | null => item === null || route(item));
  }

  presenceReport(status: ConnectionStatus, server: TunnelServer | null): PresenceReport {
    return this.current().run("liveEvents.presenceReport", { status, server }, () => presenceReport(status, server),
      (item): item is PresenceReport => record(item) && typeof item.vpnConnected === "boolean"
        && (item.nodeId === null || typeof item.nodeId === "string") && (item.country === null || typeof item.country === "string"));
  }
}
