import { createHash } from "node:crypto";
import type { TunnelServer } from "../../shared/contracts";

/**
 * Favourite servers shared between the user's apps, docs/app-platform.md.
 *
 * A server is named by its node id: the hash of its endpoint host, so every
 * protocol of one server has the same id on every platform. The account keeps
 * a sorted list of node ids; this computer keeps its own server ids for the UI
 * and reconciles both sides whenever the favourites or the servers change.
 */
export const MAX_FAVORITE_NODES = 40;
const NODE_ID = /^n1[0-9a-f]{20}$/;

export function nodeIdForHost(host: string): string | null {
  const normalized = host.trim().toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "");
  if (!normalized || normalized.length > 253) return null;
  return `n1${createHash("sha256").update(`levik-node-v1|${normalized}`).digest("hex").slice(0, 20)}`;
}

/**
 * One port of a host, docs/app-platform.md "Node ids". A relay forwards several
 * servers from one address on distinct ports, so only the port tells them apart.
 */
export function nodeIdForEndpoint(host: string, port: number): string | null {
  const normalized = host.trim().toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || !Number.isInteger(port) || port < 1 || port > 65_535) return null;
  return `n1${createHash("sha256").update(`levik-endpoint-v1|${normalized}|${port}`).digest("hex").slice(0, 20)}`;
}

/** The host that names a server and its port; local engines that point at loopback have none. */
export function serverSyncEndpoint(server: TunnelServer): { host: string; port: number | null } | null {
  const tuic = (server as { tuic?: { address?: unknown; port?: unknown } }).tuic;
  if (tuic && typeof tuic.address === "string" && tuic.address) {
    return { host: tuic.address.toLowerCase(), port: portOf(tuic.port) };
  }
  const settings = server.outbound.settings;
  let host: string | null = null;
  let port: number | null = null;
  if (isRecord(settings)) {
    if (typeof settings.address === "string" && settings.address) {
      host = settings.address;
      port = portOf(settings.port);
    }
    for (const key of ["vnext", "servers"]) {
      const list = settings[key];
      if (!host && Array.isArray(list) && isRecord(list[0]) && typeof list[0].address === "string" && list[0].address) {
        host = list[0].address;
        port = portOf(list[0].port);
      }
    }
  }
  const lower = host?.toLowerCase() ?? null;
  if (!lower || lower === "localhost" || lower === "::1" || lower.startsWith("127.")) return null;
  return { host: lower, port };
}

/** The host that names a server; local engines that point at loopback have none. */
export function serverSyncHost(server: TunnelServer): string | null {
  return serverSyncEndpoint(server)?.host ?? null;
}

export function nodeIdForServer(server: TunnelServer): string | null {
  const host = serverSyncHost(server);
  return host ? nodeIdForHost(host) : null;
}

/**
 * A server's load, docs/app-platform.md "Node load": by its host and port
 * first, which names one server behind a shared relay, then by its host.
 */
export function nodeLoadForServer(load: Readonly<Record<string, number>>, server: TunnelServer): number | null {
  const endpoint = serverSyncEndpoint(server);
  if (!endpoint) return null;
  const exact = endpoint.port === null ? null : nodeIdForEndpoint(endpoint.host, endpoint.port);
  const node = nodeIdForHost(endpoint.host);
  return (exact ? load[exact] : undefined) ?? (node ? load[node] : undefined) ?? null;
}

export function isCanonicalNodeList(value: string): boolean {
  if (!value) return true;
  const ids = value.split(",");
  return ids.length <= MAX_FAVORITE_NODES && ids.every((id) => NODE_ID.test(id))
    && ids.every((id, index) => index === 0 || (ids[index - 1] ?? "") < id);
}

export function parseNodeList(value: string | null | undefined): Set<string> {
  if (!value || !isCanonicalNodeList(value)) return new Set();
  return new Set(value.split(","));
}

/** Sorted and distinct; beyond the limit the last ids in order are left out. */
export function canonicalNodeList(ids: Iterable<string>): string {
  return [...new Set([...ids].filter((id) => NODE_ID.test(id)))].sort().slice(0, MAX_FAVORITE_NODES).join(",");
}

export function unionNodeLists(first: string, second: string): string {
  return canonicalNodeList([...parseNodeList(first), ...parseNodeList(second)]);
}

/** Server ids of this computer grouped by node; servers without a host are not shared. */
export function serversByNode(servers: readonly TunnelServer[]): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const server of servers) {
    const node = nodeIdForServer(server);
    if (!node) continue;
    result.set(node, [...(result.get(node) ?? []), server.id]);
  }
  return result;
}

export interface FavoriteState {
  /** What the account should hold. */
  nodes: Set<string>;
  /** Local favourites as they were after the last reconcile. */
  reconciledLocal: Set<string>;
}

/**
 * A node starred or unstarred here since the last reconcile is a local edit
 * and changes the account list. For every other node present on this computer
 * the account list wins. Favourites of servers without a node id stay, and
 * nodes this computer does not have are kept for the other apps.
 */
export function reconcileFavorites(
  state: FavoriteState,
  local: ReadonlySet<string>,
  byNode: ReadonlyMap<string, readonly string[]>,
): { nodes: Set<string>; local: Set<string> } {
  const nodes = new Set(state.nodes);
  const result = new Set(local);
  for (const [node, ids] of byNode) {
    const now = ids.some((id) => local.has(id));
    const before = ids.some((id) => state.reconciledLocal.has(id));
    if (now !== before) {
      if (now) nodes.add(node);
      else nodes.delete(node);
    } else if (nodes.has(node) && !now) {
      for (const id of ids) result.add(id);
    } else if (!nodes.has(node) && now) {
      for (const id of ids) result.delete(id);
    }
  }
  return { nodes: parseNodeList(canonicalNodeList(nodes)), local: result };
}

function portOf(value: unknown): number | null {
  const port = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
  return Number.isInteger(port) && port >= 1 && port <= 65_535 ? port : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
