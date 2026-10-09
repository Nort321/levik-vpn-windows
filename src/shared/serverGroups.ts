import type { TunnelServer } from "./contracts";

export type ServerProtocol = "vless" | "hysteria" | "tuic" | "other";

/** One physical server with the protocols the subscription offers for it. */
export interface ServerGroup {
  id: string;
  countryCode: string;
  /** Ordered VLESS, Hysteria 2, TUIC, then anything else. */
  variants: TunnelServer[];
}

const PROTOCOL_ORDER: readonly ServerProtocol[] = ["vless", "hysteria", "tuic", "other"];

export function serverProtocolKey(server: TunnelServer): ServerProtocol {
  if (server.tuic) return "tuic";
  const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol.toLowerCase() : "";
  if (protocol === "vless") return "vless";
  if (protocol === "hysteria" || protocol === "hysteria2" || protocol === "hy2") return "hysteria";
  if (protocol === "tuic") return "tuic";
  return "other";
}

export function serverProtocolShortLabel(server: TunnelServer): string {
  switch (serverProtocolKey(server)) {
    case "vless": return "VLESS";
    case "hysteria": return "Hysteria 2";
    case "tuic": return "TUIC";
    default: {
      const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol : "VPN";
      return protocol.toUpperCase();
    }
  }
}

export function serverEndpointHost(server: TunnelServer): string | null {
  if (server.tuic) return server.tuic.address;
  const settings = server.outbound.settings;
  if (!isRecord(settings)) return null;
  const direct = settings.address;
  if (typeof direct === "string" && direct) return direct.toLowerCase();
  for (const key of ["vnext", "servers"]) {
    const list = settings[key];
    if (Array.isArray(list) && isRecord(list[0]) && typeof list[0].address === "string" && list[0].address) {
      return list[0].address.toLowerCase();
    }
  }
  return null;
}

/**
 * Groups protocol variants of the same server. Variants merge when they share
 * the endpoint host and country; a second variant of an already present
 * protocol (for example a separate canary inbound) starts its own group.
 */
export function groupServers(servers: readonly TunnelServer[]): ServerGroup[] {
  const groups: ServerGroup[] = [];
  for (const server of servers) {
    const host = serverEndpointHost(server);
    const protocol = serverProtocolKey(server);
    const country = server.countryCode.toUpperCase();
    const existing = host === null ? undefined : groups.find((group) =>
      group.id.startsWith(`${host}|`)
      && group.countryCode === country
      && protocol !== "other"
      && !group.variants.some((variant) => serverProtocolKey(variant) === protocol));
    if (existing) {
      existing.variants.push(server);
    } else {
      groups.push({ id: `${host ?? server.id}|${groups.length}`, countryCode: country, variants: [server] });
    }
  }
  for (const group of groups) {
    group.variants.sort((left, right) =>
      PROTOCOL_ORDER.indexOf(serverProtocolKey(left)) - PROTOCOL_ORDER.indexOf(serverProtocolKey(right)));
  }
  return groups;
}

/** The variant a group connects with: the selected one, else the preferred protocol. */
export function activeVariant(group: ServerGroup, selectedServerId: string | null): TunnelServer {
  return group.variants.find((variant) => variant.id === selectedServerId) ?? group.variants[0]!;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
