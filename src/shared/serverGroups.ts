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

/** A server of a country: one node with its protocols and the name it has there. */
export interface CountryServer extends ServerGroup {
  /** The label from the host remark, else «Сервер N»; the remark itself for ungrouped entries. */
  label: string;
  /** False when the label is the «Сервер N» fallback. */
  labelled: boolean;
}

/**
 * Regular servers of one country, docs/app-platform.md "Server list".
 * Entries that are never grouped get one of their own with an empty country.
 */
export interface CountryGroup {
  id: string;
  countryCode: string;
  nodes: CountryServer[];
}

const LABEL_SEPARATOR = /\s+[·|]\s+/u;
const FLAGS = /[\u{1F1E6}-\u{1F1FF}]/gu;
const PROTOCOL_WORDS = /(?<![\p{L}\p{N}])(?:vless|reality|hysteria\s*2?|hy2|tuic(?:\s*v5)?)(?![\p{L}\p{N}])/giu;
const LABEL_EDGES = /^[\s\p{Extended_Pictographic}\uFE0F\u200D·|,:;()–—-]+|[\s\p{Extended_Pictographic}\uFE0F\u200D·|,:;()–—-]+$/gu;

export function groupByCountry(servers: readonly TunnelServer[]): CountryGroup[] {
  const countries: CountryGroup[] = [];
  for (const group of groupServers(servers)) {
    const country = groupedCountry(group);
    const node: CountryServer = { ...group, label: group.variants[0]!.name, labelled: true };
    const existing = country === null ? undefined : countries.find((item) => item.countryCode === country);
    if (existing) existing.nodes.push(node);
    else countries.push({ id: country === null ? group.id : `country:${country}`, countryCode: country ?? "", nodes: [node] });
  }
  for (const country of countries) {
    if (country.countryCode) nameNodes(country);
  }
  return countries;
}

/** Every protocol variant of every server of a country, in list order. */
export function countryServers(servers: readonly TunnelServer[], countryCode: string): TunnelServer[] {
  const code = countryCode.toUpperCase();
  if (!code) return [];
  return groupByCountry(servers).find((country) => country.countryCode === code)?.nodes.flatMap((node) => node.variants) ?? [];
}

/** The server's own name inside its country: `🇩🇪 Германия · Франкфурт` is «Франкфурт». */
export function serverLabel(name: string, countryCode: string): string | null {
  const text = name.replace(FLAGS, "").trim();
  const parts = text.split(LABEL_SEPARATOR);
  const rest = parts.length > 1 ? parts.slice(1).join(" · ") : withoutCountryName(text, countryCode);
  const label = rest.replace(PROTOCOL_WORDS, " ").replace(/\s{2,}/g, " ").replace(LABEL_EDGES, "");
  return label || null;
}

/** «Германия» for DE; null when the code names no region. */
export function countryName(countryCode: string, locale = "ru"): string | null {
  if (!/^[A-Z]{2}$/i.test(countryCode) || countryCode.toUpperCase() === "XX") return null;
  try {
    const name = new Intl.DisplayNames([locale], { type: "region" }).of(countryCode.toUpperCase());
    return name && name.toUpperCase() !== countryCode.toUpperCase() ? name : null;
  } catch {
    return null;
  }
}

/** The country a server is listed under; null keeps it on a card of its own. */
function groupedCountry(group: ServerGroup): string | null {
  const first = group.variants[0]!;
  if (first.name.startsWith("🏠") || serverProtocolKey(first) === "other" || serverEndpointHost(first) === null) return null;
  return countryName(group.countryCode) === null ? null : group.countryCode;
}

function nameNodes(country: CountryGroup): void {
  const seen = new Map<string, number>();
  country.nodes.forEach((node, index) => {
    const label = node.variants.map((variant) => serverLabel(variant.name, country.countryCode)).find((item) => item !== null) ?? null;
    const base = label ?? `Сервер ${index + 1}`;
    const key = base.toLocaleLowerCase("ru");
    const count = (seen.get(key) ?? 0) + 1;
    seen.set(key, count);
    node.label = count === 1 ? base : `${base} ${count}`;
    node.labelled = label !== null;
  });
}

function withoutCountryName(text: string, countryCode: string): string {
  const lower = text.toLocaleLowerCase("ru");
  for (const name of [countryName(countryCode, "ru"), countryName(countryCode, "en"), countryCode]) {
    if (!name) continue;
    const prefix = name.toLocaleLowerCase("ru");
    if (lower.startsWith(prefix) && !/[\p{L}\p{N}]/u.test(text.charAt(prefix.length))) return text.slice(prefix.length);
  }
  return text;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
