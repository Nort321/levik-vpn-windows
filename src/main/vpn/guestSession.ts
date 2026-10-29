import { networkInterfaces, type NetworkInterfaceInfo } from "node:os";
import { isIPv4 } from "node:net";
import { GUEST_INVITE_MAX_LENGTH } from "../../shared/sharing";
import { tunInbound } from "./xrayConfig";
import { XRAY_STATS_ENDPOINT } from "./xrayStats";
import { TUNNEL_HEALTH_PORT, TUNNEL_HEALTH_TAG } from "./tunnelHealth";

/** This is local, ephemeral access to a phone, never an account/subscription profile. */
export interface GuestInvitation {
  v: 1;
  host: string;
  port: number;
  method: "aes-256-gcm";
  password: string;
  name: string;
  expiresAt: number;
}

export const GUEST_OUTBOUND_TAG = "levik-sharing-guest";
const PREFIX = "levik-share://v1/";
const FIELDS = ["expiresAt", "host", "method", "name", "password", "port", "v"];
const PRIVATE_DESTINATIONS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/0"];
const BAD_INVITE = "Приглашение повреждено или не поддерживается. Скопируйте его заново с экрана раздачи Levik на телефоне.";

export function privateIpv4(value: unknown): value is string {
  if (typeof value !== "string" || !isIPv4(value)) return false;
  const [a, b, , d] = value.split(".").map(Number);
  return d !== 0 && d !== 255 && (a === 10 || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168));
}

export function parseGuestInvitation(raw: string, now = Date.now()): GuestInvitation {
  if (raw.length > GUEST_INVITE_MAX_LENGTH) throw new Error(BAD_INVITE);
  const text = raw.trim();
  if (!text.startsWith(PREFIX)) throw new Error(BAD_INVITE);
  const encoded = text.slice(PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(BAD_INVITE);
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.toString("base64url") !== encoded) throw new Error(BAD_INVITE);
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error(BAD_INVITE); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(BAD_INVITE);
  const item = value as Record<string, unknown>;
  if (Object.keys(item).sort().join(",") !== FIELDS.join(",") || item.v !== 1 || !privateIpv4(item.host)
    || typeof item.port !== "number" || !Number.isInteger(item.port) || item.port < 1 || item.port > 65_535
    || item.method !== "aes-256-gcm" || typeof item.password !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(item.password)
    || Buffer.from(item.password, "base64url").length !== 32 || Buffer.from(item.password, "base64url").toString("base64url") !== item.password
    || typeof item.name !== "string" || !item.name.trim() || item.name.length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(item.name)
    || typeof item.expiresAt !== "number" || !Number.isSafeInteger(item.expiresAt)) throw new Error(BAD_INVITE);
  if (item.expiresAt <= now) throw new Error("Срок приглашения истёк. Попросите владельца телефона создать новое.");
  if (item.expiresAt > now + 62 * 60_000) throw new Error(BAD_INVITE);
  return { v: 1, host: item.host, port: item.port, method: item.method, password: item.password, name: item.name.trim(), expiresAt: item.expiresAt };
}

/** Select the local network containing the phone, not an unrelated default route. */
export function guestInterface(host: string, interfaces: NodeJS.Dict<NetworkInterfaceInfo[]> = networkInterfaces()): string {
  if (!privateIpv4(host)) throw new Error(BAD_INVITE);
  const hostIp = ipv4Number(host);
  const candidates = Object.entries(interfaces).filter(([name, entries]) =>
    !/levik|loopback|virtual|vmware|vbox|hyper-v|^tun|^tap|^wg|^utun|^docker|^veth/i.test(name)
    && entries?.some((entry) => entry.family === "IPv4" && !entry.internal && privateIpv4(entry.address)
      && isIPv4(entry.netmask) && ((ipv4Number(entry.address) & ipv4Number(entry.netmask)) >>> 0) === ((hostIp & ipv4Number(entry.netmask)) >>> 0)
      && entry.address !== host));
  if (candidates.length !== 1) throw new Error("Не удалось однозначно найти сеть телефона. Подключитесь к его Wi-Fi и отключите другие подключения с таким же локальным адресом.");
  return candidates[0]![0];
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((sum, octet) => ((sum << 8) | Number(octet)) >>> 0, 0);
}

/** All captured traffic takes the phone; no account rules, direct outbound or failover. */
export function buildGuestConfig(invitation: GuestInvitation): Record<string, unknown> {
  return {
    log: { loglevel: "error", access: "none" },
    api: { tag: "levik-api", listen: XRAY_STATS_ENDPOINT, services: ["StatsService"] },
    dns: { tag: "levik-dns", servers: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"], queryStrategy: "UseIPv4" },
    inbounds: [tunInbound("1.1.1.1"), { tag: TUNNEL_HEALTH_TAG, listen: "127.0.0.1", port: TUNNEL_HEALTH_PORT, protocol: "http", settings: { allowTransparent: false } }],
    outbounds: [
      { tag: GUEST_OUTBOUND_TAG, protocol: "shadowsocks", settings: { servers: [{ address: invitation.host, port: invitation.port, method: invitation.method, password: invitation.password }] } },
      { tag: "levik-dns-out", protocol: "dns", settings: {} },
      { tag: "levik-block", protocol: "blackhole", settings: {} },
    ],
    routing: { domainStrategy: "IPIfNonMatch", rules: [
      { type: "field", inboundTag: ["levik-tun-in"], port: "53", outboundTag: "levik-dns-out" },
      { type: "field", inboundTag: ["levik-dns", TUNNEL_HEALTH_TAG], outboundTag: GUEST_OUTBOUND_TAG },
      { type: "field", ip: PRIVATE_DESTINATIONS, outboundTag: "levik-block" },
      { type: "field", domain: ["full:localhost", "domain:local"], outboundTag: "levik-block" },
      { type: "field", network: "tcp,udp", outboundTag: GUEST_OUTBOUND_TAG },
    ] },
    policy: { system: { statsInboundDownlink: true, statsInboundUplink: true } },
    stats: {},
  };
}
