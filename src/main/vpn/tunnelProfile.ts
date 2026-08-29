import { createDecipheriv, createHash } from "node:crypto";
import type { TunnelProfileEnvelope } from "../api/models";
import { decodeBase64Url } from "../../shared/base64";
import type { TunnelServer } from "../../shared/contracts";
import { DeviceIdentity } from "../security/deviceIdentity";

export interface PreparedTunnelProfile {
  profileId: string;
  subscriptionId: string;
  subscriptionExpiresAt: string | null;
  servers: TunnelServer[];
  directCidrs: string[];
  directDomains: string[];
  proxyDomains: string[];
}

interface RawTunnelProfile {
  version: number;
  profileId: string;
  subscriptionId: string;
  issuedAt: string;
  subscriptionExpiresAt?: string | null;
  source: { mediaType: string; content: string };
  routing?: { directCidrs?: string[]; directDomains?: string[]; proxyDomains?: string[] };
}

export function decryptTunnelProfile(identity: DeviceIdentity, envelope: TunnelProfileEnvelope): Buffer {
  const key = identity.decryptProfileKey(envelope.algorithm, envelope.encryptedKey);
  const iv = decodeBase64Url(envelope.iv);
  const encrypted = decodeBase64Url(envelope.ciphertext);
  const aad = decodeBase64Url(envelope.aad);
  if (key.length !== 32 || iv.length !== 12 || encrypted.length < 16) throw new Error("Некорректный шифрованный профиль");
  const authTag = encrypted.subarray(encrypted.length - 16);
  const ciphertext = encrypted.subarray(0, encrypted.length - 16);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    key.fill(0);
    iv.fill(0);
    encrypted.fill(0);
    aad.fill(0);
  }
}

export function prepareTunnelProfile(plaintext: Uint8Array, expectedSubscriptionId: string): PreparedTunnelProfile {
  if (plaintext.byteLength < 2 || plaintext.byteLength > 4 * 1024 * 1024) throw new Error("Некорректный размер профиля");
  const raw = JSON.parse(Buffer.from(plaintext).toString("utf8")) as RawTunnelProfile;
  if (raw.version !== 1 || raw.subscriptionId !== expectedSubscriptionId) throw new Error("Профиль не соответствует подписке");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(raw.profileId)) throw new Error("Некорректный идентификатор профиля");
  if (!raw.source || typeof raw.source.content !== "string") throw new Error("Профиль не содержит конфигурацию");
  const servers = parseSource(raw.source.content);
  if (servers.length === 0 || servers.length > 200) throw new Error("В профиле нет совместимых серверов");
  return {
    profileId: raw.profileId,
    subscriptionId: raw.subscriptionId,
    subscriptionExpiresAt: raw.subscriptionExpiresAt ?? null,
    servers,
    directCidrs: validateCidrs(raw.routing?.directCidrs ?? []),
    directDomains: validateDomains(raw.routing?.directDomains ?? []),
    proxyDomains: validateDomains(raw.routing?.proxyDomains ?? []),
  };
}

function parseSource(source: string): TunnelServer[] {
  const trimmed = decodeSubscriptionText(source.trim());
  if (trimmed.startsWith("{")) {
    const config = JSON.parse(trimmed) as { outbounds?: unknown[] };
    return (config.outbounds ?? []).flatMap((value, index) => outboundToServer(value, index));
  }
  return trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).flatMap((line, index) => {
    if (line.startsWith("vless://")) return [parseVless(line, index)];
    if (line.startsWith("trojan://")) return [parseTrojan(line, index)];
    if (line.startsWith("hysteria2://") || line.startsWith("hy2://")) return [parseHysteria2(line, index)];
    return [];
  });
}

function parseHysteria2(value: string, index: number): TunnelServer {
  const normalized = value.startsWith("hy2://") ? `hysteria2://${value.slice("hy2://".length)}` : value;
  const url = new URL(normalized);
  const port = Number(url.port || "443");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Некорректный порт Hysteria2");
  const auth = decodeURIComponent(url.username || url.password);
  if (!auth || auth.length > 512) throw new Error("Некорректная авторизация Hysteria2");
  const serverName = url.searchParams.get("sni") || url.hostname;
  const allowInsecure = ["1", "true"].includes((url.searchParams.get("insecure") || "").toLowerCase());
  const outbound: Record<string, unknown> = {
    protocol: "hysteria",
    settings: { version: 2, address: url.hostname, port },
    streamSettings: {
      network: "hysteria",
      security: "tls",
      tlsSettings: { serverName, allowInsecure, alpn: ["h3"] },
      hysteriaSettings: { version: 2, auth, udpIdleTimeout: 60 },
    },
  };
  return createServer(outbound, url.hash, url.hostname, index);
}

function decodeSubscriptionText(source: string): string {
  if (source.includes("://") || source.startsWith("{")) return source;
  try {
    const decoded = Buffer.from(source.replace(/\s/g, ""), "base64").toString("utf8").trim();
    return decoded.includes("://") || decoded.startsWith("{") ? decoded : source;
  } catch {
    return source;
  }
}

function parseVless(value: string, index: number): TunnelServer {
  const url = new URL(value);
  const id = decodeURIComponent(url.username);
  if (!/^[0-9a-f-]{32,36}$/i.test(id)) throw new Error("Некорректный VLESS UUID");
  const port = Number(url.port || "443");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Некорректный порт VLESS");
  const network = url.searchParams.get("type") || "tcp";
  const security = url.searchParams.get("security") || "none";
  const flow = url.searchParams.get("flow");
  const outbound: Record<string, unknown> = {
    protocol: "vless",
    settings: {
      vnext: [{
        address: url.hostname,
        port,
        users: [{ id, encryption: url.searchParams.get("encryption") || "none", ...(flow ? { flow } : {}) }],
      }],
    },
    streamSettings: buildStreamSettings(url, network, security),
  };
  return createServer(outbound, url.hash, url.hostname, index);
}

function parseTrojan(value: string, index: number): TunnelServer {
  const url = new URL(value);
  const port = Number(url.port || "443");
  const network = url.searchParams.get("type") || "tcp";
  const security = url.searchParams.get("security") || "tls";
  const outbound: Record<string, unknown> = {
    protocol: "trojan",
    settings: { servers: [{ address: url.hostname, port, password: decodeURIComponent(url.username) }] },
    streamSettings: buildStreamSettings(url, network, security),
  };
  return createServer(outbound, url.hash, url.hostname, index);
}

function buildStreamSettings(url: URL, network: string, security: string): Record<string, unknown> {
  const settings: Record<string, unknown> = { network, security };
  const serverName = url.searchParams.get("sni") || url.hostname;
  if (security === "reality") {
    settings.realitySettings = {
      serverName,
      fingerprint: url.searchParams.get("fp") || "chrome",
      publicKey: url.searchParams.get("pbk") || "",
      shortId: url.searchParams.get("sid") || "",
      spiderX: url.searchParams.get("spx") || "/",
    };
  } else if (security === "tls") {
    settings.tlsSettings = { serverName, fingerprint: url.searchParams.get("fp") || "chrome" };
  }
  if (network === "ws") settings.wsSettings = { path: url.searchParams.get("path") || "/", headers: hostHeader(url) };
  if (network === "grpc") settings.grpcSettings = { serviceName: url.searchParams.get("serviceName") || "" };
  if (network === "xhttp" || network === "splithttp") {
    settings.xhttpSettings = { path: url.searchParams.get("path") || "/", host: url.searchParams.get("host") || serverName };
  }
  return settings;
}

function hostHeader(url: URL): Record<string, string> {
  const host = url.searchParams.get("host");
  return host ? { Host: host } : {};
}

function outboundToServer(value: unknown, index: number): TunnelServer[] {
  if (!isRecord(value) || typeof value.protocol !== "string") return [];
  const protocol = value.protocol.toLowerCase();
  if (!["vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"].includes(protocol)) return [];
  const tag = typeof value.tag === "string" ? value.tag : "";
  return [createServer({ ...value }, tag, tag, index)];
}

function createServer(outbound: Record<string, unknown>, rawName: string, fallback: string, index: number): TunnelServer {
  const name = decodeURIComponent(rawName.replace(/^#/, "")).trim() || fallback || `Сервер ${index + 1}`;
  const hash = createHash("sha256").update(JSON.stringify(outbound)).digest("hex");
  const tag = `levik-server-${index}-${hash.slice(0, 10)}`;
  return { id: hash, tag, name: name.slice(0, 128), countryCode: extractCountryCode(name), outbound: { ...outbound, tag } };
}

function extractCountryCode(name: string): string {
  const regionalIndicators = [...name].filter((character) => {
    const point = character.codePointAt(0) ?? 0;
    return point >= 0x1f1e6 && point <= 0x1f1ff;
  });
  if (regionalIndicators.length >= 2) {
    return regionalIndicators.slice(0, 2).map((character) => String.fromCharCode((character.codePointAt(0) ?? 0) - 0x1f1e6 + 65)).join("");
  }
  const code = name.toUpperCase().match(/(?:^|\s|[-_(])([A-Z]{2})(?=$|\s|[-_)])/);
  if (code?.[1]) return code[1];
  const normalized = name.toLocaleLowerCase("en");
  const countryNames: ReadonlyArray<readonly [string, string]> = [
    ["germany", "DE"], ["deutschland", "DE"], ["frankfurt", "DE"],
    ["netherlands", "NL"], ["amsterdam", "NL"], ["finland", "FI"], ["helsinki", "FI"],
    ["france", "FR"], ["paris", "FR"], ["united kingdom", "GB"], ["london", "GB"],
    ["united states", "US"], ["new york", "US"], ["los angeles", "US"], ["singapore", "SG"],
    ["sweden", "SE"], ["stockholm", "SE"], ["switzerland", "CH"], ["zurich", "CH"],
    ["poland", "PL"], ["warsaw", "PL"], ["latvia", "LV"], ["riga", "LV"],
    ["russia", "RU"], ["moscow", "RU"], ["japan", "JP"], ["tokyo", "JP"],
    ["canada", "CA"], ["toronto", "CA"], ["turkey", "TR"], ["istanbul", "TR"],
  ];
  return countryNames.find(([needle]) => normalized.includes(needle))?.[1] ?? "";
}

function validateCidrs(values: string[]): string[] {
  if (values.length > 64 || values.some((value) => !/^[0-9A-Fa-f:.]+\/[0-9]{1,3}$/.test(value))) {
    throw new Error("Некорректные правила маршрутизации");
  }
  return values;
}

function validateDomains(values: string[]): string[] {
  const rulePattern = /^(?:(?:domain|full):[a-z0-9][a-z0-9.-]*|geosite:[a-z0-9][a-z0-9_-]*(?:@[a-z0-9-]+)?)$/;
  if (values.length > 500 || values.some((value) => !rulePattern.test(value))) {
    throw new Error("Некорректные доменные правила");
  }
  return values;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
