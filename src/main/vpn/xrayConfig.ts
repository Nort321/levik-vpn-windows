import type { AppSettings, TunnelServer } from "../../shared/contracts";
import type { PreparedTunnelProfile } from "./tunnelProfile";
import { XRAY_STATS_ENDPOINT } from "./xrayStats";

const LOCAL_CIDRS = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
  "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

const RUSSIAN_GEOSITES = ["geosite:category-ru"];
const RUSSIAN_IPS = ["geoip:ru"];
const BLOCKED_DOMAINS = [
  "domain:instagram.com", "domain:cdninstagram.com", "domain:facebook.com", "domain:fbcdn.net",
  "domain:x.com", "domain:twitter.com", "domain:twimg.com", "domain:openai.com", "domain:chatgpt.com",
  "domain:oaistatic.com", "domain:oaiusercontent.com", "domain:claude.ai", "domain:anthropic.com",
  "domain:notion.so", "domain:notion.site", "domain:discord.com", "domain:discordapp.com",
  "domain:discord.gg", "domain:canva.com", "domain:linkedin.com", "domain:licdn.com",
  "domain:spotify.com", "domain:rutracker.org", "domain:flibusta.is", "domain:meduza.io",
  "domain:bbc.com", "domain:dw.com", "domain:svoboda.org", "domain:rferl.org",
  "domain:zona.media", "domain:theins.ru", "domain:novayagazeta.eu", "domain:holod.media",
  "domain:vpngenerator.org", "domain:ntc.party",
];
export function buildXrayConfig(
  profile: PreparedTunnelProfile,
  server: TunnelServer,
  settings: AppSettings,
): Record<string, unknown> {
  const selectedOutbound = withAntiDpi(server, settings);
  const directDomains = [...profile.directDomains];
  const proxyDomains = [...profile.proxyDomains];
  if (settings.routingMode === "blockedOnly") proxyDomains.push(...BLOCKED_DOMAINS);

  const rules: Record<string, unknown>[] = [
    { type: "field", ip: LOCAL_CIDRS, outboundTag: "levik-direct" },
    ...(settings.splitTunnelMode === "bypass" && settings.splitTunnelProcesses.length
      ? [{ type: "field", process: settings.splitTunnelProcesses, outboundTag: "levik-direct" }]
      : []),
    ...(settings.splitTunnelMode === "only" && settings.splitTunnelProcesses.length
      ? [{ type: "field", process: settings.splitTunnelProcesses, outboundTag: server.tag }]
      : []),
    ...(proxyDomains.length ? [{ type: "field", domain: unique(proxyDomains), outboundTag: server.tag }] : []),
    ...(profile.directCidrs.length ? [{ type: "field", ip: profile.directCidrs, outboundTag: "levik-direct" }] : []),
    ...(directDomains.length ? [{ type: "field", domain: unique(directDomains), outboundTag: "levik-direct" }] : []),
    ...(settings.routingMode === "bypassRu" ? [
      { type: "field", domain: RUSSIAN_GEOSITES, outboundTag: "levik-direct" },
      { type: "field", ip: RUSSIAN_IPS, outboundTag: "levik-direct" },
    ] : []),
  ];
  if (settings.routingMode === "blockedOnly" || settings.splitTunnelMode === "only") {
    rules.push({ type: "field", network: "tcp,udp", outboundTag: "levik-direct" });
  }

  return {
    log: { loglevel: "warning" },
    api: { tag: "levik-api", listen: XRAY_STATS_ENDPOINT, services: ["StatsService"] },
    dns: {
      servers: settings.useDoh
        ? [{ address: "https://1.1.1.1/dns-query", skipFallback: false }, settings.dnsServer]
        : [settings.dnsServer],
      queryStrategy: "UseIP",
    },
    inbounds: [tunInbound(settings.dnsServer)],
    outbounds: [
      selectedOutbound,
      { tag: "levik-direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
      ...(settings.antiDpiEnabled && selectedOutbound !== server.outbound ? [{
        tag: "levik-fragment",
        protocol: "freedom",
        settings: {
          domainStrategy: "AsIs",
          fragment: {
            packets: settings.antiDpiPackets,
            length: settings.antiDpiLength,
            interval: settings.antiDpiInterval,
          },
        },
      }] : []),
      { tag: "levik-block", protocol: "blackhole", settings: {} },
    ],
    routing: { domainStrategy: "IPIfNonMatch", domainMatcher: "hybrid", rules },
    policy: { system: { statsInboundDownlink: true, statsInboundUplink: true, statsOutboundDownlink: true, statsOutboundUplink: true } },
    stats: {},
  };
}

function withAntiDpi(server: TunnelServer, settings: AppSettings): Record<string, unknown> {
  if (!settings.antiDpiEnabled || server.outbound.protocol === "hysteria") return server.outbound;
  const outbound = structuredClone(server.outbound);
  const existingStream = isRecord(outbound.streamSettings) ? outbound.streamSettings : {};
  const existingSockopt = isRecord(existingStream.sockopt) ? existingStream.sockopt : {};
  outbound.streamSettings = {
    ...existingStream,
    sockopt: { ...existingSockopt, dialerProxy: "levik-fragment" },
  };
  return outbound;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function buildLockdownConfig(settings: AppSettings): Record<string, unknown> {
  return {
    log: { loglevel: "warning" },
    dns: { servers: [settings.dnsServer], queryStrategy: "UseIP" },
    inbounds: [tunInbound(settings.dnsServer)],
    outbounds: [
      { tag: "levik-direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
      { tag: "levik-block", protocol: "blackhole", settings: {} },
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        { type: "field", ip: LOCAL_CIDRS, outboundTag: "levik-direct" },
        { type: "field", network: "tcp,udp", outboundTag: "levik-block" },
      ],
    },
  };
}

function tunInbound(dnsServer: string): Record<string, unknown> {
  return {
    tag: "levik-tun-in",
    protocol: "tun",
    settings: {
      name: "LevikVPN",
      desc: "Levik VPN",
      mtu: 1500,
      gateway: ["10.89.0.1/30", "fdfe:89::1/126"],
      dns: [dnsServer],
      autoSystemRoutingTable: ["0.0.0.0/0", "::/0"],
      autoOutboundsInterface: "auto",
    },
    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: false },
  };
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
