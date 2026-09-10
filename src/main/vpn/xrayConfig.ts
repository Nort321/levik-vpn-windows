import type { AppSettings, TunnelServer } from "../../shared/contracts";
import type { PreparedTunnelProfile } from "./tunnelProfile";
import { XRAY_STATS_ENDPOINT } from "./xrayStats";
import { resolveProcessCompanions } from "../../shared/processes";

const LOCAL_CIDRS = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
  "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

// More-specific half-default routes always win over a physical adapter's
// existing default route on Windows, independently of its interface metric.
const FULL_TUN_ROUTES = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

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
  const processes = resolveProcessCompanions(settings.splitTunnelProcesses);
  const processBypass = settings.splitTunnelMode === "bypass" && processes.length > 0;

  const rules: Record<string, unknown>[] = [
    ...(processBypass
      ? [{ type: "field", process: processes, network: "tcp,udp", outboundTag: "direct", ruleTag: "process-bypass" }]
      : []),
    { type: "field", ip: LOCAL_CIDRS, outboundTag: "direct" },
    ...(settings.splitTunnelMode === "only" && processes.length
      ? [{ type: "field", process: processes, network: "tcp,udp", outboundTag: server.tag }]
      : []),
    ...(settings.splitTunnelMode === "only" ? [{ type: "field", network: "tcp,udp", outboundTag: "direct" }] : []),
    ...(proxyDomains.length ? [{ type: "field", domain: unique(proxyDomains), outboundTag: server.tag }] : []),
    ...(profile.directCidrs.length ? [{ type: "field", ip: profile.directCidrs, outboundTag: "direct" }] : []),
    ...(directDomains.length ? [{ type: "field", domain: unique(directDomains), outboundTag: "direct" }] : []),
    ...(settings.routingMode === "bypassRu" ? [
      { type: "field", domain: RUSSIAN_GEOSITES, outboundTag: "direct" },
      { type: "field", ip: RUSSIAN_IPS, outboundTag: "direct" },
    ] : []),
  ];
  if (settings.routingMode === "blockedOnly" && settings.splitTunnelMode !== "only") {
    rules.push({ type: "field", network: "tcp,udp", outboundTag: "direct" });
  }

  return {
    // Temporary bypass diagnostics: Xray emits ruleTag hits (including tcp:/udp:)
    // at info level. Keep ordinary connections at the existing warning level.
    log: { loglevel: processBypass ? "info" : "warning" },
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
      { tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
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

export function bindXrayOutboundInterface(config: Record<string, unknown>, interfaceName: string): Record<string, unknown> {
  const bound = structuredClone(config);
  if (Array.isArray(bound.inbounds)) {
    for (const inbound of bound.inbounds) {
      if (isRecord(inbound) && inbound.protocol === "tun" && isRecord(inbound.settings)) {
        // Applies to TCP, UDP and Xray's local DNS sockets; never bind to TUN.
        inbound.settings.autoOutboundsInterface = interfaceName;
      }
    }
  }
  if (Array.isArray(bound.outbounds)) {
    for (const outbound of bound.outbounds) {
      if (isRecord(outbound) && outbound.tag === "direct" && outbound.protocol === "freedom") {
        // Explicit direct binding also uses the destination address family for
        // UDP sockets. sendThrough would unnecessarily pin a DHCP IP/family.
        outbound.streamSettings = { sockopt: { interface: interfaceName } };
      }
    }
  }
  return bound;
}

export function buildLockdownConfig(settings: AppSettings): Record<string, unknown> {
  return {
    log: { loglevel: "warning" },
    dns: { servers: [settings.dnsServer], queryStrategy: "UseIP" },
    inbounds: [tunInbound(settings.dnsServer)],
    outbounds: [
      { tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
      { tag: "levik-block", protocol: "blackhole", settings: {} },
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        { type: "field", ip: LOCAL_CIDRS, outboundTag: "direct" },
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
      autoSystemRoutingTable: FULL_TUN_ROUTES,
      autoOutboundsInterface: "auto",
    },
    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true },
  };
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
