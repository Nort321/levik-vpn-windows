import type { AppSettings, TunnelServer } from "../../shared/contracts";
import type { PreparedTunnelProfile } from "./tunnelProfile";
import { XRAY_STATS_ENDPOINT } from "./xrayStats";
import { TUNNEL_HEALTH_PORT, TUNNEL_HEALTH_TAG } from "./tunnelHealth";
import { resolveProcessCompanions } from "../../shared/processes";
import { isIP } from "node:net";

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
  "domain:discord.gg", "domain:discord.media", "domain:discordapp.net", "domain:discordcdn.com",
  "geosite:discord", "domain:canva.com", "domain:linkedin.com", "domain:licdn.com",
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
  const antiDpiOutbound = server.tuic ? server.outbound : withAntiDpi(server, settings);
  const selectedOutbound = server.tuic
    ? tuicLocalOutbound(server.tag)
    : withBootstrapResolution(withAlternateXhttpMux(antiDpiOutbound));
  const bootstrapDomains = endpointDomains(server.outbound.settings);
  const directDomains = [...profile.directDomains];
  const proxyDomains = [...profile.proxyDomains];
  if (settings.routingMode === "blockedOnly") proxyDomains.push(...BLOCKED_DOMAINS);
  const processes = resolveProcessCompanions(settings.splitTunnelProcesses);
  const processBypass = settings.splitTunnelMode === "bypass" && processes.length > 0;

  const rules: Record<string, unknown>[] = [
    // Probe the selected VPN even when application/domain rules bypass it.
    { type: "field", inboundTag: [TUNNEL_HEALTH_TAG], outboundTag: server.tag },
    // System DNS must reach the configured resolver before process/LAN bypass.
    { type: "field", inboundTag: ["levik-tun-in"], port: "53", outboundTag: "levik-dns-out" },
    { type: "field", inboundTag: ["levik-dns"], outboundTag: server.tag },
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
      tag: "levik-dns",
      servers: [
        // Resolving the VPN endpoint through that same VPN creates a cycle.
        // Only endpoint names use physical-interface HTTPS bootstrap DNS.
        ...bootstrapDomains.length ? ["1.1.1.1", "8.8.8.8"].map((ip) => ({
          address: `https+local://${ip}/dns-query`, domains: bootstrapDomains,
          skipFallback: true,
        })) : [],
        ...settings.useDoh
          ? ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
          : [settings.dnsServer],
      ],
      disableFallbackIfMatch: true,
      queryStrategy: "UseIP",
    },
    inbounds: [tunInbound(settings.dnsServer), {
      tag: TUNNEL_HEALTH_TAG, listen: "127.0.0.1", port: TUNNEL_HEALTH_PORT,
      protocol: "http", settings: { allowTransparent: false },
    }],
    outbounds: [
      selectedOutbound,
      // The pinned core answers non-address queries immediately with NODATA.
      { tag: "levik-dns-out", protocol: "dns", settings: {} },
      { tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
      ...(settings.antiDpiEnabled && antiDpiOutbound !== server.outbound ? [{
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

/**
 * Xray reaches a TUIC server through a loopback VLESS hop to the bundled
 * sing-box. VLESS carries UDP inside the TCP stream: the TUN binds Xray's UDP
 * sockets to the physical interface, so a SOCKS5 UDP relay on loopback would
 * drop DNS and QUIC. XrayManager starts the sidecar with a per-session user id
 * and rewrites this placeholder before Xray starts.
 */
export function tuicLocalOutbound(tag: string): Record<string, unknown> {
  return {
    tag,
    protocol: "vless",
    settings: { vnext: [{ address: "127.0.0.1", port: TUIC_PLACEHOLDER_PORT, users: [{ id: TUIC_PLACEHOLDER_ID, encryption: "none" }] }] },
  };
}

export const TUIC_PLACEHOLDER_PORT = 1;
export const TUIC_PLACEHOLDER_ID = "00000000-0000-4000-8000-000000000000";

function endpointDomains(value: unknown): string[] {
  if (Array.isArray(value)) return unique(value.flatMap(endpointDomains));
  if (!isRecord(value)) return [];
  return unique(Object.entries(value).flatMap(([key, item]) =>
    key === "address" && typeof item === "string" && !isIP(item)
      ? [`full:${item}`] : endpointDomains(item)));
}

function withBootstrapResolution(outbound: Record<string, unknown>): Record<string, unknown> {
  const stream = isRecord(outbound.streamSettings) ? outbound.streamSettings : {};
  const sockopt = isRecord(stream.sockopt) ? stream.sockopt : {};
  const strategy = typeof sockopt.domainStrategy === "string" && sockopt.domainStrategy !== "AsIs"
    ? sockopt.domainStrategy : "UseIPv4v6";
  return { ...outbound, streamSettings: { ...stream, sockopt: { ...sockopt, domainStrategy: strategy } } };
}

function withAlternateXhttpMux(outbound: Record<string, unknown>): Record<string, unknown> {
  if ("mux" in outbound || outbound.protocol !== "vless") return outbound;
  const stream = outbound.streamSettings;
  if (!isRecord(stream) || typeof stream.network !== "string") return outbound;
  if (!["xhttp", "splithttp"].includes(stream.network.toLowerCase())) return outbound;
  const settings = outbound.settings;
  if (!isRecord(settings) || !Array.isArray(settings.vnext) || settings.vnext.length === 0) return outbound;
  if (!settings.vnext.every((server: unknown) => isRecord(server)
    && typeof server.address === "string"
    && server.address.toLowerCase() === "leva.levikfartik.ru")) return outbound;

  // This edge requires the patched server's Mux keepalive for idle XHTTP downlinks.
  // Explicit profile settings take precedence; other hosts keep their own behavior.
  return { ...outbound, mux: { enabled: true, concurrency: 1 } };
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

export function bindXrayOutboundInterface(
  config: Record<string, unknown>,
  interfaceName: string,
  ipv6: boolean,
): Record<string, unknown> {
  const bound = structuredClone(config);
  if (Array.isArray(bound.inbounds)) {
    for (const inbound of bound.inbounds) {
      if (isRecord(inbound) && inbound.protocol === "tun" && isRecord(inbound.settings)) {
        // Applies to TCP, UDP and Xray's local DNS sockets; never bind to TUN.
        inbound.settings.autoOutboundsInterface = interfaceName;
        // Without IPv6 on the physical adapter a direct IPv6 socket cannot be
        // bound to it and is routed back into the TUN, looping forever. No
        // tunnel node has IPv6 either, so the TUN must not offer it.
        if (!ipv6) {
          inbound.settings.gateway = ipv4Only(inbound.settings.gateway);
          inbound.settings.autoSystemRoutingTable = ipv4Only(inbound.settings.autoSystemRoutingTable);
        }
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

function ipv4Only(value: unknown): unknown {
  return Array.isArray(value) ? value.filter((cidr) => typeof cidr !== "string" || !cidr.includes(":")) : value;
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
