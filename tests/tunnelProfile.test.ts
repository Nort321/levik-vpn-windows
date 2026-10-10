import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { bindXrayOutboundInterface, buildXrayConfig } from "../src/main/vpn/xrayConfig";
import type { AppSettings } from "../src/shared/contracts";

const settings: AppSettings = {
  routingMode: "bypassRu",
  automaticServer: true,
  autoReconnect: true,
  killSwitch: true,
  useDoh: true,
  dnsServer: "1.1.1.1",
  theme: "dark",
  launchAtLogin: false,
  autoConnectOnLaunch: false,
  closeToTray: true,
  preventDnsLeaks: true,
  favoriteServerIds: [],
  antiDpiEnabled: false,
  antiDpiPackets: "tlshello",
  antiDpiLength: "100-200",
  antiDpiInterval: "10-20",
  splitTunnelMode: "off",
  splitTunnelProcesses: [],
  connectionTelemetry: false,
  telemetryNoticeShown: false,
};

describe("Windows tunnel profile", () => {
  it("converts VLESS Reality share links without exposing Android dependencies", () => {
    const profile = {
      version: 1,
      profileId: "profile-1",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=public-key&sid=0123&type=tcp#DE%20Frankfurt",
      },
      routing: { directCidrs: ["203.0.113.0/24"], directDomains: ["domain:example.ru"], proxyDomains: ["geosite:category-anticensorship"] },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    expect(prepared.servers).toHaveLength(1);
    expect(prepared.servers[0]?.name).toBe("DE Frankfurt");
    expect(prepared.servers[0]?.outbound.protocol).toBe("vless");
    const config = buildXrayConfig(prepared, prepared.servers[0]!, settings);
    const inbounds = config.inbounds as Array<Record<string, unknown>>;
    expect(inbounds[0]?.protocol).toBe("tun");
    expect(inbounds[0]?.settings).toEqual(expect.objectContaining({
      autoSystemRoutingTable: ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
      autoOutboundsInterface: "auto",
    }));
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules).not.toContainEqual(expect.objectContaining({
      network: "tcp,udp",
      outboundTag: "direct",
    }));
  });

  it("rejects a profile issued for another subscription", () => {
    const profile = { version: 1, profileId: "p", subscriptionId: "one", issuedAt: new Date().toISOString(), source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" } };
    expect(() => prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "two")).toThrow(/подписке/);
  });

  it.each(["hysteria2", "hy2"])("preserves Salamander from %s subscriptions through Anti-DPI configuration", (scheme) => {
    const source = `${scheme}://secret@example.com:2443?sni=hy2.example.com&obfs=salamander&obfs-password=S%2Band%26%3DSecret#Obfuscated`;
    for (const content of [source, Buffer.from(source).toString("base64")]) {
      const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify({
        version: 1, profileId: "salamander-profile", subscriptionId: "subscription-1",
        source: { mediaType: "text/plain", content },
      })), "subscription-1");
      const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, antiDpiEnabled: true });
      expect(config).toHaveProperty("outbounds.0.streamSettings.finalmask", {
        udp: [{ type: "salamander", settings: { password: "S+and&=Secret" } }],
      });
      expect(config).toHaveProperty("outbounds.0.streamSettings.tlsSettings.serverName", "hy2.example.com");
      expect(config).toHaveProperty("outbounds.0.streamSettings.hysteriaSettings.auth", "secret");
      expect(config).toHaveProperty("outbounds.0.settings.port", 2443);
    }
  });

  it.each([
    "obfs=gecko&obfs-password=valid-password",
    "obfs=salamander",
    "obfs=salamander&obfs-password=abc",
    `obfs=salamander&obfs-password=${"x".repeat(1025)}`,
  ])("rejects unsupported or invalid Hysteria2 obfuscation instead of dropping it", (query) => {
    expect(() => prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "invalid-obfs", subscriptionId: "subscription-1",
      source: { mediaType: "text/plain", content: `hysteria2://secret@example.com:2443?${query}` },
    })), "subscription-1")).toThrow(/обфускации Hysteria2/);
  });

  it("supports Hysteria2 share links", () => {
    const profile = {
      version: 1,
      profileId: "hysteria-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "hysteria2://secret@example.com:443?sni=cdn.example.com#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam",
      },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    expect(prepared.servers[0]?.outbound.protocol).toBe("hysteria");
    expect(prepared.servers[0]?.countryCode).toBe("NL");
  });

  it("adds Anti-DPI fragmentation and process routing", () => {
    const profile = {
      version: 1,
      profileId: "routing-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#DE%20Berlin",
      },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    const config = buildXrayConfig(prepared, prepared.servers[0]!, {
      ...settings,
      antiDpiEnabled: true,
      splitTunnelMode: "bypass",
      splitTunnelProcesses: ["chrome.exe"],
    });
    const outbounds = config.outbounds as Array<Record<string, unknown>>;
    const inbounds = config.inbounds as Array<Record<string, unknown>>;
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(config.api).toEqual(expect.objectContaining({ services: ["StatsService"] }));
    expect(outbounds.some((outbound) => outbound.tag === "levik-fragment")).toBe(true);
    expect(routing.rules).toContainEqual(expect.objectContaining({ process: ["chrome.exe"], outboundTag: "direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ ip: ["geoip:ru"], outboundTag: "direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ domain: ["geosite:category-ru"], outboundTag: "direct" }));
    expect((inbounds[0]?.sniffing as { destOverride: string[] }).destOverride).not.toContain("fakedns");
  });

  it("bypasses Overwatch and its companions while keeping Battle.net and Agent on the VPN", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "battle-net", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
    })), "subscription-1");
    const server = profile.servers[0]!;
    const config = buildXrayConfig(profile, server, {
      ...settings, routingMode: "global", splitTunnelMode: "bypass", splitTunnelProcesses: ["overwatch.exe"],
    });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules.slice(3)).toEqual([
      { type: "field", process: ["overwatch.exe", "Overwatch Launcher.exe", "VivoxVoiceService.exe"], network: "tcp,udp", outboundTag: "direct", ruleTag: "process-bypass" },
      { type: "field", ip: expect.arrayContaining(["127.0.0.0/8", "::1/128"]), outboundTag: "direct" },
    ]);
    // Unmatched Battle.net/Agent internet traffic uses Xray's first outbound.
    expect((config.outbounds as Array<Record<string, unknown>>)[0]?.tag).toBe(server.tag);
  });

  it.each(["global", "bypassRu", "blockedOnly"] as const)("routes only selected applications before domain policies in %s mode", (routingMode) => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "process-only", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
      routing: { proxyDomains: ["domain:vivox.com"] },
    })), "subscription-1");
    const server = profile.servers[0]!;
    const config = buildXrayConfig(profile, server, {
      ...settings, routingMode, splitTunnelMode: "only", splitTunnelProcesses: ["overwatch.exe", "Browser Helper.EXE"],
    });
    const rules = (config.routing as { rules: Array<Record<string, unknown>> }).rules;
    expect(rules[4]).toEqual({ type: "field", process: ["overwatch.exe", "Browser Helper.EXE", "Overwatch Launcher.exe", "VivoxVoiceService.exe"], network: "tcp,udp", outboundTag: server.tag });
    expect(rules[5]).toEqual({ type: "field", network: "tcp,udp", outboundTag: "direct" });
    expect(rules.findIndex((rule) => rule.domain)).toBeGreaterThan(5);
    const empty = buildXrayConfig(profile, server, { ...settings, routingMode, splitTunnelMode: "only", splitTunnelProcesses: [] });
    expect((empty.routing as { rules: typeof rules }).rules[4]).toEqual({ type: "field", network: "tcp,udp", outboundTag: "direct" });
    expect((config.inbounds as Array<{ sniffing: { routeOnly: boolean } }>)[0]?.sniffing.routeOnly).toBe(true);
  });

  it.each(["off", "only", "bypass"] as const)("forces health probes through the VPN with split mode %s", (splitTunnelMode) => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "health", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
    })), "subscription-1");
    const config = buildXrayConfig(profile, profile.servers[0]!, {
      ...settings, splitTunnelMode, splitTunnelProcesses: ["Levik VPN.exe"], routingMode: "blockedOnly",
    });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules[0]).toEqual({ type: "field", inboundTag: ["levik-health"], outboundTag: profile.servers[0]!.tag });
    expect(config.inbounds).toContainEqual({
      tag: "levik-health", listen: "127.0.0.1", port: 47186,
      protocol: "http", settings: { allowTransparent: false },
    });
  });

  it.each(["global", "bypassRu", "blockedOnly"] as const)("prioritizes VALORANT TCP/UDP bypass in %s mode", (routingMode) => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "voice", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
      routing: { proxyDomains: ["domain:vivox.com"] },
    })), "subscription-1");
    const processes = ["VALORANT-Win64-Shipping.exe", "VALORANT.exe", "RiotClientServices.exe"];
    const config = buildXrayConfig(profile, profile.servers[0]!, {
      ...settings, routingMode, splitTunnelMode: "bypass", splitTunnelProcesses: processes,
    });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules[3]).toEqual({ type: "field", process: processes, network: "tcp,udp", outboundTag: "direct", ruleTag: "process-bypass" });
    expect(routing.rules.findIndex((rule) => !rule.inboundTag && rule.outboundTag === profile.servers[0]!.tag)).toBeGreaterThan(0);
    expect(config.log).toEqual({ loglevel: "info" });

    for (const splitTunnelMode of ["off", "only", "bypass"] as const) {
      const inactive = buildXrayConfig(profile, profile.servers[0]!, { ...settings, splitTunnelMode, splitTunnelProcesses: [] });
      expect(inactive.log).toEqual({ loglevel: "warning" });
      expect((inactive.routing as typeof routing).rules.some((rule) => rule.ruleTag === "process-bypass")).toBe(false);
    }
    const only = buildXrayConfig(profile, profile.servers[0]!, { ...settings, splitTunnelMode: "only", splitTunnelProcesses: processes });
    expect((only.routing as typeof routing).rules).toContainEqual({ type: "field", process: processes, network: "tcp,udp", outboundTag: profile.servers[0]!.tag });
  });

  it.each(["Ethernet", "Wi-Fi"])("binds direct and automatic outbound sockets to %s without pinning an IP", (name) => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "binding", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
    })), "subscription-1");
    const config = buildXrayConfig(profile, profile.servers[0]!, settings);
    const original = structuredClone(config);
    const bound = bindXrayOutboundInterface(config, name, true);
    const outbounds = bound.outbounds as Array<Record<string, unknown>>;
    const inbounds = bound.inbounds as Array<{ settings: Record<string, unknown> }>;
    expect(inbounds[0]?.settings.autoOutboundsInterface).toBe(name);
    expect(outbounds.find((outbound) => outbound.tag === "direct")).toEqual({
      tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" },
      streamSettings: { sockopt: { interface: name } },
    });
    expect(outbounds.find((outbound) => outbound.tag === "levik-block")).toEqual({ tag: "levik-block", protocol: "blackhole", settings: {} });
    expect(inbounds[0]?.settings.gateway).toEqual(["10.89.0.1/30", "fdfe:89::1/126"]);
    expect(config).toEqual(original);
  });

  it("keeps IPv6 out of the TUN when the physical adapter has no IPv6 route", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "ipv4-only", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
    })), "subscription-1");
    const config = buildXrayConfig(profile, profile.servers[0]!, settings);
    const original = structuredClone(config);
    const inbounds = bindXrayOutboundInterface(config, "Ethernet", false).inbounds as Array<{ settings: Record<string, unknown> }>;
    expect(inbounds[0]?.settings.gateway).toEqual(["10.89.0.1/30"]);
    expect(inbounds[0]?.settings.autoSystemRoutingTable).toEqual(["0.0.0.0/1", "128.0.0.0/1"]);
    expect(inbounds[0]?.settings.autoOutboundsInterface).toBe("Ethernet");
    expect(config).toEqual(original);
  });

  it("uses the expanded blocked-only domain set", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1,
      profileId: "blocked-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#DE%20Berlin" },
    })), "subscription-1");
    const config = buildXrayConfig(profile, profile.servers[0]!, { ...settings, routingMode: "blockedOnly" });
    const routing = config.routing as { rules: Array<{ domain?: string[]; outboundTag: string }> };
    const proxyRule = routing.rules.find((rule) => rule.outboundTag === profile.servers[0]?.tag && rule.domain);
    expect(proxyRule?.domain?.length).toBeGreaterThan(30);
  });
});


describe("alternate XHTTP Mux", () => {
  const alternateHost = "leva.levikfartik.ru";
  const uuid = "11111111-1111-4111-8111-111111111111";
  const link = (host: string, network: string) =>
    `vless://${uuid}@${host}:443?security=tls&type=${network}&path=%2Fapi%2FgetFile%2F&mode=packet-up#Alternate`;
  const prepare = (content: string) => prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "alternate-xhttp", subscriptionId: "subscription-1",
    source: { mediaType: "text/plain", content },
  })), "subscription-1");

  it.each(["xhttp", "splithttp"])("enables Mux for an alternate %s share link without mutating the profile", (network) => {
    const profile = prepare(link(alternateHost, network));
    const original = structuredClone(profile);
    const server = profile.servers[0]!;
    for (const antiDpiEnabled of [false, true]) {
      const config = buildXrayConfig(profile, server, { ...settings, antiDpiEnabled });
      expect(config).toHaveProperty("outbounds.0.mux", { enabled: true, concurrency: 1 });
      expect(config).toHaveProperty("outbounds.0.streamSettings.xhttpSettings.path", "/api/getFile/");
      expect(config).toHaveProperty("outbounds.0.streamSettings.tlsSettings.serverName", alternateHost);
      if (antiDpiEnabled) {
        expect(config).toHaveProperty("outbounds.0.streamSettings.sockopt.dialerProxy", "levik-fragment");
        expect(config.outbounds).toContainEqual(expect.objectContaining({ tag: "levik-fragment" }));
      } else {
        expect(config.outbounds).not.toContainEqual(expect.objectContaining({ tag: "levik-fragment" }));
      }
    }
    expect(profile).toEqual(original);
  });

  it.each([
    { enabled: false },
    { enabled: true, concurrency: 8, xudpConcurrency: 16, xudpProxyUDP443: "allow" },
    {},
    null,
  ])("preserves explicit JSON profile Mux settings: %j", (mux) => {
    const outbound = prepare(link(alternateHost, "xhttp")).servers[0]!.outbound;
    const profile = prepare(JSON.stringify({ outbounds: [{ ...outbound, mux }] }));
    for (const antiDpiEnabled of [false, true]) {
      const config = buildXrayConfig(profile, profile.servers[0]!, { ...settings, antiDpiEnabled });
      expect(config).toHaveProperty("outbounds.0.mux", mux);
    }
  });

  it("matches JSON endpoint host and transport case insensitively", () => {
    const profile = prepare(JSON.stringify({ outbounds: [{
      protocol: "vless", settings: { vnext: [{ address: "LEVA.LEVIKFARTIK.RU" }] },
      streamSettings: { network: "SplitHTTP" },
    }] }));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings))
      .toHaveProperty("outbounds.0.mux", { enabled: true, concurrency: 1 });
  });

  it.each([
    ["example.com", "xhttp"],
    ["example.com", "splithttp"],
    ["leva.levikfartik.ru.example.com", "xhttp"],
    [alternateHost, "tcp"],
    [alternateHost, "ws"],
  ])("leaves %s over %s unchanged", (host, network) => {
    const profile = prepare(link(host, network));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings)).not.toHaveProperty("outbounds.0.mux");
  });

  it.each([
    { protocol: "trojan", settings: { servers: [{ address: alternateHost }] } },
    { protocol: "vless", settings: { vnext: [{ address: alternateHost }, { address: "example.com" }] } },
    { protocol: "vless", settings: { vnext: [] } },
    { protocol: "vless", settings: { vnext: [null] } },
    { protocol: "vless", settings: { vnext: [{ address: 42 }] } },
    { protocol: "vless", settings: {} },
  ])("does not enable Mux for unrelated or incomplete JSON outbounds: %j", (outbound) => {
    const profile = prepare(JSON.stringify({ outbounds: [{ ...outbound, streamSettings: { network: "xhttp" } }] }));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings)).not.toHaveProperty("outbounds.0.mux");
  });
});
