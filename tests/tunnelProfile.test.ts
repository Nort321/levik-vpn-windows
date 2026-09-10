import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { bindXrayOutboundInterface, buildLockdownConfig, buildXrayConfig } from "../src/main/vpn/xrayConfig";
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

  it("bypasses only Overwatch while keeping Battle.net and Agent on the VPN", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "battle-net", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" },
    })), "subscription-1");
    const server = profile.servers[0]!;
    const config = buildXrayConfig(profile, server, {
      ...settings, routingMode: "global", splitTunnelMode: "bypass", splitTunnelProcesses: ["overwatch.exe"],
    });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules).toEqual([
      { type: "field", process: ["overwatch.exe"], network: "tcp,udp", outboundTag: "direct", ruleTag: "process-bypass" },
      { type: "field", ip: expect.arrayContaining(["127.0.0.0/8", "::1/128"]), outboundTag: "direct" },
    ]);
    // Unmatched launcher/agent internet traffic uses Xray's first outbound.
    expect((config.outbounds as Array<Record<string, unknown>>)[0]?.tag).toBe(server.tag);
  });

  it("builds a fail-closed Kill Switch configuration", () => {
    const config = buildLockdownConfig(settings);
    const routing = config.routing as { rules: Array<{ outboundTag: string }> };
    expect(routing.rules.at(-1)?.outboundTag).toBe("levik-block");
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
    expect(routing.rules[0]).toEqual({ type: "field", process: processes, network: "tcp,udp", outboundTag: "direct", ruleTag: "process-bypass" });
    expect(routing.rules.findIndex((rule) => rule.outboundTag === profile.servers[0]!.tag)).toBeGreaterThan(0);
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
    const config = buildLockdownConfig(settings);
    const original = structuredClone(config);
    const bound = bindXrayOutboundInterface(config, name);
    const outbounds = bound.outbounds as Array<Record<string, unknown>>;
    const inbounds = bound.inbounds as Array<{ settings: Record<string, unknown> }>;
    expect(inbounds[0]?.settings.autoOutboundsInterface).toBe(name);
    expect(outbounds.find((outbound) => outbound.tag === "direct")).toEqual({
      tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" },
      streamSettings: { sockopt: { interface: name } },
    });
    expect(outbounds.find((outbound) => outbound.tag === "levik-block")).toEqual({ tag: "levik-block", protocol: "blackhole", settings: {} });
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
