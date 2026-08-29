import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildLockdownConfig, buildXrayConfig } from "../src/main/vpn/xrayConfig";
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
      outboundTag: "levik-direct",
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
    expect(routing.rules).toContainEqual(expect.objectContaining({ process: ["chrome.exe"], outboundTag: "levik-direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ ip: ["geoip:ru"], outboundTag: "levik-direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ domain: ["geosite:category-ru"], outboundTag: "levik-direct" }));
    expect((inbounds[0]?.sniffing as { destOverride: string[] }).destOverride).not.toContain("fakedns");
  });

  it("builds a fail-closed Kill Switch configuration", () => {
    const config = buildLockdownConfig(settings);
    const routing = config.routing as { rules: Array<{ outboundTag: string }> };
    expect(routing.rules.at(-1)?.outboundTag).toBe("levik-block");
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
