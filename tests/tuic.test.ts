import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildXrayConfig, TUIC_PLACEHOLDER_ID, TUIC_PLACEHOLDER_PORT } from "../src/main/vpn/xrayConfig";
import { buildTuicSidecarConfig, withTuicProxy } from "../src/main/vpn/tuicSidecar";
import { WindowsKillSwitch } from "../src/main/windows/killSwitch";
import { activeVariant, groupServers, serverProtocolShortLabel } from "../src/shared/serverGroups";
import type { AppSettings } from "../src/shared/contracts";

// Self-signed CA used only by these tests (base64url DER).
const TEST_CA = "MIIBLTCB1KADAgECAgkAlrWlAi74LtUwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjEwMDkwNjMzMzlaFw0zNjEwMDYwNjMzMzlaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQMkvwcR00n8QEH8ejxpVyrdEu2mitTmHTzJVVb-D2knRhRrsjtu5BW_5G6nQhjImjchTZSEvYh58TTUkbLgujloxMwETAPBgNVHRMBAf8EBTADAQH_MAoGCCqGSM49BAMCA0gAMEUCIQCS7Jk2t47s5ODjcF4pvBsQRoz_9CyV_roiGAHkKEDm4wIgJ2W-0_H9Nr4eiUTxs3o6LwMmI0nbP_oM6G-6pDD3fl4";
const UUID = "123e4567-e89b-42d3-a456-426614174000";
const PASSWORD = "_EnbjPjIrpPjymZ63JYDPCUY7WN9ZvWv";

const settings: AppSettings = {
  routingMode: "bypassRu", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
  dnsServer: "1.1.1.1", theme: "dark", launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
  showTrayIcon: true, preventDnsLeaks: true, favoriteServerIds: [], antiDpiEnabled: true,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20",
  splitTunnelMode: "off", splitTunnelProcesses: [],
  connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
} as AppSettings;

function tuicLink(overrides: Record<string, string> = {}, host = "94.156.114.70"): string {
  const query = new URLSearchParams({ sni: "www.samsung.com", alpn: "h3", congestion_control: "bbr", udp_relay_mode: "native", levik_ca: TEST_CA, ...overrides });
  return `tuic://${UUID}:${PASSWORD}@${host}:8443?${query.toString()}#${encodeURIComponent("🇩🇪 TUIC")}`;
}

function profileFrom(lines: string[]) {
  return prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "tuic-test", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
    source: { mediaType: "text/plain", content: Buffer.from(lines.join("\n")).toString("base64") },
  })), "subscription-1");
}

const SUBSCRIPTION = [
  `vless://${UUID}@94.156.114.70:443?security=reality&type=xhttp&pbk=key&sid=ab#${encodeURIComponent("🇩🇪 🚀 Prime")}`,
  `hysteria2://auth@94.156.114.70:2443?sni=example.org#${encodeURIComponent("🇩🇪 🛡️ Hysteria2")}`,
  `vless://${UUID}@138.124.31.13:443?security=reality&pbk=key&sid=ab#${encodeURIComponent("🇫🇷 🚀 Prime")}`,
  tuicLink(),
];

describe("Windows TUIC support", () => {
  it("parses only pinned, IP-literal TUIC links", () => {
    const profile = profileFrom([...SUBSCRIPTION, tuicLink({ levik_ca: "" }), tuicLink({}, "tuic.example.com")]);
    const tuic = profile.servers.filter((server) => server.tuic);
    expect(tuic).toHaveLength(1);
    expect(tuic[0]?.tuic).toMatchObject({ address: "94.156.114.70", port: 8443, uuid: UUID, password: PASSWORD, serverName: "www.samsung.com" });
  });

  it("routes Xray to a loopback VLESS sidecar and patches the per-session user id", () => {
    const profile = profileFrom(SUBSCRIPTION);
    const server = profile.servers.find((item) => item.tuic)!;
    const config = buildXrayConfig(profile, server, settings);
    const outbounds = config.outbounds as Array<Record<string, unknown>>;
    expect(outbounds[0]).toEqual({
      tag: server.tag,
      protocol: "vless",
      settings: { vnext: [{ address: "127.0.0.1", port: TUIC_PLACEHOLDER_PORT, users: [{ id: TUIC_PLACEHOLDER_ID, encryption: "none" }] }] },
    });
    expect(outbounds.some((outbound) => outbound.tag === "levik-fragment")).toBe(false);

    const proxy = { port: 41000, id: "123e4567-e89b-42d3-a456-426614174000" };
    const patched = withTuicProxy(config, proxy);
    expect((patched.outbounds as Array<Record<string, unknown>>)[0]).toEqual({
      tag: server.tag,
      protocol: "vless",
      settings: { vnext: [{ address: "127.0.0.1", port: 41000, users: [{ id: proxy.id, encryption: "none" }] }] },
    });
    expect(() => withTuicProxy({ outbounds: [{ protocol: "vless", settings: {} }] }, proxy)).toThrow();
    expect(() => withTuicProxy({ outbounds: [{ protocol: "socks", settings: { address: "127.0.0.1", port: TUIC_PLACEHOLDER_PORT } }] }, proxy)).toThrow();
  });

  it("builds a sing-box config bound to the physical interface with only the pinned CA", () => {
    const server = profileFrom(SUBSCRIPTION).servers.find((item) => item.tuic)!;
    const id = "123e4567-e89b-42d3-a456-426614174000";
    const config = buildTuicSidecarConfig(server.tuic!, { port: 41000, id }, "Ethernet");
    expect(config.inbounds).toEqual([{ type: "vless", tag: "levik-tuic-in", listen: "127.0.0.1", listen_port: 41000, users: [{ uuid: id }] }]);
    const [outbound] = config.outbounds as Array<Record<string, unknown>>;
    expect(outbound).toMatchObject({ type: "tuic", server: "94.156.114.70", server_port: 8443, bind_interface: "Ethernet" });
    expect(outbound?.tls).toEqual({ enabled: true, server_name: "www.samsung.com", alpn: ["h3"], certificate: [server.tuic!.caCertificatePem] });
  });

  it("permits the sing-box executable in the kill switch boundary", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      appExecutablePath: "C:\\Levik\\Levik VPN.exe",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      tuicExecutablePath: () => "C:\\Levik\\singbox\\sing-box.exe",
      run: async (arguments_) => { commands.push(arguments_); return { exitCode: 0, errorText: "" }; },
    });
    await killSwitch.enable();
    expect(commands).toEqual([["enable", "C:\\Levik\\Levik VPN.exe", "C:\\Levik\\xray.exe", "C:\\Levik\\singbox\\sing-box.exe"]]);
  });

  it("groups protocol variants of one server", () => {
    const groups = groupServers(profileFrom(SUBSCRIPTION).servers);
    expect(groups.map((group) => group.variants.map(serverProtocolShortLabel))).toEqual([["VLESS", "Hysteria 2", "TUIC"], ["VLESS"]]);
    expect(activeVariant(groups[0]!, null)).toBe(groups[0]!.variants[0]);
  });
});
