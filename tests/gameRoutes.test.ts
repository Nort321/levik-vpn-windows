import { describe, expect, it } from "vitest";
import { bestGameRoute, summarizeGameSamples, GAME_BALANCER, GAME_BLOCK } from "../src/main/vpn/gameRoutes";
import { gameProcesses, normalizeGameIds } from "../src/shared/games";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildXrayConfig } from "../src/main/vpn/xrayConfig";
import type { AppSettings, TunnelServer } from "../src/shared/contracts";

const settings: AppSettings = {
  routingMode: "bypassRu", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
  dnsServer: "1.1.1.1", theme: "dark", launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
  preventDnsLeaks: true, favoriteServerIds: [], antiDpiEnabled: true,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20",
  splitTunnelMode: "bypass", splitTunnelProcesses: ["VALORANT.exe"], connectionTelemetry: false,
  telemetryNoticeShown: true, syncSettings: true,
  gameEnabled: true, gameIds: ["valorant"], gameProcesses: [], gameRouteId: null,
};
const source = [
  "vless://11111111-1111-4111-8111-111111111111@normal.example:443#Normal",
  "vless://11111111-1111-4111-8111-111111111111@game.example:443#Game",
  "hy2://secret@game.example:443?sni=game.example#UDP",
].join("\n");
function profile(game: unknown) {
  return prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "game-test", subscriptionId: "sub",
    source: { mediaType: "text/plain", content: source }, game })), "sub");
}
const endpoint = { address: "game.example", port: 443, protocol: "hysteria" };

describe("Game access and routing", () => {
  it("requires explicit entitlement, never names or a locally enabled switch", () => {
    for (const value of [undefined, null, { enabled: false, endpoints: [endpoint] }, { enabled: "true", endpoints: [endpoint] }]) {
      const p = profile(value);
      expect(p.game).toEqual({ enabled: false, servers: [] });
      const config = buildXrayConfig(p, p.servers[0]!, settings, "test-password");
      expect(config).not.toHaveProperty("routing.balancers");
      expect(config).toHaveProperty("routing.rules", expect.arrayContaining([expect.objectContaining({ ruleTag: "game", outboundTag: "levik-block" })]));
    }
  });
  it("matches protocol as well as endpoint and separates game from ordinary auto-selection", () => {
    const p = profile({ enabled: true, endpoints: [endpoint] });
    expect(p.game?.servers.map((s) => s.name)).toEqual(["UDP"]);
    expect(p.servers.map((s) => s.name)).toEqual(["Normal", "Game"]);
  });
  it("keeps normal VPN first, Game before bypass, and blocks games until an authenticated probe succeeds", () => {
    const p = profile({ enabled: true, endpoints: [endpoint] });
    const config = buildXrayConfig(p, p.servers[0]!, settings, "test-password");
    expect(config).toHaveProperty("outbounds.0.tag", p.servers[0]!.tag);
    expect(config).toHaveProperty("routing.balancers.0", { tag: GAME_BALANCER, selector: [GAME_BLOCK], strategy: { type: "random" } });
    const rules = (config.routing as { rules: Record<string, unknown>[] }).rules;
    expect(rules.findIndex((r) => r.ruleTag === "game")).toBeLessThan(rules.findIndex((r) => r.ruleTag === "process-bypass"));
    expect(rules.find((r) => r.ruleTag === "game")).toMatchObject({ process: ["VALORANT.exe", "VALORANT-Win64-Shipping.exe"], balancerTag: GAME_BALANCER });
    expect(config).toHaveProperty("inbounds.1.settings.accounts.0", { user: "levik-game", pass: "test-password" });
    // Anti-DPI belongs to ordinary VPN; adding latency to Game is never inherited.
    expect(config).not.toHaveProperty("outbounds.1.streamSettings.sockopt.dialerProxy");
  });
  it("does not add game listeners or routes when disabled", () => {
    const p = profile({ enabled: true, endpoints: [endpoint] });
    const config = buildXrayConfig(p, p.servers[0]!, { ...settings, gameEnabled: false });
    expect(config).not.toHaveProperty("routing.balancers");
    expect(config.inbounds).toHaveLength(2);
  });
  it("does not route launchers or anti-cheat services for selected games", () => {
    expect(gameProcesses(settings)).toEqual(["VALORANT.exe", "VALORANT-Win64-Shipping.exe"]);
    expect(normalizeGameIds(["valorant", "valorant", "unknown", 123])).toEqual(["valorant"]);
    expect(gameProcesses({ ...settings, gameIds: [], gameProcesses: ["custom.exe", "CUSTOM.exe", "../bad.exe"] })).toEqual(["custom.exe"]);
  });
});

describe("Game quality selection", () => {
  const server = (id: string, protocol = "hysteria"): TunnelServer => ({ id, tag: id, name: id, countryCode: "RU", outbound: { protocol } });
  it("chooses stability over one low latency and rejects unusable paths", () => {
    const servers = [server("fast"), server("steady"), server("down")];
    const quality = {
      fast: summarizeGameSamples([4, 4, 4, 4, 4, 4, null, null]),
      steady: summarizeGameSamples(Array(8).fill(40)),
      down: summarizeGameSamples(Array(8).fill(null)),
    };
    expect(bestGameRoute(servers, quality)?.id).toBe("steady");
    expect(bestGameRoute([server("down")], quality)).toBeNull();
  });
  it("uses repeated samples, reports no fake zero latency, and favours native UDP within 5ms", () => {
    expect(summarizeGameSamples([null, null])).toMatchObject({ latencyMs: null, jitterMs: null, lossPercent: 100 });
    expect(summarizeGameSamples([10, 20, 10, 20])).toMatchObject({ latencyMs: 20, jitterMs: 10, lossPercent: 0 });
    expect(bestGameRoute([server("tcp", "vless"), server("udp")], {
      tcp: summarizeGameSamples(Array(8).fill(39)), udp: summarizeGameSamples(Array(8).fill(40)),
    })?.id).toBe("udp");
  });
});
