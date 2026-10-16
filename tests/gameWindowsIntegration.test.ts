import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverInstalledGames, gameFromManifest, steamLibraryPaths } from "../src/main/windows/installedGames";
import { measureDirectGameTargets, parseDirectProbeSample, summarizeDirectSamples } from "../src/main/windows/gameProbe";
import { GAME_HISTORY_MAX_BYTES, GAME_HISTORY_MAX_ENTRIES, GameHistory, parseGameHistory } from "../src/main/vpn/gameHistory";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });
async function temporary(): Promise<string> { const path = await mkdtemp(join(tmpdir(), "levik-game-ui-")); directories.push(path); return path; }

describe("physical Windows game measurement", () => {
  it("does not mistake all fast TUN replies for a winning direct exit", async () => {
    const results = await measureDirectGameTargets([{ address: "1.1.1.1", port: 27015 }, { address: "8.8.8.8", port: 27015 }],
      "192.168.1.10", new AbortController().signal, async () => ({ latencyMs: 1, method: "icmp", approximate: false }));
    expect(results).toHaveLength(2);
    expect(results.every((result) => result.quality.latencyMs === null && result.quality.method === "unknown")).toBe(true);
  });
  it("labels last-router estimates and rejects invalid native output", () => {
    const sample = parseDirectProbeSample('{"latencyMs":25,"method":"ttl-hop","approximate":false}');
    expect(summarizeDirectSamples([sample], 100)).toMatchObject({ latencyMs: 25, approximate: true, method: "ttl-hop", measuredAt: 100 });
    expect(() => parseDirectProbeSample('{"latencyMs":-1,"method":"icmp","approximate":false}')).toThrow();
  });
  it("stops before native calls when cancelled", async () => {
    const abort = new AbortController(); abort.abort(); let calls = 0;
    expect(await measureDirectGameTargets([{ address: "1.1.1.1", port: 27015 }], "192.168.1.10", abort.signal,
      async () => { calls++; return { latencyMs: 10, method: "icmp", approximate: false }; })).toEqual([]);
    expect(calls).toBe(0);
  });
});

describe("local Game history", () => {
  it("persists only /24, bounded entries and known exit metadata", async () => {
    const directory = await temporary(); const path = join(directory, "history.json"); const history = new GameHistory(path);
    await history.record("cs2", "8.8.8.8", "US", "node-a", 100);
    expect(await readFile(path, "utf8")).not.toContain("8.8.8.8");
    const restored = new GameHistory(path); await restored.load();
    expect(restored.snapshot()).toEqual([{ gameId: "cs2", subnet: "8.8.8.0/24", region: "US", nodeId: "node-a", updatedAt: 100 }]);
    expect(restored.preferredExit("cs2")).toBe("node-a");
    expect(parseGameHistory(Array.from({ length: GAME_HISTORY_MAX_ENTRIES + 10 }, () => restored.snapshot()[0]))).toHaveLength(GAME_HISTORY_MAX_ENTRIES);
    await writeFile(path, "x".repeat(GAME_HISTORY_MAX_BYTES + 1)); await restored.load();
    expect(restored.snapshot()).toHaveLength(1);
  });
  it("rejects malformed, full-IP or account-shaped history", () => {
    expect(parseGameHistory([{ gameId: "cs2", subnet: "8.8.8.8", region: null, nodeId: "node-a", updatedAt: 100 }])).toEqual([]);
  });
});

describe("installed game discovery", () => {
  it("reads Steam manifests without running launchers", async () => {
    const directory = await temporary(); await mkdir(join(directory, "steamapps"));
    await writeFile(join(directory, "steamapps", "appmanifest_730.acf"), '"AppState" { "appid" "730" "name" "Counter-Strike 2" }');
    expect(await discoverInstalledGames({ steam: [directory], riot: [], epic: [] })).toEqual([{ gameId: "cs2", launcher: "steam" }]);
    expect(steamLibraryPaths('"libraryfolders" { "1" { "path" "D:\\\\Games\\\\Steam" }}')).toEqual(["D:\\Games\\Steam"]);
    expect(gameFromManifest('{"DisplayName":"Fortnite"}', "epic")).toEqual({ gameId: "fortnite", launcher: "epic" });
    expect(gameFromManifest('{"DisplayName":"Fortnite","account":"hidden"}', "epic")).toEqual({ gameId: "fortnite", launcher: "epic" });
  });
});

describe("Game profile version tolerance", () => {
  const source = "vless://11111111-1111-4111-8111-111111111111@game.example.com:443#Game";
  const profile = (game: unknown) => prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "p", subscriptionId: "s", source: { content: source }, game })), "s");
  it("groups legacy addresses and preserves ordinary-server exclusion", () => {
    const result = profile({ enabled: true, endpoints: [{ address: "game.example.com", port: 443, protocol: "vless" }] });
    expect(result.servers).toEqual([]); expect(result.game?.servers[0]?.nodeId).toMatch(/^legacy-/);
    expect(result.game?.nodes?.[0]?.state).toBe("enabled");
  });
  it("preserves draining and parses mesh without exposing secrets", () => {
    const result = profile({ enabled: true, endpoints: [{ address: "game.example.com", port: 443, protocol: "vless", nodeId: "node-a" }],
      nodes: [{ nodeId: "node-a", name: "Узел", countryCode: "RU", city: "Город", mesh: { address: "10.77.0.1", port: 37080 }, state: "draining", privateKey: "must-not-cross" }] });
    expect(result.game?.nodes?.[0]).toMatchObject({ nodeId: "node-a", state: "draining", mesh: { address: "10.77.0.1", port: 37080 } });
    expect(JSON.stringify(result.game)).not.toContain("must-not-cross");
  });
  it("does not enable an endpoint when its supplied node metadata is invalid", () => {
    const result = profile({ enabled: true, endpoints: [{ address: "game.example.com", port: 443, protocol: "vless", nodeId: "node-a" }], nodes: [{ nodeId: "node-a", state: "disabled", name: "x", countryCode: "invalid" }] });
    expect(result.game?.nodes?.[0]?.state).toBe("disabled"); expect(result.servers).toEqual([]);
  });
});
