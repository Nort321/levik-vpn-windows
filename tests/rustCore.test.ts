import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isDiagnosisVerdict, isIndexList, isListPositions, isTunnelProfileOutcome } from "../src/main/core/coreGuards";
import { prepareProfileWithCore } from "../src/main/core/coreProfile";
import { buildXrayConfigWithCore } from "../src/main/core/coreXray";
import { countryServersWithCore } from "../src/main/core/coreServers";
import { compiledServiceRoutes } from "../src/main/vpn/serviceRoutes";
import { buildXrayConfig } from "../src/main/vpn/xrayConfig";
import type { AppSettings } from "../src/shared/contracts";
import { levikCorePath, loadLevikCore } from "../src/main/core/levikCore";
import { coreBridge, coreModeFor, jsonDifference, RustCore, type CoreBridge } from "../src/main/core/rustCore";
import { diagnosisSummary, diagnosisVerdict, parseDiagnoseReport, type DiagnosisInput, type DiagnosisVerdict } from "../src/main/platform/diagnosis";
import { avoidMaintenance, maintenanceFor, maintenanceMove, parseMaintenance } from "../src/main/platform/maintenance";
import { flagEnabled, parseAdvice, parseRemoteConfig, visibleAnnouncements, type RemoteConfig } from "../src/main/platform/remoteConfig";
import * as smart from "../src/main/vpn/smartAuto";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { countryServers } from "../src/shared/serverGroups";

function fakeBridge(answers: Record<string, (input: unknown) => unknown>): CoreBridge & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    functions: () => Object.keys(answers),
    call: (name, input) => {
      calls.push(name);
      const answer = answers[name];
      if (!answer) throw new Error(`unknown function ${name}`);
      return JSON.stringify(answer(JSON.parse(input)));
    },
  };
}

const verdict: DiagnosisVerdict = { verdict: "ALL_OK", action: "support" };

describe("RustCore", () => {
  it("runs only TypeScript in ts mode and without a module", () => {
    const bridge = fakeBridge({ "diagnosis.diagnosisVerdict": () => verdict });
    const off = new RustCore(bridge, () => {}, "ts");
    expect(off.run("diagnosis.diagnosisVerdict", {}, () => verdict, isDiagnosisVerdict)).toBe(verdict);
    expect(bridge.calls).toEqual([]);
    const none = new RustCore(null, () => {});
    expect(none.run("diagnosis.diagnosisVerdict", {}, () => 5)).toBe(5);
    expect(none.has("diagnosis.diagnosisVerdict")).toBe(false);
  });

  it("keeps the TypeScript answer in shadow mode and reports differences without values", () => {
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({ f: () => ({ verdict: "ALL_OK", provider: "Секретный провайдер" }) }), (line) => lines.push(line));
    const answer = { verdict: "ALL_OK", provider: "Другой провайдер" };
    expect(core.run("f", {}, () => answer)).toBe(answer);
    expect(lines).toEqual(["Rust-ядро: f расходится с TypeScript в $.provider"]);
    expect(lines.join()).not.toContain("провайдер");
    expect(core.stats()).toEqual({ compared: 1, differed: 1, failed: 0, decided: 0 });
  });

  it("treats undefined fields and number forms as JSON does", () => {
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({ f: () => ({ a: 1, list: [1.5] }) }), (line) => lines.push(line));
    core.run("f", {}, () => ({ a: 1.0, list: [1.5], gone: undefined }));
    expect(lines).toEqual([]);
    expect(core.stats()).toEqual({ compared: 1, differed: 0, failed: 0, decided: 0 });
  });

  it("limits repeated reports but keeps counting", () => {
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({ f: () => 2 }), (line) => lines.push(line));
    for (let index = 0; index < 10; index += 1) core.run("f", null, () => 1);
    expect(lines).toHaveLength(3);
    expect(lines[2]).toContain("дальше только счётчик");
    expect(core.stats().differed).toBe(10);
  });

  it("falls back to TypeScript when Rust fails or answers in the wrong shape", () => {
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({
      "diagnosis.diagnosisVerdict": () => ({ verdict: "NOT_A_VERDICT", action: null }),
      boom: () => { throw new Error("bad input (data at line 1 column 2)"); },
    }), (line) => lines.push(line), "rust");
    expect(core.run("diagnosis.diagnosisVerdict", {}, () => verdict, isDiagnosisVerdict)).toBe(verdict);
    expect(core.run("boom", {}, () => "ts", (value): value is string => typeof value === "string")).toBe("ts");
    expect(lines).toEqual([
      "Rust-ядро: diagnosis.diagnosisVerdict ответ не той формы",
      "Rust-ядро: boom ошибка: bad input (data at line 1 column 2)",
    ]);
    expect(core.stats().failed).toBe(2);
  });

  it("uses the Rust answer in rust mode only with a shape check", () => {
    const rust = { verdict: "ALL_OK_VPN_OFF", action: "connect" };
    const core = new RustCore(fakeBridge({ "diagnosis.diagnosisVerdict": () => rust }), () => {}, "rust");
    expect(core.run("diagnosis.diagnosisVerdict", {}, () => verdict, isDiagnosisVerdict)).toEqual(rust);
    // Without a check the call is compared like in shadow mode.
    expect(core.run("diagnosis.diagnosisVerdict", {}, () => verdict)).toBe(verdict);
  });

  it("skips functions the module does not have", () => {
    const bridge = fakeBridge({});
    const core = new RustCore(bridge, () => {});
    expect(core.run("diagnosis.diagnosisVerdict", {}, () => 1)).toBe(1);
    expect(bridge.calls).toEqual([]);
  });

  it("survives a module whose function list throws", () => {
    const lines: string[] = [];
    const core = new RustCore({ functions: () => { throw new Error("broken"); }, call: () => "null" }, (line) => lines.push(line));
    expect(core.run("f", {}, () => 1)).toBe(1);
    expect(lines).toEqual(["Rust-ядро: список функций недоступен (broken)"]);
  });

  it("tallies per function for the connection report, and nothing without a module", () => {
    const core = new RustCore(fakeBridge({
      "smartAuto.rankSmart": () => [2],
      "diagnosis.parseDiagnoseReport": () => { throw new Error("x"); },
      "diagnosis.diagnosisVerdict": () => verdict,
    }), () => {}, "shadow", "0.3.0");
    core.run("smartAuto.rankSmart", {}, () => [1]);
    core.run("smartAuto.rankSmart", {}, () => [1]);
    core.run("diagnosis.parseDiagnoseReport", {}, () => null);
    core.run("diagnosis.diagnosisVerdict", {}, () => verdict);
    core.setMode("rust");
    core.run("diagnosis.diagnosisVerdict", {}, () => verdict, isDiagnosisVerdict);
    expect(core.tally()).toEqual({
      version: "0.3.0",
      mode: "rust",
      compared: 3,
      differed: 2,
      failed: 1,
      decided: 1,
      functions: {
        "smartAuto.rankSmart": { differed: 2, failed: 0 },
        "diagnosis.parseDiagnoseReport": { differed: 0, failed: 1 },
      },
    });
    expect(new RustCore(null, () => {}, "shadow", "0.3.0").tally()).toBeNull();
    expect(new RustCore(fakeBridge({}), () => {}).tally()).toBeNull();
  });

  it("logs mode changes once", () => {
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({}), (line) => lines.push(line), "ts");
    core.setMode("shadow");
    core.setMode("shadow");
    expect(lines).toEqual(["Rust-ядро: режим shadow"]);
    expect(core.mode).toBe("shadow");
  });
});

describe("jsonDifference", () => {
  it("names the path and hides keys that look like data", () => {
    expect(jsonDifference({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] })).toBe("$.a[1].b");
    expect(jsonDifference([1], [1, 2])).toBe("$ (длина 1 ≠ 2)");
    expect(jsonDifference({ n1aaaaaaaaaaaaaaaaaaaa: 1 }, {})).toBe("$.n1aaaaaaaaaaaaaaaaaaaa (только с одной стороны)");
    expect(jsonDifference({ "Мой ключ": 1 }, { "Мой ключ": 2 })).toBe("$.<ключ>");
    expect(jsonDifference(null, { a: 1 })).toBe("$");
    expect(jsonDifference({ a: null }, { a: null })).toBeNull();
  });
});

describe("coreModeFor", () => {
  const config = (flags: RemoteConfig["flags"]): RemoteConfig => ({ flags, announcements: [], protocols: null, maintenance: [], nodeLoad: {}, refreshAfterSeconds: 900 });
  it("is shadow unless a flag says otherwise; the kill switch wins", () => {
    expect(coreModeFor(null, "salt")).toBe("shadow");
    expect(coreModeFor(config({ rust_core_primary: { enabled: true, rolloutPercent: 100 } }), "salt")).toBe("rust");
    expect(coreModeFor(config({
      rust_core_primary: { enabled: true, rolloutPercent: 100 },
      rust_core_off: { enabled: true, rolloutPercent: 100 },
    }), "salt")).toBe("ts");
    expect(coreModeFor(config({ rust_core_primary: { enabled: true, rolloutPercent: 0 } }), "salt")).toBe("shadow");
  });
});

describe("isIndexList", () => {
  it("accepts ascending indices within the list only", () => {
    expect(isIndexList(3)([0, 2])).toBe(true);
    expect(isIndexList(3)([])).toBe(true);
    expect(isIndexList(3)([2, 0])).toBe(false);
    expect(isIndexList(3)([1, 1])).toBe(false);
    expect(isIndexList(3)([3])).toBe(false);
    expect(isIndexList(3)([0.5])).toBe(false);
  });
});

/** A test-only CA (its key was discarded), as the profile service pins one in TUIC links. */
const TEST_CA = readFileSync(join(__dirname, "fixtures", "tuic-test-ca.txt"), "utf8").trim();

const PROFILE_LINKS = [
  "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=public-key&sid=0123&type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20Frankfurt",
  "trojan://secret@trojan.example.com:8443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws#NL%20Amsterdam",
  "hysteria2://secret@example.com:443?sni=cdn.example.com&obfs=salamander&obfs-password=obfs-pass-1234#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam",
  `tuic://11111111-1111-4111-8111-111111111111:tuic-password-0123456789@203.0.113.10:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr&levik_ca=${TEST_CA}#FI`,
  "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:2053?security=tls&type=xhttp&path=%2Fapi&mode=packet-up#IPv6",
];

/** A profile as the server sends it, encoded; `patch` changes or removes fields. */
function profileBytes(content: string, patch: Record<string, unknown> = {}): Uint8Array {
  return Buffer.from(JSON.stringify({ version: 1, profileId: "p-1", subscriptionId: "sub", issuedAt: "2026-01-01T00:00:00Z",
    subscriptionExpiresAt: "2027-01-01T00:00:00Z", source: { mediaType: "text/plain", content },
    routing: { directCidrs: ["10.0.0.0/8"], directDomains: ["domain:example.ru"], proxyDomains: [] }, ...patch }));
}

const PROFILE_VARIANTS: { label: string; bytes: Uint8Array; subscription?: string }[] = [
  { label: "all links", bytes: profileBytes(PROFILE_LINKS.join("\n")) },
  { label: "base64", bytes: profileBytes(Buffer.from(PROFILE_LINKS.join("\n")).toString("base64")) },
  { label: "xray json", bytes: profileBytes(JSON.stringify({ outbounds: [{ protocol: "vless", tag: "x",
    settings: { vnext: [{ address: "json.example.com", port: 443, users: [{ id: "11111111-1111-4111-8111-111111111111", encryption: "none" }] }] },
    streamSettings: { network: "tcp", security: "tls" } }] })) },
  { label: "game", bytes: profileBytes(PROFILE_LINKS.join("\n"), { game: { enabled: true, only: false,
    endpoints: [{ address: "example.com", port: 443, protocol: "hysteria2", nodeId: "n1aaaaaaaaaaaaaaaaaaaa" }],
    nodes: [{ nodeId: "n1aaaaaaaaaaaaaaaaaaaa", name: "NL", countryCode: "NL", state: "enabled" }] } }) },
  { label: "another subscription", bytes: profileBytes(PROFILE_LINKS[0] ?? ""), subscription: "other" },
  { label: "stub", bytes: profileBytes("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp#%D0%9F%D0%BE%D0%B4%D0%BF%D0%B8%D1%81%D0%BA%D0%B0%20%D0%B7%D0%B0%D0%BA%D0%BE%D0%BD%D1%87%D0%B8%D0%BB%D0%B0%D1%81%D1%8C") },
  { label: "no servers", bytes: profileBytes("") },
  { label: "bad routing", bytes: profileBytes(PROFILE_LINKS[0] ?? "", { routing: { directCidrs: ["not a cidr"] } }) },
  { label: "bad policy", bytes: profileBytes(PROFILE_LINKS[0] ?? "", { serviceRoutes: { version: 2 } }) },
  { label: "broken json", bytes: Buffer.from("{\"version\": 1,") },
  { label: "too small", bytes: Buffer.from("{") },
];

function outcomeOf(run: () => unknown): string {
  try {
    run();
    return "profile";
  } catch (error) {
    return `${error instanceof Error ? error.constructor.name : "?"}: ${error instanceof Error ? error.message : String(error)}`;
  }
}

describe("prepareProfileWithCore", () => {
  const bytes = profileBytes(PROFILE_LINKS[0] ?? "");
  const expected = prepareTunnelProfile(bytes, "sub");

  it("asks nothing in ts mode or without the function", () => {
    const bridge = fakeBridge({});
    expect(prepareProfileWithCore(new RustCore(bridge, () => {}, "shadow"), bytes, "sub")).toEqual(expected);
    expect(prepareProfileWithCore(new RustCore(fakeBridge({ "tunnelProfile.prepareTunnelProfile": () => ({ refused: "x" }) }), () => {}, "ts"), bytes, "sub"))
      .toEqual(expected);
    expect(bridge.calls).toEqual([]);
  });

  it("compares refusals in shadow mode and keeps the TypeScript error object", () => {
    const lines: string[] = [];
    const inputs: unknown[] = [];
    const core = new RustCore(fakeBridge({ "tunnelProfile.prepareTunnelProfile": (input) => {
      inputs.push(input);
      return { refused: "Профиль не соответствует подписке" };
    } }), (line) => lines.push(line), "shadow");
    expect(() => prepareProfileWithCore(core, bytes, "other")).toThrow("Профиль не соответствует подписке");
    expect(inputs[0]).toMatchObject({ bytes: bytes.byteLength, subscriptionId: "other", platform: "windows" });
    const broken = Buffer.from("{\"version\":");
    expect(() => prepareProfileWithCore(core, broken, "sub")).toThrow(SyntaxError);
    expect(core.stats()).toMatchObject({ compared: 2, differed: 1 });
    expect(lines).toEqual(["Rust-ядро: tunnelProfile.prepareTunnelProfile расходится с TypeScript в $.refused"]);
  });

  it("lets Rust decide in rust mode and asks TypeScript for the wording of engine errors", () => {
    const answers: unknown[] = [{ profile: expected }, { refused: "Профиль не соответствует подписке" }, { refused: "" }, { profile: { servers: [] } }];
    const core = new RustCore(fakeBridge({ "tunnelProfile.prepareTunnelProfile": () => answers.shift() }), () => {}, "rust");
    expect(prepareProfileWithCore(core, bytes, "sub")).toEqual(expected);
    expect(() => prepareProfileWithCore(core, bytes, "sub")).toThrow("Профиль не соответствует подписке");
    expect(() => prepareProfileWithCore(core, Buffer.from("{\"version\":"), "sub")).toThrow(SyntaxError);
    expect(prepareProfileWithCore(core, bytes, "sub")).toEqual(expected);
    expect(core.stats()).toMatchObject({ decided: 3, failed: 1 });
  });

  it("accepts only the two answer shapes", () => {
    expect(isTunnelProfileOutcome({ refused: "" })).toBe(true);
    expect(isTunnelProfileOutcome({ profile: expected })).toBe(true);
    expect(isTunnelProfileOutcome({ refused: "", profile: expected })).toBe(false);
    expect(isTunnelProfileOutcome({ refused: 1 })).toBe(false);
    expect(isTunnelProfileOutcome({ profile: { ...expected, servers: [] } })).toBe(false);
    expect(isTunnelProfileOutcome({ profile: { ...expected, game: undefined } })).toBe(false);
  });
});

const XRAY_SETTINGS: AppSettings = { routingMode: "bypassRu", automaticServer: true, autoReconnect: true, killSwitch: true,
  useDoh: true, dnsServer: "1.1.1.1", theme: "system", launchAtLogin: false, autoConnectOnLaunch: false,
  closeToTray: true, preventDnsLeaks: true, favoriteServerIds: [], favoriteNodes: null, antiDpiEnabled: false,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20", splitTunnelMode: "off",
  splitTunnelProcesses: [], connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
  sharePresence: true, sleepAtHome: true };

const XRAY_POLICY = { version: 1, revision: 4, fingerprint: "a".repeat(64), rules: [
  { id: "de", label: "Страна", source: "domain", domains: ["full:work.example"], route: { kind: "country", countryCode: "DE" }, fallback: { kind: "block" } },
  { id: "nl", label: "Выход", source: "service", domains: ["domain:video.example"], route: { kind: "exit", exitId: "nl" }, fallback: { kind: "main" } },
  { id: "ru", label: "Напрямую", source: "preset", domains: ["regexp:^.+\\.ru$"], route: { kind: "direct" }, fallback: { kind: "block" } },
  { id: "all", label: "Как везде", source: "domain", domains: ["full:default.example"], route: { kind: "default" }, fallback: { kind: "block" } },
], exits: [
  { exitId: "de", name: "Германия", countryCode: "DE", role: "ordinary", state: "enabled", endpoints: [{ address: "example.com", port: 443, protocol: "vless" }] },
  { exitId: "nl", name: "Нидерланды", countryCode: "NL", role: "ordinary", state: "enabled", endpoints: [{ address: "trojan.example.com", port: 8443, protocol: "trojan" }] },
  { exitId: "lv", name: "Латвия", countryCode: "LV", role: "ordinary", state: "draining", endpoints: [{ address: "example.com", port: 443, protocol: "hy2" }] },
] };

const XRAY_PROFILES = [
  prepareTunnelProfile(profileBytes(PROFILE_LINKS.join("\n")), "sub"),
  prepareTunnelProfile(profileBytes(PROFILE_LINKS.join("\n"), { serviceRoutes: XRAY_POLICY }), "sub"),
];

const GAME_PROFILE = prepareTunnelProfile(profileBytes(PROFILE_LINKS.join("\n"), { game: { enabled: true,
  endpoints: [{ address: "example.com", port: 443, protocol: "hysteria2", nodeId: "n1aaaaaaaaaaaaaaaaaaaa" }],
  nodes: [{ nodeId: "n1aaaaaaaaaaaaaaaaaaaa", name: "NL", countryCode: "NL", state: "enabled" }] } }), "sub");

const XRAY_VARIANTS: Partial<AppSettings>[] = [
  {}, { routingMode: "global", automaticServer: false }, { routingMode: "blockedOnly", antiDpiEnabled: true },
  { splitTunnelMode: "only", splitTunnelProcesses: ["Telegram.exe", "VALORANT.exe"] }, { splitTunnelMode: "bypass", splitTunnelProcesses: ["Telegram.exe", "VALORANT.exe"] },
  { useDoh: false, dnsServer: "9.9.9.9" }, { useDoh: false, dnsServer: "dns.example.com" },
];

describe("buildXrayConfigWithCore", () => {
  const profile = XRAY_PROFILES[1]!;
  const server = profile.servers[0]!;

  it("asks nothing in ts mode", () => {
    const bridge = fakeBridge({ "xrayConfig.buildXrayConfig": () => ({}) });
    const config = buildXrayConfigWithCore(new RustCore(bridge, () => {}, "ts"), profile, server, XRAY_SETTINGS, "probe-password");
    expect(bridge.calls).toEqual([]);
    expect(compiledServiceRoutes(config)?.status.state).toBe("pending");
  });

  it("gives both implementations the same fresh control password and compares their answers", () => {
    const inputs: Record<string, unknown>[] = [];
    const lines: string[] = [];
    const core = new RustCore(fakeBridge({ "xrayConfig.buildXrayConfig": (input) => {
      inputs.push(input as Record<string, unknown>);
      return { config: {}, serviceRoutes: null };
    } }), (line) => lines.push(line), "shadow");
    const first = buildXrayConfigWithCore(core, profile, server, XRAY_SETTINGS, "probe-password");
    const second = buildXrayConfigWithCore(core, profile, server, XRAY_SETTINGS, "probe-password");
    expect(inputs[0]).toMatchObject({ platform: "windows", settings: XRAY_SETTINGS, gameProbePassword: "probe-password" });
    expect(compiledServiceRoutes(first)?.auth?.password).toBe(inputs[0]?.servicePassword);
    expect(compiledServiceRoutes(second)?.auth?.password).toBe(inputs[1]?.servicePassword);
    expect(inputs[0]?.servicePassword).not.toBe(inputs[1]?.servicePassword);
    expect(core.stats()).toMatchObject({ compared: 2, differed: 2 });
    expect(lines[0]).toMatch(/^Rust-ядро: xrayConfig\.buildXrayConfig расходится с TypeScript в \$\./);
  });

  it("uses the Rust configuration and its routes in rust mode, and TypeScript for a malformed answer", () => {
    const expected = buildXrayConfig(profile, server, XRAY_SETTINGS, "probe-password");
    const routes = compiledServiceRoutes(expected);
    const answers: unknown[] = [{ config: expected, serviceRoutes: routes }, { config: { inbounds: [] }, serviceRoutes: null }];
    const core = new RustCore(fakeBridge({ "xrayConfig.buildXrayConfig": () => answers.shift() }), () => {}, "rust");
    const decided = buildXrayConfigWithCore(core, profile, server, XRAY_SETTINGS, "probe-password");
    expect(decided).toEqual(JSON.parse(JSON.stringify(expected)));
    expect(compiledServiceRoutes(decided)).toEqual(JSON.parse(JSON.stringify(routes)));
    const fallback = buildXrayConfigWithCore(core, profile, server, XRAY_SETTINGS, "probe-password");
    expect(compiledServiceRoutes(fallback)?.status.state).toBe("pending");
    expect(core.stats()).toMatchObject({ decided: 1, failed: 1 });
  });
});

// The profile's servers, then copies under other countries and names.
const COUNTRY_SERVERS = [
  ...XRAY_PROFILES[0]!.servers,
  ...XRAY_PROFILES[0]!.servers.map((server, index) => ({
    ...server,
    id: `${server.id}-copy`,
    countryCode: ["de", "NL", "XX", "HK", "RU"][index % 5]!,
    name: ["🇩🇪 Германия · Франкфурт", "Netherlands Amsterdam", "Unknown", "Hong Kong 2", "🏠 Домашний ПК"][index % 5]!,
  })),
];
const COUNTRY_CODES = [...new Set(COUNTRY_SERVERS.map((server) => server.countryCode))].concat(["de", "xx", "", "JP"]);

describe("countryServersWithCore", () => {
  const code = COUNTRY_SERVERS[0]!.countryCode;
  const expected = countryServers(COUNTRY_SERVERS, code);

  it("asks nothing in ts mode", () => {
    const bridge = fakeBridge({ "serverGroups.countryServers": () => [] });
    expect(countryServersWithCore(new RustCore(bridge, () => {}, "ts"), COUNTRY_SERVERS, code)).toEqual(expected);
    expect(bridge.calls).toEqual([]);
  });

  it("compares positions in shadow mode and hands back the caller's own servers", () => {
    const inputs: unknown[] = [];
    const core = new RustCore(fakeBridge({ "serverGroups.countryServers": (input) => {
      inputs.push(input);
      return [0];
    } }), () => {}, "shadow");
    const found = countryServersWithCore(core, COUNTRY_SERVERS, code);
    expect(found).toEqual(expected);
    expect(found.every((server) => COUNTRY_SERVERS.includes(server))).toBe(true);
    expect(inputs[0]).toMatchObject({ countryCode: code, platform: "windows" });
    expect(core.stats().compared).toBe(1);
  });

  it("uses the Rust positions in rust mode, and TypeScript for positions outside the list or repeated", () => {
    const answers: unknown[] = [[1, 0], [0, COUNTRY_SERVERS.length], [0, 0], ["0"]];
    const core = new RustCore(fakeBridge({ "serverGroups.countryServers": () => answers.shift() }), () => {}, "rust");
    expect(countryServersWithCore(core, COUNTRY_SERVERS, code)).toEqual([COUNTRY_SERVERS[1], COUNTRY_SERVERS[0]]);
    for (let index = 0; index < 3; index += 1) expect(countryServersWithCore(core, COUNTRY_SERVERS, code)).toEqual(expected);
    expect(core.stats()).toMatchObject({ decided: 1, failed: 3 });
  });

  it("accepts distinct positions within the list only", () => {
    expect(isListPositions([2, 0, 1], 3)).toBe(true);
    expect(isListPositions([], 0)).toBe(true);
    expect(isListPositions([3], 3)).toBe(false);
    expect(isListPositions([1, 1], 3)).toBe(false);
    expect(isListPositions([-1], 3)).toBe(false);
    expect(isListPositions([0.5], 3)).toBe(false);
    expect(isListPositions({}, 3)).toBe(false);
  });
});

// The real module, when `npm run download:levik-core` (or a local build) put it into vendor.
const status = loadLevikCore(levikCorePath({ packaged: false, resourcesPath: "", appPath: join(__dirname, "..") }));
const bridge = coreBridge(status);

describe.runIf(bridge !== null)("the Rust core in shadow mode agrees with TypeScript", () => {
  const lines: string[] = [];
  const core = new RustCore(bridge, (line) => lines.push(line), "shadow");
  const NOW = 1_767_225_600_000;
  const NODE = "n1aaaaaaaaaaaaaaaaaaaa";
  const window = { nodeId: NODE, startsAt: "2026-01-01T00:10:00Z", endsAt: "2026-01-01T02:00:00Z" };
  const rawReports: unknown[] = [
    null, {}, [], "x",
    { network: { known: true, provider: "  Golden Telecom " }, whitelist: { status: "active" },
      services: [{ slug: "youtube", name: " YouTube ", state: "restricted", operator: "failing" }, { slug: "Bad", name: "x" }],
      protocols: { preferred: ["vless-xhttp", "Bad"], avoid: ["vless-reality"] },
      countries: [{ country: "DE", online: 0, total: 3 }, { country: "nl", online: 1, total: 1 }], maintenance: [window] },
  ];

  it("diagnosis", () => {
    for (const raw of rawReports) {
      const report = core.run("diagnosis.parseDiagnoseReport", raw, () => parseDiagnoseReport(raw));
      for (const vpn of ["off", "connecting", "connected", "failed"] as const) {
        for (const failing of [[], ["youtube"], ["discord", "telegram"]]) {
          const input: DiagnosisInput = { network: "ok", cellular: vpn === "failed", vpn, serverCountry: "DE", serverNodeId: NODE,
            protocol: "vless-reality", failingServices: failing, anyServiceWorks: failing.length === 0, report, now: NOW + 3_600_000 };
          const result = core.run("diagnosis.diagnosisVerdict", input, () => diagnosisVerdict(input));
          for (const networkSettings of [true, false]) {
            core.run("diagnosis.diagnosisSummary", { result, networkSettings }, () => diagnosisSummary(result, { networkSettings }));
          }
        }
      }
    }
    expect(lines).toEqual([]);
    expect(core.stats().failed).toBe(0);
  });

  it("maintenance and remote configuration", () => {
    const windows = parseMaintenance([window, { ...window, nodeId: "n1bbbbbbbbbbbbbbbbbbbb", startsAt: "2026-01-01T05:00:00Z", endsAt: "2026-01-01T06:00:00Z" }]);
    const ids = [NODE, "n1bbbbbbbbbbbbbbbbbbbb", null];
    for (const now of [NOW - 60_000, NOW, NOW + 60 * 60_000, NOW + 2 * 3_600_000, NOW + 4.9 * 3_600_000]) {
      for (const nodeId of ids) {
        const found = core.run("maintenance.maintenanceFor", { windows, nodeId, now }, () => maintenanceFor(windows, nodeId, now));
        core.run("maintenance.maintenanceMove", { window: found, now }, () => maintenanceMove(found, now));
      }
      core.run("maintenance.avoidMaintenance", { nodeIds: ids, windows, now }, () =>
        avoidMaintenance(ids, windows, (id) => id, now).map((id) => ids.indexOf(id)));
    }
    const response = { ok: true, refreshAfterSeconds: 600.5, flags: { service_routes: { enabled: true, rolloutPercent: 40 }, Bad: { enabled: true } },
      announcements: [{ id: "0f8fad5b-d9cb-469f-a165-70867728950e", level: "info", title: " Работы ", body: "Текст", linkUrl: "https://leviknet.org",
        notify: true, startsAt: "2026-01-01T00:00:00Z", endsAt: "2026-01-02T00:00:00Z" }],
      protocols: { preferred: ["tuic"], avoid: [] }, maintenance: [window], nodeLoad: { [NODE]: 0.4, bad: 1 } };
    const config = core.run("remoteConfig.parseRemoteConfig", response, () => parseRemoteConfig(response));
    core.run("remoteConfig.parseAdvice", response.protocols, () => parseAdvice(response.protocols));
    for (const salt of ["a", "b", "c", "d", "e", "f"]) {
      core.run("remoteConfig.flagEnabled", { config, key: "service_routes", salt }, () => flagEnabled(config, "service_routes", salt));
    }
    core.run("remoteConfig.visibleAnnouncements", { config, dismissed: [], now: NOW }, () => visibleAnnouncements(config, new Set(), NOW));
    expect(lines).toEqual([]);
    expect(core.stats()).toMatchObject({ differed: 0, failed: 0 });
    expect(core.stats().compared).toBeGreaterThan(20);
  });

  it("Smart Auto", () => {
    const route = { measuredAt: NOW - 1_000, confidence: "measured" as const, medianMs: 70, jitterMs: 4, failureRate: 0, targets: 2, samples: 6,
      setupMs: 300, downMbps: 40, upMbps: 15, dataVerified: true };
    const candidates: smart.SmartCandidate[] = [
      { id: "b".repeat(64), protocol: "vless-reality", latencyMs: 40, silenceMeansDown: true, load: 0.2, verdict: "unknown", quality: 1.1, full: false, resourceHeadroom: null, routeDegraded: false },
      { id: "a".repeat(64), protocol: "vless-xhttp", latencyMs: 55, silenceMeansDown: true, load: null, verdict: "works", quality: null, full: false, resourceHeadroom: 0.4, routeDegraded: false },
      { id: "c".repeat(64), protocol: "hysteria2", latencyMs: null, silenceMeansDown: false, load: 0.9, verdict: "suspect", full: true, resourceHeadroom: null, routeDegraded: false },
      { id: "d".repeat(64), protocol: "vless-reality", latencyMs: 30, silenceMeansDown: true, load: 0.1, verdict: "blocked", route, resourceHeadroom: 0.7, routeDegraded: false },
    ];
    for (const advice of [null, { preferred: ["vless-xhttp"], avoid: ["vless-reality"] }]) {
      for (const spread of [null, 0, 0.5, 0.99]) {
        for (const pool of [candidates, candidates.slice(0, 3), candidates.slice(1, 2), []]) {
          const ranked = core.run("smartAuto.rankSmart", { candidates: pool, advice, spread, now: NOW }, () => smart.rankSmart(pool, advice, spread, NOW));
          core.run("smartAuto.nextRung", { ranked, triedProtocols: ["vless-reality"], triedIds: [] }, () => smart.nextRung(ranked, new Set(["vless-reality"]), new Set()));
        }
      }
    }
    let history = smart.emptyHistory();
    for (const [index, protocol] of ["vless-reality", "hysteria2", "vless-reality", "tuic"].entries()) {
      const previous = history;
      history = core.run("smartAuto.recordFailure", { history: previous, networkKey: "0123456789abcdef", protocol, nodeId: `n${index}`, now: NOW + index, failedServerId: "srv" },
        () => smart.recordFailure(previous, "0123456789abcdef", protocol, `n${index}`, NOW + index, "srv"));
      const current = history;
      history = core.run("smartAuto.recordSuccess", { history: current, networkKey: `${index}`.repeat(16), protocol, now: NOW + index, serverId: "srv" },
        () => smart.recordSuccess(current, `${index}`.repeat(16), protocol, NOW + index, "srv"));
    }
    const stored = JSON.parse(JSON.stringify(history)) as unknown;
    core.run("smartAuto.parseHistory", stored, () => smart.parseHistory(stored));
    const interfaces = { en0: [{ address: "192.168.1.5", netmask: "255.255.255.0", family: "IPv4", mac: "00:00:00:00:00:00", internal: false, cidr: "192.168.1.5/24" }] };
    const store = new smart.ProtocolHistoryStore("/nonexistent");
    core.run("smartAuto.networkKey", { salt: store.localSalt(), interfaces }, () => store.networkKey(interfaces as never));
    const servers = [{ host: "Relay.example.com", countryCode: "de" }, { host: "relay.example.com", countryCode: "NL" }, { host: null, countryCode: "FI" }];
    core.run("smartAuto.relayHosts", servers, () => [...smart.relayHosts(servers)]);
    expect(lines).toEqual([]);
    expect(core.stats()).toMatchObject({ differed: 0, failed: 0 });
  });

  it("tunnel profiles, refusals included", () => {
    expect(core.has("tunnelProfile.prepareTunnelProfile")).toBe(true);
    for (const { label, bytes, subscription } of PROFILE_VARIANTS) {
      const ts = outcomeOf(() => prepareTunnelProfile(bytes, subscription ?? "sub"));
      expect(outcomeOf(() => prepareProfileWithCore(core, bytes, subscription ?? "sub")), label).toBe(ts);
    }
    expect(lines).toEqual([]);
    expect(core.stats()).toMatchObject({ differed: 0, failed: 0 });
    expect(prepareTunnelProfile(PROFILE_VARIANTS[0]?.bytes ?? new Uint8Array(), "sub").servers).toHaveLength(PROFILE_LINKS.length);
    expect(PROFILE_VARIANTS.map(({ bytes, subscription }) => outcomeOf(() => prepareTunnelProfile(bytes, subscription ?? "sub")).split(":")[0]))
      .toEqual(["profile", "profile", "profile", "profile", "Error", "Error", "Error", "Error", "Error", "SyntaxError", "Error"]);
  });

  it("Xray configurations with service routes", () => {
    expect(core.has("xrayConfig.buildXrayConfig")).toBe(true);
    const before = core.stats().compared;
    for (const profile of XRAY_PROFILES) {
      for (const server of profile.servers) {
        for (const patch of XRAY_VARIANTS) buildXrayConfigWithCore(core, profile, server, { ...XRAY_SETTINGS, ...patch }, "probe-password");
      }
    }
    for (const server of GAME_PROFILE.servers) {
      for (const patch of [{ gameEnabled: true }, { gameEnabled: true, gameIds: ["valorant", "cs2"], gameProcesses: ["custom.exe"] }]) {
        buildXrayConfigWithCore(core, GAME_PROFILE, server, { ...XRAY_SETTINGS, ...patch }, "probe-password");
      }
    }
    expect(lines).toEqual([]);
    expect(core.stats()).toMatchObject({ differed: 0, failed: 0 });
    expect(core.stats().compared - before).toBeGreaterThan(50);
  });

  it("servers of a country", () => {
    expect(core.has("serverGroups.countryServers")).toBe(true);
    const before = core.stats().compared;
    for (const code of COUNTRY_CODES) countryServersWithCore(core, COUNTRY_SERVERS, code);
    expect(lines).toEqual([]);
    expect(core.stats()).toMatchObject({ differed: 0, failed: 0 });
    expect(core.stats().compared - before).toBe(COUNTRY_CODES.length);
    expect(COUNTRY_CODES.filter((code) => countryServers(COUNTRY_SERVERS, code).length > 0).length).toBeGreaterThan(2);
  });
});
