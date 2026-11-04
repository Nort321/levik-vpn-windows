import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isDiagnosisVerdict, isIndexList } from "../src/main/core/coreGuards";
import { levikCorePath, loadLevikCore } from "../src/main/core/levikCore";
import { coreBridge, coreModeFor, jsonDifference, RustCore, type CoreBridge } from "../src/main/core/rustCore";
import { diagnosisSummary, diagnosisVerdict, parseDiagnoseReport, type DiagnosisInput, type DiagnosisVerdict } from "../src/main/platform/diagnosis";
import { avoidMaintenance, maintenanceFor, maintenanceMove, parseMaintenance } from "../src/main/platform/maintenance";
import { flagEnabled, parseAdvice, parseRemoteConfig, visibleAnnouncements, type RemoteConfig } from "../src/main/platform/remoteConfig";
import * as smart from "../src/main/vpn/smartAuto";

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
});
