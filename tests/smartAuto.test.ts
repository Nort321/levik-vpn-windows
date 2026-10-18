import { describe, expect, it } from "vitest";
import { currentNodeLoad, parseNodeLoad, parseRemoteConfig, type StoredRemoteConfig } from "../src/main/platform/remoteConfig";
import {
  emptyHistory,
  MAX_NETWORKS,
  nextRung,
  parseHistory,
  ProtocolHistoryStore,
  rankSmart,
  recordFailure,
  recordSuccess,
  SmartLadder,
  TunnelFreezeDetector,
  verdictOf,
  winnerOf,
  worthSwitching,
  type SmartCandidate,
} from "../src/main/vpn/smartAuto";

const HOUR = 60 * 60_000;
const NODE_A = "n1aaaaaaaaaaaaaaaaaaaa";

function candidate(id: string, overrides: Partial<SmartCandidate> = {}): SmartCandidate {
  return { id, protocol: "vless-reality", latencyMs: 50, silenceMeansDown: true, load: 0.2, verdict: "unknown", ...overrides };
}

describe("Smart Auto ranking", () => {
  it("prefers a free server over a slightly faster busy one", () => {
    const ranked = rankSmart([candidate("busy", { latencyMs: 40, load: 0.85 }), candidate("free", { latencyMs: 60, load: 0.1 })], null);
    expect(ranked.map((item) => item.id)).toEqual(["free", "busy"]);
  });

  it("leaves out blocked protocols and down TCP servers unless nothing else is left", () => {
    const ranked = rankSmart([
      candidate("blocked", { verdict: "blocked", latencyMs: 10 }),
      candidate("down", { latencyMs: null }),
      candidate("udp", { protocol: "hysteria2", latencyMs: null, silenceMeansDown: false }),
    ], null);
    expect(ranked.map((item) => item.id)).toEqual(["udp"]);
    expect(rankSmart([candidate("blocked", { verdict: "blocked" })], null).map((item) => item.id)).toEqual(["blocked"]);
  });

  it("follows the operator advice only until the computer has its own experience", () => {
    const advice = { preferred: ["hysteria2"], avoid: ["vless-reality"] };
    const fresh = rankSmart([candidate("reality"), candidate("hy2", { protocol: "hysteria2", latencyMs: 80 })], advice);
    expect(fresh[0]?.id).toBe("hy2");
    const known = rankSmart([candidate("reality", { verdict: "works" }), candidate("hy2", { protocol: "hysteria2", latencyMs: 80 })], advice);
    expect(known[0]?.id).toBe("reality");
  });

  it("climbs to an untried protocol first, then to any untried server", () => {
    const ranked = rankSmart([candidate("r1"), candidate("r2", { latencyMs: 55 }), candidate("hy", { protocol: "hysteria2", latencyMs: 90 })], null);
    expect(nextRung(ranked, new Set(["vless-reality"]), new Set(["r1"]))?.id).toBe("hy");
    expect(nextRung(ranked, new Set(["vless-reality", "hysteria2"]), new Set(["r1", "hy"]))?.id).toBe("r2");
    expect(nextRung(ranked, new Set(), new Set(["r1", "r2", "hy"]))).toBeNull();
    expect(worthSwitching(100, 80)).toBe(false);
    expect(worthSwitching(100, 70)).toBe(true);
  });

  it("stops climbing after a few rungs", () => {
    const ladder = new SmartLadder(2);
    ladder.climbed();
    expect(ladder.exhausted()).toBe(false);
    ladder.climbed();
    expect(ladder.exhausted()).toBe(true);
    ladder.reset();
    expect(ladder.exhausted()).toBe(false);
  });
});

describe("protocol history", () => {
  it("suspects after one dead server and blocks after a second, per network", () => {
    const once = recordFailure(emptyHistory(), "net", "vless-reality", "n1de", 0);
    expect(verdictOf(once, "net", "vless-reality", HOUR)).toBe("suspect");
    const twice = recordFailure(once, "net", "vless-reality", "n1nl", HOUR);
    expect(verdictOf(twice, "net", "vless-reality", 2 * HOUR)).toBe("blocked");
    expect(verdictOf(twice, "net", "vless-reality", 26 * HOUR)).toBe("unknown");
    expect(verdictOf(twice, "other", "vless-reality", HOUR)).toBe("unknown");
    const works = recordSuccess(twice, "net", "vless-reality", 3 * HOUR, "de");
    expect(verdictOf(works, "net", "vless-reality", 4 * HOUR)).toBe("works");
  });

  it("names the last winner per network until it fails, and forgets old networks", () => {
    let history = recordSuccess(emptyHistory(), "net-0", "hysteria2", 0, "first");
    expect(winnerOf(history, "net-0")).toBe("first");
    expect(winnerOf(recordFailure(history, "net-0", "hysteria2", NODE_A, HOUR, "first"), "net-0")).toBeNull();
    for (let index = 1; index <= MAX_NETWORKS; index++) history = recordSuccess(history, `net-${index}`, "tuic", index, `s${index}`);
    expect(winnerOf(history, "net-0")).toBeNull();
    expect(history.networks).toHaveLength(MAX_NETWORKS);
  });

  it("parses only well-formed records", () => {
    const key = "0123456789abcdef";
    const parsed = parseHistory({
      networks: [
        { key, protocols: { "vless-reality": { failedNodes: [NODE_A, 5], lastFailureAt: 10, lastSuccessAt: -1 }, "BAD NAME": {} } },
        { key: "not-a-key", protocols: {} },
      ],
      winners: { [key]: "server-1", other: "server-2" },
    });
    expect(parsed).toEqual({
      networks: [{ key, protocols: { "vless-reality": { failedNodes: [NODE_A], lastFailureAt: 10, lastSuccessAt: 0 } } }],
      winners: { [key]: "server-1" },
    });
    expect(parseHistory("nonsense")).toEqual(emptyHistory());
  });

  it("names a network by its subnets, not by tunnels, and differently per salt", async () => {
    const store = new ProtocolHistoryStore("/nonexistent/levik-smart-auto.json");
    await store.load();
    const wifi = { address: "192.168.1.23", netmask: "255.255.255.0", family: "IPv4" as const, mac: "aa:bb:cc:dd:ee:ff", internal: false, cidr: "192.168.1.23/24" };
    const tun = { ...wifi, address: "172.19.0.1", cidr: "172.19.0.1/30" };
    const key = store.networkKey({ "Wi-Fi": [wifi] });
    expect(key).toMatch(/^[0-9a-f]{16}$/);
    expect(store.networkKey({ "Wi-Fi": [{ ...wifi, address: "192.168.1.99", cidr: "192.168.1.99/24" }], LevikVPN: [tun] })).toBe(key);
    expect(store.networkKey({ "Wi-Fi": [{ ...wifi, address: "10.0.0.5", netmask: "255.0.0.0", cidr: "10.0.0.5/8" }] })).not.toBe(key);
    expect(store.networkKey({ utun4: [tun] })).toBeNull();
  });
});

describe("tunnel freeze detector", () => {
  it("raises the alarm when uploads get no answers, once per cooldown", () => {
    const detector = new TunnelFreezeDetector();
    expect(detector.record(100 * 1024, 10 * 1024, 0)).toBe(false);
    expect(detector.record(104 * 1024, 50 * 1024, 12_000)).toBe(true);
    detector.record(104 * 1024, 50 * 1024, 13_000);
    expect(detector.record(105 * 1024, 100 * 1024, 26_000)).toBe(false);
  });

  it("ignores ordinary browsing", () => {
    const detector = new TunnelFreezeDetector();
    detector.record(0, 0, 0);
    expect(detector.record(900 * 1024, 60 * 1024, 12_000)).toBe(false);
  });
});

describe("node load in the remote config", () => {
  it("keeps node ids with values from 0 to 1 and expires with the configuration", () => {
    expect(parseNodeLoad({ [NODE_A]: 0.4, n1bbbbbbbbbbbbbbbbbbbb: 1.5, other: 0.2 })).toEqual({ [NODE_A]: 0.4 });
    const config = parseRemoteConfig({ ok: true, nodeLoad: { [NODE_A]: 0.7 } });
    expect(config?.nodeLoad).toEqual({ [NODE_A]: 0.7 });
    if (!config) throw new Error("config");
    const stored: StoredRemoteConfig = { response: {}, config, fetchedAt: 0, advice: null, adviceAt: null };
    expect(currentNodeLoad(stored, 9 * 60_000)).toEqual({ [NODE_A]: 0.7 });
    expect(currentNodeLoad(stored, 11 * 60_000)).toEqual({});
  });
});
