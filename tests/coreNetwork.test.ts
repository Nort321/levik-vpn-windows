import { describe, expect, it } from "vitest";
import type { AppSettings } from "../src/shared/contracts";
import { CoreSettings } from "../src/main/core/coreSettings";
import { CoreLiveLoad } from "../src/main/core/coreLiveLoad";
import { RustCore } from "../src/main/core/rustCore";
import { loadLevikCore } from "../src/main/core/levikCore";
import { portableSettings } from "../src/main/platform/settingsSync";

const settings: AppSettings = { routingMode: "global", automaticServer: true, autoReconnect: true, killSwitch: true,
  useDoh: true, dnsServer: "1.1.1.1", theme: "system", launchAtLogin: false, autoConnectOnLaunch: false,
  closeToTray: true, preventDnsLeaks: true, favoriteServerIds: [], favoriteNodes: null, antiDpiEnabled: false,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20", splitTunnelMode: "off",
  splitTunnelProcesses: [], connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
  sharePresence: true, sleepAtHome: true };
const node = `n1${"a".repeat(20)}`;

describe("network domain output guards", () => {
  it("rejects unknown settings and keeps the TypeScript result", () => {
    const core = new RustCore({ functions: () => ["settingsSync.parsePending"], call: () => '{"untrusted":true}' }, () => {}, "rust");
    expect(new CoreSettings(() => core).parsePending({ killSwitch: true })).toEqual({ killSwitch: true });
    expect(core.stats().failed).toBe(1);
  });

  it("rejects an out-of-range native load", () => {
    const core = new RustCore({ functions: () => ["liveLoad.parseLiveLoad"], call: () => JSON.stringify({ load: { [node]: 2 }, full: [], quality: null }) }, () => {}, "rust");
    expect(new CoreLiveLoad(() => core).parse({ ok: true, load: { [node]: 0.5 } })).toEqual({ load: { [node]: 0.5 }, full: [], quality: null });
    expect(core.stats().failed).toBe(1);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real network domain bridge", () => {
  it.each(["shadow", "rust"] as const)("preserves sync and freshness rules in %s mode", (mode) => {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded") throw new Error("native module rejected");
    const core = new RustCore(status.module, () => {}, mode);
    const sync = new CoreSettings(() => core);
    expect(sync.portableSettings(settings)).toEqual(portableSettings(settings));
    expect(sync.parsePending({ killSwitch: true, dnsServer: "1.2.3.4" })).toEqual({ killSwitch: true });
    expect(sync.parseSettingsDocument({ ok: true, revision: 7, settings: { killSwitch: false } })).toEqual({ revision: 7, settings: { killSwitch: false } });
    expect(sync.syncedChanges(settings, { ...settings, killSwitch: false })).toEqual({ killSwitch: false });
    expect(sync.remotePatch(settings, { killSwitch: false }, { killSwitch: true })).toEqual({});
    expect(sync.withoutConfirmed({ killSwitch: true }, { killSwitch: false })).toEqual({ killSwitch: true });
    const load = new CoreLiveLoad(() => core);
    const parsed = load.parse({ ok: true, v: 2, load: { [node]: 0.4 }, quality: { [node]: 1.2 },
      routes: { [node]: { id: `r1${"b".repeat(20)}`, path: [node], complete: true, state: "healthy", ageSeconds: 5, resourceLoad: 0.4, resourceHeadroom: 0.6 } } });
    if (!parsed) throw new Error("valid load refused");
    const first = load.merge(null, { kind: "fresh", ...parsed, etag: '"first"' }, 1000, false);
    const same = load.merge(first, { kind: "same" }, 80_000, false);
    expect(same?.qualityAt).toBe(1000);
    expect(same?.routesAt).toBe(1000);
    expect(load.currentRouteResource(same, [node], 80_000)?.state).toBe("unknown");
    expect(load.currentQuality(same, 7_201_000)).toEqual({});
    expect(load.merge(first, { kind: "fresh", load: {}, full: [], quality: { [node]: 0.5 }, etag: null }, 2000, true)?.quality).toEqual({ [node]: 1.2 });
    expect(load.presenceReport("disconnected", null)).toEqual({ vpnConnected: false, nodeId: null, country: null });
    expect(core.stats().failed).toBe(0);
    expect(core.stats().differed).toBe(0);
    expect(mode === "shadow" ? core.stats().compared : core.stats().decided).toBeGreaterThan(10);
  });
});
