import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppSettings, SubscriptionSummary } from "../src/shared/contracts";
import { MobileApiClient } from "../src/main/api/mobileApiClient";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";
import { RequestSigner } from "../src/main/security/requestSigner";
import { deepLinkFromArgv, isAllowedExternalUrl, isCabinetTarget, isHandoffUrl, parseDeepLink } from "../src/main/platform/links";
import { expiryMilestone, expiryNotices } from "../src/main/platform/notices";
import {
  adviceCandidates,
  currentAdvice,
  flagEnabled,
  mergeFetched,
  parseRemoteConfig,
  PROTOCOL_ADVICE_TTL_MS,
  RemoteConfigClient,
  visibleAnnouncements,
} from "../src/main/platform/remoteConfig";
import {
  parseSettingsDocument,
  portableSettings,
  remotePatch,
  syncedChanges,
  withoutConfirmed,
} from "../src/main/platform/settingsSync";

const NOW = Date.parse("2026-10-10T12:00:00Z");
const ANNOUNCEMENT = {
  id: "0b8f5f0e-7d1c-4d6f-9b6a-1d8f0e2a3b4c",
  level: "warning",
  title: "Работы на серверах",
  body: "Нидерланды недоступны до 14:00.",
  linkUrl: "https://leviknet.org/status",
  notify: true,
  startsAt: "2026-10-10T10:00:00.000Z",
  endsAt: "2026-10-10T14:00:00.000Z",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => vi.unstubAllGlobals());

describe("remote configuration", () => {
  it("keeps only valid flags, announcements and advice", () => {
    const config = parseRemoteConfig({
      ok: true,
      refreshAfterSeconds: 10,
      flags: { new_picker: { enabled: true, rolloutPercent: 150 }, "Bad-Key": { enabled: true } },
      announcements: [ANNOUNCEMENT, { ...ANNOUNCEMENT, id: "x" }, { ...ANNOUNCEMENT, id: "1b8f5f0e-7d1c-4d6f-9b6a-1d8f0e2a3b4c", linkUrl: "javascript:alert(1)" }],
      protocols: { preferred: ["hysteria2", "<script>"], avoid: ["vless-reality"] },
    });
    expect(config).toEqual({
      flags: { new_picker: { enabled: true, rolloutPercent: 100 } },
      announcements: [
        { ...ANNOUNCEMENT, startsAt: Date.parse(ANNOUNCEMENT.startsAt), endsAt: Date.parse(ANNOUNCEMENT.endsAt) },
        { ...ANNOUNCEMENT, id: "1b8f5f0e-7d1c-4d6f-9b6a-1d8f0e2a3b4c", linkUrl: null, startsAt: Date.parse(ANNOUNCEMENT.startsAt), endsAt: Date.parse(ANNOUNCEMENT.endsAt) },
      ],
      protocols: { preferred: ["hysteria2"], avoid: ["vless-reality"] },
      refreshAfterSeconds: 300,
    });
    expect(parseRemoteConfig({ ok: false })).toBeNull();
  });

  it("shows current announcements the user has not closed", () => {
    const config = parseRemoteConfig({ ok: true, announcements: [ANNOUNCEMENT] });
    expect(visibleAnnouncements(config, new Set(), NOW)).toHaveLength(1);
    expect(visibleAnnouncements(config, new Set([ANNOUNCEMENT.id]), NOW)).toHaveLength(0);
    expect(visibleAnnouncements(config, new Set(), Date.parse(ANNOUNCEMENT.endsAt))).toHaveLength(0);
  });

  it("rolls features out by a local salt", () => {
    const config = parseRemoteConfig({ ok: true, flags: { half: { enabled: true, rolloutPercent: 50 }, off: { enabled: false, rolloutPercent: 100 } } });
    const enabled = Array.from({ length: 400 }, (_, index) => flagEnabled(config, "half", `salt-${index}`)).filter(Boolean).length;
    expect(enabled).toBeGreaterThan(150);
    expect(enabled).toBeLessThan(250);
    expect(flagEnabled(config, "half", "fixed")).toBe(flagEnabled(config, "half", "fixed"));
    expect(flagEnabled(config, "off", "fixed")).toBe(false);
    expect(flagEnabled(config, "missing", "fixed")).toBe(false);
  });

  it("keeps advice measured outside the tunnel and lets it expire", () => {
    const outside = mergeFetched(null, { response: {}, config: parseRemoteConfig({ ok: true, protocols: { preferred: ["tuic"], avoid: [] } })! }, NOW, false);
    expect(currentAdvice(outside, NOW)).toEqual({ preferred: ["tuic"], avoid: [] });
    const throughTunnel = mergeFetched(outside, { response: {}, config: parseRemoteConfig({ ok: true, protocols: { preferred: ["trojan"], avoid: [] } })! }, NOW + 1_000, true);
    expect(currentAdvice(throughTunnel, NOW + 1_000)).toEqual({ preferred: ["tuic"], avoid: [] });
    expect(currentAdvice(throughTunnel, NOW + PROTOCOL_ADVICE_TTL_MS)).toBeNull();
  });

  it("narrows automatic choice by protocol advice", () => {
    const servers = [{ id: "a", proto: "vless-reality" }, { id: "b", proto: "hysteria2" }, { id: "c", proto: "vless-xhttp" }];
    const protocol = (server: { proto: string }) => server.proto;
    expect(adviceCandidates(servers, { preferred: ["hysteria2"], avoid: ["vless-reality"] }, protocol).map((server) => server.id)).toEqual(["b"]);
    expect(adviceCandidates(servers, { preferred: [], avoid: ["vless-reality"] }, protocol).map((server) => server.id)).toEqual(["b", "c"]);
    expect(adviceCandidates(servers, { preferred: [], avoid: ["vless-reality", "hysteria2", "vless-xhttp"] }, protocol)).toHaveLength(3);
    expect(adviceCandidates(servers, null, protocol)).toHaveLength(3);
  });

  it("asks anonymously and falls back to the second domain", async () => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValueOnce(json(200, { ok: true, announcements: [] }));
    const result = await new RemoteConfigClient("windows", "1.4.0", fetchImpl).fetch();
    expect(result?.config.announcements).toEqual([]);
    const [target, init] = fetchImpl.mock.calls[1]!;
    expect(target).toBe("https://leviknet.com/api/app/v1/config");
    expect(init).toMatchObject({ method: "GET", credentials: "omit", redirect: "error" });
    expect(init?.headers).toEqual({ Accept: "application/json", "X-Levik-Client": "windows/1.4.0" });
  });

  it("does not repeat a rejected request on the other domain", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(json(400, { ok: false }));
    await expect(new RemoteConfigClient("windows", "1.4.0", fetchImpl).fetch()).resolves.toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("settings sync", () => {
  const settings = {
    routingMode: "global", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
    dnsServer: "1.1.1.1", theme: "system", launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
    preventDnsLeaks: true, favoriteServerIds: [], antiDpiEnabled: false, antiDpiPackets: "tlshello",
    antiDpiLength: "100-200", antiDpiInterval: "10-20", splitTunnelMode: "off", splitTunnelProcesses: [],
    connectionTelemetry: true, telemetryNoticeShown: true, syncSettings: true,
  } satisfies AppSettings;

  it("shares only portable fields", () => {
    expect(portableSettings({ ...settings, antiDpiPackets: "1,2" })).toEqual({
      routingMode: "global", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
      antiDpiEnabled: false, antiDpiLength: "100-200", antiDpiInterval: "10-20",
    });
    expect(syncedChanges(settings, { ...settings, killSwitch: false, theme: "dark", dnsServer: "8.8.8.8" })).toEqual({ killSwitch: false });
  });

  it("applies the account's values except unsent and device-only ones", () => {
    const remote = { killSwitch: false, routingMode: "bypassRu", antiDpiPackets: "1-3" } as const;
    expect(remotePatch(settings, remote, {})).toEqual({ killSwitch: false, routingMode: "bypassRu", antiDpiPackets: "1-3" });
    expect(remotePatch(settings, remote, { killSwitch: true })).toEqual({ routingMode: "bypassRu", antiDpiPackets: "1-3" });
    expect(remotePatch({ ...settings, antiDpiPackets: "1,2" }, remote, {})).toEqual({ killSwitch: false, routingMode: "bypassRu" });
  });

  it("forgets only the edits the server confirmed", () => {
    expect(withoutConfirmed({ killSwitch: false, useDoh: true }, { killSwitch: false, useDoh: false })).toEqual({ useDoh: true });
  });

  it("reads the server document strictly", () => {
    expect(parseSettingsDocument({ ok: true, revision: 3, settings: { killSwitch: false, routingMode: "x", extra: 1 } }))
      .toEqual({ revision: 3, settings: { killSwitch: false } });
    expect(parseSettingsDocument({ ok: true, revision: -1, settings: {} })).toBeNull();
  });

  it("sends the client header and signs PUT requests", async () => {
    let sentBody = "";
    const fetchMock = vi.fn(async (_url: URL, init: RequestInit) => {
      sentBody = Buffer.from(init.body as Uint8Array).toString("utf8");
      return json(200, { ok: true, settings: {}, revision: 1, updatedAt: null, updatedBy: "windows" });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new MobileApiClient("https://leviknet.com", new RequestSigner(DeviceIdentity.create()), "1.4.0");
    await client.updateSettings("access-token", { killSwitch: false });
    const [url, init] = (fetchMock.mock.calls[0] ?? []) as unknown as [URL, RequestInit];
    expect(String(url)).toBe("https://leviknet.com/api/mobile/v1/settings");
    expect(init.method).toBe("PUT");
    expect(init.headers).toMatchObject({ "X-Levik-Client": "windows/1.4.0", "Content-Type": "application/json" });
    // The client wipes the buffer after sending, so the body is read inside fetch.
    expect(sentBody).toBe('{"changes":{"killSwitch":false}}');
  });
});

describe("links", () => {
  it("accepts only known levik:// targets", () => {
    expect(parseDeepLink("levik://open?to=subscriptions")).toBe("profile");
    expect(parseDeepLink("levik://open")).toBe("home");
    expect(parseDeepLink("levik://open?to=constructor")).toBeNull();
    expect(parseDeepLink("levik://connect?to=home")).toBeNull();
    expect(parseDeepLink("https://open?to=home")).toBeNull();
    expect(deepLinkFromArgv(["C:\\Levik VPN.exe", "--flag", "levik://open?to=plans"])).toBe("profile");
    expect(deepLinkFromArgv(["C:\\Levik VPN.exe"])).toBeNull();
  });

  it("opens only the website's one-time sign-in page", () => {
    const token = "A".repeat(43);
    expect(isHandoffUrl(`https://leviknet.org/handoff?token=${token}`)).toBe(true);
    expect(isHandoffUrl(`https://leviknet.com/handoff?token=${token}`)).toBe(true);
    expect(isHandoffUrl(`https://evil.example/handoff?token=${token}`)).toBe(false);
    expect(isHandoffUrl(`https://leviknet.org/dashboard?token=${token}`)).toBe(false);
    expect(isHandoffUrl(`http://leviknet.org/handoff?token=${token}`)).toBe(false);
    expect(isCabinetTarget("/dashboard/plans")).toBe(true);
    expect(isCabinetTarget("/dashboard/admin")).toBe(false);
    expect(isAllowedExternalUrl("https://t.me/leviksupportbot")).toBe(true);
    expect(isAllowedExternalUrl("https://example.com")).toBe(false);
  });
});

describe("subscription reminders", () => {
  const subscription = (expireAt: string | null, status = "active"): SubscriptionSummary => ({
    uuid: "sub-1", title: "Standard", status, expireAt,
    traffic: { usedBytes: 0, limitBytes: 0 },
    devices: { used: 1, limit: 3, items: [] },
    shield: { supported: false, enabled: false },
    actions: { renew: true, revokeDevice: true },
  });

  it("reminds 3 days and 1 day before the end and once after it", () => {
    const day = 24 * 60 * 60 * 1_000;
    expect(expiryMilestone(NOW + 5 * day, NOW)).toBeNull();
    expect(expiryMilestone(NOW + 2 * day, NOW)).toBe("3d");
    expect(expiryMilestone(NOW + day / 2, NOW)).toBe("1d");
    expect(expiryMilestone(NOW - day, NOW)).toBe("expired");
    expect(expiryMilestone(NOW - 4 * day, NOW)).toBeNull();
  });

  it("does not repeat a reminder and starts over after renewal", () => {
    const expiresSoon = subscription(new Date(NOW + 2 * 24 * 60 * 60 * 1_000).toISOString());
    const [first] = expiryNotices([expiresSoon], new Set(), NOW);
    expect(first?.notice.title).toBe("Подписка скоро закончится");
    expect(expiryNotices([expiresSoon], new Set([first!.key]), NOW)).toEqual([]);
    const renewed = subscription(new Date(NOW + 2.5 * 24 * 60 * 60 * 1_000).toISOString());
    expect(expiryNotices([renewed], new Set([first!.key]), NOW)).toHaveLength(1);
    expect(expiryNotices([subscription(expiresSoon.expireAt, "disabled"), subscription(null)], new Set(), NOW)).toEqual([]);
  });
});
