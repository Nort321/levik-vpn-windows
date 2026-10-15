import { describe, expect, it } from "vitest";
import {
  captivePortal,
  checkServices,
  diagnosisSummary,
  diagnosisVerdict,
  parseDiagnoseReport,
  vpnPhase,
  type DiagnosisInput,
} from "../src/main/platform/diagnosis";

const NOW = Date.parse("2026-10-15T12:00:00Z");
const NODE = "n1142bf5571df2373ffb23";

const REPORT = parseDiagnoseReport({
  generatedAt: "2026-10-15T12:00:00.000Z",
  network: { known: true, provider: "MTS", country: "RU" },
  whitelist: { status: "none", since: null },
  services: [
    { slug: "youtube", name: "YouTube", state: "restricted", operator: "unknown" },
    { slug: "discord", name: "Discord", state: "outage", operator: "unknown" },
    { slug: "telegram", name: "Telegram", state: "operational", operator: "failing" },
    { slug: "BAD SLUG", name: "x", state: "operational", operator: "unknown" },
  ],
  protocols: { preferred: ["vless-reality", "hysteria2"], avoid: ["vless-ws"] },
  countries: [{ country: "DE", online: 0, total: 2 }, { country: "NL", online: 3, total: 3 }],
  maintenance: [{ nodeId: NODE, startsAt: "2026-10-15T11:30:00Z", endsAt: "2026-10-15T12:30:00Z" }],
});

function input(patch: Partial<DiagnosisInput>): DiagnosisInput {
  return {
    network: "ok",
    cellular: false,
    vpn: "off",
    serverCountry: "NL",
    serverNodeId: null,
    protocol: "vless-reality",
    failingServices: [],
    anyServiceWorks: true,
    report: REPORT,
    now: NOW,
    ...patch,
  };
}

describe("diagnosis", () => {
  it("parses the website's report and drops what it cannot trust", () => {
    expect(REPORT?.services.map((item) => item.slug)).toEqual(["youtube", "discord", "telegram"]);
    expect(REPORT?.network).toEqual({ known: true, provider: "MTS" });
    expect(REPORT?.maintenance).toHaveLength(1);
    expect(parseDiagnoseReport(null)).toBeNull();
    expect(parseDiagnoseReport({ services: [{ slug: "x", name: "X", state: "weird" }] })?.services[0]?.state).toBe("unknown");
  });

  it("starts with the computer's own network", () => {
    expect(diagnosisVerdict(input({ network: "none" })).verdict).toBe("NO_NETWORK");
    expect(diagnosisVerdict(input({ network: "captive" })).verdict).toBe("CAPTIVE_PORTAL");
    expect(diagnosisVerdict(input({ report: null, anyServiceWorks: false })))
      .toEqual({ verdict: "INTERNET_DOWN", action: "retry" });
    expect(diagnosisVerdict(input({ vpn: "connected", report: null, anyServiceWorks: false })).verdict).toBe("VPN_PATH_BROKEN");
  });

  it("explains a VPN that does not connect", () => {
    expect(diagnosisVerdict(input({ vpn: "failed", serverNodeId: NODE }))).toMatchObject({ verdict: "SERVER_DOWN", action: "bestServer" });
    expect(diagnosisVerdict(input({ vpn: "failed", serverCountry: "DE" }))).toMatchObject({ verdict: "SERVER_DOWN", country: "DE" });
    expect(diagnosisVerdict(input({ vpn: "connecting", protocol: "vless-ws" })))
      .toMatchObject({ verdict: "PROTOCOL", provider: "MTS", protocol: "vless-reality" });
    expect(diagnosisVerdict(input({ vpn: "failed" }))).toMatchObject({ verdict: "VPN_UNREACHABLE", action: "bestServer" });
    // Whitelists are a cellular verdict; a computer is not on one itself.
    const whitelisted = REPORT ? { ...REPORT, whitelist: { status: "active" } } : null;
    expect(diagnosisVerdict(input({ vpn: "failed", report: whitelisted })).verdict).toBe("VPN_UNREACHABLE");
    expect(diagnosisVerdict(input({ vpn: "failed", report: whitelisted, cellular: true })).verdict).toBe("WHITELISTS");
  });

  it("names the service and who is at fault", () => {
    expect(diagnosisVerdict(input({ failingServices: ["discord", "youtube"] })))
      .toEqual({ verdict: "SERVICE_DOWN_EVERYWHERE", action: null, service: "Discord" });
    expect(diagnosisVerdict(input({ failingServices: ["youtube"] })))
      .toEqual({ verdict: "SERVICE_RESTRICTED", action: "connect", service: "YouTube" });
    expect(diagnosisVerdict(input({ failingServices: ["telegram"] })))
      .toMatchObject({ verdict: "SERVICE_OPERATOR", service: "Telegram", provider: "MTS" });
    expect(diagnosisVerdict(input({ failingServices: ["github"] })))
      .toMatchObject({ verdict: "SERVICE_FAILS_DIRECT", service: "GitHub" });
    expect(diagnosisVerdict(input({})).verdict).toBe("ALL_OK_VPN_OFF");
    expect(diagnosisVerdict(input({ vpn: "connected", failingServices: ["youtube"] })))
      .toMatchObject({ verdict: "SERVICE_VIA_VPN", action: "bestServer" });
    expect(diagnosisVerdict(input({ vpn: "connected" }))).toEqual({ verdict: "ALL_OK", action: "support" });
  });

  it("says it in one sentence with one button", () => {
    const summary = diagnosisSummary({ verdict: "SERVER_DOWN", action: "bestServer", country: "DE" }, { networkSettings: true });
    expect(summary.text).toBe("Сервер в стране «Германия» сейчас недоступен. Переключитесь на другой.");
    expect(summary.actionLabel).toBe("Переключить на лучший сервер");
    expect(diagnosisSummary({ verdict: "PROTOCOL", action: "bestServer", provider: "MTS", protocol: "hysteria2" }, { networkSettings: true }).text)
      .toBe("У MTS сейчас лучше работает Hysteria 2.");
    expect(diagnosisSummary({ verdict: "NO_NETWORK", action: "networkSettings" }, { networkSettings: false }))
      .toMatchObject({ action: null, actionLabel: null });
  });

  it("maps the connection status", () => {
    expect(vpnPhase("connected")).toBe("connected");
    expect(vpnPhase("reconnecting")).toBe("connecting");
    expect(vpnPhase("error")).toBe("failed");
    expect(vpnPhase("disconnecting")).toBe("off");
  });

  it("checks services and sign-in pages", async () => {
    const seen: string[] = [];
    const checks = await checkServices(async (url) => {
      seen.push(url);
      if (url.includes("youtube")) throw new Error("reset");
      return new Response(null, { status: url.includes("discord") ? 503 : 200 });
    });
    expect(seen).toHaveLength(4);
    expect(checks).toEqual([
      { slug: "telegram", ok: true },
      { slug: "youtube", ok: false },
      { slug: "discord", ok: false },
      { slug: "github", ok: true },
    ]);
    const probe = { url: "http://captive.apple.com/hotspot-detect.html", expect: "Success" };
    expect(await captivePortal(async () => new Response("<HTML>Success</HTML>"), probe)).toBe(false);
    expect(await captivePortal(async () => new Response("<form>Log in</form>"), probe)).toBe(true);
    expect(await captivePortal(async () => new Response(null, { status: 302, headers: { Location: "http://portal" } }), probe)).toBe(true);
    expect(await captivePortal(async () => { throw new Error("offline"); }, probe)).toBe(false);
  });
});
