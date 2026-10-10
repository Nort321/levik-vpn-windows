import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiskLog, redactLogLine } from "../src/main/diagnostics/diskLog";
import { classifyCoreLogLine, networkTypeOfInterface, probeErrorCode, protocolOf } from "../src/main/telemetry/codes";
import { ConnectionTelemetry } from "../src/main/telemetry/connectionTelemetry";
import { MAX_TIMELINE_EVENTS, SessionRecorder, type TelemetrySessionBody } from "../src/main/telemetry/sessionRecorder";
import { buildBatches, MAX_BATCH_BYTES, TelemetryClient } from "../src/main/telemetry/telemetryClient";
import { TelemetryQueue } from "../src/main/telemetry/telemetryQueue";

const CLIENT = { platform: "windows", app: "1.3.0", os: "11" } as const;
const SETTINGS = { killSwitch: true, autoRecovery: true, splitTunnel: false };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

let directory: string;
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), "levik-telemetry-")); });
afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

function clock(start = Date.UTC(2026, 9, 10, 12)) {
  let value = start;
  return { now: () => value, advance: (ms: number) => { value += ms; } };
}

describe("telemetry codes", () => {
  it("reduces core log lines to fixed codes and ignores informational lines", () => {
    expect(classifyCoreLogLine("2026/10/10 [Warning] [1] app/proxyman/outbound: failed to process outbound traffic > dial tcp 1.2.3.4:443: i/o timeout")).toBe("dial_timeout");
    expect(classifyCoreLogLine("[Warning] transport/internet/reality: REALITY: processed invalid connection")).toBe("reality_verify_failed");
    expect(classifyCoreLogLine("ERROR [12] outbound/tuic: connection reset by peer")).toBe("conn_reset");
    expect(classifyCoreLogLine("Xray 26.7.28 (Xray, Penetrates Everything.) started")).toBeNull();
    expect(classifyCoreLogLine("[Info] accepted tcp:example.com:443")).toBeNull();
  });

  it("maps socket errors and servers to contract values", () => {
    expect(probeErrorCode(Object.assign(new Error("x"), { code: "ECONNRESET" }))).toBe("reset");
    expect(probeErrorCode(Object.assign(new Error("x"), { code: "ERR_TLS_CERT_ALTNAME_INVALID" }))).toBe("tls");
    expect(probeErrorCode("nope")).toBe("other");
    expect(protocolOf({ outbound: { protocol: "vless", streamSettings: { network: "tcp", security: "reality" } } })).toBe("vless-reality");
    expect(protocolOf({ outbound: { protocol: "vless", streamSettings: { network: "xhttp" } } })).toBe("vless-xhttp");
    expect(protocolOf({ tuic: {}, outbound: {} })).toBe("tuic");
    expect(networkTypeOfInterface("Беспроводная сеть")).toBe("wifi");
    expect(networkTypeOfInterface("Ethernet 2")).toBe("ethernet");
    expect(networkTypeOfInterface(null)).toBe("unknown");
  });
});

describe("SessionRecorder", () => {
  it("builds ordered checkpoints with increasing seq and a final end", () => {
    const time = clock();
    const session = new SessionRecorder(CLIENT, "user", SETTINGS, time.now);
    session.attempt("🇩🇪 Germany", "vless-reality", "initial");
    time.advance(900);
    session.connected();
    time.advance(60_000);
    session.coreLog("dial_timeout");
    session.coreLog("dial_timeout");
    session.probeFailed(["timeout", "timeout", "not a code!"]);
    time.advance(15_000);
    session.probeSucceeded();
    const checkpoint = session.snapshot();
    expect(checkpoint).toMatchObject({ v: 1, seq: 0, final: false, ageS: 75, trigger: "user" });
    expect(checkpoint.sid).toMatch(UUID);
    expect(checkpoint.timeline).toEqual([
      { t: 0, e: "attempt", node: "🇩🇪 Germany", proto: "vless-reality", cause: "initial" },
      { t: 900, e: "connected" },
      { t: 60_900, e: "core_log", code: "dial_timeout", count: 2 },
      { t: 60_900, e: "probe_fail", codes: ["timeout", "other"], n: 1 },
      { t: 75_900, e: "probe_ok", afterFailures: 1 },
    ]);
    time.advance(5_000);
    session.end("user", "user");
    session.connected();
    const final = session.snapshot();
    expect(final).toMatchObject({ seq: 1, final: true, end: { by: "user", code: "user", durationS: 80 } });
    expect(final.timeline).toHaveLength(5);
  });

  it("keeps how a session started and its latest events when the timeline is full", () => {
    const time = clock();
    const session = new SessionRecorder(CLIENT, "user", SETTINGS, time.now);
    session.attempt("A", "tuic", "initial");
    for (let index = 0; index < MAX_TIMELINE_EVENTS + 50; index++) {
      time.advance(1_000);
      session.power(index % 2 ? "resume" : "suspend");
    }
    const { timeline } = session.snapshot();
    expect(timeline).toHaveLength(MAX_TIMELINE_EVENTS);
    expect(timeline[0]).toMatchObject({ e: "attempt" });
    expect(timeline.at(-1)?.t).toBe((MAX_TIMELINE_EVENTS + 50) * 1_000);
  });
});

describe("TelemetryQueue", () => {
  it("keeps the latest checkpoint per session and acknowledges only what was sent", async () => {
    const time = clock();
    const queue = new TelemetryQueue(directory, time.now);
    const session = new SessionRecorder(CLIENT, "user", SETTINGS, time.now);
    const first = session.snapshot();
    const second = session.snapshot();
    await queue.put({ startedAt: session.startedAt, savedAt: time.now(), body: second });
    await queue.put({ startedAt: session.startedAt, savedAt: time.now(), body: first });
    expect((await queue.pending()).map((entry) => entry.body.seq)).toEqual([1]);
    const third = session.snapshot();
    await queue.put({ startedAt: session.startedAt, savedAt: time.now(), body: third });
    await queue.acknowledge([{ sid: session.sid, seq: 1 }]);
    expect((await queue.pending()).map((entry) => entry.body.seq)).toEqual([2]);
    await queue.acknowledge([{ sid: session.sid, seq: 2 }]);
    expect(await queue.pending()).toEqual([]);
  });

  it("rotates the install id every UTC day and drops week-old reports", async () => {
    const time = clock();
    const queue = new TelemetryQueue(directory, time.now);
    const today = await queue.installId();
    expect(await queue.installId()).toBe(today);
    const session = new SessionRecorder(CLIENT, "user", SETTINGS, time.now);
    await queue.put({ startedAt: time.now(), savedAt: time.now(), body: session.snapshot() });
    time.advance(24 * 60 * 60 * 1_000);
    const tomorrow = await queue.installId();
    expect(tomorrow).not.toBe(today);
    expect(tomorrow).toMatch(UUID);
    expect(await new TelemetryQueue(directory, time.now).installId()).toBe(tomorrow);
    time.advance(7 * 24 * 60 * 60 * 1_000);
    expect(await queue.pending()).toEqual([]);
  });
});

describe("telemetry transport", () => {
  it("splits batches by count and size and recomputes ageS", () => {
    const time = clock();
    const entries = Array.from({ length: 45 }, () => {
      const session = new SessionRecorder(CLIENT, "user", SETTINGS, time.now);
      return { startedAt: time.now() - 120_000, savedAt: time.now(), body: session.snapshot() };
    });
    const batches = buildBatches("install", entries, time.now());
    expect(batches.map((batch) => batch.sessions.length)).toEqual([20, 20, 5]);
    const body = JSON.parse(batches[0]!.body) as { install: string; sessions: TelemetrySessionBody[] };
    expect(body.install).toBe("install");
    expect(body.sessions[0]!.ageS).toBe(120);
    for (const batch of batches) expect(Buffer.byteLength(batch.body)).toBeLessThanOrEqual(MAX_BATCH_BYTES);
  });

  it("sends anonymously and classifies responses", async () => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("{}", { status: 202 }))
      .mockResolvedValueOnce(new Response("{}", { status: 400 }))
      .mockResolvedValueOnce(new Response("{}", { status: 503 }))
      .mockRejectedValueOnce(new Error("offline"));
    const client = new TelemetryClient(fetchImpl);
    expect(await client.send("{}")).toBe("sent");
    expect(await client.send("{}")).toBe("rejected");
    expect(await client.send("{}")).toBe("retry");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe("https://leviknet.org/api/telemetry/v1/sessions");
    expect(init).toMatchObject({ method: "POST", credentials: "omit" });
    expect(Object.keys(init?.headers ?? {})).toEqual(["Content-Type"]);
    // 503 from the first origin falls back to the second one, which is offline.
    expect(String(fetchImpl.mock.calls[3]![0])).toBe("https://leviknet.com/api/telemetry/v1/sessions");
  });

  it("accepts only a well-formed network token", async () => {
    const expiresAt = "2026-10-11T12:00:00.000Z";
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ token: "abc.def", asn: 8359, country: "RU", expiresAt }))
      .mockResolvedValueOnce(Response.json({ token: null, asn: null, country: null, expiresAt: null }));
    const client = new TelemetryClient(fetchImpl);
    expect(await client.networkToken()).toEqual({ token: "abc.def", expiresAt: Date.parse(expiresAt) });
    expect(await client.networkToken()).toBeNull();
  });
});

describe("ConnectionTelemetry", () => {
  function fakeHttp() {
    const sent: string[] = [];
    const http = {
      send: vi.fn(async (body: string) => { sent.push(body); return "sent" as const; }),
      networkToken: vi.fn(async () => ({ token: "net.token", expiresAt: Date.UTC(2026, 9, 11) })),
    };
    return { http: http as unknown as TelemetryClient, sent, mock: http };
  }

  it("records nothing while disabled and clears the queue when switched off", async () => {
    const { http, mock } = fakeHttp();
    const telemetry = new ConnectionTelemetry(directory, CLIENT, http);
    telemetry.begin("user", SETTINGS);
    expect(telemetry.active).toBe(false);
    await telemetry.setEnabled(true);
    telemetry.begin("user", SETTINGS);
    telemetry.record((session) => session.attempt("A", "tuic", "initial"));
    await telemetry.persist();
    await expect(readFile(join(directory, "queue.json"), "utf8")).resolves.toContain("\"tuic\"");
    await telemetry.setEnabled(false);
    await expect(readFile(join(directory, "queue.json"), "utf8")).rejects.toThrow();
    expect(telemetry.active).toBe(false);
    telemetry.dispose();
    expect(mock.networkToken).not.toHaveBeenCalled();
  });

  it("sends a finished session with the network token and removes it", async () => {
    const { http, sent } = fakeHttp();
    const telemetry = new ConnectionTelemetry(directory, CLIENT, http);
    await telemetry.setEnabled(true);
    await telemetry.prepareNetwork();
    telemetry.begin("auto_connect", SETTINGS);
    telemetry.record((session) => session.attempt("A", "vless-reality", "initial"));
    telemetry.record((session) => session.connected());
    await telemetry.finish("user", "user");
    await telemetry.flush();
    const body = JSON.parse(sent.at(-1)!) as { sessions: TelemetrySessionBody[] };
    expect(body.sessions).toHaveLength(1);
    expect(body.sessions[0]).toMatchObject({ final: true, trigger: "auto_connect", net: { token: "net.token" } });
    await telemetry.flush();
    expect(sent).toHaveLength(1);
    telemetry.dispose();
  });

  it("closes sessions left open by an app that stopped unexpectedly", async () => {
    const time = clock();
    const crashed = new ConnectionTelemetry(directory, CLIENT, fakeHttp().http, time.now);
    await crashed.setEnabled(true);
    crashed.begin("user", SETTINGS);
    time.advance(42_000);
    crashed.record((session) => session.connected());
    await crashed.persist();
    crashed.dispose();

    const { http, sent } = fakeHttp();
    const restarted = new ConnectionTelemetry(directory, CLIENT, http, time.now);
    await restarted.setEnabled(true);
    await restarted.flush();
    const body = JSON.parse(sent[0]!) as { sessions: TelemetrySessionBody[] };
    expect(body.sessions[0]).toMatchObject({ seq: 1, final: true, end: { by: "unknown", code: null, durationS: 42 } });
    restarted.dispose();
  });
});

describe("DiskLog", () => {
  it("redacts addresses, foreign domains, identifiers and queries", async () => {
    expect(redactLogLine("[Warning] failed to dial tcp:203.0.113.7:443 via example.com for user@mail.ru"))
      .toBe("[Warning] failed to dial tcp:<ip>:443 via <host> for <email>");
    expect(redactLogLine("GET https://api.leviknet.org/v1/x?token=abc 2001:db8::1 11111111-1111-4111-8111-111111111111"))
      .toBe("GET https://api.leviknet.org/v1/x?<query> <ip6> <id>");
    expect(redactLogLine("2026/10/10 13:14:04 Xray 26.7.28 loaded config.json")).toBe("2026/10/10 13:14:04 Xray 26.7.28 loaded config.json");
    expect(redactLogLine("dial [fe80:0:0:0:1:2:3:4]:443")).toBe("dial [<ip6>]:443");
  });

  it("keeps two rotating files and skips per-connection lines", async () => {
    const log = new DiskLog(directory, () => new Date(Date.UTC(2026, 9, 10)));
    log.write("[Info] accepted tcp:example.com:443");
    log.write("Состояние: connected");
    for (let index = 0; index < 1_900; index++) log.write(`[Warning] ${"x ".repeat(450)} ${index}`);
    await log.flush();
    for (let index = 0; index < 1_900; index++) log.write(`[Warning] ${"y ".repeat(450)}${index}`);
    const text = await log.read();
    expect(text).not.toContain("accepted");
    expect(text.endsWith(`${"y ".repeat(450)}1899\n`)).toBe(true);
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(1024 * 1024);
  });
});

describe("switching telemetry off", () => {
  it("does not let in-flight writes recreate the queue", async () => {
    const queue = new TelemetryQueue(directory);
    const session = new SessionRecorder(CLIENT, "user", SETTINGS);
    const put = queue.put({ startedAt: session.startedAt, savedAt: Date.now(), body: session.snapshot() });
    const cleared = queue.clear();
    await Promise.all([put, cleared]);
    await expect(readFile(join(directory, "queue.json"), "utf8")).rejects.toThrow();
    expect(await queue.pending()).toEqual([]);
  });
});
