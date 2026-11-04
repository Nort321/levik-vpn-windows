import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadLevikCore } from "../src/main/core/levikCore";
import type { NativeTelemetryQueue, OpenTelemetryQueue } from "../src/main/core/nativeTelemetry";
import { RustCore } from "../src/main/core/rustCore";
import { ConnectionTelemetry } from "../src/main/telemetry/connectionTelemetry";
import { SessionRecorder } from "../src/main/telemetry/sessionRecorder";
import { buildBatches, TelemetryClient } from "../src/main/telemetry/telemetryClient";
import { TelemetryQueue, type QueuedSession } from "../src/main/telemetry/telemetryQueue";

let directory: string;
const now = () => Date.UTC(2026, 10, 5, 12);
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), "levik-native-queue-")); });
afterEach(async () => { vi.restoreAllMocks(); await rm(directory, { recursive: true, force: true }); });
function entry(): QueuedSession {
  const session = new SessionRecorder({ platform: "windows", app: "TEST", os: "TEST" }, "user",
    { killSwitch: true, autoRecovery: true, splitTunnel: false }, now);
  return { startedAt: now(), savedAt: now(), body: session.snapshot() };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function fake(): NativeTelemetryQueue {
  return { snapshot: vi.fn(), installId: vi.fn(), put: vi.fn(), pending: vi.fn(async () => "[]"),
    unfinished: vi.fn(async () => "[]"), acknowledge: vi.fn(), clear: vi.fn() };
}

describe("optional Rust anonymous queue", () => {
  it.each(["ts", "shadow"] as const)("does not open the native queue in %s mode", async (mode) => {
    const queue = new TelemetryQueue(directory, now);
    const open = vi.fn();
    queue.useRustCore(new RustCore(null, () => {}, mode), open, () => {});
    await queue.put(entry());
    expect(open).not.toHaveBeenCalled();
  });

  it("keeps the Node checkpoint on activation failure and reports without private details", async () => {
    const queue = new TelemetryQueue(directory, now);
    const open = vi.fn(async () => { throw new Error("PRIVATE queue details"); });
    const report = vi.fn();
    queue.useRustCore(new RustCore(null, () => {}, "rust"), open, report);
    const row = entry(); await queue.put(row);
    expect(await queue.pending()).toEqual([row]);
    expect(open).toHaveBeenCalledOnce(); expect(report).toHaveBeenCalledWith();
  });

  it("does not replay a failed native write through Node", async () => {
    const queue = new TelemetryQueue(directory, now);
    const native = fake(); native.put = vi.fn(async () => { throw new Error("TEST write failure"); });
    queue.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    await expect(queue.put(entry())).rejects.toThrow();
    expect(await readdir(directory)).toEqual([]);
  });

  it("ignores a native activation completed after the mode changed", async () => {
    const queue = new TelemetryQueue(directory, now);
    const core = new RustCore(null, () => {}, "rust");
    const opened = deferred<NativeTelemetryQueue>(); const started = deferred<void>(); const native = fake();
    queue.useRustCore(core, async () => { started.resolve(); return opened.promise; }, () => {});
    const row = entry(); const putting = queue.put(row);
    await started.promise; core.setMode("ts"); opened.resolve(native); await putting;
    expect(native.put).not.toHaveBeenCalled(); expect(await queue.pending()).toEqual([row]);
  });

  it("finishes earlier native writes before clearing and honors consent if the bridge clear fails", async () => {
    const queue = new TelemetryQueue(directory, now); const row = entry(); await queue.put(row);
    const native = fake(); const written = deferred<void>(); const started = deferred<void>();
    native.put = vi.fn(async () => { started.resolve(); await written.promise; });
    native.clear = vi.fn(async () => { throw new Error("TEST bridge failure"); });
    queue.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    const putting = queue.put(row); await started.promise; const clearing = queue.clear();
    expect(native.clear).not.toHaveBeenCalled(); written.resolve(); await putting; await clearing;
    expect(await readdir(directory)).toEqual([]); expect(await queue.pending()).toEqual([]);
  });

  it.each([false, true])("does not restore interrupted reports after consent changes while reading (reenable: %s)", async (reenable) => {
    const native = fake(); const reading = deferred<void>(); const rows = deferred<string>(); const row = entry();
    native.unfinished = vi.fn(async () => { reading.resolve(); return rows.promise; });
    const telemetry = new ConnectionTelemetry(directory, { platform: "windows", app: "TEST", os: "TEST" }, new TelemetryClient(), now);
    telemetry.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    try {
      const enabling = telemetry.setEnabled(true); await reading.promise;
      const disabling = telemetry.setEnabled(false);
      native.unfinished = vi.fn(async () => "[]");
      const reenabling = reenable ? telemetry.setEnabled(true) : Promise.resolve();
      rows.resolve(JSON.stringify([row]));
      await Promise.all([enabling, disabling, reenabling]);
      expect(native.put).not.toHaveBeenCalled(); expect(await readdir(directory)).toEqual([]);
    } finally { telemetry.dispose(); }
  });
});

describe("anonymous network token consent", () => {
  it("ignores a late network token from an earlier consent period", async () => {
    const native = fake(); const response = deferred<{ token: string; expiresAt: number } | null>();
    const http = new TelemetryClient(); vi.spyOn(http, "networkToken").mockReturnValue(response.promise);
    const telemetry = new ConnectionTelemetry(directory, { platform: "windows", app: "TEST", os: "TEST" }, http, now);
    telemetry.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    try {
      await telemetry.setEnabled(true); const preparing = telemetry.prepareNetwork();
      await telemetry.setEnabled(false); await telemetry.setEnabled(true);
      response.resolve({ token: "TEST old network token", expiresAt: now() + 60_000 }); await preparing;
      telemetry.begin("user", { killSwitch: true, autoRecovery: true, splitTunnel: false }); await telemetry.persist();
      expect(native.put).toHaveBeenCalledOnce();
      const put = vi.mocked(native.put).mock.calls[0];
      expect(JSON.parse(put![0]).body.net.token).toBeNull();
    } finally { telemetry.dispose(); }
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real Rust report queue", () => {
  function configured() {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const loaded = loadLevikCore(modulePath);
    if (loaded.state !== "loaded" || !loaded.module.openTelemetryQueue) throw new Error("Native queue unavailable");
    const open: OpenTelemetryQueue = loaded.module.openTelemetryQueue;
    const core = new RustCore(loaded.module, () => {}, "rust");
    const report = vi.fn();
    const queue = new TelemetryQueue(directory, now); queue.useRustCore(core, open, report);
    return { queue, core, open, report };
  }

  it("preserves an unsaved daily id and the latest checkpoint across repeated mode handovers", async () => {
    const { queue, core, report } = configured(); core.setMode("ts");
    const id = await queue.installId(); expect(await readdir(directory)).toEqual([]);
    core.setMode("rust"); expect(await queue.installId()).toBe(id);
    const row = entry(); const putting = queue.put(row); row.body.seq = 99; await putting;
    expect((await queue.pending())[0]?.body.seq).toBe(0);
    core.setMode("shadow"); expect(await queue.installId()).toBe(id);
    const next = { ...row, body: { ...row.body, seq: 1 } }; await queue.put(next);
    core.setMode("rust"); expect(await queue.pending()).toEqual([next]);
    await queue.acknowledge([{ sid: next.body.sid, seq: 1 }]);
    core.setMode("ts"); expect(await queue.pending()).toEqual([]); expect(await queue.unfinished()).toHaveLength(1);
    expect(report).not.toHaveBeenCalled();
  });

  it("keeps Node/Rust checkpoints compatible and removes reports without backups on clear", async () => {
    const { queue, core, report } = configured(); const row = entry();
    await queue.put(row); const rustBytes = await readFile(join(directory, "queue.json"), "utf8");
    const node = new TelemetryQueue(directory, now); expect(await node.pending()).toEqual([row]);
    await node.acknowledge([{ sid: row.body.sid, seq: 0 }]);
    const updated = { ...row, body: { ...row.body, seq: 1, final: true } };
    core.setMode("ts"); await queue.put(updated); core.setMode("rust");
    expect(await queue.pending()).toEqual([updated]);
    expect(JSON.parse(rustBytes).sessions).toEqual([row]);
    await queue.acknowledge([{ sid: row.body.sid, seq: 1 }]); expect(await queue.unfinished()).toEqual([]);
    const writing = queue.put(row); const clearing = queue.clear(); await Promise.all([writing, clearing]);
    expect(await readdir(directory)).toEqual([]); core.setMode("ts"); expect(await queue.pending()).toEqual([]);
    expect(report).not.toHaveBeenCalled();
  });

  it("builds the same bounded JSON bytes through the production bridge", () => {
    const { core } = configured(); const entries = Array.from({ length: 45 }, entry);
    const expected = buildBatches("TEST anonymous id", entries, now());
    const actual = core.run("telemetryClient.buildBatches", { install: "TEST anonymous id", entries, now: now() },
      () => { throw new Error("Native function fell back"); }, (value): value is typeof expected => Array.isArray(value));
    expect(actual).toEqual(expected); expect(core.stats().decided).toBe(1);
  });
});
