import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConfigCacheFile, type NativeConfigCache } from "../src/main/core/nativeConfigCache";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { RemoteConfigStore, parseRemoteConfig } from "../src/main/platform/remoteConfig";
import { ServiceEndpointsStore, serviceEndpoints, useEndpointsDocument } from "../src/main/platform/serviceEndpoints";

let directory: string;
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), "levik-native-cache-")); });
afterEach(async () => { useEndpointsDocument(null); await rm(directory, { recursive: true, force: true }); });

describe("optional native configuration cache", () => {
  it.each(["ts", "shadow"] as const)("leaves the native cache closed in %s mode", async (mode) => {
    const cache = new ConfigCacheFile(join(directory, "remote-config.json"), "remote-config");
    const open = vi.fn(); cache.useRustCore(new RustCore(null, () => {}, mode), open, () => {});
    await cache.write("{}"); expect(await cache.read()).toBe("{}"); expect(open).not.toHaveBeenCalled();
  });

  it("falls back once if activation fails before writing and reports no path or contents", async () => {
    const cache = new ConfigCacheFile(join(directory, "remote-config.json"), "remote-config");
    const report = vi.fn(); const open = vi.fn(async () => { throw new Error("PRIVATE file details"); });
    cache.useRustCore(new RustCore(null, () => {}, "rust"), open, report);
    await cache.write("{}"); await cache.read();
    expect(open).toHaveBeenCalledOnce(); expect(report).toHaveBeenCalledWith();
  });

  it("does not replay a native write that failed after activation", async () => {
    const path = join(directory, "remote-config.json"); await writeFile(path, "{\"original\":true}");
    const cache = new ConfigCacheFile(path, "remote-config");
    const native: NativeConfigCache = { read: async () => null, write: async () => { throw new Error("TEST failure"); } };
    cache.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    await expect(cache.write("{}")).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe('{"original":true}');
  });

  it("serializes mode changes behind an in-flight native write", async () => {
    const path = join(directory, "remote-config.json"); const cache = new ConfigCacheFile(path, "remote-config");
    const core = new RustCore(null, () => {}, "rust");
    let finish!: () => void; let began!: () => void;
    const pending = new Promise<void>((done) => { finish = done; });
    const started = new Promise<void>((done) => { began = done; });
    const native: NativeConfigCache = { read: async () => null, write: async (_kind, text) => { began(); await pending; await writeFile(path, text); } };
    cache.useRustCore(core, async () => native, () => {});
    const first = cache.write('{"seq":1}'); await started; core.setMode("ts");
    const second = cache.write('{"seq":2}'); finish(); await Promise.all([first, second]);
    expect(await readFile(path, "utf8")).toBe('{"seq":2}');
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real Rust configuration cache", () => {
  function configured() {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded" || !status.module.openConfigCache) throw new Error("Native config cache unavailable");
    return { open: status.module.openConfigCache, core: new RustCore(status.module, () => {}, "rust") };
  }

  it("loads an existing Node cache and retains original bytes before the first native update", async () => {
    const path = join(directory, "remote-config.json"); const node = new RemoteConfigStore(path);
    const response = { ok: true, flags: { rust_core_primary: { enabled: true, rolloutPercent: 100 } } };
    const config = parseRemoteConfig(response); if (!config) throw new Error("TEST config");
    const stored = { response, config, fetchedAt: 1_000, advice: null, adviceAt: null };
    await node.save(stored); const original = await readFile(path, "utf8");
    const { core, open } = configured(); const rust = new RemoteConfigStore(path); const report = vi.fn();
    rust.useRustCore(core, open, report); expect(await rust.load()).toEqual(stored);
    expect(await readdir(directory)).toEqual(["remote-config.json"]);
    await rust.save({ ...stored, fetchedAt: 2_000 });
    expect((await node.load())?.fetchedAt).toBe(2_000);
    expect(await readFile(join(directory, "migration-backup-rust-v1/data/remote-config.json"), "utf8")).toBe(original);
    expect(report).not.toHaveBeenCalled();
  });

  it("verifies the pinned endpoint signature after a native read and rejects forged cached bytes", async () => {
    const body = await readFile(join(__dirname, "fixtures/levik-config-v1.json"));
    const signature = await readFile(join(__dirname, "fixtures/levik-config-v1.json.sig"), "utf8");
    const path = join(directory, "service-endpoints.json");
    const fetchMock = vi.fn(async (url: string) => new Response(url.endsWith(".sig") ? signature : body));
    const store = new ServiceEndpointsStore(path, fetchMock as typeof fetch);
    const { core, open } = configured(); store.useRustCore(core, open, () => {});
    expect(await store.refresh()).toBe(true); useEndpointsDocument(null); await store.load();
    expect(serviceEndpoints().sequence).toBeGreaterThanOrEqual(1);
    const forged = body.toString().replace("cloudnote-sync.xyz", "attacker.example");
    await writeFile(path, JSON.stringify({ body: Buffer.from(forged).toString("base64"), signature }));
    useEndpointsDocument(null); await store.load(); expect(serviceEndpoints().sequence).toBe(0);
  });

  it("cannot name secret files or traverse paths and does not write merely by opening or reading", async () => {
    const { open } = configured(); const native = await open(directory);
    expect(await native.read("remote-config")).toBeNull();
    expect(await readdir(directory)).toEqual([]);
    // Exercise the untyped Node-API boundary with names outside the TS union.
    const status = modulePath ? loadLevikCore(modulePath) : null;
    if (status?.state !== "loaded") throw new Error("Module missing");
    const call: unknown = native;
    if (typeof call !== "object" || call === null || !("read" in call) || typeof call.read !== "function") throw new Error("TEST handle");
    await expect(call.read("../secure-v1/device_identity.json")).rejects.toThrow("cache operation failed");
    expect(await readdir(directory)).toEqual([]);
  });
});
