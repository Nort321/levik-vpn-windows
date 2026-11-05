import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiEndpoints, DEFAULT_API_ORIGIN } from "../src/main/api/apiEndpoints";
import { loadLevikCore } from "../src/main/core/levikCore";
import type { NativeApiDiscovery } from "../src/main/core/nativeApiDiscovery";
import { RustCore } from "../src/main/core/rustCore";
import { useEndpointsDocument } from "../src/main/platform/serviceEndpoints";

afterEach(() => useEndpointsDocument(null));
const healthy = () => new Response('{"ok":true}', { headers: { "Content-Type": "application/json" } });
function deferred<T>() { let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const fetch = vi.fn(async () => healthy());
  const endpoints = new ApiEndpoints(DEFAULT_API_ORIGIN, undefined, fetch);
  const native: NativeApiDiscovery = { resolve: vi.fn(async () => DEFAULT_API_ORIGIN), invalidate: vi.fn() };
  const create = vi.fn(() => native); const report = vi.fn(); const core = new RustCore(null, () => {}, mode);
  endpoints.useRustCore(core, create, report);
  return { endpoints, fetch, native, create, report, core };
}

describe("Rust API discovery selection", () => {
  it.each(["ts", "shadow"] as const)("does not open native discovery in %s mode", async (mode) => {
    const { endpoints, fetch, create } = configured(mode); await endpoints.resolve();
    expect(fetch).toHaveBeenCalledOnce(); expect(create).not.toHaveBeenCalled();
  });

  it("does not probe production hosts for an explicit override", async () => {
    const create = vi.fn(); const fetch = vi.fn(); const endpoints = new ApiEndpoints("https://custom.example", undefined, fetch);
    endpoints.useRustCore(new RustCore(null, () => {}, "rust"), create, () => {});
    expect((await endpoints.resolve()).origin).toBe("https://custom.example");
    expect(create).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
  });

  it("uses the trusted host list without account data and shares the pending result", async () => {
    const { endpoints, fetch, native } = configured(); const result = deferred<string>();
    native.resolve = vi.fn(() => result.promise);
    const a = endpoints.resolve(); const b = endpoints.resolve();
    expect(native.resolve).toHaveBeenCalledOnce();
    const call = vi.mocked(native.resolve).mock.calls[0];
    expect(JSON.parse(call![0])).toContain(DEFAULT_API_ORIGIN);
    result.resolve(DEFAULT_API_ORIGIN);
    expect((await a).origin).toBe(DEFAULT_API_ORIGIN); expect((await b).origin).toBe(DEFAULT_API_ORIGIN);
    expect(fetch).not.toHaveBeenCalled();
    endpoints.invalidate(); expect(native.invalidate).toHaveBeenCalledOnce();
  });

  it("falls back only when activation fails before the native check", async () => {
    const { endpoints, fetch, create, report } = configured();
    create.mockImplementation(() => { throw new Error("PRIVATE details"); });
    await endpoints.resolve(); await endpoints.resolve();
    expect(create).toHaveBeenCalledOnce(); expect(fetch).toHaveBeenCalledOnce(); expect(report).toHaveBeenCalledWith();
  });

  it.each(["failure", "untrusted origin"])("does not repeat native discovery through Node on %s", async (result) => {
    const { endpoints, native, fetch } = configured();
    native.resolve = result === "failure" ? vi.fn(async () => { throw new Error("TEST unavailable"); })
      : vi.fn(async () => "https://untrusted.example");
    await expect(endpoints.resolve()).rejects.toThrow(); expect(fetch).not.toHaveBeenCalled();
  });

  it("refreshes signed hosts once before retrying the native health sequence", async () => {
    const native: NativeApiDiscovery = { resolve: vi.fn().mockRejectedValueOnce(new Error("TEST unreachable"))
      .mockResolvedValueOnce("https://reserve.example"), invalidate: vi.fn() };
    const refresh = vi.fn(async () => { useEndpointsDocument({ sequence: 2, apiOrigins: ["https://reserve.example"],
      webOrigin: "https://leviknet.org", configUrls: [] }); return true; });
    const fetch = vi.fn(); const endpoints = new ApiEndpoints(DEFAULT_API_ORIGIN, refresh, fetch);
    endpoints.useRustCore(new RustCore(null, () => {}, "rust"), () => native, () => {});
    expect((await endpoints.resolve()).origin).toBe("https://reserve.example");
    expect(refresh).toHaveBeenCalledOnce(); expect(native.resolve).toHaveBeenCalledTimes(2); expect(fetch).not.toHaveBeenCalled();
  });

  it("cannot restore an old cache or clear a newer pending check after invalidation", async () => {
    const first = deferred<Response>(); const second = deferred<Response>();
    const fetch = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockImplementation(async () => healthy());
    const endpoints = new ApiEndpoints(DEFAULT_API_ORIGIN, undefined, fetch);
    useEndpointsDocument({ sequence: 2, apiOrigins: ["https://first.example"], webOrigin: "https://leviknet.org", configUrls: [] });
    const a = endpoints.resolve(); endpoints.invalidate();
    useEndpointsDocument({ sequence: 3, apiOrigins: ["https://second.example"], webOrigin: "https://leviknet.org", configUrls: [] });
    const b = endpoints.resolve(); first.resolve(healthy()); expect((await a).origin).toBe("https://first.example");
    const c = endpoints.resolve(); expect(fetch).toHaveBeenCalledTimes(2);
    second.resolve(healthy()); expect((await b).origin).toBe("https://second.example"); expect((await c).origin).toBe("https://second.example");
    expect((await endpoints.resolve()).origin).toBe("https://second.example"); expect(fetch).toHaveBeenCalledTimes(2);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("native discovery handle", () => {
  it("exposes the typed factory, validates origins and can resolve an explicit override without network", async () => {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded" || !status.module.createApiDiscovery) throw new Error("Native API discovery missing");
    const create = status.module.createApiDiscovery;
    for (const origin of ["http://unsafe.example", "https://user@unsafe.example", "https://unsafe.example/path"]) {
      expect(() => create(origin)).toThrow("Levik API is unavailable");
    }
    const override = create("https://unused.invalid"); override.invalidate();
    expect(await override.resolve("[]")).toBe("https://unused.invalid");
    await expect(create(DEFAULT_API_ORIGIN).resolve('["http://unsafe.example"]')).rejects.toThrow("Levik API is unavailable");
  });
});
