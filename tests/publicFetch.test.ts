import { describe, expect, it, vi } from "vitest";
import { corePublicFetch, type NativePublicClient } from "../src/main/core/publicFetch";
import { RemoteConfigClient } from "../src/main/platform/remoteConfig";
import { LiveLoadClient } from "../src/main/platform/liveLoad";
import { ApiEndpoints, DEFAULT_API_ORIGIN } from "../src/main/api/apiEndpoints";
import { TelemetryClient } from "../src/main/telemetry/telemetryClient";

const options: RequestInit = { method: "GET", credentials: "omit", redirect: "error" };
function response(body: string, status = 200, extra: Record<string, unknown> = {}) {
  return JSON.stringify({ ok: true, value: { body: Buffer.from(body).toString("base64"), status,
    contentType: "application/json", etag: null, retryAfter: null, ...extra } });
}
function setup(output = response('{"ok":true}')) {
  const operation = { read: vi.fn(async () => output), close: vi.fn() };
  const native = { start: vi.fn((_input: string) => operation) } satisfies NativePublicClient;
  const fallback = vi.fn().mockResolvedValue(new Response("node"));
  return { native, operation, fallback, fetch: corePublicFetch(() => native, () => "rust", fallback) };
}

describe("anonymous Rust HTTP boundary", () => {
  it("returns bounded body and cache metadata without an account or device", async () => {
    const { fetch, native, operation, fallback } = setup(response('{"ok":true}', 200, { etag: '"v1"', retryAfter: "45" }));
    const result = await fetch("https://api.example/api/app/v1/load", { ...options,
      headers: { "X-Levik-Client": "macos/1.0.0", "If-None-Match": '"v0"' } });
    expect(await result.json()).toEqual({ ok: true });
    expect(result.headers.get("etag")).toBe('"v1"');
    expect(result.headers.get("retry-after")).toBe("45");
    expect(JSON.parse(native.start.mock.calls[0]?.[0] ?? "null")).toEqual({ url: "https://api.example/api/app/v1/load",
      method: "GET", body: "", client: "macos/1.0.0", etag: '"v0"' });
    expect(fallback).not.toHaveBeenCalled();
    expect(operation.close).toHaveBeenCalledOnce();
  });

  it.each(["Authorization", "Cookie", "X-Levik-Device-Id", "X-Levik-Signature"])
    ("refuses the private header %s before creating a request", async (name) => {
      const { fetch, native, fallback } = setup();
      await expect(fetch("https://api.example/api/health", { ...options, headers: { [name]: "private" } })).rejects.toThrow("служебные данные");
      expect(native.start).not.toHaveBeenCalled();
      expect(fallback).not.toHaveBeenCalled();
    });

  it.each(["ts", "shadow"] as const)("sends only through Node in %s mode", async (mode) => {
    const { native, fallback } = setup();
    const fetch = corePublicFetch(() => native, () => mode, fallback);
    await fetch("https://api.example/api/health", options);
    expect(fallback).toHaveBeenCalledOnce();
    expect(native.start).not.toHaveBeenCalled();
  });

  it("keeps old modules compatible", async () => {
    const { fallback } = setup();
    await corePublicFetch(() => null, () => "rust", fallback)("https://api.example/api/health", options);
    expect(fallback).toHaveBeenCalledOnce();
  });

  it.each(["private native error", response("x".repeat(128 * 1024 + 1)), response("", 999), response("", 200, { etag: 1 })])
    ("does not replay a failed or malformed result via Node", async (output) => {
      const { fetch, operation, fallback } = setup(output);
      await expect(fetch("https://api.example/api/health", options)).rejects.toThrow("служебные данные");
      expect(operation.close).toHaveBeenCalledOnce();
      expect(fallback).not.toHaveBeenCalled();
    });

  it("cancels while native TLS or response reading is pending", async () => {
    const { fetch, operation } = setup();
    operation.read.mockImplementation(() => new Promise(() => {}));
    const controller = new AbortController();
    const pending = fetch("https://api.example/api/health", { ...options, signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(operation.close).toHaveBeenCalledOnce();
  });

  it("does not start if already aborted", async () => {
    const { fetch, native } = setup();
    const controller = new AbortController(); controller.abort();
    await expect(fetch("https://api.example/api/health", { ...options, signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(native.start).not.toHaveBeenCalled();
  });

  it("keeps config, discovery, load 304 and anonymous telemetry callers working", async () => {
    const config = setup(response('{"ok":true,"flags":{}}'));
    expect((await new RemoteConfigClient("macos", "1.0.0", config.fetch).fetch())?.config.flags).toEqual({});
    const discovery = setup();
    expect((await new ApiEndpoints(DEFAULT_API_ORIGIN, async () => false, discovery.fetch).resolve()).origin).toBe(DEFAULT_API_ORIGIN);
    const load = setup(response("", 304, { etag: '"v1"' }));
    expect(await new LiveLoadClient("macos", "1.0.0", load.fetch).fetch('"v0"')).toEqual({ kind: "same" });
    const telemetry = setup(response("", 202));
    const body = '{"install":"anonymous","sessions":[]}';
    expect(await new TelemetryClient(telemetry.fetch).send(body)).toBe("sent");
    expect(JSON.parse(telemetry.native.start.mock.calls[0]?.[0] ?? "null")).toMatchObject({ method: "POST", body, client: null, etag: null });
  });
});
