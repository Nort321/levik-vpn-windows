import { describe, expect, it, vi } from "vitest";
import { nativeEventSource, type NativeEventStream } from "../src/main/core/nativeEvents";
import { MobileApiError, isAuthenticationRejected } from "../src/main/api/mobileApiClient";

const batch = (events: string[], done = false) => JSON.stringify({ ok: true, value: { events, done } });
const failure = (status: number | null, rejected: boolean) => new MobileApiError("stream unavailable", status, rejected);
function handle(...values: string[]) {
  return { read: vi.fn(async () => values.shift() ?? batch([], true)), close: vi.fn() } satisfies NativeEventStream;
}

describe("native live-event reader", () => {
  it("keeps heartbeat batches and known event names, then closes the handle", async () => {
    const native = handle(batch([]), batch(["ready", "settings"]));
    const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
    expect(await reader.read()).toEqual({ done: false, value: [] });
    expect(await reader.read()).toEqual({ done: false, value: ["ready", "settings"] });
    expect((await reader.read()).done).toBe(true);
    expect(native.close).toHaveBeenCalledOnce();
  });

  it.each(["not JSON", batch(["erase_data"]), '{"ok":true,"value":{"events":[],"done":"false"}}'])
    ("rejects a malformed native result without leaking it: %s", async (value) => {
      const native = handle(value);
      const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
      await expect(reader.read()).rejects.toThrow("stream unavailable");
      expect(native.close).toHaveBeenCalledOnce();
    });

  it("sanitizes native exceptions", async () => {
    const native = { read: vi.fn().mockRejectedValue(new Error("private-session")), close: vi.fn() };
    const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
    await expect(reader.read()).rejects.toThrow("stream unavailable");
    expect(native.close).toHaveBeenCalledOnce();
  });

  it.each([true, false])("preserves only a structured unauthorized response: valid=%s", async (valid) => {
    const native = handle(JSON.stringify({ ok: false, error: { status: 401, authenticationRejected: true,
      code: valid ? "unauthorized" : "http_401", message: "private-session" } }));
    const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
    const error: unknown = await reader.read().catch((caught: unknown) => caught);
    expect(isAuthenticationRejected(error)).toBe(valid);
    expect(String(error)).not.toContain("private-session");
    expect(native.close).toHaveBeenCalledOnce();
  });

  it("cancels a read that has not received headers, including repeated abort", async () => {
    const native = { read: vi.fn(() => new Promise<string>(() => {})), close: vi.fn() };
    const controller = new AbortController();
    const reader = nativeEventSource(native, controller.signal, failure).getReader();
    const pending = reader.read();
    controller.abort(); controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(native.close).toHaveBeenCalledOnce();
  });

  it("cancels without reading if already aborted", async () => {
    const native = handle();
    const controller = new AbortController(); controller.abort();
    const reader = nativeEventSource(native, controller.signal, failure).getReader();
    await expect(reader.read()).rejects.toMatchObject({ name: "AbortError" });
    expect(native.read).not.toHaveBeenCalled();
    expect(native.close).toHaveBeenCalledOnce();
  });

  it("closes the native transport when the consumer cancels", async () => {
    const native = handle(batch(["ready"]));
    const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
    await reader.read();
    await reader.cancel();
    expect(native.close).toHaveBeenCalledOnce();
  });

  it("does not leave a pending reader if native cleanup throws", async () => {
    const native = { read: async () => batch([], true), close: () => { throw new Error("native failure"); } };
    const reader = nativeEventSource(native, new AbortController().signal, failure).getReader();
    expect((await reader.read()).done).toBe(true);
  });
});
