import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecureStore } from "../src/main/security/secureStore";
import { RustCore } from "../src/main/core/rustCore";
import type { NativeSecureStore } from "../src/main/core/nativeStore";

const state = vi.hoisted(() => ({ directory: "", encrypted: vi.fn() }));
vi.mock("electron", () => ({ app: { getPath: () => state.directory }, safeStorage: {
  isEncryptionAvailable: () => true, getSelectedStorageBackend: () => "gnome_libsecret",
  encryptString: (value: string) => { state.encrypted(); return Buffer.from(`TEST:${value}`); },
  decryptString: (value: Buffer) => {
    const text = value.toString(); if (!text.startsWith("TEST:")) throw new Error("TEST key failure");
    return text.slice(5);
  },
} }));

beforeEach(async () => { state.directory = await mkdtemp(join(tmpdir(), "levik-store-test-")); state.encrypted.mockClear(); });
afterEach(async () => { await rm(state.directory, { recursive: true, force: true }); });

function nativeStore(): NativeSecureStore {
  return { get: vi.fn(async () => ({ found: true, value: Buffer.from("TEST identity") })),
    put: vi.fn(async () => {}), remove: vi.fn(async () => {}) };
}

describe("secure-store writer selection", () => {
  it("keeps the existing format and serializes concurrent Node writes", async () => {
    const store = new SecureStore();
    const original = Buffer.from("TEST first");
    const first = store.put("settings", original); original.fill(0);
    await first;
    expect((await store.get("settings"))?.toString()).toBe("TEST first");
    await Promise.all([store.put("settings", Buffer.from("TEST second")), store.put("settings", Buffer.from("TEST third"))]);
    expect((await store.get("settings"))?.toString()).toBe("TEST third");
    const envelope: unknown = JSON.parse(await readFile(join(state.directory, "secure-v1/settings.json"), "utf8"));
    expect(envelope).toMatchObject({ version: 1, ciphertext: expect.any(String) });
    await store.remove("settings"); expect(await store.get("settings")).toBeNull();
  });

  it("does not repeat a failed native write or removal through Electron", async () => {
    const store = new SecureStore(); await store.put("device_identity", Buffer.from("TEST identity"));
    const native = nativeStore();
    vi.mocked(native.put).mockRejectedValue(new Error("Native write failed"));
    vi.mocked(native.remove).mockRejectedValue(new Error("Native removal failed"));
    const core = new RustCore(null, () => {}, "rust");
    store.useRustCore(core, async () => native, () => {});
    state.encrypted.mockClear();
    await expect(store.put("device_identity", Buffer.from("TEST must not replace"))).rejects.toThrow("Native write failed");
    await expect(store.remove("device_identity")).rejects.toThrow("Native removal failed");
    expect(state.encrypted).not.toHaveBeenCalled();
    core.setMode("ts");
    expect((await store.get("device_identity"))?.toString()).toBe("TEST identity");
  });

  it("does not reinterpret a malformed native read as an absent identity", async () => {
    const store = new SecureStore(); await store.put("device_identity", Buffer.from("TEST identity"));
    const native = nativeStore();
    const read = vi.mocked(native.get);
    read.mockResolvedValueOnce({ found: true, value: Buffer.from("TEST identity") });
    read.mockResolvedValue({ found: true });
    store.useRustCore(new RustCore(null, () => {}, "rust"), async () => native, () => {});
    await expect(store.get("device_identity")).rejects.toThrow("восстановить");
    expect(native.put).not.toHaveBeenCalled();
  });

  it("leaves Node available if activation fails before any native mutation", async () => {
    const store = new SecureStore(); await store.put("device_identity", Buffer.from("TEST identity"));
    const report = vi.fn();
    store.useRustCore(new RustCore(null, () => {}, "rust"), async () => { throw new Error("TEST unavailable"); }, report);
    await store.put("access_token", Buffer.from("TEST token"));
    expect((await store.get("access_token"))?.toString()).toBe("TEST token");
    expect(report).toHaveBeenCalledOnce();
  });
});
