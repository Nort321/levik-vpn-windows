import { describe, expect, it, vi } from "vitest";
import { CoreSecureStore, secretValue, type NativeSecureStore } from "../src/main/core/nativeStore";
import type { CoreMode } from "../src/main/core/rustCore";

function configured(mode: CoreMode = "rust", restored = Buffer.from("TEST existing device key")) {
  const reference = Buffer.from("TEST existing device key");
  const native = { get: vi.fn(async () => ({ found: true, value: restored })), put: vi.fn(), remove: vi.fn() } satisfies NativeSecureStore;
  const open = vi.fn(async () => native);
  const report = vi.fn();
  let currentMode = mode;
  const bridge = new CoreSecureStore({ directory: "/TEST/userData", backend: () => "macos", mode: () => currentMode,
    open, reference: async () => reference, report });
  return { bridge, reference, restored, native, open, report, mode: (value: CoreMode) => { currentMode = value; } };
}

describe("Rust secure-store activation", () => {
  it.each(["ts", "shadow"] as const)("does not open the OS key store in %s mode", async (mode) => {
    const { bridge, open } = configured(mode);
    expect(await bridge.handle()).toBeNull();
    expect(open).not.toHaveBeenCalled();
  });

  it("compares the exact existing identity before allowing writes, then zeros comparison buffers", async () => {
    const { bridge, open, native, reference, restored } = configured();
    expect(await bridge.handle()).toBe(native);
    expect(await bridge.handle()).toBe(native);
    expect(open).toHaveBeenCalledOnce();
    expect(native.put).not.toHaveBeenCalled();
    expect(reference.every((byte) => byte === 0)).toBe(true);
    expect(restored.every((byte) => byte === 0)).toBe(true);
  });

  it("shares activation among concurrent operations", async () => {
    const { bridge, open, native } = configured();
    expect(await Promise.all([bridge.handle(), bridge.handle(), bridge.handle()])).toEqual([native, native, native]);
    expect(open).toHaveBeenCalledOnce();
  });

  it("does not replace or write an identity on mismatch", async () => {
    const { bridge, native, report, open } = configured("rust", Buffer.from("TEST different identity"));
    expect(await bridge.handle()).toBeNull();
    expect(await bridge.handle()).toBeNull();
    expect(open).toHaveBeenCalledOnce();
    expect(native.put).not.toHaveBeenCalled();
    expect(native.remove).not.toHaveBeenCalled();
    expect(report).toHaveBeenCalledOnce();
  });

  it("honors a mode change while activation is pending and can later reuse the verified handle", async () => {
    const { bridge, native, mode } = configured();
    const pending = bridge.handle(); mode("ts");
    expect(await pending).toBeNull();
    mode("rust"); expect(await bridge.handle()).toBe(native);
  });

  it("does not try again or reveal a key-store error", async () => {
    const { bridge, open, report } = configured();
    open.mockRejectedValueOnce(new Error("PRIVATE keychain details"));
    expect(await bridge.handle()).toBeNull();
    expect(await bridge.handle()).toBeNull();
    expect(open).toHaveBeenCalledOnce();
    expect(report).toHaveBeenCalledWith();
  });

  it("does not activate when the existing identity is missing", async () => {
    const open = vi.fn();
    const bridge = new CoreSecureStore({ directory: "/TEST/userData", backend: () => "macos", mode: () => "rust",
      open, reference: async () => null, report: () => {} });
    expect(await bridge.handle()).toBeNull();
    expect(open).not.toHaveBeenCalled();
  });

  it.each([undefined, null, {}, { found: false, value: Buffer.from("must not discard") }, { found: true }, { found: true, value: "plaintext" }])
    ("never treats a malformed result as a missing secret", (value) => { expect(() => secretValue(value)).toThrow("восстановить"); });

  it("distinguishes missing secrets and empty values", () => {
    expect(secretValue({ found: false })).toBeNull();
    expect(secretValue({ found: false, value: null })).toBeNull();
    expect(secretValue({ found: true, value: Buffer.alloc(0) })).toEqual(Buffer.alloc(0));
  });
});
