import { describe, expect, it, vi } from "vitest";
import { DnsLeakProtection, type RegistryValue } from "../src/main/windows/dnsLeakProtection";

function fixture(initial: RegistryValue = { existed: true, value: 0 }) {
  let backup: Buffer | null = null;
  let current = initial;
  const store = {
    get: vi.fn(async () => backup),
    put: vi.fn(async (_key: string, data: Uint8Array) => { backup = Buffer.from(data); }),
    remove: vi.fn(async () => { backup = null; }),
  };
  const registry = {
    read: vi.fn(async () => current),
    write: vi.fn(async (value: RegistryValue) => { current = value; }),
  };
  return { store, registry, create: () => new DnsLeakProtection(store, "win32", registry) };
}

describe("Windows DNS policy recovery", () => {
  it.each([{ existed: false, value: 0 }, { existed: true, value: 0 }, { existed: true, value: 1 }])(
    "restores the exact prior policy after a process restart: %j", async (previous) => {
      const { create, registry, store } = fixture(previous);
      await create().enable();
      expect(await registry.read()).toEqual({ existed: true, value: 1 });
      await create().disable();
      expect(await registry.read()).toEqual(previous);
      expect(await store.get()).toBeNull();
    },
  );

  it("keeps the recovery record after failure and retries restoration", async () => {
    const { create, registry, store } = fixture();
    const policy = create();
    await policy.enable();
    registry.write.mockRejectedValueOnce(new Error("access denied"));
    await expect(policy.disable()).rejects.toThrow("access denied");
    expect(await store.get()).not.toBeNull();
    await policy.disable();
    expect(await registry.read()).toEqual({ existed: true, value: 0 });
    expect(await store.get()).toBeNull();
  });

  it("does not mistake a read failure for an absent policy", async () => {
    const { create, registry, store } = fixture();
    registry.read.mockRejectedValueOnce(new Error("registry unavailable"));
    await expect(create().enable()).rejects.toThrow("registry unavailable");
    expect(registry.write).not.toHaveBeenCalled();
    expect(store.put).not.toHaveBeenCalled();
  });

  it("does not modify Windows if the recovery record cannot be persisted", async () => {
    const { create, registry, store } = fixture();
    store.put.mockRejectedValueOnce(new Error("disk unavailable"));
    await expect(create().enable()).rejects.toThrow("disk unavailable");
    expect(registry.write).not.toHaveBeenCalled();
  });

  it("preserves an administrator's subsequent policy change", async () => {
    const { create, registry } = fixture();
    const policy = create();
    await policy.enable();
    await registry.write({ existed: true, value: 2 });
    await policy.disable();
    expect(await registry.read()).toEqual({ existed: true, value: 2 });
  });

  it("serializes enable and disconnect so the original snapshot is restored", async () => {
    const { create, registry } = fixture();
    const policy = create();
    await Promise.all([policy.enable(), policy.enable(), policy.disable()]);
    expect(await registry.read()).toEqual({ existed: true, value: 0 });
    expect(registry.write).toHaveBeenCalledTimes(2);
  });
});
