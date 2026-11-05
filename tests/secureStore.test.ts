import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const paths = vi.hoisted(() => ({ userData: "" }));

vi.mock("electron", () => ({
  app: { getPath: () => paths.userData },
  safeStorage: {
    isEncryptionAvailable: () => true,
    encryptString: (text: string) => Buffer.from(text),
    decryptString: (bytes: Buffer) => {
      if (!bytes.length) throw new Error("Error while decrypting the ciphertext");
      return bytes.toString();
    },
  },
}));

import { SecureStore } from "../src/main/security/secureStore";

describe("SecureStore", () => {
  const stored = (name: string) => join(paths.userData, "secure-v1", `${name}.json`);

  async function plant(name: string, contents: string): Promise<void> {
    await mkdir(join(paths.userData, "secure-v1"), { recursive: true });
    await writeFile(stored(name), contents);
  }

  beforeEach(async () => {
    paths.userData = await mkdtemp(join(tmpdir(), "levik-secure-store-"));
  });

  afterEach(async () => {
    await rm(paths.userData, { recursive: true, force: true });
  });

  it("returns what was stored", async () => {
    const store = new SecureStore();
    await store.put("settings", Buffer.from("{\"a\":1}"));
    expect((await store.get("settings"))?.toString()).toBe("{\"a\":1}");
    expect(await readdir(join(paths.userData, "secure-v1"))).toEqual(["settings.json"]);
  });

  it("returns nothing for a missing file", async () => {
    expect(await new SecureStore().get("settings")).toBeNull();
  });

  it.each([
    ["zero bytes left by a power loss", "\0".repeat(256)],
    ["an empty file", ""],
    ["a truncated envelope", "{\"version\":1,\"cipher"],
    ["JSON that is not an object", "null"],
    ["an envelope of another shape", "{\"version\":1}"],
  ])("resets a key whose file holds %s", async (_label, contents) => {
    const damaged: string[] = [];
    const store = new SecureStore((name) => damaged.push(name));
    await plant("device_identity", contents);

    expect(await store.get("device_identity")).toBeNull();
    expect(damaged).toEqual(["device_identity"]);
    expect(await readdir(join(paths.userData, "secure-v1"))).toEqual([]);
  });

  it("leaves other keys alone when one is damaged", async () => {
    const store = new SecureStore();
    await store.put("access_token", Buffer.from("token"));
    await plant("settings", "\0\0\0\0");

    expect(await store.get("settings")).toBeNull();
    expect((await store.get("access_token"))?.toString()).toBe("token");
  });

  it("keeps a file that only fails to decrypt", async () => {
    const damaged: string[] = [];
    const store = new SecureStore((name) => damaged.push(name));
    await plant("access_token", JSON.stringify({ version: 1, ciphertext: "" }));

    await expect(store.get("access_token")).rejects.toThrow("decrypting");
    expect(damaged).toEqual([]);
    expect(await readdir(join(paths.userData, "secure-v1"))).toEqual(["access_token.json"]);
  });
});
