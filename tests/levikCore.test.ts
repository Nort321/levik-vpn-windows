import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { describeLevikCore, LEVIK_CORE_CONTRACT, levikCorePath, loadLevikCore } from "../src/main/core/levikCore";

const host = { platform: "darwin" as const, arch: "arm64" };
const info = { version: "0.1.0", contract: LEVIK_CORE_CONTRACT, os: "macos", arch: "aarch64" };
const present = { exists: () => true, ...host };

describe("levikCorePath", () => {
  it("uses resources in packaged builds and vendor during development", () => {
    expect(levikCorePath({ packaged: true, resourcesPath: "/r", appPath: "/a" })).toBe(join("/r", "levik-core", "levik_core.node"));
    expect(levikCorePath({ packaged: false, resourcesPath: "/r", appPath: "/a", platform: "win32", arch: "x64" }))
      .toBe(join("/a", "vendor", "levik-core", "windows-x64", "levik_core.node"));
    expect(levikCorePath({ packaged: false, resourcesPath: "/r", appPath: "/a", platform: "darwin", arch: "arm64" }))
      .toBe(join("/a", "vendor", "levik-core", "darwin-arm64", "levik_core.node"));
  });
});

describe("loadLevikCore", () => {
  it("accepts a module built for this computer", () => {
    const status = loadLevikCore("/m.node", { ...present, load: () => ({ coreInfo: () => info }) });
    expect(status.state).toBe("loaded");
    expect(describeLevikCore(status)).toBe("Rust-ядро 0.1.0 (контракт 1, macos/aarch64) загружено");
  });

  it("reports a build without the module", () => {
    const status = loadLevikCore("/m.node", { ...host, exists: () => false, load: () => { throw new Error("not called"); } });
    expect(status).toEqual({ state: "missing" });
  });

  it("rejects instead of throwing", () => {
    const cases: Array<[unknown, string]> = [
      [{}, "нет coreInfo()"],
      [{ coreInfo: () => ({ version: 1 }) }, "coreInfo() вернул не то"],
      [{ coreInfo: () => ({ ...info, contract: 2 }) }, "контракт 2, нужен 1"],
      [{ coreInfo: () => ({ ...info, arch: "x86_64" }) }, "собран для macos/x86_64"],
      [{ coreInfo: () => { throw new Error("boom"); } }, "coreInfo() упал: boom"],
    ];
    for (const [module, reason] of cases) {
      expect(loadLevikCore("/m.node", { ...present, load: () => module })).toEqual({ state: "rejected", reason });
    }
    expect(loadLevikCore("/m.node", { ...present, load: () => { throw new Error("dlopen failed"); } }))
      .toEqual({ state: "rejected", reason: "не загрузился: dlopen failed" });
  });

  it("loads the real module when it has been fetched into vendor", () => {
    const path = levikCorePath({ packaged: false, resourcesPath: "", appPath: join(__dirname, "..") });
    const status = loadLevikCore(path);
    // Optional by design: CI builds without the module still pass.
    if (status.state === "missing") return;
    expect(status.state).toBe("loaded");
  });
});
