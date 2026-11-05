import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { describeLevikCore, LEVIK_CORE_CONTRACT, levikCorePath, loadLevikCore } from "../src/main/core/levikCore";

const host = { platform: "darwin" as const, arch: "arm64" };
const info = { version: "0.2.0", contract: LEVIK_CORE_CONTRACT, os: "macos", arch: "aarch64" };
const bridge = { functions: () => ["diagnosis.vpnPhase", 5], call: (name: string, input: string) => `${name}:${input}` };
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
    const status = loadLevikCore("/m.node", { ...present, load: () => ({ coreInfo: () => info, ...bridge }) });
    expect(status.state).toBe("loaded");
    expect(describeLevikCore(status)).toBe("Rust-ядро 0.2.0 (контракт 2, macos/aarch64) загружено");
    if (status.state !== "loaded") return;
    expect(status.module.functions()).toEqual(["diagnosis.vpnPhase"]);
    expect(status.module.call("f", "null")).toBe("f:null");
  });

  it("reports a build without the module", () => {
    const status = loadLevikCore("/m.node", { ...host, exists: () => false, load: () => { throw new Error("not called"); } });
    expect(status).toEqual({ state: "missing" });
  });

  it("rejects instead of throwing", () => {
    const cases: Array<[unknown, string]> = [
      [{}, "нет coreInfo()"],
      [{ coreInfo: () => ({ version: 1 }) }, "coreInfo() вернул не то"],
      [{ coreInfo: () => ({ ...info, contract: 1 }), ...bridge }, "контракт 1, нужен 2"],
      [{ coreInfo: () => info }, "нет functions() или call()"],
      [{ coreInfo: () => ({ ...info, arch: "x86_64" }), ...bridge }, "собран для macos/x86_64"],
      [{ coreInfo: () => { throw new Error("boom"); } }, "coreInfo() упал: boom"],
    ];
    for (const [module, reason] of cases) {
      expect(loadLevikCore("/m.node", { ...present, load: () => module })).toEqual({ state: "rejected", reason });
    }
    const loaded = loadLevikCore("/m.node", { ...present, load: () => ({ coreInfo: () => info, functions: () => [], call: () => 5 }) });
    expect(loaded.state).toBe("loaded");
    if (loaded.state === "loaded") expect(() => loaded.module.call("f", "null")).toThrow("call() вернул не строку");
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
  it("keeps service probes optional and validates handles when the capability is invoked", async () => {
    const native = { read: async () => '{"ok":true,"value":false}', close: () => {} };
    const loaded = loadLevikCore("/m.node", { ...present, load: () => ({ coreInfo: () => info, ...bridge, startServiceProbe: () => native }) });
    if (loaded.state !== "loaded") throw new Error("TEST module rejected");
    expect(loaded.module.startServiceProbe?.("{}")).toBe(native);
    const bad = loadLevikCore("/m.node", { ...present, load: () => ({ coreInfo: () => info, ...bridge, startServiceProbe: () => ({ read: () => "wrong" }) }) });
    if (bad.state !== "loaded") throw new Error("TEST module rejected");
    expect(() => bad.module.startServiceProbe?.("{}")).toThrow("Invalid native service probe");
  });

});
