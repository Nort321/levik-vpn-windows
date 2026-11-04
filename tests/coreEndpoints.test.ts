import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CoreEndpoints } from "../src/main/core/coreEndpoints";
import { RustCore } from "../src/main/core/rustCore";
import { loadLevikCore } from "../src/main/core/levikCore";
import { verifyEndpointsDocument } from "../src/main/platform/serviceEndpoints";

const body = readFileSync(join(__dirname, "fixtures/levik-config-v1.json"));
const signature = readFileSync(join(__dirname, "fixtures/levik-config-v1.json.sig"), "utf8");

describe("signed endpoint core guard", () => {
  it("refuses an unsafe native result and uses the verified Node document", () => {
    const core = new RustCore({ functions: () => ["serviceEndpoints.verifyEndpointsDocument"], call: () => JSON.stringify({ sequence: 1, apiOrigins: ["http://evil.example"], webOrigin: "https://site.example", configUrls: [] }) }, () => {}, "rust");
    expect(new CoreEndpoints(() => core).verify(body, signature)).toEqual(verifyEndpointsDocument(body, signature));
    expect(core.stats().failed).toBe(1);
  });

  it("bounds input before crossing the bridge", () => {
    const core = new RustCore({ functions: () => ["serviceEndpoints.verifyEndpointsDocument"], call: () => { throw new Error("must not be called"); } }, () => {}, "rust");
    expect(new CoreEndpoints(() => core).verify(Buffer.alloc(16 * 1024 + 1), signature)).toBeNull();
    expect(core.stats().failed).toBe(0);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real endpoint verification", () => {
  it.each(["shadow", "rust"] as const)("accepts only the published bytes in %s mode", (mode) => {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded") throw new Error("module not loaded");
    const core = new RustCore(status.module, () => {}, mode);
    const endpoints = new CoreEndpoints(() => core);
    expect(endpoints.verify(body, signature)).toEqual(verifyEndpointsDocument(body, signature));
    expect(endpoints.verify(Buffer.from(body.toString().replace("cloudnote-sync.xyz", "attacker.example")), signature)).toBeNull();
    expect(core.stats().differed).toBe(0);
    expect(core.stats().failed).toBe(0);
    expect(mode === "shadow" ? core.stats().compared : core.stats().decided).toBe(2);
  });
});
