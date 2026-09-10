import { describe, expect, it } from "vitest";
import { assertProcessRoutingSupport, xrayConfigArguments } from "../src/main/vpn/xrayManager";

describe("Xray configuration channel", () => {
  it("refuses silent process routing failures with an old bundled core", () => {
    const config = { routing: { rules: [{ process: ["overwatch.exe"] }] } };
    expect(() => assertProcessRoutingSupport(config, "Xray 26.7.28 Custom")).toThrow(/VPN-ядро/);
    expect(() => assertProcessRoutingSupport(config, "Xray 26.7.28 levik-process-v1")).not.toThrow();
    expect(() => assertProcessRoutingSupport({ routing: { rules: [{ ip: ["127.0.0.1"] }] } }, "Xray 26.7.28")).not.toThrow();
  });

  it("validates explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(true)).toEqual([
      "run", "-test", "-format", "json", "-config", "stdin:",
    ]);
  });

  it("executes explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(false)).toEqual([
      "run", "-format", "json", "-config", "stdin:",
    ]);
  });
});
