import { describe, expect, it } from "vitest";
import { xrayConfigArguments } from "../src/main/vpn/xrayManager";

describe("Xray configuration channel", () => {
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
