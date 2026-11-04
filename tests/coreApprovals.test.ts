import { describe, expect, it } from "vitest";
import { CoreApprovals } from "../src/main/core/coreApprovals";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";

const NOW = Date.parse("2026-01-01T00:00:00Z");
const approval = { id: "0f8fad5b-d9cb-469f-a165-70867728950e", deviceName: "Evil\u202e PC\n\tname", platformLabel: "macOS", choices: [37, 52, 81], expiresAt: "2026-01-01T00:05:00Z" };

describe("approval output guards", () => {
  it("refuses invalid native number choices", () => {
    const core = new RustCore({ functions: () => ["loginApproval.matchNumber"], call: () => '"37"' }, () => {}, "rust");
    expect(new CoreApprovals(() => core).matchNumber(37)).toBe(37);
    expect(core.stats().failed).toBe(1);
  });

  it("does not ask the native bridge to turn a string into an approval number", () => {
    const core = new RustCore({ functions: () => ["loginApproval.isApprovalAnswer"], call: () => "true" }, () => {}, "rust");
    expect(new CoreApprovals(() => core).isApprovalAnswer(approval, "37")).toBe(false);
    expect(core.stats().decided).toBe(0);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
const status = modulePath ? loadLevikCore(modulePath) : null;
const available = status?.state === "loaded" && status.module.functions().includes("loginApproval.parseApprovals");
describe.runIf(available)("real approval bridge", () => {
  it.each(["shadow", "rust"] as const)("preserves safe device names and number matching in %s mode", (mode) => {
    if (status?.state !== "loaded") throw new Error("module missing");
    const core = new RustCore(status.module, () => {}, mode);
    const approvals = new CoreApprovals(() => core);
    const parsed = approvals.parseApprovals([approval], NOW);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.deviceName).toBe("Evil PC name");
    expect(parsed[0]?.expiresAt).toBe("2026-01-01T00:05:00.000Z");
    const first = parsed[0];
    if (!first) throw new Error("approval missing");
    expect(approvals.isApprovalAnswer(first, 37)).toBe(true);
    expect(approvals.isApprovalAnswer(first, 38)).toBe(false);
    expect(approvals.isApprovalAnswer(first, null)).toBe(true);
    expect(approvals.matchNumber(37)).toBe(37);
    expect(approvals.isAccountHint(`v1.${"a".repeat(16)}.${"b".repeat(40)}.${"c".repeat(22)}`)).toBe(true);
    expect(approvals.isTelegramLink(`https://t.me/levikvpnbot?start=web_${"x".repeat(43)}`)).toBe(true);
    expect(core.stats().failed).toBe(0);
    expect(core.stats().differed).toBe(0);
    expect(mode === "shadow" ? core.stats().compared : core.stats().decided).toBe(7);
  });
});
