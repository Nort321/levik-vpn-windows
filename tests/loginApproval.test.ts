import { describe, expect, it } from "vitest";
import { isAccountHint, isApprovalAnswer, isTelegramLink, matchNumber, parseApprovals } from "../src/main/platform/loginApproval";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const approval = {
  id: "0f8e2a64-5c1b-4d3e-9a7f-1b2c3d4e5f60",
  deviceName: "MacBook Pro",
  platform: "macos",
  platformLabel: "macOS",
  choices: [37, 52, 81],
  expiresAt: "2026-10-14T12:05:00Z",
};

describe("login approval", () => {
  it("accepts only well-formed account hints", () => {
    expect(isAccountHint(`v1.${"a".repeat(16)}.${"b".repeat(40)}.${"c".repeat(22)}`)).toBe(true);
    expect(isAccountHint(`v2.${"a".repeat(16)}.${"b".repeat(40)}.${"c".repeat(22)}`)).toBe(false);
    expect(isAccountHint(`v1.${"a".repeat(16)}.b+c/.${"c".repeat(22)}`)).toBe(false);
    expect(isAccountHint(42)).toBe(false);
  });

  it("keeps two-digit numbers only", () => {
    expect(matchNumber(37)).toBe(37);
    for (const value of [9, 100, 37.5, "37", null, true]) expect(matchNumber(value)).toBeNull();
  });

  it("opens only the bot's sign-in link", () => {
    expect(isTelegramLink(`https://t.me/levikvpnbot?start=web_${"x".repeat(43)}`)).toBe(true);
    expect(isTelegramLink(`http://t.me/levikvpnbot?start=web_${"x".repeat(43)}`)).toBe(false);
    expect(isTelegramLink(`https://t.me.evil.example/levikvpnbot?start=web_${"x".repeat(43)}`)).toBe(false);
    expect(isTelegramLink(`https://t.me/levikvpnbot?start=pay_${"x".repeat(43)}`)).toBe(false);
    expect(isTelegramLink(`https://t.me/levikvpnbot?start=web_${"x".repeat(43)}#x`)).toBe(false);
    expect(isTelegramLink("not a url")).toBe(false);
  });

  it("parses approvals and drops expired or malformed ones", () => {
    const parsed = parseApprovals([
      approval,
      { ...approval, id: "not-a-uuid" },
      { ...approval, choices: [37, 37, 52] },
      { ...approval, choices: [37, 52] },
      { ...approval, expiresAt: "2026-10-14T11:59:00Z" },
      { ...approval, deviceName: "" },
      null,
    ], NOW);
    expect(parsed).toEqual([{
      id: approval.id, deviceName: "MacBook Pro", platformLabel: "macOS", choices: [37, 52, 81],
      expiresAt: "2026-10-14T12:05:00.000Z",
    }]);
    expect(parseApprovals("nope", NOW)).toEqual([]);
  });

  it("cleans control and bidi characters out of device names", () => {
    const [parsed] = parseApprovals([{ ...approval, deviceName: "Evil‮ PC\n\tname" }], NOW);
    expect(parsed?.deviceName).toBe("Evil PC name");
  });

  it("accepts one of the offered numbers or a decline", () => {
    const [parsed] = parseApprovals([approval], NOW);
    if (!parsed) throw new Error("approval missing");
    expect(isApprovalAnswer(parsed, 52)).toBe(true);
    expect(isApprovalAnswer(parsed, null)).toBe(true);
    expect(isApprovalAnswer(parsed, 53)).toBe(false);
    expect(isApprovalAnswer(parsed, "52")).toBe(false);
  });
});
