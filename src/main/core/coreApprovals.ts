import type { PendingApproval } from "../../shared/contracts";
import { isAccountHint, isApprovalAnswer, isTelegramLink, matchNumber, parseApprovals } from "../platform/loginApproval";
import { isBoolean } from "./coreGuards";
import type { RustCore } from "./rustCore";

function numberOrNull(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isInteger(value) && value >= 10 && value <= 99);
}

function approvals(value: unknown): value is PendingApproval[] {
  return Array.isArray(value) && value.length <= 5 && value.every((item: unknown) => {
    if (typeof item !== "object" || item === null) return false;
    return "id" in item && typeof item.id === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.id)
      && "deviceName" in item && typeof item.deviceName === "string" && item.deviceName.length >= 1 && item.deviceName.length <= 120
      && "platformLabel" in item && typeof item.platformLabel === "string" && item.platformLabel.length >= 1 && item.platformLabel.length <= 40
      && "expiresAt" in item && typeof item.expiresAt === "string" && Number.isFinite(Date.parse(item.expiresAt))
      && "choices" in item && Array.isArray(item.choices) && item.choices.length === 3
      && item.choices.every((n: unknown) => n !== null && numberOrNull(n)) && new Set(item.choices).size === 3;
  });
}

export class CoreApprovals {
  constructor(private readonly current: () => RustCore) {}

  isAccountHint(value: unknown): value is string {
    return this.current().run("loginApproval.isAccountHint", value, () => isAccountHint(value), isBoolean);
  }

  matchNumber(value: unknown): number | null {
    return this.current().run("loginApproval.matchNumber", value, () => matchNumber(value), numberOrNull);
  }

  isTelegramLink(value: string): boolean {
    return this.current().run("loginApproval.isTelegramLink", value, () => isTelegramLink(value), isBoolean);
  }

  parseApprovals(value: unknown, now = Date.now()): PendingApproval[] {
    return this.current().run("loginApproval.parseApprovals", { value, now }, () => parseApprovals(value, now), approvals);
  }

  isApprovalAnswer(approval: PendingApproval, answer: unknown): answer is number | null {
    if (answer !== null && typeof answer !== "number") return false;
    return this.current().run("loginApproval.isApprovalAnswer", { approval, answer }, () => isApprovalAnswer(approval, answer), isBoolean);
  }
}
