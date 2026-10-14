import type { PendingApproval } from "../../shared/contracts";

/**
 * Approving sign-ins by number matching, docs/app-platform.md "Approving a
 * sign-in". A new computer shows a number; this app, signed in to the same
 * account, offers three and the user picks the one on the new computer.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACCOUNT_HINT = /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{22}$/;
const MAX_APPROVALS = 5;

/** Kept after signing out so the next sign-in can be approved on the user's other apps. */
export function isAccountHint(value: unknown): value is string {
  return typeof value === "string" && value.length <= 400 && ACCOUNT_HINT.test(value);
}

export function matchNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 10 && value <= 99 ? value : null;
}

function text(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  // Control and bidi characters could disguise the device name.
  const cleaned = value.replace(/[\p{Cc}\p{Cf}]/gu, " ").replace(/\s+/g, " ").trim();
  return cleaned && cleaned.length <= max ? cleaned : null;
}

/** The bot link of a sign-in: https://t.me/<bot>?start=web_<token>, nothing else. */
export function isTelegramLink(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "t.me" && !url.port && !url.username && !url.password &&
      /^\/[A-Za-z][A-Za-z0-9_]{4,31}$/.test(url.pathname) && /^\?start=web_[A-Za-z0-9_-]{20,96}$/.test(url.search) &&
      !url.hash;
  } catch {
    return false;
  }
}

/** The server's list, checked field by field; expired and malformed entries are dropped. */
export function parseApprovals(value: unknown, now = Date.now()): PendingApproval[] {
  if (!Array.isArray(value)) return [];
  const approvals: PendingApproval[] = [];
  for (const item of value.slice(0, MAX_APPROVALS)) {
    if (typeof item !== "object" || item === null) continue;
    const entry = item as Record<string, unknown>;
    const id = typeof entry.id === "string" && UUID.test(entry.id) ? entry.id : null;
    const deviceName = text(entry.deviceName, 120);
    const platformLabel = text(entry.platformLabel, 40);
    const choices = Array.isArray(entry.choices) ? entry.choices.map(matchNumber) : [];
    const expiresAt = typeof entry.expiresAt === "string" ? Date.parse(entry.expiresAt) : Number.NaN;
    if (!id || !deviceName || !platformLabel || choices.length !== 3 || !Number.isFinite(expiresAt)) continue;
    const numbers = choices.filter((choice): choice is number => choice !== null);
    if (numbers.length !== 3 || new Set(numbers).size !== 3 || expiresAt <= now) continue;
    approvals.push({ id, deviceName, platformLabel, choices: numbers, expiresAt: new Date(expiresAt).toISOString() });
  }
  return approvals;
}

/** A number of the offered three, or null for "this is not me". */
export function isApprovalAnswer(approval: PendingApproval, answer: unknown): answer is number | null {
  return answer === null || (typeof answer === "number" && approval.choices.includes(answer));
}
