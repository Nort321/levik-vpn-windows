import type { SubscriptionSummary } from "../../shared/contracts";
import { parseAccountNotices, type AccountNotice } from "../platform/accountNotices";
import { expiryNotices, type ExpiryNotice } from "../platform/notices";
import { isAccountNoticeList, isExpiryNoticeList } from "./coreGuards";
import type { RustCore } from "./rustCore";

const EXPIRY = "notices.expiryNotices";
const ACCOUNT = "notices.parseAccountNotices";

/** Reminders before the end of a subscription, through the Rust core. */
export function expiryNoticesWithCore(
  core: RustCore,
  subscriptions: readonly SubscriptionSummary[],
  remembered: ReadonlySet<string>,
  now: number,
): ExpiryNotice[] {
  if (core.mode === "ts" || !core.has(EXPIRY)) return expiryNotices(subscriptions, remembered, now);
  const input = { subscriptions, remembered: [...remembered], now };
  return core.run(EXPIRY, input, () => expiryNotices(subscriptions, remembered, now), isExpiryNoticeList);
}

/** The notices the server handed over, through the Rust core. */
export function parseAccountNoticesWithCore(core: RustCore, value: unknown): AccountNotice[] {
  // undefined is no JSON; the TypeScript answer for it is the empty list.
  if (core.mode === "ts" || !core.has(ACCOUNT) || value === undefined) return parseAccountNotices(value);
  return core.run(ACCOUNT, value, () => parseAccountNotices(value), isAccountNoticeList);
}
