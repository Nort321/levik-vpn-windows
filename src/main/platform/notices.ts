import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AppTab, SubscriptionSummary } from "../../shared/contracts";

/** A system notification the app wants to show. */
export interface AppNotice {
  title: string;
  body: string;
  tab: AppTab;
}

const DAY_MS = 24 * 60 * 60 * 1_000;
const MAX_REMEMBERED = 200;

export type ExpiryMilestone = "3d" | "1d" | "expired";

/** Reminders before the end of a subscription and once right after it. */
export function expiryMilestone(expireAt: number, now: number): ExpiryMilestone | null {
  const left = expireAt - now;
  if (left <= 0) return now - expireAt < 3 * DAY_MS ? "expired" : null;
  if (left <= DAY_MS) return "1d";
  if (left <= 3 * DAY_MS) return "3d";
  return null;
}

/** One reminder per subscription, milestone and end date; renewing starts over. */
export function expiryNotices(
  subscriptions: readonly SubscriptionSummary[],
  remembered: ReadonlySet<string>,
  now: number,
): Array<{ key: string; notice: AppNotice }> {
  const result: Array<{ key: string; notice: AppNotice }> = [];
  for (const subscription of subscriptions) {
    const status = subscription.status.toLowerCase();
    if (!subscription.expireAt || (status !== "active" && status !== "expired")) continue;
    const expireAt = Date.parse(subscription.expireAt);
    if (!Number.isFinite(expireAt)) continue;
    const milestone = expiryMilestone(expireAt, now);
    if (!milestone) continue;
    const key = `expiry:${subscription.uuid}:${milestone}:${expireAt}`;
    if (remembered.has(key)) continue;
    const title = milestone === "expired" ? "Подписка закончилась" : "Подписка скоро закончится";
    const body = milestone === "expired"
      ? `«${subscription.title}» больше не действует. Продлите её, чтобы снова подключаться.`
      : `«${subscription.title}» действует ${milestone === "1d" ? "меньше суток" : "меньше 3 дней"}. Продлите её в личном кабинете.`;
    result.push({ key, notice: { title, body, tab: "profile" } });
  }
  return result;
}

interface NoticeStateData {
  salt: string;
  dismissed: string[];
  notified: string[];
}

/**
 * What the user has already seen: closed announcements, shown notifications
 * and the local rollout salt. Nothing here is sent anywhere.
 */
export class NoticeState {
  private data: NoticeStateData = { salt: randomBytes(16).toString("hex"), dismissed: [], notified: [] };

  constructor(private readonly path: string) {}

  async load(): Promise<void> {
    try {
      const value: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (typeof value !== "object" || value === null) return;
      const record = value as Record<string, unknown>;
      const strings = (items: unknown) => Array.isArray(items)
        ? items.filter((item): item is string => typeof item === "string" && item.length <= 200).slice(-MAX_REMEMBERED)
        : [];
      this.data = {
        salt: typeof record.salt === "string" && /^[0-9a-f]{32}$/.test(record.salt) ? record.salt : this.data.salt,
        dismissed: strings(record.dismissed),
        notified: strings(record.notified),
      };
    } catch {
      await this.save();
    }
  }

  get salt(): string {
    return this.data.salt;
  }

  dismissed(): ReadonlySet<string> {
    return new Set(this.data.dismissed);
  }

  notified(): ReadonlySet<string> {
    return new Set(this.data.notified);
  }

  async dismiss(id: string): Promise<void> {
    if (this.data.dismissed.includes(id)) return;
    this.data.dismissed = [...this.data.dismissed, id].slice(-MAX_REMEMBERED);
    await this.save();
  }

  async remember(keys: readonly string[]): Promise<void> {
    const fresh = keys.filter((key) => !this.data.notified.includes(key));
    if (!fresh.length) return;
    this.data.notified = [...this.data.notified, ...fresh].slice(-MAX_REMEMBERED);
    await this.save();
  }

  private async save(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.tmp`;
    await writeFile(temporary, JSON.stringify(this.data), { mode: 0o600 });
    await rename(temporary, this.path);
  }
}
