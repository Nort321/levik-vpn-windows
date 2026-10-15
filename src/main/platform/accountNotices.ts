import type { CabinetTarget } from "../../shared/contracts";
import { isCabinetTarget } from "./links";

/**
 * A notice of the notification center, docs/app-platform.md "Notifications":
 * a subscription that ends soon, a family member who needs help. Taking it
 * from the server delivers it; no other app and no Telegram message repeats it.
 */
export interface AccountNotice {
  id: string;
  title: string;
  body: string;
  /** The cabinet page a click opens signed in. */
  cabinet: CabinetTarget;
}

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_NOTICES = 20;

function text(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= max ? trimmed : null;
}

/** Entries that are not a valid notice are skipped; an unknown page opens the cabinet. */
export function parseAccountNotices(value: unknown): AccountNotice[] {
  if (!Array.isArray(value)) return [];
  const notices: AccountNotice[] = [];
  for (const item of value) {
    if (notices.length >= MAX_NOTICES) break;
    if (typeof item !== "object" || item === null) continue;
    const record = item as Record<string, unknown>;
    const id = typeof record.id === "string" && ID.test(record.id) ? record.id : null;
    const title = text(record.title, 80);
    const body = text(record.body, 400);
    if (!id || !title || !body) continue;
    notices.push({ id, title, body, cabinet: isCabinetTarget(record.target) ? record.target : "/dashboard" });
  }
  return notices;
}
