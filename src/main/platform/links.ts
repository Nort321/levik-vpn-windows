import type { AppTab, CabinetTarget } from "../../shared/contracts";
import { serviceEndpoints, websiteHosts } from "./serviceEndpoints";

export const DEEP_LINK_SCHEME = "levik";

const DEEP_LINK_TABS: Readonly<Record<string, AppTab>> = {
  home: "home",
  servers: "servers",
  subscriptions: "profile",
  plans: "profile",
  support: "profile",
};

/**
 * levik://open?to=<page> from the website's "return to the app" page.
 * The link can only choose a tab; anything else is ignored.
 */
export function parseDeepLink(raw: string): AppTab | null {
  if (raw.length > 200) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== `${DEEP_LINK_SCHEME}:` || url.hostname !== "open") return null;
  const target = url.searchParams.get("to") ?? "home";
  return Object.hasOwn(DEEP_LINK_TABS, target) ? DEEP_LINK_TABS[target] ?? null : null;
}

/** The deep link among command line arguments (Windows and Linux pass it there). */
export function deepLinkFromArgv(argv: readonly string[]): AppTab | null {
  for (const argument of argv) {
    if (argument.startsWith(`${DEEP_LINK_SCHEME}://`)) return parseDeepLink(argument);
  }
  return null;
}

export const CABINET_TARGETS: ReadonlyArray<CabinetTarget> = [
  "/dashboard",
  "/dashboard/subscriptions",
  "/dashboard/plans",
  "/dashboard/orders",
  "/dashboard/devices",
  "/dashboard/support",
  "/dashboard/account-security",
  "/dashboard/rules",
  "/dashboard/family",
  "/dashboard/notifications",
  "/dashboard/road",
];

export function isCabinetTarget(value: unknown): value is CabinetTarget {
  return typeof value === "string" && (CABINET_TARGETS as readonly string[]).includes(value);
}

/** The one-time sign-in link must point at the Levik website's /handoff page. */
export function isHandoffUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && websiteHosts().has(url.hostname) && !url.port &&
      url.pathname === "/handoff" && /^\?token=[A-Za-z0-9_-]{43}$/.test(url.search) && !url.hash &&
      !url.username && !url.password;
  } catch {
    return false;
  }
}

/** Where a page opens when the app cannot sign the browser in. */
export function cabinetFallbackUrl(target: CabinetTarget): string {
  return `${serviceEndpoints().webOrigin}${target}`;
}

/** Fixed license links are the only exception to Levik/Telegram destinations. */
const DATA_LICENSE_LINKS = new Set(["https://db-ip.com/db/lite.php", "https://creativecommons.org/licenses/by/4.0/"]);

/** Links the app opens in the browser, including two exact data-attribution pages. */
export function isAllowedExternalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (DATA_LICENSE_LINKS.has(url.href)) return true;
    const host = url.hostname.replace(/^www\./, "");
    return (url.protocol === "https:" && (websiteHosts().has(host) || url.hostname === "t.me")) || url.protocol === "tg:";
  } catch {
    return false;
  }
}
