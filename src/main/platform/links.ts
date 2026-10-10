import type { AppTab, CabinetTarget } from "../../shared/contracts";

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
];

export function isCabinetTarget(value: unknown): value is CabinetTarget {
  return typeof value === "string" && (CABINET_TARGETS as readonly string[]).includes(value);
}

const SITE_HOSTS = new Set(["leviknet.org", "leviknet.com"]);

/** The one-time sign-in link must point at the Levik website's /handoff page. */
export function isHandoffUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && SITE_HOSTS.has(url.hostname) && !url.port &&
      url.pathname === "/handoff" && /^\?token=[A-Za-z0-9_-]{43}$/.test(url.search) && !url.hash &&
      !url.username && !url.password;
  } catch {
    return false;
  }
}

/** Where a page opens when the app cannot sign the browser in. */
export function cabinetFallbackUrl(target: CabinetTarget): string {
  return `https://leviknet.org${target}`;
}

const EXTERNAL_HTTPS_HOSTS = new Set(["leviknet.org", "www.leviknet.org", "leviknet.com", "www.leviknet.com", "t.me"]);

/** Links the app opens in the browser: the Levik website and Telegram only. */
export function isAllowedExternalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" && EXTERNAL_HTTPS_HOSTS.has(url.hostname)) || url.protocol === "tg:";
  } catch {
    return false;
  }
}
