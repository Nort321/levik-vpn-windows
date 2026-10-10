import type { AppSettings } from "../../shared/contracts";

/**
 * Settings that mean the same thing in every Levik VPN app, docs/app-platform.md.
 * Split tunnelling, DNS, theme, autostart and favourites stay on this computer.
 */
export const SYNCED_KEYS = [
  "routingMode",
  "automaticServer",
  "autoReconnect",
  "killSwitch",
  "useDoh",
  "antiDpiEnabled",
  "antiDpiPackets",
  "antiDpiLength",
  "antiDpiInterval",
] as const;

export type SyncedKey = (typeof SYNCED_KEYS)[number];
export type SyncedSettings = Partial<Pick<AppSettings, SyncedKey>>;

export interface SettingsDocument {
  settings: SyncedSettings;
  revision: number;
}

const ROUTING_MODES: ReadonlyArray<AppSettings["routingMode"]> = ["global", "bypassRu", "blockedOnly"];
const PACKETS = /^(tlshello|[0-9]{1,3}(-[0-9]{1,3})?)?$/;
const RANGE = /^([0-9]{1,4}(-[0-9]{1,4})?)?$/;

/** Only values every app (and the server) accepts are shared. */
export function isPortable(key: SyncedKey, value: unknown): boolean {
  switch (key) {
    case "routingMode":
      return ROUTING_MODES.includes(value as AppSettings["routingMode"]);
    case "antiDpiPackets":
      return typeof value === "string" && value.length <= 24 && PACKETS.test(value);
    case "antiDpiLength":
    case "antiDpiInterval":
      return typeof value === "string" && value.length <= 16 && RANGE.test(value);
    default:
      return typeof value === "boolean";
  }
}

export function portableSettings(settings: AppSettings): SyncedSettings {
  const result: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    if (isPortable(key, settings[key])) result[key] = settings[key];
  }
  return result as SyncedSettings;
}

/** The shared fields the user just changed. */
export function syncedChanges(before: AppSettings, after: AppSettings): SyncedSettings {
  const result: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    if (before[key] !== after[key] && isPortable(key, after[key])) result[key] = after[key];
  }
  return result as SyncedSettings;
}

export function parseSettingsDocument(value: unknown): SettingsDocument | null {
  if (!isRecord(value) || value.ok !== true || !isRecord(value.settings)) return null;
  const revision = value.revision;
  if (typeof revision !== "number" || !Number.isSafeInteger(revision) || revision < 0) return null;
  const settings: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    if (isPortable(key, value.settings[key])) settings[key] = value.settings[key];
  }
  return { settings: settings as SyncedSettings, revision };
}

/**
 * What the account has that differs here. Fields with unsent local edits stay,
 * and so do local values other apps cannot express (they were never shared).
 */
export function remotePatch(local: AppSettings, remote: SyncedSettings, pending: SyncedSettings): Partial<AppSettings> {
  const patch: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    const value = remote[key];
    if (value !== undefined && !(key in pending) && local[key] !== value && isPortable(key, local[key])) patch[key] = value;
  }
  return patch as Partial<AppSettings>;
}

/** Pending edits that the server has not confirmed yet. */
export function withoutConfirmed(pending: SyncedSettings, sent: SyncedSettings): SyncedSettings {
  const result: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    if (key in pending && pending[key] !== sent[key]) result[key] = pending[key];
  }
  return result as SyncedSettings;
}

export function parsePending(value: unknown): SyncedSettings {
  if (!isRecord(value)) return {};
  const result: Record<string, unknown> = {};
  for (const key of SYNCED_KEYS) {
    if (isPortable(key, value[key])) result[key] = value[key];
  }
  return result as SyncedSettings;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
