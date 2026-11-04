import type { AppSettings } from "../../shared/contracts";
import { isPortable, parsePending, parseSettingsDocument, portableSettings, remotePatch, syncedChanges, withoutConfirmed,
  SYNCED_KEYS, type SettingsDocument, type SyncedKey, type SyncedSettings } from "../platform/settingsSync";
import type { RustCore } from "./rustCore";

function isSyncedKey(value: string): value is SyncedKey {
  return SYNCED_KEYS.some((key) => key === value);
}

export function isSyncedSettings(value: unknown): value is SyncedSettings {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.entries(value).every(([key, item]) => isSyncedKey(key) && isPortable(key, item));
}

function isDocument(value: unknown): value is SettingsDocument | null {
  return value === null || (typeof value === "object" && value !== null && "settings" in value && isSyncedSettings(value.settings)
    && "revision" in value && typeof value.revision === "number" && Number.isSafeInteger(value.revision) && value.revision >= 0);
}

/** The existing account-sync flow, with decisions compared before switching to Rust. */
export class CoreSettings {
  constructor(private readonly current: () => RustCore) {}

  parsePending(value: unknown): SyncedSettings {
    return this.current().run("settingsSync.parsePending", value, () => parsePending(value), isSyncedSettings);
  }

  parseSettingsDocument(value: unknown): SettingsDocument | null {
    return this.current().run("settingsSync.parseSettingsDocument", value, () => parseSettingsDocument(value), isDocument);
  }

  portableSettings(settings: AppSettings): SyncedSettings {
    return this.current().run("settingsSync.portableSettings", settings, () => portableSettings(settings), isSyncedSettings);
  }

  syncedChanges(before: AppSettings, after: AppSettings): SyncedSettings {
    return this.current().run("settingsSync.syncedChanges", { before, after }, () => syncedChanges(before, after), isSyncedSettings);
  }

  withoutConfirmed(pending: SyncedSettings, sent: SyncedSettings): SyncedSettings {
    return this.current().run("settingsSync.withoutConfirmed", { pending, sent }, () => withoutConfirmed(pending, sent), isSyncedSettings);
  }

  remotePatch(local: AppSettings, remote: SyncedSettings, pending: SyncedSettings): Partial<AppSettings> {
    return this.current().run("settingsSync.remotePatch", { local, remote, pending }, () => remotePatch(local, remote, pending), isSyncedSettings);
  }
}
