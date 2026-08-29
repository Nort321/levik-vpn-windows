import { EventEmitter } from "node:events";
import { app } from "electron";
import { autoUpdater } from "electron-updater";
import type { AppSnapshot } from "../../shared/contracts";

type UpdateSnapshot = AppSnapshot["update"];

interface AppUpdaterEvents {
  changed: [snapshot: UpdateSnapshot];
}

export class AppUpdater extends EventEmitter<AppUpdaterEvents> {
  private state: UpdateSnapshot = { status: "idle", version: null, progress: null, message: null };

  constructor() {
    super();
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowPrerelease = false;
    const updateUrlOverride = process.env.LEVIK_UPDATE_URL;
    if (updateUrlOverride) autoUpdater.setFeedURL({ provider: "generic", url: updateUrlOverride });
    autoUpdater.on("checking-for-update", () => this.patch({ status: "checking", message: "Проверяем обновления…" }));
    autoUpdater.on("update-available", (info) => this.patch({ status: "available", version: info.version, progress: 0, message: `Доступна версия ${info.version}` }));
    autoUpdater.on("update-not-available", () => this.patch({ status: "upToDate", version: app.getVersion(), progress: null, message: "Установлена актуальная версия" }));
    autoUpdater.on("download-progress", (progress) => this.patch({ status: "downloading", progress: Math.round(progress.percent), message: "Загрузка обновления…" }));
    autoUpdater.on("update-downloaded", (info) => this.patch({ status: "downloaded", version: info.version, progress: 100, message: "Обновление готово к установке" }));
    autoUpdater.on("error", (error) => this.patch({ status: "error", progress: null, message: safeUpdateError(error) }));
  }

  snapshot(): UpdateSnapshot {
    return { ...this.state };
  }

  async check(silent = false): Promise<void> {
    if (!app.isPackaged) {
      if (!silent) this.patch({ status: "upToDate", version: app.getVersion(), progress: null, message: "Обновления проверяются только в установленной сборке" });
      return;
    }
    try {
      await autoUpdater.checkForUpdates();
    } catch (error) {
      if (!silent) this.patch({ status: "error", progress: null, message: safeUpdateError(error) });
    }
  }

  async download(): Promise<void> {
    if (this.state.status !== "available") throw new Error("Сначала проверьте наличие обновления");
    this.patch({ status: "downloading", progress: 0, message: "Загрузка обновления…" });
    try {
      await autoUpdater.downloadUpdate();
    } catch (error) {
      this.patch({ status: "error", progress: null, message: safeUpdateError(error) });
      throw error;
    }
  }

  async install(prepare: () => Promise<void>, beforeQuit: () => void): Promise<void> {
    if (this.state.status !== "downloaded") throw new Error("Обновление ещё не загружено");
    this.patch({ status: "installing", progress: 100, message: "Подготовка к установке…" });
    try {
      await prepare();
      beforeQuit();
      autoUpdater.quitAndInstall(false, true);
    } catch (error) {
      this.patch({ status: "downloaded", progress: 100, message: `Не удалось запустить установку: ${safeUpdateError(error)}` });
      throw error;
    }
  }

  private patch(patch: Partial<UpdateSnapshot>): void {
    this.state = { ...this.state, ...patch };
    this.emit("changed", this.snapshot());
  }
}

function safeUpdateError(error: unknown): string {
  const message = error instanceof Error ? error.message : "Не удалось проверить обновления";
  return message.replace(/[\r\n]/g, " ").slice(0, 240);
}
