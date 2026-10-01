import { app } from "electron";
import { join } from "node:path";

export function windowsHelperPath(): string {
  return app.isPackaged
    ? join(process.resourcesPath, "kill-switch", "levik-kill-switch.exe")
    : join(app.getAppPath(), "vendor", "kill-switch", "windows-x64", "levik-kill-switch.exe");
}
