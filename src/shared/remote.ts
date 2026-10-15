/**
 * The remote, docs/app-platform.md "Remote". Disconnecting is deliberately not
 * a command: an app answers "unsupported" to anything outside this list.
 */
export const REMOTE_COMMANDS = ["connect", "auto_server", "refresh_profile", "check_update", "collect_diagnostics"] as const;
export type RemoteCommand = (typeof REMOTE_COMMANDS)[number];

export type RemoteCommandState = "pending" | "delivered" | "done" | "failed" | "unsupported" | "expired";

export interface RemoteDevice {
  /** The id the app sends as X-HWID. */
  deviceId: string;
  name: string;
  platform: "android" | "windows" | "macos" | "linux";
  appVersion: string | null;
  current: boolean;
  /** The app asks for commands, so the remote reaches it. */
  remote: boolean;
  online: boolean;
  vpnConnected: boolean;
  country: string | null;
}

export interface IssuedCommand {
  id: string;
  deviceId: string;
  command: RemoteCommand;
  state: RemoteCommandState;
  detail: string | null;
}

export interface RemoteSnapshot {
  devices: RemoteDevice[];
  commands: IssuedCommand[];
  /** Diagnostics links opened with this app's key, by command id. */
  notes: Record<string, string>;
  loadedAt: number | null;
}

export const REMOTE_COMMAND_LABELS: Record<RemoteCommand, string> = {
  connect: "Подключить",
  auto_server: "Автовыбор сервера",
  refresh_profile: "Обновить профиль",
  check_update: "Проверить обновление",
  collect_diagnostics: "Собрать диагностику",
};

export function isRemoteCommand(value: unknown): value is RemoteCommand {
  return typeof value === "string" && (REMOTE_COMMANDS as readonly string[]).includes(value);
}

export function isFinalState(state: RemoteCommandState): boolean {
  return state === "done" || state === "failed" || state === "unsupported" || state === "expired";
}

/** One line about the last command for the device. */
export function remoteStatusText(command: IssuedCommand, device: RemoteDevice | undefined): string {
  switch (command.state) {
    case "pending":
      return device?.platform === "android" && !device.online
        ? "Отправлено. Телефон получит команду, когда откроет Levik VPN."
        : "Отправлено, ждём устройство…";
    case "delivered":
      return "Устройство получило команду и выполняет её…";
    case "done":
      if (command.command === "check_update") {
        return command.detail?.startsWith("available:")
          ? `Доступна версия ${command.detail.slice("available:".length)}: приложение предложит обновиться.`
          : "Обновлений нет: стоит последняя версия.";
      }
      return command.command === "collect_diagnostics" ? "Диагностика собрана." : "Готово.";
    case "failed":
      return command.detail === "vpn_permission"
        ? "Не получилось: на устройстве нужно один раз разрешить VPN."
        : "Не получилось выполнить команду на устройстве.";
    case "unsupported":
      return "Эта версия приложения не умеет выполнять такую команду.";
    case "expired":
      return "Устройство не ответило за 10 минут.";
  }
}

export function remoteIdleHint(device: RemoteDevice): string {
  return device.platform === "android"
    ? "Телефон получает команды, пока на нём включён VPN или открыт Levik VPN."
    : "Компьютер получает команды, пока на нём запущен Levik VPN.";
}
