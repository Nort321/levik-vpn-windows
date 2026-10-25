/** LevikDrop as the window sees it, docs/levik-drop.md. Files, keys and sockets stay in the main process. */

export type DropPlatform = "android" | "windows" | "macos" | "linux";
export type DropState = "offered" | "active" | "paused" | "done" | "declined" | "cancelled" | "failed" | "expired";

export interface DropDevice {
  deviceId: string;
  name: string;
  platform: DropPlatform;
  /** The app said in the last minutes that it can receive. */
  ready: boolean;
  /** The app has a LevikDrop version (it registered a key once). */
  supported: boolean;
}

export interface DropFile {
  name: string;
  size: number;
}

/** What the window asks the user about one transfer. */
export interface DropPrompt {
  /** offer: the receiver accepts or declines; confirm: the codes must match before files move. */
  kind: "offer" | "confirm";
  /** Shown on both screens when the other device's key is not known yet ("123 456"). */
  code: string | null;
  trust: "trusted" | "new" | "changed";
}

export interface DropTransfer {
  id: string;
  role: "sender" | "receiver";
  peerDeviceId: string;
  peerName: string;
  peerPlatform: DropPlatform | null;
  state: DropState;
  reason: string | null;
  fileCount: number;
  totalBytes: number;
  /** Names and sizes, when this app knows them (always for the sender). */
  files: DropFile[] | null;
  doneBytes: number;
  bytesPerSecond: number | null;
  /** How the bytes go right now; null without a session. */
  path: "relay" | "lan" | null;
  /** waiting: the other app is not connected yet. */
  link: "connecting" | "waiting" | "session" | "retrying" | null;
  prompt: DropPrompt | null;
  /** Ephemeral receiver code visible before the sender releases the manifest. */
  verificationCode?: string | null;
  /** Receiver: where the files go. */
  folder: string | null;
  /** Receiver: some files are in place and can be shown in the folder. */
  saved: boolean;
  createdAt: number;
  finishedAt: number | null;
}

export interface DropSnapshot {
  /** The website offers LevikDrop. */
  available: boolean;
  loadedAt: number | null;
  devices: DropDevice[];
  transfers: DropTransfer[];
  quota: { limitBytes: number; usedBytes: number; resetsAt: number } | null;
  limits: { maxFiles: number; maxBytes: number };
  /** Where received files go unless changed. */
  folder: string;
  error: string | null;
}

export type DropAnswer = "accept" | "decline" | "confirm" | "reject";
export type DropControl = "pause" | "resume" | "cancel";

export const DROP_ANSWERS: readonly DropAnswer[] = ["accept", "decline", "confirm", "reject"];
export const DROP_CONTROLS: readonly DropControl[] = ["pause", "resume", "cancel"];

export function isDropAnswer(value: unknown): value is DropAnswer {
  return typeof value === "string" && (DROP_ANSWERS as readonly string[]).includes(value);
}

export function isDropControl(value: unknown): value is DropControl {
  return typeof value === "string" && (DROP_CONTROLS as readonly string[]).includes(value);
}

export function isOpenDropState(state: DropState): boolean {
  return state === "offered" || state === "active" || state === "paused";
}

export function formatDropBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} Б`;
  const units = ["КБ", "МБ", "ГБ"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const shown = value >= 100 || Number.isInteger(value) ? String(Math.round(value)) : value.toFixed(1).replace(".", ",");
  return `${shown} ${units[unit]}`;
}

/** "1 файл", "2 файла", "5 файлов". */
export function dropFileCount(count: number): string {
  const tens = count % 100;
  const ones = count % 10;
  const word = tens >= 11 && tens <= 14 ? "файлов" : ones === 1 ? "файл" : ones >= 2 && ones <= 4 ? "файла" : "файлов";
  return `${count} ${word}`;
}

const FAILURE_TEXT: Record<string, string> = {
  source_changed: "файл изменился на отправителе",
  integrity: "файл повреждён в пути",
  storage_full: "не хватило места на получателе",
  storage_error: "не удалось записать файл",
  source_unreadable: "не удалось прочитать файл",
  protocol: "ошибка соединения приложений",
  key_rejected: "коды не совпали",
};

/** One line under the transfer. */
export function dropStatusText(transfer: DropTransfer): string {
  const peer = transfer.peerName;
  if (transfer.role === "receiver" && transfer.verificationCode && !transfer.prompt && isOpenDropState(transfer.state)) return "Сверьте код с отправителем";
  switch (transfer.state) {
    case "offered":
      if (transfer.role === "sender") {
        if (transfer.prompt?.kind === "confirm") return "Сверьте код на обоих устройствах";
        return transfer.link === "session" ? `Ждём, пока примут на «${peer}»…` : `Ждём «${peer}»… Levik VPN должен быть открыт на нём.`;
      }
      return transfer.prompt ? "Примите или отклоните файлы" : "Получаем список файлов…";
    case "active":
      if (transfer.prompt?.kind === "confirm") return "Сверьте код на обоих устройствах";
      if (transfer.link !== "session") return transfer.peerPlatform === "android"
        ? `Ждём «${peer}»… Откройте Levik на телефоне.`
        : `Ждём «${peer}»… Передача продолжится сама.`;
      return transfer.path === "lan" ? "Передаём напрямую по локальной сети" : "Передаём через сервер Levik";
    case "paused":
      if (transfer.reason === "quota") return "Пауза: дневной лимит передачи через сервер исчерпан";
      return "На паузе";
    case "done":
      return transfer.role === "sender" ? "Доставлено" : "Получено";
    case "declined":
      return transfer.role === "sender" ? `«${peer}» отклонил файлы` : "Вы отклонили файлы";
    case "cancelled":
      return transfer.reason === "device_revoked" ? "Отменено: устройство вышло из аккаунта" : "Отменено";
    case "failed":
      return `Не удалось: ${FAILURE_TEXT[transfer.reason ?? ""] ?? "ошибка передачи"}`;
    case "expired":
      return "Время ожидания истекло";
  }
}
