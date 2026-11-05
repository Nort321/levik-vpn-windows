import type { DevicePairing, DevicePairingStatus } from "../../shared/contracts";

/**
 * Signing a device in from another one (docs/app-platform.md "Device pairing"):
 * a signed-in app shows a QR and a short code, a new device scans the QR or
 * types the code. Activation codes go the other way and are one group longer.
 */
const PAIRING_CODE = /^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){2}$/;
const ACTIVATION_CODE = /^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}$/;
const PAIRING_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Upper case with the dashes put back, so "abcd efgh jk23" works too. */
function compactCode(value: string, groups: number): string {
  const characters = value.normalize("NFKC").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return characters.length === groups * 4 ? (characters.match(/.{4}/g) ?? []).join("-") : value.trim().toUpperCase();
}

export function normalizePairingCode(value: string): string {
  const code = compactCode(value, 3);
  if (PAIRING_CODE.test(code)) return code;
  if (ACTIVATION_CODE.test(compactCode(value, 4))) {
    throw new Error("Это код для подтверждения входа: введите его на устройстве, где вы уже вошли, в разделе «Подключить устройство».");
  }
  throw new Error("Введите код в формате XXXX-XXXX-XXXX с экрана другого устройства");
}

/** "XXXX-XXXX-XXXX-XXXX" shown by a new device; also accepts a pairing code by mistake. */
export function normalizeActivationCode(value: string): string {
  const code = compactCode(value, 4);
  if (ACTIVATION_CODE.test(code)) return code;
  if (PAIRING_CODE.test(compactCode(value, 3))) {
    throw new Error("Это код для входа на новом устройстве: введите его там, в «Вход по QR-коду» → «Ввести код».");
  }
  throw new Error("Введите код в формате XXXX-XXXX-XXXX-XXXX");
}

export function isPairingId(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}

/** The QR carries the website's /activate?pair= link; nothing else is drawn. */
export function parseDevicePairing(value: unknown): DevicePairing {
  if (typeof value !== "object" || value === null) throw new Error("Сервер вернул некорректный QR-код");
  const { id, uri, code, expiresAt } = value as Record<string, unknown>;
  if (!isPairingId(id) || typeof code !== "string" || !PAIRING_CODE.test(code) ||
    typeof expiresAt !== "string" || !Number.isFinite(Date.parse(expiresAt)) || typeof uri !== "string") {
    throw new Error("Сервер вернул некорректный QR-код");
  }
  let link: URL;
  try {
    link = new URL(uri);
  } catch {
    throw new Error("Сервер вернул некорректный QR-код");
  }
  const params = [...link.searchParams.keys()];
  if (link.protocol !== "https:" || link.username || link.password || link.hash || link.pathname !== "/activate" ||
    params.length !== 1 || params[0] !== "pair" || !PAIRING_TOKEN.test(link.searchParams.get("pair") ?? "")) {
    throw new Error("Сервер вернул некорректный QR-код");
  }
  return { id, uri: link.toString(), code, expiresAt };
}

export function parseDevicePairingStatus(value: unknown): DevicePairingStatus {
  if (typeof value !== "object" || value === null) throw new Error("Сервер вернул некорректный статус");
  const { state, deviceName } = value as Record<string, unknown>;
  if (state === "pending" || state === "expired") return { state };
  if (state === "connected") {
    return { state, deviceName: typeof deviceName === "string" && deviceName.trim() ? deviceName.trim().slice(0, 120) : null };
  }
  throw new Error("Сервер вернул некорректный статус");
}
