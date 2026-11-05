/**
 * Signing a device in from another one, both ways, docs/app-platform.md "Device pairing".
 *
 * Signed out, the sign-in screen offers «Показать QR-код» (a signed-in device
 * scans it) and «Ввести код» (the code a signed-in device shows next to its QR;
 * a computer has no camera to scan it). Signed in, «Подключить устройство»
 * shows a QR and code for a new device, or takes the code a new device shows.
 */
import QRCode from "qrcode";
import type { DevicePairing, DevicePairingStatus, LevikDesktopApi } from "../shared/contracts";

export type PairingIcon = "qr" | "link" | "login" | "check" | "refresh" | "close";

export interface PairingUiHost {
  api: Pick<LevikDesktopApi, "signInWithPairingCode" | "createDevicePairing" | "devicePairingStatus" | "cancelDevicePairing" | "authorizeActivation">;
  icon(name: PairingIcon): string;
  escapeHtml(value: string): string;
  escapeAttribute(value: string): string;
  render(): void;
  toast(message: string, tone?: "error" | "notice"): void;
  /** The «Подключить устройство» card is on screen; the QR is taken back when it is not. */
  pairingVisible(): boolean;
  /** Binds a handler for this render only; the Linux renderer keeps its DOM between renders. */
  listen<K extends keyof HTMLElementEventMap>(element: HTMLElement | null, type: K, handler: (event: HTMLElementEventMap[K]) => void): void;
}

export interface PairingUi {
  /** «Ввести код» on the sign-in screen. */
  renderCodeSignIn(): string;
  /** The «Подключить устройство» card of the profile. */
  renderConnectDevice(): string;
  /** After each render. */
  bind(): void;
  /** Signed out, or the card left the screen: the QR stops working. */
  stop(): void;
}

const POLL_MS = 2_000;
const PAIRING_CODE_LENGTH = 14;
const ACTIVATION_CODE_LENGTH = 19;

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/^Error invoking remote method '[^']+':\s*(?:Error:\s*)?/, "");
}

/** Letters and digits in groups of four, as typed. */
function formatCode(value: string, length: number): string {
  const characters = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return (characters.match(/.{1,4}/g) ?? []).join("-").slice(0, length);
}

function secondsLeft(expiresAt: string): number {
  return Math.max(0, Math.ceil((Date.parse(expiresAt) - Date.now()) / 1_000));
}

function clock(seconds: number): string {
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export function mountPairingUi(host: PairingUiHost): PairingUi {
  // Signed out: the code shown by a signed-in device.
  let signInCode = "";
  let signingIn = false;
  // Signed in: «Подключить устройство».
  let mode: "show" | "enter" = "show";
  let pairing: (DevicePairing & { qrSvg: string }) | null = null;
  let status: DevicePairingStatus | null = null;
  let creating = false;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let tickTimer: ReturnType<typeof setInterval> | null = null;
  let activationCode = "";
  let authorizing = false;

  function clearTimers(): void {
    if (pollTimer) clearTimeout(pollTimer);
    if (tickTimer) clearInterval(tickTimer);
    pollTimer = null;
    tickTimer = null;
  }

  function stop(): void {
    clearTimers();
    const pending = pairing && status?.state === "pending" ? pairing.id : null;
    pairing = null;
    status = null;
    creating = false;
    if (pending) void host.api.cancelDevicePairing(pending).catch(() => undefined);
  }

  function schedulePoll(id: string): void {
    pollTimer = setTimeout(() => void poll(id), POLL_MS);
  }

  async function poll(id: string): Promise<void> {
    pollTimer = null;
    if (!pairing || pairing.id !== id) return;
    if (!host.pairingVisible()) {
      stop();
      return;
    }
    if (secondsLeft(pairing.expiresAt) === 0) {
      status = { state: "expired" };
      clearTimers();
      host.render();
      return;
    }
    try {
      const next = await host.api.devicePairingStatus(id);
      if (!pairing || pairing.id !== id) return;
      status = next;
      if (next.state === "pending") {
        schedulePoll(id);
        return;
      }
      clearTimers();
      if (next.state === "connected") host.toast(`${next.deviceName ?? "Устройство"}: вход выполнен`, "notice");
      host.render();
    } catch {
      // A dropped request is retried until the code expires.
      if (pairing?.id === id) schedulePoll(id);
    }
  }

  async function createPairing(): Promise<void> {
    if (creating) return;
    stop();
    creating = true;
    host.render();
    try {
      const created = await host.api.createDevicePairing();
      const qrSvg = await QRCode.toString(created.uri, { type: "svg", width: 216, margin: 1, errorCorrectionLevel: "M" });
      if (!creating) return;
      pairing = { ...created, qrSvg };
      status = { state: "pending" };
      tickTimer = setInterval(() => {
        const timer = document.getElementById("device-pairing-timer");
        if (timer && pairing) timer.textContent = clock(secondsLeft(pairing.expiresAt));
      }, 1_000);
      schedulePoll(created.id);
    } catch (error) {
      host.toast(errorText(error));
    } finally {
      creating = false;
      host.render();
    }
  }

  async function signIn(): Promise<void> {
    if (signingIn) return;
    signingIn = true;
    host.render();
    try {
      await host.api.signInWithPairingCode(signInCode);
      signInCode = "";
    } catch (error) {
      host.toast(errorText(error));
    } finally {
      signingIn = false;
      host.render();
    }
  }

  async function authorize(): Promise<void> {
    if (authorizing) return;
    authorizing = true;
    host.render();
    try {
      await host.api.authorizeActivation(activationCode);
      activationCode = "";
      host.toast("Устройство авторизовано", "notice");
    } catch (error) {
      host.toast(errorText(error));
    } finally {
      authorizing = false;
      host.render();
    }
  }

  function renderCodeSignIn(): string {
    const { icon, escapeAttribute } = host;
    return `<form class="pairing-code-form" id="pairing-sign-in-form">
      <ol class="pairing-steps">
        <li>Откройте Levik VPN на устройстве, где вы уже вошли.</li>
        <li>Нажмите «Подключить устройство» → «Показать QR-код».</li>
        <li>Введите код, который показан под QR-кодом.</li>
      </ol>
      <label for="pairing-sign-in-code">Код с другого устройства</label>
      <input id="pairing-sign-in-code" class="pairing-code-input" type="text" inputmode="text" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="${PAIRING_CODE_LENGTH}" placeholder="XXXX-XXXX-XXXX" value="${escapeAttribute(signInCode)}" ${signingIn ? "readonly" : ""} />
      <button class="button primary" type="submit" ${signingIn ? "disabled" : ""}>${signingIn ? `<span class="spinner"></span>` : icon("login")} Войти</button>
    </form>`;
  }

  function renderShow(): string {
    const { icon, escapeHtml } = host;
    if (status?.state === "connected") {
      return `<div class="pairing-result" role="status">${icon("check")}<div><strong>${escapeHtml(status.deviceName ?? "Устройство")} подключено</strong><span>Подписки и серверы уже доступны на нём.</span></div></div>
        <button class="button" id="device-pairing-create">${icon("qr")} Подключить ещё одно</button>`;
    }
    if (!pairing) {
      return `<div class="card-caption">Новое устройство отсканирует этот QR-код камерой или введёт код под ним — на телевизоре или компьютере.</div>
        <button class="button primary pairing-action" id="device-pairing-create" ${creating ? "disabled" : ""}>${creating ? `<span class="spinner"></span>` : icon("qr")} Показать QR-код</button>`;
    }
    const expired = status?.state === "expired";
    return `<div class="pairing-show">
      <div class="pairing-qr ${expired ? "expired" : ""}" role="img" aria-label="QR-код для входа на новом устройстве">${pairing.qrSvg}</div>
      <div class="pairing-details">
        <span class="pairing-label">Или введите код</span>
        <strong class="pairing-code" aria-label="Код ${escapeHtml(pairing.code.split("").join(" "))}">${escapeHtml(pairing.code)}</strong>
        <ol class="pairing-steps">
          <li>На новом устройстве откройте Levik VPN.</li>
          <li>Нажмите «Вход по QR-коду» и отсканируйте код или выберите «Ввести код».</li>
        </ol>
        <div class="pairing-status" role="status">${expired ? "Срок кода истёк" : `Ждём новое устройство · <span id="device-pairing-timer">${clock(secondsLeft(pairing.expiresAt))}</span>`}</div>
        <div class="pairing-actions">
          <button class="button" id="device-pairing-create" ${creating ? "disabled" : ""}>${icon("refresh")} ${expired ? "Новый код" : "Обновить"}</button>
          <button class="button" id="device-pairing-close">${icon("close")} Скрыть</button>
        </div>
        <p class="pairing-warning">Не показывайте код посторонним: он открывает вход в ваш аккаунт.</p>
      </div>
    </div>`;
  }

  function renderEnter(): string {
    const { icon, escapeAttribute } = host;
    return `<div class="card-caption">Новое устройство без камеры (телевизор, компьютер) показывает QR-код и код под ним. Введите этот код здесь.</div>
      <form class="activation-form" id="activation-form"><label for="activation-code">Код с нового устройства</label><div class="activation-controls"><input id="activation-code" type="text" inputmode="text" autocomplete="one-time-code" spellcheck="false" maxlength="${ACTIVATION_CODE_LENGTH}" placeholder="XXXX-XXXX-XXXX-XXXX" value="${escapeAttribute(activationCode)}" ${authorizing ? "readonly" : ""} /><button class="button primary" type="submit" ${authorizing ? "disabled" : ""}>${authorizing ? `<span class="spinner"></span>` : icon("link")} Авторизовать</button></div></form>`;
  }

  function renderConnectDevice(): string {
    return `<section class="section card pairing-card" aria-labelledby="pairing-title">
      <h2 class="card-title" id="pairing-title">Подключить устройство</h2>
      <div class="pairing-switch" role="group" aria-label="Способ подключения">
        <button class="${mode === "show" ? "active" : ""}" data-pairing-mode="show" aria-pressed="${mode === "show"}">Показать QR-код</button>
        <button class="${mode === "enter" ? "active" : ""}" data-pairing-mode="enter" aria-pressed="${mode === "enter"}">Ввести код</button>
      </div>
      ${mode === "show" ? renderShow() : renderEnter()}
    </section>`;
  }

  function bind(): void {
    const { listen } = host;
    const signInInput = document.getElementById("pairing-sign-in-code") as HTMLInputElement | null;
    listen(signInInput, "input", () => {
      if (!signInInput) return;
      signInCode = formatCode(signInInput.value, PAIRING_CODE_LENGTH);
      signInInput.value = signInCode;
    });
    listen(document.getElementById("pairing-sign-in-form"), "submit", (event) => {
      event.preventDefault();
      void signIn();
    });
    document.querySelectorAll<HTMLButtonElement>("[data-pairing-mode]").forEach((button) => listen(button, "click", () => {
      const next = button.dataset.pairingMode === "enter" ? "enter" : "show";
      if (next === mode) return;
      mode = next;
      if (mode === "enter") stop();
      host.render();
    }));
    listen(document.getElementById("device-pairing-create"), "click", () => void createPairing());
    listen(document.getElementById("device-pairing-close"), "click", () => {
      stop();
      host.render();
    });
    const activationInput = document.getElementById("activation-code") as HTMLInputElement | null;
    listen(activationInput, "input", () => {
      if (!activationInput) return;
      activationCode = formatCode(activationInput.value, ACTIVATION_CODE_LENGTH);
      activationInput.value = activationCode;
    });
    listen(document.getElementById("activation-form"), "submit", (event) => {
      event.preventDefault();
      void authorize();
    });
  }

  return { renderCodeSignIn, renderConnectDevice, bind, stop };
}
