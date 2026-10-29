import type { AppSnapshot } from "../shared/contracts";
import { GUEST_INVITE_MAX_LENGTH, WINDOWS_PROXY_STEPS } from "../shared/sharing";

type Action = (operation: () => Promise<void>) => Promise<unknown> | void;

export function renderGuestScreen(root: HTMLElement, snapshot: AppSnapshot, run: Action, close: () => void): void {
  const guest = snapshot.guest;
  const title = guest?.phase === "connected" ? "Интернет через телефон"
    : guest?.phase === "connecting" ? "Подключение к телефону…"
    : guest?.phase === "expired" ? "Время доступа закончилось"
    : guest ? "Подключение приостановлено" : "Получить интернет от телефона";
  const expiry = guest ? new Date(guest.expiresAt).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "";
  root.innerHTML = `<main class="login guest-page"><section class="card guest-card">
    <h1>${title}</h1>
    ${guest ? `<p>Телефон: <strong>${escape(guest.name)}</strong> · доступ до ${escape(expiry)}</p>
      <p role="status" aria-live="polite">${escape(snapshot.statusDetail ?? "")}</p>
      <p>Гостевой режим не переключается на вашу обычную VPN-подписку. Кнопка завершения снимет блокировку Levik и вернёт обычное подключение к интернету.</p>
      <div class="guest-actions">${guest.phase === "blocked" ? `<button class="button primary" id="guest-retry">Повторить подключение</button>` : ""}
      <button class="button" id="guest-stop">Завершить гостевой режим</button></div>` : `
      <p>Подключитесь через Android-телефон с работающим Levik VPN. Аккаунт и собственная подписка для гостевого режима не нужны.</p>
      <ol class="guest-steps">
        <li>На телефоне владельца включите VPN и точку доступа, затем откройте «Поделиться VPN → Через Levik».</li>
        <li>На компьютере подключитесь к Wi-Fi этого телефона. Отключите текущее VPN-подключение Levik, если оно включено.</li>
        <li>Попросите владельца скопировать приглашение с телефона. Передайте его лично или сохраните текстовым файлом. Вставьте приглашение ниже либо выберите файл.</li>
        <li>Нажмите «Подключиться через телефон». Windows-клиент должен быть запущен от имени администратора, чтобы создать системный туннель и защиту от прямого выхода.</li>
        <li>Дождитесь сообщения о подключении. Телефон должен оставаться рядом, с включёнными VPN и раздачей. При потере связи вернитесь к его Wi-Fi и нажмите «Повторить подключение».</li>
      </ol>
      ${snapshot.elevated === false ? `<p class="guest-hint" role="alert">Приложению нужны права администратора. Завершите его и запустите Levik VPN от имени администратора.</p>` : ""}
      <label class="guest-input-label" for="guest-invite">Гостевое приглашение</label>
      <textarea id="guest-invite" class="guest-invite" rows="3" maxlength="${GUEST_INVITE_MAX_LENGTH}" spellcheck="false" autocomplete="off" placeholder="levik-share://v1/…" ${snapshot.busy ? "disabled" : ""}></textarea>
      <p class="guest-hint">Приглашение содержит временный ключ доступа. Любой, кто получит его и подключится к сети телефона, сможет использовать доступ до окончания сеанса. Не публикуйте его.</p>
      <div class="guest-actions"><button class="button primary" id="guest-connect" ${snapshot.busy ? "disabled" : ""}>Подключиться через телефон</button>
        <button class="button" id="guest-file" ${snapshot.busy ? "disabled" : ""}>Выбрать файл приглашения</button>
        <button class="button" id="guest-back">Назад</button></div>`}
    <details class="guest-proxy-help"><summary>Пошаговая инструкция: подключение через прокси</summary>
      <p>Для этого способа гостевой туннель Levik на компьютере включать не нужно. Через прокси работают браузер и совместимые приложения; остальной трафик может идти напрямую.</p>
      <ol class="guest-steps">${WINDOWS_PROXY_STEPS.map((step) => `<li>${escape(step)}</li>`).join("")}</ol>
      <p>Используйте только текущие адрес и порт с телефона: единого адреса для всех Android нет. Для HTTPS через этот прокси не нужно устанавливать сертификаты.</p>
    </details>
  </section></main>`;
  root.querySelector("#guest-back")?.addEventListener("click", close);
  root.querySelector("#guest-stop")?.addEventListener("click", () => void run(async () => { await window.levik.disconnectGuest(); close(); }));
  root.querySelector("#guest-retry")?.addEventListener("click", () => void run(() => window.levik.connect()));
  root.querySelector("#guest-connect")?.addEventListener("click", () => {
    const input = root.querySelector<HTMLTextAreaElement>("#guest-invite");
    const invitation = input?.value.trim() ?? "";
    if (!invitation) { input?.focus(); return; }
    if (input) input.value = "";
    void run(() => window.levik.connectGuest(invitation));
  });
  root.querySelector("#guest-file")?.addEventListener("click", () => void run(() => window.levik.importGuestInvite()));
}

function escape(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}
