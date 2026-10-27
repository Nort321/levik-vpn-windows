/**
 * LevikDrop outside the profile page, docs/levik-drop.md: a card in the corner
 * that follows each transfer on every tab (offer, code, progress, result), and
 * a drop zone that opens when files are dragged into the window. Both live
 * outside #app, so re-rendering the page does not restart their animations.
 */
import { dropFileCount, dropStatusText, formatDropBytes, isOpenDropState } from "../shared/drop";
import type { DropAnswer, DropControl, DropDevice, DropPlatform, DropSnapshot, DropTransfer } from "../shared/drop";

export type DropIcon = "upload" | "download" | "check" | "close" | "browse" | "devices";

export interface DropUiHost {
  /** LevikDrop of the signed-in account; null hides the card and the drop zone. */
  drop(): DropSnapshot | null;
  icon(name: DropIcon): string;
  /** A button of this transfer is pressed and not answered yet. */
  busy(id: string): boolean;
  /** The device files are being offered to right now. */
  sendingTo(): string | null;
  send(deviceId: string, paths: string[]): void;
  answer(transfer: DropTransfer, answer: DropAnswer): void;
  control(id: string, action: DropControl): void;
  showFiles(id: string): void;
  toast(message: string): void;
  /** Shown when the dragged items are not files from the file manager. */
  fileManagerHint: string;
}

export interface DropUi {
  /** After each render: cards appear, change and leave. */
  update(): void;
  /** Progress only, many times a second. */
  live(): void;
  /** Opens the card of this transfer again («Принять или отклонить» in the profile). */
  reveal(id: string): void;
}

type Phase = "sending" | "offer" | "confirm" | "code" | "waiting" | "active" | "paused" | "done" | "ended" | "failed";

export const DROP_PLATFORM_LABELS: Record<DropPlatform, string> = { android: "Android", windows: "Windows", macos: "macOS", linux: "Linux" };

const SENDING_CARD = "sending";
const MAX_CARDS = 3;
const SHOWN_FILES = 4;
/** Finished cards go by themselves; failures stay until closed. */
const HIDE_AFTER_MS: Partial<Record<Phase, number>> = { done: 8_000, ended: 5_000 };
const HOVER_DELAY_MS = 2_000;
/** Chromium repeats dragover while files hover the window; silence means the drag is over. */
const DRAG_IDLE_MS = 450;
const LEAVE_MS = 260;

export function dropPercent(transfer: DropTransfer): number {
  return transfer.totalBytes > 0 ? Math.min(100, Math.round((transfer.doneBytes / transfer.totalBytes) * 100)) : transfer.state === "done" ? 100 : 0;
}

export function dropAmountText(transfer: DropTransfer): string {
  const amount = `${formatDropBytes(transfer.doneBytes)} из ${formatDropBytes(transfer.totalBytes)}`;
  return transfer.bytesPerSecond ? `${amount} · ${formatDropBytes(Math.round(transfer.bytesPerSecond))}/с` : amount;
}

export function dropFilesText(transfer: DropTransfer): string {
  const files = transfer.files;
  if (!files?.length) return `${dropFileCount(transfer.fileCount)}, ${formatDropBytes(transfer.totalBytes)}`;
  const names = files.slice(0, 3).map((file) => file.name).join(", ");
  return files.length > 3 ? `${names} и ещё ${files.length - 3}` : names;
}

export function dropDeviceStatus(device: DropDevice, busy: boolean): string {
  if (!device.supported) return "Обновите Levik VPN на этом устройстве";
  if (device.ready) return busy ? "Готово, когда закончится текущая передача" : "Готово принять файлы";
  return device.platform === "android" ? "Откройте Levik на телефоне" : "Levik VPN на нём не запущен";
}

export function mountDropUi(host: DropUiHost): DropUi {
  const dock = document.createElement("section");
  dock.className = "drop-dock";
  dock.setAttribute("aria-label", "Передача файлов");
  const stack = document.createElement("div");
  stack.className = "dock-stack";
  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = "dock-pill";
  pill.dataset.dockAction = "expand";
  pill.setAttribute("aria-label", "Развернуть передачу файлов");
  pill.hidden = true;
  const announcer = document.createElement("div");
  announcer.className = "drop-sr";
  announcer.setAttribute("role", "status");
  announcer.setAttribute("aria-live", "assertive");
  dock.append(stack, pill, announcer);

  const overlay = document.createElement("div");
  overlay.className = "drop-overlay";
  overlay.hidden = true;
  overlay.setAttribute("role", "region");
  overlay.setAttribute("aria-label", "Отправка перетаскиванием");
  document.body.append(dock, overlay);

  const cards = new Map<string, { element: HTMLElement; html: string; phase: Phase }>();
  /** Transfers this window saw open: only they get a result card. */
  const seenOpen = new Set<string>();
  const dismissed = new Set<string>();
  const seenPrompts = new Set<string>();
  const hideTimers = new Map<string, ReturnType<typeof setTimeout>>();
  let collapsed = false;
  let pillHtml = "";
  let overlayHtml = "";
  let overlayWanted = false;
  let dragTimer: ReturnType<typeof setTimeout> | null = null;
  let hoveredTile: HTMLElement | null = null;

  // The toast moves above the card instead of covering it (jsdom in tests has no ResizeObserver).
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => {
      const height = dock.offsetHeight;
      document.documentElement.style.setProperty("--drop-dock-offset", height > 0 ? `${height + 12}px` : "0px");
    }).observe(dock);
  }

  function transfers(): DropTransfer[] {
    return host.drop()?.transfers ?? [];
  }

  function update(): void {
    const drop = host.drop();
    const list = drop?.transfers ?? [];
    for (const transfer of list) if (isOpenDropState(transfer.state)) seenOpen.add(transfer.id);
    const shown = list.filter((transfer) => !dismissed.has(transfer.id) && (isOpenDropState(transfer.state) || seenOpen.has(transfer.id))).slice(0, MAX_CARDS);
    const wanted: Array<{ id: string; phase: Phase; html: string }> = [];
    const sendingTo = drop ? host.sendingTo() : null;
    if (sendingTo && !list.some((transfer) => transfer.role === "sender" && transfer.peerDeviceId === sendingTo && isOpenDropState(transfer.state))) {
      const device = drop?.devices.find((item) => item.deviceId === sendingTo);
      wanted.push({ id: SENDING_CARD, phase: "sending", html: sendingCard(device?.name ?? "устройство") });
    }
    for (const transfer of shown) {
      const phase = phaseOf(transfer);
      wanted.push({ id: transfer.id, phase, html: card(transfer, phase) });
      if (transfer.prompt) {
        const key = `${transfer.id}:${transfer.prompt.kind}:${transfer.prompt.code ?? ""}`;
        if (!seenPrompts.has(key)) {
          seenPrompts.add(key);
          collapsed = false;
          announce(transfer.prompt.kind === "offer" ? `Файлы с «${transfer.peerName}». Примите или отклоните их.` : `Сверьте код с «${transfer.peerName}».`);
        }
      }
      scheduleHide(transfer.id, phase);
    }
    reconcile(wanted);
    renderPill(wanted);
    renderOverlayDevices();
    live();
  }

  function reconcile(wanted: Array<{ id: string; phase: Phase; html: string }>): void {
    const ids = new Set(wanted.map((item) => item.id));
    for (const [id, entry] of cards) {
      if (ids.has(id)) continue;
      cards.delete(id);
      leave(entry.element);
    }
    const focused = document.activeElement instanceof HTMLElement && dock.contains(document.activeElement) ? document.activeElement.dataset.dockAction ?? null : null;
    let previous: HTMLElement | null = null;
    for (const item of wanted) {
      let entry = cards.get(item.id);
      if (!entry) {
        const element = document.createElement("article");
        element.className = "dock-card";
        element.dataset.dockId = item.id;
        element.innerHTML = item.html;
        entry = { element, html: item.html, phase: item.phase };
        cards.set(item.id, entry);
      } else if (entry.html !== item.html) {
        const swapped = entry.phase !== item.phase;
        entry.element.innerHTML = item.html;
        entry.html = item.html;
        entry.phase = item.phase;
        if (swapped) entry.element.querySelector(".dock-body")?.classList.add("is-swapping");
      }
      entry.element.dataset.phase = item.phase;
      // Only move a card when the order changed: moving restarts its animations.
      const expected: ChildNode | null = previous ? previous.nextSibling : stack.firstChild;
      if (expected !== entry.element) stack.insertBefore(entry.element, expected);
      previous = entry.element;
    }
    if (focused && !dock.contains(document.activeElement)) {
      stack.querySelector<HTMLElement>(`[data-dock-action="${CSS.escape(focused)}"]:not(:disabled)`)?.focus({ preventScroll: true });
    }
  }

  function leave(element: HTMLElement): void {
    element.classList.add("is-leaving");
    const remove = (): void => element.remove();
    element.addEventListener("animationend", remove, { once: true });
    setTimeout(remove, LEAVE_MS + 80);
  }

  function renderPill(wanted: Array<{ id: string; phase: Phase }>): void {
    const show = collapsed && wanted.length > 0;
    stack.classList.toggle("is-collapsed", collapsed);
    pill.hidden = !show;
    if (!show) return;
    const first = wanted[0];
    const transfer = transfers().find((item) => item.id === first?.id);
    const waiting = wanted.find((item) => item.phase === "offer" || item.phase === "confirm");
    const waitingTransfer = waiting ? transfers().find((item) => item.id === waiting.id) : undefined;
    const text = waitingTransfer ? `«${escapeHtml(waitingTransfer.peerName)}» ждёт ответа`
      : first?.phase === "done" ? (transfer?.role === "sender" ? "Доставлено" : "Файлы получены")
        : first?.phase === "active" || first?.phase === "paused" ? `${transfer?.role === "sender" ? "Отправка" : "Получение"} · <span data-pill-percent></span>`
          : "Передача файлов";
    const tone = waitingTransfer ? "is-attention" : first?.phase === "done" ? "is-done" : first?.phase === "failed" ? "is-failed" : "";
    const html = `<span class="dock-pill-ring ${tone}" data-pill-ring>${host.icon(first?.phase === "done" ? "check" : transfer?.role === "receiver" ? "download" : "upload")}</span><span class="dock-pill-text">${text}</span>`;
    const spoken = waitingTransfer ? `«${waitingTransfer.peerName}» ждёт ответа` : first?.phase === "active" || first?.phase === "paused" ? (transfer?.role === "sender" ? "отправка файлов" : "получение файлов") : text;
    pill.setAttribute("aria-label", `Развернуть: ${spoken}`);
    if (html !== pillHtml) {
      pill.innerHTML = html;
      pillHtml = html;
    }
  }

  function live(): void {
    const list = transfers();
    for (const [id, entry] of cards) {
      const transfer = list.find((item) => item.id === id);
      if (!transfer) continue;
      const percent = dropPercent(transfer);
      entry.element.querySelectorAll<HTMLElement>("[data-dock-fill]").forEach((fill) => { fill.style.width = `${percent}%`; });
      entry.element.querySelectorAll<HTMLElement>("[data-dock-bar]").forEach((bar) => bar.setAttribute("aria-valuenow", String(percent)));
      entry.element.querySelectorAll<HTMLElement>("[data-dock-percent]").forEach((element) => { element.textContent = `${percent}%`; });
      entry.element.querySelectorAll<HTMLElement>("[data-dock-amount]").forEach((element) => { element.textContent = dropAmountText(transfer); });
    }
    const first = list.find((item) => cards.has(item.id));
    if (!pill.hidden && first) {
      const percent = dropPercent(first);
      pill.querySelector<HTMLElement>("[data-pill-ring]")?.style.setProperty("--progress", `${percent * 3.6}deg`);
      const label = pill.querySelector<HTMLElement>("[data-pill-percent]");
      if (label) label.textContent = `${percent}%`;
    }
  }

  function scheduleHide(id: string, phase: Phase): void {
    const delay = HIDE_AFTER_MS[phase];
    if (delay === undefined || hideTimers.has(id)) return;
    const fire = (): void => {
      const entry = cards.get(id);
      if (!entry || HIDE_AFTER_MS[entry.phase] === undefined) {
        hideTimers.delete(id);
        return;
      }
      const element = entry.element;
      // Not while the pointer or keyboard is on the card.
      if (element?.matches(":hover, :focus-within")) {
        hideTimers.set(id, setTimeout(fire, HOVER_DELAY_MS));
        return;
      }
      hideTimers.delete(id);
      dismissed.add(id);
      update();
    };
    hideTimers.set(id, setTimeout(fire, delay));
  }

  function announce(text: string): void {
    announcer.textContent = "";
    // A changed text node is what screen readers announce.
    requestAnimationFrame(() => { announcer.textContent = text; });
  }

  function reveal(id: string): void {
    dismissed.delete(id);
    collapsed = false;
    update();
    cards.get(id)?.element.querySelector<HTMLElement>(".button.primary:not(:disabled), .button:not(:disabled)")?.focus({ preventScroll: true });
  }

  // Cards ---------------------------------------------------------------------------------

  function phaseOf(transfer: DropTransfer): Phase {
    if (transfer.prompt) return transfer.prompt.kind === "offer" ? "offer" : "confirm";
    switch (transfer.state) {
      case "done": return "done";
      case "failed":
      case "expired": return "failed";
      case "declined": return transfer.role === "sender" ? "failed" : "ended";
      case "cancelled": return "ended";
      case "paused": return "paused";
      case "active": return transfer.link === "session" ? "active" : "waiting";
      case "offered": return transfer.verificationCode ? "code" : "waiting";
    }
  }

  function sendingCard(deviceName: string): string {
    return `${head("sending", "is-waiting", host.icon("upload"), `На «${escapeHtml(deviceName)}»`, "Готовим файлы…", null)}
      <div class="dock-body"><span class="dock-bar is-indeterminate"><span></span></span></div>`;
  }

  function card(transfer: DropTransfer, phase: Phase): string {
    const peer = escapeHtml(transfer.peerName);
    const busy = host.busy(transfer.id);
    const direction = host.icon(transfer.role === "sender" ? "upload" : "download");
    const title = phase === "offer" ? `Файлы с «${peer}»` : phase === "confirm" ? "Сверьте код" : transfer.role === "sender" ? `На «${peer}»` : `С «${peer}»`;
    const subtitle = phase === "confirm" ? `${transfer.role === "sender" ? "Отправка на" : "Получение с"} «${peer}»` : escapeHtml(dropFilesText(transfer));
    const final = phase === "done" || phase === "ended" || phase === "failed";
    const headButton = final
      ? { action: "close", label: "Скрыть", svg: host.icon("close") }
      : { action: "collapse", label: "Свернуть", svg: CHEVRON };
    const tone = ({ sending: "is-waiting", offer: "is-attention", confirm: "is-attention", code: "is-attention", waiting: "is-waiting", active: "is-active", paused: "is-paused", done: "is-done", ended: "is-muted", failed: "is-failed" } as const)[phase];
    const badge = phase === "done" ? CHECK_DRAW : phase === "failed" ? host.icon("close") : direction;
    return `${head(transfer.id, tone, badge, title, subtitle, headButton)}<div class="dock-body">${body(transfer, phase, busy)}</div>`;
  }

  function head(id: string, tone: string, badge: string, title: string, subtitle: string, button: { action: string; label: string; svg: string } | null): string {
    return `<header class="dock-head"><span class="dock-badge ${tone}" aria-hidden="true">${badge}</span><div class="dock-titles"><h2 class="dock-title">${title}</h2><p class="dock-subtitle">${subtitle}</p></div>${button ? `<button type="button" class="dock-icon-button" data-dock-action="${button.action}" data-dock-id="${escapeAttribute(id)}" aria-label="${button.label}">${button.svg}</button>` : ""}</header>`;
  }

  function body(transfer: DropTransfer, phase: Phase, busy: boolean): string {
    const id = escapeAttribute(transfer.id);
    const peer = escapeHtml(transfer.peerName);
    const button = (action: string, label: string, kind = "", svg = ""): string =>
      `<button type="button" class="button compact ${kind}" data-dock-action="${action}" data-dock-id="${id}" ${busy ? "disabled" : ""}>${svg}${label}</button>`;
    const status = `<p class="dock-status" aria-live="polite">${escapeHtml(dropStatusText(transfer))}</p>`;
    const changed = transfer.prompt?.trust === "changed"
      ? `<p class="dock-warning">Ключ «${peer}» изменился — например, после переустановки Levik VPN. Продолжайте, только если коды совпадают.</p>` : "";
    switch (phase) {
      case "offer": {
        const code = transfer.prompt?.code ?? null;
        const files = transfer.files ?? [];
        const items = files.slice(0, SHOWN_FILES).map((file) => `<li><span class="dock-ext" aria-hidden="true">${escapeHtml(extension(file.name))}</span><span class="dock-file-name">${escapeHtml(file.name)}</span><span class="dock-file-size">${formatDropBytes(file.size)}</span></li>`).join("");
        const more = files.length > SHOWN_FILES ? `<li class="dock-more">и ещё ${files.length - SHOWN_FILES}</li>` : "";
        const folder = host.drop()?.folder ?? "";
        return `${items ? `<ul class="dock-files">${items}${more}</ul>` : ""}
          <p class="dock-meta">${dropFileCount(transfer.fileCount)}, ${formatDropBytes(transfer.totalBytes)} · <span class="dock-folder" title="${escapeAttribute(folder)}">сохранятся в ${escapeHtml(folder)}</span></p>
          ${changed}${code ? codeBlock(code, `Проверьте, что на «${peer}» показан этот же код.`) : ""}
          <p class="dock-note">Файлы не открываются сами. Принимайте только то, что отправляли вы.</p>
          <div class="dock-actions">${button("decline", "Отклонить", "danger")}${button("accept", code ? "Код совпадает, принять" : "Принять", "primary", host.icon("download"))}</div>`;
      }
      case "confirm": {
        const code = transfer.prompt?.code ?? "";
        return `${changed}${codeBlock(code, `Проверьте, что на «${peer}» показан этот же код. Так никто посередине не подменит устройство.`)}
          <div class="dock-actions">${button("reject", "Коды разные", "danger")}${button("confirm", "Коды совпадают", "primary", host.icon("check"))}</div>`;
      }
      case "code":
        return `${codeBlock(transfer.verificationCode ?? "", "Если на другом устройстве просят сверить код, сравните его с этим.")}${status}
          <div class="dock-actions">${button("cancel", "Отменить", "danger")}</div>`;
      case "waiting":
        return `<span class="dock-bar is-indeterminate"><span></span></span>${status}<div class="dock-actions">${button("cancel", "Отменить", "danger")}</div>`;
      case "active":
      case "paused":
        return `${progress(transfer, phase === "active")}
          <div class="dock-progress-meta"><span class="dock-percent" data-dock-percent></span><span class="dock-amount" data-dock-amount></span>${phase === "active" ? `<span class="dock-chip">${transfer.path === "lan" ? "Локальная сеть" : "Через сервер"}</span>` : ""}</div>
          ${phase === "paused" ? status : ""}
          <div class="dock-actions">${phase === "active" ? button("pause", "Пауза") : button("resume", "Продолжить", "primary")}${button("cancel", "Отменить", "danger")}</div>`;
      case "done":
        return `${progress(transfer, false)}<p class="dock-status is-done" aria-live="polite">${transfer.role === "sender" ? "Доставлено" : "Получено"}: ${dropFileCount(transfer.fileCount)}, ${formatDropBytes(transfer.totalBytes)}</p>
          ${transfer.saved ? `<div class="dock-actions">${button("show", "Показать в папке", "primary", host.icon("browse"))}</div>` : ""}`;
      case "ended":
      case "failed":
        return `${status}${transfer.saved ? `<div class="dock-actions">${button("show", "Показать в папке", "", host.icon("browse"))}</div>` : ""}`;
      case "sending":
        return "";
    }
  }

  function progress(transfer: DropTransfer, moving: boolean): string {
    return `<span class="dock-bar ${moving ? "is-moving" : ""}" role="progressbar" aria-label="Передано" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${dropPercent(transfer)}" data-dock-bar><span data-dock-fill></span></span>`;
  }

  function codeBlock(code: string, hint: string): string {
    const digits = Array.from(code).map((character) => character === " " ? `<span class="dock-digit-gap"></span>` : `<span class="dock-digit">${escapeHtml(character)}</span>`).join("");
    return `<p class="dock-note">${hint}</p><div class="dock-code" role="img" aria-label="Код ${escapeAttribute(code)}">${digits}</div>`;
  }

  // Drop zone ---------------------------------------------------------------------------

  function renderOverlayDevices(): void {
    const drop = host.drop();
    if (!drop) {
      hideOverlay();
      return;
    }
    const busy = drop.transfers.some((transfer) => isOpenDropState(transfer.state));
    const tiles = drop.devices.map((device) => {
      const ready = device.ready && device.supported && !busy;
      return `<div class="drop-tile ${ready ? "is-ready" : ""}" data-overlay-device="${escapeAttribute(device.deviceId)}" data-ready="${ready}"><span class="drop-tile-icon" aria-hidden="true">${host.icon("devices")}</span><span class="drop-tile-name">${escapeHtml(device.name)}</span><span class="drop-tile-status">${DROP_PLATFORM_LABELS[device.platform]} · ${escapeHtml(dropDeviceStatus(device, busy))}</span></div>`;
    }).join("");
    const anyReady = drop.devices.some((device) => device.ready && device.supported) && !busy;
    const html = `<div class="drop-zone"><div class="drop-zone-mark" aria-hidden="true">${host.icon("upload")}</div>
      <h2 class="drop-zone-title">${anyReady ? "Отпустите файлы на устройство" : busy ? "Дождитесь конца текущей передачи" : "Нет устройств, готовых принять файлы"}</h2>
      <p class="drop-zone-caption">${anyReady ? `До ${drop.limits.maxFiles} файлов и ${formatDropBytes(drop.limits.maxBytes)} за раз. Шифруется на этом компьютере.` : "Откройте Levik VPN на другом устройстве — оно появится здесь."}</p>
      ${tiles ? `<div class="drop-zone-devices">${tiles}</div>` : ""}</div>`;
    if (html === overlayHtml) return;
    overlayHtml = html;
    overlay.innerHTML = html;
    hoveredTile = null;
  }

  function showOverlay(): void {
    if (overlayWanted) return;
    overlayWanted = true;
    renderOverlayDevices();
    overlay.hidden = false;
    requestAnimationFrame(() => {
      if (overlayWanted) overlay.classList.add("is-visible");
    });
  }

  function hideOverlay(): void {
    if (dragTimer) clearTimeout(dragTimer);
    dragTimer = null;
    setHovered(null);
    if (!overlayWanted) return;
    overlayWanted = false;
    overlay.classList.remove("is-visible");
    setTimeout(() => {
      if (!overlayWanted) overlay.hidden = true;
    }, 180);
  }

  function setHovered(tile: HTMLElement | null): void {
    if (hoveredTile === tile) return;
    hoveredTile?.classList.remove("is-hovered");
    tile?.classList.add("is-hovered");
    hoveredTile = tile;
  }

  function draggedTile(event: DragEvent): HTMLElement | null {
    const tile = event.target instanceof Element ? event.target.closest<HTMLElement>("[data-overlay-device]") : null;
    return tile?.dataset.ready === "true" ? tile : null;
  }

  function carriesFiles(event: DragEvent): boolean {
    return event.dataTransfer?.types.includes("Files") === true && host.drop() !== null;
  }

  document.addEventListener("dragover", (event) => {
    if (!carriesFiles(event)) return;
    showOverlay();
    if (dragTimer) clearTimeout(dragTimer);
    dragTimer = setTimeout(hideOverlay, DRAG_IDLE_MS);
    const tile = draggedTile(event);
    setHovered(tile);
    if (event.dataTransfer) event.dataTransfer.dropEffect = tile ? "copy" : "none";
  });
  document.addEventListener("dragleave", (event) => {
    // relatedTarget is null when the files leave the window.
    if (event.relatedTarget === null) hideOverlay();
  });
  document.addEventListener("drop", (event) => {
    if (!overlayWanted) return;
    event.preventDefault();
    const tile = draggedTile(event);
    hideOverlay();
    const deviceId = tile?.dataset.overlayDevice;
    if (!deviceId) return;
    const paths = window.levik.dropFilePaths(event.dataTransfer ? Array.from(event.dataTransfer.files) : []);
    if (paths.length === 0) {
      host.toast(host.fileManagerHint);
      return;
    }
    host.send(deviceId, paths);
  });

  // Buttons -----------------------------------------------------------------------------

  dock.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest<HTMLButtonElement>("[data-dock-action]") : null;
    if (!button || button.disabled || button.getAttribute("aria-disabled") === "true") return;
    const action = button.dataset.dockAction;
    const id = button.dataset.dockId ?? "";
    const transfer = transfers().find((item) => item.id === id);
    switch (action) {
      case "expand":
        collapsed = false;
        update();
        stack.querySelector<HTMLElement>(".dock-icon-button")?.focus({ preventScroll: true });
        return;
      case "collapse":
        collapsed = true;
        update();
        pill.focus({ preventScroll: true });
        return;
      case "close":
        dismissed.add(id);
        update();
        return;
      case "show":
        host.showFiles(id);
        return;
      case "accept":
      case "decline":
      case "confirm":
      case "reject":
        if (transfer) host.answer(transfer, action);
        return;
      case "pause":
      case "resume":
      case "cancel":
        host.control(id, action);
        return;
    }
  });
  dock.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || collapsed || cards.size === 0) return;
    event.preventDefault();
    collapsed = true;
    update();
    pill.focus({ preventScroll: true });
  });

  return { update, live, reveal };
}

/** "PDF" for report.pdf; a dot for names without one. */
function extension(name: string): string {
  const dot = name.lastIndexOf(".");
  const ext = dot > 0 && dot < name.length - 1 ? name.slice(dot + 1) : "";
  return ext && ext.length <= 4 ? ext.toUpperCase() : "•";
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}

function escapeAttribute(value: string): string {
  return escapeHtml(value.replace(/[\r\n]/g, ""));
}

const SVG = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
const CHEVRON = `<svg ${SVG}><path d="m6 9 6 6 6-6"/></svg>`;
/** The check draws itself when a transfer completes. */
const CHECK_DRAW = `<svg ${SVG} class="dock-check"><path pathLength="1" d="m5 12 4 4L19 6"/></svg>`;
