import type { AppSettings, AppSnapshot, AppTab, TunnelServer, WindowsProcess } from "../shared/contracts";

let state: AppSnapshot | null = null;
let activeTab: AppTab = "home";
let loginWaiting = false;
let authorizationUri: string | null = null;
let authorizationRetryTimer: ReturnType<typeof setTimeout> | null = null;
let showProcessDialog = false;
let processDialogLoading = false;
let processList: WindowsProcess[] = [];
let pendingProcesses = new Set<string>();
let processSearchQuery = "";
let serverSearchQuery = "";
let favoritesOnly = false;
let devicesSubscriptionId: string | null = null;
let toastTimer: ReturnType<typeof setTimeout> | null = null;
let renderedSnapshotKey: string | null = null;

const root = requiredElement("app");

void window.levik.snapshot().then((snapshot) => {
  state = snapshot;
  render();
});

window.levik.onSnapshot((snapshot) => {
  state = snapshot;
  if (snapshot.account) clearLoginWaiting();
  const nextSnapshotKey = snapshotRenderKey(snapshot);
  if (renderedSnapshotKey === nextSnapshotKey) {
    updateLiveData();
  } else {
    render();
  }
});

setInterval(() => {
  document.querySelectorAll<HTMLElement>("[data-session-duration]").forEach((element) => {
    element.textContent = formatDuration(sessionSeconds());
  });
}, 1_000);

function render(preserveScroll = true): void {
  const contentScrollTop = preserveScroll ? document.querySelector<HTMLElement>(".content")?.scrollTop ?? 0 : 0;
  const logScrollTop = preserveScroll ? document.querySelector<HTMLElement>(".log-view")?.scrollTop ?? 0 : 0;
  const processScrollTop = preserveScroll ? document.querySelector<HTMLElement>(".process-list")?.scrollTop ?? 0 : 0;
  if (!state) {
    renderedSnapshotKey = null;
    root.innerHTML = `<main class="login"><div class="spinner" aria-label="Загрузка"></div></main>`;
    return;
  }
  document.documentElement.dataset.theme = state.settings.theme;
  renderedSnapshotKey = snapshotRenderKey(state);
  if (!state.account) {
    renderLogin();
    return;
  }
  root.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark">${icon("shield")}</div>
          <div><div class="brand-name">Levik VPN</div><div class="brand-caption">Windows</div></div>
        </div>
        <nav class="nav" aria-label="Основная навигация">
          ${navButton("home", "Главная", "home")}
          ${navButton("servers", "Серверы", "servers")}
          ${navButton("stats", "Статистика", "stats")}
          ${navButton("profile", "Профиль", "profile")}
        </nav>
        <div class="sidebar-status">
          <div class="status-line"><span class="status-dot ${escapeHtml(state.status)}"></span><span>${statusTitle(state.status)}</span></div>
          <div class="status-subtitle">${escapeHtml(state.statusDetail ?? "VPN готов к подключению")}</div>
        </div>
      </aside>
      <main class="content"><div class="content-inner">${renderPage()}</div></main>
    </div>
    ${showProcessDialog ? renderProcessDialog() : ""}
    ${devicesSubscriptionId ? renderDevicesDialog(devicesSubscriptionId) : ""}`;
  bindCommonEvents();
  bindPageEvents();
  applyProgressWidths();
  applyProcessFilter();
  applyServerFilter();
  const content = document.querySelector<HTMLElement>(".content");
  if (content) content.scrollTop = contentScrollTop;
  const logView = document.querySelector<HTMLElement>(".log-view");
  if (logView) logView.scrollTop = logScrollTop;
  const processListElement = document.querySelector<HTMLElement>(".process-list");
  if (processListElement) processListElement.scrollTop = processScrollTop;
}

function renderLogin(): void {
  root.innerHTML = `
    <main class="login">
      <section class="login-card card">
        <div class="login-shield">${icon("shield")}</div>
        <h1>Добро пожаловать в Levik VPN</h1>
        <p>Войдите в Levik Account, чтобы синхронизировать подписку и получить защищённый профиль для этого компьютера.</p>
        <button class="button primary login-primary" id="login-button" ${state?.busy || loginWaiting ? "disabled" : ""}>
          ${state?.busy ? `<span class="spinner"></span>` : icon("login")} ${loginWaiting ? "Ожидание подтверждения…" : "Войти через Levik Account"}
        </button>
        ${loginWaiting && authorizationUri ? `<button class="button compact login-secondary" id="reopen-login-button">${icon("external")} Повторно открыть подтверждение</button>` : ""}
        <div class="login-status">${escapeHtml(state?.statusDetail ?? (loginWaiting ? "Завершите вход в открывшемся браузере" : ""))}</div>
      </section>
    </main>`;
  document.getElementById("login-button")?.addEventListener("click", () => void beginLogin());
  document.getElementById("reopen-login-button")?.addEventListener("click", () => {
    const uri = authorizationUri;
    if (uri) void run(() => window.levik.openExternal(uri));
  });
}

function renderPage(): string {
  switch (activeTab) {
    case "home": return renderHome();
    case "servers": return renderServers();
    case "stats": return renderStats();
    case "profile": return renderProfile();
  }
}

function renderHome(): string {
  if (!state) return "";
  const connected = state.status === "connected";
  const transitional = ["connecting", "disconnecting", "reconnecting"].includes(state.status);
  const server = selectedServer();
  return `
    <header class="page-header"><div><h1>Главная</h1><div class="subtitle">Защищённый доступ к интернету</div></div></header>
    <div class="home-grid">
      <section class="connection-card card">
        <div class="connection-label">Состояние соединения</div>
        <div class="connection-title ${connected ? "connected" : ""}">${statusTitle(state.status)}</div>
        <button class="power-button ${connected ? "connected" : ""}" id="power-button" aria-label="${connected ? "Отключить VPN" : "Подключить VPN"}" ${transitional || state.busy ? "disabled" : ""}>${transitional ? `<span class="spinner"></span>` : icon("power")}</button>
        <label class="home-server-picker">
          <span class="home-server-flag" aria-hidden="true">${countryFlagSvg(server?.countryCode ?? null)}</span>
          <select id="home-server-select" aria-label="Сервер быстрого подключения" ${state.servers.length && !state.busy ? "" : "disabled"}>
            ${state.servers.length ? state.servers.map((item) => `<option value="${escapeAttribute(item.id)}" ${item.id === state?.selectedServerId ? "selected" : ""}>${escapeHtml(item.name)}</option>`).join("") : `<option>Сервер не выбран</option>`}
          </select>
        </label>
        <div class="connection-detail">${escapeHtml(state.statusDetail ?? "Нажмите кнопку, чтобы включить защиту")}</div>
      </section>
      <div class="side-stack">
        <section class="compact-card card"><h2 class="card-title">Текущая сессия</h2><div class="card-caption">Счётчики рассчитываются локально</div><div class="metric-grid"><div class="metric"><div class="metric-label">Время</div><div class="metric-value" data-session-duration>${formatDuration(sessionSeconds())}</div></div><div class="metric"><div class="metric-label">Режим</div><div class="metric-value">${routingTitle(state.settings.routingMode)}</div></div></div></section>
        <section class="compact-card card"><h2 class="card-title">Защита соединения</h2><div class="card-caption">Автовосстановление туннеля и защищённый DNS</div><div class="metric-grid"><div class="metric"><div class="metric-label">Auto-Healing</div><div class="metric-value">${state.settings.autoReconnect ? "Вкл." : "Выкл."}</div></div><div class="metric"><div class="metric-label">DNS</div><div class="metric-value">${escapeHtml(state.settings.dnsServer)}</div></div></div></section>
      </div>
    </div>`;
}

function renderServers(): string {
  if (!state) return "";
  return `
    <header class="page-header"><div><h1>VPN-серверы</h1><div class="subtitle">Выберите точку подключения Levik VPN</div></div><div class="toolbar"><button class="button icon-button ${favoritesOnly ? "active" : ""}" id="favorites-filter-button" aria-label="Показать избранные" aria-pressed="${favoritesOnly}">${icon("star")}</button><button class="button icon-button" id="ping-button" aria-label="Измерить задержку">${icon("pulse")}</button><button class="button icon-button" id="refresh-button" aria-label="Обновить профиль">${icon("refresh")}</button></div></header>
    <label class="server-search"><span>${icon("search")}</span><input id="server-search-input" type="search" placeholder="Поиск по серверу или стране" autocomplete="off" value="${escapeAttribute(serverSearchQuery)}" /></label>
    ${state.servers.length ? `<div class="server-list">${state.servers.map(serverCard).join("")}</div><div class="empty card-flat server-empty" hidden>Серверы не найдены</div>` : `<div class="empty card-flat">Для выбранной подписки нет совместимых серверов</div>`}`;
}

function serverCard(server: TunnelServer): string {
  const selected = state?.selectedServerId === server.id;
  const favorite = state?.settings.favoriteServerIds.includes(server.id) ?? false;
  const latency = state?.serverLatencies[server.id];
  const filter = `${server.name} ${countryLabel(server.countryCode)} ${server.countryCode}`.toLocaleLowerCase("ru");
  return `<div class="server-card ${selected ? "selected" : ""}" data-server-filter="${escapeAttribute(filter)}" data-server-favorite="${favorite}"><button class="server-select" data-server-id="${escapeAttribute(server.id)}" aria-label="Выбрать ${escapeAttribute(server.name)}"><span class="server-flag" aria-hidden="true">${countryFlagSvg(server.countryCode)}</span><span class="server-copy"><span class="server-name">${escapeHtml(server.name)}</span><span class="server-meta">${escapeHtml(countryLabel(server.countryCode))} · ${escapeHtml(serverProtocol(server))} · ${latency === undefined ? "не измерен" : latency === null ? "нет ответа" : `${latency} мс`}</span></span><span class="radio"></span></button><button class="favorite-button ${favorite ? "active" : ""}" data-favorite-server-id="${escapeAttribute(server.id)}" aria-label="${favorite ? "Удалить из избранного" : "Добавить в избранное"}" aria-pressed="${favorite}">${icon("star")}</button></div>`;
}

function renderStats(): string {
  if (!state) return "";
  return `
    <header class="page-header"><div><h1>Статистика соединения</h1><div class="subtitle">Локальные показатели текущего сеанса</div></div></header>
    <div class="stats-grid">
      ${statCard("clock", formatDuration(sessionSeconds()), "Длительность", true)}
      ${statCard("download", formatBytes(state.downloadBytes), "Загружено", false, "data-download-bytes")}
      ${statCard("upload", formatBytes(state.uploadBytes), "Отправлено", false, "data-upload-bytes")}
    </div>
    <section class="logs card"><h2 class="card-title">Журнал диагностики</h2><div class="card-caption">Секреты и содержимое трафика не записываются</div><div class="log-view">${escapeHtml(state.logs.join("\n") || "Событий пока нет")}</div></section>`;
}

function renderProfile(): string {
  if (!state?.account) return "";
  return `
    <header class="page-header"><div><h1>Профиль и настройки</h1><div class="subtitle">Levik Account и параметры Windows-клиента</div></div><div class="toolbar"><button class="button" id="manage-subscription-button">${icon("renew")} Управление подпиской</button><button class="button" id="support-button">${icon("support")} Поддержка</button><button class="button danger" id="logout-button">${icon("logout")} Выйти</button></div></header>
    <div class="profile-grid">
      <section class="section card">
        <div class="account-row"><div class="avatar">${icon("profile")}</div><div><div class="account-name">${escapeHtml(state.account.userLabel)}</div><div class="account-state">Аккаунт синхронизирован</div></div></div>
        <div class="subscription-list">${state.account.subscriptions.map(subscriptionCard).join("") || `<div class="empty">Нет активных подписок</div>`}</div>
      </section>
      <section class="section card"><h2 class="card-title">Настройки</h2><div class="settings-list">
        ${selectSetting("Маршрутизация", "Какие сайты открывать через VPN", "routing-mode", state.settings.routingMode, [["global","Весь трафик"],["bypassRu","Обход ресурсов РФ"],["blockedOnly","Только заблокированное"]])}
        ${switchSetting("Автовыбор сервера", "Выбирать сервер с минимальной задержкой", "automaticServer", state.settings.automaticServer)}
        ${switchSetting("Автовосстановление", "Перезапускать туннель после сбоя", "autoReconnect", state.settings.autoReconnect)}
        ${switchSetting("Автоподключение", "Подключаться при запуске Levik VPN", "autoConnectOnLaunch", state.settings.autoConnectOnLaunch)}
        ${switchSetting("Kill Switch", "Не выпускать трафик мимо активного туннеля", "killSwitch", state.settings.killSwitch)}
        ${switchSetting("DNS over HTTPS", "Шифровать DNS-запросы", "useDoh", state.settings.useDoh)}
        ${switchSetting("Защита от DNS-утечек", "Отключать Windows SMHNR во время работы VPN", "preventDnsLeaks", state.settings.preventDnsLeaks)}
        ${switchSetting("Anti-DPI", "Фрагментировать TLS ClientHello для обхода фильтрации", "antiDpiEnabled", state.settings.antiDpiEnabled)}
        ${selectSetting("Раздельное туннелирование", "Маршрутизация по процессам Windows", "split-tunnel-mode", state.settings.splitTunnelMode, [["off","Выключено"],["bypass","Исключить выбранные"],["only","Только выбранные"]])}
        ${state.settings.splitTunnelMode !== "off" ? `<div class="setting-row"><div><div class="setting-name">Приложения</div><div class="setting-help">${state.settings.splitTunnelProcesses.length ? `Выбрано: ${state.settings.splitTunnelProcesses.length}` : "Выберите процессы из запущенных приложений"}</div></div><button class="button compact" id="process-picker-button">${icon("process")} Выбрать</button></div>` : ""}
        ${switchSetting("Запуск с Windows", "Открывать Levik VPN после входа", "launchAtLogin", state.settings.launchAtLogin)}
        ${switchSetting("Закрытие в трей", "Кнопка закрытия скрывает приложение", "closeToTray", state.settings.closeToTray)}
        ${selectSetting("Оформление", "Единый стиль Levik VPN", "theme", state.settings.theme, [["system","Системная"],["dark","Тёмная"],["light","Светлая"],["amoled","AMOLED"]])}
        ${updateSetting()}
      </div></section>
    </div>`;
}

function subscriptionCard(subscription: NonNullable<AppSnapshot["account"]>["subscriptions"][number]): string {
  const selected = state?.selectedSubscriptionId === subscription.uuid;
  const limit = subscription.traffic.limitBytes;
  const percent = limit > 0 ? Math.min(100, Math.round(subscription.traffic.usedBytes / limit * 100)) : 0;
  return `<div class="subscription-wrap"><button class="subscription ${selected ? "selected" : ""}" data-subscription-id="${escapeAttribute(subscription.uuid)}"><span class="subscription-head"><span class="subscription-title">${escapeHtml(subscription.title)}</span><span class="badge">${escapeHtml(subscription.status)}</span></span><span class="progress" role="progressbar" aria-label="Использовано трафика" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><span class="progress-fill ${subscription.traffic.usedBytes > 0 ? "has-usage" : ""}" data-progress="${percent}"></span></span><span class="subscription-meta"><span>${formatBytes(subscription.traffic.usedBytes)} из ${limit > 0 ? formatBytes(limit) : "∞"}</span><span>${subscription.devices.used}/${subscription.devices.limit} устройств</span></span></button><div class="subscription-actions"><button class="button compact" data-devices-subscription-id="${escapeAttribute(subscription.uuid)}">${icon("devices")} Устройства</button>${subscription.shield.supported ? `<button class="button compact" data-shield-subscription-id="${escapeAttribute(subscription.uuid)}" data-shield-enabled="${subscription.shield.enabled}">${icon("shield")} Shield: ${subscription.shield.enabled ? "вкл." : "выкл."}</button>` : ""}${subscription.actions.renew ? `<button class="button compact" data-renew-subscription-id="${escapeAttribute(subscription.uuid)}">${icon("renew")} Продлить</button>` : ""}</div></div>`;
}

function updateSetting(): string {
  if (!state) return "";
  const update = state.update;
  const canInstall = update.status === "downloaded";
  const disabled = ["checking", "downloading"].includes(update.status);
  const label = canInstall ? "Установить" : update.status === "downloading" ? `${update.progress ?? 0}%` : "Проверить";
  return `<div class="setting-row"><div><div class="setting-name">Обновление приложения</div><div class="setting-help">${escapeHtml(update.message ?? `Текущая версия ${state.appVersion}`)}</div></div><button class="button compact" id="update-button" ${disabled ? "disabled" : ""}>${icon(canInstall ? "install" : "update")} ${label}</button></div>`;
}

function renderProcessDialog(): string {
  const selected = pendingProcesses;
  return `<div class="dialog-backdrop" id="process-dialog-backdrop">
    <section class="process-dialog card" role="dialog" aria-modal="true" aria-labelledby="process-dialog-title">
      <header class="dialog-header"><div><h2 id="process-dialog-title">Приложения Windows</h2><p>Выберите процессы для правила раздельного туннелирования.</p></div><button class="button icon-button" id="close-process-dialog" aria-label="Закрыть">${icon("close")}</button></header>
      <label class="process-search"><span>${icon("search")}</span><input id="process-search-input" type="search" placeholder="Поиск по названию или пути" autocomplete="off" value="${escapeAttribute(processSearchQuery)}" ${processDialogLoading ? "disabled" : ""} /></label>
      ${processDialogLoading ? `<div class="dialog-loading"><span class="spinner"></span> Получаем список процессов…</div>` : processList.length ? `<div class="process-list">${processList.map((item) => `<button class="process-row ${selected.has(item.name) ? "selected" : ""}" data-process-name="${escapeAttribute(item.name)}" data-process-filter="${escapeAttribute(`${item.name} ${item.path ?? ""}`.toLocaleLowerCase("ru"))}" aria-pressed="${selected.has(item.name)}"><span class="process-icon">${icon("process")}</span><span class="process-copy"><span class="process-name">${escapeHtml(item.name)}</span><span class="process-path">${escapeHtml(item.path ?? "Процесс сейчас не запущен")}</span></span><span class="process-check">${selected.has(item.name) ? icon("check") : ""}</span></button>`).join("")}</div>` : `<div class="empty">Запущенные процессы не найдены</div>`}
      <footer class="dialog-actions"><button class="button" id="browse-executable-button">${icon("browse")} Обзор…</button><span class="dialog-spacer"></span><button class="button" id="cancel-process-dialog">Отмена</button><button class="button primary" id="save-process-dialog" ${processDialogLoading ? "disabled" : ""}>${icon("save")} Сохранить выбор</button></footer>
    </section>
  </div>`;
}

function renderDevicesDialog(subscriptionId: string): string {
  const subscription = state?.account?.subscriptions.find((item) => item.uuid === subscriptionId);
  if (!subscription) {
    devicesSubscriptionId = null;
    return "";
  }
  return `<div class="dialog-backdrop" id="devices-dialog-backdrop"><section class="process-dialog card" role="dialog" aria-modal="true" aria-labelledby="devices-dialog-title"><header class="dialog-header"><div><h2 id="devices-dialog-title">Подключённые устройства</h2><p>Занято слотов: ${subscription.devices.used} из ${subscription.devices.limit}</p></div><button class="button icon-button" id="close-devices-dialog" aria-label="Закрыть">${icon("close")}</button></header><div class="device-list">${subscription.devices.items.length ? subscription.devices.items.map((device) => `<div class="device-row"><span class="process-icon">${icon("devices")}</span><span class="process-copy"><span class="process-name">${escapeHtml(device.label)}</span><span class="process-path">${escapeHtml(device.id)}</span></span>${subscription.actions.revokeDevice ? `<button class="button compact danger" data-revoke-device-id="${escapeAttribute(device.id)}" data-revoke-subscription-id="${escapeAttribute(subscription.uuid)}">${icon("unlink")} Отвязать</button>` : ""}</div>`).join("") : `<div class="empty">Активных устройств нет</div>`}</div><footer class="dialog-actions"><button class="button" id="close-devices-dialog-footer">Закрыть</button></footer></section></div>`;
}

function switchSetting(name: string, help: string, key: keyof AppSettings, enabled: boolean): string {
  return `<div class="setting-row"><div><div class="setting-name">${name}</div><div class="setting-help">${help}</div></div><button class="switch ${enabled ? "on" : ""}" role="switch" aria-checked="${enabled}" data-setting="${key}" aria-label="${name}"></button></div>`;
}

function selectSetting(name: string, help: string, id: string, current: string, options: ReadonlyArray<readonly [string, string]>): string {
  return `<label class="setting-row" for="${id}"><span><span class="setting-name">${name}</span><span class="setting-help">${help}</span></span><select class="select" id="${id}">${options.map(([value,label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`).join("")}</select></label>`;
}

function statCard(iconName: IconName, value: string, name: string, duration = false, liveAttribute = ""): string {
  return `<div class="stat-card card"><div class="stat-icon">${icon(iconName)}</div><div class="stat-number" ${duration ? "data-session-duration" : liveAttribute}>${escapeHtml(value)}</div><div class="stat-name">${name}</div></div>`;
}

function navButton(tab: AppTab, label: string, iconName: IconName): string {
  return `<button class="nav-button ${activeTab === tab ? "active" : ""}" data-tab="${tab}">${icon(iconName)}<span>${label}</span></button>`;
}

function bindCommonEvents(): void {
  document.querySelectorAll<HTMLElement>("[data-tab]").forEach((button) => button.addEventListener("click", () => {
    const tab = button.dataset.tab;
    if (tab === "home" || tab === "servers" || tab === "stats" || tab === "profile") {
      activeTab = tab;
      render(false);
    }
  }));
}

function bindPageEvents(): void {
  document.getElementById("power-button")?.addEventListener("click", () => run(() => state?.status === "connected" ? window.levik.disconnect() : window.levik.connect()));
  document.getElementById("home-server-select")?.addEventListener("change", (event) => {
    const serverId = (event.target as HTMLSelectElement).value;
    if (serverId && serverId !== state?.selectedServerId) void run(() => window.levik.selectServer(serverId));
  });
  document.getElementById("refresh-button")?.addEventListener("click", () => run(() => window.levik.refreshAccount()));
  document.getElementById("ping-button")?.addEventListener("click", () => run(() => window.levik.pingServers()));
  document.getElementById("favorites-filter-button")?.addEventListener("click", () => {
    favoritesOnly = !favoritesOnly;
    render();
  });
  document.getElementById("server-search-input")?.addEventListener("input", (event) => {
    serverSearchQuery = (event.target as HTMLInputElement).value;
    applyServerFilter();
  });
  document.querySelectorAll<HTMLElement>("[data-server-id]").forEach((button) => button.addEventListener("click", () => run(() => window.levik.selectServer(button.dataset.serverId ?? ""))));
  document.querySelectorAll<HTMLElement>("[data-favorite-server-id]").forEach((button) => button.addEventListener("click", () => {
    const currentState = state;
    const serverId = button.dataset.favoriteServerId;
    if (!currentState || !serverId) return;
    const favorites = new Set(currentState.settings.favoriteServerIds);
    if (favorites.has(serverId)) favorites.delete(serverId);
    else favorites.add(serverId);
    void run(() => window.levik.updateSettings({ favoriteServerIds: [...favorites] }));
  }));
  document.querySelectorAll<HTMLElement>("[data-subscription-id]").forEach((button) => button.addEventListener("click", () => run(() => window.levik.selectSubscription(button.dataset.subscriptionId ?? ""))));
  document.querySelectorAll<HTMLElement>("[data-setting]").forEach((button) => button.addEventListener("click", () => {
    const currentState = state;
    if (!currentState) return;
    const key = button.dataset.setting as "automaticServer" | "autoReconnect" | "autoConnectOnLaunch" | "killSwitch" | "useDoh" | "preventDnsLeaks" | "antiDpiEnabled" | "launchAtLogin" | "closeToTray";
    void run(() => window.levik.updateSettings({ [key]: !currentState.settings[key] }));
  }));
  document.getElementById("routing-mode")?.addEventListener("change", (event) => {
    const routingMode = (event.target as HTMLSelectElement).value as AppSettings["routingMode"];
    void run(() => window.levik.updateSettings({ routingMode }));
  });
  document.getElementById("theme")?.addEventListener("change", (event) => {
    const theme = (event.target as HTMLSelectElement).value as AppSettings["theme"];
    void run(() => window.levik.updateSettings({ theme }));
  });
  document.getElementById("split-tunnel-mode")?.addEventListener("change", (event) => {
    const splitTunnelMode = (event.target as HTMLSelectElement).value as AppSettings["splitTunnelMode"];
    void run(() => window.levik.updateSettings({ splitTunnelMode }));
  });
  document.getElementById("process-picker-button")?.addEventListener("click", () => void openProcessDialog());
  document.getElementById("close-process-dialog")?.addEventListener("click", closeProcessDialog);
  document.getElementById("cancel-process-dialog")?.addEventListener("click", closeProcessDialog);
  document.getElementById("process-dialog-backdrop")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeProcessDialog();
  });
  document.querySelectorAll<HTMLElement>("[data-process-name]").forEach((button) => button.addEventListener("click", () => {
    const processName = button.dataset.processName;
    if (!processName) return;
    if (pendingProcesses.has(processName)) pendingProcesses.delete(processName);
    else pendingProcesses.add(processName);
    const selected = pendingProcesses.has(processName);
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
    const check = button.querySelector<HTMLElement>(".process-check");
    if (check) check.innerHTML = selected ? icon("check") : "";
  }));
  document.getElementById("process-search-input")?.addEventListener("input", (event) => {
    processSearchQuery = (event.target as HTMLInputElement).value;
    applyProcessFilter();
  });
  document.getElementById("save-process-dialog")?.addEventListener("click", () => void run(async () => {
    await window.levik.updateSettings({ splitTunnelProcesses: [...pendingProcesses].sort((left, right) => left.localeCompare(right)) });
    closeProcessDialog();
  }));
  document.getElementById("browse-executable-button")?.addEventListener("click", () => void run(async () => {
    const selected = await window.levik.selectExecutable();
    if (!selected) return;
    pendingProcesses.add(selected.name);
    if (!processList.some((item) => item.name.toLocaleLowerCase("en") === selected.name.toLocaleLowerCase("en"))) {
      processList = [...processList, selected].sort((left, right) => left.name.localeCompare(right.name));
    }
    render();
  }));
  document.querySelectorAll<HTMLElement>("[data-devices-subscription-id]").forEach((button) => button.addEventListener("click", () => {
    devicesSubscriptionId = button.dataset.devicesSubscriptionId ?? null;
    render();
  }));
  document.getElementById("close-devices-dialog")?.addEventListener("click", closeDevicesDialog);
  document.getElementById("close-devices-dialog-footer")?.addEventListener("click", closeDevicesDialog);
  document.getElementById("devices-dialog-backdrop")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeDevicesDialog();
  });
  document.querySelectorAll<HTMLElement>("[data-revoke-device-id]").forEach((button) => button.addEventListener("click", () => {
    const subscriptionId = button.dataset.revokeSubscriptionId;
    const deviceId = button.dataset.revokeDeviceId;
    if (!subscriptionId || !deviceId) return;
    const label = state?.account?.subscriptions.find((item) => item.uuid === subscriptionId)?.devices.items.find((item) => item.id === deviceId)?.label ?? "это устройство";
    if (confirm(`Отвязать «${label}» от подписки?`)) void run(() => window.levik.revokeDevice(subscriptionId, deviceId));
  }));
  document.querySelectorAll<HTMLElement>("[data-shield-subscription-id]").forEach((button) => button.addEventListener("click", () => {
    const subscriptionId = button.dataset.shieldSubscriptionId;
    if (!subscriptionId) return;
    void run(() => window.levik.setSubscriptionShield(subscriptionId, button.dataset.shieldEnabled !== "true"));
  }));
  document.querySelectorAll<HTMLElement>("[data-renew-subscription-id]").forEach((button) => button.addEventListener("click", () => run(() => window.levik.openExternal("https://t.me/levikvpnbot"))));
  document.getElementById("manage-subscription-button")?.addEventListener("click", () => run(() => window.levik.openExternal("https://t.me/levikvpnbot")));
  document.getElementById("update-button")?.addEventListener("click", () => run(() => state?.update.status === "downloaded" ? window.levik.installUpdate() : window.levik.checkForUpdates()));
  document.getElementById("support-button")?.addEventListener("click", () => run(() => window.levik.openExternal("https://t.me/leviksupportbot")));
  document.getElementById("logout-button")?.addEventListener("click", () => {
    if (confirm("Выйти из Levik Account на этом компьютере? Текущий VPN-туннель будет остановлен.")) void run(() => window.levik.logout());
  });
}

async function beginLogin(): Promise<void> {
  loginWaiting = true;
  render();
  try {
    const challenge = await window.levik.login();
    authorizationUri = challenge.verificationUri;
    render();
    if (authorizationRetryTimer) clearTimeout(authorizationRetryTimer);
    authorizationRetryTimer = setTimeout(() => {
      if (!state?.account && loginWaiting && authorizationUri) {
        void run(() => window.levik.openExternal(authorizationUri as string));
      }
    }, 7_500);
  } catch (error) {
    clearLoginWaiting();
    render();
    showToast(error instanceof Error ? error.message : String(error));
  }
}

function clearLoginWaiting(): void {
  loginWaiting = false;
  authorizationUri = null;
  if (authorizationRetryTimer) clearTimeout(authorizationRetryTimer);
  authorizationRetryTimer = null;
}

async function openProcessDialog(): Promise<void> {
  if (!state) return;
  showProcessDialog = true;
  processDialogLoading = true;
  pendingProcesses = new Set(state.settings.splitTunnelProcesses);
  processSearchQuery = "";
  render();
  try {
    const running = await window.levik.listProcesses();
    const runningNames = new Set(running.map((item) => item.name));
    processList = [
      ...running,
      ...state.settings.splitTunnelProcesses
        .filter((name) => !runningNames.has(name))
        .map((name) => ({ name, path: null })),
    ];
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error));
    processList = [];
  } finally {
    processDialogLoading = false;
    if (showProcessDialog) render();
  }
}

function closeProcessDialog(): void {
  showProcessDialog = false;
  processDialogLoading = false;
  render();
}

function closeDevicesDialog(): void {
  devicesSubscriptionId = null;
  render();
}

function applyProgressWidths(): void {
  document.querySelectorAll<HTMLElement>("[data-progress]").forEach((element) => {
    const value = Number(element.dataset.progress);
    element.style.width = `${Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0}%`;
  });
}

function applyProcessFilter(): void {
  const query = processSearchQuery.trim().toLocaleLowerCase("ru");
  document.querySelectorAll<HTMLElement>("[data-process-filter]").forEach((element) => {
    element.hidden = Boolean(query) && !(element.dataset.processFilter ?? "").includes(query);
  });
}

function applyServerFilter(): void {
  const query = serverSearchQuery.trim().toLocaleLowerCase("ru");
  let visible = 0;
  document.querySelectorAll<HTMLElement>("[data-server-filter]").forEach((element) => {
    const matchesSearch = !query || (element.dataset.serverFilter ?? "").includes(query);
    const matchesFavorite = !favoritesOnly || element.dataset.serverFavorite === "true";
    element.hidden = !(matchesSearch && matchesFavorite);
    if (!element.hidden) visible += 1;
  });
  const empty = document.querySelector<HTMLElement>(".server-empty");
  if (empty) empty.hidden = visible > 0;
}

function snapshotRenderKey(snapshot: AppSnapshot): string {
  const { downloadBytes: _downloadBytes, uploadBytes: _uploadBytes, logs: _logs, ...renderedState } = snapshot;
  return JSON.stringify(renderedState);
}

function updateLiveData(): void {
  if (!state) return;
  document.querySelectorAll<HTMLElement>("[data-session-duration]").forEach((element) => {
    element.textContent = formatDuration(sessionSeconds());
  });
  const download = document.querySelector<HTMLElement>("[data-download-bytes]");
  if (download) download.textContent = formatBytes(state.downloadBytes);
  const upload = document.querySelector<HTMLElement>("[data-upload-bytes]");
  if (upload) upload.textContent = formatBytes(state.uploadBytes);
  const logView = document.querySelector<HTMLElement>(".log-view");
  if (logView) {
    const previousHeight = logView.scrollHeight;
    const previousTop = logView.scrollTop;
    logView.textContent = state.logs.join("\n") || "Событий пока нет";
    logView.scrollTop = previousTop <= 4 ? 0 : previousTop + logView.scrollHeight - previousHeight;
  }
}

async function run(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error));
  }
}

function showToast(message: string): void {
  const toast = requiredElement("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 4_500);
}

function selectedServer(): TunnelServer | null {
  return state?.servers.find((server) => server.id === state?.selectedServerId) ?? null;
}

function sessionSeconds(): number {
  return state?.sessionStartedAt ? Math.max(0, Math.floor((Date.now() - state.sessionStartedAt) / 1_000)) : 0;
}

function statusTitle(status: AppSnapshot["status"]): string {
  return ({ disconnected: "Не подключено", connecting: "Подключение", connected: "VPN включён", reconnecting: "Восстановление", disconnecting: "Отключение", error: "Ошибка соединения" })[status];
}

function routingTitle(mode: AppSettings["routingMode"]): string {
  return ({ global: "Global", bypassRu: "Bypass RU", blockedOnly: "Anti-Block" })[mode];
}

function serverProtocol(server: TunnelServer): string {
  const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol.toLowerCase() : "vpn";
  if (protocol === "hysteria" || protocol === "hysteria2" || protocol === "hy2") return "Hysteria 2";
  if (protocol === "vless") {
    const security = isRecord(server.outbound.streamSettings) && typeof server.outbound.streamSettings.security === "string"
      ? server.outbound.streamSettings.security
      : null;
    return security?.toLowerCase() === "reality" ? "VLESS · Reality" : "VLESS";
  }
  if (protocol === "trojan") return "Trojan";
  return protocol.toUpperCase();
}

function countryLabel(countryCode: string | null): string {
  return countryCode?.toUpperCase() || "Levik VPN";
}

function countryFlagSvg(countryCode: string | null): string {
  const normalized = countryCode?.trim().toUpperCase() ?? "";
  const shapes: Readonly<Record<string, string>> = {
    DE: '<path fill="#1a1a1a" d="M0 0h24v5.34H0z"/><path fill="#d00" d="M0 5.33h24v5.34H0z"/><path fill="#ffce00" d="M0 10.66h24V16H0z"/>',
    NL: '<path fill="#ae1c28" d="M0 0h24v5.34H0z"/><path fill="#fff" d="M0 5.33h24v5.34H0z"/><path fill="#21468b" d="M0 10.66h24V16H0z"/>',
    FI: '<path fill="#fff" d="M0 0h24v16H0z"/><path fill="#003580" d="M0 6h24v4H0zM7 0h4v16H7z"/>',
    FR: '<path fill="#0055a4" d="M0 0h8v16H0z"/><path fill="#fff" d="M8 0h8v16H8z"/><path fill="#ef4135" d="M16 0h8v16h-8z"/>',
    GB: '<path fill="#012169" d="M0 0h24v16H0z"/><path stroke="#fff" stroke-width="3.2" d="m0 0 24 16M24 0 0 16"/><path stroke="#c8102e" stroke-width="1.6" d="m0 0 24 16M24 0 0 16"/><path stroke="#fff" stroke-width="5" d="M12 0v16M0 8h24"/><path stroke="#c8102e" stroke-width="3" d="M12 0v16M0 8h24"/>',
    US: '<path fill="#fff" d="M0 0h24v16H0z"/><path stroke="#b22234" stroke-width="2.45" stroke-dasharray="2.45 2.45" d="M0 1.2h24M0 6.1h24M0 11h24M0 15.9h24"/><path fill="#3c3b6e" d="M0 0h10.5v8.6H0z"/><path fill="#fff" d="m2 2 .4 1.2h1.3l-1 .7.4 1.2L2 4.4.9 5.1l.4-1.2-1-.7H1.6zM7 2l.4 1.2h1.3l-1 .7.4 1.2L7 4.4l-1.1.7.4-1.2-1-.7h1.3z"/>',
    SG: '<path fill="#ef3340" d="M0 0h24v8H0z"/><path fill="#fff" d="M0 8h24v8H0z"/><path fill="#fff" fill-rule="evenodd" d="M7 1.4a3 3 0 1 0 0 5.2 2.4 2.4 0 1 1 0-5.2"/>',
    SE: '<path fill="#006aa7" d="M0 0h24v16H0z"/><path fill="#fecc00" d="M0 6h24v4H0zM7 0h4v16H7z"/>',
    CH: '<path fill="#d52b1e" d="M0 0h24v16H0z"/><path fill="#fff" d="M10 3h4v10h-4zM7 6h10v4H7z"/>',
    PL: '<path fill="#fff" d="M0 0h24v8H0z"/><path fill="#dc143c" d="M0 8h24v8H0z"/>',
    LV: '<path fill="#9e3039" d="M0 0h24v16H0z"/><path fill="#fff" d="M0 6.4h24v3.2H0z"/>',
    RU: '<path fill="#fff" d="M0 0h24v5.34H0z"/><path fill="#0039a6" d="M0 5.33h24v5.34H0z"/><path fill="#d52b1e" d="M0 10.66h24V16H0z"/>',
    JP: '<path fill="#fff" d="M0 0h24v16H0z"/><circle fill="#bc002d" cx="12" cy="8" r="4.4"/>',
    CA: '<path fill="#d80621" d="M0 0h5v16H0zM19 0h5v16h-5z"/><path fill="#fff" d="M5 0h14v16H5z"/><path fill="#d80621" d="m12 2 1 2 2-.8-.6 2.2 2 .8-2 1.5 1.2 1.8-2.5-.3.3 3.3h-2.8l.3-3.3-2.5.3 1.2-1.8-2-1.5 2-.8-.6-2.2 2 .8z"/>',
    TR: '<path fill="#e30a17" d="M0 0h24v16H0z"/><circle fill="#fff" cx="10" cy="8" r="4.2"/><circle fill="#e30a17" cx="11.5" cy="8" r="3.4"/><path fill="#fff" d="m15.2 5.8.6 1.4 1.5.1-1.2 1 .4 1.5-1.3-.8-1.3.8.4-1.5-1.2-1 1.5-.1z"/>',
  };
  const shape = shapes[normalized];
  if (shape) return `<svg class="country-flag" viewBox="0 0 24 16" focusable="false">${shape}</svg>`;
  const label = /^[A-Z]{2}$/.test(normalized) ? normalized : "VPN";
  return `<svg class="country-flag" viewBox="0 0 24 16" focusable="false"><rect width="24" height="16" fill="#245fba"/><text x="12" y="10.7" text-anchor="middle" fill="#fff" font-size="6" font-family="Segoe UI, sans-serif" font-weight="700">${label}</text></svg>`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(seconds % 3600 / 60);
  const rest = seconds % 60;
  return hours > 0 ? `${hours}:${String(minutes).padStart(2,"0")}:${String(rest).padStart(2,"0")}` : `${minutes}:${String(rest).padStart(2,"0")}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} КБ`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} МБ`;
  return `${(bytes / 1024 ** 3).toFixed(1)} ГБ`;
}

function requiredElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing #${id}`);
  return element;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}

function escapeAttribute(value: string): string {
  return escapeHtml(value.replace(/[\r\n]/g, ""));
}

type IconName = "shield" | "home" | "servers" | "stats" | "profile" | "power" | "refresh" | "server" | "clock" | "download" | "upload" | "support" | "logout" | "login" | "external" | "process" | "close" | "check" | "search" | "star" | "pulse" | "browse" | "save" | "devices" | "unlink" | "renew" | "update" | "install";

function icon(name: IconName): string {
  const paths: Record<IconName, string> = {
    shield: '<path d="M12 3 4.8 6v4.8c0 4.5 2.9 7.5 7.2 9.3 4.3-1.8 7.2-4.8 7.2-9.3V6z"/><path d="m8.4 12 2.2 2.2 5-5"/>',
    home: '<path d="m3 11 9-8 9 8"/><path d="M5 10v10h14V10M9 20v-6h6v6"/>',
    servers: '<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01M8 17h.01M12 7h5M12 17h5"/>',
    stats: '<path d="M4 19V9M10 19V4M16 19v-7M22 19H2"/>',
    profile: '<circle cx="12" cy="8" r="4"/><path d="M4 21c.7-4.1 3.4-6 8-6s7.3 1.9 8 6"/>',
    power: '<path d="M12 2v10"/><path d="M6.7 5.8a9 9 0 1 0 10.6 0"/>',
    refresh: '<path d="M20 6v5h-5"/><path d="M19 11a8 8 0 1 0 .2 5"/>',
    server: '<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01M8 17h.01"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    download: '<path d="M12 3v13M7 11l5 5 5-5M5 21h14"/>',
    upload: '<path d="M12 21V8M7 13l5-5 5 5M5 3h14"/>',
    support: '<circle cx="12" cy="12" r="9"/><path d="M8.5 9a3.5 3.5 0 1 1 5.5 2.9c-1.4 1-2 1.5-2 3.1M12 18h.01"/>',
    logout: '<path d="M10 5H5v14h5M14 8l4 4-4 4M18 12H9"/>',
    login: '<path d="M14 5h5v14h-5M10 8l-4 4 4 4M6 12h9"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6H5V6h6"/>',
    process: '<rect x="3" y="4" width="18" height="15" rx="2"/><path d="M3 9h18M8 22h8M12 19v3"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    star: '<path d="m12 3 2.7 5.5 6.1.9-4.4 4.3 1 6.1-5.4-2.9-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/>',
    pulse: '<path d="M3 12h4l2-6 4 12 2-6h6"/>',
    browse: '<path d="M3 7h7l2 2h9v10H3z"/><path d="M3 7V5h7l2 2"/>',
    save: '<path d="M5 3h12l2 2v16H5z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/>',
    devices: '<rect x="3" y="5" width="13" height="10" rx="2"/><path d="M8 19h3M9.5 15v4M19 8h2v11h-7v-2"/>',
    unlink: '<path d="m9 15-2 2a3 3 0 0 1-4-4l3-3a3 3 0 0 1 4-.2M15 9l2-2a3 3 0 1 1 4 4l-3 3a3 3 0 0 1-4 .2M8 8l8 8"/>',
    renew: '<path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 0-2 5"/><path d="M12 8v4l3 2"/>',
    update: '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',
    install: '<path d="M12 3v11M8 10l4 4 4-4"/><rect x="4" y="17" width="16" height="4" rx="1"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${paths[name]}</svg>`;
}
