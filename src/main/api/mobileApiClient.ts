import type {
  ApprovalDecisionResponse,
  ApprovalsResponse,
  AuthChallengeResponse,
  AuthStatusResponse,
  IssueCommandResponse,
  MobileAccountResponse,
  RemoteCommandsResponse,
  AccountNotificationsResponse,
  HomeSightingResponse,
  RoadExitResponse,
  RemoteDevicesResponse,
  SettingsDocumentResponse,
  TunnelProfileResponse,
  WebHandoffResponse,
} from "./models";
import { RequestSigner } from "../security/requestSigner";
import type { PresenceReport } from "../platform/liveEvents";
import type { RemoteCommand } from "../../shared/remote";

type SignedRequest = ReturnType<RequestSigner["sign"]>;
import { ApiEndpoints } from "./apiEndpoints";

export class MobileApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null = null,
    readonly authenticationRejected = false,
    /** The website's error code, such as quota_exceeded. */
    readonly code: string | null = null,
  ) {
    super(message);
  }
}

export class MobileApiClient {
  private readonly endpoints: ApiEndpoints;

  constructor(
    baseUrl: string,
    private readonly signer: RequestSigner,
    private readonly version: string,
    refreshEndpoints?: () => Promise<boolean>,
  ) {
    this.endpoints = new ApiEndpoints(baseUrl, refreshEndpoints);
  }

  createChallenge(payload: Record<string, unknown>): Promise<AuthChallengeResponse> {
    return this.request("POST", "/api/mobile/v1/auth/challenge", payload, null);
  }

  pollStatus(loginToken: string): Promise<AuthStatusResponse> {
    return this.request("POST", "/api/mobile/v1/auth/status", { loginToken }, null);
  }

  approvals(accessToken: string): Promise<ApprovalsResponse> {
    return this.request("GET", "/api/mobile/v1/approvals", null, accessToken);
  }

  decideApproval(accessToken: string, id: string, number: number | null): Promise<ApprovalDecisionResponse> {
    return this.request("POST", "/api/mobile/v1/approvals", { id, number }, accessToken);
  }

  /** The account's apps with their live status and the remote commands sent lately. */
  remoteDevices(accessToken: string): Promise<RemoteDevicesResponse> {
    return this.request("GET", "/api/mobile/v1/devices", null, accessToken);
  }

  issueCommand(accessToken: string, deviceId: string, command: RemoteCommand, replyKey: string | null): Promise<IssueCommandResponse> {
    return this.request("POST", "/api/mobile/v1/commands", { deviceId, command, ...(replyKey ? { replyKey } : {}) }, accessToken);
  }

  /** Commands waiting for this computer; asking also makes it reachable by the remote. */
  takeCommands(accessToken: string): Promise<RemoteCommandsResponse> {
    return this.request("GET", "/api/mobile/v1/commands", null, accessToken);
  }

  /** Notices due for the account; taking them delivers them (docs/app-platform.md "Notifications"). */
  takeNotifications(accessToken: string): Promise<AccountNotificationsResponse> {
    return this.request("GET", "/api/mobile/v1/notifications", null, accessToken);
  }

  /** Levik Home: a beacon heard on the local network (docs/app-platform.md "Levik Home"). */
  reportHomeSighting(accessToken: string, sighting: { homeId: string; window: number; proof: string }): Promise<HomeSightingResponse> {
    return this.request("POST", "/api/mobile/v1/home/sighting", sighting, accessToken);
  }

  async commandResult(accessToken: string, id: string, result: "done" | "failed" | "unsupported", detail: string | null): Promise<void> {
    await this.request("POST", "/api/mobile/v1/commands/result", { id, result, detail }, accessToken);
  }

  account(accessToken: string): Promise<MobileAccountResponse> {
    return this.request("GET", "/api/mobile/v1/account", null, accessToken);
  }

  tunnelProfile(accessToken: string, subscriptionId: string): Promise<TunnelProfileResponse> {
    // «🏠» servers of the account's home exits come with the profile (docs/app-platform.md "Home road").
    return this.request("POST", "/api/mobile/v1/tunnel-profile", { subscriptionId }, accessToken, { "X-Levik-Road": "1", "X-Levik-Game": "2" });
  }

  /** This computer's home exit with a fresh relay token, or null. */
  roadExit(accessToken: string): Promise<RoadExitResponse> {
    return this.request("GET", "/api/mobile/v1/road/exit", null, accessToken);
  }

  /** On with this computer's public exit key; off without one. */
  setRoadExit(accessToken: string, key: string | null): Promise<RoadExitResponse> {
    return this.request("POST", "/api/mobile/v1/road/exit", key ? { enabled: true, key } : { enabled: false }, accessToken);
  }

  async logout(accessToken: string): Promise<void> {
    await this.request("POST", "/api/mobile/v1/auth/logout", {}, accessToken);
  }

  async revokeDevice(accessToken: string, subscriptionId: string, deviceId: string): Promise<void> {
    await this.request("POST", "/api/mobile/v1/devices/revoke", { subscriptionId, deviceId }, accessToken);
  }

  async setSubscriptionShield(accessToken: string, subscriptionId: string, enabled: boolean): Promise<void> {
    await this.request("POST", "/api/mobile/v1/subscriptions/shield", { subscriptionId, enabled }, accessToken);
  }

  async authorizeActivation(accessToken: string, code: string): Promise<void> {
    const response = await this.request<{ ok: true; state?: unknown }>(
      "POST",
      "/api/mobile/v1/activation/authorize",
      { code },
      accessToken,
    );
    if (response.state !== "authorized") throw new MobileApiError("API отклонил авторизацию устройства");
  }

  /** Settings shared by the user's apps, docs/app-platform.md. */
  settings(accessToken: string): Promise<SettingsDocumentResponse> {
    return this.request("GET", "/api/mobile/v1/settings", null, accessToken);
  }

  updateSettings(accessToken: string, changes: Record<string, unknown>): Promise<SettingsDocumentResponse> {
    return this.request("PUT", "/api/mobile/v1/settings", { changes }, accessToken);
  }

  /** This computer is online; whether its VPN is on and through which server. */
  async reportPresence(accessToken: string, report: PresenceReport): Promise<{ shared: boolean }> {
    const response = await this.request<{ ok: true; shared?: unknown }>(
      "PUT", "/api/mobile/v1/presence", { ...report }, accessToken,
    );
    return { shared: response.shared !== false };
  }

  async clearPresence(accessToken: string): Promise<void> {
    await this.request("DELETE", "/api/mobile/v1/presence", null, accessToken);
  }

  /** LevikDrop, docs/levik-drop.md: this computer can receive files now, with its identity key. */
  dropPresence(accessToken: string, key: string): Promise<{ ok: true; readyUntil?: unknown }> {
    return this.request("PUT", "/api/mobile/v1/drop/presence", { key, protocol: 1 }, accessToken);
  }

  async clearDropPresence(accessToken: string): Promise<void> {
    await this.request("DELETE", "/api/mobile/v1/drop/presence", null, accessToken);
  }

  /** The account's apps that could receive files and today's limit; checked by levikDrop/engine.ts. */
  dropDevices(accessToken: string): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/mobile/v1/drop/devices", null, accessToken);
  }

  dropTransfers(accessToken: string): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/mobile/v1/drop/transfers", null, accessToken);
  }

  createDropTransfer(accessToken: string, offer: { receiverDeviceId: string; fileCount: number; totalBytes: number }): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/mobile/v1/drop/transfers", { ...offer }, accessToken);
  }

  updateDropTransfer(accessToken: string, step: { id: string; action: string; reason?: string }): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/mobile/v1/drop/transfers/update", { ...step }, accessToken);
  }

  /** Live hints for this account (liveEvents.ts). The caller aborts the stream. */
  async openEvents(accessToken: string, signal: AbortSignal): Promise<ReadableStream<Uint8Array>> {
    const origin = await this.endpoints.resolve();
    const url = new URL("/api/mobile/v1/events", origin);
    const signed = this.signer.sign("GET", url.pathname, accessToken, Buffer.alloc(0));
    const response = await fetch(url, {
      method: "GET",
      redirect: "error",
      signal,
      headers: { ...this.headers(signed, accessToken), Accept: "text/event-stream" },
    });
    if (response.status === 401) throw new MobileApiError("Сессия истекла. Войдите снова.", 401, true);
    const contentType = response.headers.get("content-type") ?? "";
    if (!response.ok || !response.body || !contentType.toLowerCase().startsWith("text/event-stream")) {
      await response.body?.cancel().catch(() => {});
      throw new MobileApiError("Канал событий недоступен", response.status);
    }
    return response.body;
  }

  /** A one-time link that opens the website signed in to the same account. */
  webHandoff(accessToken: string, target: string): Promise<WebHandoffResponse> {
    return this.request("POST", "/api/mobile/v1/web-handoff", { target }, accessToken);
  }

  private headers(signed: SignedRequest, accessToken: string | null): Record<string, string> {
    return {
      Accept: "application/json",
      "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
      "User-Agent": `LevikVPN-Windows/${this.version}`,
      "X-Levik-App-Version": this.version,
      "X-Levik-Client": `windows/${this.version}`,
      "X-Levik-Device-Id": signed.deviceId,
      "X-Levik-Timestamp": String(signed.timestamp),
      "X-Levik-Nonce": signed.nonce,
      "X-Levik-Signature": signed.signature,
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    };
  }

  private async request<Response>(
    method: "GET" | "POST" | "PUT" | "DELETE",
    path: string,
    payload: Record<string, unknown> | null,
    accessToken: string | null,
    extraHeaders: Record<string, string> = {},
  ): Promise<Response> {
    let origin: URL;
    try { origin = await this.endpoints.resolve(); }
    catch { throw new MobileApiError("Не удалось связаться с Levik VPN"); }
    const url = new URL(path, origin);
    if (url.origin !== origin.origin) throw new Error("Cross-origin API request rejected");
    const hasBody = method === "POST" || method === "PUT";
    const body = hasBody ? Buffer.from(JSON.stringify(payload ?? {})) : Buffer.alloc(0);
    const signed = this.signer.sign(method, url.pathname, accessToken, body);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const requestInit: RequestInit = {
        method,
        redirect: "error",
        signal: controller.signal,
        headers: {
          ...this.headers(signed, accessToken),
          ...extraHeaders,
          ...(hasBody ? { "Content-Type": "application/json" } : {}),
        },
      };
      if (hasBody) requestInit.body = body;
      const response = await fetch(url, requestInit);
      const contentLength = Number(response.headers.get("content-length") ?? "0");
      if (contentLength > 4 * 1024 * 1024) throw new MobileApiError("Ответ API слишком большой", response.status);
      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.toLowerCase().includes("json")) {
        throw new MobileApiError("API вернул неожиданный формат", response.status);
      }
      const raw = await response.text();
      if (raw.length > 4 * 1024 * 1024) throw new MobileApiError("Ответ API слишком большой", response.status);
      let decoded: unknown;
      try {
        decoded = JSON.parse(raw);
      } catch {
        throw new MobileApiError("API вернул повреждённый JSON", response.status);
      }
      if (!response.ok) {
        const code = isRecord(decoded) && decoded.ok === false && isRecord(decoded.error) && typeof decoded.error.code === "string"
          ? decoded.error.code
          : `http_${response.status}`;
        throw new MobileApiError(
          apiErrorMessage(code),
          response.status,
          code === "unauthorized",
          code,
        );
      }
      if (!isRecord(decoded) || decoded.ok !== true) throw new MobileApiError("API отклонил ответ", response.status);
      return decoded as Response;
    } catch (error) {
      if (error instanceof MobileApiError) throw error;
      this.endpoints.invalidate();
      if ((error as Error).name === "AbortError") throw new MobileApiError("Превышено время ожидания сети");
      throw new MobileApiError("Не удалось связаться с Levik VPN");
    } finally {
      clearTimeout(timeout);
      body.fill(0);
    }
  }
}

export function isAuthenticationRejected(error: unknown): boolean {
  return error instanceof MobileApiError && error.authenticationRejected;
}

function apiErrorMessage(code: string): string {
  const known: Readonly<Record<string, string>> = {
    device_limit_reached: "Достигнут лимит устройств. Откройте управление подпиской и отвяжите старое устройство.",
    subscription_not_found: "Подписка не найдена",
    subscription_inactive: "Подписка неактивна или истекла",
    unauthorized: "Сессия истекла. Войдите снова.",
    invalid_activation_code: "Проверьте код активации",
    activation_not_found: "Код активации не найден или срок его действия истёк",
    rate_limited: "Слишком много попыток. Попробуйте позже.",
    app_update_required: "Обновите Levik VPN: эта версия приложения не поддерживает Levik Game.",
    drop_unavailable: "Передача файлов сейчас недоступна. Попробуйте позже.",
    subscription_required: "Для передачи файлов нужна активная подписка.",
    device_not_found: "Устройство не найдено в аккаунте.",
    device_not_ready: "Устройство сейчас не может принять файлы: откройте на нём Levik VPN.",
    device_busy: "Одно из устройств уже передаёт файлы. Дождитесь окончания.",
    quota_exceeded: "Дневной лимит передачи через сервер (20 ГБ) исчерпан. Он обновится завтра.",
    transfer_not_found: "Передача не найдена.",
    transfer_ended: "Передача уже завершена.",
    invalid_action: "Это действие сейчас недоступно.",
  };
  return known[code] ?? code;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
