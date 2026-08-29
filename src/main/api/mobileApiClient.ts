import type {
  AuthChallengeResponse,
  AuthStatusResponse,
  MobileAccountResponse,
  TunnelProfileResponse,
} from "./models";
import { RequestSigner } from "../security/requestSigner";

export class MobileApiError extends Error {
  constructor(message: string, readonly status: number | null = null) {
    super(message);
  }
}

export class MobileApiClient {
  private readonly origin: URL;

  constructor(
    baseUrl: string,
    private readonly signer: RequestSigner,
    private readonly version: string,
  ) {
    this.origin = new URL(baseUrl);
    if (this.origin.protocol !== "https:" || this.origin.pathname !== "/") {
      throw new Error("Mobile API origin must be an HTTPS origin without a path");
    }
  }

  createChallenge(payload: Record<string, unknown>): Promise<AuthChallengeResponse> {
    return this.request("POST", "/api/mobile/v1/auth/challenge", payload, null);
  }

  pollStatus(loginToken: string): Promise<AuthStatusResponse> {
    return this.request("POST", "/api/mobile/v1/auth/status", { loginToken }, null);
  }

  account(accessToken: string): Promise<MobileAccountResponse> {
    return this.request("GET", "/api/mobile/v1/account", null, accessToken);
  }

  tunnelProfile(accessToken: string, subscriptionId: string): Promise<TunnelProfileResponse> {
    return this.request("POST", "/api/mobile/v1/tunnel-profile", { subscriptionId }, accessToken);
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

  private async request<Response>(
    method: "GET" | "POST",
    path: string,
    payload: Record<string, unknown> | null,
    accessToken: string | null,
  ): Promise<Response> {
    const url = new URL(path, this.origin);
    if (url.origin !== this.origin.origin) throw new Error("Cross-origin API request rejected");
    const body = method === "POST" ? Buffer.from(JSON.stringify(payload ?? {})) : Buffer.alloc(0);
    const signed = this.signer.sign(method, url.pathname, accessToken, body);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const requestInit: RequestInit = {
        method,
        redirect: "error",
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
          "User-Agent": `LevikVPN-Windows/${this.version}`,
          "X-Levik-App-Version": this.version,
          "X-Levik-Device-Id": signed.deviceId,
          "X-Levik-Timestamp": String(signed.timestamp),
          "X-Levik-Nonce": signed.nonce,
          "X-Levik-Signature": signed.signature,
          ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
      };
      if (method === "POST") requestInit.body = body;
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
        const code = isRecord(decoded) && isRecord(decoded.error) && typeof decoded.error.code === "string"
          ? decoded.error.code
          : `http_${response.status}`;
        throw new MobileApiError(apiErrorMessage(code), response.status);
      }
      if (!isRecord(decoded) || decoded.ok !== true) throw new MobileApiError("API отклонил ответ", response.status);
      return decoded as Response;
    } catch (error) {
      if (error instanceof MobileApiError) throw error;
      if ((error as Error).name === "AbortError") throw new MobileApiError("Превышено время ожидания сети");
      throw new MobileApiError("Не удалось связаться с Levik VPN");
    } finally {
      clearTimeout(timeout);
      body.fill(0);
    }
  }
}

function apiErrorMessage(code: string): string {
  const known: Readonly<Record<string, string>> = {
    device_limit_reached: "Достигнут лимит устройств. Откройте управление подпиской и отвяжите старое устройство.",
    subscription_not_found: "Подписка не найдена",
    subscription_inactive: "Подписка неактивна или истекла",
    unauthorized: "Сессия истекла. Войдите снова.",
  };
  return known[code] ?? code;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
