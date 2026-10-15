import type { ConnectionStatus, DiagnosisAction, DiagnosisSummary } from "../../shared/contracts";
import { parseMaintenance, type MaintenanceWindow } from "./maintenance";
import { parseAdvice, type ProtocolAdvice } from "./remoteConfig";

/**
 * "It's not the VPN, it's the internet", docs/app-platform.md "Diagnosis":
 * what the computer saw and what /api/app/v1/diagnose knows, folded into one
 * sentence and one button. The same tree as the Android app.
 */

export type ServiceState = "operational" | "degraded" | "outage" | "restricted" | "unknown";
export type OperatorSignal = "failing" | "working" | "unknown";

export interface DiagnoseService {
  slug: string;
  name: string;
  state: ServiceState;
  /** How the caller's operator reaches the service now. */
  operator: OperatorSignal;
}

export interface DiagnoseReport {
  network: { known: boolean; provider: string | null };
  whitelist: { status: string };
  services: DiagnoseService[];
  protocols: ProtocolAdvice | null;
  countries: { country: string; online: number; total: number }[];
  maintenance: MaintenanceWindow[];
}

export type LocalNetwork = "none" | "captive" | "ok";
export type VpnPhase = "off" | "connecting" | "connected" | "failed";

export interface DiagnosisInput {
  network: LocalNetwork;
  /** Desktops are never on a cellular whitelist themselves; kept for parity with the tree. */
  cellular: boolean;
  vpn: VpnPhase;
  serverCountry: string | null;
  serverNodeId: string | null;
  /** The current server's protocol as telemetry names it, such as hysteria2. */
  protocol: string | null;
  /** Services checked from the computer, by the monitor's slug, that did not answer. */
  failingServices: string[];
  anyServiceWorks: boolean;
  /** Null when Levik could not be reached. */
  report: DiagnoseReport | null;
  now: number;
}

export type Verdict =
  | "NO_NETWORK"
  | "CAPTIVE_PORTAL"
  | "INTERNET_DOWN"
  | "WHITELISTS"
  | "SERVER_DOWN"
  | "PROTOCOL"
  | "VPN_UNREACHABLE"
  | "VPN_PATH_BROKEN"
  | "SERVICE_DOWN_EVERYWHERE"
  | "SERVICE_RESTRICTED"
  | "SERVICE_OPERATOR"
  | "SERVICE_FAILS_DIRECT"
  | "SERVICE_VIA_VPN"
  | "ALL_OK_VPN_OFF"
  | "ALL_OK";

export interface DiagnosisVerdict {
  verdict: Verdict;
  action: DiagnosisAction | null;
  service?: string | undefined;
  provider?: string | undefined;
  country?: string | undefined;
  protocol?: string | undefined;
}

/** Checked from the computer: slugs from the website's monitor, with an address that answers quickly. */
export const DIAGNOSIS_SERVICES: readonly { slug: string; name: string; url: string }[] = [
  { slug: "telegram", name: "Telegram", url: "https://telegram.org/img/t_logo.svg" },
  { slug: "youtube", name: "YouTube", url: "https://www.youtube.com/generate_204" },
  { slug: "discord", name: "Discord", url: "https://discord.com/api/v10/gateway" },
  { slug: "github", name: "GitHub", url: "https://api.github.com/zen" },
];

const SERVICE_STATES: readonly ServiceState[] = ["operational", "degraded", "outage", "restricted", "unknown"];
const OPERATOR_SIGNALS: readonly OperatorSignal[] = ["failing", "working", "unknown"];
const SLUG = /^[a-z0-9-]{1,32}$/;
const COUNTRY = /^[A-Z]{2}$/;

export function parseDiagnoseReport(value: unknown): DiagnoseReport | null {
  if (!isRecord(value)) return null;
  const network = isRecord(value.network) ? value.network : {};
  const provider = typeof network.provider === "string" && network.provider.trim() && network.provider.length <= 120
    ? network.provider.trim()
    : null;
  const whitelist = isRecord(value.whitelist) && typeof value.whitelist.status === "string" ? value.whitelist.status : "unknown";
  const services = Array.isArray(value.services)
    ? value.services.slice(0, 64).flatMap((item): DiagnoseService[] => {
      if (!isRecord(item) || typeof item.slug !== "string" || !SLUG.test(item.slug)) return [];
      if (typeof item.name !== "string" || !item.name.trim() || item.name.length > 60) return [];
      return [{
        slug: item.slug,
        name: item.name.trim(),
        state: oneOf(item.state, SERVICE_STATES, "unknown"),
        operator: oneOf(item.operator, OPERATOR_SIGNALS, "unknown"),
      }];
    })
    : [];
  const countries = Array.isArray(value.countries)
    ? value.countries.slice(0, 100).flatMap((item) => {
      if (!isRecord(item) || typeof item.country !== "string" || !COUNTRY.test(item.country)) return [];
      if (!isCount(item.online) || !isCount(item.total) || item.online > item.total) return [];
      return [{ country: item.country, online: item.online, total: item.total }];
    })
    : [];
  return {
    network: { known: network.known === true && provider !== null, provider },
    whitelist: { status: whitelist },
    services,
    protocols: parseAdvice(value.protocols),
    countries,
    maintenance: parseMaintenance(value.maintenance),
  };
}

export function vpnPhase(status: ConnectionStatus): VpnPhase {
  switch (status) {
    case "connected":
      return "connected";
    case "connecting":
    case "reconnecting":
      return "connecting";
    case "error":
      return "failed";
    default:
      return "off";
  }
}

export function diagnosisVerdict(input: DiagnosisInput): DiagnosisVerdict {
  if (input.network === "none") return { verdict: "NO_NETWORK", action: "networkSettings" };
  if (input.network === "captive") return { verdict: "CAPTIVE_PORTAL", action: "networkSettings" };
  const { report } = input;
  if (!report && !input.anyServiceWorks) {
    return input.vpn === "connected"
      ? { verdict: "VPN_PATH_BROKEN", action: "bestServer" }
      : { verdict: "INTERNET_DOWN", action: "retry" };
  }
  const provider = report?.network.known ? report.network.provider ?? undefined : undefined;
  const vpnFailing = input.vpn === "connecting" || input.vpn === "failed" || (input.vpn === "connected" && !input.anyServiceWorks);
  if (vpnFailing) {
    if (report?.whitelist.status === "active" && input.cellular) return { verdict: "WHITELISTS", action: "servers", provider };
    if (report && serverDown(report, input)) {
      return { verdict: "SERVER_DOWN", action: "bestServer", country: input.serverCountry ?? undefined };
    }
    const better = betterProtocol(report?.protocols ?? null, input.protocol);
    if (better) return { verdict: "PROTOCOL", action: "bestServer", provider, protocol: better };
    return input.vpn === "connected"
      ? { verdict: "VPN_PATH_BROKEN", action: "bestServer" }
      : { verdict: "VPN_UNREACHABLE", action: "bestServer", country: input.serverCountry ?? undefined };
  }
  const failing = input.failingServices.map((slug) => report?.services.find((item) => item.slug === slug)
    ?? { slug, name: DIAGNOSIS_SERVICES.find((item) => item.slug === slug)?.name ?? slug, state: "unknown", operator: "unknown" });
  const down = failing.find((item) => item.state === "outage");
  if (down) return { verdict: "SERVICE_DOWN_EVERYWHERE", action: null, service: down.name };
  if (input.vpn === "off") {
    const restricted = failing.find((item) => item.state === "restricted");
    if (restricted) return { verdict: "SERVICE_RESTRICTED", action: "connect", service: restricted.name };
    const operator = provider ? failing.find((item) => item.operator === "failing") : undefined;
    if (operator) return { verdict: "SERVICE_OPERATOR", action: "connect", service: operator.name, provider };
    const first = failing[0];
    if (first) return { verdict: "SERVICE_FAILS_DIRECT", action: "connect", service: first.name };
    return { verdict: "ALL_OK_VPN_OFF", action: "connect" };
  }
  const first = failing[0];
  if (first) return { verdict: "SERVICE_VIA_VPN", action: "bestServer", service: first.name };
  return { verdict: "ALL_OK", action: "support" };
}

function serverDown(report: DiagnoseReport, input: DiagnosisInput): boolean {
  const nodeId = input.serverNodeId;
  if (nodeId && report.maintenance.some((item) => item.nodeId === nodeId && input.now >= item.startsAt && input.now < item.endsAt)) {
    return true;
  }
  const country = report.countries.find((item) => item.country === input.serverCountry);
  return country !== undefined && country.total > 0 && country.online === 0;
}

/** A protocol that works better on this operator than the current one, if the server knows. */
function betterProtocol(advice: ProtocolAdvice | null, current: string | null): string | null {
  if (!advice || !current) return null;
  const best = advice.preferred.find((item) => item !== current);
  if (!best) return null;
  return advice.avoid.includes(current) || !advice.preferred.includes(current) ? best : null;
}

const PROTOCOL_NAMES: Record<string, string> = {
  "vless-reality": "VLESS Reality",
  "vless-xhttp": "XHTTP",
  "vless-ws": "WebSocket",
  "vless-grpc": "gRPC",
  "vless-tcp": "VLESS",
  hysteria2: "Hysteria 2",
  tuic: "TUIC",
  trojan: "Trojan",
  shadowsocks: "Shadowsocks",
};

const ACTION_LABELS: Record<DiagnosisAction, string> = {
  retry: "Проверить снова",
  networkSettings: "Открыть настройки сети",
  connect: "Подключить VPN",
  bestServer: "Переключить на лучший сервер",
  servers: "Выбрать сервер",
  support: "Создать отчёт",
};

/** The sentence and the button; `networkSettings` is left out where the system has no such page. */
export function diagnosisSummary(
  result: DiagnosisVerdict,
  { networkSettings }: { networkSettings: boolean },
): DiagnosisSummary {
  const service = result.service ?? "Сервис";
  const protocol = result.protocol ? PROTOCOL_NAMES[result.protocol] ?? result.protocol : "";
  const country = result.country ? countryName(result.country) : null;
  const texts: Record<Verdict, string> = {
    NO_NETWORK: "Компьютер не подключён к сети. Проверьте Wi-Fi или кабель.",
    CAPTIVE_PORTAL: "Эта сеть просит сначала войти, как в кафе или отеле. Откройте любой сайт в браузере, войдите, затем подключите VPN.",
    INTERNET_DOWN: "Интернет не отвечает: проблема в сети или у провайдера, а не в VPN.",
    WHITELISTS: result.provider
      ? `${result.provider} включил белые списки в вашем регионе: обычные серверы недоступны. Выберите сервер «Мобильная сеть».`
      : "У оператора в вашем регионе включены белые списки: обычные серверы недоступны. Выберите сервер «Мобильная сеть».",
    SERVER_DOWN: country
      ? `Сервер в стране «${country}» сейчас недоступен. Переключитесь на другой.`
      : "Этот сервер сейчас недоступен. Переключитесь на другой.",
    PROTOCOL: result.provider
      ? `У ${result.provider} сейчас лучше работает ${protocol}.`
      : `В вашей сети сейчас лучше работает ${protocol}.`,
    VPN_UNREACHABLE: "Сервер VPN недоступен из вашей сети. Попробуйте лучший сервер.",
    VPN_PATH_BROKEN: "VPN подключён, но через этот сервер интернет не открывается. Переключитесь на другой.",
    SERVICE_DOWN_EVERYWHERE: `${service} сейчас не работает у всех — это не VPN.`,
    SERVICE_RESTRICTED: `${service} ограничен в России: через VPN он работает.`,
    SERVICE_OPERATOR: `${service} сейчас не работает у многих на ${result.provider ?? "вашем операторе"}: через VPN он работает.`,
    SERVICE_FAILS_DIRECT: `${service} не открывается без VPN. Включите VPN.`,
    SERVICE_VIA_VPN: `${service} у других работает, а через этот сервер — нет. Переключитесь на другой.`,
    ALL_OK_VPN_OFF: "Интернет работает. Если сайт не открывается, включите VPN.",
    ALL_OK: "Интернет и VPN работают. Если проблема осталась, создайте отчёт для поддержки.",
  };
  const action = result.action === "networkSettings" && !networkSettings ? null : result.action;
  return { verdict: result.verdict, text: texts[result.verdict], action, actionLabel: action ? ACTION_LABELS[action] : null };
}

function countryName(code: string): string {
  try {
    return new Intl.DisplayNames(["ru"], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

/** Each service from the computer, through whatever routing the system uses now. */
export async function checkServices(fetchImpl: Fetch, timeoutMs = 5_000): Promise<{ slug: string; ok: boolean }[]> {
  return Promise.all(DIAGNOSIS_SERVICES.map(async ({ slug, url }) => {
    try {
      const reply = await fetchImpl(url, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
      });
      // The answer itself does not matter; a block resets or times out.
      await reply.body?.cancel().catch(() => undefined);
      return { slug, ok: reply.status >= 200 && reply.status < 500 };
    } catch {
      return { slug, ok: false };
    }
  }));
}

/**
 * A network that sends its sign-in page instead of the system's check. Only
 * meaningful without the VPN: the tunnel would answer for the network.
 */
export async function captivePortal(
  fetchImpl: Fetch,
  probe: { url: string; expect: string },
  timeoutMs = 4_000,
): Promise<boolean> {
  try {
    const reply = await fetchImpl(probe.url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (reply.status >= 300 && reply.status < 400) return true;
    if (reply.status !== 200 && reply.status !== 204) return false;
    if (!probe.expect) return reply.status !== 204;
    const text = (await reply.text()).slice(0, 4_096);
    return !text.includes(probe.expect);
  } catch {
    // No answer is not a portal; the service checks tell the rest.
    return false;
  }
}

function oneOf<Value extends string>(value: unknown, allowed: readonly Value[], fallback: Value): Value {
  return allowed.find((item) => item === value) ?? fallback;
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 10_000;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
