import type { AppSnapshot } from "../../shared/contracts";
import { protocolOf } from "../telemetry/codes";
import { redactLogLine } from "./diskLog";

export interface SupportReportContext {
  system: string;
  now: Date;
}

/**
 * The header of a support note: what support asks first, without the
 * account, subscription, device identifiers or addresses.
 */
export function supportReportText(snapshot: AppSnapshot, { system, now }: SupportReportContext): string {
  const { settings } = snapshot;
  const server = snapshot.servers.find((item) => item.id === snapshot.selectedServerId);
  const on = (enabled: boolean) => (enabled ? "вкл" : "выкл");
  const session = snapshot.sessionStartedAt
    ? `${Math.max(0, Math.round((now.getTime() - snapshot.sessionStartedAt) / 60_000))} мин`
    : "нет";
  return [
    `Levik VPN для Windows ${snapshot.appVersion}`,
    `Система: ${system}`,
    `Время: ${now.toISOString()}`,
    `Состояние: ${snapshot.status}${snapshot.statusDetail ? ` — ${redactLogLine(snapshot.statusDetail)}` : ""}`,
    `Сервер: ${server ? `${server.name} (${protocolOf(server)})` : "не выбран"}${settings.automaticServer ? ", автовыбор" : ""}`,
    `Текущее подключение: ${session}`,
    `Маршрутизация: ${settings.routingMode}; раздельное туннелирование: ${settings.splitTunnelMode}`,
    `Автовосстановление ${on(settings.autoReconnect)}, kill switch ${on(settings.killSwitch)}, защита DNS ${on(settings.preventDnsLeaks)}, DoH ${on(settings.useDoh)}, anti-DPI ${on(settings.antiDpiEnabled)}`,
  ].join("\n");
}
