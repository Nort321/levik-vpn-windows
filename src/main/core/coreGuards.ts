import { isDiagnosisAction, type AppAnnouncement, type DiagnosisSummary } from "../../shared/contracts";
import type { DiagnoseReport, DiagnosisVerdict, Verdict } from "../platform/diagnosis";
import type { MaintenanceMove, MaintenanceWindow } from "../platform/maintenance";
import type { ProtocolAdvice } from "../platform/remoteConfig";
import type { ProtocolHistory, RankedServer } from "../vpn/smartAuto";
import type { TunnelProfileOutcome } from "../vpn/tunnelProfile";
import type { CompiledServiceRoutes } from "../vpn/serviceRoutes";
import { isCanonicalNodeList } from "../platform/favoriteNodes";

/**
 * Shape checks for answers from the Rust core. In "rust" mode an answer is
 * used only when it passes; otherwise the TypeScript answers. The core is
 * ours, so these guard against a mismatched build, not against an attacker.
 */

const VERDICTS: readonly Verdict[] = [
  "NO_NETWORK", "CAPTIVE_PORTAL", "INTERNET_DOWN", "WHITELISTS", "SERVER_DOWN", "PROTOCOL", "VPN_UNREACHABLE",
  "VPN_PATH_BROKEN", "SERVICE_DOWN_EVERYWHERE", "SERVICE_RESTRICTED", "SERVICE_OPERATOR", "SERVICE_FAILS_DIRECT",
  "SERVICE_VIA_VPN", "ALL_OK_VPN_OFF", "ALL_OK",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === "string";
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isVerdictCode(value: unknown): value is Verdict {
  return typeof value === "string" && (VERDICTS as readonly string[]).includes(value);
}

export function isProtocolAdvice(value: unknown): value is ProtocolAdvice {
  return isRecord(value) && isStringList(value.preferred) && isStringList(value.avoid);
}

export function isProtocolAdviceOrNull(value: unknown): value is ProtocolAdvice | null {
  return value === null || isProtocolAdvice(value);
}

export function isMaintenanceWindow(value: unknown): value is MaintenanceWindow {
  return isRecord(value) && isString(value.nodeId) && isTime(value.startsAt) && isTime(value.endsAt);
}

export function isMaintenanceWindowOrNull(value: unknown): value is MaintenanceWindow | null {
  return value === null || isMaintenanceWindow(value);
}

export function isMaintenanceMove(value: unknown): value is MaintenanceMove {
  return value === "stay" || value === "when-idle" || value === "now";
}

/** Indices into a list of `length` items, each at most once, in order. */
export function isIndexList(length: number) {
  return (value: unknown): value is number[] => {
    if (!Array.isArray(value)) return false;
    let previous = -1;
    for (const item of value) {
      if (!isCount(item) || item >= length || item <= previous) return false;
      previous = item;
    }
    return true;
  };
}

export function isDiagnoseReportOrNull(value: unknown): value is DiagnoseReport | null {
  if (value === null) return true;
  if (!isRecord(value) || !isRecord(value.network) || !isRecord(value.whitelist)) return false;
  const { network, whitelist, services, protocols, countries, maintenance } = value;
  return typeof network.known === "boolean"
    && (network.provider === null || isString(network.provider))
    && isString(whitelist.status)
    && Array.isArray(services) && services.every((item) => isRecord(item) && isString(item.slug) && isString(item.name)
      && ["operational", "degraded", "outage", "restricted", "unknown"].includes(String(item.state))
      && ["failing", "working", "unknown"].includes(String(item.operator)))
    && isProtocolAdviceOrNull(protocols)
    && Array.isArray(countries) && countries.every((item) => isRecord(item) && isString(item.country) && isCount(item.online) && isCount(item.total))
    && Array.isArray(maintenance) && maintenance.every(isMaintenanceWindow);
}

export function isDiagnosisVerdict(value: unknown): value is DiagnosisVerdict {
  return isRecord(value)
    && isVerdictCode(value.verdict)
    && (value.action === null || isDiagnosisAction(value.action))
    && isOptionalString(value.service) && isOptionalString(value.provider)
    && isOptionalString(value.country) && isOptionalString(value.protocol);
}

export function isDiagnosisSummary(value: unknown): value is DiagnosisSummary {
  return isRecord(value)
    && isVerdictCode(value.verdict)
    && isString(value.text) && value.text.length > 0
    && (value.action === null || isDiagnosisAction(value.action))
    && (value.actionLabel === null || isString(value.actionLabel));
}

export function isAnnouncementList(value: unknown): value is AppAnnouncement[] {
  return Array.isArray(value) && value.every((item) => isRecord(item)
    && isString(item.id) && (item.level === "info" || item.level === "warning" || item.level === "critical")
    && isString(item.title) && isString(item.body) && (item.linkUrl === null || isString(item.linkUrl))
    && typeof item.notify === "boolean" && isTime(item.startsAt) && isTime(item.endsAt));
}

export function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

export function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isString);
}

export function isStringOrNull(value: unknown): value is string | null {
  return value === null || isString(value);
}

function isRankedServer(value: unknown): value is RankedServer {
  return isRecord(value) && isString(value.id) && isString(value.protocol) && typeof value.score === "number" && !Number.isNaN(value.score);
}

export function isRankedList(value: unknown): value is RankedServer[] {
  return Array.isArray(value) && value.every(isRankedServer);
}

export function isRankedServerOrNull(value: unknown): value is RankedServer | null {
  return value === null || isRankedServer(value);
}

export function isProtocolHistory(value: unknown): value is ProtocolHistory {
  if (!isRecord(value) || !Array.isArray(value.networks) || !isRecord(value.winners)) return false;
  return value.networks.every((network) => isRecord(network) && isString(network.key) && isRecord(network.protocols)
    && Object.values(network.protocols).every((record) => isRecord(record) && isStringList(record.failedNodes)
      && isTime(record.lastFailureAt) && isTime(record.lastSuccessAt)))
    && Object.values(value.winners).every(isString);
}

function isTunnelServer(value: unknown): boolean {
  return isRecord(value) && isString(value.id) && isString(value.tag) && isString(value.name) && isString(value.countryCode)
    && isRecord(value.outbound) && (value.tuic === undefined || isRecord(value.tuic)) && isOptionalString(value.nodeId);
}

export function isTunnelProfileOutcome(value: unknown): value is TunnelProfileOutcome {
  if (!isRecord(value)) return false;
  if ("refused" in value) return isString(value.refused) && Object.keys(value).length === 1;
  const profile = value.profile;
  if (!isRecord(profile) || Object.keys(value).length !== 1) return false;
  const game = profile.game;
  return isString(profile.profileId) && isString(profile.subscriptionId) && isStringOrNull(profile.subscriptionExpiresAt)
    && Array.isArray(profile.servers) && profile.servers.length > 0 && profile.servers.every(isTunnelServer)
    && isStringList(profile.directCidrs) && isStringList(profile.directDomains) && isStringList(profile.proxyDomains)
    && (profile.gameOnly === undefined || profile.gameOnly === true)
    && (profile.serviceRoutes === undefined || isRecord(profile.serviceRoutes))
    && isRecord(game) && typeof game.enabled === "boolean" && Array.isArray(game.servers) && game.servers.every(isTunnelServer)
    && (game.nodes === undefined || Array.isArray(game.nodes)) && isOptionalString(game.relayToken);
}

/** buildXrayConfig and the service routes it compiled. */
export interface XrayConfigAnswer {
  config: Record<string, unknown>;
  serviceRoutes: CompiledServiceRoutes | null;
}

function isCompiledServiceRoutes(value: unknown): value is CompiledServiceRoutes {
  return isRecord(value) && isRecord(value.policy) && Array.isArray(value.policy.rules) && Array.isArray(value.policy.exits)
    && isRecord(value.status) && isString(value.status.state) && Array.isArray(value.status.routes)
    && Array.isArray(value.plans) && value.plans.every((plan) => isRecord(plan) && isString(plan.id) && isString(plan.balancerTag)
      && isStringList(plan.primary) && isStringList(plan.fallback) && isString(plan.finalTag) && isRecord(plan.exits))
    && Array.isArray(value.probes) && value.probes.every((probe) => isRecord(probe) && isString(probe.tag) && isCount(probe.port))
    && (value.auth === undefined || (isRecord(value.auth) && isCount(value.auth.port) && isString(value.auth.user) && isString(value.auth.password)))
    && (value.resolvers === undefined || isStringList(value.resolvers))
    && (value.policyActive === undefined || typeof value.policyActive === "boolean")
    && (value.automatic === undefined || (isRecord(value.automatic) && isString(value.automatic.selectedId)
      && typeof value.automatic.enabled === "boolean" && Array.isArray(value.automatic.candidates)
      && value.automatic.candidates.every((candidate) => isRecord(candidate) && isString(candidate.id) && isString(candidate.tag)
        && isCount(candidate.port) && isString(candidate.routeKey) && isString(candidate.exitId))));
}

export function isXrayConfigAnswer(value: unknown): value is XrayConfigAnswer {
  if (!isRecord(value) || !isRecord(value.config)) return false;
  const { config } = value;
  return Array.isArray(config.inbounds) && config.inbounds.length > 0 && Array.isArray(config.outbounds) && config.outbounds.length > 0
    && isRecord(config.routing) && Array.isArray(config.routing.rules) && isRecord(config.dns)
    && (value.serviceRoutes === null || isCompiledServiceRoutes(value.serviceRoutes));
}

/** Distinct positions in a list of the given length. */
export function isListPositions(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.every((position) => isCount(position) && position < length)
    && new Set(value).size === value.length;
}

/** The account's node list and the local favourites after a reconcile. */
export interface FavoritesAnswer {
  nodes: string;
  local: string[];
}

/** A node list as the account stores it: canonical. */
export function isNodeListAnswer(value: unknown): value is string {
  return isString(value) && isCanonicalNodeList(value);
}

export function isFavoritesAnswer(value: unknown): value is FavoritesAnswer {
  return isRecord(value) && Object.keys(value).length === 2 && isNodeListAnswer(value.nodes)
    && isStringList(value.local) && new Set(value.local).size === value.local.length;
}
