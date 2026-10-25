/** Versioned ordinary-only policy; absent on legacy and white-list bypass profiles. */
export type ServiceRouteTarget = { kind: "default" | "direct" | "main" | "country" | "exit"; countryCode?: string; exitId?: string };
export type ServiceRouteFallback = { kind: "block" | "direct" | "main" | "country"; countryCode?: string };
export type ServiceRouteRule = { id: string; domains: string[]; route: ServiceRouteTarget; fallback: ServiceRouteFallback;
  source: "domain" | "service" | "category" | "preset"; label: string };
export type ServiceRouteExit = { exitId: string; name: string; countryCode: string; state: "enabled" | "draining" | "disabled";
  role: "ordinary"; endpoints: Array<{ address: string; port: number; protocol: string }> };
export type ServiceRoutePolicy = { version: 1; revision: number; fingerprint: string; rules: ServiceRouteRule[]; exits: ServiceRouteExit[] };
export type ServiceRouteSelection = { id: string; state: "active" | "fallback" | "blocked" | "unavailable"; exitId: string | null };
export type ServiceRouteStatus = { revision: number; fingerprint: string;
  state: "applied" | "pending" | "unavailable" | "unsupported" | "suspended" | "error";
  routes: ServiceRouteSelection[]; detail?: string };
