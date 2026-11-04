import type { CoreTally } from "../core/rustCore";

/**
 * The Rust core check in a connection report (docs/connection-telemetry.md,
 * "Rust core"): counters only, never inputs, answers or where they differed.
 */
export interface SessionCore {
  ver: string;
  mode: CoreTally["mode"];
  compared: number;
  differed: number;
  failed: number;
  decided: number;
  fn: Record<string, { differed: number; failed: number }>;
}

export const MAX_CORE_FUNCTIONS = 16;
const MAX_COUNT = 10_000_000;
const VERSION = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;
const FUNCTION = /^[a-z][A-Za-z0-9]{0,23}\.[a-z][A-Za-z0-9]{0,39}$/;

function count(value: number): number {
  return Number.isFinite(value) ? Math.min(MAX_COUNT, Math.max(0, Math.floor(value))) : 0;
}

/**
 * What happened between `baseline` (the tally at the previous session's final
 * report, or null) and `current`. A smaller counter means the app restarted in
 * between, so the current value counts whole. Null when there is nothing to send.
 */
export function coreReport(current: CoreTally | null, baseline: CoreTally | null): SessionCore | null {
  if (!current || !VERSION.test(current.version)) return null;
  const restarted = baseline !== null && (current.compared < baseline.compared || current.decided < baseline.decided
    || current.differed < baseline.differed || current.failed < baseline.failed);
  const base = restarted || baseline === null ? null : baseline;
  const since = (now: number, before: number | undefined) => count(now - (before ?? 0));
  const functions = Object.entries(current.functions)
    .filter(([name]) => FUNCTION.test(name))
    .map(([name, counts]) => {
      const before = base?.functions[name];
      return { name, differed: since(counts.differed, before?.differed), failed: since(counts.failed, before?.failed) };
    })
    .filter((entry) => entry.differed > 0 || entry.failed > 0)
    .sort((a, b) => b.differed + b.failed - (a.differed + a.failed) || (a.name < b.name ? -1 : 1))
    .slice(0, MAX_CORE_FUNCTIONS);
  return {
    ver: current.version,
    mode: current.mode,
    compared: since(current.compared, base?.compared),
    differed: since(current.differed, base?.differed),
    failed: since(current.failed, base?.failed),
    decided: since(current.decided, base?.decided),
    fn: Object.fromEntries(functions.map(({ name, differed, failed }) => [name, { differed, failed }])),
  };
}
