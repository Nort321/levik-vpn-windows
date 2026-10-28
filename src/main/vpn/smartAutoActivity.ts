import { performance } from "node:perf_hooks";

export interface SmartAutoTrafficTotals { uplink: number; downlink: number }
export const SMART_AUTO_ACTIVITY = {
  sampleAgeMs: 5_000,
  burstWindowMs: 5_000,
  busyBytesPerSecond: 16 * 1024,
  burstBytes: 64 * 1024,
  quietBytesPerSecond: 4 * 1024,
  quietMs: 60_000,
} as const;

/** Aggregate TUN bytes only. Unknown/reset/stale counters never mean idle. */
export class SmartAutoActivity {
  private previous: (SmartAutoTrafficTotals & { at: number }) | null = null;
  private quietSince: number | null = null;
  private readonly window: Array<{ at: number; bytes: number }> = [];

  constructor(private readonly clock: () => number = performance.now.bind(performance)) {}

  reset(): void { this.previous = null; this.quietSince = null; this.window.length = 0; }

  observe(totals: SmartAutoTrafficTotals, atMs = this.clock()): void {
    if (!Number.isFinite(atMs) || atMs < 0 || !Number.isSafeInteger(totals.uplink) || totals.uplink < 0
      || !Number.isSafeInteger(totals.downlink) || totals.downlink < 0) { this.reset(); return; }
    const previous = this.previous;
    this.previous = { uplink: totals.uplink, downlink: totals.downlink, at: atMs };
    if (!previous || atMs <= previous.at || atMs - previous.at > SMART_AUTO_ACTIVITY.sampleAgeMs
      || totals.uplink < previous.uplink || totals.downlink < previous.downlink) {
      this.quietSince = null; this.window.length = 0;
      return;
    }
    const bytes = totals.uplink - previous.uplink + totals.downlink - previous.downlink;
    if (!Number.isSafeInteger(bytes)) { this.reset(); return; }
    const rate = bytes * 1000 / (atMs - previous.at);
    this.window.push({ at: atMs, bytes });
    while (this.window[0] && this.window[0].at <= atMs - SMART_AUTO_ACTIVITY.burstWindowMs) this.window.shift();
    // A bounded number of entries also protects against a pathological zero-delay sampler.
    if (this.window.length > 256) { this.quietSince = null; this.window.length = 0; return; }
    const burst = this.window.reduce((sum, sample) => sum + sample.bytes, 0);
    if (rate >= SMART_AUTO_ACTIVITY.busyBytesPerSecond || burst >= SMART_AUTO_ACTIVITY.burstBytes
      || rate >= SMART_AUTO_ACTIVITY.quietBytesPerSecond) this.quietSince = null;
    else this.quietSince ??= previous.at;
  }

  canSwitch(atMs = this.clock()): boolean {
    const latest = this.previous;
    return latest !== null && this.quietSince !== null && Number.isFinite(atMs) && atMs >= latest.at
      && atMs - latest.at <= SMART_AUTO_ACTIVITY.sampleAgeMs && atMs - this.quietSince >= SMART_AUTO_ACTIVITY.quietMs;
  }
}
