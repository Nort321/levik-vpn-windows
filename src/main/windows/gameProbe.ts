import { execFile } from "node:child_process";
import { networkInterfaces } from "node:os";
import { promisify } from "node:util";
import { isIPv4 } from "node:net";
import type { GameMeasurement } from "../../shared/contracts";
import { windowsHelperPath } from "./helperPath";

const execute = promisify(execFile);
export const DIRECT_PROBE_SAMPLES = 5;
export const DIRECT_INTERFERENCE_MS = 3;
type Sample = { latencyMs: number | null; method: "icmp" | "ttl-hop"; approximate: boolean };

export function physicalGameSourceAddress(interfaceName: string | null): string | undefined {
  if (!interfaceName) return undefined;
  return networkInterfaces()[interfaceName]?.find((address) => address.family === "IPv4" && !address.internal)?.address;
}

/** No shell, DNS lookup, route mutation, process inspection, payload or destination logging. */
export async function measureDirectGameTargets(
  targets: Array<{ address: string; port: number }>, source: string, signal: AbortSignal,
  run: (address: string, ttl: number) => Promise<Sample> = async (address, ttl) => {
    const { stdout } = await execute(windowsHelperPath(), ["game-probe", source, address, String(ttl)], {
      signal, windowsHide: true, timeout: 2_000, maxBuffer: 4_096,
    });
    return parseDirectProbeSample(stdout);
  },
): Promise<Array<{ address: string; port: number; quality: GameMeasurement }>> {
  if (!isIPv4(source) || signal.aborted) return [];
  const measured = await Promise.all(targets.slice(0, 4).map(async (target): Promise<{ address: string; port: number; quality: GameMeasurement } | null> => {
    if (!isIPv4(target.address) || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535 || signal.aborted) return null;
    const samples: Sample[] = [];
    for (let index = 0; index < DIRECT_PROBE_SAMPLES && !signal.aborted; index++) {
      samples.push(await run(target.address, 30).catch((): Sample => ({ latencyMs: null, method: "icmp", approximate: false })));
    }
    // A silent game server may still have a responding final router. This is
    // a lower-bound estimate and is always marked approximate in the UI.
    if (samples.every((sample) => sample.latencyMs === null) && !signal.aborted) {
      let last: Sample | null = null;
      let lastTtl = 0;
      for (let ttl = 1; ttl <= 30 && !signal.aborted; ttl++) {
        const sample = await run(target.address, ttl).catch(() => null);
        if (sample?.latencyMs !== null && sample?.latencyMs !== undefined) { last = sample; lastTtl = ttl; }
        if (sample?.method === "icmp" && sample.latencyMs !== null) break;
      }
      if (last) {
        samples.length = 0; samples.push(last);
        for (let index = 1; index < DIRECT_PROBE_SAMPLES && !signal.aborted; index++) {
          samples.push(await run(target.address, lastTtl).catch((): Sample => ({ latencyMs: null, method: last!.method, approximate: last!.approximate })));
        }
      }
    }
    return signal.aborted ? null : { ...target, quality: summarizeDirectSamples(samples) };
  }));
  const results = measured.filter((result): result is NonNullable<typeof result> => result !== null);
  // The TUN can synthesize very fast ICMP echo replies. Echo targets all below
  // this threshold are interference evidence, never a winning direct route.
  // A TTL-exceeded reply comes from a real router (often the home one at 2-3 ms).
  const echoes = results.filter((result) => result.quality.method === "icmp" && result.quality.latencyMs !== null);
  if (echoes.length && echoes.every((result) => result.quality.latencyMs! < DIRECT_INTERFERENCE_MS)) {
    return results.map((result) => result.quality.method !== "icmp" ? result : ({ ...result, quality: { ...result.quality, latencyMs: null, p95Ms: null,
      jitterMs: null, lossPercent: 100, method: "unknown", approximate: true } }));
  }
  return results;
}

export function parseDirectProbeSample(text: string): Sample {
  if (text.length > 4_096) throw new Error("Некорректный ответ службы замеров");
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || !("latencyMs" in value) || !("method" in value)
    || !("approximate" in value) || (value.latencyMs !== null && (typeof value.latencyMs !== "number"
      || !Number.isFinite(value.latencyMs) || value.latencyMs < 0 || value.latencyMs > 60_000))
    || (value.method !== "icmp" && value.method !== "ttl-hop") || typeof value.approximate !== "boolean") {
    throw new Error("Некорректный ответ службы замеров");
  }
  return { latencyMs: value.latencyMs, method: value.method, approximate: value.method === "ttl-hop" || value.approximate };
}

export function summarizeDirectSamples(samples: readonly Sample[], now = Date.now()): GameMeasurement {
  const good = samples.flatMap((sample) => sample.latencyMs === null ? [] : [sample.latencyMs]).sort((a, b) => a - b);
  const percentile = (fraction: number): number | null => good.length ? good[Math.max(0, Math.ceil(good.length * fraction) - 1)]! : null;
  const mean = good.length ? good.reduce((total, value) => total + value, 0) / good.length : 0;
  return { latencyMs: percentile(.5), p95Ms: percentile(.95),
    jitterMs: good.length ? Math.round(Math.sqrt(good.reduce((total, value) => total + (value - mean) ** 2, 0) / good.length) * 10) / 10 : null,
    lossPercent: samples.length ? Math.round((samples.length - good.length) / samples.length * 1000) / 10 : 100,
    samples: samples.length, measuredAt: now,
    method: samples.some((sample) => sample.method === "ttl-hop" && sample.latencyMs !== null) ? "ttl-hop" : "icmp",
    approximate: samples.some((sample) => sample.approximate && sample.latencyMs !== null) };
}
