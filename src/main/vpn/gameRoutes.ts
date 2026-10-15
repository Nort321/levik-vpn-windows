import { createSocket } from "node:dgram";
import { Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { GameRouteQuality, TunnelServer } from "../../shared/contracts";

export const GAME_BALANCER = "levik-game";
export const GAME_BLOCK = "levik-game-block";
export const GAME_PROBE_PORT = 47210;
export const GAME_PROBE_USER = "levik-game";
export const gameTag = (index: number): string => `levik-game-route-${index}`;
export const gameProbeTag = (index: number): string => `levik-game-probe-${index}`;
const SAMPLE_COUNT = 8;
const SAMPLE_TIMEOUT_MS = 1_500;

export function summarizeGameSamples(samples: Array<number | null>, now = Date.now()): GameRouteQuality {
  const good = samples.filter((sample): sample is number => sample !== null && Number.isFinite(sample) && sample >= 0);
  const ordered = [...good].sort((a, b) => a - b);
  const median = ordered.length ? ordered[Math.floor(ordered.length / 2)]! : null;
  const jitter = good.length < 2 ? null : good.slice(1).reduce((sum, value, i) => sum + Math.abs(value - good[i]!), 0) / (good.length - 1);
  return {
    latencyMs: median === null ? null : Math.round(median),
    jitterMs: jitter === null ? null : Math.round(jitter),
    lossPercent: samples.length ? Math.round((samples.length - good.length) / samples.length * 100) : 100,
    samples: samples.length,
    measuredAt: now,
  };
}

/** Failures dominate a fast handshake; small timing differences do not favour TCP over native UDP. */
export function bestGameRoute(servers: TunnelServer[], quality: Record<string, GameRouteQuality>): TunnelServer | null {
  const score = (server: TunnelServer): number => {
    const q = quality[server.id];
    if (!q || q.latencyMs === null || q.lossPercent > 25 || q.samples < SAMPLE_COUNT) return Infinity;
    const tcpPenalty = ["hysteria", "tuic"].includes(String(server.outbound.protocol)) ? 0 : 5;
    return q.latencyMs + 2 * (q.jitterMs ?? 0) + 20 * q.lossPercent + tcpPenalty;
  };
  return servers.filter((server) => Number.isFinite(score(server)))
    .sort((a, b) => score(a) - score(b))[0] ?? null;
}

/** Measures real UDP DNS round trips through one authenticated, loopback SOCKS inbound.
 * These are control-point measurements, never presented as a game's match ping.
 */
export async function measureGameRoute(port: number, password: string, signal: AbortSignal): Promise<GameRouteQuality> {
  // Separate associations also prevent destination aliasing in UDP transports.
  const samples = await Promise.all([[1, 1, 1, 1], [8, 8, 8, 8]].map((address) => measureGameTarget(port, password, signal, address)));
  const quality = summarizeGameSamples(samples.flat());
  const jitter = samples.map((target) => summarizeGameSamples(target).jitterMs).filter((value): value is number => value !== null);
  return { ...quality, jitterMs: jitter.length ? Math.round(jitter.reduce((sum, value) => sum + value, 0) / jitter.length) : null };
}

async function measureGameTarget(port: number, password: string, signal: AbortSignal, address: number[]): Promise<Array<number | null>> {
  const count = SAMPLE_COUNT / 2;
  const samples: Array<number | null> = [];
  const tcp = new Socket();
  const udp = createSocket("udp4");
  let udpClosed = false;
  let buffer = Buffer.alloc(0);
  let wake: (() => void) | null = null;
  let failure = false;
  const fail = (): void => { failure = true; wake?.(); };
  tcp.on("data", (data: Buffer) => {
    buffer = Buffer.concat([buffer, data]);
    if (buffer.length > 1024) fail();
    wake?.();
  });
  tcp.on("error", fail);
  tcp.on("close", fail);
  udp.on("error", fail);
  udp.on("close", () => { udpClosed = true; });
  const stop = (): void => {
    fail();
    tcp.destroy();
    if (!udpClosed) { try { udp.close(); } catch { /* Never bound. */ } }
  };
  signal.addEventListener("abort", stop, { once: true });
  const deadline = setTimeout(stop, 4_000);
  const read = async (length: number): Promise<Buffer> => {
    while (buffer.length < length && !failure && !signal.aborted) {
      await new Promise<void>((resolve) => { wake = resolve; });
      wake = null;
    }
    if (failure || signal.aborted) throw new Error("Game probe unavailable");
    const result = buffer.subarray(0, length);
    buffer = buffer.subarray(length);
    return result;
  };
  try {
    if (signal.aborted) return Array<number | null>(count).fill(null);
    tcp.connect(port, "127.0.0.1");
    tcp.write(Buffer.from([5, 1, 2]));
    if (!(await read(2)).equals(Buffer.from([5, 2]))) throw new Error("SOCKS auth required");
    const user = Buffer.from(GAME_PROBE_USER);
    const pass = Buffer.from(password);
    tcp.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    if (!(await read(2)).equals(Buffer.from([1, 0]))) throw new Error("SOCKS auth failed");
    tcp.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
    const response = await read(10);
    if (response[0] !== 5 || response[1] !== 0 || response[3] !== 1) throw new Error("SOCKS UDP unavailable");
    const host = [...response.subarray(4, 8)].join(".");
    if (host !== "127.0.0.1" && host !== "0.0.0.0") throw new Error("Non-local SOCKS relay");
    const relayPort = response.readUInt16BE(8);
    if (!relayPort) throw new Error("Invalid SOCKS relay");
    await new Promise<void>((resolve, reject) => {
      const onError = (): void => reject(new Error("SOCKS UDP socket unavailable"));
      udp.once("error", onError);
      udp.once("close", onError);
      udp.connect(relayPort, "127.0.0.1", () => { udp.removeListener("error", onError); udp.removeListener("close", onError); resolve(); });
    });
    clearTimeout(deadline);
    // Warm the authenticated transport before measuring jitter; a QUIC/TLS
    // handshake is connection setup, not jitter of an established game flow.
    for (let index = -1; index < count && !signal.aborted && !failure; index++) {
      const id = randomBytes(2);
      const dns = Buffer.concat([id, Buffer.from("01000001000000000000076578616d706c6503636f6d0000010001", "hex")]);
      const packet = Buffer.concat([Buffer.from([0, 0, 0, 1, ...address, 0, 53]), dns]);
      const latency = await new Promise<number | null>((resolve) => {
        let settled = false;
        const started = performance.now();
        const finish = (value: number | null): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          udp.removeListener("message", onMessage);
          udp.removeListener("close", onClose);
          signal.removeEventListener("abort", onClose);
          resolve(value);
        };
        const onClose = (): void => finish(null);
        const onMessage = (data: Buffer): void => {
          if (data.length < 22 || data[2] !== 0 || data[3] !== 1 || data.readUInt16BE(8) !== 53
            || !data.subarray(4, 8).equals(Buffer.from(address)) || !data.subarray(10, 12).equals(id)
            || (data[12]! & 0x80) === 0 || (data[13]! & 15) !== 0) return;
          finish(performance.now() - started);
        };
        const timer = setTimeout(() => finish(null), SAMPLE_TIMEOUT_MS);
        udp.on("message", onMessage);
        udp.once("close", onClose);
        signal.addEventListener("abort", onClose, { once: true });
        udp.send(packet, (error) => { if (error) finish(null); });
      });
      if (index >= 0) samples.push(latency);
      if (!signal.aborted) await new Promise<void>((resolve) => setTimeout(resolve, 100));
    }
  } catch {
    // Failure is a measured unavailable route; no credentials or upstream details escape.
  } finally {
    clearTimeout(deadline);
    signal.removeEventListener("abort", stop);
    stop();
  }
  while (samples.length < count) samples.push(null);
  return samples;
}
