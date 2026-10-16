import { createSocket } from "node:dgram";
import { Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { openRelayPath } from "./multipath/socks";
import { decode, encode, Kind } from "./multipath/wire";
import { GAME_POLICY } from "./gameEngine";
import type { GameRouteQuality, TunnelServer } from "../../shared/contracts";

export const GAME_BALANCER = "levik-game";
export const GAME_BLOCK = "levik-game-block";
export const GAME_PROBE_PORT = 48000;
export const GAME_DATA_PROBE_PORT = 47280;
export const GAME_DATA_PROBE_TAG = "levik-game-data-check";
export const GAME_DIRECT_PORT = 47279;
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

/** Packet loss is penalized; equal-loss routes compete on measured RTT without protocol bias. */
export function bestGameRoute(servers: TunnelServer[], quality: Record<string, GameRouteQuality>): TunnelServer | null {
  const score = (server: TunnelServer): number => {
    const q = quality[server.id];
    if (!q || q.latencyMs === null || q.lossPercent > 25 || q.samples < SAMPLE_COUNT) return Infinity;
    return q.latencyMs + GAME_POLICY.jitterWeight * (q.jitterMs ?? 0) + GAME_POLICY.lossWeightMs * q.lossPercent;
  };
  return servers.filter((server) => Number.isFinite(score(server)))
    .sort((a, b) => score(a) - score(b) || (quality[a.id]?.jitterMs ?? Infinity) - (quality[b.id]?.jitterMs ?? Infinity))[0] ?? null;
}

/** A is an authenticated echo to the relay, not an arbitrary public resolver. */
export async function measureGameRoute(port: number, password: string, signal: AbortSignal): Promise<GameRouteQuality> {
  const session = randomBytes(32); const samples: Array<number | null> = [];
  let settle: ((latency: number | null) => void) | null = null; let sentAt = 0; let sequence = 0;
  let path: Awaited<ReturnType<typeof openRelayPath>> | null = null;
  try {
    path = await openRelayPath(port, password, (data) => {
      const packet = decode(data);
      if (packet?.kind === Kind.Pong && packet.sequence === sequence && packet.session.equals(session) && packet.payload.length === 16) settle?.(performance.now() - sentAt);
    }, signal);
    for (sequence = 0; sequence < SAMPLE_COUNT && !signal.aborted; sequence++) {
      samples.push(await new Promise<number | null>((resolve) => {
        const finish = (latency: number | null): void => { clearTimeout(timer); signal.removeEventListener("abort", aborted); settle = null; resolve(latency); };
        const aborted = (): void => finish(null);
        const timer = setTimeout(() => finish(null), SAMPLE_TIMEOUT_MS); settle = finish;
        signal.addEventListener("abort", aborted, { once: true }); sentAt = performance.now();
        path!.send(encode({ kind: Kind.Ping, path: 0, session, flow: Buffer.alloc(8), sequence, address: "0.0.0.0", port: 0, payload: Buffer.from([0]) }));
      }));
    }
  } catch { /* An unavailable echo is unknown A, never a successful match probe. */ }
  finally { path?.close(); }
  while (samples.length < SAMPLE_COUNT) samples.push(null);
  return summarizeGameSamples(samples);
}

/** Measures real UDP DNS round trips through one authenticated, loopback SOCKS inbound.
 * These are control-point measurements, never presented as a game's match ping.
 * It checks that UDP crosses the whole multipath chain to the Internet. Public resolvers
 * often drop large or padded queries (from some nodes 100% at 1000+ bytes) and rate-limit
 * per source, so plain queries are used and one answering resolver is enough: the result
 * is the better of the two targets. */
export async function measureGameDataRoute(port: number, password: string, signal: AbortSignal, payloadBytes = 0): Promise<GameRouteQuality> {
  // Separate associations also prevent destination aliasing in UDP transports.
  const samples = await Promise.all([[1, 1, 1, 1], [8, 8, 8, 8]].map((address) => measureGameTarget(port, password, signal, address, payloadBytes)));
  const [best] = samples.map((target) => summarizeGameSamples(target))
    .sort((a, b) => a.lossPercent - b.lossPercent || (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity));
  return best ?? summarizeGameSamples([]);
}

async function measureGameTarget(port: number, password: string, signal: AbortSignal, address: number[], payloadBytes: number): Promise<Array<number | null>> {
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
      const dns = gameDnsProbe(id, payloadBytes);
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

/** RFC 7830 EDNS padding tests transport payload size without synthetic game traffic. */
export function gameDnsProbe(id: Buffer, payloadBytes = 0): Buffer {
  const question = Buffer.concat([id, Buffer.from("01000001000000000000076578616d706c6503636f6d0000010001", "hex")]);
  if (!payloadBytes) return question;
  if (id.length !== 2 || payloadBytes < question.length + 15 || payloadBytes > 1472) throw new Error("Invalid probe size");
  question.writeUInt16BE(1, 10);
  const padding = payloadBytes - question.length - 15;
  const opt = Buffer.alloc(15 + padding);
  opt.writeUInt16BE(41, 1); opt.writeUInt16BE(1232, 3);
  opt.writeUInt16BE(4 + padding, 9); opt.writeUInt16BE(12, 11); opt.writeUInt16BE(padding, 13);
  return Buffer.concat([question, opt]);
}
