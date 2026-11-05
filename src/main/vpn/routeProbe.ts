import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { Agent, request, type ClientRequest } from "node:http";
import { createServer, Socket } from "node:net";
import { dirname } from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { performance } from "node:perf_hooks";
import { prepareMacProbeConfig } from "./routeProbeBootstrap";

/** A short, bounded sample, not a claim about sustained link capacity or ICMP loss. */
export interface RouteMeasurement {
  measuredAt: number;
  confidence: "measured" | "partial" | "failed";
  medianMs: number | null;
  jitterMs: number | null;
  failureRate: number;
  targets: number;
  samples: number;
  setupMs: number | null;
  downMbps: number | null;
  upMbps: number | null;
  /** A bounded body crossed the same live proxy path; absent for older/light observations. */
  dataVerified?: boolean;
}

export interface RouteProbeCandidate {
  id: string;
  /** Public route identity, independent of credentials; duplicates are measured once. */
  routeKey: string;
  tag: string;
  config: Record<string, unknown>;
  path?: readonly string[];
  exitId?: string;
  /** macOS helper pins endpoint DNS before creating the TUN; mirror it for the sidecar. */
  resolveEndpointsLocally?: boolean;
}

export const ROUTE_MEASUREMENT_TTL_MS = 2 * 60_000;
export const PARTIAL_ROUTE_TTL_MS = 10_000;
export const ROUTE_PROBE_LIMITS = {
  candidates: 12, parallel: 2, finalists: 3, samples: 3,
  deadlineMs: 24_000, requestMs: 2_500, coreMs: 3_000,
  latencyPhaseMs: 14_000,
  downloadBytes: 1024 * 1024, uploadBytes: 512 * 1024,
} as const;

export interface ProbeTargets {
  latency: readonly string[];
  download: string;
  upload: string;
}

/** Cloudflare's documented Speedtest API; a second provider keeps one edge from deciding latency. */
export const ROUTE_PROBE_TARGETS: ProbeTargets = {
  latency: ["https://speed.cloudflare.com/__down?bytes=0", "https://www.gstatic.com/generate_204"],
  download: `https://speed.cloudflare.com/__down?bytes=${ROUTE_PROBE_LIMITS.downloadBytes}`,
  upload: `https://speed.cloudflare.com/__up?bytes=${ROUTE_PROBE_LIMITS.uploadBytes}`,
};

export function measuredRouteUsable(value: RouteMeasurement | undefined, now: number): value is RouteMeasurement {
  return value !== undefined && now >= value.measuredAt
    && now - value.measuredAt < (value.confidence === "partial" ? PARTIAL_ROUTE_TTL_MS : ROUTE_MEASUREMENT_TTL_MS)
    && (value.confidence === "measured" || value.confidence === "partial")
    && value.medianMs !== null && Number.isFinite(value.medianMs) && value.medianMs >= 0
    && value.jitterMs !== null && Number.isFinite(value.jitterMs) && value.jitterMs >= 0
    && value.failureRate >= 0 && value.failureRate <= 0.2;
}

/** Compare only like-for-like end-to-end observations, never endpoint RTT against HTTPS RTT. */
export function rankMeasuredRoutes<T extends { id: string; resourceHeadroom?: number | null; routeDegraded?: boolean }>(
  candidates: readonly T[], measurements: Readonly<Record<string, RouteMeasurement>>, now: number,
): T[] {
  const measured = candidates.filter((candidate) => measuredRouteUsable(measurements[candidate.id], now));
  if (!measured.length) return [];
  const confirmed = measured.filter((candidate) => measurements[candidate.id]!.confidence === "measured");
  const partial = measured.filter((candidate) => measurements[candidate.id]!.confidence === "partial");
  const order = (group: T[]): T[] => {
    const bandwidth = group.filter((candidate) => positive(measurements[candidate.id]?.downMbps) && positive(measurements[candidate.id]?.upMbps));
    const bestDown = Math.max(...bandwidth.map((candidate) => measurements[candidate.id]!.downMbps!));
    const bestUp = Math.max(...bandwidth.map((candidate) => measurements[candidate.id]!.upMbps!));
    const balanced = (id: string): number => Math.min(measurements[id]!.downMbps! / bestDown, measurements[id]!.upMbps! / bestUp);
    const bestBalanced = bandwidth.length ? Math.max(...bandwidth.map((candidate) => balanced(candidate.id))) : 0;
    const nearBest = new Set(bandwidth.filter((candidate) => balanced(candidate.id) >= bestBalanced * 0.9).map((candidate) => candidate.id));
    return [...group].sort((left, right) => {
      const priority = (id: string): number => nearBest.has(id) ? 0 : bandwidth.some((candidate) => candidate.id === id) ? 1 : 2;
      const leftLatency = stableLatency(measurements[left.id]!), rightLatency = stableLatency(measurements[right.id]!);
      // Absolute buckets form a total order. Pairwise "within 3ms" comparisons
      // are not transitive and would make the winner depend on subscription order.
      return priority(left.id) - priority(right.id)
        || Math.floor(leftLatency / 5) - Math.floor(rightLatency / 5)
        || Number(left.routeDegraded ?? false) - Number(right.routeDegraded ?? false)
        || Number(left.resourceHeadroom == null) - Number(right.resourceHeadroom == null)
        || (right.resourceHeadroom ?? 0) - (left.resourceHeadroom ?? 0)
        || leftLatency - rightLatency
        || left.id.localeCompare(right.id);
    });
  };
  // Two-provider confirmation always outranks a short-lived partial result;
  // partial HTTP observations in turn outrank unrelated entry TCP handshakes.
  return [...order(confirmed), ...order(partial)];
}

function stableLatency(value: RouteMeasurement): number {
  return (value.medianMs ?? Infinity) + (value.jitterMs ?? 0) + value.failureRate * 1000;
}
function positive(value: number | null | undefined): value is number { return typeof value === "number" && Number.isFinite(value) && value > 0; }
function isRecord(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }

/** No TUN, DNS interception, API, process/domain bypass, or direct fallback. */
export function buildRouteProbeConfig(source: Record<string, unknown>, tag: string, port: number, password: string): Record<string, unknown> {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !/^[a-f0-9]{48}$/.test(password)) throw new Error("Invalid probe listener");
  const available = Array.isArray(source.outbounds) ? source.outbounds.filter(isRecord) : [];
  const selected = available.find((outbound) => outbound.tag === tag);
  if (!selected) throw new Error("Missing probe outbound");
  const required = new Set<string>();
  function include(outboundTag: string): void {
    if (required.has(outboundTag)) return;
    if (required.size > 8) throw new Error("Invalid probe dependencies");
    const outbound = available.find((item) => item.tag === outboundTag);
    if (!outbound) throw new Error("Missing probe dependency");
    required.add(outboundTag);
    if (isRecord(outbound.proxySettings) && typeof outbound.proxySettings.tag === "string") include(outbound.proxySettings.tag);
    const stream = isRecord(outbound.streamSettings) ? outbound.streamSettings : {};
    const sockopt = isRecord(stream.sockopt) ? stream.sockopt : {};
    if (typeof sockopt.dialerProxy === "string") include(sockopt.dialerProxy);
  }
  include(tag);
  const dns = isRecord(source.dns) ? { ...structuredClone(source.dns), tag: "levik-route-probe-dns" } : undefined;
  return {
    log: { loglevel: "none" },
    ...(dns ? { dns } : {}),
    inbounds: [{ tag: "levik-route-probe", listen: "127.0.0.1", port, protocol: "http", settings: { users: [{ user: "probe", pass: password }], allowTransparent: false } }],
    outbounds: available.filter((outbound) => required.has(String(outbound.tag))).map((outbound) => structuredClone(outbound)),
    routing: { domainStrategy: "AsIs", rules: [
      { type: "field", inboundTag: ["levik-route-probe"], outboundTag: tag },
      ...(dns ? [{ type: "field", inboundTag: ["levik-route-probe-dns"], outboundTag: tag }] : []),
    ] },
  };
}

export interface RouteProbeSession {
  latency(target: string): Promise<{ values: number[]; failed: number; setupMs: number; dataVerified?: boolean }>;
  transfer(target: string, direction: "down" | "up"): Promise<number | null>;
  close(): Promise<void>;
}

/** Exported separately for integration tests against the bundled, unprivileged core. */
export async function openRouteProbe(executable: string, candidate: RouteProbeCandidate, signal: AbortSignal): Promise<RouteProbeSession> {
  signal.throwIfAborted();
  const port = await unusedPort();
  signal.throwIfAborted();
  const password = randomBytes(24).toString("hex");
  const probeConfig = buildRouteProbeConfig(candidate.config, candidate.tag, port, password);
  if (candidate.resolveEndpointsLocally) await prepareMacProbeConfig(probeConfig, signal);
  signal.throwIfAborted();
  const config = Buffer.from(JSON.stringify(probeConfig));
  let child: ChildProcess | undefined;
  const agents = new Set<Agent>();
  let closed = false;
  let closing: Promise<void> | null = null;
  const close = (): Promise<void> => closing ??= (async () => {
    closed = true;
    signal.removeEventListener("abort", onAbort);
    for (const agent of agents) agent.destroy();
    agents.clear();
    if (child && child.exitCode === null && child.signalCode === null) {
      const processToStop = child;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => { processToStop.kill("SIGKILL"); resolve(); }, 800);
        processToStop.once("exit", () => { clearTimeout(timer); resolve(); });
        processToStop.kill();
      });
    }
  })();
  const onAbort = (): void => { void close(); };
  try {
    child = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], {
      windowsHide: true, stdio: ["pipe", "ignore", "ignore"], env: { ...process.env, XRAY_LOCATION_ASSET: dirname(executable) },
    });
    let coreFailed = false;
    child.once("error", () => { coreFailed = true; });
    child.once("exit", () => { coreFailed = true; });
    child.stdin?.on("error", () => { coreFailed = true; });
    child.stdin?.end(config, () => config.fill(0));
    signal.addEventListener("abort", onAbort, { once: true });
    const until = Date.now() + ROUTE_PROBE_LIMITS.coreMs;
    while (!await listening(port)) {
      signal.throwIfAborted();
      if (closed || coreFailed || Date.now() >= until) throw new Error("Probe core unavailable");
      await new Promise<void>((resolve) => setTimeout(resolve, 40));
    }
    return proxyProbeSession(port, { user: "probe", password }, signal, () => !closed && !coreFailed, agents, close);

  } catch {
    config.fill(0);
    await close();
    throw new Error("Route probe unavailable");
  }
}

/** The running core already owns the physical sockets; probes never create another core or TUN. */
export async function openExistingRouteProbe(port: number, auth: { user: string; password: string }, signal: AbortSignal,
  options: { verifyData?: boolean } = {}): Promise<RouteProbeSession> {
  signal.throwIfAborted();
  if (!Number.isInteger(port) || port < 47200 || port > 47231 || !/^[a-z0-9-]{1,32}$/.test(auth.user)
    || !/^[a-f0-9]{48}$/.test(auth.password)) throw new Error("Invalid live probe listener");
  const agents = new Set<Agent>(); let closed = false;
  const close = async (): Promise<void> => {
    closed = true; signal.removeEventListener("abort", onAbort);
    for (const agent of agents) agent.destroy(); agents.clear();
  };
  const onAbort = (): void => { void close(); };
  signal.addEventListener("abort", onAbort, { once: true });
  return proxyProbeSession(port, auth, signal, () => !closed, agents, close, options.verifyData !== false);
}

function proxyProbeSession(port: number, auth: { user: string; password: string }, signal: AbortSignal,
  available: () => boolean, agents: Set<Agent>, close: () => Promise<void>, verifyData = false): RouteProbeSession {
  const connect = async (target: string): Promise<{ agent: Agent; setupMs: number }> => {
    signal.throwIfAborted();
    if (!available()) throw new Error("Probe closed");
    const url = checkedTarget(target);
    const started = performance.now();
    const socket = await openTlsProxy(port, auth, url.hostname, signal);
    if (!available() || signal.aborted) { socket.destroy(); throw new Error("Probe cancelled"); }
    // This agent can only reuse verified TLS through the specified private
    // candidate proxy. It never opens a direct connection to the target.
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    agent.createConnection = () => socket;
    agents.add(agent);
    return { agent, setupMs: performance.now() - started };
  };
  return {
    async latency(target) {
      const url = checkedTarget(target);
      const verifyWarmup = verifyData && url.hostname === "speed.cloudflare.com" && url.pathname === "/__down";
      let connection: { agent: Agent; setupMs: number } | undefined;
      try {
        connection = await connect(target);
        const { agent, setupMs } = connection;
        const warm = new URL(target);
        if (verifyWarmup) warm.searchParams.set("bytes", "65536");
        // A small real body also catches protocols that pass handshakes and
        // freeze after 16KB. Steady latency excludes this warm-up and TLS.
        const verified = await exchange(agent, warm.href, "GET", 0, verifyWarmup ? 65536 : 4096, signal);
        if (!verified || verifyWarmup && verified.bytes !== 65536) throw new Error("Probe target unavailable");
        const values: number[] = []; let failed = 0;
        for (let index = 0; index < ROUTE_PROBE_LIMITS.samples; index++) {
          if (signal.aborted) break;
          const answer = await exchange(agent, target, "GET", 0, 4096, signal);
          if (answer) values.push(answer.firstByteMs); else if (!signal.aborted) failed++;
        }
        return { values, failed, setupMs, ...(verifyWarmup ? { dataVerified: true } : {}) };
      } catch {
        if (verifyWarmup && !signal.aborted) return { values: [], failed: 0, setupMs: connection?.setupMs ?? 0, dataVerified: false };
        throw new Error("Probe target unavailable");
      } finally {
        if (connection) { agents.delete(connection.agent); connection.agent.destroy(); }
      }
    },
    async transfer(target, direction) {
      const { agent } = await connect(target);
      try {
        const bytes = direction === "down" ? ROUTE_PROBE_LIMITS.downloadBytes : ROUTE_PROBE_LIMITS.uploadBytes;
        const answer = await exchange(agent, target, direction === "down" ? "GET" : "POST", direction === "up" ? bytes : 0, direction === "down" ? bytes : 4096, signal);
        if (!answer || direction === "down" && answer.bytes !== bytes) return null;
        return bytes * 8 / Math.max(answer.elapsedMs, 1) / 1000;
      } finally { agents.delete(agent); agent.destroy(); }
    }, close,
  };
}

function checkedTarget(target: string): URL {
  const url = new URL(target);
  if (url.protocol !== "https:" || url.port && url.port !== "443" || url.username || url.password) throw new Error("Invalid probe target");
  return url;
}

function openTlsProxy(port: number, auth: { user: string; password: string }, host: string, signal: AbortSignal): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    let tls: TLSSocket | null = null;
    let settled = false;
    const proxy = request({ host: "127.0.0.1", port, method: "CONNECT", path: `${host}:443`, agent: false,
      headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}` } });
    const finish = (error?: Error): void => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal.removeEventListener("abort", abort);
      if (error || !tls) { tls?.destroy(); proxy.destroy(); reject(new Error("Probe TLS unavailable")); }
      else resolve(tls);
    };
    const abort = (): void => finish(new Error("Cancelled"));
    const timer = setTimeout(() => finish(new Error("Timeout")), ROUTE_PROBE_LIMITS.requestMs);
    signal.addEventListener("abort", abort, { once: true });
    proxy.once("error", () => finish(new Error("Proxy unavailable")));
    proxy.once("response", () => finish(new Error("Proxy rejected")));
    proxy.once("connect", (response, socket, head) => {
      if (settled || response.statusCode !== 200) { socket.destroy(); finish(new Error("Proxy rejected")); return; }
      if (head.length) socket.unshift(head);
      tls = tlsConnect({ socket, servername: host, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
      tls.once("error", () => finish(new Error("TLS failed")));
      tls.once("secureConnect", () => finish());
    });
    proxy.end();
    if (signal.aborted) abort();
  });
}

interface Exchange { firstByteMs: number; elapsedMs: number; bytes: number }
function exchange(agent: Agent, target: string, method: "GET" | "POST", uploadBytes: number, maxBytes: number, signal: AbortSignal): Promise<Exchange | null> {
  const url = checkedTarget(target);
  return new Promise((resolve) => {
    const started = performance.now(); let bytes = 0; let firstByteMs = 0; let settled = false;
    let outgoing: ClientRequest | undefined;
    const finish = (ok: boolean): void => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal.removeEventListener("abort", abort);
      if (!ok) outgoing?.destroy();
      resolve(ok ? { firstByteMs, elapsedMs: performance.now() - started, bytes } : null);
    };
    const abort = (): void => finish(false);
    const timer = setTimeout(abort, ROUTE_PROBE_LIMITS.requestMs);
    signal.addEventListener("abort", abort, { once: true });
    outgoing = request({ host: url.hostname, port: 443, method, path: `${url.pathname}${url.search}`, agent,
      headers: { Host: url.hostname, "Accept-Encoding": "identity", "Cache-Control": "no-cache", ...(method === "POST" ? { "Content-Type": "application/octet-stream", "Content-Length": uploadBytes } : {}) } }, (response) => {
      firstByteMs = performance.now() - started;
      if (response.statusCode !== 200 && response.statusCode !== 204) { response.destroy(); finish(false); return; }
      response.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > maxBytes) finish(false); });
      response.once("error", () => finish(false));
      response.once("aborted", () => finish(false));
      response.once("end", () => finish(true));
    });
    outgoing.once("error", () => finish(false));
    if (signal.aborted) { abort(); return; }
    // Incompressible upload measures the VPN data path rather than compression.
    outgoing.end(uploadBytes ? randomBytes(uploadBytes) : undefined);
  });
}

function unusedPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer(); server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") { server.close(); reject(new Error("No probe port")); return; }
      server.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
}
function listening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket(); let done = false;
    const finish = (ok: boolean): void => { if (done) return; done = true; socket.destroy(); resolve(ok); };
    socket.setTimeout(100); socket.once("connect", () => finish(true)); socket.once("error", () => finish(false)); socket.once("timeout", () => finish(false));
    socket.connect(port, "127.0.0.1");
  });
}

export interface RouteProbeDependencies {
  open: (executable: string, candidate: RouteProbeCandidate, signal: AbortSignal) => Promise<RouteProbeSession>;
  now: () => number;
}

/** Cover independent entries/exits before another protocol of the same cascade. */
export function diverseProbeCandidates<T extends { routeKey: string; path?: readonly string[]; exitId?: string }>(candidates: readonly T[], limit: number): T[] {
  const remaining = [...new Map(candidates.map((candidate) => [candidate.routeKey, candidate])).values()];
  const chosen: T[] = [];
  const entries = new Set<string>(), exits = new Set<string>(), paths = new Set<string>();
  const entry = (candidate: T): string => candidate.path?.[0] ?? candidate.routeKey;
  const exit = (candidate: T): string => candidate.exitId ?? candidate.path?.at(-1) ?? candidate.routeKey;
  const path = (candidate: T): string => candidate.path?.join("|") ?? candidate.routeKey;
  while (remaining.length && chosen.length < limit) {
    const novelty = (candidate: T): number => (entries.has(entry(candidate)) ? 0 : 4) + (exits.has(exit(candidate)) ? 0 : 2) + (paths.has(path(candidate)) ? 0 : 1);
    let at = 0;
    for (let index = 1; index < remaining.length; index++) if (novelty(remaining[index]!) > novelty(remaining[at]!)) at = index;
    const candidate = remaining.splice(at, 1)[0]!;
    chosen.push(candidate); entries.add(entry(candidate)); exits.add(exit(candidate)); paths.add(path(candidate));
  }
  return chosen;
}

export async function measureRouteCandidates(options: {
  executable: string; candidates: readonly RouteProbeCandidate[]; signal?: AbortSignal; targets?: ProbeTargets; transfers?: boolean;
  canTransfer?: () => boolean;
}, dependencies: RouteProbeDependencies = { open: openRouteProbe, now: Date.now }): Promise<Record<string, RouteMeasurement>> {
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(abort, ROUTE_PROBE_LIMITS.deadlineMs);
  const signal = controller.signal, targets = options.targets ?? ROUTE_PROBE_TARGETS;
  const unique = diverseProbeCandidates(options.candidates, ROUTE_PROBE_LIMITS.candidates);
  const results: Record<string, RouteMeasurement> = {};
  const latencyController = new AbortController();
  const stopLatency = (): void => latencyController.abort();
  signal.addEventListener("abort", stopLatency, { once: true });
  if (signal.aborted) stopLatency();
  const latencyTimer = setTimeout(stopLatency, ROUTE_PROBE_LIMITS.latencyPhaseMs);
  const latencySignal = latencyController.signal;
  const candidateBudgetMs = Math.floor((ROUTE_PROBE_LIMITS.latencyPhaseMs - 1000) / Math.max(1, Math.ceil(unique.length / ROUTE_PROBE_LIMITS.parallel)));
  let next = 0;
  try {
    await Promise.all(Array.from({ length: Math.min(unique.length, ROUTE_PROBE_LIMITS.parallel) }, async () => {
      while (!latencySignal.aborted) {
        const candidate = unique[next++]; if (!candidate) return;
        // Allocate every route a share of the phase before probing. An early
        // blackholed entry cannot hold both workers until later routes starve.
        const candidateController = new AbortController();
        const abortCandidate = (): void => candidateController.abort();
        latencySignal.addEventListener("abort", abortCandidate, { once: true });
        if (latencySignal.aborted) abortCandidate();
        const candidateTimer = setTimeout(abortCandidate, candidateBudgetMs);
        const candidateSignal = candidateController.signal;
        let session: RouteProbeSession | undefined;
        const values: number[] = []; const setups: number[] = []; let failed = 0; let answeredTargets = 0; let confirmedTargets = 0;
        let dataVerified: boolean | undefined;
        try {
          session = await dependencies.open(options.executable, candidate, candidateSignal);
          for (const target of targets.latency.slice(0, 2)) {
            if (candidateSignal.aborted) break;
            try {
              const answer = await session.latency(target);
              values.push(...answer.values); setups.push(answer.setupMs); failed += answer.failed;
              if (answer.dataVerified !== undefined) dataVerified = answer.dataVerified;
              if (answer.values.length) answeredTargets++;
              if (answer.values.length >= 2) confirmedTargets++;
            } catch { /* A provider outage reduces confidence, not a fabricated packet-loss sample. */ }
          }
        } catch { failed += ROUTE_PROBE_LIMITS.samples * 2; }
        finally { clearTimeout(candidateTimer); latencySignal.removeEventListener("abort", abortCandidate); await session?.close(); }
        if (latencySignal.aborted) return;
        const ordered = [...values].sort((a, b) => a - b);
        const median = ordered.length ? ordered[Math.floor(ordered.length / 2)]! : null;
        const deviations = median === null ? [] : ordered.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
        results[candidate.id] = {
          measuredAt: dependencies.now(), confidence: confirmedTargets >= 2 && values.length >= 4 ? "measured" : values.length ? "partial" : "failed",
          medianMs: median, jitterMs: deviations.length ? deviations[Math.floor(deviations.length / 2)]! : null,
          failureRate: failed / Math.max(1, values.length + failed), targets: answeredTargets, samples: values.length,
          setupMs: setups.length ? Math.max(...setups) : null, downMbps: null, upMbps: null,
          ...(dataVerified !== undefined ? { dataVerified } : {}),
        };
      }
    }));
    // Transfers are deliberately sequential, so candidates cannot congest each other.
    clearTimeout(latencyTimer);
    signal.removeEventListener("abort", stopLatency);
    const finalists = options.transfers === false ? [] : diverseProbeCandidates(rankMeasuredRoutes(unique, results, dependencies.now()), ROUTE_PROBE_LIMITS.finalists);
    for (const candidate of finalists) {
      if (signal.aborted || options.canTransfer && !options.canTransfer()) break;
      let session: RouteProbeSession | undefined;
      try {
        session = await dependencies.open(options.executable, candidate, signal);
        const measurement = results[candidate.id]!;
        measurement.downMbps = await session.transfer(targets.download, "down").catch(() => null);
        if (!signal.aborted && (!options.canTransfer || options.canTransfer())) measurement.upMbps = await session.transfer(targets.upload, "up").catch(() => null);
      } catch { /* Missing transfer evidence stays unknown; latency evidence remains valid. */ }
      finally { await session?.close(); }
    }
    // An alias of the exact same protocol/route reuses the observation, never its endpoint ping.
    for (const candidate of options.candidates) {
      const canonical = unique.find((item) => item.routeKey === candidate.routeKey);
      if (canonical && results[canonical.id]) results[candidate.id] = results[canonical.id]!;
    }
    return options.signal?.aborted ? {} : results;
  } finally {
    clearTimeout(timer); clearTimeout(latencyTimer); signal.removeEventListener("abort", stopLatency); options.signal?.removeEventListener("abort", abort);
  }
}
