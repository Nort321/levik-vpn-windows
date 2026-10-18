import { request } from "node:http";
import { connect, type TLSSocket } from "node:tls";
import type { Socket } from "node:net";
import { probeErrorCode } from "../telemetry/codes";

export const TUNNEL_HEALTH_PORT = 47186;
export const TUNNEL_HEALTH_TAG = "levik-health";
// Xray opens its local listeners late when an antivirus scans it on start or
// the disk is slow; a refused connection then means "not yet", not "broken".
const STARTUP_LISTENER_WAIT_MS = 12_000;
const STARTUP_LISTENER_POLL_MS = 500;

// A local stats reply or successful upstream TCP accept does not prove that the
// VPN can carry traffic. Complete a verified TLS handshake through its outbound.
export async function isTunnelHealthy(options: {
  startup?: boolean;
  shouldContinue?: () => boolean;
  /** Receives the failure code of every probe when the tunnel is unhealthy. */
  onFailure?: ((codes: string[]) => void) | undefined;
} = {}): Promise<boolean> {
  const shouldContinue = options.shouldContinue ?? (() => true);
  const codes: string[] = [];
  const listenerDeadline = Date.now() + (options.startup ? STARTUP_LISTENER_WAIT_MS : 0);
  // Newly created Windows routes and upstream transports can settle later than
  // the local listener. Retry readiness once without restarting a viable core.
  for (let attempt = 0; attempt < (options.startup ? 2 : 1); attempt++) {
    if (attempt > 0) await sleep(1_000);
    for (const host of ["cloudflare-dns.com", "www.google.com"]) {
      if (!shouldContinue()) return false;
      let failure = await probeTunnel(host);
      while (failure === "no_vpn_network" && Date.now() < listenerDeadline) {
        await sleep(STARTUP_LISTENER_POLL_MS);
        if (!shouldContinue()) return false;
        failure = await probeTunnel(host);
      }
      if (failure === null) return shouldContinue();
      codes.push(failure);
    }
  }
  if (codes.length && shouldContinue()) options.onFailure?.(codes);
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

/** Resolves null when the tunnel works, otherwise a telemetry failure code. */
function probeTunnel(host: string): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;
    let tunnel: Socket | null = null;
    let tls: TLSSocket | null = null;
    const proxy = request({
      hostname: "127.0.0.1", port: TUNNEL_HEALTH_PORT,
      method: "CONNECT", path: `${host}:443`, agent: false,
    });
    const finish = (failure: string | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      tls?.destroy();
      tunnel?.destroy();
      proxy.destroy();
      resolve(failure);
    };
    // One deadline covers proxy establishment and TLS, including silent peers.
    const timeout = setTimeout(() => finish("timeout"), 6_000);
    // The local listener refusing means the core is not serving at all.
    proxy.once("error", (error) => finish(probeErrorCode(error) === "refused" ? "no_vpn_network" : probeErrorCode(error)));
    proxy.once("response", (response) => finish(`http_${response.statusCode ?? 0}`));
    proxy.once("connect", (response, socket, head) => {
      tunnel = socket;
      socket.once("error", (error) => finish(probeErrorCode(error)));
      socket.once("close", () => finish("reset"));
      if (settled || response.statusCode !== 200 || head.length !== 0) {
        socket.destroy();
        finish(response.statusCode === 200 ? "other" : `http_${response.statusCode ?? 0}`);
        return;
      }
      tls = connect({ socket, servername: host, rejectUnauthorized: true });
      tls.once("secureConnect", () => finish(null));
      tls.once("error", (error) => finish(probeErrorCode(error) === "other" ? "tls" : probeErrorCode(error)));
      tls.once("close", () => finish("reset"));
    });
    proxy.end();
  });
}

const TRAFFIC_CHECK_BYTES = 64 * 1024;
const TRAFFIC_CHECK_DEADLINE_MS = 8_000;
const TRAFFIC_CHECK_ROUNDS = 2;
const TRAFFIC_CHECK_RETRY_MS = 1_500;
const TRAFFIC_CHECK_TARGETS: ReadonlyArray<{ host: string; path: string }> = [
  { host: "speed.cloudflare.com", path: "/__down?bytes=131072" },
  { host: "cachefly.cachefly.net", path: "/100kb.test" },
];

/**
 * Smart Auto, docs/app-platform.md: a real download through the tunnel.
 * Operators that throttle a protocol often let the handshake and small
 * requests through and freeze the connection after about 16 KB, so the
 * handshake probe above says nothing about it.
 */
export async function carriesTraffic(shouldContinue: () => boolean = () => true): Promise<boolean> {
  for (let round = 0; round < TRAFFIC_CHECK_ROUNDS; round++) {
    if (round > 0) await sleep(TRAFFIC_CHECK_RETRY_MS);
    if (!shouldContinue()) return false;
    const results = TRAFFIC_CHECK_TARGETS.map((target) => downloadThroughTunnel(target.host, target.path));
    // The first success settles it; slower downloads finish by their own deadline.
    const passed = await new Promise<boolean>((resolve) => {
      let pending = results.length;
      for (const result of results) {
        void result.then((ok) => {
          pending -= 1;
          if (ok) resolve(true);
          else if (pending === 0) resolve(false);
        });
      }
    });
    if (passed) return true;
  }
  return false;
}

function downloadThroughTunnel(host: string, path: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    let tunnel: Socket | null = null;
    let tls: TLSSocket | null = null;
    let received = 0;
    let head = "";
    let status = 0;
    const proxy = request({
      hostname: "127.0.0.1", port: TUNNEL_HEALTH_PORT,
      method: "CONNECT", path: `${host}:443`, agent: false,
    });
    const finish = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      tls?.destroy();
      tunnel?.destroy();
      proxy.destroy();
      resolve(ok);
    };
    // A trickle that never reaches the size in time is a throttled tunnel.
    const timeout = setTimeout(() => finish(false), TRAFFIC_CHECK_DEADLINE_MS);
    proxy.once("error", () => finish(false));
    proxy.once("response", () => finish(false));
    proxy.once("connect", (response, socket) => {
      tunnel = socket;
      socket.once("error", () => finish(false));
      if (settled || response.statusCode !== 200) {
        socket.destroy();
        finish(false);
        return;
      }
      tls = connect({ socket, servername: host, rejectUnauthorized: true });
      tls.once("error", () => finish(false));
      tls.once("close", () => finish(received >= TRAFFIC_CHECK_BYTES && status === 200));
      tls.once("secureConnect", () => {
        // Compressed zeros would cross the tunnel as a few hundred bytes.
        tls?.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\nUser-Agent: LevikVPN\r\n\r\n`);
      });
      tls.on("data", (chunk: Buffer) => {
        if (!status) {
          head += chunk.toString("latin1", 0, Math.min(chunk.length, 64));
          const match = /^HTTP\/1\.[01] (\d{3})/.exec(head);
          if (match) status = Number(match[1]);
          else if (head.length >= 64) return finish(false);
          if (status && status !== 200) return finish(false);
        }
        received += chunk.length;
        if (status === 200 && received >= TRAFFIC_CHECK_BYTES) finish(true);
      });
    });
    proxy.end();
  });
}
