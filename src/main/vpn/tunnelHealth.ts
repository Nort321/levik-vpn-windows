import { request } from "node:http";
import { connect, type TLSSocket } from "node:tls";
import type { Socket } from "node:net";
import { probeErrorCode } from "../telemetry/codes";

export const TUNNEL_HEALTH_PORT = 47186;
export const TUNNEL_HEALTH_TAG = "levik-health";

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
  // Newly created Windows routes and upstream transports can settle later than
  // the local listener. Retry readiness once without restarting a viable core.
  for (let attempt = 0; attempt < (options.startup ? 2 : 1); attempt++) {
    if (attempt > 0) await new Promise<void>((resolve) => setTimeout(resolve, 1_000));
    for (const host of ["cloudflare-dns.com", "www.google.com"]) {
      if (!shouldContinue()) return false;
      const failure = await probeTunnel(host);
      if (failure === null) return shouldContinue();
      codes.push(failure);
    }
  }
  if (codes.length && shouldContinue()) options.onFailure?.(codes);
  return false;
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
