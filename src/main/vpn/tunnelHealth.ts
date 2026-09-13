import { request } from "node:http";
import { connect, type TLSSocket } from "node:tls";
import type { Socket } from "node:net";

export const TUNNEL_HEALTH_PORT = 47186;
export const TUNNEL_HEALTH_TAG = "levik-health";

// A local stats reply or successful upstream TCP accept does not prove that the
// VPN can carry traffic. Complete a verified TLS handshake through its outbound.
export async function isTunnelHealthy(): Promise<boolean> {
  for (const host of ["cloudflare-dns.com", "www.google.com"]) {
    if (await probeTunnel(host)) return true;
  }
  return false;
}

function probeTunnel(host: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    let tunnel: Socket | null = null;
    let tls: TLSSocket | null = null;
    const proxy = request({
      hostname: "127.0.0.1", port: TUNNEL_HEALTH_PORT,
      method: "CONNECT", path: `${host}:443`, agent: false,
    });
    const finish = (healthy: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      tls?.destroy();
      tunnel?.destroy();
      proxy.destroy();
      resolve(healthy);
    };
    // One deadline covers proxy establishment and TLS, including silent peers.
    const timeout = setTimeout(() => finish(false), 6_000);
    proxy.once("error", () => finish(false));
    proxy.once("response", () => finish(false));
    proxy.once("connect", (response, socket, head) => {
      tunnel = socket;
      socket.once("error", () => finish(false));
      socket.once("close", () => finish(false));
      if (settled || response.statusCode !== 200 || head.length !== 0) {
        socket.destroy();
        finish(false);
        return;
      }
      tls = connect({ socket, servername: host, rejectUnauthorized: true });
      tls.once("secureConnect", () => finish(true));
      tls.once("error", () => finish(false));
      tls.once("close", () => finish(false));
    });
    proxy.end();
  });
}
