import { app } from "electron";
import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { connect, createServer } from "node:net";
import { join } from "node:path";
import type { TuicEndpoint } from "../../shared/contracts";
import { TUIC_PLACEHOLDER_ID, TUIC_PLACEHOLDER_PORT } from "./xrayConfig";

export interface TuicLocalProxy {
  port: number;
  /** Per-session VLESS user id of the loopback hop. */
  id: string;
}

interface TuicSidecarEvents {
  log: [line: string];
  exit: [code: number | null];
}

const STARTUP_TIMEOUT_MS = 8_000;

/**
 * sing-box configuration for one session. The VLESS inbound is loopback-only
 * with a per-session user id and carries UDP inside its TCP stream, and the
 * TUIC outbound is bound to the physical interface so it never loops through
 * the Wintun adapter. Only the CA pinned by the Levik profile is trusted.
 */
export function buildTuicSidecarConfig(tuic: TuicEndpoint, proxy: TuicLocalProxy, interfaceName: string): Record<string, unknown> {
  return {
    log: { level: "warn", timestamp: false },
    inbounds: [{
      type: "vless", tag: "levik-tuic-in", listen: "127.0.0.1", listen_port: proxy.port,
      users: [{ uuid: proxy.id }],
    }],
    outbounds: [{
      type: "tuic", tag: "levik-tuic", server: tuic.address, server_port: tuic.port,
      uuid: tuic.uuid, password: tuic.password, congestion_control: tuic.congestionControl,
      udp_relay_mode: tuic.udpRelayMode, heartbeat: "10s", bind_interface: interfaceName,
      tls: { enabled: true, server_name: tuic.serverName, alpn: tuic.alpn, certificate: [tuic.caCertificatePem] },
    }],
    route: { final: "levik-tuic" },
  };
}

/** Points the TUIC placeholder outbound at the running sidecar. */
export function withTuicProxy(config: Record<string, unknown>, proxy: TuicLocalProxy, tag?: string): Record<string, unknown> {
  const outbounds = Array.isArray(config.outbounds) ? [...config.outbounds] : [];
  const index = tag === undefined ? 0 : outbounds.findIndex((outbound: unknown) => isRecord(outbound) && outbound.tag === tag);
  const first: unknown = outbounds[index];
  const vnext = isRecord(first) && isRecord(first.settings) && Array.isArray(first.settings.vnext) ? first.settings.vnext : [];
  const [placeholder]: unknown[] = vnext;
  if (!isRecord(first) || first.protocol !== "vless" || vnext.length !== 1 || !isRecord(placeholder)
    || placeholder.address !== "127.0.0.1" || placeholder.port !== TUIC_PLACEHOLDER_PORT
    || !Array.isArray(placeholder.users) || !isRecord(placeholder.users[0]) || placeholder.users[0].id !== TUIC_PLACEHOLDER_ID) {
    throw new Error("Некорректный VPN-профиль TUIC");
  }
  outbounds[index] = {
    ...first,
    settings: { vnext: [{ address: "127.0.0.1", port: proxy.port, users: [{ id: proxy.id, encryption: "none" }] }] },
  };
  return { ...config, outbounds };
}

export class TuicSidecar extends EventEmitter<TuicSidecarEvents> {
  private child: ChildProcessWithoutNullStreams | null = null;
  private readonly stopping = new WeakSet<ChildProcess>();

  constructor(private readonly stopProcess: (child: ChildProcess) => Promise<void>) {
    super();
  }

  executablePath(): string {
    return app.isPackaged
      ? join(process.resourcesPath, "singbox", "sing-box.exe")
      : join(app.getAppPath(), "vendor", "singbox", "windows-x64", "sing-box.exe");
  }

  isRunning(): boolean {
    return this.child !== null;
  }

  async start(tuic: TuicEndpoint, interfaceName: string): Promise<TuicLocalProxy> {
    await this.stop();
    const proxy: TuicLocalProxy = { port: await freeLoopbackPort(), id: randomUUID() };
    await this.startConfig(buildTuicSidecarConfig(tuic, proxy, interfaceName), [proxy.port]);
    return proxy;
  }

  async startRoutes(routes: Array<{ tag: string; endpoint: TuicEndpoint }>, interfaceName: string): Promise<Map<string, TuicLocalProxy>> {
    await this.stop();
    const proxies = new Map<string, TuicLocalProxy>();
    const inbounds: unknown[] = [];
    const outbounds: unknown[] = [];
    const rules: unknown[] = [];
    for (const { tag, endpoint } of routes) {
      const proxy = { port: await freeLoopbackPort(), id: randomUUID() };
      const config = buildTuicSidecarConfig(endpoint, proxy, interfaceName);
      const inbound = (config.inbounds as Record<string, unknown>[])[0]!;
      const outbound = (config.outbounds as Record<string, unknown>[])[0]!;
      inbounds.push({ ...inbound, tag: `${tag}-in` });
      outbounds.push({ ...outbound, tag });
      rules.push({ inbound: [`${tag}-in`], action: "route", outbound: tag });
      proxies.set(tag, proxy);
    }
    await this.startConfig({ log: { level: "warn", timestamp: false }, inbounds, outbounds, route: { rules } }, [...proxies.values()].map((proxy) => proxy.port));
    return proxies;
  }

  private async startConfig(value: Record<string, unknown>, ports: number[]): Promise<void> {
    const config = Buffer.from(JSON.stringify(value), "utf8");
    // The configuration carries credentials; pass it on stdin, never through a file.
    const child = spawn(this.executablePath(), ["run", "-c", "stdin", "--disable-color"], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    const emitLines = (chunk: Buffer): void => {
      chunk.toString("utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
        .forEach((line) => this.emit("log", `TUIC: ${line.replace(/[\u0000-\u001f]/g, "")}`));
    };
    child.stdout.on("data", emitLines);
    child.stderr.on("data", emitLines);
    child.once("error", (error) => this.emit("log", `TUIC: ${error.message}`));
    child.once("exit", (code) => {
      if (this.child === child) this.child = null;
      if (!this.stopping.has(child)) this.emit("exit", code);
    });
    try {
      child.stdin.end(config);
      await Promise.all(ports.map((port) => waitForLoopbackPort(port, child)));
    } catch (error) {
      await this.stop();
      throw error;
    } finally {
      config.fill(0);
    }
  }

  async stop(): Promise<void> {
    const child = this.child;
    if (!child) return;
    this.stopping.add(child);
    this.child = null;
    await this.stopProcess(child);
  }
}

async function freeLoopbackPort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === "object") resolve(address.port);
        else reject(new Error("Не удалось выделить локальный порт"));
      });
    });
  });
}

async function waitForLoopbackPort(port: number, child: ChildProcess): Promise<void> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Ядро TUIC завершилось при запуске");
    const accepted = await new Promise<boolean>((resolve) => {
      const socket = connect({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); resolve(true); });
      socket.once("error", () => { socket.destroy(); resolve(false); });
    });
    if (accepted) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Ядро TUIC не запустилось");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
