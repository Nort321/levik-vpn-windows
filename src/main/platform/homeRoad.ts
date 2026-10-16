import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { connect as netConnect, createServer, type Socket } from "node:net";
import { networkInterfaces } from "node:os";

import type { RoadExitStatus, RoadMode } from "../../shared/contracts";

/**
 * «Дорога домой», docs/app-platform.md "Home road": this computer is a home
 * exit of the account. A second, local-only Xray accepts the VLESS streams of
 * the devices the owner allowed; the connector keeps a control WebSocket to
 * the Levik relay and, for each device connection the relay announces, opens
 * a data WebSocket and joins it to that Xray. The relay only joins the two
 * WebSockets; it does not look into the streams.
 */

export interface RoadExitConfig {
  exitId: string;
  name: string;
  mode: RoadMode;
  lanAccess: boolean;
  vlessUuid: string;
  /** wss://…/road/x/<token>; data connections append "/<id>". */
  controlUrl: string;
  expiresAt: string;
}

const EXIT_ID = /^[A-Za-z0-9_-]{22}$/;
const STREAM_ID = /^[A-Za-z0-9_-]{8,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_STREAMS = 512;
/** A device stream waits this long for the local Xray. */
const LOCAL_CONNECT_MS = 5_000;
const HIGH_WATER = 4 * 1024 * 1024;
const RETRY_DELAYS_MS = [2_000, 5_000, 15_000, 30_000, 60_000];

/** The website's answer; anything unexpected turns the exit off rather than half on. */
export function parseRoadExit(value: unknown, websiteHosts?: ReadonlySet<string>): RoadExitConfig | null {
  if (!value || typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  const { exitId, name, mode, lanAccess, vlessUuid, controlUrl, expiresAt } = item;
  if (typeof exitId !== "string" || !EXIT_ID.test(exitId)) return null;
  if (typeof name !== "string" || name.length < 1 || name.length > 60) return null;
  if (mode !== "direct" && mode !== "vpn") return null;
  if (typeof lanAccess !== "boolean") return null;
  if (typeof vlessUuid !== "string" || !UUID.test(vlessUuid)) return null;
  if (typeof expiresAt !== "string" || Number.isNaN(Date.parse(expiresAt))) return null;
  if (typeof controlUrl !== "string" || controlUrl.length > 2_048) return null;
  let url: URL;
  try {
    url = new URL(controlUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "wss:" || url.port || url.search || url.hash || url.username || url.password) return null;
  if (!/^\/road\/x\/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(url.pathname)) return null;
  if (websiteHosts && !websiteHosts.has(url.hostname)) return null;
  return { exitId, name, mode, lanAccess, vlessUuid: vlessUuid.toLowerCase(), controlUrl: url.toString(), expiresAt };
}

/** Never reachable through the exit: the computer itself. */
const LOOPBACK = ["127.0.0.0/8", "0.0.0.0/8", "::1/128"];
/** The home network: only with the owner's "network access". */
const HOME_NETWORK = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
  "224.0.0.0/4", "255.255.255.255/32", "fc00::/7", "fe80::/10", "ff00::/8",
];

/**
 * The exit's Xray: VLESS on 127.0.0.1 only, out through the home connection.
 * `direct` binds to the physical interface, past this computer's own VPN.
 */
export function exitXrayConfig(input: {
  port: number;
  vlessUuid: string;
  mode: RoadMode;
  lanAccess: boolean;
  physicalInterface: string | null;
}): Record<string, unknown> {
  const bind = input.mode === "direct" && input.physicalInterface
    ? { streamSettings: { sockopt: { interface: input.physicalInterface } } }
    : {};
  return {
    log: { loglevel: "warning", access: "none" },
    // DoH through the exit's own outbound: the answers fit the way out.
    dns: { servers: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"], queryStrategy: "UseIP" },
    inbounds: [
      {
        tag: "road-in",
        listen: "127.0.0.1",
        port: input.port,
        protocol: "vless",
        settings: { clients: [{ id: input.vlessUuid }], decryption: "none" },
        sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true },
      },
    ],
    outbounds: [
      { tag: "home", protocol: "freedom", settings: { domainStrategy: "UseIP" }, ...bind },
      { tag: "blocked", protocol: "blackhole" },
    ],
    routing: {
      domainStrategy: "IPOnDemand",
      rules: [
        { type: "field", ip: input.lanAccess ? LOOPBACK : [...LOOPBACK, ...HOME_NETWORK], outboundTag: "blocked" },
        { type: "field", domain: ["full:localhost"], outboundTag: "blocked" },
        // No mail sent from the home address.
        { type: "field", port: "25", outboundTag: "blocked" },
      ],
    },
  };
}

const VIRTUAL_INTERFACE = /^(utun|tun|tap|wg|ppp|ipsec|lo|gif|stf|awdl|llw|anpi|ap\d|bridge|vmnet|vboxnet|virbr|docker|br-|veth|zt|tailscale|nordlynx)|levik|wintun|loopback|vethernet|virtualbox|vmware|hyper-v/i;
/** Built-in adapters first, then any wired or wireless one. */
const PREFERRED_INTERFACES = [/^(en0|eth0|Ethernet|Wi-?Fi|wlan0)$/i, /^(en\d|eth\d|eno\d|enp|wlp|wl|Ethernet|Wi-?Fi)/i];

/** The interface the home connection leaves by: not a tunnel, not a virtual machine's. */
export function physicalInterface(interfaces = networkInterfaces()): string | null {
  const candidates = Object.entries(interfaces)
    .filter(([name, entries]) => !VIRTUAL_INTERFACE.test(name) && (entries ?? []).some(
      (entry) => entry.family === "IPv4" && !entry.internal && !entry.address.startsWith("169.254.") && !entry.address.startsWith("10.89.0."),
    ))
    .map(([name]) => name);
  for (const preferred of PREFERRED_INTERFACES) {
    const found = candidates.find((name) => preferred.test(name));
    if (found) return found;
  }
  return candidates[0] ?? null;
}

/** A free local port for the exit's Xray. */
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => (port ? resolve(port) : reject(new Error("no free port"))));
    });
  });
}

export interface RoadSocket {
  binaryType: string;
  readonly readyState: number;
  readonly bufferedAmount: number;
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
  send(data: Uint8Array | string): void;
  close(code?: number): void;
}

export type RoadSocketFactory = (url: string) => RoadSocket;

const OPEN = 1;

const defaultSocket: RoadSocketFactory = (url) => new WebSocket(url) as unknown as RoadSocket;

function messageBytes(data: unknown): Buffer | null {
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

interface ConnectorEvents {
  status: [online: boolean];
}

/** The control connection to the relay and the device streams it announces. */
export class RoadConnector extends EventEmitter<ConnectorEvents> {
  private control: RoadSocket | null = null;
  private readonly streams = new Set<() => void>();
  private retry: ReturnType<typeof setTimeout> | null = null;
  private failures = 0;
  private running = false;

  constructor(
    private controlUrl: string,
    private readonly localPort: number,
    private readonly socket: RoadSocketFactory = defaultSocket,
    private readonly log: (line: string) => void = () => {},
  ) {
    super();
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.open();
  }

  stop(): void {
    this.running = false;
    if (this.retry) clearTimeout(this.retry);
    this.retry = null;
    const control = this.control;
    this.control = null;
    control?.close(1000);
    for (const end of [...this.streams]) end();
  }

  /** A fresh token for the next connections; the open ones keep going. */
  retarget(controlUrl: string): void {
    this.controlUrl = controlUrl;
  }

  get streamCount(): number {
    return this.streams.size;
  }

  private open(): void {
    const control = this.socket(this.controlUrl);
    this.control = control;
    control.onopen = () => {
      this.failures = 0;
      this.emit("status", true);
    };
    control.onmessage = (event) => {
      if (typeof event.data !== "string" || event.data.length > 512) return;
      let message: unknown;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      const { type, id } = (message ?? {}) as { type?: unknown; id?: unknown };
      if (type === "open" && typeof id === "string" && STREAM_ID.test(id)) this.stream(id);
    };
    control.onerror = () => {};
    control.onclose = () => {
      if (this.control !== control) return;
      this.control = null;
      this.emit("status", false);
      if (!this.running) return;
      const delay = RETRY_DELAYS_MS[Math.min(this.failures, RETRY_DELAYS_MS.length - 1)] ?? 60_000;
      this.failures += 1;
      this.retry = setTimeout(() => {
        this.retry = null;
        if (this.running) this.open();
      }, delay);
    };
  }

  /** One device connection: the relay's data WebSocket joined to the local Xray. */
  private stream(id: string): void {
    if (this.streams.size >= MAX_STREAMS) return;
    const data = this.socket(`${this.controlUrl}/${id}`);
    data.binaryType = "arraybuffer";
    const local: Socket = netConnect({ host: "127.0.0.1", port: this.localPort });
    local.setNoDelay(true);
    const early: Buffer[] = [];
    let connected = false;
    let ended = false;
    let drainTimer: ReturnType<typeof setInterval> | null = null;
    const end = () => {
      if (ended) return;
      ended = true;
      this.streams.delete(end);
      if (drainTimer) clearInterval(drainTimer);
      local.destroy();
      if (data.readyState <= OPEN) data.close(1000);
    };
    this.streams.add(end);
    const timer = setTimeout(() => {
      if (!connected) end();
    }, LOCAL_CONNECT_MS);
    local.once("connect", () => {
      connected = true;
      clearTimeout(timer);
      for (const chunk of early.splice(0)) local.write(chunk);
    });
    local.on("data", (chunk: Buffer) => {
      if (data.readyState !== OPEN) return;
      data.send(chunk);
      // The relay is slower than the home: wait until the WebSocket drains.
      if (data.bufferedAmount > HIGH_WATER && !drainTimer) {
        local.pause();
        drainTimer = setInterval(() => {
          if (data.bufferedAmount > HIGH_WATER / 2) return;
          if (drainTimer) clearInterval(drainTimer);
          drainTimer = null;
          local.resume();
        }, 50);
      }
    });
    local.on("error", end);
    local.on("close", end);
    data.onmessage = (event) => {
      const bytes = messageBytes(event.data);
      if (!bytes) return;
      if (connected) local.write(bytes);
      else early.push(bytes);
    };
    data.onerror = () => {};
    data.onclose = () => {
      clearTimeout(timer);
      // What the device sent last still reaches home before the end.
      if (connected) local.end();
      else end();
      setTimeout(end, 5_000).unref();
      this.streams.delete(end);
    };
  }
}

interface ExitEvents {
  status: [status: RoadExitStatus, detail: string | null];
}

/** Runs the exit's Xray and connector for the website's exit config; stops them for null. */
export class HomeRoadExit extends EventEmitter<ExitEvents> {
  private process: ChildProcess | null = null;
  private connector: RoadConnector | null = null;
  private current: RoadExitConfig | null = null;
  private interfaceName: string | null = null;
  private state: RoadExitStatus = "off";
  private detail: string | null = null;
  private applying: Promise<void> = Promise.resolve();

  constructor(
    private readonly options: {
      xrayPath: () => string;
      log?: (line: string) => void;
      socket?: RoadSocketFactory;
      /** The interface the home connection leaves by; the platform may know better than the heuristic. */
      findInterface?: () => Promise<string | null>;
    },
  ) {
    super();
  }

  get status(): RoadExitStatus {
    return this.state;
  }

  get statusDetail(): string | null {
    return this.detail;
  }

  get config(): RoadExitConfig | null {
    return this.current;
  }

  /** Applies a new config, one change at a time; the same config keeps everything running. */
  apply(config: RoadExitConfig | null): Promise<void> {
    this.applying = this.applying.catch(() => {}).then(() => this.applyNow(config));
    return this.applying;
  }

  stop(): Promise<void> {
    return this.apply(null);
  }

  private setStatus(status: RoadExitStatus, detail: string | null = null): void {
    if (status === this.state && detail === this.detail) return;
    this.state = status;
    this.detail = detail;
    this.emit("status", status, detail);
  }

  private async applyNow(config: RoadExitConfig | null): Promise<void> {
    const iface = config?.mode === "direct"
      ? await (this.options.findInterface ?? (async () => physicalInterface()))().catch(() => null)
      : null;
    const same = config && this.current && this.process && this.connector
      && config.exitId === this.current.exitId && config.mode === this.current.mode
      && config.lanAccess === this.current.lanAccess && config.vlessUuid === this.current.vlessUuid
      && iface === this.interfaceName;
    if (same) {
      // Every answer of the website carries a fresh relay token: no restart for that.
      this.current = config;
      this.connector?.retarget(config.controlUrl);
      return;
    }
    await this.halt();
    this.current = config;
    this.interfaceName = iface;
    if (!config) {
      this.setStatus("off");
      return;
    }
    this.setStatus("starting");
    try {
      const port = await freePort();
      const xrayConfig = exitXrayConfig({
        port, vlessUuid: config.vlessUuid, mode: config.mode, lanAccess: config.lanAccess, physicalInterface: iface,
      });
      // The config (with the exit's UUID) goes through stdin, never to disk.
      const child = spawn(this.options.xrayPath(), ["run", "-format", "json", "-config", "stdin:"], {
        stdio: ["pipe", "ignore", "pipe"], windowsHide: true,
      });
      this.process = child;
      child.stdin?.on("error", () => {});
      child.stdin?.end(JSON.stringify(xrayConfig));
      child.stderr?.setEncoding("utf8");
      child.stderr?.on("data", (line: string) => this.options.log?.(`[home-road] ${line.trim().slice(0, 300)}`));
      child.once("exit", (code) => {
        if (this.process !== child) return;
        this.process = null;
        this.connector?.stop();
        this.connector = null;
        this.setStatus("error", `Выход остановился (код ${code ?? "сигнал"})`);
      });
      await waitForPort(port, 5_000);
      const connector = new RoadConnector(config.controlUrl, port, this.options.socket, this.options.log);
      this.connector = connector;
      connector.on("status", (online) => this.setStatus(online ? "online" : "offline"));
      connector.start();
      if (config.mode === "direct" && !iface) {
        this.options.log?.("[home-road] no physical interface found; going out the default route");
      }
    } catch (error) {
      await this.halt();
      this.setStatus("error", error instanceof Error ? error.message.slice(0, 200) : "Выход не запустился");
    }
  }

  private async halt(): Promise<void> {
    this.connector?.stop();
    this.connector = null;
    const child = this.process;
    this.process = null;
    if (child && child.exitCode === null) {
      child.kill();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          resolve();
        }, 3_000);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }
}

async function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const ready = await new Promise<boolean>((resolve) => {
      const socket = netConnect({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        socket.destroy();
        resolve(true);
      });
      socket.once("error", () => resolve(false));
    });
    if (ready) return;
    if (Date.now() > deadline) throw new Error("Выход не запустился");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** The website names the servers of home exits «🏠 <name>». */
export function isHomeRoadServer(name: string): boolean {
  return name.startsWith("🏠");
}
