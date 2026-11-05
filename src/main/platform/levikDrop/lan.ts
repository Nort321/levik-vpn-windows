import { connect, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { networkInterfaces } from "node:os";
import { FrameSocket } from "./framing";
import { isPrivateIpv4, lanDialerFrame, lanListenerFrame, sameBytes } from "./protocol";

/** docs/levik-drop.md "Local network": a direct TCP connection when both apps share a network. */

const TUNNEL_INTERFACE = /tun|tap|wintun|utun|wg|ppp|ipsec|levik|vpn/i;
const DIAL_TIMEOUT_MS = 1_500;
const PROOF_TIMEOUT_MS = 3_000;
/** The listener stops waiting for the other app after this long. */
const LISTEN_MS = 20_000;

/** This computer's private IPv4 addresses, VPN tunnels left out. */
export function privateAddresses(): string[] {
  const found: string[] = [];
  for (const [name, entries] of Object.entries(networkInterfaces())) {
    if (TUNNEL_INTERFACE.test(name)) continue;
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal && isPrivateIpv4(entry.address) && !found.includes(entry.address)) found.push(entry.address);
    }
  }
  return found.slice(0, 8);
}

function listen(server: Server, port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const failed = (): void => resolve(false);
    server.once("error", failed);
    server.listen({ port, host, exclusive: true }, () => {
      server.off("error", failed);
      resolve(true);
    });
  });
}

/** Listens on one port of every private address until the other app proves the session key. */
export class LanListener {
  private readonly servers: Server[] = [];
  private result: Promise<FrameSocket | null> | null = null;
  private settle: ((socket: FrameSocket | null) => void) | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  port = 0;
  addresses: string[] = [];

  private constructor(private readonly transfer: Buffer, private readonly key: Buffer) {}

  static async open(transfer: Buffer, key: Buffer): Promise<LanListener | null> {
    const listener = new LanListener(transfer, key);
    for (const address of privateAddresses()) {
      const server = createServer((socket) => listener.onConnection(socket));
      if (await listen(server, listener.port, address)) {
        if (listener.port === 0) {
          const bound = server.address();
          listener.port = typeof bound === "object" && bound ? bound.port : 0;
        }
        listener.servers.push(server);
        listener.addresses.push(address);
      } else {
        server.close();
      }
    }
    if (listener.servers.length === 0) return null;
    listener.result = new Promise((resolve) => {
      listener.settle = resolve;
    });
    listener.timer = setTimeout(() => listener.finish(null), LISTEN_MS);
    return listener;
  }

  /** The verified connection, or null after the timeout or close(). */
  accepted(): Promise<FrameSocket | null> {
    return this.result ?? Promise.resolve(null);
  }

  close(): void {
    this.finish(null);
  }

  private finish(socket: FrameSocket | null): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    for (const server of this.servers.splice(0)) server.close();
    const settle = this.settle;
    this.settle = null;
    if (settle) settle(socket);
    else socket?.close();
  }

  private onConnection(socket: Socket): void {
    const frames = new FrameSocket(socket);
    if (!this.settle) {
      frames.close();
      return;
    }
    void frames.next(PROOF_TIMEOUT_MS).then(async (frame) => {
      const expected = lanDialerFrame(this.transfer, this.key);
      if (!this.settle || !sameBytes(frame, expected)) throw new Error("bad proof");
      await frames.send(lanListenerFrame(this.key));
      if (!this.settle) throw new Error("late");
      this.finish(frames);
    }).catch(() => frames.close());
  }
}

function dialOne(address: string, port: number, transfer: Buffer, key: Buffer, signal: AbortSignal): Promise<FrameSocket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: address, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("timed out"));
    }, DIAL_TIMEOUT_MS);
    const aborted = (): void => {
      socket.destroy();
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", aborted, { once: true });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once("connect", () => {
      clearTimeout(timer);
      const frames = new FrameSocket(socket);
      frames.send(lanDialerFrame(transfer, key))
        .then(() => frames.next(PROOF_TIMEOUT_MS))
        .then((frame) => {
          signal.removeEventListener("abort", aborted);
          if (!sameBytes(frame, lanListenerFrame(key))) throw new Error("bad proof");
          resolve(frames);
        })
        .catch((error: unknown) => {
          frames.close();
          reject(error instanceof Error ? error : new Error("lan failed"));
        });
    });
  });
}

/** Connects to every address at once; the first that proves the session key wins. */
export async function dialLan(addresses: readonly string[], port: number, transfer: Buffer, key: Buffer): Promise<FrameSocket | null> {
  const controller = new AbortController();
  const attempts = addresses.map((address) => dialOne(address, port, transfer, key, controller.signal));
  try {
    const winner = await Promise.any(attempts);
    controller.abort();
    // A second address may have proved too: only the first stays.
    void Promise.allSettled(attempts).then((results) => {
      for (const result of results) if (result.status === "fulfilled" && result.value !== winner) result.value.close();
    });
    return winner;
  } catch {
    return null;
  }
}
