import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DropEngine } from "../src/main/platform/levikDrop/engine";
import type { DropApi } from "../src/main/platform/levikDrop/engine";
import { FrameSocket } from "../src/main/platform/levikDrop/framing";
import type { RelayEndpoint } from "../src/main/platform/levikDrop/relay";
import type { Secrets } from "../src/main/platform/levikDrop/store";
import type { DropState } from "../src/shared/drop";

/** Two apps of one account with an in-memory website and a plain-TCP relay. */

class SiteError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

interface SiteTransfer {
  id: string;
  sender: string;
  receiver: string;
  state: DropState;
  reason: string | null;
  fileCount: number;
  totalBytes: number;
  createdAt: string;
}

const OPEN: readonly DropState[] = ["offered", "active", "paused"];

class FakeSite {
  readonly transfers = new Map<string, SiteTransfer>();
  readonly engines = new Map<string, DropEngine>();
  readonly steps: string[] = [];

  constructor(private readonly relayPort: () => number) {}

  private notify(): void {
    setImmediate(() => {
      for (const engine of this.engines.values()) engine.refresh();
    });
  }

  private view(transfer: SiteTransfer, device: string): Record<string, unknown> {
    const role = transfer.sender === device ? "sender" : "receiver";
    const peer = role === "sender" ? transfer.receiver : transfer.sender;
    return {
      id: transfer.id, role, peerDeviceId: peer, peerName: peer === "pc" ? "Рабочий ПК" : "MacBook", peerPlatform: peer === "pc" ? "windows" : "macos",
      state: transfer.state, reason: transfer.reason, fileCount: transfer.fileCount, totalBytes: transfer.totalBytes, relayedBytes: 0,
      createdAt: transfer.createdAt, updatedAt: transfer.createdAt, expiresAt: transfer.createdAt, finishedAt: OPEN.includes(transfer.state) ? null : transfer.createdAt,
    };
  }

  api(device: string): DropApi {
    const other = device === "pc" ? "mac" : "pc";
    return {
      presence: async () => ({ ok: true }),
      clearPresence: async () => {},
      devices: async () => ({ ok: true, available: true, devices: [{ deviceId: other, name: "x", platform: other === "pc" ? "windows" : "macos", ready: true, keyId: "0123456789abcdef", current: false }], limits: { maxFiles: 20, maxBytes: 2 * 1024 ** 3 } }),
      transfers: async () => ({
        ok: true,
        transfers: [...this.transfers.values()].filter((item) => item.sender === device || item.receiver === device).map((item) => this.view(item, device)),
        quota: { limitBytes: 20 * 1024 ** 3, usedBytes: 0, resetsAt: new Date().toISOString() },
      }),
      create: async (offer) => {
        if ([...this.transfers.values()].some((item) => OPEN.includes(item.state))) throw new SiteError("device_busy");
        const transfer: SiteTransfer = {
          id: randomUUID(), sender: device, receiver: offer.receiverDeviceId, state: "offered", reason: null,
          fileCount: offer.fileCount, totalBytes: offer.totalBytes, createdAt: new Date().toISOString(),
        };
        this.transfers.set(transfer.id, transfer);
        this.notify();
        return { ok: true, transfer: this.view(transfer, device) };
      },
      update: async ({ id, action, reason }) => {
        const transfer = this.transfers.get(id);
        if (!transfer) throw new SiteError("transfer_not_found");
        const role = transfer.sender === device ? "sender" : "receiver";
        this.steps.push(`${role}:${action}${reason ? `:${reason}` : ""}`);
        const next = this.next(transfer, role, action, reason ?? null);
        if (next !== transfer.state || action === "cancel" || action === "fail") {
          transfer.state = next;
          if (action === "cancel") transfer.reason = role;
          if (action === "fail" || action === "pause") transfer.reason = reason ?? null;
          this.notify();
        }
        const connection = action === "connect"
          ? { token: `${id}:${role}`, expiresAt: new Date().toISOString(), endpoints: [{ host: "127.0.0.1", port: this.relayPort(), pin: "a".repeat(43) }] }
          : undefined;
        return { ok: true, transfer: this.view(transfer, device), ...(connection ? { connection } : {}) };
      },
    };
  }

  private next(transfer: SiteTransfer, role: string, action: string, _reason: string | null): DropState {
    const state = transfer.state;
    const open = OPEN.includes(state);
    switch (action) {
      case "connect":
        if (!open) throw new SiteError("transfer_ended");
        return state === "offered" ? "offered" : "active";
      case "accept":
        if (role !== "receiver") throw new SiteError("invalid_action");
        if (state === "active") return state;
        if (state !== "offered") throw new SiteError("transfer_ended");
        return "active";
      case "decline":
        if (state === "declined") return state;
        if (state !== "offered") throw new SiteError("invalid_action");
        return "declined";
      case "pause":
        if (state === "paused") return state;
        if (state !== "active") throw new SiteError("invalid_action");
        return "paused";
      case "complete":
        if (state === "done") return state;
        if (state !== "active" && state !== "paused") throw new SiteError("invalid_action");
        return "done";
      case "cancel":
        if (state === "cancelled") return state;
        if (!open) throw new SiteError("transfer_ended");
        return "cancelled";
      case "fail":
        if (state === "failed") return state;
        if (!open) throw new SiteError("transfer_ended");
        return "failed";
      default:
        throw new SiteError("invalid_action");
    }
  }
}

/** The relay's behaviour without TLS and tokens: pairs by transfer, forwards, says wait/peer/gone. */
async function fakeRelay(): Promise<{ server: Server; port: number }> {
  const pipes = new Map<string, { sender?: FrameSocket; receiver?: FrameSocket }>();
  const control = (socket: FrameSocket, t: string): void => {
    void socket.send(Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify({ t }))])).catch(() => {});
  };
  const server = createServer((raw: Socket) => {
    const socket = new FrameSocket(raw);
    void (async () => {
      const join = JSON.parse((await socket.next()).toString()) as { token: string };
      const [id = "", role] = join.token.split(":");
      const pipe = pipes.get(id) ?? {};
      pipes.set(id, pipe);
      const side = role === "sender" ? "sender" : "receiver";
      const otherSide = side === "sender" ? "receiver" : "sender";
      pipe[side]?.close();
      pipe[side] = socket;
      const peer = pipe[otherSide];
      if (peer && !peer.closed) {
        control(peer, "peer");
        control(socket, "peer");
      } else {
        control(socket, "wait");
      }
      for (;;) {
        let frame: Buffer;
        try {
          frame = await socket.next();
        } catch {
          if (pipe[side] === socket) {
            delete pipe[side];
            const other = pipe[otherSide];
            if (other) control(other, "gone");
          }
          return;
        }
        const other = pipe[otherSide];
        if (other && !other.closed) await other.send(frame).catch(() => {});
      }
    })().catch(() => socket.close());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { server, port: typeof address === "object" && address ? address.port : 0 };
}

async function plainJoin(endpoints: readonly RelayEndpoint[], token: string): Promise<FrameSocket> {
  const endpoint = endpoints[0];
  if (!endpoint) throw new Error("no endpoint");
  const raw = connect(endpoint.port, endpoint.host);
  await new Promise<void>((resolve, reject) => {
    raw.once("connect", resolve);
    raw.once("error", reject);
  });
  const socket = new FrameSocket(raw);
  await socket.send(Buffer.from(JSON.stringify({ v: 1, token })));
  return socket;
}

function memorySecrets(): Secrets {
  const values = new Map<string, Buffer>();
  return {
    get: async (name) => values.get(name) ?? null,
    put: async (name, value) => {
      values.set(name, Buffer.from(value));
    },
    remove: async (name) => {
      values.delete(name);
    },
  };
}

async function until<T>(read: () => T | null | undefined | false, what: string, ms = 8_000): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = read();
    if (value) return value;
    if (Date.now() - started > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

async function world() {
  const root = await mkdtemp(join(tmpdir(), "levikdrop-engine-"));
  const relay = await fakeRelay();
  const site = new FakeSite(() => relay.port);
  const make = async (device: "pc" | "mac") => {
    const folder = join(root, device, "Downloads");
    await mkdir(folder, { recursive: true });
    const engine = new DropEngine({
      api: site.api(device),
      secrets: memorySecrets(),
      statePath: join(root, device, "state.json"),
      platform: device === "pc" ? "windows" : "macos",
      defaultFolder: folder,
      markDownloaded: async () => {},
      errorCode: (error) => error instanceof SiteError ? error.code : null,
      log: () => {},
      join: plainJoin,
    });
    site.engines.set(device, engine);
    await engine.start();
    return { engine, folder };
  };
  const pc = await make("pc");
  const mac = await make("mac");
  cleanup.push(async () => {
    await pc.engine.stop();
    await mac.engine.stop();
    relay.server.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, site, pc, mac };
}

const transferOf = (engine: DropEngine) => engine.snapshot().transfers[0];

describe("LevikDrop engine", () => {
  it("offers, confirms the code once, delivers, and trusts the key afterwards", async () => {
    const { root, site, pc, mac } = await world();
    const content = randomBytes(1_500_000);
    const source = join(root, "photo.jpg");
    await writeFile(source, content);

    await pc.engine.send("mac", [source]);
    // Neither app knows the other's key: the sender confirms before any name or byte leaves.
    const senderPrompt = await until(() => transferOf(pc.engine)?.prompt, "sender prompt");
    expect(senderPrompt.kind).toBe("confirm");
    expect(senderPrompt.code).toMatch(/^\d{3} \d{3}$/);
    await vi.waitFor(() => expect(Reflect.get(transferOf(mac.engine) ?? {}, "verificationCode")).toBe(senderPrompt.code), { timeout: 500 });
    expect(transferOf(mac.engine)?.files).toBeNull();
    expect(transferOf(mac.engine)?.prompt).toBeNull();
    const id = transferOf(pc.engine)?.id ?? "";
    await expect(pc.engine.answer(id, "confirm", "000 000")).rejects.toThrow(/Код изменился/);
    await pc.engine.answer(id, "confirm", senderPrompt.code);

    const offer = await until(() => transferOf(mac.engine)?.prompt, "receiver offer");
    expect(offer).toEqual({ kind: "offer", code: senderPrompt.code, trust: "new" });
    expect(transferOf(mac.engine)?.files).toEqual([{ name: "photo.jpg", size: content.length }]);
    await mac.engine.answer(id, "accept", offer.code);

    await until(() => transferOf(pc.engine)?.state === "done" && transferOf(mac.engine)?.state === "done", "done");
    expect((await readFile(join(mac.folder, "photo.jpg"))).equals(content)).toBe(true);
    expect(mac.engine.savedFile(id)).toBe(join(mac.folder, "photo.jpg"));
    expect(transferOf(mac.engine)?.verificationCode).toBeNull();
    // The receiver completes; the sender may learn it from the website before the `done` record.
    expect(site.steps).toEqual(expect.arrayContaining(["receiver:accept", "receiver:complete"]));

    // Second time both keys are pinned: no code, the receiver still decides.
    await pc.engine.send("mac", [source]);
    const second = await until(() => {
      const transfer = transferOf(mac.engine);
      return transfer?.id !== id && transfer?.prompt ? transfer : null;
    }, "second offer");
    expect(second.prompt).toEqual({ kind: "offer", code: null, trust: "trusted" });
    expect(second.verificationCode).toBeNull();
    expect(transferOf(pc.engine)?.prompt).toBeNull();
    await mac.engine.answer(second.id, "accept", null);
    await until(() => transferOf(mac.engine)?.state === "done", "second done");
    expect((await readFile(join(mac.folder, "photo (1).jpg"))).equals(content)).toBe(true);
    expect((await readdir(mac.folder)).some((name) => name.endsWith(".levikdrop"))).toBe(false);
  });

  it("declines and cancels on both sides", async () => {
    const { root, pc, mac } = await world();
    const source = join(root, "notes.txt");
    await writeFile(source, "hello");
    await mac.engine.send("pc", [source]);
    const confirm = await until(() => transferOf(mac.engine)?.prompt, "sender prompt");
    const id = transferOf(mac.engine)?.id ?? "";
    await mac.engine.answer(id, "confirm", confirm.code);
    const offer = await until(() => transferOf(pc.engine)?.prompt, "offer");
    await pc.engine.answer(id, "decline", offer.code);
    await until(() => transferOf(mac.engine)?.state === "declined", "declined at the sender");

    await mac.engine.send("pc", [source]);
    const next = await until(() => {
      const transfer = transferOf(pc.engine);
      return transfer && transfer.id !== id && transfer.prompt ? transfer : null;
    }, "second offer");
    await mac.engine.control(next.id, "cancel");
    await until(() => transferOf(pc.engine)?.state === "cancelled" && transferOf(pc.engine)?.prompt === null, "cancelled at the receiver");
    await expect(mac.engine.send("pc", [join(root, "missing.bin")])).rejects.toThrow(/Не удалось открыть/);
  });
});
