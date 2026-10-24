import { createHash, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { ChannelClosed, FrameSocket } from "./framing";
import { TargetFiles, TransferFailure, readSource } from "./files";
import type { SourceFile } from "./files";
import { LanListener, dialLan } from "./lan";
import {
  ACK_EVERY,
  ProtocolError,
  RecordOpener,
  RecordSealer,
  WINDOW,
  commitment,
  decodePlaintext,
  decodeReceiverHello,
  decodeReceiverProof,
  decodeSenderHello,
  decodeSenderProof,
  encodeControl,
  encodeData,
  encodeReceiverHello,
  encodeReceiverProof,
  encodeSenderHello,
  encodeSenderProof,
  ephemeralKey,
  sameBytes,
  sessionKeys,
  signTranscript,
  transcript,
  transferBytes,
  verifyTranscript,
} from "./protocol";
import type { Control, FailReason, ManifestFile, ReceiverHello, SenderHello, SessionKeys } from "./protocol";

/**
 * One session of a transfer, docs/levik-drop.md "Session": from the relay's
 * `peer` to its end. Keys never outlive it; what was written does.
 */

export type Trust = "trusted" | "new" | "changed";
export type DropPlatform = "android" | "windows" | "macos" | "linux";
export type SessionPath = "relay" | "lan";

export type SessionOutcome =
  /** The connection or the handshake broke: the next `peer` starts again. */
  | { kind: "lost"; detail: string; lanBroke: boolean }
  | { kind: "done" }
  | { kind: "declined"; by: "self" | "peer" }
  | { kind: "paused"; by: "self" | "peer" }
  | { kind: "cancelled"; by: "self" | "peer" }
  | { kind: "failed"; by: "self" | "peer"; reason: FailReason };

export interface Identity {
  privateKey: KeyObject;
  spki: Buffer;
}

export interface SessionEvents {
  /** After the handshake: the code both screens show and whether the peer's key is pinned. */
  keyed(code: string, trust: Trust, peerKey: Buffer): void;
  path(path: SessionPath): void;
  /** Bytes of the whole transfer in place (receiver) or acknowledged (sender). */
  progress(doneBytes: number): void;
}

interface Common {
  transferId: string;
  identity: Identity;
  peerDeviceId: string;
  ownPlatform: DropPlatform;
  peerPlatform: DropPlatform | null;
  trust(peerKey: Buffer): Trust;
  /** Unless the direct connection broke in an earlier session of this relay connection. */
  allowLan: boolean;
  events: SessionEvents;
}

export interface SenderWork extends Common {
  role: "sender";
  files: SourceFile[];
  /** Resolves true once the user confirmed the code on this computer; false: the codes differ. */
  confirm(code: string, trust: Trust): Promise<boolean>;
}

export interface ReceiverWork extends Common {
  role: "receiver";
  /** The manifest of an earlier session; later ones must repeat it exactly. */
  manifest: ManifestFile[] | null;
  /** Set once the user accepted. */
  targets: TargetFiles | null;
  /** First session: the user accepts (and so confirms the code) or declines. */
  decide(manifest: ManifestFile[], code: string, trust: Trust): Promise<TargetFiles | null>;
  /** Later sessions with an unpinned key. */
  confirm(code: string, trust: Trust): Promise<boolean>;
}

const STEP_TIMEOUT_MS = 30_000;
const LAN_SWITCH_TIMEOUT_MS = 5_000;

/** The relay's frames for this session, fed by the relay connection. */
export class Inbox {
  private readonly frames: Buffer[] = [];
  private waiter: { resolve(frame: Buffer): void; reject(error: Error): void } | null = null;
  private failure: Error | null = null;

  push(frame: Buffer): void {
    if (this.failure) return;
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter.resolve(frame);
    } else {
      this.frames.push(frame);
    }
  }

  close(error: Error = new ChannelClosed()): void {
    if (this.failure) return;
    this.failure = error;
    this.waiter?.reject(error);
    this.waiter = null;
  }

  next(timeoutMs = 0): Promise<Buffer> {
    const frame = this.frames.shift();
    if (frame) return Promise.resolve(frame);
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const timer = timeoutMs > 0 ? setTimeout(() => {
        this.waiter = null;
        reject(new ChannelClosed("timed out"));
      }, timeoutMs) : null;
      this.waiter = {
        resolve: (value) => { if (timer) clearTimeout(timer); resolve(value); },
        reject: (error) => { if (timer) clearTimeout(timer); reject(error); },
      };
    });
  }
}

class Ended extends Error {}

export class Session {
  readonly inbox = new Inbox();
  private keys: SessionKeys | null = null;
  private sealer: RecordSealer | null = null;
  private opener: RecordOpener | null = null;
  private readonly transfer: Buffer;
  private input: SessionPath = "relay";
  private output: SessionPath = "relay";
  private lan: FrameSocket | null = null;
  private lanReady: Promise<FrameSocket | null> | null = null;
  private lanListener: LanListener | null = null;
  private lanBroke = false;
  private outcome: SessionOutcome | null = null;
  private settle: ((outcome: SessionOutcome) => void) | null = null;
  private readonly result: Promise<SessionOutcome>;

  // Sender
  private manifestSent = false;
  private accepted: { offsets: number[]; prefix: Array<string | null> } | null = null;
  private acked: number[] = [];
  /** Data bytes sent, and acknowledged beyond `accept`, in this session: their difference is in flight. */
  private sentBytes = 0;
  private ackedAtAccept = 0;
  private ackWaiter: (() => void) | null = null;

  // Receiver
  private acceptSent = false;
  private lastAck: number[] = [];
  private written: number[] = [];

  constructor(private readonly relay: FrameSocket, private readonly work: SenderWork | ReceiverWork) {
    this.transfer = transferBytes(work.transferId);
    this.result = new Promise((resolve) => {
      this.settle = resolve;
    });
  }

  get finished(): boolean {
    return this.outcome !== null;
  }

  /** Runs the session to its outcome; never throws. */
  run(): Promise<SessionOutcome> {
    void this.main().catch((error: unknown) => this.fromError(error));
    return this.result;
  }

  /** The relay said `gone`, or the connection closed. */
  abort(detail: string): void {
    this.finish({ kind: "lost", detail, lanBroke: this.lanBroke });
  }

  pause(): void {
    this.sayAndFinish({ t: "pause" }, { kind: "paused", by: "self" });
  }

  cancel(): void {
    this.sayAndFinish({ t: "cancel" }, { kind: "cancelled", by: "self" });
  }

  fail(reason: FailReason): void {
    this.sayAndFinish({ t: "fail", reason }, { kind: "failed", by: "self", reason });
  }

  private sayAndFinish(control: Control, outcome: SessionOutcome): void {
    if (this.outcome) return;
    if (this.sealer) void this.sendControl(control).catch(() => {});
    this.finish(outcome);
  }

  private finish(outcome: SessionOutcome): void {
    if (this.outcome) return;
    this.outcome = outcome;
    this.inbox.close(new Ended());
    this.lanListener?.close();
    // Records already written still leave before the direct connection closes.
    this.lan?.closeGracefully();
    this.ackWaiter?.();
    if (this.work.role === "receiver") void this.work.targets?.closeWriting();
    this.settle?.(outcome);
    this.settle = null;
  }

  private fromError(error: unknown): void {
    if (this.outcome) return;
    if (error instanceof TransferFailure) {
      this.fail(error.reason);
    } else if (error instanceof ProtocolError) {
      // A broken record or message: this session is over, the transfer is not.
      this.finish({ kind: "lost", detail: `protocol: ${error.message}`, lanBroke: this.lanBroke });
    } else {
      this.finish({ kind: "lost", detail: error instanceof Error ? error.message : "session", lanBroke: this.lanBroke });
    }
  }

  // Handshake ------------------------------------------------------------------------

  private async handshake(): Promise<{ keys: SessionKeys; peerKey: Buffer }> {
    const own = this.work.identity;
    const ecdh = ephemeralKey();
    const ephemeral = ecdh.getPublicKey();
    if (this.work.role === "sender") {
      const nonce = randomBytes(32);
      const hello: SenderHello = { transfer: this.transfer, identity: own.spki, ephemeral, commit: commitment(own.spki, ephemeral, nonce) };
      await this.relay.send(encodeSenderHello(hello));
      const reply = decodeReceiverHello(await this.inbox.next(STEP_TIMEOUT_MS));
      if (!sameBytes(reply.transfer, this.transfer)) throw new ProtocolError("another transfer");
      const th = transcript(hello, reply, nonce);
      await this.relay.send(encodeSenderProof(nonce, signTranscript("sender", own.privateKey, th)));
      const signature = decodeReceiverProof(await this.inbox.next(STEP_TIMEOUT_MS));
      if (!verifyTranscript("receiver", reply.identity, th, signature)) throw new ProtocolError("receiver signature");
      return { keys: sessionKeys(ecdh, reply.ephemeral, th), peerKey: reply.identity };
    }
    const hello = decodeSenderHello(await this.inbox.next(STEP_TIMEOUT_MS));
    if (!sameBytes(hello.transfer, this.transfer)) throw new ProtocolError("another transfer");
    const reply: ReceiverHello = { transfer: this.transfer, identity: own.spki, ephemeral, nonce: randomBytes(32) };
    await this.relay.send(encodeReceiverHello(reply));
    const proof = decodeSenderProof(await this.inbox.next(STEP_TIMEOUT_MS));
    if (!sameBytes(commitment(hello.identity, hello.ephemeral, proof.nonce), hello.commit)) throw new ProtocolError("commitment");
    const th = transcript(hello, reply, proof.nonce);
    if (!verifyTranscript("sender", hello.identity, th, proof.signature)) throw new ProtocolError("sender signature");
    await this.relay.send(encodeReceiverProof(signTranscript("receiver", own.privateKey, th)));
    return { keys: sessionKeys(ecdh, hello.ephemeral, th), peerKey: hello.identity };
  }

  private async main(): Promise<void> {
    const { keys, peerKey } = await this.handshake();
    this.keys = keys;
    const role = this.work.role;
    this.sealer = new RecordSealer(role === "sender" ? keys.sr : keys.rs);
    this.opener = new RecordOpener(role === "sender" ? keys.rs : keys.sr);
    const trust = this.work.trust(peerKey);
    this.work.events.keyed(keys.code, trust, peerKey);
    this.work.events.path("relay");

    const reading = this.readLoop(trust);
    if (role === "sender") {
      if (trust !== "trusted" && !(await this.work.confirm(keys.code, trust))) {
        this.fail("key_rejected");
        return;
      }
      if (this.outcome) return;
      const files = this.work.files.map((file) => ({ name: file.name, size: file.size }));
      await this.sendControl({ t: "manifest", files, total: files.reduce((sum, file) => sum + file.size, 0) });
      this.manifestSent = true;
    }
    if (this.listensOnLan()) void this.openLan();
    await reading;
  }

  // Records --------------------------------------------------------------------------

  private socketFor(path: SessionPath): FrameSocket {
    if (path === "relay") return this.relay;
    if (!this.lan) throw new ChannelClosed("no direct connection");
    return this.lan;
  }

  private sendPlaintext(plaintext: Buffer): Promise<void> {
    if (!this.sealer) return Promise.reject(new ProtocolError("no keys"));
    // Sealing and writing in one step keeps the counters in the order the bytes leave.
    return this.socketFor(this.output).send(this.sealer.seal(plaintext));
  }

  private sendControl(control: Control): Promise<void> {
    return this.sendPlaintext(encodeControl(control));
  }

  private async nextRecord(): Promise<Buffer> {
    if (this.input === "relay") return this.inbox.next();
    const lan = this.socketFor("lan");
    try {
      return await lan.next();
    } catch (error) {
      this.lanBroke = true;
      throw error;
    }
  }

  private async readLoop(trust: Trust): Promise<void> {
    const opener = this.opener;
    if (!opener) return;
    try {
      for (;;) {
        const frame = await this.nextRecord();
        if (this.outcome) return;
        const plaintext = decodePlaintext(opener.open(frame));
        if (plaintext.kind === "unknown") continue;
        if (plaintext.kind === "data") {
          await this.onData(plaintext.data.file, plaintext.data.offset, plaintext.data.bytes);
          continue;
        }
        await this.onControl(plaintext.control, trust);
        if (this.outcome) return;
      }
    } catch (error) {
      if (error instanceof Ended) return;
      this.fromError(error);
    }
  }

  private async onControl(control: Control, trust: Trust): Promise<void> {
    switch (control.t) {
      case "pause":
        this.finish({ kind: "paused", by: "peer" });
        return;
      case "cancel":
        this.finish({ kind: "cancelled", by: "peer" });
        return;
      case "fail":
        this.finish({ kind: "failed", by: "peer", reason: control.reason });
        return;
      case "lan":
        if (!this.listensOnLan() && this.work.allowLan && !this.lanReady) this.dialLan(control.addrs, control.port);
        return;
      case "lan_on":
        // The sender's last record through the relay.
        if (this.work.role !== "receiver" || this.input !== "relay") throw new ProtocolError("unexpected lan_on");
        await this.switchReceiver();
        return;
      case "lan_ok":
        if (this.work.role !== "sender" || this.output !== "lan" || this.input !== "relay") throw new ProtocolError("unexpected lan_ok");
        this.input = "lan";
        return;
      default:
        if (this.work.role === "sender") await this.senderControl(control);
        else await this.receiverControl(control, trust);
    }
  }

  // Local network --------------------------------------------------------------------

  private listensOnLan(): boolean {
    if (!this.work.allowLan) return false;
    const receiverPlatform = this.work.role === "receiver" ? this.work.ownPlatform : this.work.peerPlatform;
    const senderPlatform = this.work.role === "sender" ? this.work.ownPlatform : this.work.peerPlatform;
    const receiverListens = !(receiverPlatform === "windows" && senderPlatform !== "windows");
    return (this.work.role === "receiver") === receiverListens;
  }

  private async openLan(): Promise<void> {
    const keys = this.keys;
    if (!keys) return;
    const listener = await LanListener.open(this.transfer, keys.lan);
    if (!listener || this.outcome) {
      listener?.close();
      return;
    }
    this.lanListener = listener;
    this.lanReady = listener.accepted();
    await this.sendControl({ t: "lan", addrs: listener.addresses, port: listener.port });
    this.onLanReady(await this.lanReady);
  }

  private dialLan(addresses: string[], port: number): void {
    const keys = this.keys;
    if (!keys) return;
    this.lanReady = dialLan(addresses, port, this.transfer, keys.lan);
    void this.lanReady.then((socket) => this.onLanReady(socket));
  }

  private onLanReady(socket: FrameSocket | null): void {
    if (!socket) return;
    if (this.outcome) {
      socket.close();
      return;
    }
    this.lan = socket;
    socket.startKeepalive();
    socket.watchIdle(60_000);
    socket.onClose(() => {
      if (this.outcome) return;
      this.lanBroke = true;
      if (this.output === "lan" || this.input === "lan") this.abort("direct connection closed");
    });
    if (this.work.role === "sender") {
      void this.sendControl({ t: "lan_on" }).catch(() => {});
      this.output = "lan";
      this.work.events.path("lan");
    }
  }

  private async switchReceiver(): Promise<void> {
    const ready = this.lanReady;
    const socket = ready ? await Promise.race([ready, new Promise<null>((resolve) => setTimeout(() => resolve(null), LAN_SWITCH_TIMEOUT_MS))]) : null;
    if (!socket || socket.closed) {
      this.lanBroke = true;
      throw new ChannelClosed("direct connection did not come up");
    }
    await this.sendControl({ t: "lan_ok" });
    this.output = "lan";
    this.input = "lan";
    this.work.events.path("lan");
  }

  // Sender ---------------------------------------------------------------------------

  private get senderWork(): SenderWork {
    if (this.work.role !== "sender") throw new ProtocolError("not a sender");
    return this.work;
  }

  private ackedTotal(): number {
    return this.acked.reduce((sum, offset) => sum + offset, 0);
  }

  private async senderControl(control: Control): Promise<void> {
    const files = this.senderWork.files;
    switch (control.t) {
      case "accept": {
        if (!this.manifestSent || this.accepted || control.offsets.length !== files.length) throw new ProtocolError("bad accept");
        control.offsets.forEach((offset, index) => {
          const size = files[index]?.size ?? 0;
          if (offset > size || ((offset > 0 && offset < size) !== (control.prefix[index] !== null))) throw new ProtocolError("bad accept");
        });
        this.accepted = { offsets: control.offsets, prefix: control.prefix };
        this.acked = [...control.offsets];
        this.ackedAtAccept = this.ackedTotal();
        this.work.events.progress(this.ackedAtAccept);
        void this.pump().catch((error: unknown) => this.fromError(error));
        return;
      }
      case "decline":
        this.finish({ kind: "declined", by: "peer" });
        return;
      case "ack": {
        const size = files[control.file]?.size;
        if (size === undefined || control.offset > size) throw new ProtocolError("bad ack");
        this.acked[control.file] = Math.max(this.acked[control.file] ?? 0, control.offset);
        this.work.events.progress(this.ackedTotal());
        this.wakePump();
        return;
      }
      case "file_ok": {
        const size = files[control.file]?.size;
        if (size === undefined) throw new ProtocolError("bad file_ok");
        this.acked[control.file] = size;
        this.work.events.progress(this.ackedTotal());
        this.wakePump();
        return;
      }
      case "done":
        if (!this.accepted) throw new ProtocolError("early done");
        this.finish({ kind: "done" });
        return;
      default:
        return;
    }
  }

  private wakePump(): void {
    const waiter = this.ackWaiter;
    this.ackWaiter = null;
    waiter?.();
  }

  private async pump(): Promise<void> {
    const accepted = this.accepted;
    if (!accepted) return;
    const files = this.senderWork.files;
    for (const [index, file] of files.entries()) {
      const offset = accepted.offsets[index] ?? 0;
      if (offset === file.size && file.size > 0) continue;
      const hash = createHash("sha256");
      let position = offset;
      for await (const chunk of readSource(file, offset, accepted.prefix[index] ?? null, hash)) {
        while (!this.outcome && this.sentBytes - (this.ackedTotal() - this.ackedAtAccept) > WINDOW) {
          await new Promise<void>((resolve) => {
            this.ackWaiter = resolve;
          });
        }
        if (this.outcome) return;
        await this.sendPlaintext(encodeData(index, position, chunk));
        position += chunk.length;
        this.sentBytes += chunk.length;
      }
      if (this.outcome) return;
      await this.sendControl({ t: "end", file: index, sha256: hash.digest("hex") });
    }
  }

  // Receiver -------------------------------------------------------------------------

  private get receiverWork(): ReceiverWork {
    if (this.work.role !== "receiver") throw new ProtocolError("not a receiver");
    return this.work;
  }

  private async receiverControl(control: Control, trust: Trust): Promise<void> {
    const work = this.receiverWork;
    if (control.t === "end") {
      await this.onEnd(control.file, control.sha256);
      return;
    }
    if (control.t !== "manifest") return;
    if (work.manifest && JSON.stringify(work.manifest) !== JSON.stringify(control.files)) throw new TransferFailure("protocol", "manifest changed");
    work.manifest = control.files;
    // The user's answer may take minutes; records keep being read meanwhile.
    void this.answerManifest(control.files, trust).catch((error: unknown) => this.fromError(error));
  }

  private async answerManifest(manifest: ManifestFile[], trust: Trust): Promise<void> {
    const work = this.receiverWork;
    const code = this.keys?.code ?? "";
    if (work.targets) {
      if (trust !== "trusted" && !(await work.confirm(code, trust))) {
        this.fail("key_rejected");
        return;
      }
    } else {
      const targets = await work.decide(manifest, code, trust);
      if (this.outcome) return;
      if (!targets) {
        this.sayAndFinish({ t: "decline" }, { kind: "declined", by: "self" });
        return;
      }
      work.targets = targets;
    }
    if (this.outcome) return;
    const targets = work.targets;
    if (!targets) return;
    const accept = await targets.offsets();
    if (this.outcome) return;
    this.lastAck = [...accept.offsets];
    this.work.events.progress(targets.doneBytes(accept.offsets));
    await this.sendControl({ t: "accept", offsets: accept.offsets, prefix: accept.prefix });
    this.acceptSent = true;
    await this.maybeDone();
  }

  private async onData(file: number, offset: number, bytes: Buffer): Promise<void> {
    const targets = this.work.role === "receiver" ? this.work.targets : null;
    if (!targets || !this.acceptSent) throw new ProtocolError("data before accept");
    const written = await targets.write(file, offset, bytes);
    this.written[file] = written;
    if (written - (this.lastAck[file] ?? 0) >= ACK_EVERY) {
      this.lastAck[file] = written;
      await this.sendControl({ t: "ack", file, offset: written });
    }
    this.work.events.progress(this.receivedTotal(targets));
  }

  private receivedTotal(targets: TargetFiles): number {
    return targets.targets.reduce((sum, target, index) => sum + (target.final ? target.size : Math.max(this.written[index] ?? 0, this.lastAck[index] ?? 0)), 0);
  }

  private async onEnd(file: number, sha256: string): Promise<void> {
    const targets = this.work.role === "receiver" ? this.work.targets : null;
    if (!targets || !this.acceptSent) throw new ProtocolError("end before accept");
    // An empty file already in place is offered at offset 0 again: it stays as it is.
    if (!targets.targets[file]?.final) await targets.finish(file, sha256);
    await this.sendControl({ t: "file_ok", file });
    this.work.events.progress(this.receivedTotal(targets));
    await this.maybeDone();
  }

  private async maybeDone(): Promise<void> {
    const targets = this.work.role === "receiver" ? this.work.targets : null;
    if (!targets || !targets.targets.every((target) => target.final)) return;
    await this.sendControl({ t: "done" });
    this.finish({ kind: "done" });
  }
}
