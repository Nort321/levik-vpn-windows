import type { Socket } from "node:net";
import { KEEPALIVE, MAX_FRAME } from "./protocol";

/**
 * `u32 big-endian length | payload` over a socket, docs/levik-drop.md
 * "Relay". Incoming frames wait in a queue the session pulls from; the socket
 * pauses while the queue holds more than a few MiB, so a slow disk slows the
 * peer down instead of filling memory.
 */

export class ChannelClosed extends Error {
  constructor(message = "connection closed") {
    super(message);
  }
}

const PAUSE_ABOVE = 4 * 1024 * 1024;
const RESUME_BELOW = 1024 * 1024;

interface Waiter {
  resolve(frame: Buffer): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout> | null;
}

export class FrameSocket {
  private chunks: Buffer[] = [];
  private buffered = 0;
  private readonly queue: Buffer[] = [];
  private queued = 0;
  private waiter: Waiter | null = null;
  private failure: Error | null = null;
  private keepalive: ReturnType<typeof setInterval> | null = null;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private idleMs = 0;
  private readonly closeListeners: Array<(error: Error) => void> = [];

  constructor(readonly socket: Socket, private readonly maxFrame = MAX_FRAME) {
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 15_000);
    socket.on("data", (chunk: Buffer) => this.onData(chunk));
    socket.on("error", (error) => this.shutdown(new ChannelClosed(error.message)));
    socket.on("close", () => this.shutdown(new ChannelClosed()));
    socket.on("end", () => this.shutdown(new ChannelClosed()));
  }

  get closed(): boolean {
    return this.failure !== null;
  }

  onClose(listener: (error: Error) => void): void {
    if (this.failure) listener(this.failure);
    else this.closeListeners.push(listener);
  }

  /** The next frame; a keepalive frame never comes out. */
  next(timeoutMs = 0): Promise<Buffer> {
    const frame = this.queue.shift();
    if (frame) {
      this.queued -= frame.length;
      if (this.queued < RESUME_BELOW && this.socket.isPaused()) this.socket.resume();
      return Promise.resolve(frame);
    }
    if (this.failure) return Promise.reject(this.failure);
    if (this.waiter) return Promise.reject(new Error("concurrent read"));
    return new Promise((resolve, reject) => {
      const timer = timeoutMs > 0 ? setTimeout(() => {
        this.waiter = null;
        reject(new ChannelClosed("timed out"));
      }, timeoutMs) : null;
      this.waiter = { resolve, reject, timer };
    });
  }

  /** Resolves once the socket took the frame (waits for drain when its buffer is full). */
  send(payload: Buffer): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    if (payload.length < 1 || payload.length > this.maxFrame) return Promise.reject(new Error("bad frame size"));
    const head = Buffer.alloc(4);
    head.writeUInt32BE(payload.length);
    const flushed = this.socket.write(Buffer.concat([head, payload]));
    if (flushed) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const done = (): void => {
        this.socket.off("drain", done);
        this.socket.off("close", closed);
        resolve();
      };
      const closed = (): void => {
        this.socket.off("drain", done);
        this.socket.off("close", closed);
        reject(this.failure ?? new ChannelClosed());
      };
      this.socket.on("drain", done);
      this.socket.on("close", closed);
    });
  }

  /** A keepalive frame every `ms` (the relay closes connections silent for 60 s). */
  startKeepalive(ms = 20_000): void {
    if (this.keepalive) return;
    this.keepalive = setInterval(() => void this.send(KEEPALIVE).catch(() => {}), ms);
  }

  /** Closes the connection when nothing, not even a keepalive, came for `ms`; 0 stops it. */
  watchIdle(ms: number): void {
    this.idleMs = ms;
    this.touch();
  }

  close(): void {
    this.socket.destroy();
    this.shutdown(new ChannelClosed());
  }

  /** Lets frames already written go out (pause, cancel), then closes. */
  closeGracefully(): void {
    if (this.failure) return;
    this.socket.end();
    setTimeout(() => this.close(), 2_000).unref();
  }

  private touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
    if (this.idleMs > 0 && !this.failure) {
      this.idleTimer = setTimeout(() => {
        this.socket.destroy();
        this.shutdown(new ChannelClosed("silent"));
      }, this.idleMs);
    }
  }

  private onData(chunk: Buffer): void {
    if (this.failure) return;
    this.touch();
    this.chunks.push(chunk);
    this.buffered += chunk.length;
    for (;;) {
      if (this.buffered < 4) return;
      const head = this.peek(4);
      const length = head.readUInt32BE(0);
      if (length < 1 || length > this.maxFrame) {
        this.socket.destroy();
        this.shutdown(new ChannelClosed("bad frame"));
        return;
      }
      if (this.buffered < 4 + length) return;
      this.consume(4);
      const frame = this.consume(length);
      if (frame.length === 1 && frame[0] === KEEPALIVE[0]) continue;
      this.deliver(frame);
    }
  }

  private deliver(frame: Buffer): void {
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = null;
      if (waiter.timer) clearTimeout(waiter.timer);
      waiter.resolve(frame);
      return;
    }
    this.queue.push(frame);
    this.queued += frame.length;
    if (this.queued > PAUSE_ABOVE) this.socket.pause();
  }

  private peek(length: number): Buffer {
    const first = this.chunks[0];
    if (first && first.length >= length) return first.subarray(0, length);
    return Buffer.concat(this.chunks).subarray(0, length);
  }

  private consume(length: number): Buffer {
    const first = this.chunks[0];
    if (first && first.length >= length) {
      const part = first.subarray(0, length);
      if (first.length === length) this.chunks.shift();
      else this.chunks[0] = first.subarray(length);
      this.buffered -= length;
      return Buffer.from(part);
    }
    const all = Buffer.concat(this.chunks);
    const part = Buffer.from(all.subarray(0, length));
    this.chunks = all.length > length ? [all.subarray(length)] : [];
    this.buffered -= length;
    return part;
  }

  private shutdown(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    if (this.keepalive) clearInterval(this.keepalive);
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.keepalive = null;
    this.idleTimer = null;
    const waiter = this.waiter;
    this.waiter = null;
    // A waiting reader means an empty queue; queued frames are still read first.
    if (waiter) {
      if (waiter.timer) clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    for (const listener of this.closeListeners.splice(0)) listener(error);
  }
}
