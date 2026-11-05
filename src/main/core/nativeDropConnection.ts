import { ChannelClosed, type DropSocket } from "../platform/levikDrop/framing";
import { MAX_FRAME } from "../platform/levikDrop/protocol";

export interface NativeDropConnection {
  read(millis: number): Promise<Buffer>;
  send(bytes: Buffer): Promise<void>;
  isClosed(): boolean;
  startKeepalive(millis: number): void;
  watchIdle(millis: number): void;
  close(): void;
  closeGracefully(): void;
}
export function isNativeDropConnection(value: unknown): value is NativeDropConnection {
  return typeof value === "object" && value !== null
    && "read" in value && typeof value.read === "function" && "send" in value && typeof value.send === "function"
    && "isClosed" in value && typeof value.isClosed === "function"
    && "startKeepalive" in value && typeof value.startKeepalive === "function"
    && "watchIdle" in value && typeof value.watchIdle === "function"
    && "close" in value && typeof value.close === "function"
    && "closeGracefully" in value && typeof value.closeGracefully === "function";
}
interface ClosedState { ended: boolean; error: Error; listeners: Array<(error: Error) => void>; report(): void }
function notify(state: ClosedState): void {
  if (state.ended) return;
  state.ended = true;
  for (const listener of state.listeners.splice(0)) {
    try { listener(state.error); } catch { try { state.report(); } catch {} }
  }
}
// This activation context holds only WeakRef, never the native handle or the
// caller's controller/report bindings. A passive observer cannot root its owner.
function observer(weak: WeakRef<ClosedState>): () => void {
  return () => { const state = weak.deref(); if (state) notify(state); };
}
export function isPromise(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value && typeof value.then === "function";
}
const REASONS = new Set(["aborted", "relay timed out", "connection closed", "bad frame", "silent", "timed out", "write queue full"]);
export function dropTransportError(error: unknown): ChannelClosed {
  return new ChannelClosed(error instanceof Error && REASONS.has(error.message) ? error.message : "relay connection failed");
}
function interval(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 300_000) throw new ChannelClosed("bad interval");
}
/** Prepare a weak observer before the native owner exists, then adopt it once. */
export function nativeDropConnection(report: () => void): { onClosed(): void; adopt(native: NativeDropConnection): DropSocket } {
  const state: ClosedState = { ended: false, error: new ChannelClosed(), listeners: [], report };
  let adopted = false;
  return {
    onClosed: observer(new WeakRef(state)),
    adopt(native) {
      if (adopted) throw new ChannelClosed();
      adopted = true;
      let disposed = false, closing = false;
      const close = (): void => {
        if (!disposed) { disposed = true; try { native.close(); } catch { try { report(); } catch {} } }
        notify(state);
      };
      const failed = (error: unknown): ChannelClosed => { state.error = dropTransportError(error); close(); return state.error; };
      const socket: DropSocket = {
        get closed() {
          try {
            const closed: unknown = native.isClosed();
            if (typeof closed !== "boolean") throw new ChannelClosed();
            return state.ended || closed;
          } catch (error) { failed(error); return true; }
        },
        next: async (millis = 0) => {
          try {
            interval(millis);
            const pending: unknown = native.read(millis);
            if (!isPromise(pending)) throw new ChannelClosed();
            const bytes = await pending;
            if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FRAME || bytes.length === 1 && bytes[0] === 0x7f) throw new ChannelClosed("bad frame");
            return bytes;
          } catch (error) {
            if (error instanceof Error && error.message === "timed out") throw new ChannelClosed("timed out");
            throw failed(error);
          }
        },
        send: async (bytes) => {
          try {
            if (disposed || closing) throw new ChannelClosed();
            if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FRAME) throw new ChannelClosed("bad frame");
            const pending: unknown = native.send(bytes);
            if (!isPromise(pending) || await pending !== undefined) throw new ChannelClosed();
          } catch (error) { throw failed(error); }
        },
        startKeepalive: (millis = 20_000) => { try { interval(millis); native.startKeepalive(millis); } catch (error) { throw failed(error); } },
        watchIdle: (millis) => { try { interval(millis); native.watchIdle(millis); } catch (error) { throw failed(error); } },
        onClose: (listener) => {
          if (socket.closed) { try { listener(state.error); } catch { try { report(); } catch {} } }
          else state.listeners.push(listener);
        },
        close,
        closeGracefully: () => {
          if (disposed || closing) return;
          closing = true;
          try { native.closeGracefully(); } catch (error) { failed(error); }
        },
      };
      return socket;
    },
  };
}
