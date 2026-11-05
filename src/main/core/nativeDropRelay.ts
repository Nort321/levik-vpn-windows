import { ChannelClosed, type DropSocket } from "../platform/levikDrop/framing";
import { MAX_FRAME } from "../platform/levikDrop/protocol";
import { joinRelay, type RelayEndpoint } from "../platform/levikDrop/relay";
import type { RustCore } from "./rustCore";
export interface NativeDropRelay {
  connected(): Promise<void>; read(millis: number): Promise<Buffer>; send(bytes: Buffer): Promise<void>;
  isClosed(): boolean; startKeepalive(millis: number): void; watchIdle(millis: number): void;
  close(): void; closeGracefully(): void;
}
export type StartDropRelay = (endpoints: RelayEndpoint[], token: string, onClosed: () => void) => NativeDropRelay;
export function isNativeDropRelay(value: unknown): value is NativeDropRelay {
  return typeof value === "object" && value !== null && "connected" in value && typeof value.connected === "function"
    && "read" in value && typeof value.read === "function" && "send" in value && typeof value.send === "function"
    && "isClosed" in value && typeof value.isClosed === "function" && "startKeepalive" in value && typeof value.startKeepalive === "function"
    && "watchIdle" in value && typeof value.watchIdle === "function" && "close" in value && typeof value.close === "function"
    && "closeGracefully" in value && typeof value.closeGracefully === "function";
}
interface ClosedState { ended: boolean; error: Error; listeners: Array<(error: Error) => void>; report(): void }
function notify(state: ClosedState): void {
  if (state.ended) return; state.ended = true;
  for (const listener of state.listeners.splice(0)) { try { listener(state.error); } catch { try { state.report(); } catch {} } }
}
// A separate activation context holds only WeakRef, never the caller's native
// handle/report/controller bindings. A passive native observer cannot root its owner.
function observer(weak: WeakRef<ClosedState>): () => void {
  return () => { const state = weak.deref(); if (state) notify(state); };
}
function promise(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value && typeof value.then === "function";
}
const REASONS = new Set(["aborted","relay timed out","connection closed","bad frame","silent","timed out","write queue full"]);
function refused(error: unknown): ChannelClosed { return new ChannelClosed(error instanceof Error && REASONS.has(error.message) ? error.message : "relay connection failed"); }
function interval(value: number): void { if (!Number.isSafeInteger(value) || value < 0 || value > 300_000) throw new ChannelClosed("bad interval"); }
/** Choose before any dial/token bytes. Active connections never fall back to
 * Node, and keep their transport across mode changes. Abort owns the dial only:
 * RelayLink aborts that signal before its final graceful control write. */
export function joinRelayWithCore(current: () => RustCore, start: () => StartDropRelay | undefined, report: () => void,
  typescript: typeof joinRelay = joinRelay): typeof joinRelay {
  return async (endpoints, token, signal) => {
    if (signal.aborted) throw new ChannelClosed("aborted");
    const core = current(), open = start();
    if (core.mode !== "rust" || !open) return typescript(endpoints,token,signal);
    const state: ClosedState = { ended:false, error:new ChannelClosed(), listeners:[], report };
    const native = core.runNative<NativeDropRelay | null>("levikDrop.relay.activate",
      () => open([...endpoints],token,observer(new WeakRef(state))), () => null,isNativeDropRelay);
    if (!native) return typescript(endpoints,token,signal);
    let disposed = false, closing = false;
    const close = (): void => { if (!disposed) { disposed = true; try { native.close(); } catch { try { report(); } catch {} } } notify(state); };
    const failed = (error: unknown): ChannelClosed => { state.error = refused(error); close(); return state.error; };
    const aborted = (): void => { state.error = new ChannelClosed("aborted"); close(); };
    signal.addEventListener("abort",aborted,{once:true});
    try {
      if (signal.aborted) { aborted(); throw state.error; }
      const pending: unknown = native.connected(); if (!promise(pending) || await pending !== undefined) throw new ChannelClosed();
      if (signal.aborted) { aborted(); throw state.error; }
    } catch (error) { throw failed(error); }
    finally { signal.removeEventListener("abort",aborted); }
    const socket: DropSocket = {
      get closed() {
        try { const closed: unknown = native.isClosed(); if (typeof closed !== "boolean") throw new ChannelClosed(); return state.ended || closed; }
        catch (error) { failed(error); return true; }
      },
      next: async (millis = 0) => {
        try {
          interval(millis); const pending: unknown = native.read(millis); if (!promise(pending)) throw new ChannelClosed();
          const bytes = await pending;
          if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FRAME || bytes.length === 1 && bytes[0] === 0x7f) throw new ChannelClosed("bad frame");
          return bytes;
        } catch (error) { if (error instanceof Error && error.message === "timed out") throw new ChannelClosed("timed out"); throw failed(error); }
      },
      send: async (bytes) => {
        try {
          if (disposed || closing) throw new ChannelClosed();
          if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FRAME) throw new ChannelClosed("bad frame");
          const pending: unknown = native.send(bytes); if (!promise(pending) || await pending !== undefined) throw new ChannelClosed();
        } catch (error) { throw failed(error); }
      },
      startKeepalive: (millis = 20_000) => { try { interval(millis); native.startKeepalive(millis); } catch (error) { throw failed(error); } },
      watchIdle: (millis) => { try { interval(millis); native.watchIdle(millis); } catch (error) { throw failed(error); } },
      onClose: (listener) => { if (socket.closed) { try { listener(state.error); } catch { try { report(); } catch {} } } else state.listeners.push(listener); },
      close,
      closeGracefully: () => { if (disposed || closing) return; closing = true; try { native.closeGracefully(); } catch (error) { failed(error); } },
    };
    return socket;
  };
}
