import { ChannelClosed } from "../platform/levikDrop/framing";
import { joinRelay, type RelayEndpoint } from "../platform/levikDrop/relay";
import type { RustCore } from "./rustCore";
import { dropTransportError, isNativeDropConnection, isPromise, nativeDropConnection, type NativeDropConnection } from "./nativeDropConnection";

export interface NativeDropRelay extends NativeDropConnection { connected(): Promise<void> }
export type StartDropRelay = (endpoints: RelayEndpoint[], token: string, onClosed: () => void) => NativeDropRelay;
export function isNativeDropRelay(value: unknown): value is NativeDropRelay {
  return isNativeDropConnection(value) && "connected" in value && typeof value.connected === "function";
}
/** Choose before any dial/token bytes. Active connections never replay through
 * Node. Abort owns the dial only: RelayLink aborts before its graceful final send. */
export function joinRelayWithCore(current: () => RustCore, start: () => StartDropRelay | undefined, report: () => void,
  typescript: typeof joinRelay = joinRelay): typeof joinRelay {
  return async (endpoints, token, signal) => {
    if (signal.aborted) throw new ChannelClosed("aborted");
    const core = current(), open = start();
    if (core.mode !== "rust" || !open) return typescript(endpoints, token, signal);
    const prepared = nativeDropConnection(report);
    const native = core.runNative<NativeDropRelay | null>("levikDrop.relay.activate",
      () => open([...endpoints], token, prepared.onClosed), () => null, isNativeDropRelay);
    if (!native) return typescript(endpoints, token, signal);
    const socket = prepared.adopt(native);
    const aborted = (): void => socket.close();
    signal.addEventListener("abort", aborted, { once: true });
    try {
      if (signal.aborted) { aborted(); throw new ChannelClosed("aborted"); }
      const pending: unknown = native.connected();
      if (!isPromise(pending) || await pending !== undefined) throw new ChannelClosed();
      if (signal.aborted) { aborted(); throw new ChannelClosed("aborted"); }
      return socket;
    } catch (error) { socket.close(); throw dropTransportError(error); }
    finally { signal.removeEventListener("abort", aborted); }
  };
}
