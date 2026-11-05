import { type DropSocket } from "../platform/levikDrop/framing";
import { LanListener, dialLan, privateAddresses, type DropLan, type LanAcceptor } from "../platform/levikDrop/lan";
import { isNativeDropConnection, isPromise, nativeDropConnection, type NativeDropConnection } from "./nativeDropConnection";
import type { RustCore } from "./rustCore";

export interface NativeLanDialer {
  read(onClosed: () => void): Promise<NativeDropConnection | null>;
  close(): void;
}
export interface NativeLanListener {
  listen(): Promise<{ addresses: string[]; port: number } | null>;
  accepted(onClosed: () => void): Promise<NativeDropConnection | null>;
  close(): void;
}
export type StartDropLanDial = (addresses: string[], port: number, transfer: Buffer, key: Buffer) => NativeLanDialer;
export type OpenDropLanListener = (addresses: string[], transfer: Buffer, key: Buffer) => NativeLanListener;
export interface NativeLanConstructors { dial: StartDropLanDial; listen: OpenDropLanListener }
export function isNativeLanDialer(value: unknown): value is NativeLanDialer {
  return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function" && "close" in value && typeof value.close === "function";
}
export function isNativeLanListener(value: unknown): value is NativeLanListener {
  return typeof value === "object" && value !== null && "listen" in value && typeof value.listen === "function"
    && "accepted" in value && typeof value.accepted === "function" && "close" in value && typeof value.close === "function";
}
function listening(value: unknown, allowed: readonly string[]): value is { addresses: string[]; port: number } {
  return typeof value === "object" && value !== null && "port" in value && typeof value.port === "number"
    && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65535 && "addresses" in value && Array.isArray(value.addresses)
    && value.addresses.length > 0 && value.addresses.length <= 8 && new Set(value.addresses).size === value.addresses.length
    && value.addresses.every((address: unknown) => typeof address === "string" && allowed.includes(address));
}
/** The selected attempt owns pending listeners/dials. Adopted connections belong
 * to Session, so cancelling discovery cannot drop its final graceful write. */
export function dropLanWithCore(core: RustCore, constructors: NativeLanConstructors | undefined, report: () => void,
  typescript: Pick<DropLan, "open" | "dial"> = { open: LanListener.open, dial: dialLan }, discover = privateAddresses): DropLan | null {
  if (core.mode !== "rust" || !constructors) return null;
  let closed = false;
  const owners = new Set<{ close(): void }>();
  const retire = (owner: { close(): void }): void => {
    if (!owners.delete(owner)) return;
    try { owner.close(); } catch { try { report(); } catch {} }
  };
  const adopt = (value: unknown, prepared: ReturnType<typeof nativeDropConnection>): DropSocket | null => {
    if (value === null) return null;
    if (!isNativeDropConnection(value)) {
      if (typeof value === "object" && value !== null && "close" in value && typeof value.close === "function") {
        try { value.close(); } catch { try { report(); } catch {} }
      }
      throw new Error("Invalid native LAN connection");
    }
    const socket = prepared.adopt(value);
    if (closed) { socket.close(); return null; }
    return socket;
  };
  return {
    async open(transfer, key): Promise<LanAcceptor | null> {
      if (closed) return null;
      const addresses = discover();
      if (addresses.length === 0) return null;
      const native = core.runNative<NativeLanListener | null>("levikDrop.lan.listen.activate",
        () => constructors.listen(addresses, transfer, key), () => null, isNativeLanListener);
      if (!native) {
        const result = await typescript.open(transfer, key);
        if (closed) { result?.close(); return null; }
        return result;
      }
      owners.add(native);
      try {
        const pending: unknown = native.listen();
        if (!isPromise(pending)) throw new Error("Invalid native LAN listen");
        const info = await pending;
        if (closed || info === null) { retire(native); return null; }
        if (!listening(info, addresses)) throw new Error("Invalid native LAN address");
        let accepted = false;
        return {
          addresses: [...info.addresses], port: info.port,
          async accepted() {
            if (accepted || closed || !owners.has(native)) return null;
            accepted = true;
            const prepared = nativeDropConnection(report);
            try {
              const ready: unknown = native.accepted(prepared.onClosed);
              if (!isPromise(ready)) throw new Error("Invalid native LAN accept");
              const socket = adopt(await ready, prepared);
              if (!owners.has(native)) { socket?.close(); return null; }
              return socket;
            } catch { return null; }
            finally { retire(native); }
          },
          close: () => retire(native),
        };
      } catch { retire(native); return null; }
    },
    async dial(addresses, port, transfer, key) {
      if (closed) return null;
      const native = core.runNative<NativeLanDialer | null>("levikDrop.lan.dial.activate",
        () => constructors.dial([...addresses], port, transfer, key), () => null, isNativeLanDialer);
      if (!native) {
        const socket = await typescript.dial(addresses, port, transfer, key);
        if (closed) { socket?.close(); return null; }
        return socket;
      }
      owners.add(native);
      const prepared = nativeDropConnection(report);
      try {
        const pending: unknown = native.read(prepared.onClosed);
        if (!isPromise(pending)) throw new Error("Invalid native LAN dial");
        return adopt(await pending, prepared);
      } catch { return null; }
      finally { retire(native); }
    },
    close() {
      if (closed) return;
      closed = true;
      for (const owner of [...owners]) retire(owner);
    },
  };
}
