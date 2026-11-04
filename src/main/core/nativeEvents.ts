import { LIVE_EVENTS, type LiveEvent } from "../platform/liveEvents";

/** Optional typed capability of the device handle. Never enters generic call(). */
export interface NativeEventStream {
  read(): Promise<string>;
  close(): void;
}

export function isNativeEventStream(value: unknown): value is NativeEventStream {
  return typeof value === "object" && value !== null
    && "read" in value && typeof value.read === "function"
    && "close" in value && typeof value.close === "function";
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Backpressure and AbortSignal cover the handshake as well as response reads.
 * Empty batches are heartbeats; they must refresh the existing idle timer. */
export function nativeEventSource(handle: NativeEventStream, signal: AbortSignal,
  failure: (status: number | null, rejected: boolean) => Error): ReadableStream<LiveEvent[]> {
  let closed = false;
  let abort: () => void;
  const cleanup = () => {
    closed = true;
    signal.removeEventListener("abort", abort);
    try { handle.close(); } catch { /* Cleanup must still finish the reader. */ }
  };
  return new ReadableStream<LiveEvent[]>({
    start(controller) {
      abort = () => {
        if (closed) return;
        cleanup();
        controller.error(new DOMException("Aborted", "AbortError"));
      };
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    },
    async pull(controller) {
      let reported: Error | null = null;
      try {
        const result: unknown = JSON.parse(await handle.read());
        if (closed) return;
        if (!record(result)) throw failure(null, false);
        if (result.ok === false) {
          const error = record(result.error) ? result.error : null;
          const status = typeof error?.status === "number" && Number.isInteger(error.status)
            && error.status >= 100 && error.status <= 599 ? error.status : null;
          reported = failure(status, error?.authenticationRejected === true && error.code === "unauthorized");
          throw reported;
        }
        const value = record(result.value) ? result.value : null;
        if (result.ok !== true || !value || typeof value.done !== "boolean" || !Array.isArray(value.events)
          || value.events.length > 4096 || !value.events.every((event): event is LiveEvent =>
            typeof event === "string" && (LIVE_EVENTS as readonly string[]).includes(event))) throw failure(null, false);
        if (value.done) { cleanup(); controller.close(); }
        else controller.enqueue(value.events);
      } catch (error) {
        if (closed) return;
        cleanup();
        // Native errors can include implementation details. Only the error
        // produced by our local factory is allowed to cross this boundary.
        controller.error(error === reported ? reported : failure(null, false));
      }
    },
    cancel() { if (!closed) cleanup(); },
  });
}
