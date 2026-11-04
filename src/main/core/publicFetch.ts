import type { CoreMode } from "./rustCore";

export interface NativePublicRequest {
  read(): Promise<string>;
  close(): void;
}

export interface NativePublicClient { start(input: string): NativePublicRequest }

export function isNativePublicClient(value: unknown): value is NativePublicClient {
  return typeof value === "object" && value !== null && "start" in value && typeof value.start === "function";
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The small fetch subset used by public service clients. No account headers,
 * cookies, streaming uploads, or redirects can cross this separate boundary. */
export function corePublicFetch(native: () => NativePublicClient | null, mode: () => CoreMode,
  fallback: typeof fetch = fetch): typeof fetch {
  return async (input, options = {}) => {
    const client = mode() === "rust" ? native() : null;
    if (!client) return fallback(input, options);
    const signal = options.signal;
    signal?.throwIfAborted();
    const error = () => new Error("Не удалось получить служебные данные Levik");
    let request: NativePublicRequest | null = null;
    let abort = () => {};
    try {
      if (!(typeof input === "string" || input instanceof URL) || options.credentials !== "omit"
        || options.redirect !== "error" || !(options.body === undefined || typeof options.body === "string")) throw error();
      const headers = new Headers(options.headers);
      headers.forEach((_value, name) => {
        if (!["accept", "content-type", "x-levik-client", "if-none-match"].includes(name)) throw error();
      });
      if (headers.has("content-type") && headers.get("content-type") !== "application/json") throw error();
      request = client.start(JSON.stringify({ url: input.toString(), method: options.method ?? "GET", body: options.body ?? "",
        client: headers.get("X-Levik-Client"), etag: headers.get("If-None-Match") }));
      if (!request || typeof request.read !== "function" || typeof request.close !== "function") throw error();
      const aborted = new Promise<never>((_resolve, reject) => {
        abort = () => reject(new DOMException("Aborted", "AbortError"));
        signal?.addEventListener("abort", abort, { once: true });
        if (signal?.aborted) abort();
      });
      const output: unknown = JSON.parse(await Promise.race([request.read(), aborted]));
      const value = record(output) && output.ok === true && record(output.value) ? output.value : null;
      if (!value || typeof value.status !== "number" || !Number.isInteger(value.status) || value.status < 200 || value.status > 599
        || typeof value.contentType !== "string" || value.contentType.length > 1024
        || !(value.etag === null || typeof value.etag === "string" && value.etag.length <= 1024)
        || !(value.retryAfter === null || typeof value.retryAfter === "string" && value.retryAfter.length <= 1024)
        || typeof value.body !== "string" || value.body.length > 180_000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.body)) throw error();
      const body = Buffer.from(value.body, "base64");
      if (body.length > 128 * 1024) throw error();
      const responseHeaders = new Headers({ "Content-Type": value.contentType, "Content-Length": String(body.length) });
      if (value.etag !== null) responseHeaders.set("ETag", value.etag);
      if (value.retryAfter !== null) responseHeaders.set("Retry-After", value.retryAfter);
      return new Response([204, 205, 304].includes(value.status) ? null : body,
        { status: value.status, headers: responseHeaders });
    } catch {
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      throw error();
    } finally {
      signal?.removeEventListener("abort", abort);
      try { request?.close(); } catch { /* Cleanup must not reveal native errors. */ }
    }
  };
}
