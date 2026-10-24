import { createHash } from "node:crypto";
import { connect } from "node:tls";
import type { TLSSocket } from "node:tls";
import { FrameSocket } from "./framing";

/** docs/levik-drop.md "Relay": TLS with the pinned key, then the join frame. */

export interface RelayEndpoint {
  host: string;
  port: number;
  /** base64url SHA-256 of the certificate's SPKI. */
  pin: string;
}

export type RelayControl =
  | { t: "wait" }
  | { t: "peer" }
  | { t: "gone" }
  | { t: "end"; reason: string };

const DIAL_TIMEOUT_MS = 6_000;

export function spkiPin(socket: TLSSocket): string | null {
  const certificate = socket.getPeerX509Certificate();
  if (!certificate) return null;
  const spki = certificate.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("base64url");
}

function dialOne(endpoint: RelayEndpoint, signal: AbortSignal): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    // The certificate is self-signed: the pin below is the only check, made
    // before a byte of ours goes out.
    const socket = connect({ host: endpoint.host, port: endpoint.port, rejectUnauthorized: false, minVersion: "TLSv1.2" });
    const finish = (error: Error | null): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", aborted);
      socket.off("error", failed);
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        resolve(socket);
      }
    };
    const failed = (error: Error): void => finish(error);
    const aborted = (): void => finish(new Error("aborted"));
    const timer = setTimeout(() => finish(new Error("relay timed out")), DIAL_TIMEOUT_MS);
    socket.once("secureConnect", () => finish(spkiPin(socket) === endpoint.pin ? null : new Error("relay answered with another key")));
    socket.on("error", failed);
    signal.addEventListener("abort", aborted);
  });
}

/** Tries the endpoints in order and joins the first that answers with its pin. */
export async function joinRelay(endpoints: readonly RelayEndpoint[], token: string, signal: AbortSignal): Promise<FrameSocket> {
  let last: unknown = new Error("no relay endpoints");
  for (const endpoint of endpoints) {
    if (signal.aborted) throw new Error("aborted");
    try {
      const socket = await dialOne(endpoint, signal);
      const frames = new FrameSocket(socket);
      await frames.send(Buffer.from(JSON.stringify({ v: 1, token }), "utf8"));
      frames.startKeepalive();
      return frames;
    } catch (error) {
      last = error;
    }
  }
  throw last instanceof Error ? last : new Error("relay unreachable");
}

/** A frame from the relay itself (first byte 0x00), or null for one from the other app. */
export function relayControl(frame: Buffer): RelayControl | null {
  if (frame[0] !== 0x00) return null;
  try {
    const value: unknown = JSON.parse(frame.subarray(1).toString("utf8"));
    if (typeof value !== "object" || value === null) return { t: "end", reason: "bad_control" };
    const { t, reason } = value as { t?: unknown; reason?: unknown };
    if (t === "wait" || t === "peer" || t === "gone") return { t };
    if (t === "end") return { t, reason: typeof reason === "string" ? reason.slice(0, 40) : "ended" };
  } catch {
    // Falls through: an unreadable control ends the connection.
  }
  return { t: "end", reason: "bad_control" };
}

export function parseEndpoints(value: unknown): RelayEndpoint[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item): RelayEndpoint[] => {
    if (typeof item !== "object" || item === null) return [];
    const { host, port, pin } = item as Record<string, unknown>;
    if (typeof host !== "string" || !/^[A-Za-z0-9.:-]{1,253}$/.test(host)) return [];
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65_535) return [];
    if (typeof pin !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(pin)) return [];
    return [{ host, port, pin }];
  }).slice(0, 4);
}
