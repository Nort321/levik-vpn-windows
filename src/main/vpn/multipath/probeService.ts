import { createConnection } from "node:net";
import { MAX_CONTROL_BYTES, isRecord } from "./wire";

/** One bounded request per Unix connection. No upstream error text crosses it. */
export async function probeService(socketPath: string, request: unknown): Promise<Record<string, unknown> | null> {
  const serialized = JSON.stringify(request) + "\n";
  if (!socketPath.startsWith("/") || Buffer.byteLength(serialized) > MAX_CONTROL_BYTES) return null;
  return new Promise((resolve) => {
    const socket = createConnection(socketPath); let buffer = Buffer.alloc(0); let finished = false;
    const finish = (value: Record<string, unknown> | null): void => {
      if (finished) return; finished = true; clearTimeout(timer); socket.destroy(); resolve(value);
    };
    const timer = setTimeout(() => finish(null), 1500);
    socket.on("error", () => finish(null)); socket.on("end", () => finish(null));
    socket.on("connect", () => socket.write(serialized));
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_CONTROL_BYTES) { finish(null); return; }
      const newline = buffer.indexOf(10); if (newline < 0) return;
      try { const value: unknown = JSON.parse(buffer.subarray(0, newline).toString("utf8")); finish(isRecord(value) && value.version === 2 ? value : null); }
      catch { finish(null); }
    });
  });
}
