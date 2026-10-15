import { createSocket } from "node:dgram";
import { Socket } from "node:net";
import { GAME_PROBE_USER } from "../gameRoutes";
import { RELAY_PORT } from "./wire";

export interface RelayPath { send(data: Buffer): void; close(): void }
export async function openRelayPath(port: number, password: string, receive: (data: Buffer) => void,
  signal: AbortSignal): Promise<RelayPath> {
  const tcp = new Socket(); const udp = createSocket("udp4");
  let buffer = Buffer.alloc(0); let wake: (() => void) | undefined; let closed = false;
  const close = (): void => {
    if (closed) return; closed = true; tcp.destroy();
    try { udp.close(); } catch { /* Not bound yet. */ }
    wake?.(); signal.removeEventListener("abort", close);
  };
  tcp.on("error", close); tcp.on("close", close); udp.on("error", close);
  tcp.on("data", (data: Buffer) => { buffer = Buffer.concat([buffer, data]); if (buffer.length > 1024) close(); wake?.(); });
  signal.addEventListener("abort", close, { once: true });
  const timer = setTimeout(close, 3_000);
  const read = async (size: number): Promise<Buffer> => {
    while (!closed && buffer.length < size) await new Promise<void>((resolve) => { wake = resolve; });
    wake = undefined;
    if (closed) throw new Error("Game path unavailable");
    const result = buffer.subarray(0, size); buffer = buffer.subarray(size); return result;
  };
  try {
    if (signal.aborted) throw new Error("Game path cancelled");
    tcp.setNoDelay(true); tcp.connect(port, "127.0.0.1"); tcp.write(Buffer.from([5, 1, 2]));
    if (!(await read(2)).equals(Buffer.from([5, 2]))) throw new Error("Game authentication required");
    const user = Buffer.from(GAME_PROBE_USER); const pass = Buffer.from(password);
    tcp.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    if (!(await read(2)).equals(Buffer.from([1, 0]))) throw new Error("Game authentication failed");
    tcp.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
    const reply = await read(10);
    if (reply[0] !== 5 || reply[1] !== 0 || reply[3] !== 1 || !["0.0.0.0", "127.0.0.1"].includes([...reply.subarray(4, 8)].join(".")) || !reply.readUInt16BE(8)) throw new Error("Invalid Game relay");
    await new Promise<void>((resolve, reject) => {
      udp.once("error", reject); udp.once("close", () => reject(new Error("Game path closed")));
      udp.connect(reply.readUInt16BE(8), "127.0.0.1", () => { udp.removeListener("error", reject); resolve(); });
    });
    const header = Buffer.from([0, 0, 0, 1, 127, 0, 0, 1, RELAY_PORT >> 8, RELAY_PORT & 255]);
    udp.on("message", (data) => { if (data.length >= 10 && data.subarray(0, 10).equals(header)) receive(data.subarray(10)); });
    return { send: (data) => { if (!closed) udp.send(Buffer.concat([header, data]), () => {}); }, close };
  } catch (error) { close(); throw error; }
  finally { clearTimeout(timer); }
}
