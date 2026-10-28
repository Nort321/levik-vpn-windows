import { randomBytes } from "node:crypto";
import { connect as http2Connect, constants } from "node:http2";
import { request } from "node:http";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { isIP, type Socket } from "node:net";
import { XRAY_STATS_ENDPOINT } from "./xrayStats";
import type { ServiceRouteAuth } from "./serviceRoutes";

/** Pinned Xray26.7.28 command.proto fields 1 and 2; service API is password protected. */
export async function overrideServiceRoute(balancer: string, target: string, endpoint = XRAY_STATS_ENDPOINT, auth?: ServiceRouteAuth): Promise<void> {
  if (!/^levik-service-(?:main|rule-\d{1,3})$/.test(balancer)
    || !/^(?:levik-service-endpoint-\d{1,2}|levik-block|direct|levik-direct)$/.test(target)
    || !/^127\.0\.0\.1:\d{1,5}$/.test(endpoint)) throw new Error("Некорректный сервисный маршрут");
  await serviceRpc("/xray.app.router.command.RoutingService/OverrideBalancerTarget",
    Buffer.concat([field(1, balancer), field(2, target)]), endpoint, auth);
}
export async function queryServiceRouteStats(auth: ServiceRouteAuth): Promise<{ uplink: number; downlink: number }> {
  const { uplink, downlink } = await queryServiceRouteStatistics(auth);
  return { uplink, downlink };
}
/** Missing counters are different from observed zero traffic when deciding whether a live switch is safe. */
export async function queryServiceRouteStatistics(auth: ServiceRouteAuth): Promise<{ uplink: number; downlink: number; initialized: boolean }> {
  const response = await serviceRpc("/xray.app.stats.command.StatsService/QueryStats", field(1, "inbound>>>levik-tun-in>>>traffic>>>"), XRAY_STATS_ENDPOINT, auth);
  return decodeServiceRouteStatistics(response);
}
export function decodeServiceRouteStatistics(response: Buffer): { uplink: number; downlink: number; initialized: boolean } {
  let uplink = 0; let downlink = 0; let offset = 0;
  let seenUplink = false; let seenDownlink = false; let duplicate = false;
  while (offset < response.length) {
    if (offset + 5 > response.length || response[offset] !== 0) throw new Error("Некорректная статистика ядра");
    const length = response.readUInt32BE(offset + 1); offset += 5;
    if (offset + length > response.length) throw new Error("Некорректная статистика ядра");
    const message = response.subarray(offset, offset + length); offset += length;
    for (const stat of protobufFields(message)) {
      if (stat.id !== 1 || !Buffer.isBuffer(stat.value)) continue;
      let name = ""; let value = 0;
      for (const item of protobufFields(stat.value)) {
        if (item.id === 1 && Buffer.isBuffer(item.value)) name = item.value.toString();
        if (item.id === 2 && typeof item.value === "bigint") {
          if (item.value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Некорректный счётчик ядра");
          value = Number(item.value);
        }
      }
      if (name === "inbound>>>levik-tun-in>>>traffic>>>uplink") { duplicate ||= seenUplink; uplink = value; seenUplink = true; }
      if (name === "inbound>>>levik-tun-in>>>traffic>>>downlink") { duplicate ||= seenDownlink; downlink = value; seenDownlink = true; }
    }
  }
  return { uplink, downlink, initialized: seenUplink && seenDownlink && !duplicate };
}
function protobufFields(message: Buffer): Array<{ id: number; value: Buffer | bigint }> {
  const fields: Array<{ id: number; value: Buffer | bigint }> = []; let offset = 0;
  const read = (): bigint => {
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      if (offset >= message.length) throw new Error("Некорректная статистика ядра");
      const byte = message[offset++]!; value |= BigInt(byte & 127) << shift;
      if (!(byte & 128)) return value;
    }
    throw new Error("Некорректная статистика ядра");
  };
  while (offset < message.length) {
    const tag = read(); const wire = Number(tag & 7n); const id = Number(tag >> 3n);
    if (wire === 0) fields.push({ id, value: read() });
    else if (wire === 2) {
      const length = Number(read());
      if (!Number.isSafeInteger(length) || length < 0 || offset + length > message.length) throw new Error("Некорректная статистика ядра");
      fields.push({ id, value: message.subarray(offset, offset + length) }); offset += length;
    } else if (wire === 1 || wire === 5) { offset += wire === 1 ? 8 : 4; if (offset > message.length) throw new Error("Некорректная статистика ядра"); }
    else throw new Error("Некорректная статистика ядра");
  }
  return fields;
}
async function serviceRpc(path: string, message: Buffer, endpoint: string, auth?: ServiceRouteAuth): Promise<Buffer> {
  const socket = auth ? await openServiceApi(auth) : undefined;
  const session = http2Connect(`http://${endpoint}`, socket ? { createConnection: () => socket } : {});
  session.unref();
  const frame = Buffer.alloc(5 + message.length); frame.writeUInt32BE(message.length, 1); message.copy(frame, 5);
  return await new Promise<Buffer>((resolve, reject) => {
    let settled = false; let status: string | undefined; let httpStatus = 0; let bytes = 0; const chunks: Buffer[] = [];
    const done = (error?: Error): void => {
      if (settled) return; settled = true; clearTimeout(timer); session.destroy();
      if (error) reject(error); else resolve(Buffer.concat(chunks, bytes));
    };
    const timer = setTimeout(() => done(new Error("API маршрутизации не ответил")), 3500);
    session.once("error", () => done(new Error("API маршрутизации недоступен")));
    const req = session.request({ ":method": "POST", ":path": path, "content-type": "application/grpc", te: "trailers", "grpc-timeout": "3000m" });
    req.on("response", (headers) => { httpStatus = Number(headers[":status"] ?? 0); if (headers["grpc-status"] !== undefined) status = String(headers["grpc-status"]); });
    req.on("trailers", (headers) => { if (headers["grpc-status"] !== undefined) status = String(headers["grpc-status"]); });
    req.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 256 * 1024) { req.close(constants.NGHTTP2_CANCEL); done(new Error("Некорректный ответ ядра")); } else chunks.push(chunk); });
    req.once("error", () => done(new Error("API маршрутизации недоступен")));
    req.once("end", () => done(httpStatus === 200 && status === "0" ? undefined : new Error("Ядро не применило сервисный маршрут")));
    req.end(frame);
  });
}
function field(number: number, value: string): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length >= 128) throw new Error("Некорректный параметр API ядра");
  return Buffer.concat([Buffer.from([(number << 3) | 2, bytes.length]), bytes]);
}
function proxyAuthorization(auth: ServiceRouteAuth): string { return `Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`; }
function openServiceApi(auth: ServiceRouteAuth): Promise<Socket> {
  if ((!Number.isInteger(auth.port) || auth.port < 1024 || auth.port > 65535) || !/^[a-z0-9-]{1,32}$/.test(auth.user) || !/^[0-9a-f]{48}$/.test(auth.password)) return Promise.reject(new Error("Некорректный канал API ядра"));
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port: auth.port, method: "CONNECT", path: "levik-service-api:80", agent: false,
      headers: { "Proxy-Authorization": proxyAuthorization(auth) } });
    let settled = false;
    const finish = (error: Error): void => { if (settled) return; settled = true; clearTimeout(timer); req.destroy(); reject(error); };
    const timer = setTimeout(() => finish(new Error("API ядра не ответил")), 3500);
    req.once("error", () => finish(new Error("API ядра недоступен")));
    req.once("response", () => finish(new Error("API ядра отклонил авторизацию")));
    req.once("connect", (response, socket, head) => {
      if (settled || response.statusCode !== 200 || head.length > 16384) { socket.destroy(); finish(new Error("API ядра отклонил авторизацию")); return; }
      if (head.length) socket.unshift(head);
      settled = true; clearTimeout(timer); resolve(socket);
    }); req.end();
  });
}

/** Verified TLS through one fixed ordinary outbound, using a session-authenticated loopback proxy. */
export async function probeServiceRoute(port: number, auth: ServiceRouteAuth): Promise<boolean> {
  if (!Number.isInteger(port) || port < 47200 || port > 47231) return false;
  for (const target of [{ address: "1.1.1.1", name: "cloudflare-dns.com" }, { address: "8.8.8.8", name: "dns.google" }]) {
    if (await probe(port, target.address, target.name, auth)) return true;
  }
  return false;
}
function probe(port: number, address: string, servername: string, auth: ServiceRouteAuth): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false; let socket: Socket | undefined; let tls: TLSSocket | undefined;
    const req = request({ hostname: "127.0.0.1", port, method: "CONNECT", path: `${address}:443`, agent: false,
      headers: { "Proxy-Authorization": proxyAuthorization(auth) } });
    const finish = (ok: boolean): void => { if (settled) return; settled = true; clearTimeout(timer); tls?.destroy(); socket?.destroy(); req.destroy(); resolve(ok); };
    const timer = setTimeout(() => finish(false), 4500);
    req.once("error", () => finish(false)); req.once("response", () => finish(false));
    req.once("connect", (response, connected, head) => {
      socket = connected;
      if (settled || response.statusCode !== 200 || head.length) return finish(false);
      socket.once("error", () => finish(false)); tls = tlsConnect({ socket, servername, rejectUnauthorized: true });
      tls.once("secureConnect", () => finish(true)); tls.once("error", () => finish(false)); tls.once("close", () => finish(false));
    }); req.end();
  });
}


/** Checks an actual DNS wire answer through the candidate, independently of transport-only main health. */
export async function probeServiceRouteDns(port: number, auth: ServiceRouteAuth, resolvers: readonly string[]): Promise<boolean> {
  for (const resolver of resolvers) {
    if (await queryResolver(port, auth, resolver)) return true;
  }
  return false;
}
function dnsQuestion(): Buffer {
  const header = Buffer.alloc(12); randomBytes(2).copy(header, 0); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  return Buffer.concat([header, Buffer.from([7, ...Buffer.from("example"), 3, ...Buffer.from("com"), 0, 0, 1, 0, 1])]);
}
function dnsAnswer(value: Buffer, expectedId: number): boolean {
  if (value.length < 12 || value.readUInt16BE(0) !== expectedId || (value[2]! & 0x80) === 0
    || (value[2]! & 2) !== 0 || (value[3]! & 15) !== 0 || value.readUInt16BE(4) !== 1) return false;
  const skipName = (start: number): number => {
    let offset = start;
    for (let labels = 0; labels < 128 && offset < value.length; labels++) {
      const length = value[offset++]!;
      if (length === 0) return offset;
      if ((length & 0xc0) === 0xc0) {
        if (offset >= value.length || ((length & 63) << 8 | value[offset]!) >= value.length) return -1;
        return offset + 1;
      }
      if (length > 63 || offset + length > value.length) return -1;
      offset += length;
    }
    return -1;
  };
  let offset = skipName(12);
  if (offset < 0 || offset + 4 > value.length || value.readUInt16BE(offset) !== 1 || value.readUInt16BE(offset + 2) !== 1) return false;
  offset += 4;
  const count = value.readUInt16BE(6);
  if (count < 1 || count > 1024) return false;
  let foundAddress = false;
  for (let index = 0; index < count; index++) {
    offset = skipName(offset);
    if (offset < 0 || offset + 10 > value.length) return false;
    const type = value.readUInt16BE(offset); const recordClass = value.readUInt16BE(offset + 2);
    const length = value.readUInt16BE(offset + 8); offset += 10;
    if (offset + length > value.length) return false;
    if (type === 1 && recordClass === 1 && length === 4) foundAddress = true;
    offset += length;
  }
  return foundAddress;
}

async function queryResolver(port: number, auth: ServiceRouteAuth, resolver: string): Promise<boolean> {
  let url: URL;
  try { url = new URL(resolver); } catch { return false; }
  if (!["https:", "tcp:"].includes(url.protocol) || url.username || url.password || url.hash) return false;
  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  const destinationPort = url.port || (url.protocol === "https:" ? "443" : "53");
  const destination = `${host.includes(":") ? `[${host}]` : host}:${destinationPort}`;
  return await new Promise<boolean>((resolve) => {
    let settled = false; let socket: Socket | undefined; let tls: TLSSocket | undefined;
    let dnsRequest: ReturnType<typeof request> | undefined;
    const proxy = request({ hostname: "127.0.0.1", port, method: "CONNECT", path: destination, agent: false,
      headers: { "Proxy-Authorization": proxyAuthorization(auth) } });
    const finish = (ok: boolean): void => {
      if (settled) return; settled = true; clearTimeout(timer); dnsRequest?.destroy(); tls?.destroy(); socket?.destroy(); proxy.destroy(); resolve(ok);
    };
    const timer = setTimeout(() => finish(false), 3500);
    proxy.once("error", () => finish(false)); proxy.once("response", () => finish(false));
    proxy.once("connect", (response, connected, head) => {
      socket = connected;
      if (settled || response.statusCode !== 200 || head.length) return finish(false);
      socket.once("error", () => finish(false));
      const question = dnsQuestion();
      if (url.protocol === "tcp:") {
        socket.once("end", () => finish(false));
        const frame = Buffer.alloc(question.length + 2); frame.writeUInt16BE(question.length); question.copy(frame, 2);
        let buffered = Buffer.alloc(0);
        socket.on("data", (chunk: Buffer) => {
          buffered = Buffer.concat([buffered, chunk]);
          if (buffered.length > 65537) return finish(false);
          if (buffered.length >= 2 && buffered.length >= buffered.readUInt16BE(0) + 2) finish(dnsAnswer(buffered.subarray(2, buffered.readUInt16BE(0) + 2), question.readUInt16BE(0)));
        }); socket.write(frame);
      } else {
        tls = tlsConnect({ socket, host, ...(!isIP(host) ? { servername: host } : {}), rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
        tls.once("error", () => finish(false));
        tls.once("secureConnect", () => {
          if (settled || !tls) return;
          // The HTTP parser owns framing/chunking; createConnection reuses the already verified TLS socket.
          dnsRequest = request({ hostname: host, port: Number(destinationPort), method: "POST", path: `${url.pathname || "/dns-query"}${url.search}`,
            createConnection: () => tls!, headers: { Host: url.host, "Content-Type": "application/dns-message", Accept: "application/dns-message", "Content-Length": question.length } }, (res) => {
              const chunks: Buffer[] = []; let bytes = 0;
              res.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 65535) finish(false); else chunks.push(chunk); });
              res.once("error", () => finish(false));
              res.once("end", () => finish(res.statusCode === 200 && String(res.headers["content-type"] ?? "").split(";")[0]?.trim() === "application/dns-message"
                && dnsAnswer(Buffer.concat(chunks, bytes), question.readUInt16BE(0))));
            });
          dnsRequest.once("error", () => finish(false)); dnsRequest.end(question);
        });
      }
    }); proxy.end();
  });
}

/** Parse/dependency validation before replacing a working core; credentials stay on stdin. */
export async function validateServiceRouteConfig(executable: string, config: Record<string, unknown>): Promise<void> {
  const { spawn } = await import("node:child_process");
  const { dirname } = await import("node:path");
  await new Promise<void>((resolve, reject) => {
    const child = spawn(executable, ["run", "-test", "-format", "json", "-config", "stdin:"], {
      windowsHide: true, stdio: ["pipe", "ignore", "ignore"], env: { ...process.env, XRAY_LOCATION_ASSET: dirname(executable) },
    });
    const timer = setTimeout(() => { child.kill(); reject(new Error("Проверка новых маршрутов не завершилась")); }, 10000);
    child.once("error", () => { clearTimeout(timer); reject(new Error("Не удалось проверить новые маршруты")); });
    child.once("exit", (code) => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error("Ядро отклонило новые маршруты")); });
    const bytes = Buffer.from(JSON.stringify(config));
    child.stdin.on("error", () => {});
    child.stdin.end(bytes, () => bytes.fill(0));
  });
}
