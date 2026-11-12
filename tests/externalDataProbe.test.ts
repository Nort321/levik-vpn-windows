import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const trust = vi.hoisted(() => ({ ca: undefined as Buffer | undefined }));
vi.mock("node:tls", async (original) => {
  const actual = await original<typeof import("node:tls")>();
  return { ...actual, connect: (options: import("node:tls").ConnectionOptions, callback?: () => void) =>
    actual.connect({ ...options, ...(trust.ca ? { ca: trust.ca } : {}) }, callback) };
});
import { openExistingRouteProbe } from "../src/main/vpn/routeProbe";

describe("external HTTPS data proof through an authenticated private proxy", () => {
  const directory = mkdtempSync(join(tmpdir(), "levik-external-data-"));
  let bytes = 0, connections = 0;
  const sockets = new Set<import("node:stream").Duplex>();
  let remote: ReturnType<typeof httpsServer>;
  let proxy: ReturnType<typeof httpServer>;
  let proxyPort: number;
  beforeAll(async () => {
    const key = join(directory, "fixture.key"), cert = join(directory, "fixture.pem");
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
      "-days", "1", "-subj", "/CN=speed.cloudflare.com", "-addext", "subjectAltName=DNS:speed.cloudflare.com,DNS:proof.ovh.net"], { stdio: "ignore" });
    trust.ca = readFileSync(cert);
    remote = httpsServer({ key: readFileSync(key), cert: trust.ca }, (_request, response) => {
      response.writeHead(200, { "Content-Length": bytes }); response.end(Buffer.alloc(bytes, 37));
    });
    await new Promise<void>((resolve) => remote.listen(0, "127.0.0.1", resolve));
    const address = remote.address(); if (!address || typeof address === "string") throw new Error("Missing fixture port");
    proxy = httpServer();
    proxy.on("connect", (request, peer) => {
      if (request.headers["proxy-authorization"] !== "Basic " + Buffer.from("fixture:" + "b".repeat(48)).toString("base64")) { peer.destroy(); return; }
      connections++;
      const upstream = connect(address.port, "127.0.0.1");
      sockets.add(peer); sockets.add(upstream);
      peer.on("error", () => upstream.destroy()); upstream.on("error", () => peer.destroy());
      peer.on("close", () => { sockets.delete(peer); upstream.destroy(); });
      upstream.on("close", () => { sockets.delete(upstream); peer.destroy(); });
      upstream.once("connect", () => { peer.write("HTTP/1.1 200 Connection Established\r\n\r\n"); peer.pipe(upstream).pipe(peer); });
    });
    await new Promise<void>((resolve) => proxy.listen(47230, "127.0.0.1", resolve));
    const local = proxy.address(); if (!local || typeof local === "string") throw new Error("Missing proxy port"); proxyPort = local.port;
  });
  afterAll(async () => {
    trust.ca = undefined;
    for (const socket of sockets) socket.destroy();
    await Promise.all([new Promise<void>((resolve) => proxy?.close(() => resolve())), new Promise<void>((resolve) => remote?.close(() => resolve()))]);
    rmSync(directory, { recursive: true });
  });
  it.each([0, 16 * 1024, 65535, 65536, 1024 * 1024])("requires at least 64 KiB, even if the response body is %i bytes", async (bodyBytes) => {
    bytes = bodyBytes;
    const before = connections;
    const session = await openExistingRouteProbe(proxyPort, { user: "fixture", password: "b".repeat(48) }, new AbortController().signal);
    try { expect(await session.verifyData?.()).toBe(bodyBytes >= 65536); }
    finally { await session.close(); }
    expect(connections - before).toBe(bodyBytes >= 65536 ? 1 : 2);
  });
});
