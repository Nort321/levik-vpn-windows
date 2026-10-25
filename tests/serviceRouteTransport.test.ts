import { afterEach, describe, expect, it } from "vitest";
import { spawn, execFile, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, request, type Server } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { once } from "node:events";
import { overrideServiceRoute, queryServiceRouteStats, probeServiceRouteDns } from "../src/main/vpn/serviceRouteTransport";

const executable = process.env.LEVIK_TEST_XRAY ?? resolve("../levik_vpn_macos/vendor/xray", `darwin-${process.arch}`, "xray");
let core: ChildProcessWithoutNullStreams | undefined;
let upstream: Server | undefined;
let dnsUpstream: ReturnType<typeof createTcpServer> | undefined;
afterEach(async () => {
  if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
  core = undefined;
  if (upstream) await new Promise<void>((done) => upstream!.close(() => done()));
  upstream = undefined;
  if (dnsUpstream) await new Promise<void>((done) => dnsUpstream!.close(() => done()));
  dnsUpstream = undefined;
});
async function freePort(): Promise<number> {
  const server = createTcpServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); if (!address || typeof address === "string") throw new Error("No test port");
  const port = address.port; await new Promise<void>((done) => server.close(() => done())); return port;
}
function get(proxy: number, port: number): Promise<string> {
  return new Promise((resolveBody, reject) => {
    const req = request({ hostname: "127.0.0.1", port: proxy, method: "GET", path: `http://127.0.0.1:${port}/`,
      headers: { host: `127.0.0.1:${port}` }, agent: false }, (res) => {
      let body = ""; res.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      res.once("end", () => res.statusCode === 200 ? resolveBody(body) : reject(new Error("route blocked"))); res.once("error", reject);
    });
    req.setTimeout(1000, () => req.destroy(new Error("route blocked"))); req.once("error", reject); req.end();
  });
}
async function ready(child: ChildProcessWithoutNullStreams): Promise<void> {
  await new Promise<void>((resolveReady, reject) => {
    const timer = setTimeout(() => reject(new Error("Test core did not start")), 5000);
    const onData = (chunk: Buffer): void => { if (chunk.toString().includes("started")) { clearTimeout(timer); resolveReady(); } };
    child.stdout.on("data", onData); child.stderr.on("data", onData);
    child.once("error", reject); child.once("exit", () => { clearTimeout(timer); reject(new Error("Test core exited")); });
  });
}
describe("service route transport", () => {
  it("rejects unowned balancers and arbitrary targets before contacting the core", async () => {
    await expect(overrideServiceRoute("game-balancer", "direct")).rejects.toThrow();
    await expect(overrideServiceRoute("levik-service-rule-0", "unknown-exit")).rejects.toThrow();
  });
  it.skipIf(process.platform !== "darwin" || !existsSync(executable))("switches only one live route using the real pinned core", async () => {
    // Entirely loopback: no TUN, privileges, public network, customer keys or live VPN nodes.
    const api = await freePort(); const routeA = await freePort(); const routeB = await freePort();
    upstream = createServer((_req, res) => res.end("ordinary-data")); upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
    const address = upstream.address(); if (!address || typeof address === "string") throw new Error("No upstream port");
    const config = { log: { loglevel: "info" }, api: { tag: "api", listen: `127.0.0.1:${api}`, services: ["RoutingService"] },
      inbounds: [{ tag: "route-a", listen: "127.0.0.1", port: routeA, protocol: "http" },
        { tag: "route-b", listen: "127.0.0.1", port: routeB, protocol: "http" }],
      outbounds: [{ tag: "levik-block", protocol: "blackhole" }, { tag: "levik-service-endpoint-0", protocol: "freedom" }],
      routing: { rules: [{ type: "field", inboundTag: ["route-a"], balancerTag: "levik-service-rule-0" },
        { type: "field", inboundTag: ["route-b"], outboundTag: "levik-service-endpoint-0" }],
        balancers: [{ tag: "levik-service-rule-0", selector: ["levik-block"], strategy: { type: "random" } }] } };
    core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: ["pipe", "pipe", "pipe"] });
    const started = ready(core); core.stdin.end(JSON.stringify(config)); await started;
    await expect(get(routeA, address.port)).rejects.toThrow();
    expect(await get(routeB, address.port)).toBe("ordinary-data");
    await overrideServiceRoute("levik-service-rule-0", "levik-service-endpoint-0", `127.0.0.1:${api}`);
    expect(await get(routeA, address.port)).toBe("ordinary-data");
    await overrideServiceRoute("levik-service-rule-0", "levik-block", `127.0.0.1:${api}`);
    await expect(get(routeA, address.port)).rejects.toThrow();
    expect(await get(routeB, address.port)).toBe("ordinary-data");
    expect(core.exitCode).toBeNull();
  }, 15000);
  it.skipIf(process.platform !== "darwin" || !existsSync(executable))("requires per-session authentication for API and probe ingress", async () => {
    const api = await freePort(); const probe = await freePort();
    const auth = { port: api, user: "levik-service", password: "b".repeat(48) };
    const settings = { accounts: [{ user: auth.user, pass: auth.password }] };
    const config = { log: { loglevel: "info" }, api: { tag: "levik-api", services: ["RoutingService", "StatsService"] }, stats: {},
      inbounds: [{ tag: "private-api", listen: "127.0.0.1", port: api, protocol: "http", settings },
        { tag: "private-probe", listen: "127.0.0.1", port: probe, protocol: "http", settings }],
      outbounds: [{ tag: "levik-service-endpoint-0", protocol: "freedom" }, { tag: "levik-block", protocol: "blackhole" }],
      routing: { rules: [{ type: "field", inboundTag: ["private-api"], outboundTag: "levik-api" },
        { type: "field", inboundTag: ["private-probe"], balancerTag: "levik-service-rule-0" }],
        balancers: [{ tag: "levik-service-rule-0", selector: ["levik-block"], strategy: { type: "random" } }] } };
    core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: ["pipe", "pipe", "pipe"] });
    const started = ready(core); core.stdin.end(JSON.stringify(config)); await started;
    await expect(get(api, 1)).rejects.toThrow();
    await expect(get(probe, 1)).rejects.toThrow();
    await expect(overrideServiceRoute("levik-service-rule-0", "levik-service-endpoint-0", undefined,
      { ...auth, password: "c".repeat(48) })).rejects.toThrow();
    await overrideServiceRoute("levik-service-rule-0", "levik-service-endpoint-0", undefined, auth);
    expect(await queryServiceRouteStats(auth)).toEqual({ uplink: 0, downlink: 0 });
    let validDns = true;
    dnsUpstream = createTcpServer((socket) => {
      let data = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        data = Buffer.concat([data, chunk]);
        if (data.length < 2 || data.length < data.readUInt16BE(0) + 2) return;
        const question = Buffer.from(data.subarray(2)); question.writeUInt16BE(validDns ? 0x8180 : 0x8183, 2);
        question.writeUInt16BE(validDns ? 1 : 0, 6);
        const answer = validDns ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 1]) : Buffer.alloc(0);
        const result = Buffer.concat([question, answer]); const frame = Buffer.alloc(result.length + 2);
        frame.writeUInt16BE(result.length); result.copy(frame, 2); socket.end(frame);
      });
    }); dnsUpstream.listen(0, "127.0.0.1"); await once(dnsUpstream, "listening");
    const dnsAddress = dnsUpstream.address(); if (!dnsAddress || typeof dnsAddress === "string") throw new Error("No DNS test port");
    expect(await probeServiceRouteDns(probe, auth, [`tcp://127.0.0.1:${dnsAddress.port}`])).toBe(true);
    validDns = false;
    expect(await probeServiceRouteDns(probe, auth, [`tcp://127.0.0.1:${dnsAddress.port}`])).toBe(false);
    if (process.env.LEVIK_TEST_PUBLIC_DNS === "1") {
      expect(await probeServiceRouteDns(probe, auth, ["https://1.1.1.1/dns-query"])).toBe(true);
      expect(await probeServiceRouteDns(probe, auth, ["https://www.google.com/generate_204"])).toBe(false);
    }

    // The existing Game CLI can use the same private API without exposing a second TCP listener.
    const proxy = `http://${auth.user}:${auth.password}@127.0.0.1:${api}`;
    const result = await promisify(execFile)(executable, ["api", "bo", "--server=levik-service-api:80", "-b", "levik-service-rule-0", "levik-block"],
      { timeout: 5000, env: { ...process.env, HTTPS_PROXY: proxy, HTTP_PROXY: proxy, NO_PROXY: "", https_proxy: proxy, http_proxy: proxy, no_proxy: "" } });
    expect(result.stderr).toBe("");
  }, 15000);

});
