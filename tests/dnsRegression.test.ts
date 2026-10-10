import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createSocket, type Socket } from "node:dgram";
import { once } from "node:events";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildXrayConfig } from "../src/main/vpn/xrayConfig";
import type { AppSettings } from "../src/shared/contracts";

const settings: AppSettings = {
  routingMode: "blockedOnly", automaticServer: false, autoReconnect: true,
  killSwitch: true, useDoh: true, dnsServer: "1.1.1.1", theme: "system",
  launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
  preventDnsLeaks: true, favoriteServerIds: [], antiDpiEnabled: false,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20",
  splitTunnelMode: "off", splitTunnelProcesses: [],
  connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
};

function profile(host = "192.0.2.1") {
  return prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "dns-test", subscriptionId: "test",
    source: { content: `vless://11111111-1111-4111-8111-111111111111@${host}:443?security=tls#Test` },
  })), "test");
}

function packet(type: number): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.from([7, ...Buffer.from("example"), 4, ...Buffer.from("test"), 0, 0, type, 0, 1]);
  return Buffer.concat([header, question]);
}

async function bind(socket: Socket): Promise<number> {
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  return socket.address().port;
}

async function query(port: number, type: number): Promise<Buffer> {
  const client = createSocket("udp4");
  try {
    const response = once(client, "message", { signal: AbortSignal.timeout(2_000) });
    client.send(packet(type), port, "127.0.0.1");
    const [data] = await response;
    if (!Buffer.isBuffer(data)) throw new Error("Invalid DNS response");
    return data;
  } finally { client.close(); }
}

async function ready(child: ChildProcessWithoutNullStreams): Promise<void> {
  await new Promise<void>((resolveReady, reject) => {
    const timer = setTimeout(() => finish(new Error("Test core did not start")), 5_000);
    const output = (data: Buffer): void => { if (data.toString().includes("started")) finish(); };
    const failed = (): void => finish(new Error("Test core exited before startup"));
    const finish = (error?: Error): void => {
      clearTimeout(timer);
      child.stdout.off("data", output);
      child.off("exit", failed);
      child.off("error", failed);
      if (error) reject(error); else resolveReady();
    };
    child.stdout.on("data", output);
    child.once("exit", failed);
    child.once("error", failed);
  });
}

describe("DNS regression", () => {
  it("keeps DoH failover encrypted and intercepts DNS before bypass rules", () => {
    const prepared = profile();
    const server = prepared.servers[0]!;
    const config = buildXrayConfig(prepared, server, settings);
    const rules = (config.routing as { rules: Array<Record<string, unknown>> }).rules;
    const dnsIndex = rules.findIndex((rule) => rule.port === "53");
    expect(dnsIndex).toBeGreaterThanOrEqual(0);
    expect(dnsIndex).toBeLessThan(rules.findIndex((rule) => rule.ip));
    expect(config.dns).toMatchObject({
      tag: "levik-dns", servers: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
    });
    expect(rules).toContainEqual({ type: "field", inboundTag: ["levik-dns"], outboundTag: server.tag });
  });

  it("bootstraps only VPN endpoints outside the VPN and preserves profile options", () => {
    const prepared = profile("vpn.example.com");
    const server = prepared.servers[0]!;
    const original = structuredClone(server.outbound);
    const config = buildXrayConfig(prepared, server, settings);
    expect(config.dns).toMatchObject({
      disableFallbackIfMatch: true,
      servers: [
        { address: "https+local://1.1.1.1/dns-query", domains: ["full:vpn.example.com"], skipFallback: true },
        { address: "https+local://8.8.8.8/dns-query", domains: ["full:vpn.example.com"], skipFallback: true },
        "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query",
      ],
    });
    expect(config).toHaveProperty("outbounds.0.streamSettings.sockopt.domainStrategy", "UseIPv4v6");
    expect(server.outbound).toEqual(original);
    const executable = process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe");
    for (const routingMode of ["global", "bypassRu", "blockedOnly"] as const) {
      for (const useDoh of [true, false]) {
        const candidate = buildXrayConfig(prepared, server, { ...settings, routingMode, useDoh });
        expect(() => execFileSync(executable, ["run", "-test", "-format", "json", "-config", "stdin:"], {
          input: JSON.stringify(candidate), timeout: 5_000, stdio: "pipe",
        })).not.toThrow();
      }
    }
  });

  it("delivers A/AAAA and promptly answers HTTPS/SVCB using the bundled core", async () => {
    // Loopback only: no TUN, privileges, external network or customer profile.
    const upstream = createSocket("udp4");
    const reservation = createSocket("udp4");
    let core: ChildProcessWithoutNullStreams | undefined;
    try {
      const upstreamPort = await bind(upstream);
      const port = await bind(reservation);
      reservation.close();
      await once(reservation, "close");
      upstream.on("message", (request, peer) => {
        const type = request.readUInt16BE(request.length - 4);
        if (type !== 1 && type !== 28) return; // unsupported queries must never wait here
        const header = Buffer.from(request.subarray(0, 12));
        header.writeUInt16BE(0x8180, 2);
        header.writeUInt16BE(1, 6);
        const address = type === 1 ? Buffer.from([203, 0, 113, 7]) : Buffer.from("20010db8000000000000000000000007", "hex");
        const answer = Buffer.from([0xc0, 0x0c, 0, type, 0, 1, 0, 0, 0, 60, 0, address.length]);
        upstream.send(Buffer.concat([header, request.subarray(12), answer, address]), peer.port, peer.address);
      });
      const prepared = profile();
      const server = prepared.servers[0]!;
      const config = buildXrayConfig(prepared, server, settings);
      config.log = { loglevel: "info", access: "none" };
      delete config.api;
      config.dns = { tag: "levik-dns", servers: [{ address: "203.0.113.53", port: upstreamPort }] };
      config.inbounds = [{ tag: "levik-tun-in", listen: "127.0.0.1", port, protocol: "dokodemo-door", settings: { address: "1.1.1.1", port: 53, network: "udp" } }];
      const outbounds = config.outbounds as Array<Record<string, unknown>>;
      config.outbounds = outbounds.map((outbound) => outbound.tag === server.tag
        ? { tag: server.tag, protocol: "freedom", settings: { redirect: `127.0.0.1:${upstreamPort}` } }
        : outbound.protocol === "freedom" ? { tag: outbound.tag, protocol: "blackhole" } : outbound);
      const executable = process.env.LEVIK_TEST_XRAY ?? (process.platform === "win32"
        ? resolve("vendor/xray/windows-x64/xray.exe") : resolve(`vendor/xray/darwin-${process.arch}/xray`));
      core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe" });
      const started = ready(core);
      core.stdin.end(JSON.stringify(config));
      await started;
      for (const type of [1, 28, 64, 65]) {
        const response = await query(port, type);
        expect(response.readUInt16BE(0)).toBe(type);
        expect(response.readUInt16BE(2) & 0x800f).toBe(0x8000);
        expect(response.readUInt16BE(6)).toBe(type === 1 || type === 28 ? 1 : 0);
      }
    } finally {
      if (core && core.exitCode === null) {
        const exited = once(core, "exit");
        core.kill();
        await exited;
      }
      upstream.close();
      try { reservation.close(); } catch { /* already released before core start */ }
    }
  }, 15_000);
});
