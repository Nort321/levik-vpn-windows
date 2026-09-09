import { describe, expect, it } from "vitest";
import { createSocket, type RemoteInfo, type Socket as UdpSocket } from "node:dgram";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { extractServerEndpoint, measureServerLatency } from "../src/main/vpn/serverPinger";
import type { TunnelServer } from "../src/shared/contracts";

describe("Windows server pinger", () => {
  it("extracts nested VLESS endpoints", () => {
    expect(extractServerEndpoint({
      protocol: "vless",
      settings: { vnext: [{ address: "vpn.example.com", port: 443 }] },
    })).toEqual({ host: "vpn.example.com", port: 443 });
  });

  it("extracts Hysteria endpoints", () => {
    expect(extractServerEndpoint({
      protocol: "hysteria",
      settings: { version: 2, address: "hy.example.com", port: 8443 },
    })).toEqual({ host: "hy.example.com", port: 8443 });
  });

  it("rejects invalid ports", () => {
    expect(extractServerEndpoint({ settings: { address: "vpn.example.com", port: 70_000 } })).toBeNull();
  });

  it.each([
    { address: " hy.example.com ", port: "8443" },
    { host: "hy.example.com", port: 8443 },
    { server: "hy.example.com", server_port: 8443 },
    { streamSettings: { hysteriaSettings: { address: "hy.example.com", port: 8443 } } },
  ])("extracts compatible endpoint fields: %j", (outbound) => {
    expect(extractServerEndpoint(outbound)).toEqual({ host: "hy.example.com", port: 8443 });
  });

  it.each(["hysteria", "hysteria2", "tuic"])("measures %s on a UDP-only QUIC endpoint", async (protocol) => {
    await withUdpServer(async (socket, port) => {
      const incoming = nextProbe(socket);
      const measurement = measureServerLatency(server({ protocol, settings: { address: "127.0.0.1", port } }));
      const { packet, remote } = await incoming;
      // A QUIC endpoint cannot decrypt the old all-zero v1 Initial.
      if (packet.readUInt32BE(1) !== 1) socket.send(versionNegotiation(packet), remote.port, remote.address);
      expect(await measurement).toBeGreaterThan(0);
      expect(packet.length).toBeGreaterThanOrEqual(1200);
      expect(packet.readUInt32BE(1) & 0x0f0f0f0f).toBe(0x0a0a0a0a);
    });
  });

  it("ignores unrelated and malformed datagrams until a matching response arrives", async () => {
    await withUdpServer(async (socket, port) => {
      const incoming = nextProbe(socket);
      let settled = false;
      const measurement = measureServerLatency(server({ type: "Hysteria2", server: "127.0.0.1", server_port: port }))
        .then((latency) => { settled = true; return latency; });
      const { packet, remote } = await incoming;
      const valid = versionNegotiation(packet);
      const wrongDestination = Buffer.from(valid);
      wrongDestination[6] = wrongDestination[6]! ^ 0xff;
      const wrongSource = Buffer.from(valid);
      wrongSource[15] = wrongSource[15]! ^ 0xff;
      const wrongVersion = Buffer.from(valid);
      wrongVersion.writeUInt32BE(1, 1);
      const shortHeader = Buffer.from(valid);
      shortHeader[0] = 0x40;
      const invalidLength = Buffer.from(valid);
      invalidLength[5] = 255;
      const advertisedProbe = Buffer.from(valid);
      advertisedProbe.writeUInt32BE(packet.readUInt32BE(1), 23);
      for (const invalid of [Buffer.alloc(0), packet, wrongDestination, wrongSource, wrongVersion, shortHeader, invalidLength, advertisedProbe, valid.subarray(0, 23), valid.subarray(0, 26)]) {
        socket.send(invalid, remote.port, remote.address);
      }
      await withUdpServer(async (otherSocket) => {
        otherSocket.send(valid, remote.port, remote.address);
        await delay(40);
        expect(settled).toBe(false);
      });
      socket.send(valid, remote.port, remote.address);
      expect(await measurement).toBeGreaterThan(0);
    });
  });

  it("keeps TCP fallback when UDP does not respond", async () => {
    await withUdpServer(async (_socket, port) => {
      const tcp = createServer((socket) => socket.destroy());
      await new Promise<void>((resolve) => tcp.listen(port, "127.0.0.1", resolve));
      try {
        expect(await measureServerLatency(server({ protocol: "hysteria", settings: { address: "127.0.0.1", port } }))).toBeGreaterThan(0);
        expect(await measureServerLatency(server({ protocol: "vless", settings: { address: "127.0.0.1", port } }))).toBeGreaterThan(0);
      } finally {
        await new Promise<void>((resolve) => tcp.close(() => resolve()));
      }
    });
  }, 7_000);

  it("returns no latency for a silent UDP endpoint without TCP service", async () => {
    await withUdpServer(async (_socket, port) => {
      expect(await measureServerLatency(server({ protocol: "hysteria", settings: { address: "127.0.0.1", port } }))).toBeNull();
    });
    expect(await measureServerLatency(server({ protocol: "hysteria" }))).toBeNull();
  }, 7_000);
});

function server(outbound: Record<string, unknown>): TunnelServer {
  return { id: "probe-test", tag: "probe-test", name: "Probe test", countryCode: "", outbound };
}

async function withUdpServer(run: (socket: UdpSocket, port: number) => Promise<void>): Promise<void> {
  const socket = createSocket("udp4");
  await new Promise<void>((resolve) => socket.bind(0, "127.0.0.1", resolve));
  try {
    await run(socket, socket.address().port);
  } finally {
    await new Promise<void>((resolve) => socket.close(() => resolve()));
  }
}

function nextProbe(socket: UdpSocket): Promise<{ packet: Buffer; remote: RemoteInfo }> {
  return new Promise((resolve) => socket.once("message", (packet, remote) => resolve({ packet, remote })));
}

function versionNegotiation(probe: Buffer): Buffer {
  const destinationLength = probe.readUInt8(5);
  const destination = probe.subarray(6, 6 + destinationLength);
  const sourceLength = probe.readUInt8(6 + destinationLength);
  const source = probe.subarray(7 + destinationLength, 7 + destinationLength + sourceLength);
  return Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0, source.length]), source, Buffer.from([destination.length]), destination, Buffer.from([0, 0, 0, 1])]);
}
