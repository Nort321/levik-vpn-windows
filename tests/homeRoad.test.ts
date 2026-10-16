import { createServer, type Server, type Socket } from "node:net";
import type { NetworkInterfaceInfo } from "node:os";

import { afterEach, describe, expect, it } from "vitest";

import {
  createRoadKey,
  exitXrayConfig,
  isHomeRoadServer,
  parseRoadExit,
  physicalInterface,
  RoadConnector,
  roadKeyFrom,
} from "../src/main/platform/homeRoad";
import type { RoadSocket } from "../src/main/platform/homeRoad";

const token = "eyJ2IjoxLCJrIjoieCJ9.awxffJnVDuNrf_EA9LdiwC8AKM-d1rO7HucojENsT5k";
const exit = {
  exitId: "q8V3cS1mXyZ0aB2cD4eF6g",
  name: "Домашний Mac",
  mode: "direct",
  lanAccess: false,
  vlessUuid: "7A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D",
  key: "xaZp27rLapm8s6kvmxgRySzd84PqE2054hk2HFRLTRs",
  controlUrl: `wss://api.cloudnote-sync.xyz/road/x/${token}`,
  expiresAt: "2026-11-15T00:00:00.000Z",
};
const hosts = new Set(["api.cloudnote-sync.xyz", "leviknet.org"]);

describe("the website's exit", () => {
  it("is taken as it is when every field is right", () => {
    expect(parseRoadExit(exit, hosts)).toEqual({ ...exit, vlessUuid: exit.vlessUuid.toLowerCase() });
    // Before this computer reported its key, the website has none.
    expect(parseRoadExit({ ...exit, key: null }, hosts)?.key).toBeNull();
  });

  it("turns the exit off for anything unexpected", () => {
    for (const change of [
      { controlUrl: `ws://api.cloudnote-sync.xyz/road/x/${token}` },
      { controlUrl: `wss://evil.example/road/x/${token}` },
      { controlUrl: `wss://api.cloudnote-sync.xyz:8443/road/x/${token}` },
      { controlUrl: `wss://api.cloudnote-sync.xyz/road/c/${token}` },
      { controlUrl: `wss://api.cloudnote-sync.xyz/road/x/${token}?a=1` },
      { mode: "lan" },
      { lanAccess: "yes" },
      { vlessUuid: "not-a-uuid" },
      { key: "short" },
      { key: `${exit.key.slice(0, 42)}B` },
      { key: undefined },
      { exitId: "short" },
      { name: "" },
      { expiresAt: "soon" },
    ]) {
      expect(parseRoadExit({ ...exit, ...change }, hosts)).toBeNull();
    }
    expect(parseRoadExit(null, hosts)).toBeNull();
    expect(parseRoadExit("exit", hosts)).toBeNull();
  });
});

describe("the exit's key", () => {
  it("is an X25519 pair whose public half follows from the stored private half", () => {
    const key = createRoadKey();
    expect(key.privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(roadKeyFrom(key.privateKey)).toEqual(key);
    expect(createRoadKey().publicKey).not.toBe(key.publicKey);
    // As `xray x25519 -i` derives it.
    expect(roadKeyFrom("8LyO3Zux_-QA5HP-P0jODnhhQhLVlm82c_KNPbrenE4")?.publicKey).toBe("xaZp27rLapm8s6kvmxgRySzd84PqE2054hk2HFRLTRs");
    expect(roadKeyFrom("not a key")).toBeNull();
  });
});

describe("the exit's Xray", () => {
  const base = { port: 41000, vlessUuid: exit.vlessUuid.toLowerCase(), privateKey: "8LyO3Zux_-QA5HP-P0jODnhhQhLVlm82c_KNPbrenE4", physicalInterface: "en0" };

  function rules(config: Record<string, unknown>): Array<Record<string, unknown>> {
    return (config.routing as { rules: Array<Record<string, unknown>> }).rules;
  }

  it("listens on this computer only and goes out past the VPN in direct mode", () => {
    const config = exitXrayConfig({ ...base, mode: "direct", lanAccess: false });
    const [inbound] = config.inbounds as Array<Record<string, unknown>>;
    expect(inbound).toMatchObject({ listen: "127.0.0.1", port: 41000, protocol: "vless" });
    // Only devices that encrypt to this computer's key get through.
    expect(inbound?.settings).toEqual({
      clients: [{ id: exit.vlessUuid.toLowerCase() }],
      decryption: "mlkem768x25519plus.native.600s.8LyO3Zux_-QA5HP-P0jODnhhQhLVlm82c_KNPbrenE4",
    });
    expect(config.log).toEqual({ loglevel: "error", access: "none" });
    const [home] = config.outbounds as Array<Record<string, unknown>>;
    expect(home).toMatchObject({ protocol: "freedom", streamSettings: { sockopt: { interface: "en0" } } });
    // The home network and the computer itself stay closed without network access.
    expect(rules(config)[0]?.ip).toEqual(expect.arrayContaining(["127.0.0.0/8", "192.168.0.0/16", "fe80::/10"]));
    expect(rules(config)).toContainEqual({ type: "field", port: "25", outboundTag: "blocked" });
  });

  it("follows this computer's VPN in vpn mode and opens the home network on request", () => {
    const config = exitXrayConfig({ ...base, mode: "vpn", lanAccess: true });
    const [home] = config.outbounds as Array<Record<string, unknown>>;
    expect(home?.streamSettings).toBeUndefined();
    const closed = rules(config)[0]?.ip as string[];
    expect(closed).toContain("127.0.0.0/8");
    expect(closed).not.toContain("192.168.0.0/16");
  });
});

describe("the physical interface", () => {
  const address = (value: string, internal = false): NetworkInterfaceInfo => ({
    address: value, netmask: "255.255.255.0", family: "IPv4", mac: "00:00:00:00:00:00", internal, cidr: null,
  });

  it("skips tunnels, loopback and virtual machines", () => {
    expect(physicalInterface({
      lo0: [address("127.0.0.1", true)],
      utun4: [address("10.89.0.2")],
      bridge100: [address("192.168.64.1")],
      en7: [address("192.168.1.20")],
      en0: [address("192.168.1.21")],
    })).toBe("en0");
    expect(physicalInterface({ utun3: [address("172.19.0.1")], en5: [address("169.254.2.2")] })).toBeNull();
  });
});

it("names the servers of home exits", () => {
  expect(isHomeRoadServer("🏠 Домашний Mac")).toBe(true);
  expect(isHomeRoadServer("Нидерланды")).toBe(false);
});

class FakeSocket implements RoadSocket {
  binaryType = "blob";
  readyState = 0;
  bufferedAmount = 0;
  onopen: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  readonly sent: Buffer[] = [];

  constructor(readonly url: string) {}

  open(): void {
    this.readyState = 1;
    this.onopen?.({});
  }

  receive(data: unknown): void {
    this.onmessage?.({ data });
  }

  send(data: Uint8Array | string): void {
    this.sent.push(typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data));
  }

  close(): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.({});
  }
}

async function until(check: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200 && !check(); attempt += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  expect(check()).toBe(true);
}

describe("the connector", () => {
  let server: Server | null = null;
  let connector: RoadConnector | null = null;
  afterEach(async () => {
    connector?.stop();
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    server = null;
  });

  it("joins each stream the relay announces to the local Xray, both ways", async () => {
    const local: Socket[] = [];
    const received: Buffer[] = [];
    server = createServer((socket) => {
      local.push(socket);
      socket.on("data", (chunk: Buffer) => {
        received.push(chunk);
        socket.write(Buffer.from("pong"));
      });
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const sockets: FakeSocket[] = [];
    const statuses: boolean[] = [];
    connector = new RoadConnector(exit.controlUrl, port, (url) => {
      const socket = new FakeSocket(url);
      sockets.push(socket);
      return socket;
    });
    connector.on("status", (online) => statuses.push(online));
    connector.start();
    const control = sockets[0];
    if (!control) throw new Error("no control socket");
    control.open();
    expect(statuses).toEqual([true]);

    // Junk from the relay opens nothing.
    control.receive("{");
    control.receive(JSON.stringify({ type: "open", id: "../../x" }));
    control.receive(new ArrayBuffer(4));
    expect(sockets).toHaveLength(1);

    control.receive(JSON.stringify({ type: "open", id: "stream-0001" }));
    const data = sockets[1];
    if (!data) throw new Error("no data socket");
    expect(data.url).toBe(`${exit.controlUrl}/stream-0001`);
    expect(data.binaryType).toBe("arraybuffer");
    data.open();
    // What the device sends before the local connection is up still arrives.
    data.receive(new Uint8Array(Buffer.from("ping")).buffer);
    await until(() => received.length > 0);
    expect(Buffer.concat(received).toString()).toBe("ping");
    await until(() => data.sent.length > 0);
    expect(Buffer.concat(data.sent).toString()).toBe("pong");
    expect(connector.streamCount).toBe(1);

    // A new token is used for the next connections; the open stream goes on.
    const fresh = `${exit.controlUrl.slice(0, -4)}AAAA`;
    connector.retarget(fresh);
    control.receive(JSON.stringify({ type: "open", id: "stream-0002" }));
    expect(sockets[2]?.url).toBe(`${fresh}/stream-0002`);
    expect(connector.streamCount).toBe(2);

    connector.stop();
    expect(connector.streamCount).toBe(0);
    expect(data.readyState).toBe(3);
    await until(() => local.every((socket) => socket.destroyed || socket.readableEnded));
  });

  it("comes back after the relay drops the control connection", async () => {
    const sockets: FakeSocket[] = [];
    connector = new RoadConnector(exit.controlUrl, 1, (url) => {
      const socket = new FakeSocket(url);
      sockets.push(socket);
      return socket;
    });
    const statuses: boolean[] = [];
    connector.on("status", (online) => statuses.push(online));
    connector.start();
    sockets[0]?.open();
    sockets[0]?.close();
    expect(statuses).toEqual([true, false]);
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    expect(sockets).toHaveLength(2);
  });
});
