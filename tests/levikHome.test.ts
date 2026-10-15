import { describe, expect, it } from "vitest";

import {
  beaconFresh,
  encodeQuery,
  HomeSleepPolicy,
  parseBeacon,
  parseResponse,
  parseSighting,
} from "../src/main/platform/levikHome";
import type { VerifiedHome } from "../src/main/platform/levikHome";

const homeId = "AbCdEfGhIjKlMnOpQrStUv";
const proof = "uo4VQl8xhhyJqBeyUxfjkw";
const beaconStrings = ["v=1", `h=${homeId}`, "w=5870000", `p=${proof}`];

function name(value: string): Buffer {
  return Buffer.concat([
    ...value.split(".").map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
    Buffer.from([0]),
  ]);
}

function record(owner: Buffer, type: number, data: Buffer): Buffer {
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(0x8001, 2);
  fixed.writeUInt32BE(120, 4);
  fixed.writeUInt16BE(data.length, 8);
  return Buffer.concat([owner, fixed, data]);
}

/** What the router's agent answers: PTR, then SRV, TXT and A of the instance, its name compressed. */
function response(strings: string[]): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x8400, 2);
  header.writeUInt16BE(1, 6);
  header.writeUInt16BE(2, 10);
  const instance = name("Levik Home router-1._levik._tcp.local");
  const ptrOwner = name("_levik._tcp.local");
  const instanceOffset = 12 + ptrOwner.length + 10;
  const pointer = Buffer.from([0xc0 | (instanceOffset >> 8), instanceOffset & 0xff]);
  const txt = Buffer.concat(strings.map((item) => Buffer.concat([Buffer.from([item.length]), Buffer.from(item)])));
  return Buffer.concat([
    header,
    record(ptrOwner, 12, instance),
    record(pointer, 16, txt),
    record(name("levik-home-router-1.local"), 1, Buffer.from([192, 168, 1, 1])),
  ]);
}

/** levik-home.py 1.0.0 answering a one-shot query (Responder.response), byte for byte. */
const AGENT_REPLY =
  "123484000001000100000003065f6c6576696b045f746370056c6f63616c00000c0001065f6c6576696b045f74637005" +
  "6c6f63616c00000c0001000000780027134c6576696b20486f6d6520726f757465722d31065f6c6576696b045f746370" +
  "056c6f63616c00134c6576696b20486f6d6520726f757465722d31065f6c6576696b045f746370056c6f63616c000021" +
  "8001000000780021000000000009136c6576696b2d686f6d652d726f757465722d31056c6f63616c00134c6576696b20" +
  "486f6d6520726f757465722d31065f6c6576696b045f746370056c6f63616c000010800100000078004003763d311868" +
  "3d4162436445664768496a4b6c4d6e4f7051725374557609773d3538373030303018703d756f3456516c38786868794a" +
  "714265795578666a6b77136c6576696b2d686f6d652d726f757465722d31056c6f63616c0000018001000000780004c0" +
  "a80101";

describe("Levik Home beacons", () => {
  it("reads the router agent's own answer", () => {
    expect(parseResponse(Buffer.from(AGENT_REPLY, "hex")).map(parseBeacon)).toEqual([{ homeId, window: 5_870_000, proof }]);
  });

  it("reads a v1 beacon and ignores anything else", () => {
    expect(parseBeacon(beaconStrings)).toEqual({ homeId, window: 5_870_000, proof });
    expect(parseBeacon(["v=2", `h=${homeId}`, "w=5870000", `p=${proof}`])).toBeNull();
    expect(parseBeacon(["v=1", "h=short", "w=5870000", `p=${proof}`])).toBeNull();
    expect(parseBeacon(["v=1", `h=${homeId}`, "w=0", `p=${proof}`])).toBeNull();
    expect(parseBeacon(["v=1", `h=${homeId}`, "w=12a", `p=${proof}`])).toBeNull();
    expect(parseBeacon(["v=1", `h=${homeId}`, "w=5870000"])).toBeNull();
  });

  it("only beacons of the current window and its neighbours are fresh", () => {
    const now = 5_870_000 * 300_000 + 1_000;
    expect(beaconFresh({ homeId, window: 5_870_001, proof }, now)).toBe(true);
    expect(beaconFresh({ homeId, window: 5_869_999, proof }, now)).toBe(true);
    expect(beaconFresh({ homeId, window: 5_869_998, proof }, now)).toBe(false);
  });

  it("asks for the service and reads the TXT record of the router's answer", () => {
    const query = encodeQuery(0x1234);
    expect(query.readUInt16BE(0)).toBe(0x1234);
    expect(query.readUInt16BE(4)).toBe(1);
    expect(query.subarray(12).toString("latin1")).toContain("_levik");
    expect(parseResponse(response(beaconStrings))).toEqual([beaconStrings]);
    expect(parseResponse(query)).toEqual([]);
    expect(parseResponse(response(beaconStrings).subarray(0, 60))).toEqual([]);
  });

  it("reads the server's answer", () => {
    expect(parseSighting({ ok: true, home: { name: "Дом", routerOnline: true, routerVpnActive: true } }))
      .toEqual({ name: "Дом", routerOnline: true, routerVpnActive: true });
    expect(parseSighting({ ok: true, home: null })).toBeNull();
    expect(parseSighting({ ok: true, home: { name: " ", routerOnline: true, routerVpnActive: true } })).toBeNull();
    expect(parseSighting({ ok: true, home: { name: "Дом", routerOnline: "yes", routerVpnActive: true } })).toBeNull();
  });
});

describe("HomeSleepPolicy", () => {
  const protecting: VerifiedHome = { name: "Дом", routerOnline: true, routerVpnActive: true };
  const unprotected: VerifiedHome = { name: "Дом", routerOnline: true, routerVpnActive: false };

  it("sleeps at a protected home and wakes when the computer leaves", () => {
    const policy = new HomeSleepPolicy();
    expect(policy.heard(protecting, 0, true, true)).toEqual({ kind: "sleep", home: "Дом" });
    expect(policy.asleep).toBe(true);
    expect(policy.heard(protecting, 60_000, false, true)).toEqual({ kind: "none" });
    expect(policy.left()).toEqual({ kind: "wake" });
  });

  it("does not sleep while the router's VPN is off, the setting is off or the VPN is not on", () => {
    const policy = new HomeSleepPolicy();
    expect(policy.heard(unprotected, 0, true, true)).toEqual({ kind: "none" });
    expect(policy.heard(protecting, 0, true, false)).toEqual({ kind: "none" });
    expect(policy.heard(protecting, 0, false, true)).toEqual({ kind: "none" });
    expect(policy.asleep).toBe(false);
  });

  it("wakes when the router's VPN stops, the setting is turned off or the home is silent", () => {
    const policy = new HomeSleepPolicy();
    policy.heard(protecting, 0, true, true);
    expect(policy.heard(unprotected, 1_000, false, true)).toEqual({ kind: "wake" });
    policy.heard(protecting, 2_000, true, true);
    expect(policy.heard(protecting, 3_000, false, false)).toEqual({ kind: "wake" });
    policy.heard(protecting, 4_000, true, true);
    expect(policy.heard(null, 4_000 + HomeSleepPolicy.SILENCE_MS, false, true)).toEqual({ kind: "none" });
    expect(policy.silence(4_001 + HomeSleepPolicy.SILENCE_MS)).toEqual({ kind: "wake" });
  });

  it("a user who connects at home keeps the VPN until the next arrival", () => {
    const policy = new HomeSleepPolicy();
    policy.heard(protecting, 0, true, true);
    policy.resumedByUser();
    expect(policy.heard(protecting, 60_000, true, true)).toEqual({ kind: "none" });
    policy.left();
    expect(policy.heard(protecting, 120_000, true, true)).toEqual({ kind: "sleep", home: "Дом" });
    policy.stopped();
    expect(policy.left()).toEqual({ kind: "none" });
  });
});
