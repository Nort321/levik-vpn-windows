import { describe, expect, it } from "vitest";
import { decode, encode, Kind, publicIPv4, SequenceWindow, MAX_CONTROL_BYTES, HEADER_V2, HEADER_V3, parseMeasurement, tagResolver, instanceMatches, parseCapabilities } from "../../src/main/vpn/multipath/wire";

describe("Game multipath packet boundary", () => {
  it("rejects truncation and unknown versions and round-trips opaque game payloads", () => {
    const packet = { kind: Kind.Up, path: 1, session: Buffer.alloc(32, 7), flow: Buffer.alloc(8, 9), sequence: 42,
      address: "1.1.1.1", port: 7000, payload: Buffer.from([0, 255, 128, 42]) };
    expect(decode(encode(packet))).toEqual(packet);
    expect(decode(encode(packet).subarray(0, 55))).toBeNull();
    const broken = encode(packet); broken[3] = 99; expect(decode(broken)).toBeNull();
  });
  it("forwards first arrival once without waiting for lost earlier packets", () => {
    const window = new SequenceWindow();
    expect(window.accept(3)).toBe(true); expect(window.accept(1)).toBe(true);
    expect(window.accept(3)).toBe(false); expect(window.accept(1024)).toBe(true);
    expect(window.accept(2)).toBe(false); expect(window.accept(1023)).toBe(true);
  });
  it("cannot reach loopback, metadata, private, multicast or documentation networks", () => {
    for (const ip of ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "224.0.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.1", "::1", "bad"]) expect(publicIPv4(ip)).toBe(false);
    expect(publicIPv4("1.1.1.1")).toBe(true);
  });
  it("version 2 carries exit identity and instance and rejects excessive hops and control bytes", () => {
    const packet = { version: 2 as const, kind: Kind.Up, path: 7, session: Buffer.alloc(32), flow: Buffer.alloc(8), sequence: 0,
      address: "1.1.1.1", port: 7000, payload: Buffer.from("game"), exitNodeId: "node-a", hops: 1, instance: Buffer.alloc(16, 1) };
    expect(decode(encode(packet))).toEqual(packet);
    const bad = encode(packet); bad[121] = 2; expect(decode(bad)).toBeNull();
    const truncated = encode(packet).subarray(0, HEADER_V2 - 1); expect(decode(truncated)).toBeNull();
    expect(() => encode({ ...packet, kind: Kind.ProbeRequest, payload: Buffer.alloc(MAX_CONTROL_BYTES + 1) })).toThrow();
    expect(() => encode({ ...packet, exitNodeId: "bad.node" })).toThrow();
    expect(() => encode({ ...packet, sequence: -1 })).toThrow();
  });
  it("rejects malformed measurement numbers and reserved targets before runtime state", () => {
    const result = { address: "1.1.1.1", port: 7000, medianMs: 20, p95Ms: 21, jitterMs: 1,
      lossPercent: 0, sampleCount: 5, measuredAt: new Date().toISOString(), method: "icmp", approximate: false };
    expect(parseMeasurement(result)).toEqual(result);
    expect(parseMeasurement({ ...result, medianMs: NaN })).toBeNull();
    expect(parseMeasurement({ ...result, address: "169.254.169.254" })).toBeNull();
    expect(parseMeasurement({ ...result, lossPercent: 101 })).toBeNull();
    expect(parseMeasurement({ ...result, sampleCount: 0 })).toBeNull();
    // Only a lower bound names its router, and only a public one.
    expect(parseMeasurement({ ...result, method: "ttl-hop", hop: "62.115.139.181" })?.hop).toBe("62.115.139.181");
    expect(parseMeasurement({ ...result, method: "ttl-hop", hop: "10.0.0.1" })?.hop).toBeUndefined();
    expect(parseMeasurement({ ...result, hop: "62.115.139.181" })?.hop).toBeUndefined();
  });
  it("version 3 matches the golden vector shared with the Go relay", () => {
    const session = Buffer.alloc(32); Buffer.from("0102030405060708", "hex").copy(session);
    const flow = Buffer.alloc(8); Buffer.from("a1b2c3d4", "hex").copy(flow);
    const packet = { version: 3 as const, kind: Kind.Up, path: 2, session, flow, sequence: 0x01020304, address: "203.0.114.9", port: 27015,
      payload: Buffer.from("game"), exitNodeId: "node-a", hops: 1, instance: Buffer.from("deadbeef", "hex") };
    const golden = "4c474d33030201000102030405060708a1b2c3d401020304775375addeadbeefcb007209698767616d65";
    expect(encode(packet).toString("hex")).toBe(golden);
    expect(encode(packet).length).toBe(HEADER_V3 + 4);
    expect(decode(Buffer.from(golden, "hex"), tagResolver(["node-a", "node-b"]))).toEqual(packet);
    // An unknown exit tag is never guessed.
    expect(decode(Buffer.from(golden, "hex"), tagResolver(["node-b"]))).toBeNull();
    expect(decode(Buffer.from(golden, "hex"))).toBeNull();
    const reserved = Buffer.from(golden, "hex"); reserved[7] = 1; expect(decode(reserved, tagResolver(["node-a"]))).toBeNull();
    const flags = Buffer.from(golden, "hex"); flags[6] = 3; expect(decode(flags, tagResolver(["node-a"]))).toBeNull();
    // Control frames and long session ids stay on version 2.
    expect(() => encode({ ...packet, kind: Kind.NodeInfo })).toThrow();
    expect(() => encode({ ...packet, session: Buffer.alloc(32, 1) })).toThrow();
  });
  it("compares short instance tags with the full process instance", () => {
    const instance = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    expect(instanceMatches(Buffer.from("00112233", "hex"), instance)).toBe(true);
    expect(instanceMatches(Buffer.alloc(4), instance)).toBe(true);
    expect(instanceMatches(Buffer.from("00112234", "hex"), instance)).toBe(false);
    expect(instanceMatches(instance, instance)).toBe(true);
  });
  it("treats missing capabilities as an old relay", () => {
    expect(parseCapabilities(undefined)).toEqual({ probe: false, mesh: false, lgm3: false, eim: false, fec: false, regions: false, spread: false });
    expect(parseCapabilities({ lgm3: true, eim: "yes" })).toMatchObject({ lgm3: true, eim: false });
  });
});
