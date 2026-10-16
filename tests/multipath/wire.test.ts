import { describe, expect, it } from "vitest";
import { decode, encode, Kind, publicIPv4, SequenceWindow, MAX_CONTROL_BYTES, HEADER_V2, parseMeasurement } from "../../src/main/vpn/multipath/wire";

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
  });
});
