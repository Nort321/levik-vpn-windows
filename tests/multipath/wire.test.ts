import { describe, expect, it } from "vitest";
import { decode, encode, Kind, publicIPv4, SequenceWindow } from "../../src/main/vpn/multipath/wire";

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
});
