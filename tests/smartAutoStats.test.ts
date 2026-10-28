import { describe, expect, it } from "vitest";
import { decodeServiceRouteStatistics } from "../src/main/vpn/serviceRouteTransport";

function variable(value: bigint): Buffer {
  const bytes: number[] = [];
  do { const low = Number(value & 127n); value >>= 7n; bytes.push(value ? low | 128 : low); } while (value);
  return Buffer.from(bytes);
}
function stringField(id: number, value: Buffer): Buffer { return Buffer.concat([Buffer.from([(id << 3) | 2]), variable(BigInt(value.length)), value]); }
function stat(name: string, value: bigint): Buffer {
  const payload = Buffer.concat([stringField(1, Buffer.from(name)), Buffer.from([16]), variable(value)]);
  return stringField(1, payload);
}
function frame(...stats: Buffer[]): Buffer {
  const body = Buffer.concat(stats), header = Buffer.alloc(5); header.writeUInt32BE(body.length, 1);
  return Buffer.concat([header, body]);
}
const up = "inbound>>>levik-tun-in>>>traffic>>>uplink", down = "inbound>>>levik-tun-in>>>traffic>>>downlink";

describe("activity counter evidence", () => {
  it("distinguishes missing counters from an observed zero baseline", () => {
    expect(decodeServiceRouteStatistics(frame())).toEqual({ uplink: 0, downlink: 0, initialized: false });
    expect(decodeServiceRouteStatistics(frame(stat(up, 0n)))).toMatchObject({ initialized: false });
    expect(decodeServiceRouteStatistics(frame(stat(up, 0n), stat(down, 0n)))).toEqual({ uplink: 0, downlink: 0, initialized: true });
  });

  it("uses only exact TUN counters, excluding the private probe/API inbounds", () => {
    const response = frame(stat("inbound>>>levik-service-endpoint-00-probe>>>traffic>>>uplink", 9000000n),
      stat(up, 12n), stat(down, 34n));
    expect(decodeServiceRouteStatistics(response)).toEqual({ uplink: 12, downlink: 34, initialized: true });
  });

  it("does not accept duplicate, truncated, compressed or out-of-range samples as quiet evidence", () => {
    expect(decodeServiceRouteStatistics(frame(stat(up, 0n), stat(up, 1n), stat(down, 0n))).initialized).toBe(false);
    expect(() => decodeServiceRouteStatistics(frame(stat(up, BigInt(Number.MAX_SAFE_INTEGER) + 1n)))).toThrow();
    const complete = frame(stat(up, 1n), stat(down, 2n));
    expect(() => decodeServiceRouteStatistics(complete.subarray(0, complete.length - 1))).toThrow();
    const compressed = Buffer.from(complete); compressed[0] = 1;
    expect(() => decodeServiceRouteStatistics(compressed)).toThrow();
  });
});
