import { describe, expect, it } from "vitest";
import { DelayQueue, FecDecoder, FecEncoder, type FecPacket } from "../../src/main/vpn/multipath/fec";

const packet = (sequence: number, payload: string, port = 7000 + sequence): FecPacket =>
  ({ sequence, address: `198.51.${100 + sequence}.${sequence + 1}`, port, payload: Buffer.from(payload) });

describe("Game FEC", () => {
  it("rebuilds any single lost packet of a group, including its destination", () => {
    for (let lost = 0; lost < 4; lost++) {
      const encoder = new FecEncoder(); const decoder = new FecDecoder();
      const packets = [packet(8, "a"), packet(9, "longer payload"), packet(10, ""), packet(11, "xyz")];
      let parity = null; let recovered: FecPacket | null = null;
      for (const item of packets) { parity = encoder.add(item) ?? parity; if (item.sequence !== 8 + lost) recovered = decoder.data(item) ?? recovered; }
      expect(parity?.sequence).toBe(8);
      recovered = decoder.parity(parity!.sequence, parity!.payload) ?? recovered;
      expect(recovered).toEqual(packets[lost]);
    }
  });
  it("flushes a partial group, skips single packets and never recovers two losses", () => {
    const encoder = new FecEncoder();
    encoder.add(packet(0, "only")); expect(encoder.flush()).toBeNull();
    encoder.add(packet(4, "one")); encoder.add(packet(5, "two")); const parity = encoder.flush()!;
    expect(parity.sequence).toBe(4);
    const decoder = new FecDecoder(); expect(decoder.parity(parity.sequence, parity.payload)).toBeNull();
    expect(decoder.data(packet(5, "two"))).toEqual(packet(4, "one"));
    expect(decoder.data(packet(4, "one"))).toBeNull();

    const twoLost = new FecEncoder(); let full = null;
    for (const item of [packet(12, "a"), packet(13, "b"), packet(14, "c"), packet(15, "d")]) full = twoLost.add(item) ?? full;
    const other = new FecDecoder(); other.data(packet(12, "a")); other.data(packet(13, "b"));
    expect(other.parity(full!.sequence, full!.payload)).toBeNull();
  });
  it("starting a new group emits the previous parity and rejects malformed parity", () => {
    const encoder = new FecEncoder(); encoder.add(packet(0, "a")); encoder.add(packet(1, "b"));
    expect(encoder.add(packet(4, "c"))?.sequence).toBe(0);
    const decoder = new FecDecoder();
    expect(decoder.parity(1, Buffer.alloc(12, 1))).toBeNull();
    expect(decoder.parity(0, Buffer.alloc(4))).toBeNull();
    expect(decoder.parity(0, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0]))).toBeNull();
    expect(decoder.parity(0, Buffer.from([16, 0, 0, 0, 0, 0, 0, 0, 0]))).toBeNull();
  });
  it("delays copies in order through one timer", async () => {
    const order: number[] = []; const queue = new DelayQueue(() => performance.now());
    queue.push(4, () => order.push(2)); queue.push(1, () => order.push(1));
    await new Promise((done) => setTimeout(done, 20));
    expect(order.sort()).toEqual([1, 2]);
    queue.push(5, () => order.push(3)); queue.clear();
    await new Promise((done) => setTimeout(done, 20));
    expect(order).toEqual([1, 2]);
  });
});
