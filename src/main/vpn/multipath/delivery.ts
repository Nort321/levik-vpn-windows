/** Evidence only for relay→client envelope delivery, never game-server loss.
 * A packet becomes final once it falls outside the protocol's replay window. */
export class DeliveryEvidence {
  private high = -1;
  private finalized = -1;
  private readonly arrivals = new Map<number, { paths: Set<number>; primary: number; replicated: boolean }>();
  private expected = 0;
  private lost = 0;
  private rescued = 0;
  observe(sequence: number, path: number, primary: number, replicas: number): void {
    if (sequence <= this.finalized) return;
    let arrival = this.arrivals.get(sequence);
    if (!arrival) { arrival = { paths: new Set(), primary, replicated: replicas >= 2 }; this.arrivals.set(sequence, arrival); }
    arrival.paths.add(path); this.high = Math.max(this.high, sequence);
    const boundary = this.high - 512;
    let delivered = 0;
    const finalizedCount = Math.max(0, boundary - this.finalized);
    for (const [value, item] of this.arrivals) if (value <= boundary) {
      delivered++;
      if (item.replicated && !item.paths.has(item.primary)) this.rescued++;
      this.arrivals.delete(value);
    }
    this.expected += finalizedCount; this.lost += finalizedCount - delivered;
    this.finalized = Math.max(this.finalized, boundary);
  }
  snapshot(): { lossPercent: number | null; rescuedPackets: number } {
    return { lossPercent: this.expected ? this.lost / this.expected * 100 : null, rescuedPackets: this.rescued };
  }
}
