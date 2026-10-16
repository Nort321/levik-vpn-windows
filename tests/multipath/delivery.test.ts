import { expect, it } from "vitest";
import { DeliveryEvidence } from "../../src/main/vpn/multipath/delivery";
it("counts confirmed sequence gaps and packets delivered only through a backup, after replay expiry", () => {
  const evidence = new DeliveryEvidence();
  evidence.observe(0, 1, 0, 2); // backup delivered, primary absent
  evidence.observe(1, 1, 0, 2); evidence.observe(1, 0, 0, 2); // ordinary duplicate, not rescued
  // sequence2 genuinely absent from all paths
  evidence.observe(3, 0, 0, 2);
  expect(evidence.snapshot()).toEqual({ lossPercent: null, rescuedPackets: 0 });
  evidence.observe(515, 0, 0, 2);
  expect(evidence.snapshot()).toEqual({ lossPercent: 25, rescuedPackets: 1 });
  evidence.observe(0, 0, 0, 2); // late and outside protocol replay window
  expect(evidence.snapshot().rescuedPackets).toBe(1);
});
it("does not describe single-path packets as rescued or infer a game's server-side loss", () => {
  const evidence = new DeliveryEvidence(); evidence.observe(0, 1, 0, 1); evidence.observe(512, 1, 0, 1);
  expect(evidence.snapshot()).toEqual({ lossPercent: 0, rescuedPackets: 0 });
});
it("bounds work on a large valid sequence jump", () => {
  const evidence = new DeliveryEvidence(); evidence.observe(0, 0, 0, 1); evidence.observe(0xffffffff, 0, 0, 1);
  expect(evidence.snapshot().lossPercent).toBeGreaterThan(99);
});
