import { describe, expect, it } from "vitest";
import {
  avoidMaintenance,
  IdleMeter,
  MAINTENANCE_FORCE_MS,
  MAINTENANCE_LEAD_MS,
  maintenanceFor,
  maintenanceMove,
  type MaintenanceWindow,
} from "../src/main/platform/maintenance";

const START = Date.parse("2026-10-14T12:30:00Z");
const WINDOW: MaintenanceWindow = { nodeId: "n1142bf5571df2373ffb23", startsAt: START, endsAt: START + 60 * 60_000 };

describe("server maintenance", () => {
  it("keeps the app off a node from the lead time until the end", () => {
    expect(maintenanceFor([WINDOW], WINDOW.nodeId, START - MAINTENANCE_LEAD_MS - 1)).toBeNull();
    expect(maintenanceFor([WINDOW], WINDOW.nodeId, START - MAINTENANCE_LEAD_MS)).toEqual(WINDOW);
    expect(maintenanceFor([WINDOW], WINDOW.nodeId, WINDOW.endsAt - 1)).toEqual(WINDOW);
    expect(maintenanceFor([WINDOW], WINDOW.nodeId, WINDOW.endsAt)).toBeNull();
    expect(maintenanceFor([WINDOW], "n1000000000000000000000", START)).toBeNull();
    expect(maintenanceFor([WINDOW], null, START)).toBeNull();
  });

  it("chooses other servers unless none is left", () => {
    const servers = [{ id: "a", node: WINDOW.nodeId }, { id: "b", node: "n1000000000000000000000" }, { id: "relay", node: null }];
    expect(avoidMaintenance(servers, [WINDOW], (item) => item.node, START).map((item) => item.id)).toEqual(["b", "relay"]);
    expect(avoidMaintenance(servers.slice(0, 1), [WINDOW], (item) => item.node, START).map((item) => item.id)).toEqual(["a"]);
  });

  it("moves while idle first and two minutes before the start at the latest", () => {
    expect(maintenanceMove(null, START)).toBe("stay");
    expect(maintenanceMove(WINDOW, START - MAINTENANCE_FORCE_MS - 1)).toBe("when-idle");
    expect(maintenanceMove(WINDOW, START - MAINTENANCE_FORCE_MS)).toBe("now");
    expect(maintenanceMove(WINDOW, START + 1)).toBe("now");
  });

  it("calls a connection idle after twenty quiet seconds", () => {
    const meter = new IdleMeter();
    for (let second = 0; second <= 19; second += 1) meter.record(second * 1_000, second * 1_000);
    expect(meter.idle(19_000)).toBe(false);
    meter.record(20_000, 20_000);
    expect(meter.idle(20_000)).toBe(true);
    // 100 KB/s for a few seconds: busy again.
    for (let second = 21; second <= 23; second += 1) meter.record(20_000 + (second - 20) * 100_000, second * 1_000);
    expect(meter.idle(23_000)).toBe(false);
    meter.reset();
    expect(meter.idle(23_000)).toBe(false);
  });

  it("starts over when the counters restart", () => {
    const meter = new IdleMeter();
    meter.record(5_000_000, 0);
    meter.record(10, 1_000);
    for (let second = 2; second <= 22; second += 1) meter.record(10 + second, second * 1_000);
    expect(meter.idle(22_000)).toBe(true);
  });
});
