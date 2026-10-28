import { describe, expect, it } from "vitest";
import { SMART_AUTO_ACTIVITY, SmartAutoActivity } from "../src/main/vpn/smartAutoActivity";

function sampler() {
  let now = 0, up = 0, down = 0;
  const activity = new SmartAutoActivity(() => now);
  const sample = (bytesPerSecond: number, seconds = 1) => {
    now += seconds * 1000; down += bytesPerSecond * seconds;
    activity.observe({ uplink: up, downlink: down });
  };
  activity.observe({ uplink: up, downlink: down });
  return { activity, sample, time: () => now, set: (at: number, uplink: number, downlink: number) => {
    now = at; up = uplink; down = downlink; activity.observe({ uplink: up, downlink: down });
  } };
}

describe("live Smart Auto user activity", () => {
  it("starts unknown and requires a complete minute of quiet keepalives", () => {
    const { activity, sample } = sampler();
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 59; i++) sample(512);
    expect(activity.canSwitch()).toBe(false);
    sample(512);
    expect(activity.canSwitch()).toBe(true);
  });

  it("blocks an active transfer and waits for a new quiet minute", () => {
    const { activity, sample } = sampler();
    for (let i = 0; i < 60; i++) sample(0);
    sample(SMART_AUTO_ACTIVITY.busyBytesPerSecond);
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 59; i++) sample(0);
    expect(activity.canSwitch()).toBe(false);
    sample(0);
    expect(activity.canSwitch()).toBe(true);
  });

  it("does not treat moderate scrolling traffic as quiet", () => {
    const { activity, sample } = sampler();
    for (let i = 0; i < 120; i++) sample(5 * 1024);
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 60; i++) sample(512);
    expect(activity.canSwitch()).toBe(true);
  });

  it("treats the 4KiB/s boundary as activity rather than quiet", () => {
    const { activity, sample } = sampler();
    for (let i = 0; i < 65; i++) sample(4 * 1024);
    expect(activity.canSwitch()).toBe(false);
  });

  it("detects a five-second burst even below the 16KiB/s average", () => {
    const { activity, sample } = sampler();
    for (let i = 0; i < 60; i++) sample(0);
    sample(SMART_AUTO_ACTIVITY.burstBytes / 5, 5);
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 4; i++) sample(0);
    expect(activity.canSwitch()).toBe(false);
  });

  it("rejects stale/missing samples and restarts quiet evidence after a sampling gap", () => {
    const { activity, sample, time } = sampler();
    for (let i = 0; i < 60; i++) sample(0);
    expect(activity.canSwitch(time() + 5_001)).toBe(false);
    sample(0, 6);
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 60; i++) sample(0);
    expect(activity.canSwitch()).toBe(true);
  });

  it("treats counter resets, invalid values and backwards time as unknown", () => {
    const { activity, sample, set, time } = sampler();
    for (let i = 0; i < 60; i++) sample(512);
    expect(activity.canSwitch()).toBe(true);
    set(time() + 1000, 0, 0);
    expect(activity.canSwitch()).toBe(false);
    for (let i = 0; i < 60; i++) sample(0);
    expect(activity.canSwitch()).toBe(true);
    activity.observe({ uplink: NaN, downlink: 0 });
    expect(activity.canSwitch()).toBe(false);
    set(100, 0, 0); set(99, 0, 0);
    expect(activity.canSwitch()).toBe(false);
  });

  it("counts uplink and downlink together", () => {
    const { activity, sample, set, time } = sampler();
    for (let i = 0; i < 60; i++) sample(0);
    set(time() + 1000, 3 * 1024, 3 * 1024);
    expect(activity.canSwitch()).toBe(false);
  });
});
