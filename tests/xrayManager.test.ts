import { describe, expect, it } from "vitest";
import { assertProcessRoutingSupport, xrayConfigArguments } from "../src/main/vpn/xrayManager";

describe("Xray configuration channel", () => {
  it("refuses silent process routing failures with an old bundled core", () => {
    const config = { routing: { rules: [{ process: ["overwatch.exe"] }] } };
    expect(() => assertProcessRoutingSupport(config, "Xray 26.7.28 Custom")).toThrow(/VPN-ядро/);
    expect(() => assertProcessRoutingSupport(config, "Xray 26.7.28 levik-process-v1")).not.toThrow();
    expect(() => assertProcessRoutingSupport({ routing: { rules: [{ ip: ["127.0.0.1"] }] } }, "Xray 26.7.28")).not.toThrow();
  });

  it("validates explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(true)).toEqual([
      "run", "-test", "-format", "json", "-config", "stdin:",
    ]);
  });

  it("executes explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(false)).toEqual([
      "run", "-format", "json", "-config", "stdin:",
    ]);
  });
});

import { ChildProcess } from "node:child_process";
import { afterEach, vi } from "vitest";
import { stopChild } from "../src/main/vpn/xrayManager";

describe("Xray process teardown", () => {
  afterEach(() => { vi.useRealTimers(); });

  function child() {
    const process = new ChildProcess();
    Object.defineProperty(process, "pid", { value: 123 });
    return process;
  }

  it("handles an immediate exit and cancels the force-kill timer", async () => {
    vi.useFakeTimers();
    const process = child();
    const kill = vi.spyOn(process, "kill").mockImplementation(() => { process.emit("exit", 0, null); return true; });
    await stopChild(process);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(kill).toHaveBeenCalledOnce();
    expect(process.listenerCount("exit")).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("waits for forced termination before allowing a replacement tunnel", async () => {
    vi.useFakeTimers();
    const process = child();
    const kill = vi.spyOn(process, "kill").mockReturnValue(true);
    const finished = vi.fn();
    const stopped = stopChild(process).then(finished);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(kill).toHaveBeenLastCalledWith("SIGKILL");
    expect(finished).not.toHaveBeenCalled();
    process.emit("exit", 0, null);
    await stopped;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reports an unkillable core instead of pretending it stopped", async () => {
    vi.useFakeTimers();
    const process = child();
    vi.spyOn(process, "kill").mockReturnValue(false);
    const stopped = expect(stopChild(process)).rejects.toThrow("остановить");
    await vi.advanceTimersByTimeAsync(10_000);
    await stopped;
    expect(vi.getTimerCount()).toBe(0);
  });
});
