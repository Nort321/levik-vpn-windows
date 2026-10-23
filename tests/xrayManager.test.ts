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

import { PassThrough } from "node:stream";
import { CoreStartError, startupExitError, waitForStartup } from "../src/main/vpn/xrayManager";

describe("Xray startup", () => {
  afterEach(() => { vi.useRealTimers(); });

  function starting() {
    const process = new ChildProcess();
    const stdout = new PassThrough();
    Object.defineProperty(process, "stdout", { value: stdout });
    Object.defineProperty(process, "stderr", { value: new PassThrough() });
    return { process, stdout };
  }

  it("waits for Xray's own started line, however the output is split", async () => {
    vi.useFakeTimers();
    const { process, stdout } = starting();
    const started = vi.fn();
    const startup = waitForStartup(process).then(started);
    await vi.advanceTimersByTimeAsync(10_000);
    stdout.write("2026/10/23 10:00:00 [Warning] core: Xray 26.7.28 sta");
    await vi.advanceTimersByTimeAsync(0);
    expect(started).not.toHaveBeenCalled();
    stdout.write("rted\n");
    await startup;
    expect(started).toHaveBeenCalledOnce();
    expect(process.listenerCount("exit")).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reports a core that exits after creating its adapter late, with its own reason, as retryable", async () => {
    const { process, stdout } = starting();
    const startup = waitForStartup(process);
    stdout.write("Failed to start: app/proxyman/inbound: failed to start inbound handler > Cannot create a file when that file already exists.\n");
    await new Promise((resolve) => setImmediate(resolve));
    process.emit("exit", 4294967295, null);
    const error = await startup.catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(CoreStartError);
    expect(error).toMatchObject({ retryable: true, message: expect.stringContaining("сетевой адаптер") });
  });

  it("keeps the antivirus hint for a core ended from outside and never retries a rejected configuration", () => {
    expect(startupExitError(-1, null)).toMatchObject({ retryable: false, message: expect.stringContaining("антивирус") });
    expect(startupExitError(23, "infra/conf: invalid")).toMatchObject({ retryable: false, message: expect.stringContaining("конфигурацию") });
    expect(startupExitError(-1, "app/proxyman/inbound: failed to listen TCP on 47186 > bind: Only one usage of each socket address"))
      .toMatchObject({ retryable: true, message: expect.stringContaining("порт") });
  });

  it("gives up on a core that never reports started", async () => {
    vi.useFakeTimers();
    const { process } = starting();
    const startup = expect(waitForStartup(process, 30_000)).rejects.toMatchObject({ retryable: false });
    await vi.advanceTimersByTimeAsync(30_000);
    await startup;
  });
});
