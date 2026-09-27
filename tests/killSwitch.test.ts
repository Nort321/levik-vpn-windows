import { afterEach, describe, expect, it, vi } from "vitest";
import { WindowsKillSwitch } from "../src/main/windows/killSwitch";
import type { KillSwitchCommandRunner } from "../src/main/windows/killSwitch";

function recordingRunner(
  commands: string[][],
  results: number[] = [],
): KillSwitchCommandRunner {
  return async (arguments_) => {
    commands.push(arguments_);
    return { exitCode: results.shift() ?? 0, errorText: "" };
  };
}

describe("Windows Kill Switch lifecycle", () => {
  it("installs the boot-scoped boundary before allowing the tunnel", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      appExecutablePath: "C:\\Levik\\Levik VPN.exe",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands),
    });

    await killSwitch.enable();
    await killSwitch.allowTunnel();
    await killSwitch.disable();

    expect(commands).toEqual([
      ["enable", "C:\\Levik\\Levik VPN.exe", "C:\\Levik\\xray.exe"],
      ["allow-tunnel", "LevikVPN"],
      ["disable"],
    ]);
    expect(killSwitch.isActive()).toBe(false);
  });

  it("delegates legacy plaintext cleanup to the protected Windows helper", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands),
    });

    await killSwitch.cleanupLegacyConfig("C:\\Users\\Levik\\AppData\\Roaming\\levik-vpn-windows");

    expect(commands).toEqual([[
      "cleanup-legacy", "C:\\Users\\Levik\\AppData\\Roaming\\levik-vpn-windows",
    ]]);
  });

  it("restores a same-boot boundary left by an abnormal application exit", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      appExecutablePath: "C:\\Levik\\Levik VPN.exe",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands, [0, 0]),
    });

    await expect(killSwitch.recover()).resolves.toBe(true);
    expect(commands).toEqual([
      ["status"],
      ["enable", "C:\\Levik\\Levik VPN.exe", "C:\\Levik\\xray.exe"],
    ]);
    expect(killSwitch.isActive()).toBe(true);
  });

  it("does not activate when no boot-scoped boundary exists", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands, [2]),
    });

    await expect(killSwitch.recover()).resolves.toBe(false);
    expect(commands).toEqual([["status"]]);
  });

  it("repairs a removed boundary while protection is still required", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      appExecutablePath: "C:\\Levik\\Levik VPN.exe",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands, [0, 2, 0]),
    });

    await killSwitch.enable();
    await expect(killSwitch.ensureActive(() => true)).resolves.toBe(true);

    expect(commands).toEqual([
      ["enable", "C:\\Levik\\Levik VPN.exe", "C:\\Levik\\xray.exe"],
      ["status"],
      ["enable", "C:\\Levik\\Levik VPN.exe", "C:\\Levik\\xray.exe"],
    ]);
  });

  it("does not race an explicit disconnect when the boundary disappears", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "C:\\Levik\\xray.exe", {
      platform: "win32",
      helperExecutablePath: "C:\\Levik\\levik-kill-switch.exe",
      run: recordingRunner(commands, [0, 2]),
    });

    await killSwitch.enable();
    await expect(killSwitch.ensureActive(() => false)).resolves.toBe(false);

    expect(commands).toEqual([
      ["enable", expect.any(String), expect.any(String)],
      ["status"],
    ]);
  });
});


describe("Wintun readiness", () => {
  afterEach(() => { vi.useRealTimers(); });

  it("retries a registering adapter and succeeds without removing WFP protection", async () => {
    vi.useFakeTimers();
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe", run: recordingRunner(commands, [0, 1168, 1168, 0]),
    });
    await killSwitch.enable();
    const pending = killSwitch.allowTunnel();
    await vi.advanceTimersByTimeAsync(500);
    await pending;
    expect(commands.filter((command) => command[0] === "allow-tunnel")).toHaveLength(3);
    expect(killSwitch.isActive()).toBe(true);
  });

  it("bounds retries when the adapter never appears", async () => {
    vi.useFakeTimers();
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe", run: recordingRunner(commands, [0, ...Array<number>(21).fill(1168)]),
    });
    await killSwitch.enable();
    const pending = expect(killSwitch.allowTunnel()).rejects.toThrow("1168");
    await vi.advanceTimersByTimeAsync(5_000);
    await pending;
    expect(commands).toHaveLength(22);
  });

  it("does not retry permission errors", async () => {
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe", run: recordingRunner(commands, [0, 5]),
    });
    await killSwitch.enable();
    await expect(killSwitch.allowTunnel()).rejects.toThrow("5");
    expect(commands).toHaveLength(2);
  });

  it("stops retrying after protection is disabled", async () => {
    vi.useFakeTimers();
    const commands: string[][] = [];
    const killSwitch = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe", run: recordingRunner(commands, [0, 1168, 0]),
    });
    await killSwitch.enable();
    const pending = killSwitch.allowTunnel();
    await Promise.resolve();
    await killSwitch.disable();
    await vi.advanceTimersByTimeAsync(250);
    await pending;
    expect(commands.map((command) => command[0])).toEqual(["enable", "allow-tunnel", "disable"]);
  });
});

describe("Kill Switch repair races", () => {
  it("retries after a failed repair instead of silently abandoning protection", async () => {
    const commands: string[][] = [];
    const policy = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe",
      run: recordingRunner(commands, [0, 2, 5, 2, 0]),
    });
    await policy.enable();
    await expect(policy.ensureActive(() => true)).rejects.toThrow("5");
    await expect(policy.ensureActive(() => true)).resolves.toBe(true);
    expect(commands.map((command) => command[0])).toEqual(["enable", "status", "enable", "status", "enable"]);
  });

  it("waits for a pending repair before disabling so no filters are left behind", async () => {
    let finishRepair: (() => void) | undefined;
    let enables = 0;
    let systemActive = false;
    const policy = new WindowsKillSwitch(() => "xray.exe", {
      platform: "win32", helperExecutablePath: "helper.exe",
      run: async ([command]) => {
        if (command === "status") return { exitCode: 2, errorText: "" };
        if (command === "enable") {
          if (++enables === 2) await new Promise<void>((resolve) => { finishRepair = resolve; });
          systemActive = true;
        }
        if (command === "disable") systemActive = false;
        return { exitCode: 0, errorText: "" };
      },
    });
    await policy.enable();
    const repair = policy.ensureActive(() => true);
    for (let tick = 0; tick < 10 && !finishRepair; tick++) await Promise.resolve();
    expect(finishRepair).toBeDefined();
    const disconnect = policy.disable();
    finishRepair?.();
    await Promise.all([repair, disconnect]);
    expect(systemActive).toBe(false);
    expect(policy.isActive()).toBe(false);
  });
});
