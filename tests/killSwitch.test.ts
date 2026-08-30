import { describe, expect, it } from "vitest";
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
