import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildGuestConfig } from "../src/main/vpn/guestSession";
import { bindXrayOutboundInterface } from "../src/main/vpn/xrayConfig";

const executable = process.env.LEVIK_TEST_XRAY ?? (process.platform === "win32"
  ? resolve("vendor/xray/windows-x64/xray.exe")
  : resolve("../levik_vpn_macos/vendor/xray", `darwin-${process.arch}`, "xray"));

describe.skipIf(!existsSync(executable))("guest configuration with the pinned native core", () => {
  it("validates the real encrypted guest config without creating a system tunnel", () => {
    const config = bindXrayOutboundInterface(buildGuestConfig({
      v: 1, host: "192.168.43.1", port: 18271, method: "aes-256-gcm",
      password: Buffer.alloc(32, 7).toString("base64url"), name: "Test phone", expiresAt: Date.now() + 60_000,
    }), "Wi-Fi", true);
    expect(() => execFileSync(executable, ["run", "-test", "-format", "json", "-config", "stdin:"], {
      input: JSON.stringify(config), timeout: 5_000, stdio: "pipe",
    })).not.toThrow();
  });
});
