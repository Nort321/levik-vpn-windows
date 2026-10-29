import { describe, expect, it } from "vitest";
import type { NetworkInterfaceInfo } from "node:os";
import { buildGuestConfig, guestInterface, parseGuestInvitation, type GuestInvitation } from "../src/main/vpn/guestSession";
import { bindXrayOutboundInterface } from "../src/main/vpn/xrayConfig";

const NOW = 1_800_000_000_000;
const valid: GuestInvitation = { v: 1, host: "192.168.43.1", port: 18271, method: "aes-256-gcm", password: Buffer.alloc(32, 7).toString("base64url"), name: "Телефон", expiresAt: NOW + 60_000 };
const invite = (value: unknown): string => `levik-share://v1/${Buffer.from(JSON.stringify(value)).toString("base64url")}`;

describe("local phone invitation", () => {
  it("accepts the versioned Android format without creating an account profile", () => {
    expect(parseGuestInvitation(invite(valid), NOW)).toEqual(valid);
  });

  it.each(["8.8.8.8", "127.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.1.1.example.com", "192.168.1.256", "::1", "010.0.0.1", "192.168.1.0", "192.168.1.255"])("rejects nonlocal or ambiguous host %s", (host) => {
    expect(() => parseGuestInvitation(invite({ ...valid, host }), NOW)).toThrow();
  });

  it.each([
    { token: "account-secret" }, { method: "none" }, { password: "short" }, { port: 0 }, { port: 65_536 }, { port: 1.5 },
    { name: "\nsecret" }, { name: "\u0080secret" }, { name: "" }, { expiresAt: NOW + 63 * 60_000 }, { expiresAt: "2030-01-01" }, { v: 2 },
  ])("rejects invalid or extra invitation fields", (change) => {
    expect(() => parseGuestInvitation(invite({ ...valid, ...change }), NOW)).toThrow();
  });

  it("rejects expired, overlong, padded and externally routed invitations", () => {
    expect(() => parseGuestInvitation(invite({ ...valid, expiresAt: NOW }), NOW)).toThrow("истёк");
    expect(() => parseGuestInvitation(invite(valid) + "=", NOW)).toThrow();
    expect(() => parseGuestInvitation("https://example.com/?invite=" + invite(valid), NOW)).toThrow();
    expect(() => parseGuestInvitation(" ".repeat(2_049) + invite(valid), NOW)).toThrow();
  });

  it("does not include credentials in validation errors", () => {
    const password = "private-invite-content";
    try { parseGuestInvitation(invite({ ...valid, password }), NOW); }
    catch (error) { expect(String(error)).not.toContain(password); }
  });
});

function address(ip: string): NetworkInterfaceInfo {
  return { address: ip, netmask: "255.255.255.0", family: "IPv4", internal: false, mac: "00:00:00:00:00:01", cidr: `${ip}/24` };
}

describe("phone network selection", () => {
  it("binds to the phone Wi-Fi even when another physical network has the default route", () => {
    expect(guestInterface(valid.host, { Ethernet: [address("10.10.0.2")], "Wi-Fi": [address("192.168.43.12")], LevikVPN: [address("10.89.0.2")] })).toBe("Wi-Fi");
  });
  it("rejects absent and ambiguous local networks", () => {
    expect(() => guestInterface(valid.host, { Ethernet: [address("10.10.0.2")] })).toThrow();
    expect(() => guestInterface(valid.host, { A: [address("192.168.43.12")], B: [address("192.168.43.13")] })).toThrow();
  });
});

describe("guest routing", () => {
  it("has only the encrypted phone egress, controlled DNS and explicit IPv6/local-network block", () => {
    const config = buildGuestConfig(valid);
    const text = JSON.stringify(config);
    expect(text).not.toContain('"freedom"');
    expect(text).not.toContain("https+local");
    expect(text).not.toContain("subscriptionId");
    expect(text).toContain('"protocol":"shadowsocks"');
    expect(text).toContain('"queryStrategy":"UseIPv4"');
    expect(text).toContain('"::/0"');
    expect(text).toContain('"port":"53","outboundTag":"levik-dns-out"');
    const bound = bindXrayOutboundInterface(config, "Wi-Fi", true);
    expect(JSON.stringify(bound)).toContain('"autoOutboundsInterface":"Wi-Fi"');
    expect(JSON.stringify(bound)).toContain('"8000::/1"');
  });
});
