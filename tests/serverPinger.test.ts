import { describe, expect, it } from "vitest";
import { extractServerEndpoint } from "../src/main/vpn/serverPinger";

describe("Windows server pinger", () => {
  it("extracts nested VLESS endpoints", () => {
    expect(extractServerEndpoint({
      protocol: "vless",
      settings: { vnext: [{ address: "vpn.example.com", port: 443 }] },
    })).toEqual({ host: "vpn.example.com", port: 443 });
  });

  it("extracts Hysteria endpoints", () => {
    expect(extractServerEndpoint({
      protocol: "hysteria",
      settings: { version: 2, address: "hy.example.com", port: 8443 },
    })).toEqual({ host: "hy.example.com", port: 8443 });
  });

  it("rejects invalid ports", () => {
    expect(extractServerEndpoint({ settings: { address: "vpn.example.com", port: 70_000 } })).toBeNull();
  });
});
