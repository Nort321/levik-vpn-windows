import { describe, expect, it } from "vitest";
import { parseXrayStats } from "../src/main/vpn/xrayStats";

describe("Xray traffic statistics", () => {
  it("extracts TUN upload and download counters", () => {
    const result = parseXrayStats(JSON.stringify({
      stat: [
        { name: "inbound>>>levik-tun-in>>>traffic>>>uplink", value: "2048" },
        { name: "inbound>>>levik-tun-in>>>traffic>>>downlink", value: 8192 },
        { name: "outbound>>>levik-server>>>traffic>>>uplink", value: 999 },
      ],
    }));
    expect(result).toEqual({ uplink: 2048, downlink: 8192 });
  });

  it("ignores malformed and unrelated counters", () => {
    const result = parseXrayStats(JSON.stringify({
      stat: [
        { name: "inbound>>>levik-tun-in>>>traffic>>>uplink", value: "invalid" },
        { name: "inbound>>>levik-tun-in>>>traffic>>>downlink", value: -1 },
      ],
    }));
    expect(result).toEqual({ uplink: 0, downlink: 0 });
  });
});
