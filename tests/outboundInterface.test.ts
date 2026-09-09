import { describe, expect, it } from "vitest";
import { selectWindowsOutboundInterface } from "../src/main/windows/outboundInterface";

const ethernet = { name: "Ethernet", physical: true, up: true, index: 2, prefix: "0.0.0.0/0", routeMetric: 10, interfaceMetric: 5 };

describe("Windows physical outbound interface", () => {
  it("uses the combined route and interface metric instead of preferring the Wi-Fi name", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "Wi-Fi", index: 3, routeMetric: 1, interfaceMetric: 50 },
      ethernet,
    ])).toBe("Ethernet");
    expect(selectWindowsOutboundInterface([
      ethernet,
      { ...ethernet, name: "Wi-Fi", index: 3, interfaceMetric: 1 },
    ])).toBe("Wi-Fi");
  });

  it("excludes TUN, virtual adapters, disconnected adapters and non-default routes", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "LevikVPN", routeMetric: 0 },
      { ...ethernet, name: "Other VPN", physical: false, routeMetric: 0 },
      { ...ethernet, name: "Wi-Fi", up: false, routeMetric: 0 },
      { ...ethernet, name: "Half default", prefix: "0.0.0.0/1", routeMetric: 0 },
      ethernet,
    ])).toBe("Ethernet");
  });

  it("supports singleton PowerShell output, Unicode aliases and IPv6-only networks", () => {
    expect(selectWindowsOutboundInterface({ ...ethernet, name: "Сеть Ethernet", prefix: "::/0" })).toBe("Сеть Ethernet");
  });

  it("prefers IPv4 when different adapters own the two default routes, with a stable metric tie-break", () => {
    expect(selectWindowsOutboundInterface([
      { ...ethernet, name: "IPv6", prefix: "::/0", routeMetric: 0, interfaceMetric: 0 },
      { ...ethernet, name: "Higher index", index: 3 },
      ethernet,
    ])).toBe("Ethernet");
  });

  it.each([null, [], {}, [{ ...ethernet, routeMetric: "10" }], [{ ...ethernet, interfaceMetric: -1 }], [{ ...ethernet, name: "bad\nname" }]])(
    "fails closed for unavailable or malformed route data: %j",
    (value) => expect(() => selectWindowsOutboundInterface(value)).toThrow(/физического интерфейса/),
  );
});
