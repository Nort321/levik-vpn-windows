import { describe, expect, it } from "vitest";
import { isCabinetTarget } from "../src/main/platform/links";
import { ruleRoutingKey } from "../src/main/vpn/tunnelProfile";

const routing = { directDomains: ["domain:sberbank.ru"], proxyDomains: ["domain:youtube.com"] };

describe("account rules", () => {
  it("reconnect only when the rules routing changed", () => {
    expect(ruleRoutingKey(routing)).toBe(ruleRoutingKey({ ...routing, directDomains: ["domain:sberbank.ru"] }));
    expect(ruleRoutingKey(routing)).not.toBe(ruleRoutingKey({ ...routing, directDomains: [] }));
    expect(ruleRoutingKey(routing)).not.toBe(ruleRoutingKey({ ...routing, proxyDomains: [] }));
    expect(ruleRoutingKey(null)).toBeNull();
  });

  it("open the cabinet's rules page", () => {
    expect(isCabinetTarget("/dashboard/rules")).toBe(true);
  });
});
