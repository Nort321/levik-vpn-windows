import { describe, expect, it } from "vitest";
import { countrySwitchLabel, serverSwitchLabel } from "../src/renderer/serverSwitchUi";
import type { AppSnapshot } from "../src/shared/contracts";

const connected: Pick<AppSnapshot, "status" | "selectedServerId" | "hotSwitchServerIds" | "hotSwitch"> = {
  status: "connected", selectedServerId: "a", hotSwitchServerIds: ["a", "b"],
};

describe("server switch choices", () => {
  it("distinguishes a hot target, a restarting target and the current selection before a click", () => {
    expect(serverSwitchLabel(connected, "b")).toBe("HotSwitch");
    expect(serverSwitchLabel(connected, "tuic")).toBe("с переподключением");
    expect(serverSwitchLabel(connected, "a")).toBeNull();
  });

  it("does not advertise a hot switch while disconnected or when the capability is missing", () => {
    expect(serverSwitchLabel({ ...connected, status: "disconnected" }, "b")).toBeNull();
    expect(serverSwitchLabel({ status: "connected", selectedServerId: "a" }, "b")).toBe("с переподключением");
    expect(serverSwitchLabel({ ...connected, hotSwitchServerIds: [] }, "a")).toBe("с переподключением");
  });

  it("warns about a country containing both compatible and restarting variants", () => {
    expect(countrySwitchLabel(connected, ["b"])).toBe("HotSwitch");
    expect(countrySwitchLabel(connected, ["b", "tuic"])).toBe("возможны переподключения");
    expect(countrySwitchLabel(connected, ["a", "b"])).toBeNull();
  });

  it("allows a visible recovery choice for an uncertain last acknowledged server", () => {
    const uncertain = { ...connected, hotSwitch: { phase: "uncertain" as const, targetServerId: "b", message: "Маршрут не подтверждён" } };
    expect(serverSwitchLabel(uncertain, "a")).toBe("HotSwitch");
    expect(countrySwitchLabel(uncertain, ["a"])).toBe("HotSwitch");
  });
});
