import { describe, expect, it } from "vitest";
import { windowsProcessFromPath } from "../src/main/windows/processes";

describe("Windows process split tunneling", () => {
  it("keeps the executable extension required by Xray", () => {
    expect(windowsProcessFromPath("C:\\Program Files\\Telegram Desktop\\Telegram.exe")).toEqual({
      name: "Telegram.exe",
      path: "C:/Program Files/Telegram Desktop/Telegram.exe",
    });
  });

  it("rejects non-executable selections", () => {
    expect(windowsProcessFromPath("C:\\Temp\\notes.txt")).toBeNull();
  });
});
