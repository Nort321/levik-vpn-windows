import { describe, expect, it } from "vitest";
import { shouldShowLogin } from "../src/shared/sessionState";

describe("offline session rendering", () => {
  it("keeps an existing local session out of the login screen while offline", () => {
    expect(shouldShowLogin({ sessionAvailable: true })).toBe(false);
  });

  it("shows login only when no local session exists", () => {
    expect(shouldShowLogin({ sessionAvailable: false })).toBe(true);
  });
});
