import { describe, expect, it } from "vitest";
import { isPairingId, normalizeActivationCode, normalizePairingCode, parseDevicePairing, parseDevicePairingStatus } from "../src/main/platform/devicePairing";

const id = "74ea3429-0a7e-4f42-a4ef-50f019c13a39";
const pairing = { id, uri: `https://leviknet.com/activate?pair=${"p".repeat(43)}`, code: "ABCD-EFGH-JK23", expiresAt: "2026-11-05T12:05:00.000Z" };

describe("device pairing", () => {
  it("accepts a pairing code typed with spaces, lower case or without dashes", () => {
    for (const typed of ["ABCD-EFGH-JK23", " abcd efgh jk23 ", "abcdefghjk23"]) expect(normalizePairingCode(typed)).toBe("ABCD-EFGH-JK23");
    for (const typed of ["ABCD-EFGH", "ABCD-EFGH-JK2O", "ABCD-EFGH-JK23-MN45x"]) expect(() => normalizePairingCode(typed)).toThrow();
  });

  it("tells which device each kind of code belongs on", () => {
    expect(() => normalizePairingCode("ABCD-EFGH-JK23-MN45")).toThrow(/устройстве, где вы уже вошли/);
    expect(() => normalizeActivationCode("ABCD-EFGH-JK23")).toThrow(/на новом устройстве/);
    expect(normalizeActivationCode("abcd efgh jk23 mn45")).toBe("ABCD-EFGH-JK23-MN45");
  });

  it("draws only the website's one-time pairing link", () => {
    expect(parseDevicePairing(pairing)).toEqual(pairing);
    for (const uri of [
      `http://leviknet.com/activate?pair=${"p".repeat(43)}`,
      `https://leviknet.com/other?pair=${"p".repeat(43)}`,
      `https://leviknet.com/activate?pair=${"p".repeat(43)}&next=x`,
      "https://leviknet.com/activate?pair=short",
      `https://user:pass@leviknet.com/activate?pair=${"p".repeat(43)}`,
      "javascript:alert(1)",
    ]) expect(() => parseDevicePairing({ ...pairing, uri })).toThrow();
    expect(() => parseDevicePairing({ ...pairing, id: "1" })).toThrow();
    expect(() => parseDevicePairing({ ...pairing, code: "ABCD-EFGH-JK23-MN45" })).toThrow();
    expect(() => parseDevicePairing(null)).toThrow();
  });

  it("reads the pairing state and trims the connected device's name", () => {
    expect(parseDevicePairingStatus({ ok: true, state: "pending" })).toEqual({ state: "pending" });
    expect(parseDevicePairingStatus({ ok: true, state: "connected", deviceName: "  Android TV " })).toEqual({ state: "connected", deviceName: "Android TV" });
    expect(parseDevicePairingStatus({ ok: true, state: "connected", deviceName: 7 })).toEqual({ state: "connected", deviceName: null });
    expect(() => parseDevicePairingStatus({ ok: true, state: "claimed" })).toThrow();
  });

  it("checks pairing ids before they reach the main process", () => {
    expect(isPairingId(id)).toBe(true);
    for (const value of ["", "../x", 42, null, id.toUpperCase()]) expect(isPairingId(value)).toBe(false);
  });
});
