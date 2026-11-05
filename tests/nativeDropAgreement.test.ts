import { createECDH, createPublicKey, generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { dropAgreementWithCore, type NativeDropAgreement } from "../src/main/core/nativeDropAgreement";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { ProtocolError, sessionKeys, verifyTranscript } from "../src/main/platform/levikDrop/protocol";
import type { Identity } from "../src/main/platform/levikDrop/session";

function identity(): Identity {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { privateKey: pair.privateKey, spki: pair.publicKey.export({ type: "spki", format: "der" }) };
}
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const diagnostics: string[] = []; const core = new RustCore(null, (text) => diagnostics.push(text), mode);
  const own = identity(); const report = vi.fn(); const point = Buffer.alloc(65, 0x41); point[0] = 4;
  const keys = { sr: Buffer.alloc(32, 0x41), rs: Buffer.alloc(32, 0x42), lan: Buffer.alloc(32, 0x43), code: "123 456" };
  const native: NativeDropAgreement = { publicKey: vi.fn(() => point), signTranscript: vi.fn(() => Buffer.alloc(70)), derive: vi.fn(() => keys), close: vi.fn() };
  let serialized: Buffer | undefined;
  const open = vi.fn((der: Buffer, _spki: Buffer) => { serialized = der; return native; });
  const create = () => dropAgreementWithCore(core, open, own, report);
  return { own, core, diagnostics, native, open, create, report, keys, serialized: () => serialized };
}

describe("Drop agreement attempt ownership", () => {
  it.each(["ts", "shadow"] as const)("does not export private material or create ECDH in %s", (mode) => {
    const c = configured(mode); const spy = vi.spyOn(c.own.privateKey, "export");
    expect(c.create()).toBeNull(); expect(c.open).not.toHaveBeenCalled(); expect(spy).not.toHaveBeenCalled();
  });
  it("retains compatibility with older modules without exporting PKCS8", () => {
    const c = configured(); const spy = vi.spyOn(c.own.privateKey, "export");
    expect(dropAgreementWithCore(c.core, undefined, c.own, c.report)).toBeNull(); expect(spy).not.toHaveBeenCalled();
  });
  it("exports the existing identity only during activation and erases its DER copy", () => {
    const c = configured(); const agreement = c.create(); expect(agreement).not.toBeNull();
    expect(c.open).toHaveBeenCalledWith(expect.any(Buffer), c.own.spki);
    expect(c.serialized()?.every((byte) => byte === 0)).toBe(true);
    const point = agreement!.publicKey(); point.fill(0); expect(agreement!.publicKey()[0]).toBe(4);
    agreement!.close(); agreement!.close(); expect(c.native.close).toHaveBeenCalledOnce();
    expect(() => agreement!.publicKey()).toThrow("no keys");
  });
  it("erases an exported private buffer even when its length is rejected", () => {
    const c = configured(); const large = Buffer.alloc(4097, 0x41);
    Object.defineProperty(c.own.privateKey, "export", { value: () => large, configurable: true });
    expect(c.create()).toBeNull(); expect(c.open).not.toHaveBeenCalled(); expect(large.every((v) => v === 0)).toBe(true);
  });
  it("allows fallback only before selecting a usable ephemeral point", () => {
    const c = configured(); c.native.publicKey = vi.fn(() => { throw new Error("PRIVATE_TEST_MARKER"); });
    expect(c.create()).toBeNull(); expect(c.native.close).toHaveBeenCalledOnce();
    expect(c.serialized()?.every((v) => v === 0)).toBe(true); expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_MARKER");
  });
  it("keeps the chosen implementation across a flag change and derives once", () => {
    const c = configured(); const agreement = c.create()!; c.core.setMode("ts");
    expect(agreement.sessionKeys(Buffer.alloc(65, 4), Buffer.alloc(32))).toEqual(c.keys);
    expect(() => agreement.sessionKeys(Buffer.alloc(65, 4), Buffer.alloc(32))).toThrow("no keys");
    expect(c.open).toHaveBeenCalledOnce(); expect(c.native.derive).toHaveBeenCalledOnce(); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("ends the attempt without replay or leaking a signing error", () => {
    const c = configured(); const agreement = c.create()!;
    c.native.signTranscript = vi.fn(() => { throw new Error("PRIVATE_TEST_MARKER"); });
    expect(() => agreement.signTranscript("sender", Buffer.alloc(32))).toThrow("native handshake operation failed");
    expect(() => agreement.sessionKeys(Buffer.alloc(65, 4), Buffer.alloc(32))).toThrow("no keys"); expect(c.open).toHaveBeenCalledOnce();
  });
  it("rejects malformed key output and erases all returned buffers", () => {
    const c = configured(); const agreement = c.create()!; c.keys.sr = Buffer.alloc(31, 0x41);
    expect(() => agreement.sessionKeys(Buffer.alloc(65, 4), Buffer.alloc(32))).toThrow(ProtocolError);
    for (const key of [c.keys.sr, c.keys.rs, c.keys.lan]) expect(key.every((v) => v === 0)).toBe(true);
    expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("validates transcript and point lengths before invoking native operations", () => {
    const c = configured(); const agreement = c.create()!;
    expect(() => agreement.signTranscript("sender", Buffer.alloc(31))).toThrow("bad transcript"); expect(c.native.signTranscript).not.toHaveBeenCalled();
    const next = configured(); expect(() => next.create()!.sessionKeys(Buffer.alloc(32), Buffer.alloc(32))).toThrow("bad ephemeral key");
    expect(next.native.derive).not.toHaveBeenCalled();
  });
  it("contains close errors and closes at most once", () => {
    const c = configured(); const agreement = c.create()!; c.native.close = vi.fn(() => { throw new Error("PRIVATE_TEST_MARKER"); });
    expect(() => agreement.close()).not.toThrow(); agreement.close(); expect(c.report).toHaveBeenCalledWith(); expect(c.native.close).toHaveBeenCalledOnce();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("actual native P-256 agreement", () => {
  it("keeps the same identity, signs role-bound Node-verifiable DER and agrees on every key", () => {
    const loaded = loadLevikCore(modulePath!);
    if (loaded.state !== "loaded" || !loaded.module.openDropAgreement) throw new Error("Native Drop agreement missing");
    const own = identity(); const report = vi.fn(); const core = new RustCore(null, () => {}, "rust");
    const agreement = dropAgreementWithCore(core, loaded.module.openDropAgreement, own, report)!;
    const peer = createECDH("prime256v1"); peer.generateKeys(); const th = Buffer.alloc(32, 0x5a);
    try {
      const point = agreement.publicKey(); const proof = agreement.signTranscript("sender", th);
      expect(verifyTranscript("sender", own.spki, th, proof)).toBe(true);
      expect(verifyTranscript("receiver", own.spki, th, proof)).toBe(false);
      expect(createPublicKey(own.privateKey).export({ type: "spki", format: "der" })).toEqual(own.spki);
      const expected = sessionKeys(peer, point, th); const keys = agreement.sessionKeys(peer.getPublicKey(), th);
      try { expect(keys).toEqual(expected); } finally { for (const k of [keys, expected]) { k.sr.fill(0); k.rs.fill(0); k.lan.fill(0); } }
      expect(() => agreement.sessionKeys(peer.getPublicKey(), th)).toThrow("no keys");
    } finally { agreement.close(); }
    expect(report).not.toHaveBeenCalled();
  });
  it("refuses a mismatched restored identity before choosing a public point", () => {
    const loaded = loadLevikCore(modulePath!);
    if (loaded.state !== "loaded" || !loaded.module.openDropAgreement) throw new Error("Native Drop agreement missing");
    const own = identity(); own.spki = identity().spki; const diagnostics: string[] = [];
    expect(dropAgreementWithCore(new RustCore(null, (line) => diagnostics.push(line), "rust"), loaded.module.openDropAgreement, own, () => {})).toBeNull();
    expect(diagnostics.length).toBeGreaterThan(0);
  });
});
