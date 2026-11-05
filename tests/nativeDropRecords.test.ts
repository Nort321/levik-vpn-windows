import { afterEach, describe, expect, it, vi } from "vitest";
import { dropRecordsWithCore, type NativeDropRecords } from "../src/main/core/nativeDropRecords";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { MAX_FRAME, ProtocolError, RecordOpener, RecordSealer, type DropRecords, type SessionKeys } from "../src/main/platform/levikDrop/protocol";
import vectors from "./fixtures/levikDropVectors.json";

function keys(): SessionKeys {
  return { sr: Buffer.alloc(32, 0x41), rs: Buffer.alloc(32, 0x42), lan: Buffer.alloc(32, 0x43), code: "123 456" };
}
const owners: DropRecords[] = [];
afterEach(() => { for (const owner of owners) owner.close(); owners.length = 0; });
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const diagnostics: string[] = [];
  const core = new RustCore(null, (text) => diagnostics.push(text), mode);
  const frame = Buffer.alloc(26); frame[0] = 0x10;
  const native: NativeDropRecords = { seal: vi.fn(() => frame), open: vi.fn(() => Buffer.from("x")), close: vi.fn() };
  const open = vi.fn((_send: Buffer, _receive: Buffer) => native); const report = vi.fn();
  const create = (role: "sender" | "receiver" = "sender") => {
    const codec = dropRecordsWithCore(core, open, keys(), role, report);
    if (codec) owners.push(codec);
    return codec;
  };
  return { core, diagnostics, native, open, report, create };
}

describe("Drop record attempt ownership", () => {
  it.each(["ts", "shadow"] as const)("retains Node crypto without creating a native counter in %s", (mode) => {
    const { create, open } = configured(mode); expect(create()).toBeNull(); expect(open).not.toHaveBeenCalled();
  });
  it("keeps older modules working", () => {
    const { core, report } = configured(); expect(dropRecordsWithCore(core, undefined, keys(), "sender", report)).toBeNull();
  });
  it.each(["sender", "receiver"] as const)("selects the exact directional keys for %s", (role) => {
    const { create, open, native } = configured(); const codec = create(role); expect(codec).not.toBeNull();
    const sample = keys();
    expect(open).toHaveBeenCalledWith(role === "sender" ? sample.sr : sample.rs, role === "sender" ? sample.rs : sample.sr);
    expect(codec?.seal(Buffer.from("x")).length).toBe(26); expect(native.seal).toHaveBeenCalledWith(Buffer.from("x"), false);
    codec?.close(); codec?.close(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("falls back only before constructing a usable owner and does not expose an activation error", () => {
    const { create, open, diagnostics } = configured(); open.mockImplementation(() => { throw new Error("PRIVATE_TEST_MARKER"); });
    expect(create()).toBeNull(); expect(diagnostics.length).toBeGreaterThan(0); expect(diagnostics.join(" ")).not.toContain("PRIVATE_TEST_MARKER");
  });
  it.each(["throw", "wrong bytes", "wrong length"])("ends the attempt after native seal %s, without a new factory or counter", (kind) => {
    const { create, native, open } = configured();
    native.seal = vi.fn(() => { if (kind === "throw") throw new Error("PRIVATE_TEST_MARKER"); return kind === "wrong bytes" ? Buffer.alloc(26) : Buffer.alloc(0); });
    const codec = create(); expect(() => codec?.seal(Buffer.from("x"))).toThrow("native record operation failed");
    expect(() => codec?.seal(Buffer.from("x"))).toThrow("no keys"); expect(native.close).toHaveBeenCalledOnce(); expect(open).toHaveBeenCalledOnce();
  });
  it("bounds plaintext/record bytes before invoking native operations", () => {
    const { create, native } = configured(); const codec = create();
    expect(() => codec?.seal(Buffer.alloc(MAX_FRAME))).toThrow("record too long"); expect(native.seal).not.toHaveBeenCalled();
    const next = configured(); const receiver = next.create();
    expect(() => receiver?.open(Buffer.alloc(MAX_FRAME + 1))).toThrow("not a record"); expect(next.native.open).not.toHaveBeenCalled();
  });
  it("rejects an unexpected ABI return type without exposing its bytes", () => {
    const close = vi.fn();
    const loaded = loadLevikCore("/TEST.node", { exists: () => true, platform: "darwin", arch: "arm64", load: () => ({
      coreInfo: () => ({ version: "0.18.0", contract: 2, os: "macos", arch: "aarch64" }), functions: () => [], call: () => "null",
      openDropRecords: () => ({ seal: () => "PRIVATE_TEST_MARKER", open: () => Buffer.from("x"), close }),
    }) });
    if (loaded.state !== "loaded") throw new Error("TEST module rejected");
    const codec = dropRecordsWithCore(new RustCore(null, () => {}, "rust"), loaded.module.openDropRecords, keys(), "sender", () => {});
    if (!codec) throw new Error("TEST owner missing"); owners.push(codec);
    expect(() => codec.seal(Buffer.from("x"))).toThrow("native record operation failed"); expect(close).toHaveBeenCalledOnce();
    expect(() => codec.seal(Buffer.from("x"))).toThrow("no keys");
  });
  it("retains an activated codec across a mode change and closes it once", () => {
    const { create, core, native } = configured(); const codec = create(); core.setMode("ts");
    codec?.seal(Buffer.from("x")); expect(native.seal).toHaveBeenCalledOnce(); codec?.close(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("does not leak a native close error or prevent the owner from retiring", () => {
    const { create, native, report } = configured(); native.close = vi.fn(() => { throw new Error("PRIVATE_TEST_MARKER"); }); const codec = create();
    expect(() => codec?.close()).not.toThrow(); expect(report).toHaveBeenCalledWith();
    expect(() => codec?.seal(Buffer.from("x"))).toThrow("no keys"); codec?.close(); expect(native.close).toHaveBeenCalledOnce();
  });
  it("rejects invalid directional keys before activation", () => {
    const { core, open, report } = configured(); expect(() => dropRecordsWithCore(core, open, { ...keys(), sr: Buffer.alloc(31) }, "sender", report)).toThrow("bad key length");
    expect(open).not.toHaveBeenCalled();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
function factory() {
  if (!modulePath) throw new Error("LEVIK_TEST_CORE missing"); const status = loadLevikCore(modulePath);
  if (status.state !== "loaded" || !status.module.openDropRecords) throw new Error("Native Drop record owner missing");
  return status.module.openDropRecords;
}
describe.skipIf(!modulePath)("actual native Drop records", () => {
  it("matches Node bytes and decrypts both directions through full-size data frames", () => {
    const sample = keys(); const native = factory()(sample.sr, sample.rs); const nodeWriter = new RecordSealer(sample.rs);
    const nodeReader = new RecordOpener(sample.sr); const expectedWriter = new RecordSealer(sample.sr);
    try {
      for (const size of [1, 17, 65536, 262144]) {
        for (const data of [false, true]) {
          const plain = Buffer.alloc(size, 0x5a); const frame = native.seal(plain, data);
          expect(frame.equals(expectedWriter.seal(plain, data))).toBe(true); expect(nodeReader.open(frame).equals(plain)).toBe(true);
          expect(native.open(nodeWriter.seal(plain, data)).equals(plain)).toBe(true);
        }
      }
    } finally { native.close(); sample.sr.fill(0); sample.rs.fill(0); sample.lan.fill(0); }
  });
  it("matches the Android-shared record vector", () => {
    const native = factory()(Buffer.from(vectors.sr, "hex"), Buffer.from(vectors.rs, "hex"));
    try {
      native.seal(Buffer.from("x"), false);
      expect(native.seal(Buffer.from([1, ...Buffer.from('{"t":"done"}')]), false).toString("hex")).toBe(vectors.record1);
    } finally { native.close(); }
  });
  it("does not advance raw receive state on damaged authentication or replay", () => {
    const sample = keys(); const native = factory()(sample.sr, sample.rs); const writer = new RecordSealer(sample.rs);
    try {
      const valid = writer.seal(Buffer.from("TEST")); const bad = Buffer.from(valid); bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
      expect(() => native.open(bad)).toThrow("record does not authenticate"); expect(native.open(valid).toString()).toBe("TEST");
      expect(() => native.open(valid)).toThrow("record out of order");
    } finally { native.close(); }
  });
  it("turns a native authentication error into a terminal ProtocolError at the session boundary", () => {
    const sample = keys(); const codec = dropRecordsWithCore(new RustCore(null, () => {}, "rust"), factory(), sample, "sender", () => {});
    if (!codec) throw new Error("TEST native owner missing"); owners.push(codec);
    const bad = new RecordSealer(sample.rs).seal(Buffer.from("TEST")); bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    expect(() => codec.open(bad)).toThrow(ProtocolError); expect(() => codec.open(bad)).toThrow("no keys");
  });
});
