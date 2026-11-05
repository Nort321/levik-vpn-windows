import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dropSourceWithCore, type NativeDropSource } from "../src/main/core/nativeDropSource";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { TransferFailure, type SourceFile } from "../src/main/platform/levikDrop/files";
const temporary: string[] = [];
afterEach(async () => { for (const path of temporary.splice(0)) await rm(path,{recursive:true,force:true}); });
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const diagnostics: string[] = []; const core = new RustCore(null,(line) => diagnostics.push(line),mode);
  const native: NativeDropSource = { read: vi.fn(async () => Buffer.from("TEST")), digest: vi.fn(() => "0".repeat(64)), close: vi.fn() };
  const open = vi.fn((_path: string, _size: number, _mtime: number, _offset: number, _prefix: string | null) => native);
  const file: SourceFile = { path: join(tmpdir(),"TEST.bin"), name: "TEST.bin", size: 4, mtimeMs: 123 };
  const report = vi.fn(); const create = () => dropSourceWithCore(core,open,file,0,null,report);
  return { core,native,open,file,report,diagnostics,create };
}
describe("Drop source ownership", () => {
  it.each(["ts","shadow"] as const)("performs no native I/O in %s", (mode) => {
    const c=configured(mode); expect(c.create()).toBeNull(); expect(c.open).not.toHaveBeenCalled();
  });
  it("retains an older module and falls back only before a reader exists", () => {
    const c=configured(); expect(dropSourceWithCore(c.core,undefined,c.file,0,null,c.report)).toBeNull();
    c.open.mockImplementation(() => { throw new Error("PRIVATE_TEST_PATH"); }); expect(c.create()).toBeNull();
    expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_PATH");
  });
  it("bounds offsets and resume hashes before invoking native", () => {
    const c=configured();
    for(const offset of [-1,5,0.5,NaN]) expect(() => dropSourceWithCore(c.core,c.open,c.file,offset,null,c.report)).toThrow("protocol");
    expect(() => dropSourceWithCore(c.core,c.open,c.file,1,null,c.report)).toThrow("protocol"); expect(c.open).not.toHaveBeenCalled();
  });
  it("retains a reader across a mode change and closes it once", async () => {
    const c=configured(); const source=c.create()!; c.core.setMode("ts"); expect(await source.read()).toEqual(Buffer.from("TEST"));
    c.native.read=vi.fn(async () => null); expect(await source.read()).toBeNull(); expect(source.digest()).toBe("0".repeat(64));
    source.close(); source.close(); expect(c.native.close).toHaveBeenCalledOnce(); await expect(source.read()).rejects.toThrow("source_unreadable");
  });
  it.each(["empty","oversize","past end"])("rejects %s native output without replaying a byte", async (kind) => {
    const c=configured(); c.native.read=vi.fn(async () => Buffer.alloc(kind==="oversize" ? 262145 : kind==="past end" ? 5 : 0));
    const source=c.create()!; await expect(source.read()).rejects.toThrow(TransferFailure);
    expect(c.native.close).toHaveBeenCalledOnce(); expect(c.open).toHaveBeenCalledOnce(); await expect(source.read()).rejects.toThrow("source_unreadable");
  });
  it("rejects an unexpected ABI return type without exposing its contents", async () => {
    const close=vi.fn(); const loaded=loadLevikCore("TEST.node",{exists:()=>true,platform:"darwin",arch:"arm64",load:()=>({
      coreInfo:()=>({version:"0.20.0",contract:2,os:"macos",arch:"aarch64"}),functions:()=>[],call:()=>"null",
      openDropSource:()=>({read:async()=>"PRIVATE_TEST_PATH",digest:()=>"0".repeat(64),close}),
    })});
    if(loaded.state!=="loaded") throw new Error("TEST module rejected"); const c=configured();
    const source=dropSourceWithCore(c.core,loaded.module.openDropSource,c.file,0,null,c.report)!;
    await expect(source.read()).rejects.toThrow("protocol"); expect(close).toHaveBeenCalledOnce();
  });
  it("redacts native I/O errors and retires the attempt", async () => {
    const c=configured(); c.native.read=vi.fn(async () => { throw new Error("PRIVATE_TEST_PATH"); });
    const source=c.create()!; await expect(source.read()).rejects.toThrow("source_unreadable"); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("rejects early EOF and an invalid final digest", async () => {
    const c=configured(); c.native.read=vi.fn(async () => null); await expect(c.create()!.read()).rejects.toThrow("source_changed");
    const other=configured(); const source=other.create()!; await source.read(); other.native.read=vi.fn(async () => null); await source.read();
    other.native.digest=vi.fn(() => "PRIVATE_TEST_PATH"); expect(() => source.digest()).toThrow("protocol"); expect(other.native.close).toHaveBeenCalledOnce();
  });
  it("drops an in-flight result after cancellation and never reopens the file", async () => {
    const c=configured(); let resolve: (bytes: Buffer) => void = () => {};
    c.native.read=vi.fn(() => new Promise<Buffer>((done) => { resolve=done; })); const source=c.create()!; const read=source.read();
    source.close(); resolve(Buffer.from("TEST")); await expect(read).rejects.toThrow("source_unreadable"); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("refuses concurrent reads without draining the source twice", async () => {
    const c=configured(); let resolve: (bytes: Buffer) => void = () => {}; c.native.read=vi.fn(() => new Promise<Buffer>((done) => { resolve=done; }));
    const source=c.create()!; const first=source.read(); await expect(source.read()).rejects.toThrow("protocol");
    resolve(Buffer.from("TEST")); await expect(first).rejects.toThrow("source_unreadable"); expect(c.native.read).toHaveBeenCalledOnce();
  });
});
const modulePath=process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("actual native Drop source", () => {
  it("reads a resumed file in bounded chunks and produces the full Node SHA-256", async () => {
    const loaded=loadLevikCore(modulePath!); if(loaded.state!=="loaded" || !loaded.module.openDropSource) throw new Error("Native Drop source missing");
    const directory=await mkdtemp(join(tmpdir(),"levik-source-client-test-")); temporary.push(directory);
    const path=join(directory,"TEST.bin"); const bytes=Buffer.alloc(700000,0x5a); await writeFile(path,bytes); const info=await stat(path);
    const file={path,name:"TEST.bin",size:bytes.length,mtimeMs:Math.trunc(info.mtimeMs)}; const offset=262151;
    const prefix=createHash("sha256").update(bytes.subarray(0,offset)).digest("hex");
    const source=dropSourceWithCore(new RustCore(null,()=>{},"rust"),loaded.module.openDropSource,file,offset,prefix,()=>{})!;
    try {
      const chunks: Buffer[]=[]; for(;;){const chunk=await source.read(); if(chunk===null) break; expect(chunk.length).toBeLessThanOrEqual(262144); chunks.push(chunk);}
      expect(Buffer.concat(chunks)).toEqual(bytes.subarray(offset)); expect(source.digest()).toBe(createHash("sha256").update(bytes).digest("hex"));
      expect(await readFile(path)).toEqual(bytes);
    } finally {source.close();}
  }, 30_000);
});
