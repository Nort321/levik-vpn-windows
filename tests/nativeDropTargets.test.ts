import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dropTargetsWithCore, type NativeDropTargets, type NativeDropTarget } from "../src/main/core/nativeDropTargets";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { TargetFiles, planTargets, type TargetFile } from "../src/main/platform/levikDrop/files";
const temporary:string[]=[];
afterEach(async()=>{for(const path of temporary.splice(0)) await rm(path,{recursive:true,force:true});});
function configured(mode:"ts"|"shadow"|"rust"="rust"){
 const diagnostics:string[]=[];const core=new RustCore(null,(line)=>diagnostics.push(line),mode);const folder=join(tmpdir(),"TEST targets");
 const targets:TargetFile[]=[{name:"TEST.bin",size:4,partial:join(folder,".TEST.bin.levikdrop"),final:null}];
 const native:NativeDropTargets={offsets:vi.fn(async()=>({offsets:[0],prefix:[null]})),write:vi.fn(async(_i:number,offset:number,bytes:Buffer)=>offset+bytes.length),finish:vi.fn(async()=>join(folder,"TEST.bin")),closeWriting:vi.fn(async()=>{}),discardPartials:vi.fn(async()=>{})};
 const open=vi.fn((_folder:string,_targets:NativeDropTarget[])=>native);const report=vi.fn();
 return {core,folder,targets,native,open,report,diagnostics,create:()=>dropTargetsWithCore(core,open,folder,targets,report)};
}
describe("Drop recipient ownership",()=>{
 it.each(["ts","shadow"] as const)("does not construct a native writer in %s",(mode)=>{const c=configured(mode);expect(c.create()).toBeNull();expect(c.open).not.toHaveBeenCalled();});
 it("retains old modules and allows fallback only before adoption",()=>{const c=configured();expect(dropTargetsWithCore(c.core,undefined,c.folder,c.targets,c.report)).toBeNull();c.open.mockImplementation(()=>{throw new Error("PRIVATE_TEST_PATH");});expect(c.create()).toBeNull();expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_PATH");});
 it("preserves explicit null final paths across the ABI and stays selected across a mode change",async()=>{const c=configured();const owner=c.create()!;expect(c.open).toHaveBeenCalledWith(c.folder,[{name:"TEST.bin",size:4,partial:c.targets[0]!.partial,finalPath:null}]);c.core.setMode("ts");expect(await owner.offsets()).toEqual({offsets:[0],prefix:[null]});expect(await owner.write(0,0,Buffer.from("TEST"))).toBe(4);await owner.closeWriting();expect(c.native.closeWriting).toHaveBeenCalledOnce();});
 it("refuses paths outside the chosen folder before activation",()=>{const c=configured();c.targets[0]!.partial=join(tmpdir(),"outside.levikdrop");expect(()=>c.create()).toThrow("protocol");expect(c.open).not.toHaveBeenCalled();});
 it.each([{offsets:[4],prefix:[null]},{offsets:[2],prefix:[null]},{offsets:[0],prefix:[]},{offsets:[-1],prefix:[null]}])("rejects malformed native offsets without Node I/O",async(value)=>{const c=configured();c.native.offsets=vi.fn(async()=>value);const owner=c.create()!;await expect(owner.offsets()).rejects.toThrow("storage_error");expect(c.native.closeWriting).toHaveBeenCalledOnce();await expect(owner.write(0,0,Buffer.from("TEST"))).rejects.toThrow("storage_error");expect(c.native.write).not.toHaveBeenCalled();});
 it("validates write bounds before mutation and refuses a short native write result",async()=>{const c=configured();const owner=c.create()!;await expect(owner.write(0,3,Buffer.from("TEST"))).rejects.toThrow("protocol");expect(c.native.write).not.toHaveBeenCalled();const next=configured();next.native.write=vi.fn(async()=>3);await expect(next.create()!.write(0,0,Buffer.from("TEST"))).rejects.toThrow("storage_error");expect(next.open).toHaveBeenCalledOnce();});
 it("redacts storage errors and never retries a mutation through another implementation",async()=>{const c=configured();c.native.write=vi.fn(async()=>{throw new Error("PRIVATE_TEST_PATH");});const owner=c.create()!;await expect(owner.write(0,0,Buffer.from("TEST"))).rejects.toThrow("storage_error");await expect(owner.offsets()).rejects.toThrow("storage_error");expect(c.native.write).toHaveBeenCalledOnce();expect(c.open).toHaveBeenCalledOnce();});
 it("retains integrity and full-disk reasons while refusing an unexpected placement path",async()=>{for(const reason of ["integrity","storage_full"]){const c=configured();c.native.finish=vi.fn(async()=>{throw new Error(reason);});await expect(c.create()!.finish(0,"0".repeat(64))).rejects.toThrow(reason);}const c=configured();c.native.finish=vi.fn(async()=>join(tmpdir(),"outside.bin"));await expect(c.create()!.finish(0,"0".repeat(64))).rejects.toThrow("storage_error");});
 it("contains descriptor-close and discard errors without exposing paths",async()=>{const c=configured();c.native.closeWriting=vi.fn(async()=>{throw new Error("PRIVATE_TEST_PATH");});c.native.discardPartials=vi.fn(async()=>{throw new Error("PRIVATE_TEST_PATH");});const owner=c.create()!;await expect(owner.closeWriting()).resolves.toBeUndefined();await expect(owner.discardPartials()).resolves.toBeUndefined();expect(c.report).toHaveBeenCalledWith();});
});
const modulePath=process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("actual native Drop recipient",()=>{
 it("resumes, validates SHA-256, numbers a collision and updates the existing TargetFiles facade",async()=>{
  const loaded=loadLevikCore(modulePath!);if(loaded.state!=="loaded"||!loaded.module.openDropTargets)throw new Error("Native Drop recipient missing");
  const folder=await mkdtemp(join(tmpdir(),"levik-native-recipient-test-"));temporary.push(folder);const bytes=Buffer.alloc(700000,0x5a);
  const targets=await planTargets(folder,[{name:"TEST.bin",size:bytes.length}]);const mark=vi.fn(async()=>{});const core=new RustCore(null,()=>{},"rust");
  const backend=dropTargetsWithCore(core,loaded.module.openDropTargets,folder,targets,()=>{})!;const files=new TargetFiles(folder,targets,mark,backend);
  expect(await files.offsets()).toEqual({offsets:[0],prefix:[null]});
  await files.write(0,0,bytes.subarray(0,262144));await files.closeWriting();expect(await files.offsets()).toEqual({offsets:[262144],prefix:[createHash("sha256").update(bytes.subarray(0,262144)).digest("hex")]});
  for(let offset=262144;offset<bytes.length;offset+=262144)await files.write(0,offset,bytes.subarray(offset,offset+262144));
  await writeFile(join(folder,"TEST.bin"),"original");const final=await files.finish(0,createHash("sha256").update(bytes).digest("hex"));expect(final).toBe(join(folder,"TEST (1).bin"));expect(targets[0]!.final).toBe(final);expect(mark).toHaveBeenCalledWith(final);
  expect(await readFile(final)).toEqual(bytes);expect(await readFile(join(folder,"TEST.bin"),"utf8")).toBe("original");await files.discardPartials();expect(await readFile(final)).toEqual(bytes);
 },30_000);
});
