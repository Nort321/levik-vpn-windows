import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { planTargetsWithCore, type NativeDropFilePlan, type StartDropFilePlan } from "../src/main/core/nativeDropPlanning";
import { dropTargetsWithCore } from "../src/main/core/nativeDropTargets";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { TargetFiles, TransferFailure, planTargets } from "../src/main/platform/levikDrop/files";
import type { ManifestFile } from "../src/main/platform/levikDrop/protocol";
import type { NativeDropTarget } from "../src/main/core/nativeDropTargets";
const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
function configured(mode: "ts" | "shadow" | "rust" = "rust") {
  const folder = resolve(tmpdir(), "TEST-native-file-plan"), files = [{ name: "a.txt", size: 3 }];
  const diagnostics: string[] = [], core = new RustCore(null, (line) => diagnostics.push(line), mode);
  const planned: NativeDropTarget[] = [{ name: "a.txt", size: 3, partial: join(folder, ".a.txt.levikdrop"), finalPath: null }];
  const native: NativeDropFilePlan = { read: vi.fn(async () => planned), commit: vi.fn(), discard: vi.fn(async () => {}), close: vi.fn() };
  const start = vi.fn((_folder: string, _files: ManifestFile[]) => native), report = vi.fn();
  const fallback = [{ name: "a.txt", size: 3, partial: join(folder, ".a (1).txt.levikdrop"), final: null }];
  const typescript = vi.fn(async () => fallback);
  const run = () => planTargetsWithCore(core, start, folder, files, report, typescript);
  return { core, folder, files, diagnostics, planned, native, start, report, typescript, fallback, run };
}
describe("native file planning adoption", () => {
  it.each(["ts", "shadow"] as const)("does not construct a native plan in %s", async (mode) => {
    const c = configured(mode); expect(await c.run()).toBe(c.fallback); expect(c.start).not.toHaveBeenCalled();
  });
  it("keeps modules without planning on the existing path", async () => {
    const c = configured(); expect(await planTargetsWithCore(c.core, undefined, c.folder, c.files, c.report, c.typescript)).toBe(c.fallback);
  });
  it("falls back before any reservation when the pure constructor fails", async () => {
    const c = configured(); c.start.mockImplementation(() => { throw new Error("PRIVATE_TEST_PATH"); });
    expect(await c.run()).toBe(c.fallback); expect(c.native.read).not.toHaveBeenCalled(); expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_PATH");
  });
  it.each(["storage_full", "storage_error", "protocol", "PRIVATE_TEST_PATH"])("never reserves again after a native worker error: %s", async (reason) => {
    const c = configured(); c.native.read = vi.fn(async () => { throw new Error(reason); });
    await expect(c.run()).rejects.toMatchObject({ reason: reason === "PRIVATE_TEST_PATH" ? "storage_error" : reason });
    expect(c.typescript).not.toHaveBeenCalled(); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("retains expected metadata independently of caller and constructor input mutation", async () => {
    const c = configured(); let ready: (files: NativeDropTarget[]) => void = () => {};
    c.native.read = vi.fn(() => new Promise<NativeDropTarget[]>((done) => { ready = done; }));
    c.start.mockImplementation((_folder, files) => { files[0]!.name = "constructor mutation"; return c.native; });
    const pending = c.run(); c.files[0]!.name = "caller mutation"; c.files[0]!.size = 100;
    c.core.setMode("ts"); ready(c.planned);
    expect(await pending).toEqual([{ name: "a.txt", size: 3, partial: join(c.folder, ".a.txt.levikdrop"), final: null }]);
    expect(c.typescript).not.toHaveBeenCalled(); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("accepts numbered reservations using the existing extension rule", async () => {
    const c = configured(); c.planned[0]!.partial = join(c.folder, ".a (12).txt.levikdrop");
    expect((await c.run())[0]!.partial).toBe(c.planned[0]!.partial);
  });
  it.each(["outside", "unreserved", "renamed", "size", "final", "missing", "duplicate"])("rejects foreign plan output without filesystem replay: %s", async (kind) => {
    const c = configured();
    switch (kind) {
      case "outside": c.planned[0]!.partial = join(tmpdir(), ".a.txt.levikdrop"); break;
      case "unreserved": c.planned[0]!.partial = join(c.folder, ".unrelated.txt.levikdrop"); break;
      case "renamed": c.planned[0]!.name = "other.txt"; break;
      case "size": c.planned[0]!.size = 4; break;
      case "final": c.planned[0]!.finalPath = join(c.folder, "existing.txt"); break;
      case "missing": c.planned.splice(0); break;
      case "duplicate": c.files.push({ name: "a.txt", size: 3 }); c.planned.push({ ...c.planned[0]! }); break;
    }
    await expect(c.run()).rejects.toBeInstanceOf(TransferFailure); expect(c.typescript).not.toHaveBeenCalled(); expect(c.native.close).toHaveBeenCalledOnce();
  });
  it("rejects a foreign Promise ABI shape", async () => {
    const c = configured(); Object.defineProperty(c.native, "read", { value: () => "PRIVATE_TEST_PATH" });
    await expect(c.run()).rejects.toMatchObject({ reason: "protocol" }); expect(c.typescript).not.toHaveBeenCalled();
  });
  it("keeps lexical folder normalization on Node before native adoption", async () => {
    const c = configured(); expect(await planTargetsWithCore(c.core, c.start, c.folder + "/.", c.files, c.report, c.typescript)).toBe(c.fallback);
    expect(c.start).not.toHaveBeenCalled();
  });
  it("rejects invalid sizes before constructing either writer", async () => {
    const c = configured(); c.files[0]!.size = NaN; await expect(c.run()).rejects.toMatchObject({ reason: "protocol" });
    expect(c.start).not.toHaveBeenCalled(); expect(c.typescript).not.toHaveBeenCalled();
  });
  it("reports a cleanup failure without discarding successful reservations", async () => {
    const c = configured(); c.native.close = vi.fn(() => { throw new Error("PRIVATE_TEST_PATH"); });
    expect(await c.run()).toHaveLength(1); expect(c.report).toHaveBeenCalledWith(); expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_PATH");
  });
});
const modulePath = process.env.LEVIK_TEST_CORE;
function actual() {
  if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
  const loaded = loadLevikCore(modulePath);
  if (loaded.state !== "loaded" || !loaded.module.startDropFilePlan || !loaded.module.openDropTargets) throw new Error("Native file planner missing");
  return { core: new RustCore(loaded.module, () => {}, "rust", loaded.info.version), start: loaded.module.startDropFilePlan, targets: loaded.module.openDropTargets };
}
async function temp() { const folder = await mkdtemp(join(tmpdir(), "levik-planning-TEST-")); directories.push(folder); return folder; }
describe.skipIf(!modulePath)("actual native file planning", () => {
  it("matches Node reservations for normalization, system names and collisions", async () => {
    const root = await temp(), nativeFolder = join(root, "native"), nodeFolder = join(root, "node"); await mkdir(nativeFolder); await mkdir(nodeFolder);
    for (const folder of [nativeFolder, nodeFolder]) await writeFile(join(folder, ".é.txt.levikdrop"), "previous");
    const files = [{ name: "e\u0301.txt", size: 4 }, { name: "é.txt", size: 0 }, { name: "CON.txt", size: 1 }, { name: "../folder/name.bin", size: 2 }];
    const c = actual(), fallback = vi.fn(planTargets), native = await planTargetsWithCore(c.core, c.start, nativeFolder, files, () => {}, fallback);
    const node = await planTargets(nodeFolder, files);
    const visible = (targets: typeof native) => targets.map((target) => ({ name: target.name, size: target.size, partial: basename(target.partial), final: target.final }));
    expect(visible(native)).toEqual(visible(node)); expect(fallback).not.toHaveBeenCalled();
    expect(await readFile(join(nativeFolder, ".é.txt.levikdrop"), "utf8")).toBe("previous");
  });
  it("reserves simultaneous batches separately and hands them to native recipient I/O", async () => {
    const folder = await temp(), c = actual(), files = [{ name: "report.txt", size: 4 }]; await writeFile(join(folder, "report.txt"), "original");
    const planned = await Promise.all(Array.from({ length: 4 }, () => planTargetsWithCore(c.core, c.start, folder, files, () => {})));
    expect(new Set(planned.map((targets) => targets[0]!.partial)).size).toBe(4);
    const io = dropTargetsWithCore(c.core, c.targets, folder, planned[0]!, () => {}); expect(io).not.toBeNull();
    const mark = vi.fn(async () => {}), targets = new TargetFiles(folder, planned[0]!, mark, io);
    await targets.offsets(); await targets.write(0, 0, Buffer.from("TEST")); await targets.finish(0, createHash("sha256").update("TEST").digest("hex"));
    expect(await readFile(join(folder, "report (1).txt"), "utf8")).toBe("TEST"); expect(await readFile(join(folder, "report.txt"), "utf8")).toBe("original"); expect(mark).toHaveBeenCalledOnce();
    await targets.closeWriting();
  });
  it("rolls back a real reservation when bridge validation refuses the unclaimed result", async () => {
    const folder = await temp(), c = actual(); await writeFile(join(folder, "sentinel.txt"), "keep");
    const start: StartDropFilePlan = (destination, files) => {
      const native = c.start(destination, files);
      return { read: async () => { const rows = await native.read(); rows[0]!.name = "foreign name"; return rows; },
        commit: () => native.commit(), discard: () => native.discard(), close: () => native.close() };
    };
    await expect(planTargetsWithCore(c.core, start, folder, [{ name: "TEST.txt", size: 0 }], () => {})).rejects.toMatchObject({ reason: "protocol" });
    expect(await readdir(folder)).toEqual(["sentinel.txt"]); expect(await readFile(join(folder, "sentinel.txt"), "utf8")).toBe("keep");
  });
  it("GC rolls back an abandoned unclaimed plan while its Node process remains alive", async () => {
    const root = await temp(), folder = join(root, "reservations"), script = join(root, "gc.cjs"); await mkdir(folder);
    await writeFile(script, `
      const core = require(process.argv[2]), fs = require('node:fs');
      const folder = process.argv[3];
      async function reserve() {
        const owner = core.startDropFilePlan(folder,[{name:'TEST abandoned.txt',size:0}]);
        const files = await owner.read();
        if(files.length!==1 || !fs.existsSync(files[0].partial)) throw new Error('TEST reservation missing');
      }
      (async()=>{
        await reserve();
        const deadline = Date.now()+10000;
        do {
          global.gc(); await new Promise(done=>setTimeout(done,20));
          if(fs.readdirSync(folder).length===0) { console.log('TEST unclaimed plan cleaned'); return; }
        } while(Date.now()<deadline);
        throw new Error('TEST abandoned plan retained its reservation');
      })().catch(error=>{console.error(error.message);process.exitCode=1;});
    `);
    const result = await promisify(execFile)(process.execPath, ["--expose-gc", script, modulePath!, folder], { timeout: 15000, maxBuffer: 16384 });
    expect(result.stdout).toContain("TEST unclaimed plan cleaned"); expect(await readdir(folder)).toEqual([]);
  }, 30_000);
  it("keeps unsupported UTF16 filename text on Node before native filesystem work", async () => {
    const folder = await temp(), c = actual(), fallback = vi.fn(planTargets);
    const targets = await planTargetsWithCore(c.core, c.start, folder, [{ name: "bad-\ud800.txt", size: 0 }], () => {}, fallback);
    expect(fallback).toHaveBeenCalledOnce(); expect(targets).toHaveLength(1);
    expect(dropTargetsWithCore(c.core, c.targets, folder, targets, () => {})).toBeNull();
    const receiver = new TargetFiles(folder, targets, async () => {}); await receiver.offsets();
    await receiver.finish(0, createHash("sha256").update(Buffer.alloc(0)).digest("hex"));
    expect((await readdir(folder)).filter((name) => !name.endsWith(".levikdrop"))).toHaveLength(1);
  });
});
