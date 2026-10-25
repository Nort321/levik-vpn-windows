import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-drop-lifecycle", getVersion: () => "1.0.0", isPackaged: true, setLoginItemSettings: vi.fn() } }));
vi.mock("../src/main/update/appUpdater", () => ({ AppUpdater: class { on(): this { return this; } } }));
vi.mock("../src/main/windows/killSwitch", async (original) => ({ ...await original<typeof import("../src/main/windows/killSwitch")>(), WindowsKillSwitch: class {} }));
import { AppController } from "../src/main/appController";
import { MobileApiError } from "../src/main/api/mobileApiClient";
import { DropEngine } from "../src/main/platform/levikDrop/engine";
import type { DropApi } from "../src/main/platform/levikDrop/engine";
const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: Error) => void; const promise = new Promise<T>((yes,no) => { resolve=yes; reject=no; }); return { promise, resolve, reject }; }
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of cleanups.splice(0).reverse()) await close(); vi.restoreAllMocks(); });
async function fixture(overrides: Partial<DropApi> = {}) {
  const root = await mkdtemp(join(tmpdir(), "levik-drop-lifecycle-")); const values = new Map<string, Buffer>();
  const api: DropApi = { presence: async () => ({}), clearPresence: async () => {}, devices: async () => ({available:true,devices:[]}), transfers: async () => ({transfers:[]}), create: async () => ({}), update: async () => ({}), ...overrides };
  const engine = new DropEngine({ api, secrets: {get: async (key) => values.get(key) ?? null, put: async (key,value) => {values.set(key,Buffer.from(value));}, remove: async (key) => {values.delete(key);} }, statePath:join(root,"state.json"), platform:"windows", defaultFolder:root, markDownloaded:async()=>{}, errorCode:()=>null, log:()=>{} });
  cleanups.push(async () => {await engine.stop(); await rm(root,{recursive:true,force:true});});
  await engine.start(); return {root,engine,api};
}
function controllerFixture() {
  const controller = new AppController(); Reflect.set(controller,"accessToken","owner-a");
  const stop = vi.fn(async () => {}), clear=vi.fn(async () => {});
  Reflect.set(controller,"stopConnection",stop); Reflect.set(controller,"clearLocalSession",clear);
  return {controller,stop,clear,drop: (Reflect.get(controller,"dropApi") as () => DropApi).call(controller)};
}
describe("Drop account lifecycle", () => {
  it("ignores an old request's 401 after another account signed in", async () => {
    const {controller,drop,stop,clear}=controllerFixture(); const read=deferred<unknown>();
    Reflect.set(controller,"api",{dropDevices:()=>read.promise}); const request=drop.devices();
    Reflect.set(controller,"accessToken","owner-b"); read.reject(new MobileApiError("expired",401,true));
    await expect(request).rejects.toThrow("expired"); expect(stop).not.toHaveBeenCalled(); expect(clear).not.toHaveBeenCalled();
  });
  it("rejects an old successful account response", async () => {
    const {controller,drop}=controllerFixture(); const read=deferred<unknown>();
    Reflect.set(controller,"api",{dropDevices:()=>read.promise}); const request=drop.devices();
    Reflect.set(controller,"accessToken","owner-b"); read.resolve({available:true,devices:[{name:"old-account"}]});
    await expect(request).rejects.toThrow("Сессия");
  });
  it("does not restore a late device list after sign-out", async () => {
    const list=deferred<unknown>(); const devices=vi.fn(()=>list.promise); const {engine}=await fixture({devices});
    await vi.waitFor(()=>expect(devices).toHaveBeenCalledOnce()); await engine.signedOut();
    list.resolve({available:true,devices:[{deviceId:"old-device",name:"old-account",platform:"windows",ready:true,keyId:"0123456789abcdef",current:false}]});
    await flush();await flush(); expect(engine.snapshot().devices).toEqual([]); expect(engine.snapshot().available).toBe(false);
  });
  it("withdraws the old presence before awaited file cleanup", async () => {
    let owner="owner-a"; const withdrawn:string[]=[];const close=deferred<void>();
    const {engine}=await fixture({clearPresence:async()=>{withdrawn.push(owner);}});
    await engine.refreshNow(); (Reflect.get(engine,"targets") as Map<string,unknown>).set("old",{closeWriting:()=>close.promise});
    const stopping=engine.stop(); owner="owner-b";close.resolve();await stopping;
    expect(withdrawn).toEqual(["owner-a"]);
  });
  it("rejects a late created transfer after sign-out", async () => {
    const create=deferred<unknown>();const creating=vi.fn(()=>create.promise); const {root,engine}=await fixture({create:creating});
    const path=join(root,"file.txt");await writeFile(path,"private old-account file");const sending=engine.send("peer",[path]);
    await vi.waitFor(()=>expect(creating).toHaveBeenCalledOnce());await engine.signedOut();
    create.resolve({transfer:{id:"11111111-1111-4111-8111-111111111111",role:"sender",peerDeviceId:"peer",peerName:"Peer",peerPlatform:"windows",state:"offered",reason:null,fileCount:1,totalBytes:24,createdAt:new Date().toISOString(),finishedAt:null}});
    await expect(sending).rejects.toThrow("Сессия"); expect(engine.snapshot().transfers).toEqual([]);
  });
  it("does not clear a new account after expired-session cleanup awaited", async () => {
    const {controller,drop,clear}=controllerFixture();const stopping=deferred<void>();
    const stop=vi.fn(()=>stopping.promise);Reflect.set(controller,"stopConnection",stop);
    Reflect.set(controller,"api",{dropDevices:async()=>{throw new MobileApiError("expired",401,true);}});
    const request=drop.devices();await vi.waitFor(()=>expect(stop).toHaveBeenCalledOnce());
    Reflect.set(controller,"accessToken","owner-b");stopping.resolve();
    await expect(request).rejects.toThrow("expired");expect(clear).not.toHaveBeenCalled();
  });
  it("waits for old-account cleanup before starting a new generation", async () => {
    const devices=vi.fn(async()=>({available:true,devices:[]}));const {engine}=await fixture({devices});await engine.refreshNow();
    const close=deferred<void>();(Reflect.get(engine,"targets") as Map<string,unknown>).set("old",{closeWriting:()=>close.promise});
    const leaving=engine.signedOut();const starting=engine.start();const before=devices.mock.calls.length;
    await flush();expect(devices.mock.calls.length).toBe(before);close.resolve();await leaving;await starting;await engine.refreshNow();
    expect(devices.mock.calls.length).toBeGreaterThan(before);expect(engine.snapshot().available).toBe(true);
  });
  it("ignores callbacks of a retired relay link after another start", async () => {
    const update=vi.fn(async()=>({}));const {engine}=await fixture({update});await engine.refreshNow();
    const host=(Reflect.get(engine,"hostFor") as (id:string)=>import("../src/main/platform/levikDrop/link").LinkHost).call(engine,"old");
    await engine.stop();await engine.start();await engine.refreshNow();host.status("waiting");host.outcome({kind:"done"});
    await expect(host.connect()).rejects.toThrow("Сессия");expect(update).not.toHaveBeenCalled();expect(engine.snapshot().transfers).toEqual([]);
  });

});
