import { CoreRouteProbes, type NativeRouteProbe } from "../src/main/core/nativeRouteProbes";
import { RustCore } from "../src/main/core/rustCore";
import { openExistingRouteProbe, openRouteProbe } from "../src/main/vpn/routeProbe";
import { existsSync } from "node:fs";
import { loadLevikCore } from "../src/main/core/levikCore";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import { createServer as createTlsServer } from "node:tls";
import { connect, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { once } from "node:events";

const auth = { user: "probe", password: "a".repeat(48) };
const measured = { values: [1,2,3], failed: 0, setupMs: 4, dataVerified: true };
const answer = (value: unknown) => JSON.stringify({ok:true,value});
const managers: CoreRouteProbes[] = [];
function configured(mode: "ts"|"shadow"|"rust" = "rust") {
  const core = new RustCore(null,()=>{},mode); const report = vi.fn();
  const native: NativeRouteProbe = { latency: vi.fn(async()=>answer(measured)), transfer: vi.fn(async()=>answer(5)), close: vi.fn() };
  const open = vi.fn((_input: string)=>native); const probes = new CoreRouteProbes(); managers.push(probes); probes.useRustCore(()=>core,open,report);
  const node = { latency: vi.fn(async()=>measured), transfer: vi.fn(async()=>null), close: vi.fn(async()=>{}) };
  const fallback = vi.fn(()=>node); const closeOwner=vi.fn(async()=>{}); const abort=new AbortController();
  const wrap=()=>probes.wrap(47200,auth,abort.signal,()=>true,closeOwner,true,fallback);
  return {core,native,report,open,probes,node,fallback,closeOwner,abort,wrap};
}
function pending() { let resolve!: (text:string)=>void; const promise=new Promise<string>((done)=>{resolve=done;});return {promise,resolve}; }
afterEach(()=>{for(const probes of managers) probes.cancel(); managers.length=0;});
describe("route measurement ownership",()=>{
  it("connects the live route factory to the selected native backend", async () => {
    const { probes, native, open, abort } = configured();
    const session = await openExistingRouteProbe(47231, auth, abort.signal, { verifyData: false, core: probes });
    expect(open).toHaveBeenCalledOnce();
    expect(await session.latency("https://unused.invalid/")).toEqual(measured);
    expect(native.latency).toHaveBeenCalledWith("https://unused.invalid/", false);
    abort.abort(); await session.close(); expect(native.close).toHaveBeenCalledOnce();
  });
  const executable = process.env.LEVIK_TEST_XRAY ?? resolve("../levik_vpn_macos/vendor/xray", `darwin-${process.arch}`, "xray");
  it.skipIf(process.platform !== "darwin" || !existsSync(executable))("keeps the isolated Xray owner and releases its listener when native measurement closes", async () => {
    const { probes, open, native, abort } = configured();
    const session = await openRouteProbe(executable, { id: "TEST", routeKey: "TEST", tag: "TEST", config: {
      outbounds: [{ tag: "TEST", protocol: "freedom" }],
    } }, abort.signal, probes);
    try {
      expect(open).toHaveBeenCalledOnce();
      expect(await session.latency("https://unused.invalid/")).toEqual(measured);
      expect(native.latency).toHaveBeenCalledWith("https://unused.invalid/", false);
    } finally { await session.close(); }
    expect(native.close).toHaveBeenCalledOnce();
    const input: unknown = JSON.parse(open.mock.calls[0]![0]);
    if (typeof input !== "object" || input === null || !("port" in input) || typeof input.port !== "number") throw new Error("TEST port missing");
    const replacement = createServer(); servers.add(replacement); replacement.listen(input.port, "127.0.0.1"); await once(replacement, "listening");
  });

  it.each(["ts","shadow"] as const)("preserves the exact Node session and promise in %s",async(mode)=>{
    const {wrap,node,open}=configured(mode); const session=wrap(); expect(session).toBe(node);
    const promise=Promise.resolve(measured);node.latency.mockReturnValue(promise);expect(session.latency("https://unused.invalid")).toBe(promise);expect(open).not.toHaveBeenCalled();
  });
  it("keeps older contract-2 modules working",()=>{
    const {probes,core,wrap,node}=configured();probes.useRustCore(()=>core,undefined,()=>{});expect(wrap()).toBe(node);
  });
  it("sends only the loopback credentials and forwards the selected target",async()=>{
    const {wrap,open,native,fallback,closeOwner}=configured();const session=wrap();
    expect(JSON.parse(open.mock.calls[0]![0])).toEqual({port:47200,auth:{...auth,port:47200}});
    expect(await session.latency("https://speed.cloudflare.com/__down?bytes=0")).toEqual(measured);
    expect(native.latency).toHaveBeenCalledWith("https://speed.cloudflare.com/__down?bytes=0",true);
    expect(await session.transfer("https://speed.cloudflare.com/__up","up")).toBe(5);
    expect(native.transfer).toHaveBeenCalledWith("https://speed.cloudflare.com/__up","up");expect(fallback).not.toHaveBeenCalled();
    await session.close();await session.close();expect(native.close).toHaveBeenCalledOnce();expect(closeOwner).toHaveBeenCalledOnce();
  });
  it("falls back once only when a lazy handle cannot be activated",()=>{
    const {open,wrap,node,report,fallback}=configured();open.mockImplementation(()=>{throw new Error("PRIVATE");});
    expect(wrap()).toBe(node);expect(wrap()).toBe(node);expect(open).toHaveBeenCalledOnce();expect(fallback).toHaveBeenCalledTimes(2);expect(report).toHaveBeenCalledWith();
  });
  it.each(["reject","bad JSON","failed","missing","too many samples","invalid counts","bad setup","bad data proof"])("rejects %s without Node replay",async(kind)=>{
    const {native,wrap,fallback,report}=configured();native.latency=vi.fn(async()=>{
      if(kind==="reject")throw new Error("PRIVATE");
      return kind==="bad JSON"?"PRIVATE":kind==="failed"?'{"ok":false}':kind==="missing"?'{"ok":true}':
        answer(kind==="too many samples"?{...measured,values:[1,2,3,4]}:kind==="invalid counts"?{...measured,failed:1}:
          kind==="bad setup"?{...measured,setupMs:-1}:{...measured,dataVerified:false});
    });const session=wrap();await expect(session.latency("https://unused.invalid/")).rejects.toThrow("Измерение маршрута не подтверждено");
    expect(fallback).not.toHaveBeenCalled();expect(report).toHaveBeenCalledWith();await session.close();
  });
  it("accepts a failed warmup as missing evidence",async()=>{
    const {native,wrap}=configured();native.latency=vi.fn(async()=>answer({values:[],failed:0,setupMs:0,dataVerified:false}));
    expect(await wrap().latency("https://speed.cloudflare.com/__down?bytes=0")).toMatchObject({values:[],dataVerified:false});
  });
  it.each([0,-1,10001,"PRIVATE"])("rejects invalid bandwidth %s",async(value)=>{
    const {native,wrap,fallback}=configured();native.transfer=vi.fn(async()=>answer(value));const session=wrap();
    await expect(session.transfer("https://unused.invalid/","down")).rejects.toThrow();expect(fallback).not.toHaveBeenCalled();await session.close();
  });
  it("retains unknown bandwidth as null",async()=>{const {native,wrap}=configured();native.transfer=vi.fn(async()=>answer(null));expect(await wrap().transfer("https://unused.invalid/","down")).toBeNull();});
  it.each(["abort","stop"])("closes the owner and ignores a late result on %s",async(kind)=>{
    const {native,wrap,probes,abort,closeOwner,report}=configured();const result=pending();native.latency=vi.fn(()=>result.promise);const session=wrap();
    const reading=session.latency("https://unused.invalid/");const rejected=expect(reading).rejects.toThrow();
    if(kind==="abort")abort.abort();else probes.cancel();expect(native.close).toHaveBeenCalledOnce();result.resolve(answer(measured));await rejected;
    await session.close();expect(closeOwner).toHaveBeenCalledOnce();expect(report).not.toHaveBeenCalled();
  });
  it("rejects aborted or invalid activation without invoking either backend",()=>{
    const {probes,abort,open,fallback,closeOwner,wrap}=configured();
    expect(()=>probes.wrap(22,auth,abort.signal,()=>true,closeOwner,true,fallback)).toThrow();
    expect(()=>probes.wrap(47200,{...auth,password:"PRIVATE"},abort.signal,()=>true,closeOwner,true,fallback)).toThrow();
    abort.abort();expect(wrap).toThrow();expect(open).not.toHaveBeenCalled();expect(fallback).not.toHaveBeenCalled();
  });
});

const modulePath=process.env.LEVIK_TEST_CORE;const servers=new Set<Server|ReturnType<typeof createTlsServer>>();const sockets=new Set<Socket>();
function track(socket:Socket){sockets.add(socket);socket.on("error",()=>{});socket.once("close",()=>sockets.delete(socket));return socket;}
afterEach(async()=>{for(const socket of sockets)socket.destroy();sockets.clear();await Promise.all([...servers].map(server=>new Promise<void>(done=>server.close(()=>done()))));servers.clear();});
async function listen(server:Server|ReturnType<typeof createTlsServer>):Promise<number>{servers.add(server);server.on("connection",track);server.listen(0,"127.0.0.1");await once(server,"listening");const address=server.address();if(!address||typeof address==="string")throw new Error("TEST listener");return address.port;}
function real(port:number,signal=new AbortController().signal){
  if(!modulePath)throw new Error("LEVIK_TEST_CORE missing");const status=loadLevikCore(modulePath);
  if(status.state!=="loaded"||!status.module.openRouteProbe)throw new Error("Native route measurement missing");
  const probes=new CoreRouteProbes();managers.push(probes);probes.useRustCore(()=>new RustCore(null,()=>{},"rust"),status.module.openRouteProbe,()=>{});
  return probes.wrap(port,auth,signal,()=>true,async()=>{},true,()=>{throw new Error("Unexpected Node replay");});
}
describe.skipIf(!modulePath)("real native route probe",()=>{
  it("cancels a silent CONNECT and observes socket close before cleanup",async()=>{
    const server=createServer();const port=await listen(server);const accepted=once(server,"connect");const abort=new AbortController();const probe=real(port,abort.signal);
    const reading=probe.latency("https://probe.test/");const rejected=expect(reading).rejects.toThrow();const [request,socket]=await accepted;
    expect(request.url).toBe("probe.test:443");expect(request.headers["proxy-authorization"]).toBe(`Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`);
    const closed=once(socket,"close");socket.once("end",()=>socket.end());socket.resume();abort.abort();await rejected;await closed;
  });
  it("bounds a silent CONNECT by the real 2.5 second deadline",async()=>{
    const server=createServer();const port=await listen(server);const accepted=once(server,"connect");const probe=real(port);
    const started=Date.now();const reading=probe.latency("https://probe.test/");const rejected=expect(reading).rejects.toThrow();const [,socket]=await accepted;
    const closed=once(socket,"close");socket.once("end",()=>socket.end());socket.resume();await rejected;expect(Date.now()-started).toBeGreaterThanOrEqual(2400);await closed;await probe.close();
  });
  it("uses OS trust and never accepts the public TEST certificate",async()=>{
    const fixture=(name:string)=>readFileSync(resolve("../levik_desktop/crates/levik-api/tests/tls",`${name}.pem`));
    const tls=createTlsServer({cert:fixture("cert"),key:fixture("key")});tls.on("tlsClientError",()=>{});const tlsPort=await listen(tls);
    const proxy=createServer();const port=await listen(proxy);let requests=0;
    proxy.on("connect",(_req,socket)=>{requests++;const peer=track(connect(tlsPort,"127.0.0.1"));socket.once("close",()=>peer.destroy());peer.once("connect",()=>{socket.write("HTTP/1.1 200 OK\r\n\r\n");socket.pipe(peer).pipe(socket);});});
    const probe=real(port);await expect(probe.latency("https://api.test/")).rejects.toThrow("Измерение маршрута не подтверждено");
    expect(requests).toBe(1);await probe.close();
  });
});
