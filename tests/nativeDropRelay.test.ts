import { fork } from "node:child_process";
import { build } from "esbuild";
import { tmpdir } from "node:os";
import { Session, TYPESCRIPT_PROTOCOL, type Identity } from "../src/main/platform/levikDrop/session";
import { TargetFiles, describeSources, planTargets } from "../src/main/platform/levikDrop/files";
import { dropProtocolWithCore } from "../src/main/core/coreDrop";
import { joinRelay } from "../src/main/platform/levikDrop/relay";
import { createHash, createPublicKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createServer, type Server, type TLSSocket } from "node:tls";
import { afterEach, describe, expect, it, vi } from "vitest";
import { joinRelayWithCore, type NativeDropRelay } from "../src/main/core/nativeDropRelay";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import { ChannelClosed, FrameSocket, type DropSocket } from "../src/main/platform/levikDrop/framing";
import type { RelayEndpoint } from "../src/main/platform/levikDrop/relay";
const owners:DropSocket[]=[];const cleanups:Array<()=>Promise<void>>=[];
afterEach(async()=>{for(const owner of owners.splice(0))owner.close();for(const close of cleanups.splice(0).reverse())await close();});
const endpoints:RelayEndpoint[]=[{host:"127.0.0.1",port:47200,pin:"Q".repeat(43)}];
function configured(mode:"ts"|"shadow"|"rust"="rust"){
 const diagnostics:string[]=[];const core=new RustCore(null,(line)=>diagnostics.push(line),mode);let notify=()=>{};
 const native:NativeDropRelay={connected:vi.fn(async()=>{}),read:vi.fn(async()=>Buffer.from([0x10,1])),send:vi.fn(async()=>{}),isClosed:vi.fn(()=>false),startKeepalive:vi.fn(),watchIdle:vi.fn(),close:vi.fn(),closeGracefully:vi.fn()};
 const fallback:DropSocket={closed:false,next:async()=>Buffer.from([1]),send:async()=>{},startKeepalive:()=>{},watchIdle:()=>{},onClose:()=>{},close:()=>{},closeGracefully:()=>{}};
 const typescript=vi.fn(async()=>fallback);const open=vi.fn((_endpoints:RelayEndpoint[],_token:string,onClosed:()=>void)=>{notify=onClosed;return native;});const report=vi.fn();
 const join=joinRelayWithCore(()=>core,()=>open,report,typescript);const controller=new AbortController();
 const create=async()=>{const socket=await join(endpoints,"PRIVATE_TEST_TOKEN",controller.signal);owners.push(socket);return socket;};
 return{core,native,open,report,typescript,controller,create,diagnostics,notify:()=>notify(),fallback};
}
describe("Drop relay attempt ownership",()=>{
 it.each(["ts","shadow"] as const)("performs native-free Node I/O in %s",async(mode)=>{const c=configured(mode);expect(await c.create()).toBe(c.fallback);expect(c.open).not.toHaveBeenCalled();expect(c.typescript).toHaveBeenCalledOnce();});
 it("keeps older modules working",async()=>{const c=configured();const join=joinRelayWithCore(()=>c.core,()=>undefined,c.report,c.typescript);expect(await join(endpoints,"TEST",c.controller.signal)).toBe(c.fallback);expect(c.open).not.toHaveBeenCalled();});
 it("falls back only before a lazy native owner is adopted and redacts activation failure",async()=>{const c=configured();c.open.mockImplementation(()=>{throw new Error("PRIVATE_TEST_TOKEN");});expect(await c.create()).toBe(c.fallback);expect(c.diagnostics.join(" ")).not.toContain("PRIVATE_TEST_TOKEN");expect(c.native.connected).not.toHaveBeenCalled();});
 it("never redials through Node after a native connection error",async()=>{const c=configured();c.native.connected=vi.fn(async()=>{throw new Error("PRIVATE_TEST_TOKEN");});await expect(c.create()).rejects.toThrow("relay connection failed");expect(c.typescript).not.toHaveBeenCalled();expect(c.open).toHaveBeenCalledOnce();expect(c.native.close).toHaveBeenCalledOnce();});
 it("does not create either transport for an already aborted join",async()=>{const c=configured();c.controller.abort();await expect(c.create()).rejects.toThrow("aborted");expect(c.open).not.toHaveBeenCalled();expect(c.typescript).not.toHaveBeenCalled();});
 it("retires a late native connection after abort without replay",async()=>{const c=configured();let ready=()=>{};c.native.connected=vi.fn(()=>new Promise<void>((done)=>{ready=done;}));const joining=c.create();c.controller.abort();expect(c.native.close).toHaveBeenCalledOnce();ready();await expect(joining).rejects.toThrow("aborted");expect(c.typescript).not.toHaveBeenCalled();});
 it("retains the chosen transport across a mode change",async()=>{const c=configured();const socket=await c.create();c.core.setMode("ts");await socket.send(Buffer.from("TEST"));expect(c.native.send).toHaveBeenCalledOnce();expect(c.typescript).not.toHaveBeenCalled();});
 it("removes dial abort handling before RelayLink's final graceful send",async()=>{const c=configured();const order:string[]=[];let sent=()=>{};c.native.send=vi.fn(()=>{order.push("send");return new Promise<void>((done)=>{sent=done;});});c.native.closeGracefully=vi.fn(()=>{order.push("graceful");});const socket=await c.create();const writing=socket.send(Buffer.from("TEST final"));c.controller.abort();socket.closeGracefully();expect(order).toEqual(["send","graceful"]);expect(c.native.close).not.toHaveBeenCalled();sent();await writing;socket.close();socket.close();expect(c.native.close).toHaveBeenCalledOnce();});
 it("still drains queued frames when close notice arrives before ready",async()=>{const c=configured();c.native.connected=vi.fn(async()=>{c.notify();});c.native.isClosed=vi.fn(()=>true);const socket=await c.create();expect(socket.closed).toBe(true);expect(await socket.next()).toEqual(Buffer.from([0x10,1]));});
 it("a timed next does not close a live connection",async()=>{const c=configured();c.native.read=vi.fn().mockRejectedValueOnce(new Error("timed out")).mockResolvedValue(Buffer.from([1]));const socket=await c.create();await expect(socket.next(10)).rejects.toThrow("timed out");expect(c.native.close).not.toHaveBeenCalled();expect(await socket.next()).toEqual(Buffer.from([1]));});
 it.each([Buffer.alloc(0),Buffer.from([0x7f]),Buffer.alloc(270337)])("refuses an invalid native frame and closes without exposing bytes",async(frame)=>{const c=configured();c.native.read=vi.fn(async()=>frame);const socket=await c.create();await expect(socket.next()).rejects.toThrow("bad frame");expect(c.native.close).toHaveBeenCalledOnce();expect(c.typescript).not.toHaveBeenCalled();});
 it("rejects a foreign ABI return shape",async()=>{const c=configured();Object.defineProperty(c.native,"send",{value:()=>"PRIVATE_TEST_TOKEN"});const socket=await c.create();await expect(socket.send(Buffer.from("TEST"))).rejects.toThrow(ChannelClosed);expect(c.native.close).toHaveBeenCalledOnce();});
 it("notifies listeners once and contains observer exceptions",async()=>{const c=configured();const socket=await c.create();const listener=vi.fn();socket.onClose(listener);socket.onClose(()=>{throw new Error("PRIVATE_TEST_TOKEN");});expect(()=>c.notify()).not.toThrow();c.notify();socket.close();expect(listener).toHaveBeenCalledOnce();expect(c.report).toHaveBeenCalledWith();});
});
const modulePath=process.env.LEVIK_TEST_CORE;
function factory(){if(!modulePath)throw new Error("LEVIK_TEST_CORE missing");const loaded=loadLevikCore(modulePath);if(loaded.state!=="loaded"||!loaded.module.startDropRelay)throw new Error("Native Drop relay missing");return loaded.module.startDropRelay;}
async function tlsFixture(work:(peer:FrameSocket)=>Promise<void>){
 const cert=await readFile(resolve(__dirname,"fixtures/health-test-cert.pem"));const key=await readFile(resolve(__dirname,"fixtures/health-test-key.pem"));
 const pin=createHash("sha256").update(createPublicKey(cert).export({type:"spki",format:"der"})).digest("base64url");const sockets=new Set<TLSSocket>();let joins=0;
 let resolveWork=()=>{},rejectWork:(error:unknown)=>void=()=>{};const finished=new Promise<void>((yes,no)=>{resolveWork=yes;rejectWork=no;});void finished.catch(()=>{});
 const server:Server=createServer({cert,key},(socket)=>{sockets.add(socket);socket.on("close",()=>sockets.delete(socket));const peer=new FrameSocket(socket);
  void(async()=>{const value:unknown=JSON.parse((await peer.next(10000)).toString());expect(value).toEqual({v:1,token:"TEST native relay"});joins++;await work(peer);})().then(resolveWork,rejectWork);
 });server.on("tlsClientError",()=>{});await new Promise<void>((done)=>server.listen(0,"127.0.0.1",done));
 const address=server.address();if(!address||typeof address==="string")throw new Error("TEST listener missing");
 cleanups.push(async()=>{for(const socket of sockets)socket.destroy();await new Promise<void>((done)=>server.close(()=>done()));});
 return{endpoint:{host:"127.0.0.1",port:address.port,pin},finished,joins:()=>joins};
}
describe.skipIf(!modulePath)("actual native Drop TLS relay",()=>{
 it("matches Node's join, filters keepalive and preserves the final snapshot through graceful close",async()=>{
  let bytes:Buffer|undefined;const fixture=await tlsFixture(async(peer)=>{await peer.send(Buffer.from([0x7f]));await peer.send(Buffer.from([0,...Buffer.from('{"t":"wait"}')]));bytes=await peer.next(10000);peer.closeGracefully();});
  const core=new RustCore(null,()=>{},"rust"),controller=new AbortController();const socket=await joinRelayWithCore(()=>core,()=>factory(),()=>{})([fixture.endpoint],"TEST native relay",controller.signal);owners.push(socket);
  expect((await socket.next(10000)).toString()).toBe(String.fromCharCode(0)+'{"t":"wait"}');await expect(socket.next(20)).rejects.toThrow("timed out");expect(socket.closed).toBe(false);
  core.setMode("ts");const payload=Buffer.from("TEST final"),writing=socket.send(payload);payload.fill(0);controller.abort();socket.closeGracefully();await writing;await fixture.finished;expect(bytes?.toString()).toBe("TEST final");expect(fixture.joins()).toBe(1);
 },30_000);
 it("reads a relay final control before its immediate EOF",async()=>{
  const fixture=await tlsFixture(async(peer)=>{await peer.send(Buffer.from([0,...Buffer.from('{"t":"end","reason":"ended"}')]));peer.closeGracefully();});
  const socket=await joinRelayWithCore(()=>new RustCore(null,()=>{},"rust"),()=>factory(),()=>{})([fixture.endpoint],"TEST native relay",new AbortController().signal);owners.push(socket);
  expect((await socket.next(10000)).toString()).toBe(String.fromCharCode(0)+'{"t":"end","reason":"ended"}');await fixture.finished;await expect(socket.next(10000)).rejects.toThrow(ChannelClosed);
 },30_000);
 it("a passive close observer cannot keep an abandoned native socket alive",async()=>{
  const directory=await mkdtemp(join(tmpdir(),"levik-relay-gc-"));cleanups.push(()=>rm(directory,{recursive:true,force:true}));
  const entry=join(directory,"child.cjs");
  await build({stdin:{contents:`
    import { RustCore } from ${JSON.stringify(resolve(__dirname,"../src/main/core/rustCore.ts"))};
    import { joinRelayWithCore } from ${JSON.stringify(resolve(__dirname,"../src/main/core/nativeDropRelay.ts"))};
    const core = require(process.argv[2]);
    async function open() {
      const configured = new RustCore(null,()=>{},"rust");
      return joinRelayWithCore(()=>configured,()=>core.startDropRelay,()=>{})([JSON.parse(process.argv[3])],"TEST native relay",new AbortController().signal);
    }
    async function main() {
      let owner = await open(); owner = null;
      let closed = false;
      process.on("message", message => { if(message === "closed") closed = true; });
      process.send("ready");
      const deadline = Date.now()+10000;
      while(!closed && Date.now()<deadline) { global.gc(); await new Promise(done=>setTimeout(done,20)); }
      if(!closed) throw new Error("TEST native socket retained by its observer");
      process.disconnect();
    }
    main().catch(error=>{ console.error(error.message); process.exit(1); });
  `,resolveDir:resolve(__dirname,".."),sourcefile:"TEST-relay-gc.ts",loader:"ts"},outfile:entry,bundle:true,platform:"node",format:"cjs",target:"node22",logLevel:"silent"});
  let peerClosed=()=>{};
  const fixture=await tlsFixture(async(peer)=>{await new Promise<void>((done)=>{peer.onClose(()=>{peerClosed();done();});});});
  const child=fork(entry,[modulePath!,JSON.stringify(fixture.endpoint)],{execArgv:["--expose-gc"],stdio:["ignore","ignore","pipe","ipc"]});
  cleanups.push(async()=>{if(child.exitCode===null&&!child.killed)child.kill();});
  let errors="";child.stderr?.on("data",(chunk:Buffer)=>{errors+=chunk.toString();});
  let notified=false;const acknowledge=()=>{if(notified||!child.connected)return;notified=true;expect(child.exitCode).toBeNull();child.send("closed");};
  peerClosed=acknowledge;
  const exited=new Promise<number|null>((done,no)=>{child.once("exit",done);child.once("error",no);});
  expect(await exited,errors).toBe(0);await fixture.finished;expect(notified).toBe(true);expect(fixture.joins()).toBe(1);
 },30_000);
 it("refuses a wrong pin before sending its token",async()=>{
  const fixture=await tlsFixture(async()=>{});const join=joinRelayWithCore(()=>new RustCore(null,()=>{},"rust"),()=>factory(),()=>{});
  await expect(join([{...fixture.endpoint,pin:"Q".repeat(43)}],"PRIVATE_TEST_TOKEN",new AbortController().signal)).rejects.toThrow("relay connection failed");expect(fixture.joins()).toBe(0);
 },30_000);
});

async function pairedRelay(){
  const cert=await readFile(resolve(__dirname,"fixtures/health-test-cert.pem")),key=await readFile(resolve(__dirname,"fixtures/health-test-key.pem"));
  const pin=createHash("sha256").update(createPublicKey(cert).export({type:"spki",format:"der"})).digest("base64url");
  const sockets=new Set<TLSSocket>(),peers:FrameSocket[]=[];let count=0;
  let paired=()=>{};const ready=new Promise<void>((done)=>{paired=done;});
  const server=createServer({cert,key},(socket)=>{
    sockets.add(socket);socket.on("close",()=>sockets.delete(socket));const peer=new FrameSocket(socket);
    void(async()=>{
      expect(JSON.parse((await peer.next(10000)).toString())).toEqual({v:1,token:"TEST paired relay"});
      const index=peers.length;peers.push(peer);count++;if(peers.length===2)paired();await ready;
      const other=peers[index===0?1:0]!;
      for(;;){await other.send(await peer.next());}
    })().catch(()=>peer.close());
  });server.on("tlsClientError",()=>{});await new Promise<void>((done)=>server.listen(0,"127.0.0.1",done));
  const address=server.address();if(!address||typeof address==="string")throw new Error("TEST relay listener missing");
  cleanups.push(async()=>{for(const socket of sockets)socket.destroy();await new Promise<void>((done)=>server.close(()=>done()));});
  return{endpoint:{host:"127.0.0.1",port:address.port,pin},count:()=>count};
}
function testIdentity():Identity{const pair=generateKeyPairSync("ec",{namedCurve:"prime256v1"});return{privateKey:pair.privateKey,spki:pair.publicKey.export({type:"spki",format:"der"})};}
function feed(socket:DropSocket,session:Session):Promise<void>{return(async()=>{try{while(!session.finished)session.inbox.push(await socket.next());}catch{session.abort("TEST relay closed");}})();}
describe.skipIf(!modulePath)("actual TLS file transfer with Rust owners",()=>{
  it.each(["sender","receiver","both"] as const)("delivers unchanged files through the TLS broker with native %s",async(side)=>{
    const loaded=loadLevikCore(modulePath!);if(loaded.state!=="loaded"||!loaded.module.startDropRelay)throw new Error("Native Drop relay missing");
    const core=new RustCore(loaded.module,()=>{},"rust",loaded.info.version);
    const protocol=dropProtocolWithCore(()=>core,()=>loaded.module.openDropRecords,()=>{},()=>loaded.module.openDropAgreement,()=>loaded.module.openDropSource,()=>loaded.module.openDropTargets);
    const broker=await pairedRelay();const controller=new AbortController();
    const native=joinRelayWithCore(()=>core,()=>loaded.module.startDropRelay,()=>{});
    const senderSocket=await(side!=="receiver"?native:joinRelay)([broker.endpoint],"TEST paired relay",controller.signal);owners.push(senderSocket);
    const receiverSocket=await(side!=="sender"?native:joinRelay)([broker.endpoint],"TEST paired relay",controller.signal);owners.push(receiverSocket);
    const root=await mkdtemp(join(tmpdir(),"levik-tls-file-transfer-"));cleanups.push(()=>rm(root,{recursive:true,force:true}));
    const source=join(root,"source"),target=join(root,"target");await mkdir(source);await mkdir(target);
    const bytes=Buffer.alloc(700000,0x5a),path=join(source,"mixed.bin"),empty=join(source,"empty.txt");
    await writeFile(path,bytes);await writeFile(empty,Buffer.alloc(0));await writeFile(join(target,"mixed.bin"),"original");
    const files=await describeSources([path,empty]),codes:string[]=[];
    const common={transferId:randomUUID(),allowLan:false,route:"relay" as const,expectedFiles:2,expectedBytes:bytes.length,selectRoute:async()=>true,
      trust:()=>"new" as const,
      events:{keyed:(code:string)=>{codes.push(code);},path:()=>{},progress:()=>{}},
    };
    const receiveProtocol=side!=="sender"?protocol:TYPESCRIPT_PROTOCOL;
    const sender=new Session(senderSocket,{...common,role:"sender",identity:testIdentity(),peerDeviceId:"TEST receiver",ownPlatform:"macos",peerPlatform:"windows",files,confirm:async()=>true,protocol:side!=="receiver"?protocol:TYPESCRIPT_PROTOCOL});
    const receiver=new Session(receiverSocket,{...common,role:"receiver",identity:testIdentity(),peerDeviceId:"TEST sender",ownPlatform:"windows",peerPlatform:"macos",manifest:null,targets:null,confirm:async()=>true,protocol:receiveProtocol,
      decide:async(manifest)=>{const targets=await planTargets(target,manifest);return new TargetFiles(target,targets,async()=>{},receiveProtocol.createTargets?.(target,targets)??null);}});
    const reading=[feed(senderSocket,sender),feed(receiverSocket,receiver)];
    try{
      const outcomes=await Promise.all([sender.run(),receiver.run()]);expect(outcomes).toEqual([{kind:"done"},{kind:"done"}]);
      expect(codes).toHaveLength(2);expect(codes[0]).toBe(codes[1]);expect(broker.count()).toBe(2);
      expect(await readFile(join(target,"mixed (1).bin"))).toEqual(bytes);expect(await readFile(join(target,"empty.txt"))).toEqual(Buffer.alloc(0));expect(await readFile(join(target,"mixed.bin"),"utf8")).toBe("original");
    }finally{sender.abort("TEST cleanup");receiver.abort("TEST cleanup");senderSocket.close();receiverSocket.close();await Promise.all(reading);}
  },30_000);
});
