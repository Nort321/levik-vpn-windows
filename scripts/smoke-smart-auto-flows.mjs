import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { createServer, connect } from 'node:net';
import dgram from 'node:dgram';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

// Manual, local-only core integration smoke. No TUN, production credentials,
// external target or installed VPN settings are used. Requires the bundled core.
const repository = fileURLToPath(new URL('../', import.meta.url));
const bundle = await build({ entryPoints: [join(repository, 'src/main/vpn/serviceRouteTransport.ts')], bundle: true, platform: 'node', format: 'esm', write: false, logLevel: 'silent' });
const { overrideServiceRoute, queryServiceRouteStatistics } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString('base64')}`);
const statsBundle = await build({ entryPoints: [join(repository, 'src/main/vpn/xrayStats.ts')], bundle: true, platform: 'node', format: 'esm', write: false, logLevel: 'silent' });
const { parseXrayStats } = await import(`data:text/javascript;base64,${Buffer.from(statsBundle.outputFiles[0].contents).toString('base64')}`);
const execute = promisify(execFile);
const controlBundle = await build({ stdin: { contents: 'export {withServiceRoutes, compiledServiceRoutes} from "./src/main/vpn/serviceRoutes"; export {ServiceRouteSession} from "./src/main/vpn/serviceRouteSession";', resolveDir: repository, sourcefile: 'live-flow-fixture.ts', loader: 'ts' }, bundle: true, platform: 'node', format: 'esm', write: false, logLevel: 'silent' });
const { withServiceRoutes, compiledServiceRoutes, ServiceRouteSession } = await import(`data:text/javascript;base64,${Buffer.from(controlBundle.outputFiles[0].contents).toString('base64')}`);

const system = process.platform === 'darwin' ? 'darwin' : process.platform === 'win32' ? 'windows' : process.platform === 'linux' ? 'linux' : null;
if (!system) throw new Error('Unsupported platform');
const executable = process.env.LEVIK_SMART_AUTO_XRAY ?? join(repository, 'vendor/xray', `${system}-${process.arch}`, process.platform === 'win32' ? 'xray.exe' : 'xray');
const sockets = new Set(), servers = [], datagrams = [], children = [], owners = [];
function track(socket) { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); return socket; }
async function listen(server) {
  await new Promise((resolve,reject) => { server.once('error',reject); server.listen(0,'127.0.0.1',resolve); });
  servers.push(server); return server.address().port;
}
async function port() { const server=createServer(); const result=await listen(server); await new Promise(r=>server.close(r)); return result; }
async function udpEcho(label) {
  const socket=dgram.createSocket('udp4'); datagrams.push(socket);
  socket.on('message',(data,remote)=>socket.send(Buffer.concat([Buffer.from(label+':'),data]),remote.port,remote.address));
  await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(0,'127.0.0.1',resolve);});
  return socket.address().port;
}
async function tcpEcho(label) { return listen(createServer(socket=>{
  track(socket);let buffered='';socket.on('data',data=>{
    buffered+=data.toString();let end;
    while((end=buffered.indexOf('\n'))>=0){socket.write(`${label}:${buffered.slice(0,end+1)}`);buffered=buffered.slice(end+1);}
  });
})); }
async function start(config,readyPort) {
  const child=spawn(executable,['run','-format','json','-config','stdin:'],{stdio:['pipe','ignore','ignore']});
  children.push(child); child.stdin.on('error',()=>{}); child.stdin.end(JSON.stringify(config));
  for(let attempt=0;attempt<100;attempt++) {
    if(child.exitCode!==null) throw new Error('Fixture core failed');
    const ready=await new Promise(resolve=>{const socket=track(connect(readyPort,'127.0.0.1'));socket.once('connect',()=>{socket.destroy();resolve(true);});socket.once('error',()=>resolve(false));});
    if(ready)return child;
    await new Promise(r=>setTimeout(r,30));
  }
  throw new Error('Fixture core did not listen');
}
class Reader {
  buffer=Buffer.alloc(0); pending=null; closed=false;
  constructor(socket){this.socket=socket;socket.on('data',data=>{this.buffer=Buffer.concat([this.buffer,data]);this.drain();});socket.on('close',()=>{this.closed=true;if(this.pending){const p=this.pending;this.pending=null;clearTimeout(p.timer);p.reject(new Error('Flow closed'));}});}
  drain(){const p=this.pending;if(!p)return;const n=p.delimiter?this.buffer.indexOf(p.delimiter)+p.delimiter.length:(this.buffer.length>=p.length?p.length:0);if(n<=0||p.delimiter&&n<p.delimiter.length)return;this.pending=null;clearTimeout(p.timer);const result=this.buffer.subarray(0,n);this.buffer=this.buffer.subarray(n);p.resolve(result);}
  read(length){return this.wait({length});}
  until(delimiter){return this.wait({delimiter:Buffer.from(delimiter)});}
  wait(options){if(this.closed)throw new Error('Flow already closed');assert.equal(this.pending,null);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending=null;reject(new Error('Fixture flow timeout'));},4000);this.pending={...options,resolve,reject,timer};this.drain();});}
}
async function openSocket(port){const socket=track(connect(port,'127.0.0.1'));const reader=new Reader(socket);await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});return {socket,reader};}
async function httpFlow(port,auth){const flow=await openSocket(port);const authorization=auth?`Proxy-Authorization: Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString('base64')}\r\n`:'';flow.socket.write(`CONNECT test.example:12345 HTTP/1.1\r\nHost: test.example:12345\r\n${authorization}\r\n`);const header=(await flow.reader.until('\r\n\r\n')).toString();assert.match(header,/ 200 /);return flow;}
async function tcpMessage(flow,text){flow.socket.write(text+'\n');return (await flow.reader.until('\n')).toString().trim();}
async function socksFlow(port){
  const flow=await openSocket(port);flow.socket.write(Buffer.from([5,1,0]));assert.deepEqual(await flow.reader.read(2),Buffer.from([5,0]));
  flow.socket.write(Buffer.from([5,1,0,1,1,1,1,1,0x30,0x39]));const header=await flow.reader.read(4);assert.equal(header[1],0);assert.equal(header[3],1);await flow.reader.read(6);return flow;
}
async function udpFlow(port){
  const control=await openSocket(port);control.socket.write(Buffer.from([5,1,0]));assert.deepEqual(await control.reader.read(2),Buffer.from([5,0]));
  control.socket.write(Buffer.from([5,3,0,1,0,0,0,0,0,0]));const header=await control.reader.read(4);assert.equal(header[1],0);assert.equal(header[3],1);
  const endpoint=await control.reader.read(6);const udpPort=endpoint.readUInt16BE(4);
  const socket=dgram.createSocket('udp4');datagrams.push(socket);await new Promise(r=>socket.bind(0,'127.0.0.1',r));
  return {socket,control,port:udpPort};
}
async function udpMessage(flow,text){return new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>{flow.socket.off('message',receive);reject(new Error('UDP fixture timeout'));},4000);
  const receive=packet=>{clearTimeout(timer);const kind=packet[3];const offset=kind===1?10:kind===4?22:7+packet[4];resolve(packet.subarray(offset).toString().trim());};
  flow.socket.once('message',receive);
  flow.socket.send(Buffer.concat([Buffer.from([0,0,0,1,1,1,1,1,0x30,0x39]),Buffer.from(text+'\n')]),flow.port,'127.0.0.1');
});}
async function run(mux,compiledOverlay=false){
  const tcpA=await tcpEcho('A'),tcpB=await tcpEcho('B'),udpA=await udpEcho('A'),udpB=await udpEcho('B');
  const exitA=await port(),exitB=await port(),user=await port(),socks=await port(),api=await port(),probe=await port();const id=randomUUID();
  // The fixture exits alone permit their exact loopback echo destinations.
  // Product configurations and the core's private-target protection stay unchanged.
  const inbound=(tag,p)=>({tag,listen:'127.0.0.1',port:p,protocol:'vless',settings:{clients:[{id}],decryption:'none'}});
  await start({log:{loglevel:'none'},inbounds:[inbound('A',exitA),inbound('B',exitB)],outbounds:[
    {tag:'tcpA',protocol:'freedom',settings:{finalRules:[{action:'allow',ip:['127.0.0.1/32']}],redirect:`127.0.0.1:${tcpA}`}}, {tag:'tcpB',protocol:'freedom',settings:{finalRules:[{action:'allow',ip:['127.0.0.1/32']}],redirect:`127.0.0.1:${tcpB}`}},
    {tag:'udpA',protocol:'freedom',settings:{finalRules:[{action:'allow',ip:['127.0.0.1/32']}],redirect:`127.0.0.1:${udpA}`}}, {tag:'udpB',protocol:'freedom',settings:{finalRules:[{action:'allow',ip:['127.0.0.1/32']}],redirect:`127.0.0.1:${udpB}`}},
  ],routing:{rules:[
    {type:'field',inboundTag:['A'],network:'tcp',outboundTag:'tcpA'},{type:'field',inboundTag:['A'],network:'udp',outboundTag:'udpA'},
    {type:'field',inboundTag:['B'],network:'tcp',outboundTag:'tcpB'},{type:'field',inboundTag:['B'],network:'udp',outboundTag:'udpB'},
  ]}},exitA);
  const outbound=(tag,p)=>({tag,protocol:'vless',settings:{vnext:[{address:'127.0.0.1',port:p,users:[{id,encryption:'none'}]}]},streamSettings:{network:'tcp',security:'none'},...(mux?{mux:{enabled:true,concurrency:8}}:{})});
  let launch={log:{loglevel:'none'},api:{tag:'api',services:['RoutingService','StatsService']},stats:{},policy:{system:{statsInboundUplink:true,statsInboundDownlink:true}},inbounds:[
    {tag:'user',listen:'127.0.0.1',port:user,protocol:'http',settings:{}},
    {tag:'levik-tun-in',listen:'127.0.0.1',port:socks,protocol:'socks',settings:{auth:'noauth',udp:true}},
    {tag:'probe',listen:'127.0.0.1',port:probe,protocol:'http',settings:{}},
    {tag:'api-in',listen:'127.0.0.1',port:api,protocol:'dokodemo-door',settings:{address:'127.0.0.1'}},
  ],outbounds:[outbound('levik-service-endpoint-00',exitA),outbound('levik-service-endpoint-01',exitB)],routing:{balancers:[{tag:'levik-service-main',selector:['levik-service-endpoint-00'],strategy:{type:'random'}}],rules:[
    {type:'field',inboundTag:['api-in'],outboundTag:'api'}, {type:'field',inboundTag:['probe'],outboundTag:'levik-service-endpoint-00'}, {type:'field',inboundTag:['user','levik-tun-in'],balancerTag:'levik-service-main'},
  ]}};
  let compiled,auth;
  if(compiledOverlay){
    launch.dns={servers:['https://1.1.1.1/dns-query']};
    launch.api.tag='levik-api';
    launch.inbounds=launch.inbounds.filter(inbound=>inbound.tag!=='api-in');
    launch.routing.rules=launch.routing.rules.filter(rule=>!rule.inboundTag.includes('api-in'));
    delete launch.routing.balancers;
    launch.routing.rules=launch.routing.rules.map(rule=>rule.balancerTag?{type:'field',inboundTag:rule.inboundTag,outboundTag:'source-A'}:rule);
    launch.outbounds=[{...outbound('source-A',exitA)},{...outbound('source-B',exitB)},{tag:'direct',protocol:'freedom',settings:{}},{tag:'levik-block',protocol:'blackhole',settings:{}}];
    const makeServer=(serverId,address,remotePort)=>({id:serverId,tag:`source-${serverId}`,name:serverId,countryCode:serverId==='A'?'DE':'FI',outbound:{...outbound(`source-${serverId}`,remotePort),settings:{vnext:[{address,port:remotePort,users:[{id,encryption:'none'}]}]}}});
    const candidates=[makeServer('A','198.51.100.1',exitA),makeServer('B','198.51.100.2',exitB)];
    launch=withServiceRoutes(launch,{policy:undefined,selected:candidates[0],servers:candidates,automaticServer:false,directTag:'direct',prepareOutbound:server=>outbound(server.tag,server.id==='A'?exitA:exitB)});
    compiled=compiledServiceRoutes(launch);assert.ok(compiled?.automatic,'ordinary manual core must preload controls for hot Auto enable');
    auth=compiled.auth;assert.ok(auth);
    // Remap only the fixture listeners; production keeps its reserved port range.
    const remap=new Map();for(const listener of [auth,...compiled.probes]){if(!remap.has(listener.port))remap.set(listener.port,await port());}
    for(const inbound of launch.inbounds)if(remap.has(inbound.port))inbound.port=remap.get(inbound.port);
    auth.port=remap.get(auth.port);for(const probe of compiled.probes)probe.port=remap.get(probe.port);
    for(const candidate of compiled.automatic.candidates)candidate.port=remap.get(candidate.port);
  }
  const core=await start(launch,user);
  let owner,failProof=false;
  if(compiledOverlay){
    owner=new ServiceRouteSession(()=>{}, {verifyMain:async candidate=>{
      const flow=await httpFlow(candidate.port,auth);
      try{assert.equal(await tcpMessage(flow,'preflight'),`${candidate.id}:preflight`);return !failProof;}
      finally{flow.socket.destroy();}
    }});
    owners.push(owner);
      owner.configureSmartAuto({controls:()=>({}),canTransfer:()=>false,networkKey:()=> 'local-fixture',report:()=>{}});
      await owner.start(launch);assert.equal(owner.automaticAvailable,true);assert.equal(owner.smartAutoActive,false);
      await owner.setAutomaticEnabled(true);assert.equal(owner.smartAutoActive,true);
      await owner.setAutomaticEnabled(false);assert.equal(owner.smartAutoActive,false);
      assert.equal(core.exitCode,null,'hot mode changes must preserve core');
  }
  const switchMain=async(id,tag)=>{
    if(owner)assert.deepEqual(await owner.selectMain(id),{status:'applied',serverId:id});
    else await overrideServiceRoute('levik-service-main',tag,`127.0.0.1:${api}`);
  };
  const pid=core.pid;
  const stats={query:async pattern=>compiledOverlay?queryServiceRouteStatistics(auth):parseXrayStats((await execute(executable,['api','statsquery',`--server=127.0.0.1:${api}`,`-pattern=${pattern}`],{timeout:5000})).stdout)};
  const pattern='inbound>>>levik-tun-in>>>traffic>>>';
  const beforeProbe=await stats.query(pattern);
  const probeFlow=await httpFlow(compiledOverlay?compiled.probes[0].port:probe,auth);assert.equal(await tcpMessage(probeFlow,'measurement'),'A:measurement');probeFlow.socket.destroy();
  assert.deepEqual(await stats.query(pattern),beforeProbe,'private route probes must not count as user TUN activity');
  const old=await socksFlow(socks),oldUDP=await udpFlow(socks);
  assert.equal(await tcpMessage(old,'before'),'A:before');assert.equal(await udpMessage(oldUDP,'before'),'A:before');
  const large=await socksFlow(socks);assert.equal(await tcpMessage(large,'large-open'),'A:large-open');
  const payload=randomBytes(512*1024).toString('base64');const midpoint=Math.floor(payload.length/2);
  const digest=value=>createHash('sha256').update(value).digest('hex');
  large.socket.write(payload.slice(0,midpoint));
  await switchMain('B','levik-service-endpoint-01');
  large.socket.write(payload.slice(midpoint)+'\n');
  const delivered=(await large.reader.until('\n')).toString();
  assert.equal(delivered.slice(0,2),'A:');assert.equal(digest(delivered.slice(2,-1)),digest(payload),'in-flight large transfer must stay intact across HotSwitch');
  assert.equal(await tcpMessage(old,'after'),'A:after');assert.equal(await udpMessage(oldUDP,'after'),'A:after');
  const next=await socksFlow(socks),nextUDP=await udpFlow(socks);
  assert.equal(await tcpMessage(next,'new'),'B:new');assert.equal(await udpMessage(nextUDP,'new'),'B:new');
  if(owner){
    failProof=true;assert.deepEqual(await owner.selectMain('A'),{status:'failed'});
    const retained=await socksFlow(socks);assert.equal(await tcpMessage(retained,'failed-switch'),'B:failed-switch');
    failProof=false;
  }
  await switchMain('A','levik-service-endpoint-00');
  assert.equal(await tcpMessage(next,'retained'),'B:retained');assert.equal(await udpMessage(nextUDP,'retained'),'B:retained');
  assert.equal(await tcpMessage(old,'retained'),'A:retained');assert.equal(await udpMessage(oldUDP,'retained'),'A:retained');
  for(const [id,tag] of [['B','levik-service-endpoint-01'],['A','levik-service-endpoint-00'],['B','levik-service-endpoint-01'],['A','levik-service-endpoint-00']]){
    await switchMain(id,tag);
    assert.equal(await tcpMessage(old,'repeated'),'A:repeated');assert.equal(await udpMessage(oldUDP,'repeated'),'A:repeated');
    assert.equal(await tcpMessage(next,'repeated'),'B:repeated');assert.equal(await udpMessage(nextUDP,'repeated'),'B:repeated');
  }
  assert.equal(core.pid,pid);assert.equal(core.exitCode,null);
  const userTraffic=await stats.query(pattern);assert.ok(userTraffic.uplink>0&&userTraffic.downlink>0,'real user TCP/UDP must advance TUN activity counters');
  console.log(JSON.stringify({result:'PASS',mux,compiledOverlay,manualHotSwitch:Boolean(owner),failedPreflightPreservesMain:Boolean(owner),largeTransferChecksum:true,repeatedSwitches:6,pidStable:true,existingTCP:'retained',existingUDP:'retained',newTCP:'new target',newUDP:'new target',privateProbesExcluded:true,userTrafficCounted:true}));
}
try{await run(false);await run(true);await run(false,true);await run(true,true);}finally{
  for(const owner of owners)owner.stop();
  for(const socket of sockets)socket.destroy();
  for(const socket of datagrams)try{socket.close();}catch{}
  await Promise.all(children.map(child=>new Promise(resolve=>{if(child.exitCode!==null||child.signalCode!==null)return resolve();child.once('exit',resolve);child.kill();setTimeout(()=>{child.kill('SIGKILL');resolve();},800).unref();})));
  await Promise.all(servers.map(server=>new Promise(resolve=>{if(!server.listening)return resolve();server.close(resolve);})));
}
