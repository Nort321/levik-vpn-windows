#!/usr/bin/env node
// Run with ELECTRON_RUN_AS_NODE=1 on the packaged executable. Uses a fresh TEST
// identity in memory and uses only disposable TEST queue/cache directories; never initializes the app, OS key store, network or VPN.
const assert = require("node:assert/strict");
const { createHash, createECDH, generateKeyPairSync, hkdfSync, sign, verify } = require("node:crypto");
const { resolve, join } = require("node:path");
const { mkdtemp, readFile, readdir, rm, stat, writeFile } = require("node:fs/promises");
const { tmpdir } = require("node:os");

if (!process.versions.electron) throw new Error("Run this check with Electron, not regular Node");
const [modulePath, expectedVersion] = process.argv.slice(2);
if (!modulePath || !expectedVersion) throw new Error("Usage: smoke-bundled-core.cjs <module> <version>");
const core = require(resolve(modulePath));
const info = core.coreInfo();
assert.equal(info.contract, 2);
assert.equal(info.version, expectedVersion);
assert.equal(info.os, { win32: "windows", darwin: "macos", linux: "linux" }[process.platform]);
assert.equal(info.arch, { x64: "x86_64", arm64: "aarch64" }[process.arch]);
assert.ok(core.functions().includes("serviceEndpoints.verifyEndpointsDocument"));
const pair = generateKeyPairSync("rsa", { modulusLength: 3072, publicExponent: 0x10001 });
const serialized = { privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }), publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }) };
const identity = core.restoreIdentity(JSON.stringify(serialized));
const spki = pair.publicKey.export({ type: "spki", format: "der" });
assert.equal(identity.deviceId(), createHash("sha256").update(spki).digest("hex"));
const payload = Buffer.from("Levik bundled module check: TEST ONLY");
assert.equal(identity.sign(payload), sign("RSA-SHA256", payload, pair.privateKey).toString("base64url"));
async function checkAsyncHandles() {
  assert.equal(typeof core.openSecureStore, "function");
  await assert.rejects(core.openSecureStore("relative-path-is-rejected", "secret_service"));
  const events = identity.openEventStream(JSON.stringify({ origin: "https://unused.invalid", method: "GET",
    path: "/api/mobile/v1/events", accessToken: "TEST token", body: "", platform: info.os, version: "1.0.0", road: false, game: false }));
  events.close(); events.close();
  assert.deepEqual(JSON.parse(await events.read()), { ok: true, value: { events: [], done: true } });
  const publicRequest = core.createPublicClient().start(JSON.stringify({ url: "https://unused.invalid/api/health", method: "GET" }));
  publicRequest.close();
  assert.deepEqual(JSON.parse(await publicRequest.read()), { ok: false });
  const discovery = core.createApiDiscovery("https://unused.invalid");
  discovery.invalidate();
  assert.equal(await discovery.resolve("[]"), "https://unused.invalid");
  const pings = core.startServerPings(JSON.stringify([{ id: "TEST", endpoint: { host: "unused.invalid", port: 443 }, udp: true }]));
  pings.close();
  assert.deepEqual(JSON.parse(await pings.read()), { ok: false });
  const rpc = core.startXrayRequest('{"request":{"kind":"statistics"}}');
  rpc.close(); rpc.close();
  assert.deepEqual(JSON.parse(await rpc.read()), { ok: false });
  const dropIdentity = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = dropIdentity.privateKey.export({ type: "pkcs8", format: "der" });
  let agreement;
  try { agreement = core.openDropAgreement(privateDer, dropIdentity.publicKey.export({ type: "spki", format: "der" })); }
  finally { privateDer.fill(0); }
  try {
    const th = Buffer.alloc(32, 0x5a), peer = createECDH("prime256v1"); peer.generateKeys();
    const point = agreement.publicKey();
    const proof = agreement.signTranscript("sender", th);
    assert.ok(verify("sha256", Buffer.concat([Buffer.from("levik-drop/v1 sender\0"), th]), dropIdentity.publicKey, proof));
    const shared = peer.computeSecret(point);
    const expected = Buffer.from(hkdfSync("sha256", shared, th, Buffer.from("levik-drop/v1 keys"), 96));
    shared.fill(0);
    const keys = agreement.derive(peer.getPublicKey(), th);
    try { assert.deepEqual(keys.sr, expected.subarray(0,32)); assert.deepEqual(keys.rs, expected.subarray(32,64)); assert.deepEqual(keys.lan, expected.subarray(64,96)); }
    finally { expected.fill(0); keys.sr.fill(0); keys.rs.fill(0); keys.lan.fill(0); }
    assert.throws(() => agreement.derive(peer.getPublicKey(), th), /no keys/);
  } finally { agreement.close(); }
  const send = Buffer.alloc(32, 0x41), receive = Buffer.alloc(32, 0x42);
  const drop = core.openDropRecords(send, receive), peer = core.openDropRecords(receive, send);
  try {
    const payload = Buffer.alloc(262144, 0x5a);
    assert.deepEqual(peer.open(drop.seal(payload, true)), payload);
    assert.deepEqual(drop.open(peer.seal(Buffer.from("TEST reply"), false)), Buffer.from("TEST reply"));
    drop.close(); drop.close();
    assert.throws(() => drop.seal(Buffer.from("TEST"), false), /no keys/);
  } finally { drop.close(); peer.close(); send.fill(0); receive.fill(0); }
  const route = core.openRouteProbe(JSON.stringify({ port: 47200,
    auth: { port: 47200, user: "probe", password: "a".repeat(48) } }));
  route.close(); route.close();
  assert.deepEqual(JSON.parse(await route.latency("https://unused.invalid/", false)), { ok: false });
  const service = core.startServiceProbe(JSON.stringify({ kind: "dns", port: 47200,
    auth: { port: 47188, user: "levik-service", password: "a".repeat(48) }, resolvers: ["tcp://unused.invalid"] }));
  service.close(); service.close();
  assert.deepEqual(JSON.parse(await service.read()), { ok: true, value: false });
  const health = core.startTunnelProbe('{"kind":"handshake"}');
  health.close(); health.close();
  assert.deepEqual(JSON.parse(await health.read()), { ok: true, value: { healthy: false, durationMs: null, codes: [], cancelled: true } });
  const sourceDirectory = await mkdtemp(join(tmpdir(), "levik-bundled-source-"));
  try {
    const sourcePath = join(sourceDirectory,"TEST.bin"), bytes = Buffer.alloc(700000,0x5a);
    await writeFile(sourcePath,bytes); const metadata = await stat(sourcePath);
    const offset = 262151, prefix = createHash("sha256").update(bytes.subarray(0,offset)).digest("hex");
    const source = core.openDropSource(sourcePath,bytes.length,Math.trunc(metadata.mtimeMs),offset,prefix);
    try {
      const chunks = []; for (;;) { const chunk = await source.read(); if (chunk === null) break;
        assert.ok(Buffer.isBuffer(chunk) && chunk.length > 0 && chunk.length <= 262144); chunks.push(chunk); }
      assert.deepEqual(Buffer.concat(chunks),bytes.subarray(offset));
      assert.equal(source.digest(),createHash("sha256").update(bytes).digest("hex"));
      source.close(); await assert.rejects(source.read());
    } finally { source.close(); }
  } finally { await rm(sourceDirectory,{recursive:true,force:true}); }
  const directory = await mkdtemp(join(tmpdir(), "levik-bundled-queue-"));
  try {
    const queue = await core.openTelemetryQueue(directory);
    const now = Date.UTC(2026, 10, 5, 12);
    const install = await queue.installId(now);
    const entry = { startedAt: now, savedAt: now, body: { sid: "TEST", seq: 0, final: false, ageS: 0 } };
    await queue.put(JSON.stringify(entry), now);
    assert.deepEqual(JSON.parse(await queue.pending(now)), [entry]);
    assert.equal(await queue.installId(now), install);
    await queue.clear();
    assert.deepEqual(await readdir(directory), []);
  } finally { await rm(directory, { recursive: true, force: true }); }
  const cacheDirectory = await mkdtemp(join(tmpdir(), "levik-bundled-cache-"));
  try {
    const original = '{"response":{"ok":true},"fetchedAt":1}';
    await writeFile(join(cacheDirectory, "remote-config.json"), original);
    const cache = await core.openConfigCache(cacheDirectory);
    assert.equal(await cache.read("remote-config"), original);
    await cache.write("remote-config", '{"response":{"ok":true},"fetchedAt":2}');
    assert.equal(await readFile(join(cacheDirectory, "migration-backup-rust-v1/data/remote-config.json"), "utf8"), original);
    await assert.rejects(cache.read("../secure-v1/device_identity.json"));
    assert.deepEqual(JSON.parse(core.call("liveEvents.retryPlan", JSON.stringify({ failures: 0, received: false, random: 0.5 }))), { failures: 1, delay: 5750 });
  } finally { await rm(cacheDirectory, { recursive: true, force: true }); }
  console.log(`Bundled Rust core ${info.version} verified in Electron ${process.versions.electron} (${info.os}/${info.arch}); async handles verified`);
}
const deadline = setTimeout(() => { console.error("Bundled Rust async check timed out"); process.exit(1); }, 10_000);
checkAsyncHandles().catch(() => { console.error("Bundled Rust async check failed"); process.exitCode = 1; })
  .finally(() => clearTimeout(deadline));
