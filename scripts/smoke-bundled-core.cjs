#!/usr/bin/env node
// Run with ELECTRON_RUN_AS_NODE=1 on the packaged executable. Uses a fresh TEST
// identity in memory and uses only a disposable TEST queue; never initializes the app, OS key store, network or VPN.
const assert = require("node:assert/strict");
const { createHash, generateKeyPairSync, sign } = require("node:crypto");
const { resolve, join } = require("node:path");
const { mkdtemp, readdir, rm } = require("node:fs/promises");
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
  console.log(`Bundled Rust core ${info.version} verified in Electron ${process.versions.electron} (${info.os}/${info.arch}); async handles verified`);
}
const deadline = setTimeout(() => { console.error("Bundled Rust async check timed out"); process.exit(1); }, 10_000);
checkAsyncHandles().catch(() => { console.error("Bundled Rust async check failed"); process.exitCode = 1; })
  .finally(() => clearTimeout(deadline));
