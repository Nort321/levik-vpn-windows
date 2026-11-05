import { dropProtocolWithCore } from "../src/main/core/coreDrop";
import { loadLevikCore } from "../src/main/core/levikCore";
import { RustCore } from "../src/main/core/rustCore";
import type { DropProtocol } from "../src/main/platform/levikDrop/session";
import { createECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, open, readFile, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { createServer, connect } from "node:net";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import vectors from "./fixtures/levikDropVectors.json";
import { FrameSocket } from "../src/main/platform/levikDrop/framing";
import { describeSources, planTargets, TargetFiles } from "../src/main/platform/levikDrop/files";
import { numberedName, safeFileName } from "../src/main/platform/levikDrop/fileNames";
import { privateAddresses } from "../src/main/platform/levikDrop/lan";
import * as protocol from "../src/main/platform/levikDrop/protocol";
import { relayControl, parseEndpoints } from "../src/main/platform/levikDrop/relay";
import { Session } from "../src/main/platform/levikDrop/session";
import type { Identity, ReceiverWork, SenderWork, SessionOutcome, SessionPath } from "../src/main/platform/levikDrop/session";

const bytes = (start: number): Buffer => Buffer.from(Array.from({ length: 32 }, (_, index) => start + index));
const hex = (value: Buffer): string => value.toString("hex");

function fixedIdentity(d: Buffer): Identity {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey();
  const privateKey = createPrivateKey({
    key: { kty: "EC", crv: "P-256", d: d.toString("base64url"), x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") },
    format: "jwk",
  });
  return { privateKey, spki: createPublicKey(privateKey).export({ type: "spki", format: "der" }) };
}

describe("LevikDrop wire format", () => {
  it("matches the vectors the Android app checks too", () => {
    const sender = fixedIdentity(bytes(0x01));
    const receiver = fixedIdentity(bytes(0x21));
    expect(hex(sender.spki)).toBe(vectors.spkiS);
    expect(hex(receiver.spki)).toBe(vectors.spkiR);
    const ephemeralS = createECDH("prime256v1");
    ephemeralS.setPrivateKey(bytes(0x41));
    const ephemeralR = createECDH("prime256v1");
    ephemeralR.setPrivateKey(bytes(0x61));
    const transfer = protocol.transferBytes(vectors.transfer);
    const commit = protocol.commitment(sender.spki, ephemeralS.getPublicKey(), bytes(0xa0));
    expect(hex(commit)).toBe(vectors.commit);
    const helloS = { transfer, identity: sender.spki, ephemeral: ephemeralS.getPublicKey(), commit };
    const helloR = { transfer, identity: receiver.spki, ephemeral: ephemeralR.getPublicKey(), nonce: bytes(0xc0) };
    expect(hex(protocol.encodeSenderHello(helloS))).toBe(vectors.helloS);
    expect(hex(protocol.encodeReceiverHello(helloR))).toBe(vectors.helloR);
    expect(protocol.decodeSenderHello(Buffer.from(vectors.helloS, "hex"))).toEqual(helloS);
    expect(protocol.decodeReceiverHello(Buffer.from(vectors.helloR, "hex"))).toEqual(helloR);
    const th = protocol.transcript(helloS, helloR, bytes(0xa0));
    expect(hex(th)).toBe(vectors.th);
    const keys = protocol.sessionKeys(ephemeralS, helloR.ephemeral, th);
    const mirrored = protocol.sessionKeys(ephemeralR, helloS.ephemeral, th);
    expect([hex(keys.sr), hex(keys.rs), hex(keys.lan), keys.code]).toEqual([vectors.sr, vectors.rs, vectors.lan, vectors.code]);
    expect(mirrored).toEqual(keys);

    const sealer = new protocol.RecordSealer(keys.sr);
    const opener = new protocol.RecordOpener(keys.sr);
    expect(opener.open(sealer.seal(Buffer.from("x"))).toString()).toBe("x");
    const record = sealer.seal(protocol.encodeControl({ t: "done" }));
    expect(hex(record)).toBe(vectors.record1);
    expect(protocol.decodePlaintext(opener.open(record))).toEqual({ kind: "control", control: { t: "done" } });
    expect(hex(protocol.lanDialerFrame(transfer, keys.lan))).toBe(vectors.dialer);
    expect(hex(protocol.lanListenerFrame(keys.lan))).toBe(vectors.listener);
    expect(hex(protocol.encodeData(3, 262_144, Buffer.from("abc")))).toBe(vectors.data);

    // Signatures are randomized; each side checks the other's.
    const signature = protocol.signTranscript("sender", sender.privateKey, th);
    expect(protocol.verifyTranscript("sender", sender.spki, th, signature)).toBe(true);
    expect(protocol.verifyTranscript("receiver", sender.spki, th, signature)).toBe(false);
    expect(protocol.verifyTranscript("sender", receiver.spki, th, signature)).toBe(false);
  });

  it("rejects records out of order, tampered or under another key", () => {
    const key = randomBytes(32);
    const sealer = new protocol.RecordSealer(key);
    const first = sealer.seal(Buffer.from([0x01, 0x7b, 0x7d]));
    const second = sealer.seal(Buffer.from([0x01, 0x7b, 0x7d]));
    expect(() => new protocol.RecordOpener(key).open(second)).toThrow(protocol.ProtocolError);
    const tampered = Buffer.from(first);
    tampered[12] = (tampered[12] ?? 0) ^ 1;
    expect(() => new protocol.RecordOpener(key).open(tampered)).toThrow(protocol.ProtocolError);
    expect(() => new protocol.RecordOpener(randomBytes(32)).open(first)).toThrow(protocol.ProtocolError);
    const opener = new protocol.RecordOpener(key);
    opener.open(first);
    expect(() => opener.open(first)).toThrow(protocol.ProtocolError);
  });

  it("checks every control field", () => {
    expect(protocol.parseControl({ t: "manifest", files: [{ name: "a", size: 2 }, { name: "b", size: 3 }], total: 5 })).toEqual({
      t: "manifest", files: [{ name: "a", size: 2 }, { name: "b", size: 3 }], total: 5,
    });
    expect(() => protocol.parseControl({ t: "manifest", files: [{ name: "a", size: 2 }], total: 3 })).toThrow();
    expect(protocol.parseControl({ t: "manifest", files: Array.from({ length: 21 }, () => ({ name: "a", size: 1 })), total: 21 })?.t).toBe("manifest");
    expect(() => protocol.parseControl({ t: "manifest", files: [{ name: "a", size: Number.MAX_SAFE_INTEGER + 1 }], total: Number.MAX_SAFE_INTEGER + 1 })).toThrow();
    expect(() => protocol.parseControl({ t: "accept", offsets: [1], prefix: ["zz"] })).toThrow();
    expect(() => protocol.parseControl({ t: "lan", addrs: ["8.8.8.8"], port: 1 })).toThrow();
    expect(protocol.parseControl({ t: "lan", addrs: ["192.168.1.5", "10.0.0.2"], port: 50_000 })).toEqual({ t: "lan", addrs: ["192.168.1.5", "10.0.0.2"], port: 50_000 });
    expect(protocol.parseControl({ t: "fail", reason: "rm -rf" })).toEqual({ t: "fail", reason: "protocol" });
    expect(protocol.parseControl({ t: "future" })).toBeNull();
    expect(protocol.isPrivateIpv4("172.31.0.1")).toBe(true);
    expect(protocol.isPrivateIpv4("172.32.0.1")).toBe(false);
    expect(protocol.isPrivateIpv4("192.168.01.1")).toBe(false);
  });

  it("reads relay controls and endpoints", () => {
    expect(relayControl(Buffer.concat([Buffer.from([0]), Buffer.from('{"t":"end","reason":"limit"}')]))).toEqual({ t: "end", reason: "limit" });
    expect(relayControl(Buffer.from([0x10, 0]))).toBeNull();
    expect(relayControl(Buffer.from([0, 0x7b]))).toEqual({ t: "end", reason: "bad_control" });
    expect(parseEndpoints([{ host: "2.27.42.184", port: 25445, pin: "a".repeat(43) }, { host: "x y", port: 1, pin: "a".repeat(43) }, { host: "h", port: 0, pin: "" }]))
      .toEqual([{ host: "2.27.42.184", port: 25445, pin: "a".repeat(43) }]);
  });

  it("never turns a name into a path", () => {
    for (const [raw, safe] of vectors.names) expect(safeFileName(raw ?? "")).toBe(safe);
    const long = `${"я".repeat(200)}.tar.gz`;
    expect(Buffer.byteLength(safeFileName(long))).toBeLessThanOrEqual(180);
    expect(safeFileName(long).endsWith(".gz")).toBe(true);
    expect(numberedName("photo.jpg", 2)).toBe("photo (2).jpg");
    expect(numberedName("README", 1)).toBe("README (1)");
  });
});

// Two sessions over a loopback connection, the relay's part played by a plain socket.

async function socketPair(): Promise<[FrameSocket, FrameSocket]> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  const accepted = new Promise<Socket>((resolve) => server.once("connection", resolve));
  const client = connect(address.port, "127.0.0.1");
  const [one, two] = await Promise.all([accepted, new Promise<Socket>((resolve) => client.once("connect", () => resolve(client)))]);
  server.close();
  return [new FrameSocket(one), new FrameSocket(two)];
}

function feed(socket: FrameSocket, session: Session): void {
  void (async () => {
    for (;;) {
      let frame: Buffer;
      try {
        frame = await socket.next();
      } catch {
        session.abort("closed");
        return;
      }
      session.inbox.push(frame);
    }
  })();
}

const TRANSFER = "11111111-2222-4333-8444-555555555555";
const temporary: string[] = [];

afterEach(async () => {
  for (const path of temporary.splice(0)) await rm(path, { recursive: true, force: true });
});

interface Run {
  sender: SessionOutcome;
  receiver: SessionOutcome;
  paths: SessionPath[];
  codes: string[];
  relayPayloadBytes: number;
}

async function setup(files: Array<[string, Buffer]>) {
  const root = await mkdtemp(join(tmpdir(), "levikdrop-"));
  temporary.push(root);
  const source = join(root, "source");
  const target = join(root, "target");
  await Promise.all([mkdir(source), mkdir(target)]);
  const paths: string[] = [];
  for (const [name, content] of files) {
    const path = join(source, name);
    await writeFile(path, content);
    paths.push(path);
  }
  const sources = await describeSources(paths);
  const make = (): Identity => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    return { privateKey: pair.privateKey, spki: pair.publicKey.export({ type: "spki", format: "der" }) };
  };
  return { root, source, target, sources, senderIdentity: make(), receiverIdentity: make() };
}

type Setup = Awaited<ReturnType<typeof setup>>;

async function run(
  context: Setup,
  receiverState: { manifest: protocol.ManifestFile[] | null; targets: TargetFiles | null },
  options: { allowLan?: boolean; stopAfter?: number; senderPlatform?: "windows" | "macos"; route?: "auto" | "lan" | "relay"; decline?: boolean; senderProtocol?: DropProtocol; receiverProtocol?: DropProtocol; abortSenderOnKeyed?: boolean } = {},
): Promise<Run> {
  const [senderSocket, receiverSocket] = await socketPair();
  let relayPayloadBytes = 0;
  const sendRelay = senderSocket.send.bind(senderSocket);
  senderSocket.send = (frame) => {
    if (frame[0] === 0x11) relayPayloadBytes += frame.length;
    return sendRelay(frame);
  };
  const paths: SessionPath[] = [];
  const codes: string[] = [];
  const common = {
    transferId: TRANSFER,
    allowLan: options.allowLan ?? false,
    trust: () => "new" as const,
    ...(options.route ? { route: options.route, expectedFiles: context.sources.length, expectedBytes: context.sources.reduce((n, f) => n + f.size, 0) } : {}),
  };
  let receiverSession: Session | null = null;
  const senderWork: SenderWork = {
    ...common,
    role: "sender",
    ...(options.senderProtocol ? { protocol: options.senderProtocol } : {}),
    identity: context.senderIdentity,
    peerDeviceId: "receiver",
    ownPlatform: options.senderPlatform ?? "macos",
    peerPlatform: "windows",
    files: context.sources,
    confirm: async (code) => {
      codes.push(code);
      return true;
    },
    events: { keyed: () => { if (options.abortSenderOnKeyed) sender.abort("TEST keyed abort"); }, path: (path) => paths.push(path), progress: () => {} },
  };
  const receiverWork: ReceiverWork = {
    ...common,
    role: "receiver",
    ...(options.receiverProtocol ? { protocol: options.receiverProtocol } : {}),
    identity: context.receiverIdentity,
    peerDeviceId: "sender",
    ownPlatform: "windows",
    peerPlatform: options.senderPlatform ?? "macos",
    manifest: receiverState.manifest,
    targets: receiverState.targets,
    decide: async (manifest, code) => {
      if (options.route) expect(paths).toHaveLength(2); // Both sides know the route before accepting.
      codes.push(code);
      if (options.decline) return null;
      const planned = await planTargets(context.target, manifest);
      return new TargetFiles(context.target, planned, async () => {}, options.receiverProtocol?.createTargets?.(context.target, planned) ?? null);
    },
    confirm: async () => true,
    events: {
      keyed: () => {},
      path: (path) => paths.push(path),
      progress: (done) => {
        if (options.stopAfter !== undefined && done >= options.stopAfter) {
          senderSocket.close();
          receiverSocket.close();
        }
      },
    },
  };
  const sender = new Session(senderSocket, senderWork);
  receiverSession = new Session(receiverSocket, receiverWork);
  feed(senderSocket, sender);
  feed(receiverSocket, receiverSession);
  const [senderOutcome, receiverOutcome] = await Promise.all([sender.run().then((outcome) => { if (outcome.kind === "lost") senderSocket.close(); return outcome; }), receiverSession.run()]);
  senderSocket.close();
  receiverSocket.close();
  receiverState.manifest = receiverWork.manifest;
  receiverState.targets = receiverWork.targets;
  return { sender: senderOutcome, receiver: receiverOutcome, paths, codes, relayPayloadBytes };
}

describe("LevikDrop session", () => {
  it("delivers files end to end, both screens showing one code", async () => {
    const big = randomBytes(700_000);
    const context = await setup([["отчёт.bin", big], ["empty.txt", Buffer.alloc(0)], ["CON.txt", Buffer.from("hi")]]);
    await writeFile(join(context.target, "отчёт.bin"), "already here");
    const state = { manifest: null, targets: null };
    const result = await run(context, state);
    expect(result.sender).toEqual({ kind: "done" });
    expect(result.receiver).toEqual({ kind: "done" });
    expect(result.codes).toHaveLength(2);
    expect(result.codes[0]).toBe(result.codes[1]);
    expect((await readFile(join(context.target, "отчёт (1).bin"))).equals(big)).toBe(true);
    expect(await readFile(join(context.target, "отчёт.bin"), "utf8")).toBe("already here");
    expect((await readFile(join(context.target, "empty.txt"))).length).toBe(0);
    expect(await readFile(join(context.target, "CON_.txt"), "utf8")).toBe("hi");
    expect((await readdir(context.target)).filter((name) => name.endsWith(".levikdrop"))).toEqual([]);
  }, 30_000);

  it("continues where it stopped and checks the source did not change", async () => {
    const content = randomBytes(5 * 1024 * 1024 + 123);
    const context = await setup([["video.mp4", content]]);
    const state: { manifest: protocol.ManifestFile[] | null; targets: TargetFiles | null } = { manifest: null, targets: null };
    const first = await run(context, state, { stopAfter: 2 * 1024 * 1024 });
    expect(first.sender.kind).toBe("lost");
    expect(first.receiver.kind).toBe("lost");
    expect(state.targets).not.toBeNull();
    const second = await run(context, state);
    expect(second.sender).toEqual({ kind: "done" });
    expect(second.receiver).toEqual({ kind: "done" });
    const received = await readFile(join(context.target, "video.mp4"));
    expect(createHash("sha256").update(received).digest("hex")).toBe(createHash("sha256").update(content).digest("hex"));

    const changed = await setup([["doc.bin", randomBytes(3 * 1024 * 1024)]]);
    const changedState: { manifest: protocol.ManifestFile[] | null; targets: TargetFiles | null } = { manifest: null, targets: null };
    await run(changed, changedState, { stopAfter: 1024 * 1024 });
    const path = changed.sources[0]?.path ?? "";
    await utimes(path, new Date(), new Date(Date.now() + 60_000));
    const third = await run(changed, changedState);
    expect(third.sender).toEqual({ kind: "failed", by: "self", reason: "source_changed" });
    expect(third.receiver).toEqual({ kind: "failed", by: "peer", reason: "source_changed" });
  }, 30_000);

  it.runIf(privateAddresses().length > 0)("switches to the local network", async () => {
    const content = randomBytes(3 * 1024 * 1024);
    for (const senderPlatform of ["macos", "windows"] as const) {
      const context = await setup([["lan.bin", content]]);
      const result = await run(context, { manifest: null, targets: null }, { allowLan: true, senderPlatform });
      expect(result.sender).toEqual({ kind: "done" });
      expect(result.receiver).toEqual({ kind: "done" });
      expect(result.paths.filter((path) => path === "lan")).toHaveLength(2);
      expect((await readFile(join(context.target, "lan.bin"))).equals(content)).toBe(true);
    }
  }, 30_000);
});


describe("LevikDrop route selection", () => {
  it("carries file indices and offsets beyond the old limits without truncation", () => {
    const plain = protocol.encodeData(70_000, 50 * 1024 ** 3, Buffer.from("abc"), true);
    expect(plain.toString("hex")).toBe("03000111700000000c80000000616263");
    expect(protocol.decodePlaintext(plain)).toMatchObject({ kind: "data", data: { file: 70_000, offset: 50 * 1024 ** 3 } });
    const key = randomBytes(32);
    const sealed = new protocol.RecordSealer(key).seal(plain, true);
    expect(sealed[0]).toBe(0x11);
    expect(new protocol.RecordOpener(key).open(sealed)).toEqual(plain);
    const changed = Buffer.from(sealed); changed[0] = 0x10;
    expect(() => new protocol.RecordOpener(key).open(changed)).toThrow();
  });

  it("shows the relay route before acceptance and transfers using marked data records", async () => {
    const context = await setup([["relay.txt", Buffer.from("relay payload")]]);
    const result = await run(context, { manifest: null, targets: null }, { route: "relay" });
    expect(result.sender.kind).toBe("done");
    expect(result.receiver.kind).toBe("done");
    expect(result.paths).toEqual(["relay", "relay"]);
    expect(await readFile(join(context.target, "relay.txt"), "utf8")).toBe("relay payload");
  }, 30_000);

  it.runIf(privateAddresses().length > 0)("negotiates LAN before offering a large file without sending its contents", async () => {
    const context = await setup([["large.bin", Buffer.alloc(0)]]);
    context.sources[0]!.size = 50 * 1024 ** 3;
    const result = await run(context, { manifest: null, targets: null }, { route: "auto", allowLan: true, decline: true });
    expect(result.paths).toEqual(["lan", "lan"]);
    expect(result.sender.kind).toBe("declined");
    expect(await readdir(context.target)).toEqual([]);
  }, 30_000);

  it.runIf(privateAddresses().length > 0)("streams more than twenty files and resume offsets on LAN", async () => {
    const context = await setup(Array.from({ length: 40 }, (_, i): [string, Buffer] => [`file-${i}.txt`, Buffer.from(`payload-${i}`)]));
    const result = await run(context, { manifest: null, targets: null }, { route: "lan", allowLan: true });
    expect(result.sender.kind).toBe("done");
    expect(result.receiver.kind).toBe("done");
    expect(result.paths).toEqual(["lan", "lan"]);
    expect(await readdir(context.target)).toHaveLength(40);
    expect(await readFile(join(context.target, "file-39.txt"), "utf8")).toBe("payload-39");
  }, 30_000);

  it("never falls back to relay when a pinned local route is unavailable", async () => {
    const context = await setup([["local.txt", Buffer.from("local only")]]);
    const result = await run(context, { manifest: null, targets: null }, { route: "lan", allowLan: false });
    expect(result.sender).toMatchObject({ kind: "lost", lanBroke: true });
    expect(result.paths).toEqual([]);
    expect(result.codes).toEqual([]);
    expect(await readdir(context.target)).toEqual([]);
  }, 10_000);

  it.runIf(privateAddresses().length > 0)("marks a broken local transfer for pause and resumes on LAN", async () => {
    const content = randomBytes(12 * 1024 * 1024);
    const context = await setup([["resume.bin", content]]);
    const state: { manifest: protocol.ManifestFile[] | null; targets: TargetFiles | null } = { manifest: null, targets: null };
    const first = await run(context, state, { route: "lan", allowLan: true, stopAfter: 1024 * 1024 });
    expect(first.sender).toMatchObject({ kind: "lost", lanBroke: true });
    expect(first.receiver).toMatchObject({ kind: "lost", lanBroke: true });
    const next = await run(context, state, { route: "lan", allowLan: true });
    expect(next.sender.kind).toBe("done");
    expect((await readFile(join(context.target, "resume.bin"))).equals(content)).toBe(true);
  }, 30_000);
});


it("keeps simultaneous transfers with the same filename separate", async () => {
  const context = await setup([]);
  const manifest = [{ name: "same.txt", size: 3 }];
  const plans = await Promise.all([planTargets(context.target, manifest), planTargets(context.target, manifest)]);
  expect(plans[0]![0]!.partial).not.toBe(plans[1]![0]!.partial);
  await Promise.all(plans.map(async (plan, index) => {
    const files = new TargetFiles(context.target, plan, async () => {});
    await files.offsets();
    const bytes = Buffer.from(index ? "two" : "one");
    await files.write(0, 0, bytes);
    await files.finish(0, createHash("sha256").update(bytes).digest("hex"));
  }));
  const contents = await Promise.all((await readdir(context.target)).map((name) => readFile(join(context.target, name), "utf8")));
  expect(contents.sort()).toEqual(["one", "two"]);
});


it.runIf(process.env.LEVIK_DROP_LARGE_TEST === "1" && privateAddresses().length > 0)("delivers a real file larger than 2 GiB on LAN without relay payload", async () => {
  const context = await setup([["large.bin", Buffer.alloc(0)]]);
  const size = 2 * 1024 ** 3 + 1;
  const source = context.sources[0]!.path;
  const handle = await open(source, "r+");
  try { await handle.truncate(size); } finally { await handle.close(); }
  context.sources = await describeSources([source]);
  const result = await run(context, { manifest: null, targets: null }, { route: "lan", allowLan: true });
  expect(result.sender.kind).toBe("done");
  expect(result.receiver.kind).toBe("done");
  expect(result.paths).toEqual(["lan", "lan"]);
  expect(result.relayPayloadBytes).toBe(0);
  expect((await stat(join(context.target, "large.bin"))).size).toBe(size);
}, 180_000);


const nativeModulePath = process.env.LEVIK_TEST_CORE;
function nativeProtocol() {
  if (!nativeModulePath) throw new Error("LEVIK_TEST_CORE missing");
  const loaded = loadLevikCore(nativeModulePath);
  if (loaded.state !== "loaded" || !loaded.module.openDropRecords || !loaded.module.openDropAgreement) throw new Error("Native Drop records missing");
  const core = new RustCore(null, () => {}, "rust");
  const base = dropProtocolWithCore(() => core, () => loaded.module.openDropRecords, () => {}, () => loaded.module.openDropAgreement, () => loaded.module.openDropSource, () => loaded.module.openDropTargets);
  const retained: protocol.SessionKeys[] = [];
  let closed = 0; let agreements = 0; let agreementsClosed = 0; let sources = 0; let sourcesClosed = 0; let targetsCreated = 0;
  const native: DropProtocol = { ...base, createTargets: (folder, targets) => {
    const owner = base.createTargets?.(folder, targets); if (owner) targetsCreated++; return owner ?? null;
  }, createSource: (file, offset, prefix) => {
    const source = base.createSource?.(file, offset, prefix); if (!source) return null;
    sources++; return { read: source.read, digest: source.digest, close: () => { sourcesClosed++; source.close(); } };
  }, createAgreement: (identity) => {
    const agreement = base.createAgreement?.(identity);
    if (!agreement) throw new Error("TEST native agreement was not selected");
    agreements++;
    return { publicKey: agreement.publicKey, signTranscript: agreement.signTranscript, sessionKeys: agreement.sessionKeys,
      close: () => { agreementsClosed++; agreement.close(); } };
  }, createRecords: (role, keys) => {
    retained.push(keys);
    const records = base.createRecords?.(role, keys);
    if (!records) throw new Error("TEST native codec was not selected");
    return { seal: records.seal, open: records.open, close: () => { closed++; records.close(); } };
  } };
  return { protocol: native, created: () => retained.length, agreementsCreated: () => agreements, sourcesCreated: () => sources, sourcesSupported: !!loaded.module.openDropSource, targetsCreated: () => targetsCreated, targetsSupported: !!loaded.module.openDropTargets, verifyRetired: (count: number) => {
    expect(closed).toBe(count); expect(retained).toHaveLength(count);
    expect(agreements).toBeGreaterThanOrEqual(count); expect(agreementsClosed).toBe(agreements); expect(sourcesClosed).toBe(sources);
    for (const keys of retained) for (const bytes of [keys.sr, keys.rs, keys.lan]) expect(bytes.every((byte) => byte === 0)).toBe(true);
  } };
}

describe.skipIf(!nativeModulePath)("real Rust/Node Drop transfer", () => {
  it("retires private agreement state immediately when abort interrupts the handshake", async () => {
    const context = await setup([["unused.bin", Buffer.from("TEST")]]); const native = nativeProtocol();
    const [socket, peer] = await socketPair();
    const sender = new Session(socket, { role: "sender", transferId: TRANSFER, identity: context.senderIdentity,
      peerDeviceId: "TEST peer", ownPlatform: "macos", peerPlatform: "windows", allowLan: false, trust: () => "new",
      events: { keyed: () => { throw new Error("Unexpected keyed event"); }, path: () => {}, progress: () => {} },
      files: context.sources, confirm: async () => true, protocol: native.protocol });
    try {
      const result = sender.run(); const hello = await peer.next(2000);
      expect(hello[0]).toBe(0x01); expect(native.agreementsCreated()).toBe(1);
      sender.abort("TEST interrupted handshake"); native.verifyRetired(0);
      expect((await result).kind).toBe("lost"); native.verifyRetired(0);
    } finally { sender.abort("TEST cleanup"); socket.close(); peer.close(); }
  });

  it.each(["sender", "receiver", "both"] as const)("delivers unchanged files with native %s and retires session secrets", async (side) => {
    const content = randomBytes(1024 * 1024 + 123);
    const context = await setup([["native.bin", content], ["empty.txt", Buffer.alloc(0)]]);
    const native = nativeProtocol();
    const result = await run(context, { manifest: null, targets: null }, {
      ...(side !== "receiver" ? { senderProtocol: native.protocol } : {}),
      ...(side !== "sender" ? { receiverProtocol: native.protocol } : {}),
    });
    expect(result.sender).toEqual({ kind: "done" }); expect(result.receiver).toEqual({ kind: "done" });
    expect(result.codes[0]).toBe(result.codes[1]); expect((await readFile(join(context.target, "native.bin"))).equals(content)).toBe(true);
    expect((await readFile(join(context.target, "empty.txt"))).length).toBe(0); native.verifyRetired(side === "both" ? 2 : 1);
    if (native.sourcesSupported && side !== "receiver") expect(native.sourcesCreated()).toBe(2);
    if (native.targetsSupported && side !== "sender") expect(native.targetsCreated()).toBe(1);
  }, 30_000);
  it("keeps the v2 relay data markers and survives interrupted transfer with fresh owners", async () => {
    const content = randomBytes(3 * 1024 * 1024 + 123);
    const context = await setup([["resume.bin", content]]);
    const state: { manifest: protocol.ManifestFile[] | null; targets: TargetFiles | null } = { manifest: null, targets: null };
    const native = nativeProtocol();
    const options = { route: "relay" as const, senderProtocol: native.protocol, receiverProtocol: native.protocol };
    const first = await run(context, state, { ...options, stopAfter: 1024 * 1024 });
    expect(first.sender.kind).toBe("lost"); expect(first.receiver.kind).toBe("lost"); native.verifyRetired(2);
    const second = await run(context, state, options);
    expect(second.sender).toEqual({ kind: "done" }); expect(second.receiver).toEqual({ kind: "done" });
    expect(second.relayPayloadBytes).toBeGreaterThan(0);
    expect((await readFile(join(context.target, "resume.bin"))).equals(content)).toBe(true); native.verifyRetired(4);
  }, 30_000);
  it("sends a native decline before closing and erases both attempts", async () => {
    const context = await setup([["declined.bin", Buffer.from("TEST")]]); const native = nativeProtocol();
    const result = await run(context, { manifest: null, targets: null }, { decline: true, senderProtocol: native.protocol, receiverProtocol: native.protocol });
    expect(result.sender).toEqual({ kind: "declined", by: "peer" }); expect(result.receiver).toEqual({ kind: "declined", by: "self" });
    expect(await readdir(context.target)).toEqual([]); native.verifyRetired(2);
  });
  it("does not prompt or send after a synchronous abort from the keyed event", async () => {
    const context = await setup([["aborted.bin", Buffer.from("TEST")]]); const native = nativeProtocol();
    const result = await run(context, { manifest: null, targets: null }, {
      abortSenderOnKeyed: true, senderProtocol: native.protocol, receiverProtocol: native.protocol,
    });
    expect(result.sender).toMatchObject({ kind: "lost", detail: "TEST keyed abort" });
    expect(result.receiver.kind).toBe("lost"); expect(result.codes).toEqual([]); expect(native.created()).toBeGreaterThan(0);
    native.verifyRetired(native.created());
  });

});
