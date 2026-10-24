import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createPublicKey,
  hkdfSync,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import type { ECDH, KeyObject } from "node:crypto";

/**
 * LevikDrop v1 wire format, docs/levik-drop.md "Session". Pure functions:
 * the Android app implements the same bytes (tests/levikDropProtocol.test.ts
 * holds the vectors both check).
 */

export const PROTOCOL = 1;
export const MAX_FRAME = 270_336;
export const MAX_CHUNK = 262_144;
export const MAX_FILES = 20;
export const MAX_TOTAL = 2 * 1024 ** 3;
/** Bytes the sender keeps in flight beyond the last acknowledgement. */
export const WINDOW = 8 * 1024 * 1024;
export const ACK_EVERY = 1024 * 1024;
export const KEEPALIVE = Buffer.from([0x7f]);

const LABEL = {
  commit: "levik-drop/v1 commit\0",
  transcript: "levik-drop/v1 transcript\0",
  sender: "levik-drop/v1 sender\0",
  receiver: "levik-drop/v1 receiver\0",
  keys: "levik-drop/v1 keys",
  code: "levik-drop/v1 code",
  lanDialer: "levik-drop/v1 lan dialer",
  lanListener: "levik-drop/v1 lan listener",
} as const;

export class ProtocolError extends Error {}

function fail(message: string): never {
  throw new ProtocolError(message);
}

export function lp(value: Uint8Array): Buffer {
  if (value.length > 0xffff) fail("field too long");
  const head = Buffer.alloc(2);
  head.writeUInt16BE(value.length);
  return Buffer.concat([head, value]);
}

export function sha256(...parts: Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function transferBytes(id: string): Buffer {
  const lower = id.toLowerCase();
  if (!UUID.test(lower)) fail("bad transfer id");
  return Buffer.from(lower.replaceAll("-", ""), "hex");
}

/** The peer's identity key: ECDSA P-256, SPKI DER. */
export function identityPublicKey(spki: Uint8Array): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  } catch {
    fail("bad identity key");
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") fail("identity key is not P-256");
  return key;
}

export function keyHash(spki: Uint8Array): string {
  return sha256(spki).toString("hex");
}

/** The first 16 hex digits the website shows as keyId. */
export function keyId(spki: Uint8Array): string {
  return keyHash(spki).slice(0, 16);
}

// Handshake ------------------------------------------------------------------------------

export interface SenderHello {
  transfer: Buffer;
  identity: Buffer;
  ephemeral: Buffer;
  commit: Buffer;
}

export interface ReceiverHello {
  transfer: Buffer;
  identity: Buffer;
  ephemeral: Buffer;
  nonce: Buffer;
}

export function commitment(identity: Uint8Array, ephemeral: Uint8Array, nonce: Uint8Array): Buffer {
  return sha256(Buffer.from(LABEL.commit), lp(identity), ephemeral, nonce);
}

export function encodeSenderHello(hello: SenderHello): Buffer {
  return Buffer.concat([Buffer.from([0x01, PROTOCOL]), hello.transfer, lp(hello.identity), hello.ephemeral, hello.commit]);
}

export function encodeReceiverHello(hello: ReceiverHello): Buffer {
  return Buffer.concat([Buffer.from([0x02, PROTOCOL]), hello.transfer, lp(hello.identity), hello.ephemeral, hello.nonce]);
}

export function encodeSenderProof(nonce: Uint8Array, signature: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from([0x03]), nonce, lp(signature)]);
}

export function encodeReceiverProof(signature: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from([0x04]), lp(signature)]);
}

class Reader {
  private offset = 0;
  constructor(private readonly data: Buffer) {}

  take(length: number): Buffer {
    if (this.offset + length > this.data.length) fail("message too short");
    const part = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return Buffer.from(part);
  }

  byte(): number {
    return this.take(1)[0] ?? 0;
  }

  field(max: number): Buffer {
    const length = this.take(2).readUInt16BE();
    if (length < 1 || length > max) fail("bad field length");
    return this.take(length);
  }

  end(): void {
    if (this.offset !== this.data.length) fail("trailing bytes");
  }
}

function hello(data: Buffer, type: number): { transfer: Buffer; identity: Buffer; ephemeral: Buffer; tail: Buffer } {
  const reader = new Reader(data);
  if (reader.byte() !== type) fail("unexpected message");
  if (reader.byte() !== PROTOCOL) fail("unsupported protocol");
  const transfer = reader.take(16);
  const identity = reader.field(512);
  const ephemeral = reader.take(65);
  if (ephemeral[0] !== 0x04) fail("ephemeral key not uncompressed");
  const tail = reader.take(32);
  reader.end();
  return { transfer, identity, ephemeral, tail };
}

export function decodeSenderHello(data: Buffer): SenderHello {
  const { transfer, identity, ephemeral, tail } = hello(data, 0x01);
  return { transfer, identity, ephemeral, commit: tail };
}

export function decodeReceiverHello(data: Buffer): ReceiverHello {
  const { transfer, identity, ephemeral, tail } = hello(data, 0x02);
  return { transfer, identity, ephemeral, nonce: tail };
}

export function decodeSenderProof(data: Buffer): { nonce: Buffer; signature: Buffer } {
  const reader = new Reader(data);
  if (reader.byte() !== 0x03) fail("unexpected message");
  const nonce = reader.take(32);
  const signature = reader.field(80);
  reader.end();
  return { nonce, signature };
}

export function decodeReceiverProof(data: Buffer): Buffer {
  const reader = new Reader(data);
  if (reader.byte() !== 0x04) fail("unexpected message");
  const signature = reader.field(80);
  reader.end();
  return signature;
}

export function transcript(sender: SenderHello, receiver: ReceiverHello, senderNonce: Uint8Array): Buffer {
  return sha256(
    Buffer.from(LABEL.transcript),
    sender.transfer,
    lp(sender.identity),
    sender.ephemeral,
    sender.commit,
    lp(receiver.identity),
    receiver.ephemeral,
    receiver.nonce,
    senderNonce,
  );
}

export function signTranscript(role: "sender" | "receiver", key: KeyObject, th: Uint8Array): Buffer {
  return sign("sha256", Buffer.concat([Buffer.from(LABEL[role]), th]), { key, dsaEncoding: "der" });
}

export function verifyTranscript(role: "sender" | "receiver", identity: Uint8Array, th: Uint8Array, signature: Uint8Array): boolean {
  try {
    return verify("sha256", Buffer.concat([Buffer.from(LABEL[role]), th]), { key: identityPublicKey(identity), dsaEncoding: "der" }, signature);
  } catch {
    return false;
  }
}

export interface SessionKeys {
  /** Sender → receiver records. */
  sr: Buffer;
  /** Receiver → sender records. */
  rs: Buffer;
  lan: Buffer;
  /** Six digits both screens show, "123 456". */
  code: string;
}

export function ephemeralKey(): ECDH {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return ecdh;
}

export function sessionKeys(ecdh: ECDH, peerEphemeral: Uint8Array, th: Buffer): SessionKeys {
  let shared: Buffer;
  try {
    shared = ecdh.computeSecret(Buffer.from(peerEphemeral));
  } catch {
    fail("bad ephemeral key");
  }
  const okm = Buffer.from(hkdfSync("sha256", shared, th, Buffer.from(LABEL.keys), 96));
  shared.fill(0);
  return { sr: okm.subarray(0, 32), rs: okm.subarray(32, 64), lan: okm.subarray(64, 96), code: verificationCode(th) };
}

export function verificationCode(th: Uint8Array): string {
  const value = createHmac("sha256", th).update(LABEL.code).digest().readUInt32BE(0) % 1_000_000;
  const digits = String(value).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

export function lanProof(key: Buffer, side: "dialer" | "listener"): Buffer {
  return createHmac("sha256", key).update(side === "dialer" ? LABEL.lanDialer : LABEL.lanListener).digest();
}

export function lanDialerFrame(transfer: Buffer, key: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x20]), transfer, lanProof(key, "dialer")]);
}

export function lanListenerFrame(key: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x21]), lanProof(key, "listener")]);
}

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

// Records --------------------------------------------------------------------------------

function nonceFor(seq: bigint): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(seq, 4);
  return nonce;
}

function headerFor(seq: bigint): Buffer {
  const header = Buffer.alloc(9);
  header[0] = 0x10;
  header.writeBigUInt64BE(seq, 1);
  return header;
}

/** One direction of a session: counters start at 0 and grow by one. */
export class RecordSealer {
  private seq = 0n;
  constructor(private readonly key: Buffer) {}

  seal(plaintext: Buffer): Buffer {
    const seq = this.seq++;
    const header = headerFor(seq);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonceFor(seq));
    cipher.setAAD(header);
    return Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  }
}

export class RecordOpener {
  private seq = 0n;
  constructor(private readonly key: Buffer) {}

  open(record: Buffer): Buffer {
    if (record.length < 9 + 16 + 1 || record[0] !== 0x10) fail("not a record");
    const seq = record.readBigUInt64BE(1);
    if (seq !== this.seq) fail("record out of order");
    const decipher = createDecipheriv("aes-256-gcm", this.key, nonceFor(seq));
    decipher.setAAD(record.subarray(0, 9));
    decipher.setAuthTag(record.subarray(record.length - 16));
    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([decipher.update(record.subarray(9, record.length - 16)), decipher.final()]);
    } catch {
      fail("record does not authenticate");
    }
    this.seq++;
    return plaintext;
  }
}

// Plaintext ------------------------------------------------------------------------------

export interface ManifestFile {
  name: string;
  size: number;
}

export const FAILURES = ["source_changed", "integrity", "storage_full", "storage_error", "source_unreadable", "protocol", "key_rejected"] as const;
export type FailReason = (typeof FAILURES)[number];

export type Control =
  | { t: "manifest"; files: ManifestFile[]; total: number }
  | { t: "accept"; offsets: number[]; prefix: Array<string | null> }
  | { t: "decline" }
  | { t: "ack"; file: number; offset: number }
  | { t: "end"; file: number; sha256: string }
  | { t: "file_ok"; file: number }
  | { t: "done" }
  | { t: "pause" }
  | { t: "cancel" }
  | { t: "fail"; reason: FailReason }
  | { t: "lan"; addrs: string[]; port: number }
  | { t: "lan_on" }
  | { t: "lan_ok" };

export interface DataChunk {
  file: number;
  offset: number;
  bytes: Buffer;
}

export type Plaintext = { kind: "control"; control: Control } | { kind: "data"; data: DataChunk } | { kind: "unknown" };

export function encodeControl(control: Control): Buffer {
  return Buffer.concat([Buffer.from([0x01]), Buffer.from(JSON.stringify(control), "utf8")]);
}

export function encodeData(file: number, offset: number, bytes: Buffer): Buffer {
  if (bytes.length < 1 || bytes.length > MAX_CHUNK) fail("bad chunk");
  const head = Buffer.alloc(11);
  head[0] = 0x02;
  head.writeUInt16BE(file, 1);
  head.writeBigUInt64BE(BigInt(offset), 3);
  return Buffer.concat([head, bytes]);
}

export function decodePlaintext(plaintext: Buffer): Plaintext {
  if (plaintext[0] === 0x02) {
    if (plaintext.length < 12 || plaintext.length > 11 + MAX_CHUNK) fail("bad data record");
    const offset = plaintext.readBigUInt64BE(3);
    if (offset > BigInt(MAX_TOTAL)) fail("bad offset");
    return { kind: "data", data: { file: plaintext.readUInt16BE(1), offset: Number(offset), bytes: plaintext.subarray(11) } };
  }
  if (plaintext[0] !== 0x01) return { kind: "unknown" };
  if (plaintext.length > 64 * 1024) fail("control too long");
  let value: unknown;
  try {
    value = JSON.parse(plaintext.subarray(1).toString("utf8"));
  } catch {
    fail("bad control");
  }
  const control = parseControl(value);
  return control ? { kind: "control", control } : { kind: "unknown" };
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function count(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

const HEX = /^[0-9a-f]{64}$/;

export function isPrivateIpv4(address: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  if (parts.some((part) => part > 255) || match.slice(1).some((part) => part.length > 1 && part.startsWith("0"))) return false;
  const [a = 0, b = 0] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** A control the peer sent, checked field by field; null for a type this version does not know. */
export function parseControl(value: unknown): Control | null {
  if (!record(value) || typeof value.t !== "string") fail("bad control");
  switch (value.t) {
    case "manifest": {
      const files = value.files;
      if (!Array.isArray(files) || files.length < 1 || files.length > MAX_FILES) fail("bad manifest");
      const parsed = files.map((file): ManifestFile => {
        if (!record(file) || typeof file.name !== "string" || file.name.length < 1 || file.name.length > 1024 || !count(file.size, MAX_TOTAL)) fail("bad manifest");
        return { name: file.name, size: file.size };
      });
      const total = parsed.reduce((sum, file) => sum + file.size, 0);
      if (value.total !== total || total > MAX_TOTAL) fail("bad manifest");
      return { t: "manifest", files: parsed, total };
    }
    case "accept": {
      const { offsets, prefix } = value;
      if (!Array.isArray(offsets) || !Array.isArray(prefix) || offsets.length !== prefix.length || offsets.length > MAX_FILES) fail("bad accept");
      if (!offsets.every((offset) => count(offset, MAX_TOTAL))) fail("bad accept");
      if (!prefix.every((item) => item === null || (typeof item === "string" && HEX.test(item)))) fail("bad accept");
      return { t: "accept", offsets: offsets as number[], prefix: prefix as Array<string | null> };
    }
    case "ack":
      if (!count(value.file, MAX_FILES - 1) || !count(value.offset, MAX_TOTAL)) fail("bad ack");
      return { t: "ack", file: value.file, offset: value.offset };
    case "end":
      if (!count(value.file, MAX_FILES - 1) || typeof value.sha256 !== "string" || !HEX.test(value.sha256)) fail("bad end");
      return { t: "end", file: value.file, sha256: value.sha256 };
    case "file_ok":
      if (!count(value.file, MAX_FILES - 1)) fail("bad file_ok");
      return { t: "file_ok", file: value.file };
    case "fail": {
      const reason = FAILURES.find((item) => item === value.reason) ?? "protocol";
      return { t: "fail", reason };
    }
    case "lan": {
      const { addrs, port } = value;
      if (!Array.isArray(addrs) || addrs.length < 1 || addrs.length > 8 || !count(port, 65_535) || port < 1) fail("bad lan");
      if (!addrs.every((address) => typeof address === "string" && isPrivateIpv4(address))) fail("bad lan");
      return { t: "lan", addrs: addrs as string[], port };
    }
    case "decline":
    case "done":
    case "pause":
    case "cancel":
    case "lan_on":
    case "lan_ok":
      return { t: value.t };
    default:
      return null;
  }
}
