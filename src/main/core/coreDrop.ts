import { dropSourceWithCore, type OpenDropSource } from "./nativeDropSource";
import { dropAgreementWithCore, type OpenDropAgreement } from "./nativeDropAgreement";
import { dropRecordsWithCore, type OpenDropRecords } from "./nativeDropRecords";
import {
  ProtocolError,
  commitment,
  decodePlaintext,
  decodeReceiverHello,
  decodeReceiverProof,
  decodeSenderHello,
  decodeSenderProof,
  transcript,
  verifyTranscript,
} from "../platform/levikDrop/protocol";
import type { ReceiverHello, SenderHello } from "../platform/levikDrop/protocol";
import type { DropProtocol } from "../platform/levikDrop/session";
import {
  isBoolean,
  isControlPlaintext,
  isDropOutcome,
  isHashHex,
  isWireReceiverHello,
  isWireReceiverProof,
  isWireSenderHello,
  isWireSenderProof,
  type DropOutcome,
  type WireReceiverHello,
  type WireSenderHello,
} from "./coreGuards";
import type { RustCore } from "./rustCore";

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const fromHex = (text: string): Buffer => Buffer.from(text, "hex");

const wireSender = (hello: SenderHello): WireSenderHello => ({
  transfer: hex(hello.transfer), identity: hex(hello.identity), ephemeral: hex(hello.ephemeral), commit: hex(hello.commit),
});
const wireReceiver = (hello: ReceiverHello): WireReceiverHello => ({
  transfer: hex(hello.transfer), identity: hex(hello.identity), ephemeral: hex(hello.ephemeral), nonce: hex(hello.nonce),
});

/** The value, or the text of the ProtocolError; other errors are bugs and still throw. */
function attempt<T>(run: () => T): DropOutcome<T> {
  try {
    return { ok: run() };
  } catch (error) {
    if (error instanceof ProtocolError) return { error: error.message };
    throw error;
  }
}

function settle<T>(outcome: DropOutcome<T>): T {
  if ("error" in outcome) throw new ProtocolError(outcome.error);
  return outcome.ok;
}

/** One protocol call through the core: refusals compare by their text and stay ProtocolErrors. */
function decide<T>(core: RustCore, name: string, input: unknown, typescript: () => T, accept: (value: unknown) => value is T): T {
  return settle(core.run(name, input, () => attempt(typescript), isDropOutcome(accept)));
}

/**
 * LevikDrop's reading of the peer's bytes through the Rust core
 * (docs/rust-desktop-migration-plan.md, wave A): the handshake messages, the
 * commitment, the transcript and its signature, and control messages. File
 * data parsing stays in TypeScript; optional typed handles own P-256 agreement
 * and AES-GCM state. Ephemeral private bytes never cross the bridge. `current` is read on every
 * call because the app loads the module after the engine exists.
 */
export function dropProtocolWithCore(current: () => RustCore, records: () => OpenDropRecords | undefined = () => undefined,
  report: () => void = () => {}, agreement: () => OpenDropAgreement | undefined = () => undefined, source: () => OpenDropSource | undefined = () => undefined): DropProtocol {
  const ready = (name: string): RustCore | null => {
    const core = current();
    return core.mode === "ts" || !core.has(name) ? null : core;
  };
  const handshake = <Wire, Output>(kind: string, data: Buffer, typescript: (data: Buffer) => Output, toWire: (value: Output) => Wire,
    fromWire: (wire: Wire) => Output, accept: (value: unknown) => value is Wire): Output => {
    const core = ready("levikDrop.decodeHandshake");
    if (!core) return typescript(data);
    return fromWire(decide(core, "levikDrop.decodeHandshake", { kind, message: hex(data) }, () => toWire(typescript(data)), accept));
  };

  return {
    createSource: (file, offset, prefix) => dropSourceWithCore(current(), source(), file, offset, prefix, report),
    createAgreement: (identity) => dropAgreementWithCore(current(), agreement(), identity, report),
    createRecords: (role, keys) => dropRecordsWithCore(current(), records(), keys, role, report),
    decodeSenderHello: (data) => handshake("senderHello", data, decodeSenderHello, wireSender,
      (wire): SenderHello => ({ transfer: fromHex(wire.transfer), identity: fromHex(wire.identity), ephemeral: fromHex(wire.ephemeral), commit: fromHex(wire.commit) }),
      isWireSenderHello),
    decodeReceiverHello: (data) => handshake("receiverHello", data, decodeReceiverHello, wireReceiver,
      (wire): ReceiverHello => ({ transfer: fromHex(wire.transfer), identity: fromHex(wire.identity), ephemeral: fromHex(wire.ephemeral), nonce: fromHex(wire.nonce) }),
      isWireReceiverHello),
    decodeSenderProof: (data) => handshake("senderProof", data, decodeSenderProof,
      (proof) => ({ nonce: hex(proof.nonce), signature: hex(proof.signature) }),
      (wire) => ({ nonce: fromHex(wire.nonce), signature: fromHex(wire.signature) }),
      isWireSenderProof),
    decodeReceiverProof: (data) => handshake("receiverProof", data, decodeReceiverProof,
      (signature) => ({ signature: hex(signature) }), (wire) => fromHex(wire.signature), isWireReceiverProof),

    commitment: (identity, ephemeral, nonce) => {
      const core = ready("levikDrop.commitment");
      if (!core) return commitment(identity, ephemeral, nonce);
      return fromHex(decide(core, "levikDrop.commitment", { identity: hex(identity), ephemeral: hex(ephemeral), nonce: hex(nonce) },
        () => hex(commitment(identity, ephemeral, nonce)), isHashHex));
    },
    transcript: (sender, receiver, senderNonce) => {
      const core = ready("levikDrop.transcript");
      if (!core) return transcript(sender, receiver, senderNonce);
      return fromHex(decide(core, "levikDrop.transcript", { sender: wireSender(sender), receiver: wireReceiver(receiver), nonce: hex(senderNonce) },
        () => hex(transcript(sender, receiver, senderNonce)), isHashHex));
    },
    verifyTranscript: (role, identity, th, signature) => {
      const core = ready("levikDrop.verifyTranscript");
      if (!core) return verifyTranscript(role, identity, th, signature);
      return core.run("levikDrop.verifyTranscript", { role, identity: hex(identity), th: hex(th), signature: hex(signature) },
        () => verifyTranscript(role, identity, th, signature), isBoolean);
    },
    decodePlaintext: (plaintext) => {
      const core = ready("levikDrop.decodePlaintext");
      // File data stays in TypeScript: most of the bytes, and nothing in them to parse.
      if (!core || plaintext[0] !== 0x01) return decodePlaintext(plaintext);
      return decide(core, "levikDrop.decodePlaintext", { plaintext: hex(plaintext) }, () => decodePlaintext(plaintext), isControlPlaintext);
    },
  };
}
