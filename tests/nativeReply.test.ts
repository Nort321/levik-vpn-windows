import { constants, createPublicKey, generateKeyPairSync, privateDecrypt, publicEncrypt } from "node:crypto";
import { describe, expect, it } from "vitest";
import { loadLevikCore } from "../src/main/core/levikCore";
import { createReplyKey, openReply, sealForReply } from "../src/main/platform/remoteCommands";
import type { NativeReplyCrypto } from "../src/main/core/nativeReply";

const NOTE = "https://note.leviknet.org/test-note#test-key";

describe("reply crypto fallback", () => {
  it("can start with Node if the native generator fails before a request is sent", () => {
    const crypto: NativeReplyCrypto = { createKey: () => { throw new Error("unavailable"); }, seal: () => { throw new Error("unavailable"); } };
    const key = createReplyKey(crypto);
    expect(openReply(key.privateKey, sealForReply(key.replyKey, NOTE, crypto))).toBe(NOTE);
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
const status = modulePath ? loadLevikCore(modulePath) : null;
const crypto = status?.state === "loaded" ? status.module.replyCrypto : undefined;
describe.skipIf(!crypto)("native one-off diagnostics keys", () => {
  it("decrypts Node RSA-OAEP SHA-256 and keeps existing keys usable after a mode change", () => {
    if (!crypto) throw new Error("reply crypto missing");
    const key = createReplyKey(crypto);
    const publicKey = createPublicKey({ key: Buffer.from(key.replyKey, "base64"), format: "der", type: "spki" });
    const sealed = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(NOTE)).toString("base64");
    // No current Rust-mode argument: the key owner finishes an in-flight reply.
    expect(openReply(key.privateKey, sealed)).toBe(NOTE);
    expect(openReply(createReplyKey(crypto).privateKey, sealed)).toBeNull();
  });

  it("encrypts to a Node key without changing the remote protocol", () => {
    if (!crypto) throw new Error("reply crypto missing");
    const node = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const key = node.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const sealed = sealForReply(key, NOTE, crypto);
    expect(privateDecrypt({ key: node.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(sealed, "base64")).toString()).toBe(NOTE);
  });

  it("refuses notes outside the approved origins and damaged ciphertext", () => {
    if (!crypto) throw new Error("reply crypto missing");
    const key = createReplyKey(crypto);
    expect(openReply(key.privateKey, sealForReply(key.replyKey, "https://evil.example/a#b", crypto))).toBeNull();
    expect(openReply(key.privateKey, "broken ciphertext")).toBeNull();
  });
});
