import { createHash, constants, publicEncrypt, verify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";
import { RequestSigner } from "../src/main/security/requestSigner";
import { MobileApiClient, isAuthenticationRejected } from "../src/main/api/mobileApiClient";
import { RustCore, type CoreMode } from "../src/main/core/rustCore";
import { isNativeIdentity, type NativeIdentity } from "../src/main/core/nativeIdentity";
import { loadLevikCore } from "../src/main/core/levikCore";

const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

function fake(node: DeviceIdentity, overrides: Partial<NativeIdentity> = {}): NativeIdentity {
  return {
    deviceId: () => node.deviceId(),
    publicKeySpkiBase64Url: () => node.publicKeySpkiBase64Url(),
    sign: (payload) => node.sign(payload),
    signRequestAt: (method, path, token, body, timestamp, nonce) => {
      const deviceId = node.deviceId();
      const canonical = ["v1", method, path, timestamp, nonce, deviceId, hash(token), hash(body)].join("\n");
      return JSON.stringify({ deviceId, timestamp, nonce, signature: node.sign(Buffer.from(canonical)),
        requestHash: createHash("sha256").update(canonical).digest("base64url") });
    },
    decryptProfileKey: (algorithm, key) => node.decryptProfileKey(algorithm, key),
    decryptProfile: () => { throw new Error("not used"); },
    apiRequest: async () => JSON.stringify({ ok: true, value: { ok: true } }),
    ...overrides,
  };
}

function configured(mode: CoreMode, overrides: Partial<NativeIdentity> = {}) {
  const node = DeviceIdentity.create();
  const identity = DeviceIdentity.restore(node.serialize());
  const lines: string[] = [];
  const core = new RustCore(null, (line) => lines.push(line), mode);
  const native = fake(node, overrides);
  identity.useRustCore(core, () => native);
  return { identity, node, native, core, lines };
}

afterEach(() => vi.unstubAllGlobals());

describe("typed Rust device identity", () => {
  it("compares signatures on the same timestamp and nonce", () => {
    const { identity, node, core } = configured("shadow");
    const signed = new RequestSigner(identity).sign("POST", "/api/mobile/v1/account", "token", Buffer.from("{}"));
    const canonical = ["v1", "POST", "/api/mobile/v1/account", signed.timestamp, signed.nonce, node.deviceId(), hash("token"), hash("{}")].join("\n");
    expect(verify("RSA-SHA256", Buffer.from(canonical), node.serialize().publicKeyPem, Buffer.from(signed.signature, "base64url"))).toBe(true);
    expect(core.stats().compared).toBeGreaterThan(0);
    expect(core.stats().failed).toBe(0);
    expect(core.stats().differed).toBe(0);
  });

  it("restores lazily when the remote mode changes from ts to rust", () => {
    const { identity, core, native } = configured("ts");
    const sign = vi.spyOn(native, "sign");
    identity.sign(Buffer.from("first"));
    expect(sign).not.toHaveBeenCalled();
    core.setMode("rust");
    identity.sign(Buffer.from("second"));
    expect(sign).toHaveBeenCalledOnce();
    core.setMode("ts");
    identity.sign(Buffer.from("third"));
    expect(sign).toHaveBeenCalledOnce();
  });

  it("keeps the existing identity if native restore rejects it", () => {
    const { identity, node, core, lines } = configured("rust");
    identity.useRustCore(core, () => { throw new Error("PRIVATE KEY must never be logged"); });
    const payload = Buffer.from("payload");
    expect(identity.sign(payload)).toBe(node.sign(payload));
    expect(identity.deviceId()).toBe(node.deviceId());
    expect(core.stats().failed).toBe(1);
    expect(lines.join("\n")).not.toContain("PRIVATE KEY");
  });

  it("rejects a handle for a different device before using it", () => {
    const { identity, node, core } = configured("rust", { deviceId: () => "0".repeat(64) });
    expect(identity.sign(Buffer.from("payload"))).toBe(node.sign(Buffer.from("payload")));
    expect(core.stats().failed).toBe(1);
  });

  it("falls back on malformed pure crypto output without revealing values", () => {
    const { identity, node, core, lines } = configured("rust", { signRequestAt: () => '{"secret":"private"}' });
    const signed = new RequestSigner(identity).sign("GET", "/api/mobile/v1/account", null, Buffer.alloc(0));
    expect(signed.deviceId).toBe(node.deviceId());
    expect(core.stats().failed).toBe(1);
    expect(lines.join("\n")).not.toContain("private");
  });

  it("decrypts the same profile key in shadow and rust modes", () => {
    for (const mode of ["shadow", "rust"] as const) {
      const { identity, node, core } = configured(mode);
      const key = Buffer.alloc(32, 7);
      const encrypted = publicEncrypt({ key: node.serialize().publicKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, key);
      expect(identity.decryptProfileKey("RSA-OAEP+A256GCM", encrypted.toString("base64url"))).toEqual(key);
      expect(core.stats().differed).toBe(0);
      expect(core.stats().failed).toBe(0);
    }
  });
});

describe("native API delivery", () => {
  it("does not send a shadow request", async () => {
    const request = vi.fn(async () => JSON.stringify({ ok: true, value: { ok: true } }));
    const { identity } = configured("shadow", { apiRequest: request });
    const fetch = vi.fn(async () => new Response('{"ok":true}', { headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetch);
    await new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0").account("token");
    expect(request).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each(["reject", "throw", "malformed"])("never replays a possibly completed native POST: %s", async (failure) => {
    const request = vi.fn((_input: string): Promise<string> => {
      if (failure === "throw") throw new Error("ambiguous send");
      if (failure === "reject") return Promise.reject(new Error("response lost"));
      return Promise.resolve("not JSON");
    });
    const { identity } = configured("rust", { apiRequest: request });
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0")
      .authorizeActivation("token", "ABCD-EFGH-JKMN-PQRS")).rejects.toThrow("Не удалось связаться");
    expect(request).toHaveBeenCalledOnce();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("preserves a definitive authentication rejection and extra profile headers", async () => {
    const request = vi.fn(async (_input: string) => JSON.stringify({ ok: false, error: { message: "Сессия истекла. Войдите снова.",
      status: 401, authenticationRejected: true, code: "unauthorized", invalidateEndpoint: false } }));
    const { identity } = configured("rust", { apiRequest: request });
    const client = new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0");
    const error: unknown = await client.tunnelProfile("token", "subscription").catch((caught: unknown) => caught);
    expect(isAuthenticationRejected(error)).toBe(true);
    const input: unknown = JSON.parse(request.mock.calls[0]?.[0] ?? "null");
    expect(input).toMatchObject({ road: true, body: '{"subscriptionId":"subscription"}' });
  });
});

describe("Rust event transport selection", () => {
  it("uses only the Rust stream in rust mode", async () => {
    const nativeStream = { read: vi.fn().mockResolvedValueOnce(JSON.stringify({ ok: true, value: { events: ["ready"], done: false } }))
      .mockResolvedValue(JSON.stringify({ ok: true, value: { events: [], done: true } })), close: vi.fn() };
    const openEventStream = vi.fn((_input: string) => nativeStream);
    const { identity } = configured("rust", { openEventStream });
    const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
    const client = new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0");
    const stream = await client.openEvents("token", new AbortController().signal);
    const reader = stream.getReader();
    expect((await reader.read()).value).toEqual(["ready"]);
    await reader.cancel();
    expect(openEventStream).toHaveBeenCalledOnce();
    expect(JSON.parse(openEventStream.mock.calls[0]?.[0] ?? "null")).toMatchObject({ method: "GET", path: "/api/mobile/v1/events", accessToken: "token" });
    expect(fetch).not.toHaveBeenCalled();
    expect(nativeStream.close).toHaveBeenCalledOnce();
  });

  it("opens only one Node stream in shadow mode", async () => {
    const openEventStream = vi.fn();
    const { identity } = configured("shadow", { openEventStream });
    const fetch = vi.fn().mockResolvedValue(new Response("event: ready\n\n", { headers: { "Content-Type": "text/event-stream" } }));
    vi.stubGlobal("fetch", fetch);
    const stream = await new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0")
      .openEvents("token", new AbortController().signal);
    await stream.cancel();
    expect(fetch).toHaveBeenCalledOnce();
    expect(openEventStream).not.toHaveBeenCalled();
  });

  it("does not try Node after native stream creation fails", async () => {
    const { identity } = configured("rust", { openEventStream: () => { throw new Error("private token"); } });
    const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
    await expect(new MobileApiClient("https://custom.example", new RequestSigner(identity), "1.0.0")
      .openEvents("token", new AbortController().signal)).rejects.toThrow("Канал событий недоступен");
    expect(fetch).not.toHaveBeenCalled();
  });
});

const modulePath = process.env.LEVIK_TEST_CORE;
describe.skipIf(!modulePath)("real Rust module", () => {
  it("passes the typed handle through the verified loader and matches Node crypto", () => {
    if (!modulePath) throw new Error("LEVIK_TEST_CORE missing");
    const status = loadLevikCore(modulePath);
    if (status.state !== "loaded" || !status.module.restoreIdentity) throw new Error("wave-B module not loaded");
    const node = DeviceIdentity.create();
    const native = status.module.restoreIdentity(JSON.stringify(node.serialize()));
    expect(isNativeIdentity(native)).toBe(true);
    expect(native.deviceId()).toBe(node.deviceId());
    expect(native.sign(Buffer.from("real native signature"))).toBe(node.sign(Buffer.from("real native signature")));
    const identity = DeviceIdentity.restore(node.serialize());
    const core = new RustCore(null, () => {}, "shadow");
    identity.useRustCore(core, status.module.restoreIdentity);
    new RequestSigner(identity).sign("PUT", "/api/mobile/v1/settings", "token", Buffer.from('{"changes":{}}'));
    expect(core.stats().failed).toBe(0);
    expect(core.stats().differed).toBe(0);
    expect(core.stats().compared).toBeGreaterThan(0);
  });
});
