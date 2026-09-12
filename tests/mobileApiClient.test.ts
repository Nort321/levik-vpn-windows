import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";
import { RequestSigner } from "../src/main/security/requestSigner";
import {
  isAuthenticationRejected,
  MobileApiClient,
} from "../src/main/api/mobileApiClient";

function client(): MobileApiClient {
  return new MobileApiClient(
    "https://leviknet.com",
    new RequestSigner(DeviceIdentity.create()),
    "1.2.3",
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("Mobile API authentication rejection", () => {
  it("authorizes an activation code with the current session", async () => {
    let capturedBody = "";
    const fetchMock = vi.fn(async (_url: URL, init?: RequestInit) => {
      capturedBody = Buffer.from(init?.body as Uint8Array).toString("utf8");
      return new Response(JSON.stringify({ ok: true, state: "authorized" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    await client().authorizeActivation("stored-token", "ABCD-EFGH-JKMN-PQRS");

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe("https://leviknet.com/api/mobile/v1/activation/authorize");
    expect(init?.method).toBe("POST");
    expect(init?.headers).toMatchObject({ Authorization: "Bearer stored-token" });
    expect(capturedBody).toBe('{"code":"ABCD-EFGH-JKMN-PQRS"}');
  });

  it("does not treat a malformed intermediary 401 response as a definitive logout", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("offline", {
      status: 401,
      headers: { "Content-Type": "text/html" },
    })));

    const error = await client().account("stored-token").catch((caught: unknown) => caught);

    expect(isAuthenticationRejected(error)).toBe(false);
  });

  it("recognizes a valid API unauthorized response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      ok: false,
      error: { code: "unauthorized" },
    }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    })));

    const error = await client().account("expired-token").catch((caught: unknown) => caught);

    expect(isAuthenticationRejected(error)).toBe(true);
  });
});
