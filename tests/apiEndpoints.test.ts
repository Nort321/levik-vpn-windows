import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiEndpoints, DEFAULT_API_ORIGIN } from "../src/main/api/apiEndpoints";
import { MobileApiClient } from "../src/main/api/mobileApiClient";
import { DeviceIdentity } from "../src/main/security/deviceIdentity";
import { RequestSigner } from "../src/main/security/requestSigner";

afterEach(() => vi.unstubAllGlobals());

const healthy = () => new Response('{"ok":true}', {
  headers: { "Content-Type": "application/json" },
});

describe("trusted API endpoint discovery", () => {
  it("uses an unauthenticated health check to select the available new domain", async () => {
    const fetchMock = vi.fn(async (url: URL, init?: RequestInit) => {
      expect(init?.credentials).toBe("omit");
      expect(init?.redirect).toBe("error");
      expect(init?.headers).toEqual({ Accept: "application/json" });
      if (url.hostname === "api.leviknet.org") throw new TypeError("blocked");
      return healthy();
    });
    vi.stubGlobal("fetch", fetchMock);
    const endpoints = new ApiEndpoints(DEFAULT_API_ORIGIN);
    expect((await endpoints.resolve()).origin).toBe("https://leviknet.org");
    await endpoints.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("retains the legacy API as the last trusted fallback", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: URL) => {
      if (url.hostname.endsWith(".org")) throw new TypeError("blocked");
      return healthy();
    }));
    expect((await new ApiEndpoints(DEFAULT_API_ORIGIN).resolve()).origin).toBe("https://leviknet.com");
  });

  it("does not discover production origins for an explicit override", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect((await new ApiEndpoints("https://custom.example").resolve()).origin).toBe("https://custom.example");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["http://leviknet.org", "https://user@leviknet.org", "https://leviknet.org/?token=x", "https://leviknet.org/#fragment"])("rejects an unsafe origin %s", (origin) => {
    expect(() => new ApiEndpoints(origin)).toThrow();
  });

  it("never replays a POST after an ambiguous network failure", async () => {
    const fetchMock = vi.fn(async (_url: URL, init?: RequestInit) => {
      if (init?.method === "GET") return healthy();
      throw new TypeError("response lost after sending");
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new MobileApiClient(DEFAULT_API_ORIGIN, new RequestSigner(DeviceIdentity.create()), "1.0.0");
    await expect(client.authorizeActivation("token", "ABCD-EFGH-JKMN-PQRS")).rejects.toThrow();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
  });
});
