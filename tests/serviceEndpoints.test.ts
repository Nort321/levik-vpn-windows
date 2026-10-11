import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BUILT_IN_ENDPOINTS,
  fetchEndpointsDocument,
  serviceEndpoints,
  ServiceEndpointsStore,
  useEndpointsDocument,
  verifyEndpointsDocument,
  websiteHosts,
} from "../src/main/platform/serviceEndpoints";
import { cabinetFallbackUrl, isAllowedExternalUrl, isHandoffUrl } from "../src/main/platform/links";

const fixture = (name: string) => readFile(join(__dirname, "fixtures", name));
const testKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

function signed(document: Record<string, unknown>) {
  const body = Buffer.from(JSON.stringify(document));
  return { body, signature: sign("sha256", body, { key: testKeys.privateKey, dsaEncoding: "der" }).toString("base64") };
}

const valid = {
  schema: 1,
  sequence: 7,
  apiOrigins: ["https://api.reserve.example", "https://api.reserve.example", "http://plain.example", "https://x.example/path"],
  webOrigin: "https://site.example",
  configUrls: ["https://mirror.example/levik-config-v1.json", "https://mirror.example/other.txt"],
};

afterEach(() => {
  vi.unstubAllGlobals();
  useEndpointsDocument(null);
});

describe("signed service endpoints", () => {
  it("accepts the published document with the key built into the app", async () => {
    const document = verifyEndpointsDocument(await fixture("levik-config-v1.json"), (await fixture("levik-config-v1.json.sig")).toString());
    expect(document?.sequence).toBeGreaterThanOrEqual(1);
    expect(document?.apiOrigins[0]).toBe("https://api.cloudnote-sync.xyz");
  });

  it("rejects a document changed after signing", async () => {
    const body = Buffer.from((await fixture("levik-config-v1.json")).toString().replace("cloudnote-sync.xyz", "attacker.example"));
    expect(verifyEndpointsDocument(body, (await fixture("levik-config-v1.json.sig")).toString())).toBeNull();
  });

  it("keeps only clean HTTPS origins and JSON mirrors", () => {
    const { body, signature } = signed(valid);
    expect(verifyEndpointsDocument(body, signature, testKeys.publicKey)).toEqual({
      sequence: 7,
      apiOrigins: ["https://api.reserve.example"],
      webOrigin: "https://site.example",
      configUrls: ["https://mirror.example/levik-config-v1.json"],
    });
  });

  it.each([
    { ...valid, schema: 2 },
    { ...valid, sequence: 0 },
    { ...valid, apiOrigins: ["http://plain.example"] },
    { ...valid, webOrigin: "https://site.example/path" },
  ])("rejects an invalid document %#", (document) => {
    const { body, signature } = signed(document);
    expect(verifyEndpointsDocument(body, signature, testKeys.publicKey)).toBeNull();
  });

  it("puts the signed hosts before the built-in ones and follows the website", () => {
    useEndpointsDocument({ sequence: 3, apiOrigins: ["https://api.reserve.example"], webOrigin: "https://site.example", configUrls: [] });
    expect(serviceEndpoints().apiOrigins).toEqual(["https://api.reserve.example", ...BUILT_IN_ENDPOINTS.apiOrigins]);
    expect(serviceEndpoints().configUrls).toEqual([...BUILT_IN_ENDPOINTS.configUrls]);
    expect(cabinetFallbackUrl("/dashboard/plans")).toBe("https://site.example/dashboard/plans");
    expect(websiteHosts().has("leviknet.org")).toBe(true);
    expect(isAllowedExternalUrl("https://www.site.example/status")).toBe(true);
    expect(isAllowedExternalUrl("https://evil.example/")).toBe(false);
    expect(isHandoffUrl(`https://site.example/handoff?token=${"a".repeat(43)}`)).toBe(true);
  });

  it("skips broken mirrors and older documents", async () => {
    const body = await fixture("levik-config-v1.json");
    const signature = await fixture("levik-config-v1.json.sig");
    const fetchMock = vi.fn(async (url: string) => {
      if (url.startsWith("https://blocked.example")) throw new TypeError("blocked");
      if (url.startsWith("https://missing.example")) return new Response("", { status: 404 });
      return new Response(url.endsWith(".sig") ? signature : body);
    });
    const urls = ["https://blocked.example/a.json", "https://missing.example/a.json", "https://good.example/a.json"];
    expect((await fetchEndpointsDocument(urls, 1, fetchMock as typeof fetch))?.document.apiOrigins[0]).toBe("https://api.cloudnote-sync.xyz");
    expect(await fetchEndpointsDocument(urls, 1_000, fetchMock as typeof fetch)).toBeNull();
  });

  it("stores the signed bytes and verifies them again on load", async () => {
    const body = await fixture("levik-config-v1.json");
    const signature = await fixture("levik-config-v1.json.sig");
    const fetchMock = vi.fn(async (url: string) => new Response(url.endsWith(".sig") ? signature : body));
    const path = join(await mkdtemp(join(tmpdir(), "levik-endpoints-")), "service-endpoints.json");
    const store = new ServiceEndpointsStore(path, fetchMock as typeof fetch);
    expect(await store.refresh()).toBe(true);
    expect(await store.refresh()).toBe(false);

    useEndpointsDocument(null);
    await new ServiceEndpointsStore(path).load();
    expect(serviceEndpoints().sequence).toBeGreaterThanOrEqual(1);

    const stored = JSON.parse(await readFile(path, "utf8")) as { body: string; signature: string };
    const forged = Buffer.from(stored.body, "base64").toString().replace("cloudnote-sync.xyz", "attacker.example");
    await writeFile(path, JSON.stringify({ ...stored, body: Buffer.from(forged).toString("base64") }));
    useEndpointsDocument(null);
    await new ServiceEndpointsStore(path).load();
    expect(serviceEndpoints().sequence).toBe(0);
  });
});
