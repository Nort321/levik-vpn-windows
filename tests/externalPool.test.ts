import { describe, expect, it } from "vitest";
import { externalAutoServer, findExternalServer, parseExternalPool, retainExternalPool, type ExternalPool } from "../src/main/vpn/externalPool";
import type { TunnelServer } from "../src/shared/contracts";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";

function server(index: number, address = "8.8.8.8") {
  const fingerprint = index.toString(16).padStart(64, "0");
  const tag = "external-node-" + fingerprint;
  return { id: "external:" + fingerprint, tag, outbound: { tag, protocol: "trojan", settings: { servers: [{ address, port: 443, password: "fixture" }] } } };
}
function pool(servers: unknown[] = [server(1)]) { return { version: 1, sequence: "1", updatedAt: new Date().toISOString(), servers }; }

describe("external route selection", () => {
  it("searches beyond 32 and bounds concurrent verification", async () => {
    let active = 0, maximum = 0;
    const progress: number[] = [];
    const winner = await findExternalServer({ servers: Array.from({ length: 326 }, (_, i) => i), signal: new AbortController().signal,
      progress: (value) => progress.push(value.checked), verify: async (candidate) => {
        active++; maximum = Math.max(maximum, active);
        await new Promise((resolve) => setTimeout(resolve, 0)); active--;
        return candidate === 300;
      },
    });
    expect(winner).toBe(300); expect(maximum).toBe(4); expect(active).toBe(0);
    expect(progress.at(-1)).toBeGreaterThan(300);
    expect(progress).toEqual([...progress].sort((a, b) => a - b));
  });
  it("cancels all outstanding transfers and never selects a stale winner", async () => {
    const abort = new AbortController(); let closed = 0;
    const task = findExternalServer({ servers: [1, 2, 3, 4, 5], signal: abort.signal, progress: () => {},
      verify: async (_, signal) => new Promise<boolean>((resolve) => signal.addEventListener("abort", () => { closed++; resolve(true); }, { once: true })),
    });
    abort.abort(); await expect(task).rejects.toThrow(); expect(closed).toBe(4);
  });
  it("exhausts a failed list and isolates candidate exceptions", async () => {
    const seen: number[] = [];
    expect(await findExternalServer({ servers: [1, 2, 3, 4, 5], signal: new AbortController().signal, progress: () => {},
      verify: async (candidate) => { seen.push(candidate); throw new Error("refused"); },
    })).toBeNull();
    expect(seen.sort()).toEqual([1, 2, 3, 4, 5]);
  });
  it("keeps the complete catalog separate from the visible blackhole placeholder", () => {
    expect(parseExternalPool(pool(Array.from({ length: 326 }, (_, index) => server(index))))?.servers).toHaveLength(326);
    expect(externalAutoServer().outbound.protocol).toBe("blackhole");
    expect(parseExternalPool(undefined)).toBeUndefined();
  });
  it("shows one pool choice when the ordinary feed has only its traffic-limit notice", () => {
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "pool-profile", subscriptionId: "one",
      issuedAt: new Date().toISOString(), source: { mediaType: "text/plain",
        content: "vless://11111111-1111-4111-8111-111111111111@0.0.0.0:1#Traffic%20used" }, externalPool: pool(),
    })), "one");
    expect(prepared.servers.map((server) => server.id)).toEqual([externalAutoServer().id]);
    expect(prepared.externalPool?.servers).toHaveLength(1);
  });
  it("keeps the saved catalog on failed refresh without carrying it into another subscription or Game-only", () => {
    const previous = { subscriptionId: "one", externalPool: parseExternalPool(pool())! };
    const refreshed: { subscriptionId: string; servers: TunnelServer[]; externalPool?: ExternalPool; gameOnly?: boolean } = { subscriptionId: "one", servers: [] };
    retainExternalPool(refreshed, previous);
    expect(refreshed.externalPool).toBe(previous.externalPool);
    expect(refreshed.servers.map((server) => server.id)).toEqual([externalAutoServer().id]);
    for (const incoming of [{ subscriptionId: "two", servers: [] }, { subscriptionId: "one", servers: [], gameOnly: true }]) {
      retainExternalPool(incoming, previous); expect(incoming).not.toHaveProperty("externalPool");
    }
  });
  it("rejects LAN/rebound names, arbitrary dialers and insecure TLS", () => {
    for (const address of ["127.0.0.1", "10.0.0.1", "100.64.0.1", "192.168.1.1", "localhost", "evil.example", "::1", "2::1", "3::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
      expect(parseExternalPool(pool([server(1, address)]))?.servers, address).toHaveLength(0);
    }
    for (const address of ["2001:4860:4860::8888", "2606:4700:4700::1111", "198.51.101.8"]) {
      expect(parseExternalPool(pool([server(1, address)]))?.servers, address).toHaveLength(1);
    }
    const injected = server(1);
    expect(parseExternalPool(pool([{ ...injected, outbound: { ...injected.outbound, streamSettings: { sockopt: { dialerProxy: "direct" } } } }]))?.servers).toHaveLength(0);
    expect(() => parseExternalPool({ ...pool(), servers: new Array(10001).fill(server(1)) })).toThrow();
  });
});
