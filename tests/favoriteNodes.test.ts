import { describe, expect, it } from "vitest";
import type { TunnelServer } from "../src/shared/contracts";
import {
  canonicalNodeList,
  isCanonicalNodeList,
  nodeIdForEndpoint,
  nodeIdForHost,
  nodeIdForServer,
  nodeLoadForServer,
  parseNodeList,
  reconcileFavorites,
  serversByNode,
  unionNodeLists,
} from "../src/main/platform/favoriteNodes";
import { syncedChanges } from "../src/main/platform/settingsSync";

const fi = "n1142bf5571df2373ffb23";
const de = "n15c40cf1f1842e4bd352a";

function server(id: string, address: string, protocol = "vless"): TunnelServer {
  return { id, tag: id, name: id, countryCode: "FI", outbound: { protocol, settings: { vnext: [{ address }] } } };
}

describe("favourite nodes", () => {
  it("names servers like the site and the Android app", () => {
    expect(nodeIdForHost("fi1.example.net")).toBe(fi);
    expect(nodeIdForHost(" FI1.Example.NET. ")).toBe(fi);
    expect(nodeIdForHost("203.0.113.7")).toBe(de);
    expect(nodeIdForHost("[2001:db8::1]")).toBe("n121f47268350d79178ced");
    expect(nodeIdForHost("")).toBeNull();
    expect(nodeIdForServer(server("a", "127.0.0.1"))).toBeNull();
    expect(nodeIdForServer({ ...server("t", "x"), outbound: {}, tuic: { address: "fi1.example.net" } } as TunnelServer)).toBe(fi);
  });

  it("keeps lists sorted, distinct and bounded", () => {
    expect(canonicalNodeList([de, fi, de, "bad"])).toBe(`${fi},${de}`);
    expect(isCanonicalNodeList(`${de},${fi}`)).toBe(false);
    expect(isCanonicalNodeList("")).toBe(true);
    expect(unionNodeLists(fi, de)).toBe(`${fi},${de}`);
    const many = Array.from({ length: 50 }, (_, index) => `n1${index.toString(16).padStart(20, "0")}`);
    expect(parseNodeList(canonicalNodeList(many)).size).toBe(40);
  });

  it("turns a star here into an account edit and applies the account list elsewhere", () => {
    const byNode = serversByNode([server("fi-v", "fi1.example.net"), server("fi-h", "fi1.example.net", "hysteria2"), server("de-v", "203.0.113.7")]);
    const starred = reconcileFavorites({ nodes: new Set(), reconciledLocal: new Set() }, new Set(["fi-h"]), byNode);
    expect([...starred.nodes]).toEqual([fi]);
    const remote = reconcileFavorites({ nodes: new Set([de, "n1000000000000000000ff"]), reconciledLocal: starred.local }, starred.local, byNode);
    expect([...remote.local].sort()).toEqual(["de-v"]);
    expect(remote.nodes.has("n1000000000000000000ff")).toBe(true);
  });

  it("does not count the first list as an edit", () => {
    const base = { favoriteNodes: null } as unknown as Parameters<typeof syncedChanges>[0];
    expect(syncedChanges(base, { ...base, favoriteNodes: fi })).toEqual({});
    expect(syncedChanges({ ...base, favoriteNodes: "" }, { ...base, favoriteNodes: fi })).toEqual({ favoriteNodes: fi });
  });

  it("finds the load of one server behind a shared relay by its port", () => {
    const relayFr = nodeIdForEndpoint("2.27.42.184", 21443);
    expect(relayFr).toBe("n15f491927d4394acd315d");
    const relay = "n126c4033f0b74bc1be26a";
    expect(nodeIdForHost("2.27.42.184")).toBe(relay);
    const vless = { id: "fr", tag: "fr", name: "fr", countryCode: "FR", outbound: { protocol: "vless", settings: { vnext: [{ address: "2.27.42.184", port: 21443 }] } } } as TunnelServer;
    const flat = { ...vless, outbound: { protocol: "hysteria", settings: { address: "2.27.42.184", port: 21443 } } } as TunnelServer;
    const tuic = { ...vless, outbound: {}, tuic: { address: "2.27.42.184", port: 21444 } } as TunnelServer;
    const load = { [relayFr!]: 0.1, [nodeIdForEndpoint("2.27.42.184", 21444)!]: 0.1, [relay]: 0.28 };
    expect(nodeLoadForServer(load, vless)).toBe(0.1);
    expect(nodeLoadForServer(load, flat)).toBe(0.1);
    expect(nodeLoadForServer(load, tuic)).toBe(0.1);
    // Without a port entry the shared host's load still applies.
    expect(nodeLoadForServer({ [relay]: 0.28 }, vless)).toBe(0.28);
    expect(nodeLoadForServer({}, vless)).toBeNull();
    expect(nodeLoadForServer(load, server("de", "203.0.113.7"))).toBeNull();
  });
});
