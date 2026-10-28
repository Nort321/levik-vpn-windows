import { EventEmitter } from "node:events";
import { IncomingMessage, type RequestOptions } from "node:http";
import { Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const send = vi.hoisted(() => vi.fn());
vi.mock("node:https", () => ({ request: send }));
import { prepareMacProbeConfig } from "../src/main/vpn/routeProbeBootstrap";

type Reply = { body?: unknown; status?: number; contentLength?: string; hangBody?: boolean; connectFailure?: boolean };
let replies: Reply[];
const accepted = { Status: 0, Answer: [{ type: 1, data: "203.0.113.9" }] };

function profile(): Record<string, unknown> {
  return {
    dns: { servers: ["https://1.1.1.1/dns-query"], hosts: { "vpn.example": ["192.0.2.99"], "unrelated.example": "192.0.2.1" } },
    outbounds: [
      { tag: "vpn", protocol: "vless", settings: { vnext: [{ address: "vpn.example", port: 443 }] },
        streamSettings: { network: "tcp", sockopt: { domainStrategy: "AsIs", mark: 7 } } },
      { tag: "other", protocol: "trojan", settings: { servers: [{ address: "vpn.example", port: 443 }] } },
      { tag: "direct", protocol: "freedom", settings: { domainStrategy: "UseIP" } },
    ],
  };
}

beforeEach(() => {
  replies = [];
  send.mockReset();
  send.mockImplementation((_url: URL, _options: RequestOptions, callback: (reply: IncomingMessage) => void) => {
    let closed = false;
    const outgoing = Object.assign(new EventEmitter(), {
      destroy: vi.fn(() => { closed = true; }),
      end: () => queueMicrotask(() => {
        if (closed) return;
        const next = replies.shift() ?? { body: accepted };
        if (next.connectFailure) { outgoing.emit("error", new Error("Unavailable")); return; }
        const socket = new EventEmitter();
        outgoing.emit("socket", socket); socket.emit("secureConnect");
        const reply = new IncomingMessage(new Socket());
        reply.statusCode = next.status ?? 200;
        if (next.contentLength) reply.headers["content-length"] = next.contentLength;
        callback(reply);
        if (next.hangBody || reply.destroyed) return;
        const data = next.body === undefined ? accepted : next.body;
        reply.push(typeof data === "string" ? data : JSON.stringify(data));
        reply.push(null);
      }),
    });
    return outgoing;
  });
});

afterEach(() => vi.useRealTimers());

describe("macOS route probe bootstrap parity", () => {
  it("overwrites endpoint mappings with public DoH A-only answers and forces UseIP", async () => {
    const config = profile();
    replies.push({ body: { Status: 0, Answer: [
      { type: 5, data: "alias.example" }, { type: 28, data: "2001:db8::1" },
      { type: 1, data: "203.0.113.9" }, { type: 1, data: "203.0.113.9" }, { type: 1, data: "invalid" },
    ] } });
    expect(await prepareMacProbeConfig(config, new AbortController().signal)).toBe(config);
    expect(config).toMatchObject({ dns: { hosts: { "vpn.example": ["203.0.113.9"], "unrelated.example": "192.0.2.1" } }, outbounds: [
      { streamSettings: { network: "tcp", sockopt: { domainStrategy: "UseIP", mark: 7 } } },
      { streamSettings: { sockopt: { domainStrategy: "UseIP" } } },
      { protocol: "freedom", settings: { domainStrategy: "UseIP" } },
    ] });
    expect(send).toHaveBeenCalledTimes(1);
    const [url, options] = send.mock.calls[0] as [URL, RequestOptions];
    expect(url.hostname).toBe("1.1.1.1");
    expect(url.searchParams.get("name")).toBe("vpn.example");
    expect(url.searchParams.get("type")).toBe("A");
    expect(options).toMatchObject({ agent: false, headers: { Accept: "application/dns-json" } });
  });

  it("tries Google after malformed, failed-status, IPv6-only or oversized Cloudflare answers", async () => {
    for (const first of [
      { body: "not JSON" }, { body: { Status: 3, Answer: accepted.Answer } },
      { body: { Status: 0, Answer: [{ type: 28, data: "2001:db8::1" }] } },
      { body: { Status: 0, Answer: [{ type: 1, data: "2001:db8::1" }] } },
      { body: "x".repeat(65 * 1024) }, { status: 302 }, { connectFailure: true },
    ]) {
      send.mockClear(); replies = [first, { body: accepted }];
      await prepareMacProbeConfig(profile(), new AbortController().signal);
      expect(send).toHaveBeenCalledTimes(2);
      const [url] = send.mock.calls[1] as [URL];
      expect(`${url.origin}${url.pathname}`).toBe("https://8.8.8.8/resolve");
    }
  });

  it("keeps the config unchanged when both resolvers fail", async () => {
    const config = profile(), original = structuredClone(config);
    replies = [{ body: { Status: 2 } }, { body: { Status: 2 } }];
    await expect(prepareMacProbeConfig(config, new AbortController().signal)).rejects.toThrow("bootstrap unavailable");
    expect(config).toEqual(original);
  });

  it("does not resolve IP literals or unrelated settings keys", async () => {
    const config = { outbounds: [{ protocol: "vless", settings: { vnext: [{ address: "203.0.113.1" }], host: "transport.example" } }] };
    await prepareMacProbeConfig(config, new AbortController().signal);
    expect(send).not.toHaveBeenCalled();
    expect(config).toMatchObject({ outbounds: [{ streamSettings: { sockopt: { domainStrategy: "UseIP" } } }] });
  });

  it("rejects invalid endpoint names before making any request", async () => {
    const config = { outbounds: [{ protocol: "vless", settings: { address: "vpn.example?token=bad" } }] };
    await expect(prepareMacProbeConfig(config, new AbortController().signal)).rejects.toThrow("hostname");
    expect(send).not.toHaveBeenCalled();
  });

  it("cancels the request promptly without trying another resolver or changing config", async () => {
    const config = profile(), original = structuredClone(config), controller = new AbortController();
    replies = [{ hangBody: true }];
    const pending = prepareMacProbeConfig(config, controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow("cancelled");
    expect(send).toHaveBeenCalledTimes(1);
    expect(config).toEqual(original);
    await expect(prepareMacProbeConfig(config, controller.signal)).rejects.toThrow();
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("bounds a stalled response before falling back to the second resolver", async () => {
    vi.useFakeTimers();
    replies = [{ hangBody: true }, { body: accepted }];
    const pending = prepareMacProbeConfig(profile(), new AbortController().signal);
    await vi.advanceTimersByTimeAsync(5_000);
    await pending;
    expect(send).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });
});
