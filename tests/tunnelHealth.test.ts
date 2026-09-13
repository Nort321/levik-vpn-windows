import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:http", () => ({ request: vi.fn() }));
vi.mock("node:tls", () => ({ connect: vi.fn() }));

import { request } from "node:http";
import { connect } from "node:tls";
import { isTunnelHealthy } from "../src/main/vpn/tunnelHealth";

class FakeSocket extends EventEmitter {
  destroy = vi.fn();
}
class FakeRequest extends FakeSocket {
  end = vi.fn();
}

// These narrow test doubles model event ordering, not real network I/O.
const httpMock = vi.mocked(request);
const tlsMock = vi.mocked(connect);
let requests: FakeRequest[];
let tlsSockets: FakeSocket[];

function establishProxy(index = 0, statusCode = 200): FakeSocket {
  const socket = new FakeSocket();
  requests[index]!.emit("connect", { statusCode }, socket, Buffer.alloc(0));
  return socket;
}

describe("VPN end-to-end health probe", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    requests = [];
    tlsSockets = [];
    httpMock.mockReset().mockImplementation(() => {
      const req = new FakeRequest();
      requests.push(req);
      // Node's request type contains methods unrelated to these event tests.
      return req as unknown as ReturnType<typeof request>;
    });
    tlsMock.mockReset().mockImplementation(() => {
      const socket = new FakeSocket();
      tlsSockets.push(socket);
      return socket as unknown as ReturnType<typeof connect>;
    });
  });
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("requires verified TLS through the loopback proxy, not just CONNECT acceptance", async () => {
    let result: boolean | undefined;
    const pending = isTunnelHealthy().then((value) => { result = value; });
    const socket = establishProxy();
    await Promise.resolve();
    expect(result).toBeUndefined();
    expect(httpMock).toHaveBeenCalledWith(expect.objectContaining({
      hostname: "127.0.0.1", port: 47186, method: "CONNECT", path: "cloudflare-dns.com:443",
    }));
    expect(tlsMock).toHaveBeenCalledWith({ socket, servername: "cloudflare-dns.com", rejectUnauthorized: true });
    tlsSockets[0]!.emit("secureConnect");
    await pending;
    expect(result).toBe(true);
    expect(socket.destroy).toHaveBeenCalledOnce();
    expect(tlsSockets[0]!.destroy).toHaveBeenCalledOnce();
    expect(requests[0]!.destroy).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("tries an independent destination when the first TLS exchange fails", async () => {
    const pending = isTunnelHealthy();
    establishProxy();
    tlsSockets[0]!.emit("error", new Error("certificate or connection failure"));
    await Promise.resolve();
    expect(httpMock).toHaveBeenLastCalledWith(expect.objectContaining({ path: "www.google.com:443" }));
    establishProxy(1);
    tlsSockets[1]!.emit("secureConnect");
    await expect(pending).resolves.toBe(true);
  });

  it("detects silent blackholes and disposes every connection after the deadline", async () => {
    const pending = isTunnelHealthy();
    const socket = establishProxy();
    await vi.advanceTimersByTimeAsync(12_000);
    await expect(pending).resolves.toBe(false);
    expect(socket.destroy).toHaveBeenCalledOnce();
    expect(requests).toHaveLength(2);
    expect(requests.every((req) => req.destroy.mock.calls.length === 1)).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects proxy errors and early TCP closes", async () => {
    const pending = isTunnelHealthy();
    const first = establishProxy(0, 502);
    await Promise.resolve();
    const second = establishProxy(1);
    second.emit("close");
    await expect(pending).resolves.toBe(false);
    expect(first.destroy).toHaveBeenCalled();
    expect(tlsMock).toHaveBeenCalledOnce();
  });

  it("fails safely when the local listener is unavailable", async () => {
    const pending = isTunnelHealthy();
    requests[0]!.emit("error", new Error("ECONNREFUSED"));
    await Promise.resolve();
    requests[1]!.emit("error", new Error("ECONNREFUSED"));
    await expect(pending).resolves.toBe(false);
    expect(tlsMock).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
