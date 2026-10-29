import { afterEach, describe, expect, it, vi } from "vitest";
import { GuestConnection, type GuestConnectionDependencies } from "../src/main/vpn/guestConnection";
import type { GuestInvitation } from "../src/main/vpn/guestSession";

afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

function setup() {
  vi.useFakeTimers();
  let protectedTraffic = false;
  const dependencies = {
    interfaceFor: vi.fn(() => "Wi-Fi"),
    enableProtection: vi.fn(async () => { protectedTraffic = true; }),
    protectionActive: () => protectedTraffic,
    start: vi.fn(async () => {}), allowTunnel: vi.fn(async () => {}), healthy: vi.fn(async () => true),
    stop: vi.fn(async () => {}), releaseProtection: vi.fn(async () => { protectedTraffic = false; }), changed: vi.fn(),
  } satisfies GuestConnectionDependencies;
  const session = new GuestConnection(dependencies);
  const invitation: GuestInvitation = { v: 1, host: "192.168.43.1", port: 18344, method: "aes-256-gcm", password: Buffer.alloc(32, 9).toString("base64url"), name: "Phone", expiresAt: Date.now() + 60_000 };
  return { session, dependencies, invitation };
}

describe("guest connection lifecycle", () => {
  it("starts with protection and only exposes redacted state", async () => {
    const { session, dependencies, invitation } = setup();
    await session.connect(invitation);
    expect(session.snapshot?.phase).toBe("connected");
    expect(dependencies.enableProtection.mock.invocationCallOrder[0]).toBeLessThan(dependencies.start.mock.invocationCallOrder[0]!);
    expect(JSON.stringify(dependencies.changed.mock.calls)).not.toContain(invitation.password);
    await session.disconnect();
    expect(dependencies.releaseProtection).toHaveBeenCalledOnce();
    expect(session.active).toBe(false);
  });

  it("keeps protection after core failure and never chooses an account server", async () => {
    const { session, dependencies, invitation } = setup();
    await session.connect(invitation);
    session.coreExited();
    await vi.runAllTicks();
    expect(session.snapshot?.phase).toBe("blocked");
    expect(dependencies.releaseProtection).not.toHaveBeenCalled();
    await session.retry();
    expect(dependencies.start).toHaveBeenCalledTimes(2);
    expect(session.snapshot?.phase).toBe("connected");
    await session.disconnect();
  });

  it("expires the credential and retains protection until explicit exit", async () => {
    const { session, dependencies, invitation } = setup();
    await session.connect(invitation);
    await vi.advanceTimersByTimeAsync(60_001);
    expect(session.snapshot?.phase).toBe("expired");
    expect(dependencies.releaseProtection).not.toHaveBeenCalled();
    await session.retry();
    expect(dependencies.start).toHaveBeenCalledOnce();
    await session.disconnect();
  });

  it("does not claim traffic is blocked when Windows refuses protection", async () => {
    const { session, dependencies, invitation } = setup();
    dependencies.enableProtection.mockRejectedValueOnce(new Error("denied"));
    await session.connect(invitation);
    expect(dependencies.start).not.toHaveBeenCalled();
    expect(dependencies.changed.mock.calls.at(-1)?.[1]).toContain("Обычный интернет может оставаться доступным");
    await session.disconnect();
  });

  it("disconnect during startup cancels the stale completion and restores networking", async () => {
    const { session, dependencies, invitation } = setup();
    let resolveStart: (() => void) | undefined;
    dependencies.start.mockImplementationOnce(() => new Promise<void>((resolve) => { resolveStart = resolve; }));
    const connecting = session.connect(invitation);
    await vi.waitFor(() => expect(dependencies.start).toHaveBeenCalledOnce());
    const stopping = session.disconnect();
    resolveStart?.();
    await Promise.all([connecting, stopping]);
    expect(dependencies.healthy).not.toHaveBeenCalled();
    expect(session.snapshot).toBeNull();
    expect(dependencies.releaseProtection).toHaveBeenCalledOnce();
  });

  it("blocks after repeated failed end-to-end checks", async () => {
    const { session, dependencies, invitation } = setup();
    await session.connect(invitation);
    dependencies.healthy.mockResolvedValue(false);
    await session.probe(); await session.probe(); await session.probe();
    expect(session.snapshot?.phase).toBe("blocked");
    expect(dependencies.releaseProtection).not.toHaveBeenCalled();
    await session.disconnect();
  });
});
