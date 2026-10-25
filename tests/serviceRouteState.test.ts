import { describe, expect, it, vi } from "vitest";
import { ServiceRouteState } from "../src/main/vpn/serviceRouteState";
import type { ServiceRoutePolicy, ServiceRouteStatus } from "../src/main/vpn/serviceRoutes";

const policy = (revision: number, fingerprint = "a".repeat(64)): ServiceRoutePolicy => ({ version: 1, revision, fingerprint,
  rules: [{ id: "rule", label: "Рабочий сервис", source: "domain", domains: ["full:work.example"],
    route: { kind: "country", countryCode: "DE" }, fallback: { kind: "block" } }],
  exits: [{ exitId: "de", name: "Германия", countryCode: "DE", state: "enabled", role: "ordinary",
    endpoints: [{ address: "de.example", port: 443, protocol: "vless" }] }] });
const status = (value: ServiceRoutePolicy, state: ServiceRouteStatus["state"] = "applied"): ServiceRouteStatus => ({
  revision: value.revision, fingerprint: value.fingerprint, state, routes: [{ id: "rule", state: "active", exitId: "de" }],
});
function memory() {
  let saved: Buffer | null = null;
  return { get: vi.fn(async () => saved ? Buffer.from(saved) : null),
    put: vi.fn(async (_key: string, bytes: Uint8Array) => { saved = Buffer.from(bytes); }),
    remove: vi.fn(async () => { saved = null; }) };
}

describe("last-good service policy state", () => {
  it("never persists desired or rejected policy and restores last-good after restart", async () => {
    const disk = memory(); const state = new ServiceRouteState(disk); await state.load();
    const first = policy(1); state.propose("subscription", first);
    expect(disk.put).not.toHaveBeenCalled();
    expect(await state.acknowledge("subscription", status(first, "pending"))).toBeUndefined();
    await state.acknowledge("subscription", status(first));
    expect(state.good("subscription")).toEqual(first);
    const second = policy(2, "b".repeat(64)); state.propose("subscription", second);
    await state.acknowledge("subscription", status(second, "error"));
    const restarted = new ServiceRouteState(disk); await restarted.load();
    expect(restarted.good("subscription")).toEqual(first);
    expect(restarted.pending("subscription")).toBeUndefined();
  });
  it("suspends a protected endpoint without forgetting the ordinary strict policy", async () => {
    const disk = memory(); const state = new ServiceRouteState(disk); const first = policy(1);
    state.propose("subscription", first); await state.acknowledge("subscription", status(first));
    await state.classified("subscription", "vless|lte.example|443", false);
    expect(state.good("subscription")).toEqual(first);
    expect(state.effective("subscription", "vless|lte.example|443")).toBeUndefined();
    expect(state.effective("subscription", "vless|de.example|443")).toEqual(first);
    const restarted = new ServiceRouteState(disk); await restarted.load();
    expect(restarted.effective("subscription", "vless|lte.example|443")).toBeUndefined();
    expect(restarted.effective("subscription", "vless|de.example|443")).toEqual(first);
    await restarted.classified("subscription", "vless|lte.example|443", true);
    expect(restarted.effective("subscription", "vless|lte.example|443")).toEqual(first);
  });
  it("serializes the complete state transaction for concurrent subscriptions", async () => {
    const disk = memory(); const save = disk.put.getMockImplementation()!;
    let release = (): void => {}; let started = (): void => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const entered = new Promise<void>((resolve) => { started = resolve; });
    let calls = 0;
    disk.put.mockImplementation(async (key, bytes) => { if (++calls === 1) { started(); await gate; } await save(key, bytes); });
    const state = new ServiceRouteState(disk); const a = policy(1); const b = policy(2, "b".repeat(64));
    state.propose("a", a); state.propose("b", b);
    const first = state.acknowledge("a", status(a)); const second = state.acknowledge("b", status(b));
    await entered; expect(disk.put).toHaveBeenCalledTimes(1); release(); await Promise.all([first, second]);
    const restarted = new ServiceRouteState(disk); await restarted.load();
    expect(restarted.good("a")).toEqual(a); expect(restarted.good("b")).toEqual(b);
  });
  it("invalidates an old account's in-flight write before clearing its cache", async () => {
    const disk = memory(); const save = disk.put.getMockImplementation()!;
    let release = (): void => {}; let started = (): void => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const entered = new Promise<void>((resolve) => { started = resolve; });
    disk.put.mockImplementation(async (key, bytes) => { started(); await gate; await save(key, bytes); });
    const state = new ServiceRouteState(disk); const first = policy(1); state.propose("a", first);
    const saving = state.acknowledge("a", status(first)); await entered;
    const clearing = state.clear(); release();
    expect(await saving).toBeUndefined(); await clearing;
    expect(state.good("a")).toBeUndefined(); expect(await disk.get()).toBeNull();
  });
  it("updates an identical effective policy's revision without requiring a new configuration", async () => {
    const disk = memory(); const state = new ServiceRouteState(disk); const first = policy(1);
    state.propose("subscription", first); await state.acknowledge("subscription", status(first));
    const metadata = policy(2); state.propose("subscription", metadata);
    await state.acknowledge("subscription", status(metadata));
    expect(state.good("subscription")?.revision).toBe(2);
  });
});
