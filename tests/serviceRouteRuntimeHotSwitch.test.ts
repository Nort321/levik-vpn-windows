import { describe, expect, it, vi } from "vitest";
import { ServiceRouteRuntime, type RouteRuntimePlan } from "../src/main/vpn/serviceRoutes";

function deferred<T>() {
  let resolve: (value: T) => void = () => { throw new Error("Deferred promise was not initialized"); };
  let reject: (error: Error) => void = () => { throw new Error("Deferred promise was not initialized"); };
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, resolve, reject };
}

function fixture() {
  const exits = { a: "DE", b: "NL", fixed: "FI" };
  const plans: RouteRuntimePlan[] = [
    { id: "__main", balancerTag: "main", primary: ["a"], fallback: ["b"], finalTag: "levik-block", exits, externallyManaged: true },
    { id: "follows-main", balancerTag: "service-main", primary: ["a"], primaryRef: "__main", fallback: [], finalTag: "levik-block", exits, requireDns: true },
    { id: "fallback-main", balancerTag: "service-fallback", primary: ["missing"], fallback: ["a", "b"], fallbackRef: "__main", finalTag: "levik-block", exits, requireDns: true },
    { id: "fixed-country", balancerTag: "service-fixed", primary: ["fixed"], fallback: [], finalTag: "levik-block", exits, requireDns: true },
  ];
  const actual = new Map<string, string>();
  const probe = vi.fn(async (tag: string) => tag !== "missing");
  const dns = vi.fn(async () => true);
  const override = vi.fn(async (balancer: string, target: string) => { actual.set(balancer, target); });
  const report = vi.fn();
  const runtime = new ServiceRouteRuntime(plans, probe, override, report, dns);
  return { runtime, plans, probe, dns, override, report, actual };
}

describe("HotSwitch dependent service routes", () => {
  it("acknowledges primary=main and fallback=main together without changing a pinned country", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.probe.mockClear(); h.dns.mockClear();
    await h.runtime.reconcileExternalMain("b");
    expect(h.override.mock.calls).toEqual([["service-main", "b"], ["service-fallback", "b"]]);
    expect(h.probe).not.toHaveBeenCalledWith("fixed"); expect(h.dns).not.toHaveBeenCalledWith("fixed");
    expect(h.actual.get("service-fixed")).toBe("fixed");
    expect(h.report.mock.calls.at(-1)?.[0]).toEqual([
      { id: "__main", state: "active", exitId: "NL" },
      { id: "follows-main", state: "active", exitId: "NL" },
      { id: "fallback-main", state: "fallback", exitId: "NL" },
      { id: "fixed-country", state: "active", exitId: "FI" },
    ]);
  });

  it("waits for an old probe and then probes the new main before acknowledging", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    const gate = deferred<boolean>();
    h.probe.mockImplementationOnce(async () => await gate.promise);
    const old = h.runtime.refresh();
    let finished = false;
    const switching = h.runtime.reconcileExternalMain("b").then(() => { finished = true; });
    await Promise.resolve(); expect(finished).toBe(false); expect(h.override).not.toHaveBeenCalled();
    gate.resolve(true); await Promise.all([old, switching]);
    expect(h.probe).toHaveBeenCalledWith("b");
    expect(h.actual.get("service-main")).toBe("b");
    expect(h.actual.get("service-fallback")).toBe("b");
    expect(h.report).toHaveBeenCalledTimes(1);
  });

  it("repairs a stale already-submitted override even when returning to the cached old target", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    const gate = deferred<void>();
    h.override.mockImplementationOnce(async (balancer, target) => { h.actual.set(balancer, target); await gate.promise; });
    h.runtime.setExternalMain("b");
    const old = h.runtime.refresh();
    await vi.waitFor(() => expect(h.actual.get("service-main")).toBe("b"));
    let finished = false;
    const switching = h.runtime.reconcileExternalMain("a").then(() => { finished = true; });
    await Promise.resolve(); expect(finished).toBe(false);
    gate.resolve(); await Promise.all([old, switching]);
    expect(h.override.mock.calls).toEqual([["service-main", "b"], ["service-main", "a"]]);
    expect(h.actual.get("service-main")).toBe("a");
    expect(h.actual.get("service-fallback")).toBe("a");
    expect(h.report).toHaveBeenCalledTimes(1);
  });

  it("keeps a coalesced timer refresh from starting against the old main during reconciliation", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear();
    const gate = deferred<boolean>();
    h.probe.mockImplementationOnce(async () => await gate.promise);
    const old = h.runtime.refresh();
    // A timer already waiting on the old cycle can run before reconcile's
    // continuation. It must not reserve the fresh cycle with old candidates.
    const timer = old.then(async () => await h.runtime.refresh());
    const switching = h.runtime.reconcileExternalMain("b");
    gate.resolve(true); await Promise.all([old, timer, switching]);
    expect(h.actual.get("service-main")).toBe("b"); expect(h.actual.get("service-fallback")).toBe("b");
    expect(h.probe).toHaveBeenCalledWith("b");
  });

  it("reconciles after a stale API failure instead of leaving its possible side effect installed", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear();
    const gate = deferred<void>();
    h.override.mockImplementationOnce(async (balancer, target) => { h.actual.set(balancer, target); await gate.promise; });
    h.runtime.setExternalMain("b");
    const old = h.runtime.refresh().catch(() => {});
    await vi.waitFor(() => expect(h.actual.get("service-main")).toBe("b"));
    const switching = h.runtime.reconcileExternalMain("a");
    gate.reject(new Error("Old API response was lost"));
    await Promise.all([old, switching]);
    expect(h.actual.get("service-main")).toBe("a");
    expect(h.override.mock.calls.at(-1)).toEqual(["service-main", "a"]);
  });

  it("rejects a new unacknowledged override and reasserts the old route during compensation", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    h.override.mockImplementationOnce(async (balancer, target) => {
      h.actual.set(balancer, target); throw new Error("API response was lost");
    });
    await expect(h.runtime.reconcileExternalMain("b")).rejects.toThrow("API response was lost");
    expect(h.actual.get("service-main")).toBe("b"); expect(h.report).not.toHaveBeenCalled();
    await h.runtime.reconcileExternalMain("a");
    expect(h.actual.get("service-main")).toBe("a");
    expect(h.actual.get("service-fallback")).toBe("a");
    expect(h.override.mock.calls).toEqual([["service-main", "b"], ["service-main", "a"]]);
  });

  it("applies each dependent rule's DNS failure policy while leaving the external main alone", async () => {
    const exits = { a: "DE", b: "NL" };
    const calls: Array<[string, string]> = [];
    const runtime = new ServiceRouteRuntime([
      { id: "__main", balancerTag: "main", primary: ["a"], fallback: ["b"], finalTag: "levik-block", exits, externallyManaged: true },
      { id: "strict", balancerTag: "strict", primary: ["a"], primaryRef: "__main", fallback: [], finalTag: "levik-block", exits, requireDns: true },
      { id: "direct-permitted", balancerTag: "direct-permitted", primary: ["a"], primaryRef: "__main", fallback: [], finalTag: "direct", exits, requireDns: true },
      { id: "fallback-main", balancerTag: "fallback-main", primary: [], fallback: ["a", "b"], fallbackRef: "__main", finalTag: "levik-block", exits, requireDns: true },
    ], async () => true, async (balancer, target) => { calls.push([balancer, target]); }, () => {}, async (tag) => tag !== "b");
    await runtime.refresh(); calls.length = 0;
    await runtime.reconcileExternalMain("b");
    expect(calls).toEqual([["strict", "levik-block"], ["direct-permitted", "direct"], ["fallback-main", "levik-block"]]);
  });

  it("rejects a reconciliation stopped while the fresh target is being checked", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    const gate = deferred<boolean>();
    h.probe.mockImplementation(async (tag) => tag === "b" ? await gate.promise : tag !== "missing");
    const switching = h.runtime.reconcileExternalMain("b");
    await vi.waitFor(() => expect(h.probe).toHaveBeenCalledWith("b"));
    h.runtime.stop(); gate.resolve(true);
    await expect(switching).rejects.toThrow("reconciliation cancelled");
    expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
  });

  it("remembers an acknowledged compensating main during sleep before resuming dependent routes", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    h.actual.set("main", "a");
    const gate = deferred<boolean>();
    h.probe.mockImplementation(async (tag) => tag === "b" ? await gate.promise : tag !== "missing");
    h.actual.set("main", "b"); // The external owner has acknowledged the MAIN write.
    const switching = h.runtime.reconcileExternalMain("b");
    const rejectedSwitch = expect(switching).rejects.toThrow("reconciliation cancelled");
    await vi.waitFor(() => expect(h.probe).toHaveBeenCalledWith("b"));
    h.runtime.setSuspended(true);
    h.actual.set("main", "a"); // Compensation was acknowledged while suspended.
    const compensation = h.runtime.reconcileExternalMain("a");
    const rejectedCompensation = expect(compensation).rejects.toThrow("reconciliation cancelled");
    gate.resolve(true); await Promise.all([rejectedSwitch, rejectedCompensation]);
    expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
    h.runtime.setSuspended(false); await h.runtime.refresh();
    expect(h.actual.get("service-main")).toBe(h.actual.get("main"));
    expect(h.actual.get("service-fallback")).toBe(h.actual.get("main"));
    expect(h.report.mock.calls.at(-1)?.[0]).toContainEqual({ id: "__main", state: "active", exitId: "DE" });
  });

  it("does not revive a stopped runtime when a late main acknowledgement arrives", async () => {
    const h = fixture(); await h.runtime.refresh(); h.probe.mockClear(); h.override.mockClear(); h.report.mockClear();
    h.runtime.stop();
    await expect(h.runtime.reconcileExternalMain("b")).rejects.toThrow("reconciliation cancelled");
    h.runtime.setSuspended(false); await h.runtime.refresh();
    expect(h.probe).not.toHaveBeenCalled(); expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
  });

  it("stops after an in-flight policy write is aborted and reconciles a compensating main", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    const gate = deferred<void>();
    h.override.mockImplementationOnce(async (balancer, target) => { h.actual.set(balancer, target); await gate.promise; });
    const controller = new AbortController();
    h.actual.set("main", "b");
    const switching = h.runtime.reconcileExternalMain("b", controller.signal);
    const rejectedSwitch = expect(switching).rejects.toThrow("reconciliation cancelled");
    await vi.waitFor(() => expect(h.actual.get("service-main")).toBe("b"));
    controller.abort(); gate.resolve(); await rejectedSwitch;
    expect(h.override.mock.calls).toEqual([["service-main", "b"]]);
    expect(h.actual.get("service-fallback")).toBe("a"); expect(h.report).not.toHaveBeenCalled();
    h.actual.set("main", "a");
    await h.runtime.reconcileExternalMain("a");
    expect(h.override.mock.calls).toEqual([["service-main", "b"], ["service-main", "a"]]);
    expect(h.actual.get("service-main")).toBe(h.actual.get("main"));
    expect(h.actual.get("service-fallback")).toBe(h.actual.get("main"));
  });

  it("remembers an acknowledged main even when its reconciliation signal was already aborted", async () => {
    const h = fixture(); await h.runtime.refresh(); h.probe.mockClear(); h.override.mockClear(); h.report.mockClear();
    const controller = new AbortController(); controller.abort();
    await expect(h.runtime.reconcileExternalMain("b", controller.signal)).rejects.toThrow("reconciliation cancelled");
    expect(h.probe).not.toHaveBeenCalled(); expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
    await h.runtime.refresh();
    expect(h.actual.get("service-main")).toBe("b"); expect(h.actual.get("service-fallback")).toBe("b");
    expect(h.report.mock.calls.at(-1)?.[0]).toContainEqual({ id: "__main", state: "active", exitId: "NL" });
  });

  it("also reasserts an unrelated pinned rule whose older write was unconfirmed", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear();
    h.probe.mockImplementation(async (tag) => tag !== "missing" && tag !== "fixed");
    await h.runtime.refresh(); await h.runtime.refresh();
    const gate = deferred<void>();
    h.override.mockImplementationOnce(async (balancer, target) => { h.actual.set(balancer, target); await gate.promise; });
    const old = h.runtime.refresh();
    await vi.waitFor(() => expect(h.actual.get("service-fixed")).toBe("levik-block"));
    const switching = h.runtime.reconcileExternalMain("b");
    gate.resolve(); await Promise.all([old, switching]);
    expect(h.override.mock.calls).toEqual([
      ["service-fixed", "levik-block"], ["service-main", "b"], ["service-fallback", "b"], ["service-fixed", "levik-block"],
    ]);
  });

  it("invalidates an automatic owner's stale refresh without emitting its old selection", async () => {
    const h = fixture(); await h.runtime.refresh(); h.override.mockClear(); h.report.mockClear();
    const gate = deferred<boolean>();
    h.probe.mockImplementationOnce(async () => await gate.promise);
    const old = h.runtime.refresh(); h.runtime.setExternalMain("b"); gate.resolve(true); await old;
    expect(h.override).not.toHaveBeenCalled(); expect(h.report).not.toHaveBeenCalled();
    await h.runtime.refresh();
    expect(h.actual.get("service-main")).toBe("b"); expect(h.actual.get("service-fallback")).toBe("b");
  });

  it("rejects a target outside the prepared main pool without invalidating or probing routes", async () => {
    const h = fixture();
    await expect(h.runtime.reconcileExternalMain("unknown")).rejects.toThrow("Invalid automatic main target");
    expect(h.probe).not.toHaveBeenCalled(); expect(h.override).not.toHaveBeenCalled();
  });
});
