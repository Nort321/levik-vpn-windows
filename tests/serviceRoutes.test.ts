import { describe, expect, it } from "vitest";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, request } from "node:http";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildXrayConfig } from "../src/main/vpn/xrayConfig";
import { compiledServiceRoutes, parseServiceRoutePolicy, serviceExitForServer, ServiceRouteRuntime, type ServiceRoutePolicy } from "../src/main/vpn/serviceRoutes";
import type { AppSettings } from "../src/shared/contracts";

const settings: AppSettings = { routingMode: "global", automaticServer: true, autoReconnect: true, killSwitch: true,
  useDoh: true, dnsServer: "1.1.1.1", theme: "system", launchAtLogin: false, autoConnectOnLaunch: false,
  closeToTray: true, preventDnsLeaks: true, favoriteServerIds: [], favoriteNodes: null, antiDpiEnabled: false,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20", splitTunnelMode: "off",
  splitTunnelProcesses: [], connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
  sharePresence: true, sleepAtHome: true };
const policy: ServiceRoutePolicy = { version: 1, revision: 4, fingerprint: "a".repeat(64), rules: [
  { id: "de-rule", label: "Рабочий сервис", source: "domain", domains: ["full:work.example"], route: { kind: "country", countryCode: "DE" }, fallback: { kind: "block" } },
  { id: "nl-rule", label: "Видеосервис", source: "service", domains: ["domain:video.example"], route: { kind: "exit", exitId: "nl" }, fallback: { kind: "main" } },
  { id: "ru-rule", label: "Российские сайты", source: "preset", domains: ["regexp:^.+\\.ru$"], route: { kind: "direct" }, fallback: { kind: "block" } },
  { id: "default-rule", label: "По общему режиму", source: "domain", domains: ["full:default.example"], route: { kind: "default" }, fallback: { kind: "block" } },
], exits: [
  { exitId: "de", name: "Германия", countryCode: "DE", role: "ordinary", state: "enabled", endpoints: [{ address: "de.example", port: 443, protocol: "vless" }] },
  { exitId: "nl", name: "Нидерланды", countryCode: "NL", role: "ordinary", state: "enabled", endpoints: [{ address: "nl.example", port: 443, protocol: "vless" }] },
] };
function profile() {
  return prepareTunnelProfile(Buffer.from(JSON.stringify({ version: 1, profileId: "service-test", subscriptionId: "one",
    source: { content: ["vless://11111111-1111-4111-8111-111111111111@de.example:443?security=tls&type=xhttp#DE",
      "vless://11111111-1111-4111-8111-111111111111@nl.example:443?security=tls#NL",
      "vless://11111111-1111-4111-8111-111111111111@lte.example:443?security=tls&type=xhttp#LTE"].join("\n") },
    routing: { directDomains: ["domain:legacy.example"], proxyDomains: [], directCidrs: [] } })), "one");
}

describe("ordinary service route policy", () => {
  it("validates policy strictly and rejects ambiguous endpoint ownership", () => {
    expect(parseServiceRoutePolicy(policy)).toEqual(policy);
    expect(parseServiceRoutePolicy(undefined)).toBeUndefined();
    expect(() => parseServiceRoutePolicy({ ...policy, version: 2 })).toThrow();
    expect(() => parseServiceRoutePolicy({ ...policy, exits: [{ ...policy.exits[0], role: "lte" }] })).toThrow();
    expect(() => parseServiceRoutePolicy({ ...policy, exits: [policy.exits[0], { ...policy.exits[0], exitId: "duplicate" }] })).toThrow();
    expect(() => parseServiceRoutePolicy({ ...policy, rules: [{ ...policy.rules[0], domains: ["ext:/tmp/data"] }] })).toThrow();
  });
  it("does not classify a whole subscription or XHTTP protocol as LTE", () => {
    const prepared = profile();
    expect(serviceExitForServer(policy, prepared.servers[0]!)?.exitId).toBe("de");
    expect(serviceExitForServer(policy, prepared.servers[2]!)).toBeNull();
  });
  it("leaves legacy and protected configs unchanged", () => {
    const prepared = profile(); const selected = prepared.servers[2]!;
    const before = buildXrayConfig(prepared, selected, settings);
    prepared.serviceRoutes = policy;
    const after = buildXrayConfig(prepared, selected, settings);
    expect(after).toEqual(before);
    expect(compiledServiceRoutes(after)?.status.state).toBe("suspended");
    expect(compiledServiceRoutes(before)).toBeUndefined();
  });
  it("binds data and DNS to the same fail-closed balancer and keeps default in base policy", () => {
    const prepared = profile(); prepared.serviceRoutes = policy;
    const config = buildXrayConfig(prepared, prepared.servers[0]!, settings);
    const routing = config.routing as { rules: Array<Record<string, unknown>>; balancers: Array<Record<string, unknown>> };
    const data = routing.rules.find((rule) => Array.isArray(rule.domain) && rule.domain.includes("full:work.example"));
    const dns = routing.rules.find((rule) => Array.isArray(rule.inboundTag) && rule.inboundTag.includes("levik-service-rule-0-dns"));
    expect(data?.balancerTag).toBe(dns?.balancerTag);
    expect(routing.balancers).toEqual(expect.arrayContaining([expect.objectContaining({ tag: data?.balancerTag, selector: ["levik-block"], strategy: { type: "random" } })]));
    expect(config.dns).toMatchObject({ disableFallbackIfMatch: true, servers: expect.arrayContaining([
      expect.objectContaining({ domains: ["full:work.example"], tag: "levik-service-rule-0-dns", skipFallback: true }),
    ]) });
    expect(routing.rules).toContainEqual(expect.objectContaining({ domain: ["full:default.example"], outboundTag: "levik-service-default", inboundTag: ["levik-tun-in"] }));
    const outbounds = config.outbounds as Array<Record<string, unknown>>;
    expect(outbounds).toContainEqual({ tag: "levik-service-default", protocol: "loopback", settings: { inboundTag: "levik-service-default-in" } });
    expect(outbounds.some((item) => JSON.stringify(item).includes("lte.example"))).toBe(false);
    const dnsConfig = JSON.stringify(config.dns);
    expect(dnsConfig).toContain("full:nl.example");
  });
  it("retains a missing strict exit as a blocked rule rather than removing it", () => {
    const prepared = profile(); prepared.serviceRoutes = { ...policy, exits: [policy.exits[0]!] };
    const config = buildXrayConfig(prepared, prepared.servers[0]!, settings);
    const plan = compiledServiceRoutes(config)?.plans.find((item) => item.id === "nl-rule");
    expect(plan?.primary).toEqual([]);
    expect(plan?.fallbackRef).toBe("__main");
  });
  it("preserves custom resolver and the base DNS context for default rules", () => {
    const prepared = profile(); prepared.serviceRoutes = policy;
    const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, useDoh: false, dnsServer: "9.9.9.9" });
    const dns = config.dns as { servers: Array<string | Record<string, unknown>> };
    expect(dns.servers).toContainEqual(expect.objectContaining({ address: "tcp://9.9.9.9", domains: ["full:work.example"], tag: "levik-service-rule-0-dns", finalQuery: true }));
    expect(dns.servers).toContainEqual(expect.objectContaining({ address: "9.9.9.9", domains: ["full:default.example"], tag: "levik-dns", finalQuery: true }));
    const main = (config.routing as { balancers: Array<Record<string, unknown>> }).balancers.find((item) => item.tag === "levik-service-main");
    expect(main?.selector).toEqual(["levik-service-endpoint-00"]);
    expect(config.api).not.toHaveProperty("listen");
    const api = (config.inbounds as Array<Record<string, unknown>>).find((item) => item.tag === "levik-service-api-in");
    expect(api).toMatchObject({ listen: "127.0.0.1", protocol: "http", settings: { accounts: [{ user: "levik-service", pass: expect.stringMatching(/^[0-9a-f]{48}$/) }] } });
  });
  it("treats only-selected applications as coverage rather than a forced-main route", () => {
    const prepared = profile(); prepared.serviceRoutes = policy;
    const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, splitTunnelMode: "only", splitTunnelProcesses: ["chrome.exe"] });
    const rules = (config.routing as { rules: Array<Record<string, unknown>> }).rules;
    const service = rules.findIndex((rule) => Array.isArray(rule.domain) && rule.domain.includes("full:work.example"));
    const included = rules.findIndex((rule) => Array.isArray(rule.process) && rule.outboundTag === prepared.servers[0]!.tag);
    const outside = rules.findIndex((rule) => rule.network === "tcp,udp" && ["direct", "levik-direct"].includes(String(rule.outboundTag)));
    expect(rules[service]?.process).toEqual(["chrome.exe"]);
    expect(service).toBeLessThan(included); expect(service).toBeLessThan(outside);
  });
  const executable = process.env.LEVIK_TEST_XRAY ?? resolve("../levik_vpn_macos/vendor/xray", `darwin-${process.arch}`, "xray");
  it.skipIf(process.platform !== "darwin" || !existsSync(executable))("validates all ordinary modes using the pinned real core", () => {
    const prepared = profile(); prepared.serviceRoutes = policy;
    for (const routingMode of ["global", "bypassRu", "blockedOnly"] as const) for (const splitTunnelMode of ["off", "only"] as const) {
      const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, routingMode, splitTunnelMode, splitTunnelProcesses: ["chrome.exe"] });
      expect(() => execFileSync(executable, ["run", "-test", "-format", "json", "-config", "stdin:"], {
        input: JSON.stringify(config), timeout: 5000, stdio: "pipe", env: { ...process.env, XRAY_LOCATION_ASSET: resolve(executable, "..") },
      })).not.toThrow();
    }
  });
  it.skipIf(process.platform !== "darwin" || !existsSync(executable))("keeps default routing semantics on the actual core in all base modes", async () => {
    // Use local HTTP in place of TUN and local redirections in place of subscription exits.
    // This exercises the actual compiled rule order/loopback, without any public traffic.
    const main = createServer((_req, res) => res.end("main"));
    const direct = createServer((_req, res) => res.end("direct"));
    const listen = async (server: ReturnType<typeof createServer>): Promise<number> => {
      server.listen(0, "127.0.0.1"); await once(server, "listening");
      const address = server.address(); if (!address || typeof address === "string") throw new Error("No test port"); return address.port;
    };
    const mainPort = await listen(main); const directPort = await listen(direct);
    let core: ChildProcessWithoutNullStreams | undefined;
    try {
      for (const mode of ["global", "bypassRu", "blockedOnly"] as const) {
        const portServer = createServer(); const port = await listen(portServer);
        await new Promise<void>((done) => portServer.close(() => done()));
        const prepared = profile(); const domains = ["legacy.example", "yandex.ru", "instagram.com", "ordinary.example"];
        prepared.serviceRoutes = { ...policy, rules: domains.map((domain, index) => ({ id: `default-${index}`, label: domain,
          source: "domain", domains: [`full:${domain}`], route: { kind: "default" }, fallback: { kind: "block" } })) };
        const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, routingMode: mode });
        config.log = { loglevel: "info" };
        config.inbounds = [{ tag: "levik-tun-in", listen: "127.0.0.1", port, protocol: "http" }];
        config.outbounds = (config.outbounds as Array<Record<string, unknown>>).map((outbound) =>
          String(outbound.tag).startsWith("levik-service-endpoint-") ? { tag: outbound.tag, protocol: "freedom", settings: { redirect: `127.0.0.1:${mainPort}` } }
          : ["direct", "levik-direct"].includes(String(outbound.tag)) ? { tag: outbound.tag, protocol: "freedom", settings: { redirect: `127.0.0.1:${directPort}` } } : outbound);
        const dns = config.dns as Record<string, unknown>; dns.hosts = Object.fromEntries(domains.map((domain) => [domain, "1.1.1.1"]));
        core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, XRAY_LOCATION_ASSET: resolve(executable, "..") } });
        const ready = new Promise<void>((resolveReady, reject) => {
          const timer = setTimeout(() => reject(new Error("Test core did not start")), 5000);
          const started = (chunk: Buffer): void => { if (/core: Xray .+ started/.test(chunk.toString())) { clearTimeout(timer); resolveReady(); } };
          core!.stdout.on("data", started); core!.stderr.on("data", started); core!.once("error", reject);
          core!.once("exit", () => { clearTimeout(timer); reject(new Error("Test core exited")); });
        }); core.stdin.end(JSON.stringify(config)); await ready;
        const get = (domain: string): Promise<string> => new Promise((resolveBody, reject) => {
          const req = request({ hostname: "127.0.0.1", port, path: `http://${domain}/`, headers: { host: domain }, agent: false }, (res) => {
            let result = ""; res.on("data", (chunk: Buffer) => { result += chunk.toString(); }); res.once("end", () => resolveBody(result)); res.once("error", reject);
          }); req.setTimeout(3000, () => req.destroy(new Error("Test route timed out"))); req.once("error", reject); req.end();
        });
        expect(await get("legacy.example")).toBe("direct");
        expect(await get("instagram.com"), mode).toBe("main");
        expect(await get("yandex.ru")).toBe(mode === "global" ? "main" : "direct");
        expect(await get("ordinary.example")).toBe(mode === "blockedOnly" ? "direct" : "main");
        const ended = once(core, "exit"); core.kill(); await ended; core = undefined;
      }
    } finally {
      if (core && core.exitCode === null) { const ended = once(core, "exit"); core.kill(); await ended; }
      await new Promise<void>((done) => main.close(() => done())); await new Promise<void>((done) => direct.close(() => done()));
    }
  }, 20000);

});

describe("route-local failure recovery", () => {
  it("keeps another country live and never restarts a tunnel", async () => {
    const health = { de: true, nl: true };
    const calls: Array<[string, string]> = [];
    const runtime = new ServiceRouteRuntime([
      { id: "de", balancerTag: "germany", primary: ["de"], fallback: [], finalTag: "levik-block", exits: { de: "DE" } },
      { id: "nl", balancerTag: "netherlands", primary: ["nl"], fallback: [], finalTag: "levik-block", exits: { nl: "NL" } },
    ], async (tag) => health[tag as keyof typeof health], async (balancer, target) => { calls.push([balancer, target]); });
    await runtime.refresh(); expect(calls).toEqual([["germany", "de"], ["netherlands", "nl"]]);
    health.de = false;
    await runtime.refresh(); await runtime.refresh();
    expect(calls).toHaveLength(2);
    await runtime.refresh(); expect(calls.at(-1)).toEqual(["germany", "levik-block"]);
    expect(calls.filter(([balancer]) => balancer === "netherlands")).toHaveLength(1);
    health.de = true; await runtime.refresh(); await runtime.refresh(); expect(calls.at(-1)).toEqual(["germany", "de"]);
    runtime.stop(); health.nl = false; await runtime.refresh(); expect(calls.at(-1)).toEqual(["germany", "de"]);
  });
  it("follows the actual main route and only uses an explicitly permitted direct fallback", async () => {
    let a = false;
    const calls: Array<[string, string]> = [];
    const runtime = new ServiceRouteRuntime([
      { id: "__main", balancerTag: "main", primary: ["a"], fallback: ["b"], finalTag: "levik-block", exits: {} },
      { id: "service", balancerTag: "service", primary: ["a"], primaryRef: "__main", fallback: [], finalTag: "direct", exits: {} },
    ], async (tag) => tag === "b" || a, async (balancer, target) => { calls.push([balancer, target]); });
    await runtime.refresh(); await runtime.refresh(); await runtime.refresh();
    expect(calls).toContainEqual(["main", "b"]); expect(calls.at(-1)).toEqual(["service", "b"]);
    const before = calls.length; a = true; await runtime.refresh(); expect(calls).toHaveLength(before);
  });
  it("isolates DNS failure from a healthy ordinary main route", async () => {
    const calls: Array<[string, string]> = [];
    const runtime = new ServiceRouteRuntime([
      { id: "__main", balancerTag: "main", primary: ["a"], fallback: [], finalTag: "levik-block", exits: {} },
      { id: "service", balancerTag: "service", primary: ["a"], fallback: [], finalTag: "levik-block", exits: {}, requireDns: true },
    ], async () => true, async (balancer, target) => { calls.push([balancer, target]); }, () => {}, async () => false);
    await runtime.refresh();
    expect(calls).toEqual([["service", "levik-block"]]);
  });

  it("does not block main on the first unconfirmed failed probe", async () => {
    const calls: string[] = [];
    const runtime = new ServiceRouteRuntime([{ id: "__main", balancerTag: "main", primary: ["a"], fallback: [], finalTag: "levik-block", exits: {} }],
      async () => false, async (_balancer, tag) => { calls.push(tag); });
    await runtime.refresh(); await runtime.refresh(); expect(calls).toEqual([]);
    await runtime.refresh(); expect(calls).toEqual(["levik-block"]);
  });
  it("freezes route health while suspended and ignores an in-flight sleep failure", async () => {
    let finish: ((value: boolean) => void) | undefined;
    const calls: string[] = [];
    let waiting = true;
    const runtime = new ServiceRouteRuntime([{ id: "__main", balancerTag: "main", primary: ["a"], fallback: [], finalTag: "levik-block", exits: {} }],
      async () => waiting ? await new Promise<boolean>((resolveProbe) => { finish = resolveProbe; }) : false,
      async (_balancer, tag) => { calls.push(tag); });
    const pending = runtime.refresh(); runtime.setSuspended(true); finish?.(false); await pending;
    await runtime.refresh(); expect(calls).toEqual([]);
    waiting = false; runtime.setSuspended(false);
    await runtime.refresh(); await runtime.refresh(); expect(calls).toEqual([]);
    await runtime.refresh(); expect(calls).toEqual(["levik-block"]);
  });
  it("returns from a live fallback only after stable recovery and cooldown", async () => {
    let now = 0; let primary = true; const calls: string[] = [];
    const runtime = new ServiceRouteRuntime([{ id: "service", balancerTag: "service", primary: ["de"], fallback: ["nl"], finalTag: "levik-block", exits: {} }],
      async (tag) => tag === "nl" || primary, async (_balancer, tag) => { calls.push(tag); }, () => {}, undefined, () => now);
    await runtime.refresh(); primary = false;
    for (let index = 0; index < 3; index++) { now += 15000; await runtime.refresh(); }
    expect(calls).toEqual(["de", "nl"]);
    primary = true; now += 15000; await runtime.refresh(); expect(calls).toEqual(["de", "nl"]);
    now += 15000; await runtime.refresh(); expect(calls).toEqual(["de", "nl", "de"]);
  });

});
