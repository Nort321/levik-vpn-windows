import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-xray-test", isPackaged: false, getAppPath: () => "/tmp/levik-xray-test" }, utilityProcess: {} }));
const applied = vi.hoisted(() => [] as Array<{ routing: { rules: Record<string, unknown>[] } }>);
// `xray api adrules` reads the new routing from stdin; the fake core accepts it.
vi.mock("node:child_process", async (importOriginal) => ({ ...await importOriginal<typeof import("node:child_process")>(), spawn: () => {
  const child = Object.assign(new EventEmitter(), { exitCode: null as number | null, signalCode: null, pid: undefined, stdin: new Writable({
    write(chunk: Buffer, _encoding, done) { applied.push(JSON.parse(Buffer.from(chunk).toString())); done(); },
  }) });
  child.stdin.on("finish", () => setImmediate(() => { child.exitCode = 0; child.emit("exit", 0); }));
  return child;
} }));
import { XrayManager } from "../src/main/vpn/xrayManager";
import { gameRoutingRules, GAME_UDP_BALANCER } from "../src/main/vpn/xrayConfig";
import type { AppSettings } from "../src/shared/contracts";

const line = (time: string, body: string): string => `2026/10/17 ${time} ${body}`;

describe("Xray manager and the game data plane", () => {
  it("keeps the journal for events: no per-connection chatter and one line per repeating failure", () => {
    const xray = new XrayManager(); const logs: string[] = [];
    xray.on("log", (entry) => logs.push(entry));
    const emitLines = Reflect.get(xray, "emitLines") as (chunk: Buffer) => void;
    const refused = "app/proxyman/outbound: failed to process outbound traffic > dial tcp 127.0.0.1:50958: connectex: refused";
    emitLines.call(xray, Buffer.from([
      line("10:14:31.1", "[Info] [1] proxy/tun: processing from udp:10.89.0.1:50655 to udp:162.249.72.1:8181"),
      line("10:14:31.1", "[Info] [1] app/dispatcher: Hit route rule: [game-multipath] so taking detour [levik-game-multipath] for [udp:162.249.72.1:8181]"),
      line("10:14:31.2", "[Info] [1] transport/internet/tcp: dialing TCP to tcp:127.0.0.1:50958"),
      line("10:14:31.8", `[Info] [1] ${refused}`),
      line("10:14:31.9", `[Info] [2] ${refused}`),
      line("10:14:32.0", "from udp:10.89.0.1:50656 accepted udp:162.249.72.1:8181 [levik-tun-in -> levik-game-multipath]"),
      line("10:14:32.0", "from udp:10.89.0.1:50657 accepted udp:162.249.72.1:8181 [levik-tun-in -> levik-game-multipath]"),
    ].join("\n")));
    expect(logs).toHaveLength(3);
    expect(logs[0]).toContain("Hit route rule");
    expect(logs[1]).toContain("connectex: refused");
    expect(logs[2]).toContain("accepted udp:162.249.72.1:8181");
  });

  it("moves game UDP to the ordinary tunnel once the data plane is gone for good", async () => {
    const xray = new XrayManager(); const down = vi.fn();
    xray.on("gameDown", down);
    const routeGameThroughTunnel = vi.spyOn(xray, "routeGameThroughTunnel").mockResolvedValue(undefined);
    Reflect.set(xray, "process", {});
    await (Reflect.get(xray, "gameDataPlaneDown") as () => Promise<void>).call(xray);
    expect(routeGameThroughTunnel).toHaveBeenCalledTimes(1);
    expect(down).toHaveBeenCalledWith(true);
    routeGameThroughTunnel.mockRejectedValueOnce(new Error("api"));
    await (Reflect.get(xray, "gameDataPlaneDown") as () => Promise<void>).call(xray);
    expect(down).toHaveBeenLastCalledWith(false);
  });
  it("rebuilds Game's rules in place when the selected games change", async () => {
    const settings = { gameEnabled: true, gameIds: ["valorant"], gameProcesses: [] } as Partial<AppSettings> as AppSettings;
    const xray = new XrayManager();
    Reflect.set(xray, "process", {}); Reflect.set(xray, "tunnelTag", "proxy");
    Reflect.set(xray, "routing", { balancers: [{ tag: GAME_UDP_BALANCER, selector: ["block"] }], rules: [
      { type: "field", ip: ["10.0.0.0/8"], outboundTag: "direct" }, ...gameRoutingRules(settings, "proxy", true),
      { type: "field", process: ["Discord.exe"], outboundTag: "direct", ruleTag: "process-bypass" },
    ] });
    await xray.updateGameProcesses({ ...settings, gameIds: ["valorant", "cs2"] });
    expect(applied.at(-1)!.routing.rules.map((rule) => rule.ruleTag ?? rule.outboundTag)).toEqual(["direct", "game-match-0", "game-multipath", "game", "process-bypass"]);
    expect(applied.at(-1)!.routing.rules[2]).toMatchObject({ process: ["cs2.exe"], balancerTag: GAME_UDP_BALANCER });
    await xray.updateGameProcesses({ ...settings, gameIds: [] });
    expect(applied.at(-1)!.routing.rules.map((rule) => rule.ruleTag ?? rule.outboundTag)).toEqual(["direct", "process-bypass"]);
  });
});
