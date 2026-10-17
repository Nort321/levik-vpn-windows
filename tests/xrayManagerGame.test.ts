import { describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-xray-test", isPackaged: false, getAppPath: () => "/tmp/levik-xray-test" }, utilityProcess: {} }));
import { XrayManager } from "../src/main/vpn/xrayManager";

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
});
