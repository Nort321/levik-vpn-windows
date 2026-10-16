import { spawn, execFileSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer } from "node:net";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildXrayConfig, GAME_UDP_BALANCER } from "../src/main/vpn/xrayConfig";
import { GAME_PROBE_USER, gameTag, measureGameDataRoute as measureGameRoute } from "../src/main/vpn/gameRoutes";
import type { AppSettings, TunnelServer } from "../src/shared/contracts";
import { updateXrayRouting } from "../src/main/vpn/xrayManager";

const executable = process.env.LEVIK_TEST_XRAY ?? resolve("vendor/xray/windows-x64/xray.exe");
const settings: AppSettings = {
  routingMode: "global", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
  dnsServer: "1.1.1.1", theme: "dark", launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
  preventDnsLeaks: true, favoriteServerIds: [], favoriteNodes: null, antiDpiEnabled: false,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20", splitTunnelMode: "off",
  splitTunnelProcesses: [], connectionTelemetry: false, telemetryNoticeShown: true, syncSettings: true,
  sharePresence: true, sleepAtHome: true, gameEnabled: true, gameIds: ["valorant"],
};

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  server.close();
  await once(server, "close");
  return port;
}

describe("Game routing with the bundled Xray core", () => {
  it("probes UDP, requires authentication, overrides the blocked balancer and preserves ordinary traffic", async () => {
    const [probePort, gameAppPort, normalAppPort, apiPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
    const gameDns = createSocket("udp4");
    const normalDns = createSocket("udp4");
    let core: ChildProcessWithoutNullStreams | undefined;
    let gamePackets = 0;
    let normalPackets = 0;
    try {
      for (const socket of [gameDns, normalDns]) {
        socket.bind(0, "127.0.0.1");
        await once(socket, "listening");
        socket.on("message", (packet, peer) => {
          if (socket === gameDns) gamePackets++; else normalPackets++;
          const reply = Buffer.from(packet);
          reply[2] = 0x81;
          reply[3] = 0x80;
          socket.send(reply, peer.port, peer.address);
        });
      }
      const server = (tag: string, port: number): TunnelServer => ({ id: tag, tag, name: tag, countryCode: "RU",
        outbound: { tag, protocol: "freedom", settings: { redirect: `127.0.0.1:${port}` } } });
      const normal = server("normal", normalDns.address().port);
      const game = server("game", gameDns.address().port);
      const config = buildXrayConfig({ profileId: "test", subscriptionId: "test", subscriptionExpiresAt: null,
        servers: [normal], game: { enabled: true, servers: [game] }, directCidrs: [], directDomains: [], proxyDomains: [],
      }, normal, settings, "test-pass");
      // Runtime test uses loopback application inbounds instead of installing a
      // real TUN on the developer/CI machine. Windows TUN is a separate acceptance test.
      const inbounds = (config.inbounds as Record<string, unknown>[]).filter((inbound) => inbound.protocol === "socks");
      inbounds[0]!.port = probePort;
      config.api = { tag: "levik-api", listen: `127.0.0.1:${apiPort}`, services: ["StatsService", "RoutingService"] };
      for (const [tag, port] of [["test-game-app", gameAppPort], ["test-normal-app", normalAppPort]] as const) {
        inbounds.push({ tag, listen: "127.0.0.1", port, protocol: "socks", settings: {
          auth: "password", accounts: [{ user: GAME_PROBE_USER, pass: "test-pass" }], udp: true, ip: "127.0.0.1",
        } });
      }
      config.inbounds = inbounds;
      config.log = { loglevel: "warning" };
      const rules = (config.routing as { rules: Record<string, unknown>[] }).rules;
      const processRule = rules.find((rule) => rule.ruleTag === "game-multipath")!;
      delete processRule.process;
      processRule.inboundTag = ["test-game-app"];
      execFileSync(executable, ["run", "-test", "-format", "json", "-config", "stdin:"], { input: JSON.stringify(config), stdio: "pipe", timeout: 5000 });
      core = spawn(executable, ["run", "-format", "json", "-config", "stdin:"], { stdio: "pipe", windowsHide: true });
      const child = core;
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); });
      child.stderr.on("data", (chunk: Buffer) => { output += chunk.toString(); });
      const ready = new Promise<void>((resolveReady, reject) => {
        const timer = setTimeout(() => reject(new Error("Test core startup timeout")), 5000);
        child.stdout.on("data", (chunk: Buffer) => {
          if (chunk.toString().includes("started")) { clearTimeout(timer); resolveReady(); }
        });
        child.once("error", (error) => { clearTimeout(timer); reject(error); });
        child.once("exit", () => { clearTimeout(timer); reject(new Error(`Test core exited: ${output}`)); });
      });
      core.stdin.end(JSON.stringify(config));
      await ready;
      const denied = await measureGameRoute(probePort!, "wrong-password", AbortSignal.timeout(2000));
      expect(denied.latencyMs).toBeNull();
      expect(gamePackets).toBe(0);
      const candidate = await measureGameRoute(probePort!, "test-pass", AbortSignal.timeout(5000));
      expect(candidate.lossPercent).toBe(0);
      expect(gamePackets).toBe(10);
      const blocked = await measureGameRoute(gameAppPort!, "test-pass", AbortSignal.timeout(300));
      expect(blocked.latencyMs).toBeNull();
      expect(normalPackets).toBe(0);
      execFileSync(executable, ["api", "bo", `--server=127.0.0.1:${apiPort}`, "-b", GAME_UDP_BALANCER, gameTag(0)], { stdio: "pipe", timeout: 5000 });
      const gaming = await measureGameRoute(gameAppPort!, "test-pass", AbortSignal.timeout(5000));
      expect(gaming.lossPercent).toBe(0);
      expect(gamePackets).toBe(20);
      const ordinary = await measureGameRoute(normalAppPort!, "test-pass", AbortSignal.timeout(5000));
      expect(ordinary.lossPercent).toBe(0);
      expect(normalPackets).toBe(10);
      expect(gamePackets).toBe(20);
      // Actual pinned-core AddRule from stdin, without stopping the process.
      // ReloadRules replaces balancers, so preserve the live Game selection.
      const routing = structuredClone(config.routing) as { rules: Record<string, unknown>[]; balancers: Array<{ tag: string; selector: string[] }> };
      routing.balancers.find((balancer) => balancer.tag === GAME_UDP_BALANCER)!.selector = [gameTag(0)];
      routing.rules.unshift({ type: "field", inboundTag: ["test-normal-app"], outboundTag: gameTag(0), ruleTag: "test-new-game" });
      await updateXrayRouting(executable, `127.0.0.1:${apiPort}`, routing);
      const newlySelected = await measureGameRoute(normalAppPort!, "test-pass", AbortSignal.timeout(5000));
      expect(newlySelected.lossPercent).toBe(0); expect(normalPackets).toBe(10); expect(gamePackets).toBe(30);
    } finally {
      if (core && core.exitCode === null) { const done = once(core, "exit"); core.kill(); await done; }
      gameDns.close(); normalDns.close();
    }
  }, 20000);
});
