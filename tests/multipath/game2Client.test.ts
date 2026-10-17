import { Socket } from "node:net";
import { once } from "node:events";
import { afterEach, expect, it, vi } from "vitest";
vi.mock("node:perf_hooks", () => ({ performance: { now: () => Date.now() } }));
const network = vi.hoisted(() => ({
  sameCanonical: false,
  mesh: false,
  legacy: false,
  replyAll: false,
  directPort: 0,
  probeMode: "ready" as "ready" | "empty" | "unavailable" | "service-unavailable" | "stale",
  opened: [] as number[],
  sent: [] as Array<{ node: string; flow: string; payload: string; session: string; path: number; sequence: number }>,
  sequence: new Map<string, number>(),
  /** Per relay port and target: replaces fields of the probe result. */
  probeOverride: null as null | ((port: number, target: { address: string; port: number }) => Record<string, unknown> | null),
}));
vi.mock("../../src/main/vpn/multipath/socks", async () => {
  const { decode, encode, Kind, controlPayload, parseControl } = await import("../../src/main/vpn/multipath/wire.js");
  return { openRelayPath: async (port: number, _password: string, receive: (data: Buffer) => void) => {
    network.opened.push(port);
    if (port === network.directPort) {
      let closed = false;
      return { get closed() { return closed; }, close() { closed = true; }, send(data: Buffer) {
        setTimeout(() => { if (!closed) receive(data); }, 14);
      } };
    }
    const entry = network.mesh ? `node-${port}` : port === 1 || network.sameCanonical ? "node-a" : "node-b";
    let closed = false;
    return { get closed() { return closed; }, close() { closed = true; }, send(data: Buffer) {
      const packet = decode(data); if (!packet || closed) return;
      const node = network.mesh && packet.exitNodeId ? packet.exitNodeId : entry;
      const instance = Buffer.alloc(16, network.mesh ? Number(node.slice(5)) : network.sameCanonical ? 1 : port);
      const reply = (kind: number, payload: Buffer) => setTimeout(() => { if (!closed) receive(encode({ ...packet, version: 2, exitNodeId: node, instance, kind, payload })); }, port === 1 ? 10 : 30);
      if (packet.kind === Kind.Ping) reply(Kind.Pong, instance);
      if (packet.kind === Kind.NodeInfo && !network.legacy) reply(Kind.NodeInfo, controlPayload({ version: 2, nodeId: node, instance: instance.toString("hex"),
        load: { cpuPercent: 0 }, capabilities: { probe: true, mesh: network.mesh } }));
      if (packet.kind === Kind.ProbeRequest && !network.legacy) {
        const body = parseControl(packet.payload) as { targets: Array<{ address: string; port: number }> };
        reply(Kind.ProbeResult, controlPayload({ version: 2,
          status: network.probeMode === "service-unavailable" ? "service-unavailable" : "ok",
          results: network.probeMode === "empty" || network.probeMode === "service-unavailable" ? [] : body.targets.map((target) => ({ ...target,
            medianMs: network.probeMode === "unavailable" ? null : port === 1 ? 90 : 10,
            p95Ms: network.probeMode === "unavailable" ? null : port === 1 ? 90 : 10, jitterMs: 0,
            lossPercent: network.probeMode === "unavailable" ? 100 : 0,
            method: network.probeMode === "unavailable" ? "unavailable" : "icmp", sampleCount: 8,
            measuredAt: new Date(Date.now() - (network.probeMode === "stale" ? 600_000 : 0)).toISOString(),
            ...(network.probeOverride?.(port, target) ?? {}) })) }));
      }
      if (packet.kind === Kind.Up) {
        network.sent.push({ node, flow: packet.flow.toString("hex"), payload: packet.payload.toString(),
          session: packet.session.toString("hex"), path: packet.path, sequence: packet.sequence });
        if (network.sameCanonical || network.replyAll) reply(Kind.Down, packet.payload);
      }
    } };
  } };
});
import { GAME_FLOW_LIMITS, GameMultipath, type GameRuntimeOptions } from "../../src/main/vpn/multipath/client";
const nodes: GameRuntimeOptions["nodes"] = ["node-a", "node-b"].map((nodeId) => ({ nodeId, name: nodeId, countryCode: "SE", city: null, mesh: null, state: "enabled" }));
afterEach(() => { vi.useRealTimers(); network.sent = []; network.sequence.clear(); network.sameCanonical = false; network.mesh = false;
  network.legacy = false; network.replyAll = false; network.directPort = 0; network.probeMode = "ready"; network.opened = []; network.probeOverride = null; });
async function association(listener: { port: number; uuid: string }, target: string): Promise<Socket> {
  const socket = new Socket(); socket.on("error", () => {}); socket.connect(listener.port, "127.0.0.1"); await once(socket, "connect");
  const header = Buffer.alloc(26); Buffer.from(listener.uuid.replaceAll("-", ""), "hex").copy(header, 1);
  header[18] = 2; header.writeUInt16BE(7000, 19); header[21] = 1; Buffer.from(target.split(".").map(Number)).copy(header, 22);
  socket.write(header); return socket;
}
async function send(socket: Socket, text: string): Promise<void> {
  const payload = Buffer.from(text); const size = Buffer.alloc(2); size.writeUInt16BE(payload.length); socket.write(Buffer.concat([size, payload]));
  for (let i = 0; i < 6; i++) { await new Promise<void>((resolve) => setImmediate(resolve)); await vi.advanceTimersByTimeAsync(10); }
}
async function play(socket: Socket, prefix = "play"): Promise<void> {
  for (let index = 0; index < 110; index++) await send(socket, `${prefix}-${index}`);
}
it.each(["flow", "session"] as const)("chooses measured B for new %s exits and never moves an existing flow", async (exitScope) => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }], "test", { nodes, protection: true, preferredExitId: null, exitScope });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    // The nodes have nothing cached for these servers yet: the opening uses A.
    network.probeMode = "empty";
    for (const [index, address] of ["1.1.1.1", "8.8.8.8", "9.9.9.9"].entries()) {
      const socket = await association(local, address); sockets.push(socket); await send(socket, `lobby-${index}`);
    }
    network.probeMode = "ready";
    await vi.advanceTimersByTimeAsync(100);
    const next = await association(local, "1.1.1.1"); sockets.push(next); await send(next, "next-match");
    await send(sockets[0]!, "old-flow");
    expect(network.sent.find((item) => item.payload === "lobby-0")?.node).toBe("node-a");
    expect(network.sent.find((item) => item.payload === "next-match")?.node).toBe(exitScope === "flow" ? "node-b" : "node-a");
    expect(network.sent.find((item) => item.payload === "old-flow")?.node).toBe("node-a");
    expect(client.runtimeSnapshot().compatibility).toBe("full");
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("merges legacy address aliases into one canonical relay session with distinct path ids", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.sameCanonical = true;
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const aliases: GameRuntimeOptions["nodes"] = ["legacy-aaa", "legacy-bbb"].map((nodeId) => ({
      nodeId, name: "Узел из старого профиля", countryCode: "SE", city: null, mesh: null, state: "enabled",
    }));
    const pending = client.connect([{ index: 0, port: 1, nodeId: "legacy-aaa" }, { index: 1, port: 2, nodeId: "legacy-bbb" }],
      "test", { nodes: aliases, protection: true, preferredExitId: "legacy-bbb", exitScope: "flow" });
    await vi.advanceTimersByTimeAsync(5000); await pending;
    const socket = await association(local, "1.1.1.1"); sockets.push(socket); await send(socket, "canonical-match");
    expect(client.snapshot().state).toBe("protected");
    const copies = network.sent.filter((item) => item.payload === "canonical-match");
    expect(copies).toHaveLength(2);
    expect(new Set(copies.map((item) => item.node))).toEqual(new Set(["node-a"]));
    expect(new Set(copies.map((item) => item.session)).size).toBe(1);
    expect(new Set(copies.map((item) => item.path)).size).toBe(2);
    // A real relay keys its upstream socket by session + flow, and deduplicates
    // sequence numbers inside it. Both copies must identify exactly one socket.
    expect(new Set(copies.map((item) => `${item.session}:${item.flow}`)).size).toBe(1);
    expect(new Set(copies.map((item) => `${item.session}:${item.flow}:${item.sequence}`)).size).toBe(1);
    expect(client.snapshot()).toMatchObject({ receivedPackets: 1, duplicateReplies: 1 });
    expect(client.runtimeSnapshot().selectedExitId).toBe("node-a");
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it.each(["flow", "session"] as const)("drains a pinned node without moving existing %s flows", async (exitScope) => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }],
      "test", { nodes, protection: true, preferredExitId: null, exitScope });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    network.probeMode = "empty";
    for (const [index, address] of ["1.1.1.1", "8.8.8.8", "9.9.9.9"].entries()) {
      const socket = await association(local, address); sockets.push(socket); await send(socket, `drain-lobby-${index}`);
    }
    network.probeMode = "ready";
    await vi.advanceTimersByTimeAsync(100);
    expect(network.sent.find((item) => item.payload === "drain-lobby-0")?.node).toBe("node-a");
    const original = network.sent.find((item) => item.payload === "drain-lobby-0")!;
    client.configure({ nodes: nodes.map((node) => node.nodeId === "node-a" ? { ...node, state: "draining" } : node) });
    const next = await association(local, "1.1.1.1"); sockets.push(next); await send(next, "after-draining");
    await send(sockets[0]!, "existing-while-draining");
    const existing = network.sent.find((item) => item.payload === "existing-while-draining");
    expect(existing).toMatchObject({ node: "node-a", session: original.session, flow: original.flow });
    if (exitScope === "flow") {
      expect(network.sent.find((item) => item.payload === "after-draining")?.node).toBe("node-b");
    } else {
      expect(network.sent.some((item) => item.payload === "after-draining")).toBe(false);
      expect(client.runtimeSnapshot().selectionReason).toContain("перезапуска");
    }
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("pauses new flows atomically only while idle, and resumes normal forwarding", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", {
      nodes: [nodes[0]!], protection: true, preferredExitId: null, exitScope: "flow",
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    expect(client.pauseNewFlowsIfIdle()).toBe(true);
    const first = await association(local, "1.1.1.1"); sockets.push(first); await send(first, "blocked-while-idle");
    expect(network.sent.some((item) => item.payload === "blocked-while-idle")).toBe(false);
    expect(client.runtimeSnapshot().activeFlowCount).toBe(0);
    client.resumeNewFlows(); await send(first, "resumed-flow");
    const initial = network.sent.find((item) => item.payload === "resumed-flow");
    expect(initial?.node).toBe("node-a");
    expect(client.pauseNewFlowsIfIdle()).toBe(false);
    await send(first, "existing-after-rejected-pause");
    expect(network.sent.find((item) => item.payload === "existing-after-rejected-pause"))
      .toMatchObject({ node: "node-a", session: initial!.session, flow: initial!.flow });
    const second = await association(local, "8.8.8.8"); sockets.push(second); await send(second, "new-after-rejected-pause");
    expect(network.sent.find((item) => item.payload === "new-after-rejected-pause")?.node).toBe("node-a");
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("opens mesh paths lazily for the used exit without expanding the 64-node matrix", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.mesh = true;
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const meshNodes: GameRuntimeOptions["nodes"] = Array.from({ length: 64 }, (_, index) => ({
      nodeId: `node-${index + 1}`, name: `Узел ${index + 1}`, countryCode: "SE", city: null,
      mesh: { address: `10.70.0.${index + 1}`, port: 37080 }, state: "enabled",
    }));
    const pending = client.connect(meshNodes.map((node, index) => ({ index, port: index + 1, nodeId: node.nodeId })), "test", {
      nodes: meshNodes, protection: true, preferredExitId: "node-64", exitScope: "flow",
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    // Learning all node capabilities must not allocate every entry-to-exit pair.
    expect(network.opened).toHaveLength(64);
    expect(client.runtimeSnapshot().ingressPaths).toHaveLength(64);
    expect(client.runtimeSnapshot().ingressPaths.every((path) => path.entryNodeId === path.exitNodeId)).toBe(true);
    const socket = await association(local, "1.1.1.1"); sockets.push(socket); await send(socket, "used-mesh-exit");
    expect(network.sent.find((item) => item.payload === "used-mesh-exit")?.node).toBe("node-64");
    await vi.advanceTimersByTimeAsync(3000);
    const meshPaths = client.runtimeSnapshot().ingressPaths.filter((path) => path.entryNodeId !== path.exitNodeId);
    expect(network.opened).toHaveLength(67);
    expect(meshPaths).toHaveLength(3);
    expect(new Set(meshPaths.map((path) => path.entryNodeId)).size).toBe(3);
    expect(new Set(meshPaths.map((path) => path.exitNodeId))).toEqual(new Set(["node-64"]));
    // A second flow to the same exit reuses its existing associations.
    const next = await association(local, "8.8.8.8"); sockets.push(next); await send(next, "reuse-mesh-exit");
    expect(network.opened).toHaveLength(67);
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("warms mesh entries to the primary exit before the match sends its first packet", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.mesh = true;
  const client = new GameMultipath(); client.setPlaying(true);
  try {
    await client.listen();
    const meshNodes: GameRuntimeOptions["nodes"] = Array.from({ length: 3 }, (_, index) => ({
      nodeId: `node-${index + 1}`, name: `Узел ${index + 1}`, countryCode: "SE", city: null,
      mesh: { address: `10.70.0.${index + 1}`, port: 37080 }, state: "enabled",
    }));
    const pending = client.connect(meshNodes.map((node, index) => ({ index, port: index + 1, nodeId: node.nodeId })), "test", {
      nodes: meshNodes, protection: true, preferredExitId: null, exitScope: "session",
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    client.setPrimaryRoute(2);
    await vi.advanceTimersByTimeAsync(3000);
    const meshPaths = client.runtimeSnapshot().ingressPaths.filter((path) => path.entryNodeId !== path.exitNodeId);
    expect(new Set(meshPaths.map((path) => path.exitNodeId))).toEqual(new Set(["node-3"]));
    expect(new Set(meshPaths.map((path) => path.entryNodeId))).toEqual(new Set(["node-1", "node-2"]));
    // Still warm several seconds later, though no game flow uses the exit yet.
    await vi.advanceTimersByTimeAsync(5000);
    expect(client.runtimeSnapshot().ingressPaths.filter((path) => path.entryNodeId !== path.exitNodeId)).toHaveLength(2);
  } finally { await client.stop(); }
});

it("ignores startup health flows when pinning a session to its primary route", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  const client = new GameMultipath(false); client.setPlaying(true); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }],
      "test", { nodes, protection: true, preferredExitId: null, exitScope: "session" });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    const health = await association(local, "1.1.1.1"); sockets.push(health); await send(health, "startup-health");
    expect(network.sent.find((item) => item.payload === "startup-health")?.node).toBe("node-a");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: null, activeFlowCount: 0 });

    // TCP selected B after startup validation. The first real session flow must
    // share that exit even though its unmeasured access RTT is worse than A's.
    client.setPrimaryRoute(1); client.startCounting();
    const first = await association(local, "8.8.8.8"); sockets.push(first); await send(first, "first-real-flow");
    expect(network.sent.find((item) => item.payload === "first-real-flow")?.node).toBe("node-b");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: "node-b", activeFlowCount: 1 });

    client.setPrimaryRoute(0); client.configure({ preferredExitId: "node-a" });
    await send(health, "later-health");
    const next = await association(local, "9.9.9.9"); sockets.push(next); await send(next, "later-real-flow");
    await send(first, "existing-real-flow");
    expect(network.sent.find((item) => item.payload === "later-health")?.node).toBe("node-a");
    expect(network.sent.find((item) => item.payload === "later-real-flow")?.node).toBe("node-b");
    expect(network.sent.find((item) => item.payload === "existing-real-flow")?.node).toBe("node-b");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: "node-b", activeFlowCount: 2 });
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("keeps the opening decision, forecasts the real next exit and reports the flow identity", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  const client = new GameMultipath(); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }], "test", {
      nodes, protection: true, preferredExitId: null, exitScope: "flow", gameId: "cs2",
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    network.probeMode = "empty";
    const first = await association(local, "1.1.1.1"); sockets.push(first); await send(first, "cold-open");
    network.probeMode = "ready"; await play(first, "cold");
    expect(client.runtimeSnapshot()).toMatchObject({ currentMatch: { address: "1.1.1.1" }, selectedExitId: "node-a",
      routeDecision: { exitId: "node-a", source: "access" }, nextRouteDecision: { exitId: "node-b", source: "measured" } });
    expect(client.runtimeSnapshot().selectionReason).toContain("При открытии потока");
    expect(client.runtimeSnapshot().exits.every((exit) => exit.egressStatus === "ready")).toBe(true);

    const second = await association(local, "1.1.1.1"); sockets.push(second); await play(second, "new");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: "node-b", activeMatchFlowCount: 1, mixedMatchExits: false,
      routeDecision: { source: "measured" } });
    expect(client.runtimeSnapshot().estimateHistory.length).toBeLessThan(10);
    await send(first, "old-is-still-pinned");
    expect(client.runtimeSnapshot()).toMatchObject({ activeMatchFlowCount: 2, mixedMatchExits: true });
    expect(network.sent.find((item) => item.payload === "old-is-still-pinned")?.node).toBe("node-a");

    client.configure({ preferredExitId: "node-a" });
    expect(client.runtimeSnapshot().nextRouteDecision).toMatchObject({ exitId: "node-a", source: "manual" });
    const third = await association(local, "1.1.1.1"); sockets.push(third); await send(third, "manual-next");
    expect(network.sent.find((item) => item.payload === "manual-next")?.node).toBe("node-a");
    const closed = once(first, "close"); first.destroy(); await closed;
    await new Promise<void>((resolve) => setImmediate(resolve));
    await vi.waitFor(() => expect(client.runtimeSnapshot().matchReport).toMatchObject({ gameId: "cs2", server: { address: "1.1.1.1", port: 7000 },
      exitId: "node-a", exitName: "node-a", routeDecision: { source: "access" }, protection: { enabled: true, pathCount: 1 } }));
    // Per-match statistics: what the PC sent and which path delivered the replies first.
    const report = client.runtimeSnapshot().matchReport!;
    expect(report.sentPackets).toBeGreaterThan(0);
    expect(report.paths?.[0]).toMatchObject({ routeIndex: 0, entryNodeId: "node-a" });
    expect(report.paths?.reduce((sum, path) => sum + path.packets, 0)).toBe(report.receivedPackets - (report.recoveredPackets ?? 0));
    expect(client.runtimeSnapshot().liveMatchReport).toMatchObject({ exitId: "node-b" });
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("shows direct forwarding as one unprotected path despite requested protection", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true; network.directPort = 999;
  const client = new GameMultipath(); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", {
      nodes: [nodes[0]!], protection: true, preferredExitId: null, exitScope: "flow", directSocksPort: network.directPort,
      measureDirect: async (targets) => targets.map((target) => ({ ...target, medianMs: 14, p95Ms: 14, jitterMs: 0,
        lossPercent: 0, method: "icmp", sampleCount: 5, measuredAt: new Date().toISOString() })),
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    const first = await association(local, "1.1.1.1"); sockets.push(first); await send(first, "discover");
    const direct = await association(local, "1.1.1.1"); sockets.push(direct); await play(direct, "direct");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: "direct", routeDecision: { exitId: "direct", source: "measured" },
      protection: { enabled: true, effective: false, pathCount: 1 } });
    expect(client.runtimeSnapshot().protection.reason).toContain("Прямой путь");
    client.configure({ preferredExitId: "node-a" });
    expect(client.runtimeSnapshot().nextRouteDecision?.exitId).toBe("node-a");
    await send(direct, "direct-remains-pinned");
    expect(client.runtimeSnapshot().selectedExitId).toBe("direct");
    const closed = once(direct, "close"); direct.destroy(); await closed;
    await new Promise<void>((resolve) => setImmediate(resolve));
    await vi.waitFor(() => expect(client.runtimeSnapshot().matchReport).toMatchObject({ exitId: "direct", protection: { enabled: true, pathCount: 1 }, lossPercent: null }));
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it.each([
  ["empty", "collecting"], ["unavailable", "unavailable"], ["service-unavailable", "service-unavailable"], ["stale", "stale"],
] as const)("invalidates an earlier B measurement when the probe returns %s", async (mode, status) => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  const client = new GameMultipath(); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", {
      nodes: [nodes[0]!], protection: true, preferredExitId: null, exitScope: "flow",
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    network.probeMode = "empty";
    const socket = await association(local, "1.1.1.1"); sockets.push(socket); await send(socket, "cold-open");
    network.probeMode = "ready"; await play(socket);
    expect(client.runtimeSnapshot().exits[0]?.egressStatus).toBe("ready");
    network.probeMode = mode; await vi.advanceTimersByTimeAsync(1100); await send(socket, "still-relayed");
    expect(client.runtimeSnapshot().exits[0]).toMatchObject({ egressStatus: status, estimatedRttMs: null, egress: null });
    expect(client.runtimeSnapshot().routeDecision?.source).toBe("access");
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("reports a legacy relay as the reason B cannot be measured", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.legacy = true; network.replyAll = true;
  const client = new GameMultipath(); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", {
      nodes: [nodes[0]!], protection: true, preferredExitId: null, exitScope: "flow",
    });
    await vi.advanceTimersByTimeAsync(5000); await pending;
    const socket = await association(local, "1.1.1.1"); sockets.push(socket); await play(socket);
    expect(client.runtimeSnapshot()).toMatchObject({ compatibility: "legacy", exits: [{ egressStatus: "legacy" }] });
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("preserves a historical cold-start decision after endpoint measurements become available", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  const client = new GameMultipath(); const sockets: Socket[] = [];
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }], "test", {
      nodes, protection: true, preferredExitId: null, exitScope: "flow", gameId: "cs2",
      history: [{ gameId: "cs2", subnet: "1.1.1.0/24", region: null, nodeId: "node-b", updatedAt: Date.now() }],
    });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    network.probeMode = "empty";
    const socket = await association(local, "1.1.1.1"); sockets.push(socket); await send(socket, "cold-open");
    network.probeMode = "ready"; await play(socket, "history");
    expect(client.runtimeSnapshot()).toMatchObject({ selectedExitId: "node-b", routeDecision: { source: "history" },
      nextRouteDecision: { exitId: "node-b", source: "measured" } });
    expect(client.runtimeSnapshot().exits.every((exit) => exit.egressStatus === "ready")).toBe(true);
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
});

it("keeps a voice socket that paused for seconds and evicts a ping socket instead", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  const open = (): Set<number | undefined> => new Set([...(Reflect.get(client, "connections") as Set<{ socket: Socket }>)].map((item) => item.socket.remotePort));
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    // Voice exchanged far more than a ping socket, then nobody spoke.
    const voice = await association(local, "1.1.1.1"); sockets.push(voice);
    for (let index = 0; index < 20; index++) await send(voice, `voice-${index}`);
    const pings: Socket[] = [];
    for (let index = 0; index < GAME_FLOW_LIMITS.connections - 1; index++) {
      const ping = await association(local, "8.8.8.8"); pings.push(ping); sockets.push(ping); await send(ping, `ping-${index}`);
    }
    await vi.advanceTimersByTimeAsync(3000);
    const late = await association(local, "9.9.9.9"); sockets.push(late); await send(late, "late-region-ping");
    expect(network.sent.some((item) => item.payload === "late-region-ping")).toBe(true);
    const remaining = open();
    expect(remaining.has(voice.localPort)).toBe(true);
    expect(remaining.has(pings[0]!.localPort)).toBe(false);
    await send(voice, "voice-after-pause");
    expect(network.sent.some((item) => item.payload === "voice-after-pause")).toBe(true);
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
}, 30_000);

it("makes room from the longest-silent game socket instead of refusing the match's own", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  const open = (): Set<number | undefined> => new Set([...(Reflect.get(client, "connections") as Set<{ socket: Socket }>)].map((item) => item.socket.remotePort));
  try {
    const local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }], "test", { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    const match = await association(local, "1.1.1.1"); sockets.push(match); await play(match, "match");
    // VALORANT pings every region from a fresh socket each second: the bridge fills up.
    const pings: Socket[] = [];
    for (let index = 0; index < GAME_FLOW_LIMITS.connections - 1; index++) {
      const ping = await association(local, "8.8.8.8"); pings.push(ping); sockets.push(ping); await send(ping, `ping-${index}`);
      if (index % 20 === 0) await send(match, `match-live-${index}`);
    }
    await send(match, "match-live-end");
    expect(open().size).toBe(GAME_FLOW_LIMITS.connections);
    const late = await association(local, "9.9.9.9"); sockets.push(late); await send(late, "late-region-ping");
    expect(network.sent.some((item) => item.payload === "late-region-ping")).toBe(true);
    const remaining = open();
    expect(remaining.has(pings[0]!.localPort)).toBe(false);
    expect(remaining.has(match.localPort)).toBe(true);
    await send(match, "match-after");
    expect(network.sent.some((item) => item.payload === "match-after")).toBe(true);
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
}, 30_000);

it("sends every other game ping through an exit lacking a measurement of that ping server, then follows the measurements", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  network.replyAll = true;
  // node-a times the beacon's replies; node-b's trace stops at a silent router.
  let bReply: Record<string, unknown> = { method: "ttl-hop", medianMs: 5, p95Ms: 5, approximate: true, hop: "62.115.139.181" };
  network.probeOverride = (port, target) => target.address !== "8.8.4.4" ? null : port === 1 ? { method: "udp-echo", medianMs: 30, p95Ms: 30 } : bReply;
  const client = new GameMultipath(); client.setPlaying(true); const sockets: Socket[] = [];
  const ping = async (name: string): Promise<string | undefined> => {
    const socket = await association(local, "8.8.4.4"); sockets.push(socket); await send(socket, name);
    return network.sent.find((item) => item.payload === name)?.node;
  };
  let local: { port: number; uuid: string };
  try {
    local = await client.listen();
    const pending = client.connect([{ index: 0, port: 1, nodeId: "node-a" }, { index: 1, port: 2, nodeId: "node-b" }], "test", { nodes, protection: true, preferredExitId: null, exitScope: "flow" });
    await vi.advanceTimersByTimeAsync(2300); await pending;
    expect(await ping("ping-0")).toBe("node-a");
    await vi.advanceTimersByTimeAsync(3000);
    // The destination is now known to be ping-only: node-b gets every other ping.
    expect([await ping("ping-1"), await ping("ping-2"), await ping("ping-3"), await ping("ping-4")]).toEqual(["node-b", "node-a", "node-b", "node-a"]);
    // node-b's relay has timed enough replies: B is real on both exits and the best one takes all pings.
    bReply = { method: "udp-echo", medianMs: 5, p95Ms: 5 };
    await vi.advanceTimersByTimeAsync(1500);
    expect([await ping("ping-5"), await ping("ping-6"), await ping("ping-7")]).toEqual(["node-b", "node-b", "node-b"]);
  } finally { for (const socket of sockets) socket.destroy(); await client.stop(); }
}, 30_000);
