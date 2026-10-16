import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { startRelay, type RelayOptions } from "../src/main/vpn/multipath/relay";
import { isRecord, validNodeId } from "../src/main/vpn/multipath/wire";

async function configuration(): Promise<RelayOptions> {
  const path = process.env.LEVIK_GAME_RELAY_CONFIG;
  if (!path) return {};
  const raw = await readFile(path); if (raw.length > 32_768) throw new Error("Invalid relay configuration");
  const value: unknown = JSON.parse(raw.toString("utf8"));
  if (!isRecord(value) || typeof value.nodeId !== "string" || !validNodeId(value.nodeId)
    || (value.probeSocket !== undefined && (typeof value.probeSocket !== "string" || !value.probeSocket.startsWith("/run/")))
    || (value.port !== undefined && (!Number.isInteger(value.port) || Number(value.port) < 1 || Number(value.port) > 65535))
    || (value.excludedAddresses !== undefined && (!Array.isArray(value.excludedAddresses) || value.excludedAddresses.length > 512
      || value.excludedAddresses.some((item: unknown) => typeof item !== "string" || isIP(item) !== 4)))) throw new Error("Invalid relay configuration");
  let mesh: RelayOptions["mesh"];
  if (value.mesh !== undefined) {
    const item = value.mesh;
    if (!isRecord(item) || typeof item.address !== "string" || !/^10\.77\.0\.\d+$/.test(item.address)
      || !Number.isInteger(item.port) || Number(item.port) < 1 || Number(item.port) > 65535 || !Array.isArray(item.peers)) throw new Error("Invalid relay mesh");
    const peers: NonNullable<RelayOptions["mesh"]>["peers"] = [];
    for (const peer of item.peers) {
      if (!isRecord(peer) || typeof peer.nodeId !== "string" || typeof peer.address !== "string" || typeof peer.port !== "number") throw new Error("Invalid relay peer");
      peers.push({ nodeId: peer.nodeId, address: peer.address, port: peer.port });
    }
    mesh = { address: item.address, port: Number(item.port), peers };
  }
  return { nodeId: value.nodeId, ...(typeof value.port === "number" ? { port: value.port } : {}),
    ...(typeof value.probeSocket === "string" ? { probeSocket: value.probeSocket } : {}),
    ...(Array.isArray(value.excludedAddresses) ? { excludedAddresses: value.excludedAddresses as string[] } : {}), ...(mesh ? { mesh } : {}) };
}
void configuration().then(async (config) => {
  const relay = await startRelay(config);
  process.stdout.write("Levik Game relay ready on loopback\n");
  let reloading = false;
  process.on("SIGHUP", () => {
    if (reloading) return; reloading = true;
    void configuration().then((next) => {
      if (next.nodeId !== config.nodeId || next.mesh?.address !== config.mesh?.address || next.mesh?.port !== config.mesh?.port
        || next.probeSocket !== config.probeSocket || next.port !== config.port || !next.mesh) throw new Error("Restart required");
      relay.reloadPeers(next.mesh.peers);
    }).catch(() => process.stderr.write("Game relay configuration reload rejected\n")).finally(() => { reloading = false; });
  });
  for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { void relay.close().then(() => process.exit(0)); });
}).catch(() => { process.stderr.write("Game relay failed to start\n"); process.exitCode = 1; });
