import type { TunnelServer } from "../../shared/contracts";
import { countryServers } from "../../shared/serverGroups";
import { isListPositions } from "./coreGuards";
import type { RustCore } from "./rustCore";

const NAME = "serverGroups.countryServers";

/**
 * Every server of a country through the Rust core. Both implementations answer
 * positions in the list given, so the servers handed back are the caller's own
 * objects whichever answer is used.
 */
export function countryServersWithCore(core: RustCore, servers: readonly TunnelServer[], countryCode: string): TunnelServer[] {
  if (core.mode === "ts" || !core.has(NAME)) return countryServers(servers, countryCode);
  const positions = core.run(
    NAME,
    { servers, countryCode, platform: "windows" },
    () => countryServers(servers, countryCode).map((server) => servers.indexOf(server)),
    (value): value is number[] => isListPositions(value, servers.length),
  );
  return positions.flatMap((position) => servers[position] ?? []);
}
