import { randomBytes } from "node:crypto";
import type { AppSettings, TunnelServer } from "../../shared/contracts";
import { adoptServiceRoutes, compiledServiceRoutes } from "../vpn/serviceRoutes";
import type { PreparedTunnelProfile } from "../vpn/tunnelProfile";
import { buildXrayConfig } from "../vpn/xrayConfig";
import { isXrayConfigAnswer, type XrayConfigAnswer } from "./coreGuards";
import type { RustCore } from "./rustCore";

const NAME = "xrayConfig.buildXrayConfig";

/**
 * The Xray configuration through the Rust core. Both implementations get the
 * same fresh control password for the service routes, so their configurations
 * and compiled routes can be compared; the routes of the configuration used
 * are the ones the app reads back with compiledServiceRoutes.
 */
export function buildXrayConfigWithCore(
  core: RustCore,
  profile: PreparedTunnelProfile,
  server: TunnelServer,
  settings: AppSettings,
  gameProbePassword?: string,
): Record<string, unknown> {
  if (core.mode === "ts" || !core.has(NAME)) return buildXrayConfig(profile, server, settings, gameProbePassword);
  const servicePassword = randomBytes(24).toString("hex");
  const input = { profile, server, settings, ...(gameProbePassword === undefined ? {} : { gameProbePassword }), servicePassword, platform: "windows" };
  const answer = core.run(NAME, input, (): XrayConfigAnswer => {
    const config = buildXrayConfig(profile, server, settings, gameProbePassword, servicePassword);
    return { config, serviceRoutes: compiledServiceRoutes(config) ?? null };
  }, isXrayConfigAnswer);
  if (answer.serviceRoutes) adoptServiceRoutes(answer.config, answer.serviceRoutes);
  return answer.config;
}
