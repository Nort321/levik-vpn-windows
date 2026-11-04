import { classifyCoreLogLine, networkTypeOfInterface } from "../telemetry/codes";
import { isCoreLogCode, isNetworkType } from "./coreGuards";
import type { RustCore } from "./rustCore";

const CORE_LOG = "telemetryCodes.classifyCoreLogLine";
const NETWORK = "telemetryCodes.networkTypeOfInterface";

/** The code of an Xray or sing-box problem line, through the Rust core; the line itself never leaves the device. */
export function classifyCoreLogLineWithCore(core: RustCore, line: string): string | null {
  if (core.mode === "ts" || !core.has(CORE_LOG)) return classifyCoreLogLine(line);
  return core.run(CORE_LOG, line, () => classifyCoreLogLine(line), isCoreLogCode);
}

/** The network type of the outbound adapter, through the Rust core. */
export function networkTypeOfInterfaceWithCore(core: RustCore, name: string | null): ReturnType<typeof networkTypeOfInterface> {
  if (core.mode === "ts" || !core.has(NETWORK)) return networkTypeOfInterface(name);
  return core.run(NETWORK, { name, platform: "windows" }, () => networkTypeOfInterface(name), isNetworkType);
}
