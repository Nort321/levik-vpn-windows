import type { IssuedCommand, RemoteDevice } from "../../shared/remote";
import { parseDeliveredCommands, parseIssuedCommands, parseRemoteDevices, type DeliveredCommand } from "../platform/remoteCommands";
import { isDeliveredCommandList, isIssuedCommandList, isRemoteDeviceList } from "./coreGuards";
import type { RustCore } from "./rustCore";

/** A server answer read by both implementations; undefined is no JSON, and TypeScript reads it as nothing. */
function parse<Output>(core: RustCore, name: string, value: unknown, typescript: (value: unknown) => Output, accept: (value: unknown) => value is Output): Output {
  if (core.mode === "ts" || !core.has(name) || value === undefined) return typescript(value);
  return core.run(name, value, () => typescript(value), accept);
}

/** Commands the server delivered to this app, through the Rust core. */
export function parseDeliveredCommandsWithCore(core: RustCore, value: unknown): DeliveredCommand[] {
  return parse(core, "remote.parseDeliveredCommands", value, parseDeliveredCommands, isDeliveredCommandList);
}

/** The user's devices, through the Rust core. */
export function parseRemoteDevicesWithCore(core: RustCore, value: unknown): RemoteDevice[] {
  return parse(core, "remote.parseRemoteDevices", value, parseRemoteDevices, isRemoteDeviceList);
}

/** Commands the user issued, through the Rust core. */
export function parseIssuedCommandsWithCore(core: RustCore, value: unknown): IssuedCommand[] {
  return parse(core, "remote.parseIssuedCommands", value, parseIssuedCommands, isIssuedCommandList);
}
