import type { AppSnapshot } from "../shared/contracts";

type SwitchState = Pick<AppSnapshot, "status" | "selectedServerId" | "hotSwitchServerIds" | "hotSwitch">;

/** The warning belongs on the choice before a click, including protocol variants. */
export function serverSwitchLabel(state: SwitchState | null, serverId: string): string | null {
  if (!state || state.status !== "connected") return null;
  if (state.selectedServerId === serverId && state.hotSwitchServerIds?.includes(serverId) && state.hotSwitch?.phase !== "uncertain") return null;
  return state.hotSwitchServerIds?.includes(serverId) ? "HotSwitch" : "с переподключением";
}

/** A country button can choose any of its servers; do not promise a hot switch for a mixed group. */
export function countrySwitchLabel(state: SwitchState | null, serverIds: readonly string[]): string | null {
  if (!state || state.status !== "connected") return null;
  if (state.selectedServerId && serverIds.includes(state.selectedServerId)) return serverSwitchLabel(state, state.selectedServerId);
  return serverIds.length && serverIds.every((id) => state.hotSwitchServerIds?.includes(id))
    ? "HotSwitch" : "возможны переподключения";
}
