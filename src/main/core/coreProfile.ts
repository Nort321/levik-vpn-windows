import { prepareTunnelProfile, refusalOf, type PreparedTunnelProfile, type TunnelProfileOutcome } from "../vpn/tunnelProfile";
import { isTunnelProfileOutcome } from "./coreGuards";
import type { RustCore } from "./rustCore";

const NAME = "tunnelProfile.prepareTunnelProfile";

/**
 * The decrypted profile through the Rust core. Refusals are compared too; the
 * user sees the same message either way, and JavaScript's own errors keep
 * their wording because the TypeScript raises them again.
 */
export function prepareProfileWithCore(core: RustCore, plaintext: Uint8Array, subscriptionId: string): PreparedTunnelProfile {
  if (core.mode === "ts" || !core.has(NAME)) return prepareTunnelProfile(plaintext, subscriptionId);
  const thrown: unknown[] = [];
  const input = { text: Buffer.from(plaintext).toString("utf8"), bytes: plaintext.byteLength, subscriptionId, platform: "windows" };
  const outcome = core.run(NAME, input, (): TunnelProfileOutcome => {
    try {
      return { profile: prepareTunnelProfile(plaintext, subscriptionId) };
    } catch (error) {
      thrown.push(error);
      return { refused: refusalOf(error) };
    }
  }, isTunnelProfileOutcome);
  if ("profile" in outcome) return outcome.profile;
  if (thrown.length > 0) throw thrown[0];
  if (outcome.refused) throw new Error(outcome.refused);
  return prepareTunnelProfile(plaintext, subscriptionId);
}
