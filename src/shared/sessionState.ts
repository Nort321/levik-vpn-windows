import type { AppSnapshot } from "./contracts";

export function shouldShowLogin(snapshot: Pick<AppSnapshot, "sessionAvailable">): boolean {
  return !snapshot.sessionAvailable;
}
