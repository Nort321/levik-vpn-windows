import type { LevikDesktopApi } from "../shared/contracts";

declare global {
  interface Window {
    levik: LevikDesktopApi;
  }
}

export {};

