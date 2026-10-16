import type { GameMultipathStats, GameRouteQuality, GameRuntimeSnapshot } from "../../../shared/contracts";
import type { GameRouteCandidate, GameRuntimeOptions } from "./client";
import type { ProbeMeasurement, ProbeTarget } from "./wire";

/** What XrayManager needs from the game data plane, in-process or in its own process. */
export interface GameDataPlane {
  listen(preferred?: LoopbackIdentity): Promise<LoopbackIdentity>;
  connect(candidates: GameRouteCandidate[], password: string, options?: GameRuntimeOptions): Promise<void>;
  stop(): Promise<void>;
  snapshot(): GameMultipathStats;
  runtimeSnapshot(): GameRuntimeSnapshot;
  routeQualities(): Record<number, GameRouteQuality>;
  refreshMeasurements(): void;
  setPlaying(active: boolean): void;
  pauseNewFlowsIfIdle(): boolean;
  resumeNewFlows(): void;
  configure(options: GameConfigurableOptions): void;
  startCounting(): void;
  setPrimaryRoute(index: number): void;
}

export interface LoopbackIdentity { port: number; uuid: string }
export type GameConfigurableOptions = Partial<Pick<GameRuntimeOptions, "protection" | "preferredExitId" | "exitScope" | "gameId" | "history" | "nodes">>;
/** Options cross the process boundary as data; the direct-measurement callback stays in main. */
export type SerializableRuntimeOptions = Omit<GameRuntimeOptions, "measureDirect"> & { measureDirect: boolean };

/** Main → data plane. */
export type DataPlaneRequest =
  | { type: "call"; id: number; method: "listen"; args: [LoopbackIdentity | undefined] }
  | { type: "call"; id: number; method: "connect"; args: [GameRouteCandidate[], string, SerializableRuntimeOptions | undefined] }
  | { type: "call"; id: number; method: "stop"; args: [] }
  | { type: "call"; id: number; method: "pauseNewFlowsIfIdle"; args: [] }
  | { type: "notify"; method: "refreshMeasurements" | "resumeNewFlows" | "startCounting"; args: [] }
  | { type: "notify"; method: "setPlaying"; args: [boolean] }
  | { type: "notify"; method: "configure"; args: [GameConfigurableOptions] }
  | { type: "notify"; method: "setPrimaryRoute"; args: [number] }
  | { type: "measured"; id: number; results: ProbeMeasurement[] };

/** Data plane → main. */
export type DataPlaneEvent =
  | { type: "ready" }
  | { type: "result"; id: number; ok: true; value: unknown }
  | { type: "result"; id: number; ok: false }
  | { type: "state"; snapshot: GameMultipathStats; runtime: GameRuntimeSnapshot; qualities: Record<number, GameRouteQuality>; idle: boolean }
  | { type: "measure"; id: number; targets: ProbeTarget[] }
  | { type: "measure-abort"; id: number }
  | { type: "log"; line: string };

export const STATE_INTERVAL_MS = 250;
