import { isNativeServiceProbe, type NativeServiceProbe, type StartServiceProbe } from "./nativeServiceProbes";
import { isNativeXrayRequest, type NativeXrayRequest, type StartXrayRequest } from "./nativeXrayApi";
import { isNativeTunnelProbe, type NativeTunnelProbe, type StartTunnelProbe } from "./nativeTunnelHealth";
import { isNativePingBatch, type NativePingBatch, type StartServerPings } from "./nativeServerPinger";
import { isNativeApiDiscovery, type NativeApiDiscovery, type CreateApiDiscovery } from "./nativeApiDiscovery";
import { isNativeConfigCache, type NativeConfigCache, type OpenConfigCache } from "./nativeConfigCache";
import { isNativeTelemetryQueue, type NativeTelemetryQueue, type OpenTelemetryQueue } from "./nativeTelemetry";
import { isNativeSecureStore, type OpenNativeStore, type NativeSecureStore } from "./nativeStore";
import { isNativePublicClient, type NativePublicClient } from "./publicFetch";
import { isNativeReplyKey, type NativeReplyCrypto, type NativeReplyKey } from "./nativeReply";
import { isNativeIdentity, type NativeIdentity } from "./nativeIdentity";
import { existsSync } from "node:fs";
import { join } from "node:path";

/**
 * Rust core loaded through Node-API (levik_desktop/crates/levik-napi). The
 * module is optional: without it, or with a module that does not match, the
 * app runs exactly as before on its TypeScript code. Contract 2 (stage 2 of the
 * Rust migration plan) adds `functions()` and `call()`, see rustCore.ts.
 */
export const LEVIK_CORE_CONTRACT = 2;

export interface LevikCoreInfo {
  version: string;
  contract: number;
  os: string;
  arch: string;
}

export interface LevikCoreModule {
  coreInfo(): LevikCoreInfo;
  /** Optional wave-B handle; older contract-2 modules still work. */
  restoreIdentity?(serialized: string): NativeIdentity;
  replyCrypto?: NativeReplyCrypto;
  createPublicClient?(): NativePublicClient;
  openSecureStore?: OpenNativeStore;
  openTelemetryQueue?: OpenTelemetryQueue;
  openConfigCache?: OpenConfigCache;
  createApiDiscovery?: CreateApiDiscovery;
  startServerPings?: StartServerPings;
  startTunnelProbe?: StartTunnelProbe;
  startXrayRequest?: StartXrayRequest;
  startServiceProbe?: StartServiceProbe;
  /** Names of the core functions this build offers. */
  functions(): string[];
  /** Runs a core function: JSON in, JSON out; throws on bad input. */
  call(name: string, input: string): string;
}

export type LevikCoreStatus =
  | { state: "loaded"; info: LevikCoreInfo; module: LevikCoreModule }
  | { state: "missing" }
  | { state: "rejected"; reason: string };

const RUST_OS: Partial<Record<NodeJS.Platform, string>> = { darwin: "macos", win32: "windows", linux: "linux" };
const RUST_ARCH: Partial<Record<string, string>> = { arm64: "aarch64", x64: "x86_64" };
const VENDOR_OS: Partial<Record<NodeJS.Platform, string>> = { darwin: "darwin", win32: "windows", linux: "linux" };

/** Packaged builds carry the module in resources/levik-core; development runs use vendor/levik-core. */
export function levikCorePath(options: {
  packaged: boolean;
  resourcesPath: string;
  appPath: string;
  platform?: NodeJS.Platform;
  arch?: string;
}): string {
  if (options.packaged) return join(options.resourcesPath, "levik-core", "levik_core.node");
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  return join(options.appPath, "vendor", "levik-core", `${VENDOR_OS[platform] ?? platform}-${arch}`, "levik_core.node");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isCoreInfo(value: unknown): value is LevikCoreInfo {
  return isRecord(value)
    && typeof value.version === "string"
    && typeof value.contract === "number"
    && typeof value.os === "string"
    && typeof value.arch === "string";
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Never throws: a missing or foreign module leaves the TypeScript code in charge. */
export function loadLevikCore(path: string, options: {
  exists?: (path: string) => boolean;
  load?: (path: string) => unknown;
  platform?: NodeJS.Platform;
  arch?: string;
} = {}): LevikCoreStatus {
  const exists = options.exists ?? existsSync;
  // A computed path keeps esbuild from bundling the native module into main.js.
  const load = options.load ?? ((modulePath: string): unknown => require(modulePath));
  if (!exists(path)) return { state: "missing" };
  let loaded: unknown;
  try {
    loaded = load(path);
  } catch (error) {
    return { state: "rejected", reason: `не загрузился: ${messageOf(error)}` };
  }
  if (!isRecord(loaded) || typeof loaded.coreInfo !== "function") {
    return { state: "rejected", reason: "нет coreInfo()" };
  }
  const { coreInfo, functions, call, restoreIdentity, createReplyKey, sealReply, createPublicClient, openSecureStore, openTelemetryQueue, openConfigCache, createApiDiscovery, startServerPings, startTunnelProbe, startXrayRequest, startServiceProbe } = loaded;
  let info: unknown;
  try {
    info = coreInfo();
  } catch (error) {
    return { state: "rejected", reason: `coreInfo() упал: ${messageOf(error)}` };
  }
  if (!isCoreInfo(info)) return { state: "rejected", reason: "coreInfo() вернул не то" };
  if (info.contract !== LEVIK_CORE_CONTRACT) {
    return { state: "rejected", reason: `контракт ${info.contract}, нужен ${LEVIK_CORE_CONTRACT}` };
  }
  if (typeof functions !== "function" || typeof call !== "function") {
    return { state: "rejected", reason: "нет functions() или call()" };
  }
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  if (info.os !== RUST_OS[platform] || info.arch !== RUST_ARCH[arch]) {
    return { state: "rejected", reason: `собран для ${info.os}/${info.arch}` };
  }
  // Node-API functions do not use `this`; the wrappers keep the types exact.
  const described: LevikCoreInfo = info;
  const module: LevikCoreModule = {
    coreInfo: () => described,
    ...(typeof startServiceProbe === "function" ? { startServiceProbe: (input: string): NativeServiceProbe => {
      const probe: unknown = startServiceProbe(input);
      if (!isNativeServiceProbe(probe)) throw new Error("Invalid native service probe");
      return probe;
    } } : {}),
    ...(typeof startXrayRequest === "function" ? { startXrayRequest: (input: string): NativeXrayRequest => {
      const request: unknown = startXrayRequest(input);
      if (!isNativeXrayRequest(request)) throw new Error("Invalid native local Xray request");
      return request;
    } } : {}),
    ...(typeof startTunnelProbe === "function" ? { startTunnelProbe: (input: string): NativeTunnelProbe => {
      const probe: unknown = startTunnelProbe(input);
      if (!isNativeTunnelProbe(probe)) throw new Error("Invalid native tunnel probe");
      return probe;
    } } : {}),
    ...(typeof startServerPings === "function" ? { startServerPings: (input: string): NativePingBatch => {
      const batch: unknown = startServerPings(input);
      if (!isNativePingBatch(batch)) throw new Error("Invalid native server ping batch");
      return batch;
    } } : {}),
    ...(typeof createApiDiscovery === "function" ? { createApiDiscovery: (origin: string): NativeApiDiscovery => {
      const discovery: unknown = createApiDiscovery(origin);
      if (!isNativeApiDiscovery(discovery)) throw new Error("Invalid native API discovery");
      return discovery;
    } } : {}),
    ...(typeof openConfigCache === "function" ? { openConfigCache: async (directory: string): Promise<NativeConfigCache> => {
      const cache: unknown = await openConfigCache(directory);
      if (!isNativeConfigCache(cache)) throw new Error("Invalid native configuration cache");
      return cache;
    } } : {}),
    ...(typeof openTelemetryQueue === "function" ? { openTelemetryQueue: async (directory: string, initial?: string): Promise<NativeTelemetryQueue> => {
      const queue: unknown = await openTelemetryQueue(directory, initial);
      if (!isNativeTelemetryQueue(queue)) throw new Error("Invalid native anonymous queue");
      return queue;
    } } : {}),
    ...(typeof openSecureStore === "function" ? { openSecureStore: async (directory: string, backend: string): Promise<NativeSecureStore> => {
      const store: unknown = await openSecureStore(directory, backend);
      if (!isNativeSecureStore(store)) throw new Error("Invalid native secure store");
      return store;
    } } : {}),
    ...(typeof createPublicClient === "function" ? { createPublicClient: (): NativePublicClient => {
      const client: unknown = createPublicClient();
      if (!isNativePublicClient(client)) throw new Error("Invalid native public client");
      return client;
    } } : {}),
    ...(typeof createReplyKey === "function" && typeof sealReply === "function" ? { replyCrypto: {
      createKey: (): NativeReplyKey => {
        const key: unknown = createReplyKey();
        if (!isNativeReplyKey(key)) throw new Error("Invalid native reply key");
        return key;
      },
      seal: (publicKey: string, link: string): string => {
        const sealed: unknown = sealReply(publicKey, link);
        if (typeof sealed !== "string" || !/^[A-Za-z0-9+/]{300,1500}={0,2}$/.test(sealed)) throw new Error("Invalid native encrypted reply");
        return sealed;
      },
    } } : {}),
    ...(typeof restoreIdentity === "function" ? { restoreIdentity: (serialized: string): NativeIdentity => {
      const identity: unknown = restoreIdentity(serialized);
      if (!isNativeIdentity(identity)) throw new Error("Invalid native identity handle");
      return identity;
    } } : {}),
    functions: (): string[] => {
      const names: unknown = functions();
      return Array.isArray(names) ? names.filter((name): name is string => typeof name === "string") : [];
    },
    call: (name: string, input: string): string => {
      const output: unknown = call(name, input);
      if (typeof output !== "string") throw new Error("call() вернул не строку");
      return output;
    },
  };
  return { state: "loaded", info, module };
}

/** One diagnostics line; no paths, so nothing personal ends up in a support report. */
export function describeLevikCore(status: LevikCoreStatus): string {
  switch (status.state) {
    case "loaded":
      return `Rust-ядро ${status.info.version} (контракт ${status.info.contract}, ${status.info.os}/${status.info.arch}) загружено`;
    case "missing":
      return "Rust-ядро не входит в сборку";
    case "rejected":
      return `Rust-ядро отклонено: ${status.reason.slice(0, 200)}`;
  }
}
