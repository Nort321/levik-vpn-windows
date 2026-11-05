export interface NativeApiDiscovery {
  resolve(origins: string): Promise<string>;
  invalidate(): void;
}
export type CreateApiDiscovery = (origin: string) => NativeApiDiscovery;
export function isNativeApiDiscovery(value: unknown): value is NativeApiDiscovery {
  return typeof value === "object" && value !== null
    && "resolve" in value && typeof value.resolve === "function"
    && "invalidate" in value && typeof value.invalidate === "function";
}
