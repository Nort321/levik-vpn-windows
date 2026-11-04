/** Anonymous queue only; no filesystem primitive or account identity in this API. */
export interface NativeTelemetryQueue {
  snapshot(now: number): Promise<string>;
  installId(now: number): Promise<string>;
  put(entry: string, now: number): Promise<void>;
  pending(now: number): Promise<string>;
  unfinished(now: number): Promise<string>;
  acknowledge(sent: string, now: number): Promise<void>;
  clear(): Promise<void>;
}
export type OpenTelemetryQueue = (directory: string, initial?: string) => Promise<NativeTelemetryQueue>;

export function isNativeTelemetryQueue(value: unknown): value is NativeTelemetryQueue {
  if (typeof value !== "object" || value === null) return false;
  return "snapshot" in value && typeof value.snapshot === "function"
    && "installId" in value && typeof value.installId === "function"
    && "put" in value && typeof value.put === "function"
    && "pending" in value && typeof value.pending === "function"
    && "unfinished" in value && typeof value.unfinished === "function"
    && "acknowledge" in value && typeof value.acknowledge === "function"
    && "clear" in value && typeof value.clear === "function";
}
