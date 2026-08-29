export const XRAY_STATS_ENDPOINT = "127.0.0.1:47185";

export function parseXrayStats(raw: string): { uplink: number; downlink: number } {
  const value = JSON.parse(raw) as unknown;
  const stats = isRecord(value) && Array.isArray(value.stat) ? value.stat : [];
  let uplink = 0;
  let downlink = 0;
  for (const item of stats) {
    if (!isRecord(item) || typeof item.name !== "string") continue;
    const counter = typeof item.value === "number" ? item.value : Number(item.value ?? 0);
    if (!Number.isSafeInteger(counter) || counter < 0) continue;
    if (item.name === "inbound>>>levik-tun-in>>>traffic>>>uplink") uplink = counter;
    if (item.name === "inbound>>>levik-tun-in>>>traffic>>>downlink") downlink = counter;
  }
  return { uplink, downlink };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
