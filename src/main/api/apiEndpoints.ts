export const DEFAULT_API_ORIGIN = "https://api.leviknet.org";

const PRODUCTION_ORIGINS = [
  DEFAULT_API_ORIGIN,
  "https://leviknet.org",
  "https://leviknet.com",
] as const;

export class ApiEndpoints {
  private readonly origins: URL[];
  private selected: URL | null = null;
  private verifiedUntil = 0;
  private pending: Promise<URL> | null = null;

  constructor(baseUrl: string) {
    const origin = new URL(baseUrl);
    if (origin.protocol !== "https:" || origin.pathname !== "/" ||
        origin.username || origin.password || origin.search || origin.hash) {
      throw new Error("Mobile API requires an HTTPS origin without credentials, path, query or fragment");
    }
    // An explicit development override must never receive production credentials
    // through an implicit cross-origin retry.
    this.origins = baseUrl === DEFAULT_API_ORIGIN
      ? PRODUCTION_ORIGINS.map((value) => new URL(value))
      : [origin];
  }

  invalidate(): void {
    this.selected = null;
    this.verifiedUntil = 0;
  }

  async resolve(): Promise<URL> {
    const only = this.origins[0];
    if (this.origins.length === 1 && only) return only;
    if (this.selected && Date.now() < this.verifiedUntil) return this.selected;
    if (!this.pending) {
      this.pending = this.probe().finally(() => { this.pending = null; });
    }
    return this.pending;
  }

  private async probe(): Promise<URL> {
    for (const origin of this.origins) {
      try {
        // Discover availability without tokens or device identifiers, before
        // sending a signed operation. Never replay a possibly completed POST.
        const response = await fetch(new URL("/api/health", origin), {
          method: "GET",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          headers: { Accept: "application/json" },
          signal: AbortSignal.timeout(8_000),
        });
        if (!response.ok || !response.headers.get("content-type")?.includes("application/json") ||
            Number(response.headers.get("content-length") ?? "0") > 1_024) continue;
        const body = await response.text();
        if (body.length > 1_024) continue;
        const value: unknown = JSON.parse(body);
        if (typeof value !== "object" || value === null || !("ok" in value) || value.ok !== true) continue;
        this.selected = origin;
        this.verifiedUntil = Date.now() + 60_000;
        return origin;
      } catch {
        // Try only the built-in, trusted origins; HTTPS verification stays on.
      }
    }
    throw new Error("Levik API is unavailable");
  }
}
