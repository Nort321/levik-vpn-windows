import { serviceEndpoints } from "../platform/serviceEndpoints";

export const DEFAULT_API_ORIGIN = "https://api.cloudnote-sync.xyz";

export class ApiEndpoints {
  /** Null in production: the hosts come from the signed endpoints document. */
  private readonly fixed: URL | null;
  private selected: URL | null = null;
  private verifiedUntil = 0;
  private pending: Promise<URL> | null = null;

  constructor(baseUrl: string, private readonly refreshEndpoints: () => Promise<boolean> = async () => false) {
    const origin = new URL(baseUrl);
    if (origin.protocol !== "https:" || origin.pathname !== "/" ||
        origin.username || origin.password || origin.search || origin.hash) {
      throw new Error("Mobile API requires an HTTPS origin without credentials, path, query or fragment");
    }
    // An explicit development override must never receive production credentials
    // through an implicit cross-origin retry.
    this.fixed = baseUrl === DEFAULT_API_ORIGIN ? null : origin;
  }

  invalidate(): void {
    this.selected = null;
    this.verifiedUntil = 0;
  }

  async resolve(): Promise<URL> {
    if (this.fixed) return this.fixed;
    if (this.selected && Date.now() < this.verifiedUntil) return this.selected;
    if (!this.pending) {
      this.pending = this.probeWithRefresh().finally(() => { this.pending = null; });
    }
    return this.pending;
  }

  /** When every known host fails, a newer signed document may name working ones. */
  private async probeWithRefresh(): Promise<URL> {
    try {
      return await this.probe();
    } catch (error) {
      if (!await this.refreshEndpoints()) throw error;
      return this.probe();
    }
  }

  private async probe(): Promise<URL> {
    for (const value of serviceEndpoints().apiOrigins) {
      const origin = new URL(value);
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
        // Try only signed or built-in origins; HTTPS verification stays on.
      }
    }
    throw new Error("Levik API is unavailable");
  }
}
