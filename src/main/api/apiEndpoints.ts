import { isNativeApiDiscovery, type NativeApiDiscovery, type CreateApiDiscovery } from "../core/nativeApiDiscovery";
import type { RustCore } from "../core/rustCore";
import { serviceEndpoints } from "../platform/serviceEndpoints";

export const DEFAULT_API_ORIGIN = "https://api.cloudnote-sync.xyz";

export class ApiEndpoints {
  /** Null in production: the hosts come from the signed endpoints document. */
  private readonly fixed: URL | null;
  private selected: URL | null = null;
  private verifiedUntil = 0;
  private pending: Promise<URL> | null = null;
  private generation = 0;
  private core: RustCore | null = null;
  private create: CreateApiDiscovery | undefined;
  private native: NativeApiDiscovery | null = null;
  private attempted = false;
  private report: () => void = () => {};

  constructor(private readonly baseUrl: string, private readonly refreshEndpoints: () => Promise<boolean> = async () => false, private readonly fetchImpl: typeof fetch = fetch) {
    const origin = new URL(baseUrl);
    if (origin.protocol !== "https:" || origin.pathname !== "/" ||
        origin.username || origin.password || origin.search || origin.hash) {
      throw new Error("Mobile API requires an HTTPS origin without credentials, path, query or fragment");
    }
    // An explicit development override must never receive production credentials
    // through an implicit cross-origin retry.
    this.fixed = baseUrl === DEFAULT_API_ORIGIN ? null : origin;
  }

  useRustCore(core: RustCore, create: CreateApiDiscovery | undefined, report: () => void): void {
    this.core = core; this.create = create; this.native = null; this.attempted = false; this.report = report;
  }

  private nativeHandle(): NativeApiDiscovery | null {
    if (this.fixed || this.core?.mode !== "rust" || !this.create) return null;
    if (!this.attempted) {
      this.attempted = true;
      try {
        const native: unknown = this.create(this.baseUrl);
        if (!isNativeApiDiscovery(native)) throw new Error("Invalid native API discovery");
        this.native = native;
      } catch { this.report(); }
    }
    return this.native;
  }

  invalidate(): void {
    this.generation++;
    this.pending = null;
    try { this.native?.invalidate(); } catch { this.native = null; this.attempted = true; this.report(); }
    this.selected = null;
    this.verifiedUntil = 0;
  }

  async resolve(): Promise<URL> {
    if (this.fixed) return this.fixed;
    if (!this.nativeHandle() && this.selected && Date.now() < this.verifiedUntil) return this.selected;
    if (!this.pending) {
      const pending = this.probeWithRefresh(this.generation).finally(() => { if (this.pending === pending) this.pending = null; });
      this.pending = pending;
    }
    return this.pending;
  }

  /** When every known host fails, a newer signed document may name working ones. */
  private async probeWithRefresh(generation: number): Promise<URL> {
    try {
      return await this.probe(generation);
    } catch (error) {
      if (!await this.refreshEndpoints()) throw error;
      return this.probe(generation);
    }
  }

  private async probe(generation: number): Promise<URL> {
    const origins = [...serviceEndpoints().apiOrigins];
    const native = this.nativeHandle();
    if (native) {
      // A native health-check failure does not cause a second Node request.
      const value: unknown = await native.resolve(JSON.stringify(origins));
      if (typeof value !== "string" || !origins.some((origin) => new URL(origin).origin === value)) throw new Error("Levik API is unavailable");
      return new URL(value);
    }
    for (const value of origins) {
      const origin = new URL(value);
      try {
        // Discover availability without tokens or device identifiers, before
        // sending a signed operation. Never replay a possibly completed POST.
        const response = await this.fetchImpl(new URL("/api/health", origin), {
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
        if (generation === this.generation) {
          this.selected = origin;
          this.verifiedUntil = Date.now() + 60_000;
        }
        return origin;
      } catch {
        // Try only signed or built-in origins; HTTPS verification stays on.
      }
    }
    throw new Error("Levik API is unavailable");
  }
}
