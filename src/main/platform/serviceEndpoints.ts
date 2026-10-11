import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * Where the app finds the Levik servers. A signed document (config/levik-config-v1.json
 * in the main repository) replaces the built-in host names, so a blocked domain is
 * swapped without a new app version. Anyone may serve the file: only a document
 * signed with the Levik configuration key and not older than the stored one is used.
 */

export interface ServiceEndpointsDocument {
  sequence: number;
  apiOrigins: string[];
  webOrigin: string;
  configUrls: string[];
}

export const BUILT_IN_ENDPOINTS: Readonly<ServiceEndpointsDocument> = Object.freeze({
  sequence: 0,
  apiOrigins: [
    "https://api.cloudnote-sync.xyz",
    "https://api.leviknet.org",
    "https://leviknet.org",
    "https://leviknet.com",
  ],
  webOrigin: "https://leviknet.org",
  configUrls: [
    "https://api.cloudnote-sync.xyz/downloads/config/levik-config-v1.json",
    "https://api.leviknet.org/downloads/config/levik-config-v1.json",
    "https://raw.githubusercontent.com/Nort321/levik-vpn/main/config/levik-config-v1.json",
    "https://cdn.jsdelivr.net/gh/Nort321/levik-vpn@main/config/levik-config-v1.json",
  ],
});

/** ECDSA P-256 public key (SPKI, base64); the private key never leaves the publisher. */
const CONFIG_PUBLIC_KEY =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBxwZK9Ledu9WcstW72cqoVTP9AjtB5dzNIhqmvTlm0lXRaqspdY1KbwCnzhjgCY10hAi9CL37PxhY/GGaIdAdQ==";
const MAX_DOCUMENT_BYTES = 16 * 1024;
const MAX_SIGNATURE_BYTES = 512;
const MAX_ORIGINS = 8;
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

let publicKey: KeyObject | null = null;

function configKey(): KeyObject {
  publicKey ??= createPublicKey({ key: Buffer.from(CONFIG_PUBLIC_KEY, "base64"), format: "der", type: "spki" });
  return publicKey;
}

/** An HTTPS origin without credentials, port, path, query or fragment. */
function cleanOrigin(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 300) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !HOST.test(url.hostname) || url.port || url.username || url.password ||
        url.pathname !== "/" || url.search || url.hash) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function cleanConfigUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 300) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !HOST.test(url.hostname) || url.port || url.username || url.password ||
        url.search || url.hash || !url.pathname.endsWith(".json")) return null;
    return url.href;
  } catch {
    return null;
  }
}

function list(values: unknown, clean: (value: unknown) => string | null): string[] {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.flatMap((value) => clean(value) ?? []))].slice(0, MAX_ORIGINS);
}

/** Verifies the signature over the exact bytes, then the content. Null when anything is off. */
export function verifyEndpointsDocument(
  body: Buffer,
  signature: string,
  key: KeyObject = configKey(),
): ServiceEndpointsDocument | null {
  if (body.length === 0 || body.length > MAX_DOCUMENT_BYTES || signature.length > MAX_SIGNATURE_BYTES) return null;
  const encoded = signature.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return null;
  try {
    if (!verify("sha256", body, { key, dsaEncoding: "der" }, Buffer.from(encoded, "base64"))) return null;
    const value: unknown = JSON.parse(body.toString("utf8"));
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const document = value as Record<string, unknown>;
    if (document.schema !== 1) return null;
    const sequence = document.sequence;
    if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return null;
    const apiOrigins = list(document.apiOrigins, cleanOrigin);
    const webOrigin = cleanOrigin(document.webOrigin);
    if (!apiOrigins.length || !webOrigin) return null;
    return { sequence, apiOrigins, webOrigin, configUrls: list(document.configUrls, cleanConfigUrl) };
  } catch {
    return null;
  }
}

type Fetch = typeof fetch;

async function readLimited(response: Response, limit: number): Promise<Buffer | null> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > limit) return null;
  const bytes = Buffer.from(await response.arrayBuffer());
  return bytes.length > limit ? null : bytes;
}

/** Downloads the first valid document that is at least as new as `minSequence`. */
export async function fetchEndpointsDocument(
  urls: readonly string[],
  minSequence: number,
  fetchImpl: Fetch = fetch,
): Promise<{ document: ServiceEndpointsDocument; body: Buffer; signature: string } | null> {
  const get = (url: string, limit: number) => fetchImpl(url, {
    method: "GET",
    credentials: "omit",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  }).then((response) => response.ok ? readLimited(response, limit) : null);
  for (const url of urls) {
    try {
      const [body, signature] = await Promise.all([get(url, MAX_DOCUMENT_BYTES), get(`${url}.sig`, MAX_SIGNATURE_BYTES)]);
      if (!body || !signature) continue;
      const text = signature.toString("utf8");
      const document = verifyEndpointsDocument(body, text);
      if (document && document.sequence >= minSequence) return { document, body, signature: text };
    } catch {
      // A blocked or broken mirror: try the next one.
    }
  }
  return null;
}

/** The document's hosts come first; the built-in ones stay as a last resort. */
function merged(document: ServiceEndpointsDocument): ServiceEndpointsDocument {
  return {
    sequence: document.sequence,
    apiOrigins: [...new Set([...document.apiOrigins, ...BUILT_IN_ENDPOINTS.apiOrigins])],
    webOrigin: document.webOrigin,
    configUrls: [...new Set([...document.configUrls, ...BUILT_IN_ENDPOINTS.configUrls])],
  };
}

let current: ServiceEndpointsDocument = merged(BUILT_IN_ENDPOINTS);

/** The hosts in use now: signed document if any, otherwise the built-in ones. */
export function serviceEndpoints(): Readonly<ServiceEndpointsDocument> {
  return current;
}

/** Host names of the Levik website, current and built-in, for link checks. */
export function websiteHosts(): ReadonlySet<string> {
  const hosts = new Set(["leviknet.org", "leviknet.com"]);
  hosts.add(new URL(current.webOrigin).hostname);
  return hosts;
}

/** Test hook and store loader: installs an already verified document. */
export function useEndpointsDocument(document: ServiceEndpointsDocument | null): void {
  current = merged(document ?? BUILT_IN_ENDPOINTS);
}

/**
 * Keeps the signed bytes on disk and verifies them again on every load, so a
 * file edited on the computer cannot redirect the app either.
 */
export class ServiceEndpointsStore {
  private refreshing: Promise<boolean> | null = null;
  private lastAttemptAt = 0;

  constructor(private readonly path: string, private readonly fetchImpl: Fetch = fetch) {}

  async load(): Promise<void> {
    try {
      const value: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (typeof value !== "object" || value === null) return;
      const { body, signature } = value as Record<string, unknown>;
      if (typeof body !== "string" || typeof signature !== "string") return;
      useEndpointsDocument(verifyEndpointsDocument(Buffer.from(body, "base64"), signature));
    } catch {
      // No stored document yet: the built-in hosts apply.
    }
  }

  /**
   * Looks for a newer document. Resolves true when the hosts changed. Calls
   * closer than `minIntervalMs` apart reuse the last outcome.
   */
  refresh(minIntervalMs = 0): Promise<boolean> {
    if (this.refreshing) return this.refreshing;
    if (Date.now() - this.lastAttemptAt < minIntervalMs) return Promise.resolve(false);
    this.lastAttemptAt = Date.now();
    this.refreshing = (async () => {
      const before = current;
      const fetched = await fetchEndpointsDocument(before.configUrls, Math.max(1, before.sequence), this.fetchImpl);
      if (!fetched || (fetched.document.sequence === before.sequence && before.sequence > 0)) return false;
      useEndpointsDocument(fetched.document);
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.tmp`;
      await writeFile(temporary, JSON.stringify({ body: fetched.body.toString("base64"), signature: fetched.signature }), { mode: 0o600 });
      await rename(temporary, this.path);
      return true;
    })().catch(() => false).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }
}
