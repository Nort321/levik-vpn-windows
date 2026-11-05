#!/usr/bin/env node
// Downloads the Rust Node-API module (levik_core.node) for this build's platform from the
// private Nort321/levik-desktop release pinned below into vendor/levik-core/<platform>-<arch>/
// and checks it against the SHA-256 pinned here, not against anything in the release.
// Manual downloads need LEVIK_CORE_TOKEN with access to the pinned release.
// CI stages own-repository draft assets in an isolated job and uses --verify-local.
// Main/tag CI builds require the module. Local and fork builds may use TypeScript
// without a token. A token that is set but fails is always an error.
// Usage: node scripts/download-levik-core.mjs   (LEVIK_BUILD_ARCH overrides the arch on macOS)
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "Nort321/levik-desktop";
const VERSION = "v0.19.0";
// Drafts are addressed by immutable release ID; the tag endpoint is published-only.
const RELEASE_ID = 435139799;
const SHA256 = {
  "darwin-arm64": "81d2be1ffe369b8dd2853656c1c9200461dda2ae59b6176171152343cd26ca23",
  "darwin-x64": "78b0f237736d207d8545ccc86ba4403ed3828258d9744e73d11e8e2056e98a26",
  "windows-x64": "22c2cdfd6891589a1f005cf4ca5124e6f2a0782ffb2cfb7062064fe66c6e64e8",
  "linux-x64": "69d549d216fe04cf59f6de57a1a7dbe8a4c80147d57d5ed157ebc1fbb6ae377e",
};

const os = { darwin: "darwin", win32: "windows", linux: "linux" }[process.platform];
const dir = `${os}-${process.env.LEVIK_BUILD_ARCH ?? process.arch}`;
const expected = SHA256[dir];
if (!expected) throw new Error(`No Levik core module for ${dir}`);

const destination = join(dirname(fileURLToPath(import.meta.url)), "..", "vendor", "levik-core", dir);

function verify(bytes) {
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) throw new Error(`Levik core ${VERSION}: ${dir} SHA-256 ${actual} does not match ${expected}`);
  return actual;
}

if (process.argv.includes("--verify-local")) {
  const actual = verify(await readFile(join(destination, "levik_core.node")));
  await writeFile(join(destination, "VERSION"), `${VERSION}\nSHA256 ${actual}\n`);
  console.info(`Verified Levik core ${VERSION} ${dir}: ${actual}`);
  process.exit(0);
}

const token = process.env.LEVIK_CORE_TOKEN?.trim();
if (!token) {
  const message = "LEVIK_CORE_TOKEN is not set: building without the Rust core module";
  if (process.env.GITHUB_ACTIONS === "true" && (process.env.GITHUB_REF === "refs/heads/main" || process.env.GITHUB_REF?.startsWith("refs/tags/"))) {
    throw new Error("LEVIK_CORE_TOKEN is required for a main/tag CI build");
  }
  console.warn(process.env.GITHUB_ACTIONS ? `::warning::${message}` : message);
  process.exit(0);
}

async function request(url, headers) {
  // Redirects are followed by hand so the token never leaves api.github.com.
  if (new URL(url).origin !== "https://api.github.com") throw new Error("Levik core API origin rejected");
  const response = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(120_000) });
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location?.startsWith("https://")) throw new Error(`Levik core download: bad redirect from ${url}`);
    return fetch(location, { signal: AbortSignal.timeout(120_000) });
  }
  return response;
}

const api = { Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
const releasePath = RELEASE_ID === null ? `tags/${VERSION}` : String(RELEASE_ID);
const release = await request(`https://api.github.com/repos/${REPOSITORY}/releases/${releasePath}`, {
  ...api,
  Accept: "application/vnd.github+json",
});
if (!release.ok) throw new Error(`Levik core ${VERSION}: release lookup failed with HTTP ${release.status}`);
const { assets, tag_name: tag } = await release.json();
if (tag !== VERSION) throw new Error(`Levik core ${VERSION}: release tag mismatch`);
const name = `levik_core-${dir}.node`;
const asset = Array.isArray(assets) ? assets.find((item) => item?.name === name) : undefined;
if (typeof asset?.url !== "string") throw new Error(`Levik core ${VERSION}: ${name} is not in the release`);
const download = await request(asset.url, { ...api, Accept: "application/octet-stream" });
if (!download.ok) throw new Error(`Levik core ${VERSION}: ${name} download failed with HTTP ${download.status}`);
const bytes = Buffer.from(await download.arrayBuffer());
const actual = verify(bytes);
await mkdir(destination, { recursive: true });
await writeFile(join(destination, "levik_core.node"), bytes);
await writeFile(join(destination, "VERSION"), `${VERSION}\nSHA256 ${actual}\n`);
console.info(`Verified Levik core ${VERSION} ${dir}: ${actual}`);
