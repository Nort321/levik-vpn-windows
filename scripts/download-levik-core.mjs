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
const VERSION = "v0.9.0";
// Drafts are addressed by immutable release ID; the tag endpoint is published-only.
const RELEASE_ID = 434588057;
const SHA256 = {
  "darwin-arm64": "ade59c3909d1585ed643e3f6dad069767be04edf042eeef22aac7711baf3fa55",
  "darwin-x64": "9ec3af62f0c95c2128b8d32d697f606b29cd2a1e4ddeb45449a7ec6684bfd40c",
  "windows-x64": "bdffde632bb8de00328af08bb2c3e2098d181edd98668d10725013eebdd0f417",
  "linux-x64": "afd6748c83e7a27900ecde805f9b13f03e57a5564820b3f925b133b8f2bc9730",
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
