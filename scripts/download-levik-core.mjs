#!/usr/bin/env node
// Downloads the Rust Node-API module (levik_core.node) for this build's platform from the
// private Nort321/levik-desktop release pinned below into vendor/levik-core/<platform>-<arch>/
// and checks it against the SHA-256 pinned here, not against anything in the release.
// Needs LEVIK_CORE_TOKEN: a fine-grained token with "Contents: read" on that repository only.
// Without the token it skips with a warning: in stage 0 the module only reports itself and
// the app runs on its TypeScript code without it. A token that is set but fails is an error.
// Usage: node scripts/download-levik-core.mjs   (LEVIK_BUILD_ARCH overrides the arch on macOS)
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "Nort321/levik-desktop";
const VERSION = "v0.4.0";
const SHA256 = {
  "darwin-arm64": "4ac0d41ab6bb4cb734b5003f836edd5e3158da726a30281f74ebdf7817c517dd",
  "darwin-x64": "965903c61b183c6a28e7cc44c27c901df15bbdb201fd9b2c2de81993d6e4df04",
  "windows-x64": "d15744b29bb3246138915b088f373a471b7253ed073b2947b640b56e54833976",
  "linux-x64": "e8ed07d1097db5b009ccfd8c15a375332731b5c1d4118494b3767034eebd50b7",
};

const os = { darwin: "darwin", win32: "windows", linux: "linux" }[process.platform];
const dir = `${os}-${process.env.LEVIK_BUILD_ARCH ?? process.arch}`;
const expected = SHA256[dir];
if (!expected) throw new Error(`No Levik core module for ${dir}`);

const token = process.env.LEVIK_CORE_TOKEN?.trim();
if (!token) {
  const message = "LEVIK_CORE_TOKEN is not set: building without the Rust core module";
  console.warn(process.env.GITHUB_ACTIONS ? `::warning::${message}` : message);
  process.exit(0);
}

async function request(url, headers) {
  // Redirects are followed by hand so the token never leaves api.github.com.
  const response = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(120_000) });
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location?.startsWith("https://")) throw new Error(`Levik core download: bad redirect from ${url}`);
    return fetch(location, { signal: AbortSignal.timeout(120_000) });
  }
  return response;
}

const api = { Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
const release = await request(`https://api.github.com/repos/${REPOSITORY}/releases/tags/${VERSION}`, {
  ...api,
  Accept: "application/vnd.github+json",
});
if (!release.ok) throw new Error(`Levik core ${VERSION}: release lookup failed with HTTP ${release.status}`);
const { assets } = await release.json();
const name = `levik_core-${dir}.node`;
const asset = Array.isArray(assets) ? assets.find((item) => item?.name === name) : undefined;
if (typeof asset?.url !== "string") throw new Error(`Levik core ${VERSION}: ${name} is not in the release`);
const download = await request(asset.url, { ...api, Accept: "application/octet-stream" });
if (!download.ok) throw new Error(`Levik core ${VERSION}: ${name} download failed with HTTP ${download.status}`);
const bytes = Buffer.from(await download.arrayBuffer());
const actual = createHash("sha256").update(bytes).digest("hex");
if (actual !== expected) throw new Error(`Levik core ${VERSION}: ${name} SHA-256 ${actual} does not match ${expected}`);

const destination = join(dirname(fileURLToPath(import.meta.url)), "..", "vendor", "levik-core", dir);
await mkdir(destination, { recursive: true });
await writeFile(join(destination, "levik_core.node"), bytes);
await writeFile(join(destination, "VERSION"), `${VERSION}\nSHA256 ${actual}\n`);
console.info(`Verified Levik core ${VERSION} ${dir}: ${actual}`);
