#!/usr/bin/env node
// Copies the Rust Node-API module built in ../levik_desktop (node scripts/build-node.mjs)
// into vendor/levik-core/<platform>-<arch>/ and checks it against its .sha256 file.
// Optional: without the module the app runs on its TypeScript code only.
// Usage: node scripts/fetch-levik-core.mjs <dir...>   e.g. darwin-arm64 darwin-x64
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = process.env.LEVIK_CORE_DIST ?? join(root, "..", "levik_desktop", "dist");
const dirs = process.argv.slice(2);
if (dirs.length === 0) throw new Error("Name at least one platform directory, e.g. darwin-arm64");
for (const dir of dirs) {
  if (!/^(darwin-arm64|darwin-x64|windows-x64|linux-x64)$/.test(dir)) throw new Error(`Unknown platform directory: ${dir}`);
  const module = join(source, dir, "levik_core.node");
  if (!existsSync(module)) throw new Error(`${module} is missing; build it in levik_desktop first`);
  const expected = readFileSync(`${module}.sha256`, "utf8").split(/\s+/)[0];
  const actual = createHash("sha256").update(readFileSync(module)).digest("hex");
  if (actual !== expected) throw new Error(`${dir}: SHA-256 ${actual} does not match ${expected}`);
  const destination = join(root, "vendor", "levik-core", dir);
  mkdirSync(destination, { recursive: true });
  copyFileSync(module, join(destination, "levik_core.node"));
  console.log(`${dir}: ${actual}`);
}
