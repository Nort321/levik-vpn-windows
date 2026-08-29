import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const version = process.env.LEVIK_XRAY_VERSION ?? "v26.7.28";
const asset = "Xray-windows-64.zip";
const base = `https://github.com/XTLS/Xray-core/releases/download/${version}`;
const vendorDir = "vendor/xray/windows-x64";
const archive = "vendor/xray/xray-windows-64.zip";

await rm(vendorDir, { recursive: true, force: true });
await mkdir(vendorDir, { recursive: true });

async function download(url, destination) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok || !response.body) {
    throw new Error(`Download failed (${response.status}): ${url}`);
  }
  await pipeline(Readable.fromWeb(response.body), createWriteStream(destination));
}

await download(`${base}/${asset}`, archive);
await download(`${base}/${asset}.dgst`, `${archive}.dgst`);

const bytes = await readFile(archive);
const sha256 = createHash("sha256").update(bytes).digest("hex");
const digestText = await readFile(`${archive}.dgst`, "utf8");
if (!digestText.toLowerCase().includes(sha256)) {
  throw new Error("Xray archive SHA-256 does not match the official digest");
}

if (process.platform === "win32") {
  await execFileAsync("powershell.exe", [
    "-NoProfile",
    "-Command",
    `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${vendorDir}' -Force`,
  ]);
} else {
  await execFileAsync("unzip", ["-q", archive, "-d", vendorDir]);
}

await writeFile(`${vendorDir}/VERSION`, `${version}\n`);
await rm(archive, { force: true });
await rm(`${archive}.dgst`, { force: true });
console.log(`Verified ${asset} ${version} (${sha256})`);

