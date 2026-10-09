import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

// sing-box carries TUIC v5, which Xray does not implement. The asset is pinned
// by SHA-256 so a replaced upstream release cannot enter a signed installer.
const execFileAsync = promisify(execFile);
const version = "1.14.2";
const asset = `sing-box-${version}-windows-amd64.zip`;
const pinnedSha256 = "c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32";
const vendorDir = "vendor/singbox/windows-x64";

const response = await fetch(`https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset}`, {
  redirect: "follow",
  signal: AbortSignal.timeout(180_000),
});
if (!response.ok) throw new Error(`sing-box download failed (${response.status})`);
const bytes = Buffer.from(await response.arrayBuffer());
const sha256 = createHash("sha256").update(bytes).digest("hex");
if (sha256 !== pinnedSha256) throw new Error("sing-box archive SHA-256 does not match the pinned digest");

const work = await mkdtemp(join(tmpdir(), "levik-singbox-"));
try {
  const archive = join(work, asset);
  await writeFile(archive, bytes);
  if (process.platform === "win32") {
    await execFileAsync("powershell.exe", [
      "-NoProfile",
      "-Command",
      `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${work}' -Force`,
    ]);
  } else {
    await execFileAsync("unzip", ["-q", archive, "-d", work]);
  }
  const unpacked = join(work, `sing-box-${version}-windows-amd64`);
  await rm(vendorDir, { recursive: true, force: true });
  await mkdir(vendorDir, { recursive: true });
  await copyFile(join(unpacked, "sing-box.exe"), join(vendorDir, "sing-box.exe"));
  await copyFile(join(unpacked, "LICENSE"), join(vendorDir, "LICENSE"));
  await writeFile(join(vendorDir, "VERSION"), `v${version}\nSHA256 ${sha256}\n`);
  const binary = await readFile(join(vendorDir, "sing-box.exe"));
  if (binary.subarray(0, 2).toString("latin1") !== "MZ") throw new Error("sing-box.exe is not a Windows executable");
} finally {
  await rm(work, { recursive: true, force: true });
}
console.log(`Verified ${asset} (${sha256})`);
