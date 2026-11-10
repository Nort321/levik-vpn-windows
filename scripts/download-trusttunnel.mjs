import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const arch = "x64";
const version = "1.14.4-lx.31";
const target = `windows-${arch === "x64" ? "amd64" : arch}`;
const asset = `sing-box-${version}-${target}.zip`;
const binary = "sing-box.exe";
const pinned = {
  "x64": "6b2670c9a27dd3ee14a5640d58518292d1571255a2adf438bd8630b15030ce1a"
};
const directory = `vendor/trusttunnel/windows-${arch}`;
const response = await fetch(
  `https://github.com/Leadaxe/sing-box-lx/releases/download/v${version}/${asset}`,
  { signal: AbortSignal.timeout(180_000) },
);
if (!response.ok) throw new Error(`TrustTunnel download failed: ${response.status}`);
const data = Buffer.from(await response.arrayBuffer());
if (createHash("sha256").update(data).digest("hex") !== pinned[arch]) {
  throw new Error("TrustTunnel helper checksum mismatch");
}

const temporary = await mkdtemp(join(tmpdir(), "levik-trusttunnel-"));
try {
  const archive = join(temporary, asset);
  await writeFile(archive, data);
  execFileSync("tar.exe", ["-xf", archive, "-C", temporary]);
  const source = join(temporary, `sing-box-${version}-${target}`);
  await mkdir(directory, { recursive: true });
  await copyFile(join(source, binary), join(directory, binary));
  await copyFile(join(source, "LICENSE"), join(directory, "LICENSE"));
  await chmod(join(directory, binary), 0o755);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
