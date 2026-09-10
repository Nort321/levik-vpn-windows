import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
export const XRAY_VERSION = "v26.7.28";
const commit = "5ca6f4b7d4dc20a881d4330e498892697627ec0c";
const sourceSha256 = "45de3ead5186fea442b04c662c554a1ffd1d7bd9093a83410f2edabe74fb766e";
const patch = fileURLToPath(new URL("./patches/xray-windows-process-names.patch", import.meta.url));

export async function buildPatchedXray(destination) {
  const directory = await mkdtemp(join(tmpdir(), "levik-xray-"));
  const output = resolve(destination);
  try {
    const response = await fetch(`https://codeload.github.com/XTLS/Xray-core/tar.gz/${commit}`);
    if (!response.ok) throw new Error(`Xray source download failed (${response.status})`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (createHash("sha256").update(bytes).digest("hex") !== sourceSha256) {
      throw new Error("Xray source archive SHA-256 mismatch");
    }
    const archive = join(directory, "source.tar.gz");
    await writeFile(archive, bytes);
    await execFileAsync("tar", ["-xzf", archive, "-C", directory]);
    const source = join(directory, `Xray-core-${commit}`);
    await execFileAsync("git", ["apply", "--check", patch], { cwd: source });
    await execFileAsync("git", ["apply", patch], { cwd: source });
    const options = { cwd: source, timeout: 600_000, maxBuffer: 4 * 1024 * 1024 };
    await execFileAsync("go", ["test", "./app/router", "-run", "TestLevik", "-count=1"], options);
    const binary = join(directory, "xray.exe");
    await execFileAsync("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid= -X github.com/xtls/xray-core/core.build=levik-process-v1", "-o", binary, "./main"], {
      ...options,
      env: { ...process.env, GOOS: "windows", GOARCH: "amd64", CGO_ENABLED: "0" },
    });
    await mkdir(output, { recursive: true });
    await cp(binary, join(output, "xray.exe"));
    // Ship modified MPL-covered source alongside the executable.
    const modifiedSource = join(output, "levik-source", "app", "router");
    await mkdir(modifiedSource, { recursive: true });
    for (const file of ["condition.go", "process_name_levik.go", "process_name_levik_test.go"]) {
      await cp(join(source, "app", "router", file), join(modifiedSource, file));
    }
    await cp(patch, join(output, "levik-source", "xray-windows-process-names.patch"));
    await cp(join(source, "LICENSE"), join(output, "levik-source", "LICENSE"));
    await writeFile(join(output, "levik-source", "SOURCE.json"), JSON.stringify({
      version: XRAY_VERSION, commit, sourceSha256,
      source: `https://github.com/XTLS/Xray-core/tree/${commit}`,
      patch: "xray-windows-process-names.patch", build: "levik-process-v1",
    }, null, 2));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
