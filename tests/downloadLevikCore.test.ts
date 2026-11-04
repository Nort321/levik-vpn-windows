import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const temporary: string[] = [];
afterEach(() => { for (const directory of temporary.splice(0)) rmSync(directory, { recursive: true, force: true }); });

describe("Rust module availability in build pipelines", () => {
  it.each(["refs/heads/main", "refs/tags/v1.0.0"])("fails closed without a token on %s", (ref) => {
    const result = spawnSync(process.execPath, [join(__dirname, "../scripts/download-levik-core.mjs")], {
      encoding: "utf8", env: { ...process.env, LEVIK_CORE_TOKEN: "", GITHUB_ACTIONS: "true", GITHUB_REF: ref },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("LEVIK_CORE_TOKEN is required");
  });

  it.each(["refs/pull/42/merge", "refs/heads/contribution"])("allows a fork/local build without credentials on %s", (ref) => {
    const result = spawnSync(process.execPath, [join(__dirname, "../scripts/download-levik-core.mjs")], {
      encoding: "utf8", env: { ...process.env, LEVIK_CORE_TOKEN: "", GITHUB_ACTIONS: "true", GITHUB_REF: ref },
    });
    expect(result.status).toBe(0);
    expect(result.stderr).toContain("building without the Rust core module");
  });

  it.each([false, true])("rejects a missing or corrupted staged module: corrupt=%s", (corrupt) => {
    const directory = mkdtempSync(join(tmpdir(), "levik-core-download-test-"));
    temporary.push(directory);
    mkdirSync(join(directory, "scripts"));
    const script = join(directory, "scripts/download-levik-core.mjs");
    writeFileSync(script, readFileSync(join(__dirname, "../scripts/download-levik-core.mjs")));
    const platforms: Partial<Record<NodeJS.Platform, string>> = { win32: "windows", darwin: "darwin", linux: "linux" };
    const platform = platforms[process.platform];
    if (!platform) throw new Error("Unsupported test platform");
    const vendor = join(directory, "vendor/levik-core", `${platform}-${process.arch}`);
    if (corrupt) { mkdirSync(vendor, { recursive: true }); writeFileSync(join(vendor, "levik_core.node"), "corrupt bytes"); }
    const result = spawnSync(process.execPath, [script, "--verify-local"], {
      encoding: "utf8", env: { ...process.env, LEVIK_BUILD_ARCH: process.arch, LEVIK_CORE_TOKEN: "", GITHUB_ACTIONS: "true", GITHUB_REF: "refs/heads/main" },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(corrupt ? "does not match" : "ENOENT");
  });
});
