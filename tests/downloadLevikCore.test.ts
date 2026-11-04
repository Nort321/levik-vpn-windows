import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

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
});
