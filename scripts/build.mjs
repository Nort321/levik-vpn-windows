import { cp, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

await rm("dist", { recursive: true, force: true });
await mkdir("dist/main", { recursive: true });
await mkdir("dist/renderer", { recursive: true });
await mkdir("dist/assets", { recursive: true });

await Promise.all([
  build({
    entryPoints: ["src/main/main.ts"],
    outfile: "dist/main/main.js",
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    external: ["electron"],
    sourcemap: true,
  }),
  build({
    entryPoints: ["src/preload/preload.ts"],
    outfile: "dist/preload.js",
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    external: ["electron"],
    sourcemap: true,
  }),
  build({
    entryPoints: ["src/renderer/app.ts"],
    outfile: "dist/renderer/app.js",
    bundle: true,
    platform: "browser",
    format: "iife",
    target: "chrome136",
    sourcemap: true,
  }),
]);

await Promise.all([
  cp("src/renderer/index.html", "dist/renderer/index.html"),
  cp("src/renderer/styles.css", "dist/renderer/styles.css"),
  cp("build/icon.ico", "dist/assets/icon.ico"),
  cp("build/tray-connected.png", "dist/assets/tray-connected.png"),
  cp("build/tray-disconnected.png", "dist/assets/tray-disconnected.png"),
]);
