import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { deflateSync } from "node:zlib";
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
  ...Object.entries({ disconnected: "8b98aa", connecting: "ffbd59", connected: "45d6a0", error: "ff6b76" })
    .map(([name, color]) => writeFile(`dist/assets/tray-${name}.png`, createTrayPng(color))),
]);

function createTrayPng(hexColor) {
  const size = 32;
  const color = Buffer.from(hexColor.match(/../g).map((value) => Number.parseInt(value, 16)));
  const rows = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y += 1) {
    const rowOffset = y * (size * 4 + 1);
    for (let x = 0; x < size; x += 1) {
      const offset = rowOffset + 1 + x * 4;
      const distance = Math.hypot(x - 15.5, y - 15.5);
      const shield = y >= 8 && y <= 23 && Math.abs(x - 15.5) <= 7 - Math.max(0, y - 15) * 0.55;
      if (distance <= 14.5) {
        rows[offset] = shield ? 255 : color[0];
        rows[offset + 1] = shield ? 255 : color[1];
        rows[offset + 2] = shield ? 255 : color[2];
        rows[offset + 3] = 255;
      }
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(rows)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type);
  const chunk = Buffer.alloc(data.length + 12);
  chunk.writeUInt32BE(data.length, 0);
  typeBytes.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), data.length + 8);
  return chunk;
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
