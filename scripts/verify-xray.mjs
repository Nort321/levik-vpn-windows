import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// Every installer, and so every OTA update, must carry the Xray core built by
// build-xray.mjs: without the process-name patch, split tunneling and Game
// refuse to connect ("требуется обновлённое VPN-ядро").
export const XRAY_BUILD_MARKER = "levik-process-v1";

export async function verifyPatchedXray(directory = "vendor/xray/windows-x64") {
  const [binary, version, source] = await Promise.all([
    readFile(`${directory}/xray.exe`),
    readFile(`${directory}/VERSION`, "utf8"),
    readFile(`${directory}/levik-source/SOURCE.json`, "utf8"),
  ]).catch(() => {
    throw new Error(`Patched Xray is missing in ${directory}: run npm run download:xray`);
  });
  if (!binary.includes(Buffer.from(XRAY_BUILD_MARKER))) {
    throw new Error(`${directory}/xray.exe is not the patched Levik build (${XRAY_BUILD_MARKER}): run npm run download:xray`);
  }
  if (!version.includes(`+${XRAY_BUILD_MARKER}`)) throw new Error(`${directory}/VERSION does not name the patched build`);
  if (JSON.parse(source).build !== XRAY_BUILD_MARKER) throw new Error(`${directory}/levik-source does not match the patched build`);
  return version.trim();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`Verified patched Xray ${await verifyPatchedXray(process.argv[2])}`);
}
