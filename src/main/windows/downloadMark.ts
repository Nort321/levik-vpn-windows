import { writeFile } from "node:fs/promises";

/**
 * The mark Windows gives files from the internet (Mark of the Web): SmartScreen
 * and Office then treat a file received through LevikDrop like a download.
 */
export async function markDownloaded(path: string): Promise<void> {
  if (process.platform !== "win32") return;
  await writeFile(`${path}:Zone.Identifier`, "[ZoneTransfer]\r\nZoneId=3\r\n");
}
