/**
 * docs/levik-drop.md "Saving": a name from the other app is never a path.
 * The Android app applies the same rules.
 */

const MAX_NAME_BYTES = 180;
// C0/C1 controls, bidirectional overrides and isolates, zero-width marks, BOM.
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/gu;
const RESERVED_CHARACTERS = /[/\\:*?"<>|]/gu;
const DEVICE_NAMES = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)$/iu;

function utf8Length(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

/** Cuts `value` to at most `bytes` UTF-8 bytes without splitting a character. */
function cut(value: string, bytes: number): string {
  let result = "";
  for (const character of value) {
    if (utf8Length(result + character) > bytes) break;
    result += character;
  }
  return result;
}

function splitExtension(name: string): [string, string] {
  const dot = name.lastIndexOf(".");
  // ".bashrc"-like names have no extension; a long tail is not one either.
  if (dot <= 0 || name.length - dot > 16) return [name, ""];
  return [name.slice(0, dot), name.slice(dot)];
}

export function safeFileName(raw: string): string {
  let name = raw.normalize("NFC").replace(INVISIBLE, "").replace(RESERVED_CHARACTERS, "_");
  name = name.replace(/^[.\s]+/u, "_").replace(/[.\s]+$/u, "");
  if (name === "" || name === "_") name = "file";
  const [stem, extension] = splitExtension(name);
  if (DEVICE_NAMES.test(stem)) name = `${stem}_${extension}`;
  if (utf8Length(name) > MAX_NAME_BYTES) {
    const [longStem, longExtension] = splitExtension(name);
    const keep = utf8Length(longExtension) <= 32 ? longExtension : "";
    name = cut(longStem, MAX_NAME_BYTES - utf8Length(keep)).replace(/[.\s]+$/u, "") + keep;
    if (name === keep) name = `file${keep}`;
  }
  return name;
}

/** `name.ext`, then `name (1).ext`, `name (2).ext`… for the first `taken` says is free. */
export function numberedName(name: string, attempt: number): string {
  if (attempt === 0) return name;
  const [stem, extension] = splitExtension(name);
  return `${stem} (${attempt})${extension}`;
}

/** The hidden partial file kept next to the target while it arrives. */
export function partialName(name: string): string {
  return `.${name}.levikdrop`;
}
