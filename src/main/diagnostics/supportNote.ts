import { webcrypto } from "node:crypto";

/** The note site's limit on the plaintext, lib/notes/crypto.ts in levik_vpn_air. */
export const MAX_SUPPORT_NOTE_BYTES = 12_000;
export const SUPPORT_NOTE_HOSTS = ["note.leviknet.com", "note.leviknet.org"] as const;
const LOG_HEADER = "\n=== Recent app log ===\n";
const encoder = new TextEncoder();

export interface EncryptedSupportNote {
  id: string;
  keyFragment: string;
  keyCommitment: string;
  iv: string;
  ciphertext: string;
}

type RandomBytes = (length: number) => Uint8Array<ArrayBuffer>;
type Fetch = typeof fetch;

const secureRandom: RandomBytes = (length) => webcrypto.getRandomValues(new Uint8Array(length));
const base64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/**
 * Encrypts like Levik Notes in the browser: the server keeps the ciphertext,
 * the key stays in the link fragment, which is never sent to the server.
 */
export async function encryptSupportNote(plaintext: string, random: RandomBytes = secureRandom): Promise<EncryptedSupportNote> {
  const plaintextBytes = encoder.encode(plaintext);
  if (plaintextBytes.byteLength < 1 || plaintextBytes.byteLength > MAX_SUPPORT_NOTE_BYTES) {
    throw new Error("Отчёт слишком большой для заметки");
  }
  const id = base64Url(random(16));
  const keyBytes = random(32);
  const iv = random(12);
  const key = await webcrypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(`levik-notes:v1:${id}`), tagLength: 128 },
    key,
    plaintextBytes,
  );
  const commitment = await webcrypto.subtle.digest(
    "SHA-256",
    Buffer.concat([encoder.encode(`levik-notes:key:v1:${id}:`), keyBytes]),
  );
  return {
    id,
    keyFragment: `v1.${base64Url(keyBytes)}`,
    keyCommitment: base64Url(new Uint8Array(commitment)),
    iv: base64Url(iv),
    ciphertext: base64Url(new Uint8Array(ciphertext)),
  };
}

/** The report followed by the newest whole log lines that still fit in a note. */
export function supportNoteText(report: string, log: string, maxBytes = MAX_SUPPORT_NOTE_BYTES): string {
  let budget = maxBytes - Buffer.byteLength(report) - Buffer.byteLength(LOG_HEADER);
  if (budget <= 0 || !log.trim()) return report;
  const lines: string[] = [];
  for (const line of log.trimEnd().split("\n").reverse()) {
    const size = Buffer.byteLength(line) + 1;
    if (size > budget) break;
    lines.push(line);
    budget -= size;
  }
  if (!lines.length) return report;
  return `${report}${LOG_HEADER}${lines.reverse().join("\n")}\n`;
}

/**
 * Stores the note anonymously, without cookies or account credentials, and
 * returns the one-time link. Outages try the next domain; rejections do not.
 */
export async function createSupportNote(plaintext: string, fetchImpl: Fetch = fetch): Promise<string> {
  const note = await encryptSupportNote(plaintext);
  const body = JSON.stringify({
    id: note.id,
    keyCommitment: note.keyCommitment,
    iv: note.iv,
    ciphertext: note.ciphertext,
    expiresInDays: 7,
  });
  for (const host of SUPPORT_NOTE_HOSTS) {
    let response: Response;
    try {
      response = await fetchImpl(`https://${host}/api/notes`, {
        method: "POST",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body,
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      continue;
    }
    if (response.status === 201) return `https://${host}/${note.id}#${note.keyFragment}`;
    if (response.status >= 500) continue;
    throw new Error(await rejectionMessage(response));
  }
  throw new Error("Сервис заметок недоступен. Проверьте подключение к интернету и повторите попытку");
}

async function rejectionMessage(response: Response): Promise<string> {
  const body: unknown = await response.json().catch(() => null);
  if (typeof body === "object" && body !== null && "message" in body && typeof body.message === "string") {
    return body.message;
  }
  return `Не удалось создать отчёт (HTTP ${response.status})`;
}
