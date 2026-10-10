import { appendFile, mkdir, readFile, rename, stat } from "node:fs/promises";
import { join } from "node:path";

const MAX_FILE_BYTES = 1024 * 1024;
const FLUSH_DELAY_MS = 1_000;
const MAX_BUFFERED_LINES = 2_000;
const OWN_HOSTS = /^(?:[a-z0-9-]+\.)*leviknet\.(?:org|com)$/i;

/**
 * Removes what could identify the user or what they visit: addresses,
 * domains other than Levik's own, identifiers, e-mails and URL queries.
 */
export function redactLogLine(line: string): string {
  return line
    .replace(/[\u0000-\u001f]/g, " ")
    .replace(/\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g, "<email>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<id>")
    .replace(/\?[^\s"'<>]+/g, "?<query>")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "<ip>")
    // Full or "::"-compressed IPv6; clock times such as 13:14:04 do not match.
    .replace(/(?<![\w:.])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)(?![\w:])/gi, "<ip6>")
    .replace(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi, (host) => OWN_HOSTS.test(host) || /^\w+\.(?:exe|dll|json|ts|js|go)$/i.test(host) ? host : "<host>")
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, "<secret>")
    .slice(0, 1_000);
}

/**
 * Local diagnostics for support requests. Stays on this computer; the user
 * decides whether to attach it to a ticket. Two files of at most 1 MiB.
 */
export class DiskLog {
  private buffer: string[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private writing: Promise<void> = Promise.resolve();

  constructor(private readonly directory: string, private readonly now: () => Date = () => new Date()) {}

  write(line: string): void {
    // Per-connection core lines name visited sites and add no diagnostic value.
    if (/\[(?:Info|Debug)\]|\bINFO\b|\bDEBUG\b/.test(line)) return;
    if (this.buffer.length >= MAX_BUFFERED_LINES) this.buffer.shift();
    this.buffer.push(`${this.now().toISOString()} ${redactLogLine(line)}`);
    if (!this.timer) {
      this.timer = setTimeout(() => void this.flush(), FLUSH_DELAY_MS);
      this.timer.unref?.();
    }
  }

  flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.buffer.length) return this.writing;
    const chunk = `${this.buffer.join("\n")}\n`;
    this.buffer = [];
    this.writing = this.writing.then(() => this.append(chunk)).catch(() => {});
    return this.writing;
  }

  /** The newest lines, oldest first, for a support report. */
  async read(maxBytes = MAX_FILE_BYTES): Promise<string> {
    await this.flush();
    const parts = await Promise.all([this.path(".1"), this.path("")].map((file) => readFile(file, "utf8").catch(() => "")));
    const text = parts.join("");
    return text.length > maxBytes ? text.slice(text.indexOf("\n", text.length - maxBytes) + 1) : text;
  }

  private async append(chunk: string): Promise<void> {
    await mkdir(this.directory, { recursive: true });
    const size = await stat(this.path("")).then((info) => info.size).catch(() => 0);
    if (size + Buffer.byteLength(chunk) > MAX_FILE_BYTES) await rename(this.path(""), this.path(".1")).catch(() => {});
    await appendFile(this.path(""), chunk, { mode: 0o600 });
  }

  private path(suffix: string): string {
    return join(this.directory, `levik-vpn.log${suffix}`);
  }
}
