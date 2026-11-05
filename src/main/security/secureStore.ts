import { app, safeStorage } from "electron";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

interface SecureEnvelope {
  version: 1;
  ciphertext: string;
}

export class SecureStore {
  private readonly root = join(app.getPath("userData"), "secure-v1");

  constructor(private readonly onDamaged: (name: string) => void = () => {}) {}

  async put(name: string, plaintext: Uint8Array): Promise<void> {
    const destination = this.pathFor(name);
    await mkdir(dirname(destination), { recursive: true });
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error("Windows secure storage is unavailable");
    }
    const encrypted = safeStorage.encryptString(Buffer.from(plaintext).toString("base64"));
    const envelope: SecureEnvelope = { version: 1, ciphertext: encrypted.toString("base64") };
    const temporary = `${destination}.${process.pid}.tmp`;
    // Without the flush, a power loss after the rename can leave a file of zero bytes.
    await writeFile(temporary, JSON.stringify(envelope), { mode: 0o600, flush: true });
    await rename(temporary, destination);
  }

  async get(name: string): Promise<Buffer | null> {
    const destination = this.pathFor(name);
    let raw: string;
    try {
      raw = await readFile(destination, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    const ciphertext = envelopeCiphertext(raw);
    if (ciphertext === null) {
      // Nothing can be read from it again, and throwing would stop every later launch.
      await this.remove(name);
      this.onDamaged(name);
      return null;
    }
    const decrypted = safeStorage.decryptString(Buffer.from(ciphertext, "base64"));
    return Buffer.from(decrypted, "base64");
  }

  async remove(name: string): Promise<void> {
    await rm(this.pathFor(name), { force: true });
  }

  private pathFor(name: string): string {
    if (!/^[a-z0-9_]{1,64}$/.test(name)) throw new Error("Invalid secure storage key");
    return join(this.root, `${name}.json`);
  }
}

function envelopeCiphertext(raw: string): string | null {
  try {
    const envelope = JSON.parse(raw) as Partial<SecureEnvelope> | null;
    return envelope?.version === 1 && typeof envelope.ciphertext === "string" ? envelope.ciphertext : null;
  } catch {
    return null;
  }
}
