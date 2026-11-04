import { CoreSecureStore, secretValue, type OpenNativeStore } from "../core/nativeStore";
import type { RustCore } from "../core/rustCore";
import { app, safeStorage } from "electron";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

interface SecureEnvelope {
  version: 1;
  ciphertext: string;
}

export class SecureStore {
  private readonly root = join(app.getPath("userData"), "secure-v1");
  private native: CoreSecureStore | null = null;
  private pending: Promise<unknown> = Promise.resolve();

  useRustCore(core: RustCore, open: OpenNativeStore | undefined, report: () => void): void {
    this.native = new CoreSecureStore({ directory: app.getPath("userData"), backend: () => "windows",
      mode: () => core.mode, open, reference: () => this.nodeGet("device_identity"), report });
  }

  async put(name: string, plaintext: Uint8Array): Promise<void> {
    this.pathFor(name);
    const snapshot = Buffer.from(plaintext);
    try {
      await this.enqueue(async () => {
        const native = await this.native?.handle();
        if (native) await native.put(name, snapshot.toString("base64"));
        else await this.nodePut(name, snapshot);
      });
    } finally { snapshot.fill(0); }
  }

  async get(name: string): Promise<Buffer | null> {
    this.pathFor(name);
    return this.enqueue(async () => {
      const native = await this.native?.handle();
      return native ? secretValue(await native.get(name)) : this.nodeGet(name);
    });
  }

  async remove(name: string): Promise<void> {
    this.pathFor(name);
    return this.enqueue(async () => {
      const native = await this.native?.handle();
      if (native) await native.remove(name);
      else await this.nodeRemove(name);
    });
  }

  private enqueue<Value>(operation: () => Promise<Value>): Promise<Value> {
    const next = this.pending.then(operation);
    this.pending = next.catch(() => {});
    return next;
  }


  private async nodePut(name: string, plaintext: Uint8Array): Promise<void> {
    const destination = this.pathFor(name);
    await mkdir(dirname(destination), { recursive: true });
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error("Windows secure storage is unavailable");
    }
    const encrypted = safeStorage.encryptString(Buffer.from(plaintext).toString("base64"));
    const envelope: SecureEnvelope = { version: 1, ciphertext: encrypted.toString("base64") };
    const temporary = `${destination}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(envelope), { mode: 0o600 });
    await rename(temporary, destination);
  }

  private async nodeGet(name: string): Promise<Buffer | null> {
    const destination = this.pathFor(name);
    let raw: string;
    try {
      raw = await readFile(destination, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    const envelope = JSON.parse(raw) as Partial<SecureEnvelope>;
    if (envelope.version !== 1 || typeof envelope.ciphertext !== "string") {
      throw new Error("Invalid secure storage envelope");
    }
    const decrypted = safeStorage.decryptString(Buffer.from(envelope.ciphertext, "base64"));
    return Buffer.from(decrypted, "base64");
  }

  private async nodeRemove(name: string): Promise<void> {
    await rm(this.pathFor(name), { force: true });
  }

  private pathFor(name: string): string {
    if (!/^[a-z0-9_]{1,64}$/.test(name)) throw new Error("Invalid secure storage key");
    return join(this.root, `${name}.json`);
  }
}

