import { generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";
import type { SourceFile, TargetFile } from "./files";
import type { ManifestFile } from "./protocol";
import { keyHash } from "./protocol";
import type { Identity, Trust } from "./session";

/**
 * What survives a restart: the files of open transfers, partial-file paths,
 * the receive folder. Keys and pins live in the platform's secure storage.
 */

export interface Secrets {
  get(name: string): Promise<Buffer | null>;
  put(name: string, value: Uint8Array): Promise<void>;
  remove(name: string): Promise<void>;
}

export interface StoredSender {
  id: string;
  role: "sender";
  peerDeviceId: string;
  files: SourceFile[];
  /** Set when the transfer ended; kept for the history while the website lists it. */
  finished: boolean;
}

export interface StoredReceiver {
  id: string;
  role: "receiver";
  peerDeviceId: string;
  manifest: ManifestFile[] | null;
  folder: string | null;
  targets: TargetFile[] | null;
  decision: "accepted" | "declined" | null;
  finished: boolean;
}

export type StoredTransfer = StoredSender | StoredReceiver;

interface LocalState {
  version: 1;
  folder: string | null;
  transfers: StoredTransfer[];
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function absolute(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length < 4_096 && isAbsolute(value);
}

function parseSource(value: unknown): SourceFile | null {
  if (!record(value) || !absolute(value.path) || typeof value.name !== "string" || !safeCount(value.size) || !safeCount(value.mtimeMs)) return null;
  return { path: value.path, name: value.name, size: value.size, mtimeMs: value.mtimeMs };
}

function parseTarget(value: unknown): TargetFile | null {
  if (!record(value) || typeof value.name !== "string" || !safeCount(value.size) || !absolute(value.partial)) return null;
  if (value.final !== null && !absolute(value.final)) return null;
  return { name: value.name, size: value.size, partial: value.partial, final: value.final };
}

function parseManifest(value: unknown): ManifestFile[] | null {
  if (!Array.isArray(value)) return null;
  const files = value.flatMap((item) => record(item) && typeof item.name === "string" && safeCount(item.size) ? [{ name: item.name, size: item.size }] : []);
  return files.length === value.length ? files : null;
}

function parseTransfer(value: unknown): StoredTransfer | null {
  if (!record(value) || typeof value.id !== "string" || typeof value.peerDeviceId !== "string") return null;
  const finished = value.finished === true;
  if (value.role === "sender") {
    if (!Array.isArray(value.files)) return null;
    const files = value.files.map(parseSource);
    if (files.some((file) => file === null)) return null;
    return { id: value.id, role: "sender", peerDeviceId: value.peerDeviceId, files: files as SourceFile[], finished };
  }
  if (value.role !== "receiver") return null;
  const targets = value.targets === null ? null : Array.isArray(value.targets) ? value.targets.map(parseTarget) : null;
  if (targets?.some((target) => target === null)) return null;
  const decision = value.decision === "accepted" || value.decision === "declined" ? value.decision : null;
  return {
    id: value.id,
    role: "receiver",
    peerDeviceId: value.peerDeviceId,
    manifest: value.manifest === null ? null : parseManifest(value.manifest),
    folder: absolute(value.folder) ? value.folder : null,
    targets: targets as TargetFile[] | null,
    decision,
    finished,
  };
}

export class DropStore {
  private state: LocalState = { version: 1, folder: null, transfers: [] };
  private writing: Promise<void> = Promise.resolve();

  constructor(private readonly path: string) {}

  async load(): Promise<void> {
    try {
      const value: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (!record(value) || value.version !== 1 || !Array.isArray(value.transfers)) return;
      this.state = {
        version: 1,
        folder: absolute(value.folder) ? value.folder : null,
        transfers: value.transfers.map(parseTransfer).filter((item): item is StoredTransfer => item !== null),
      };
    } catch {
      // No state yet, or a broken file: start empty.
    }
  }

  get folder(): string | null {
    return this.state.folder;
  }

  set folder(folder: string | null) {
    this.state.folder = folder;
    this.save();
  }

  get transfers(): readonly StoredTransfer[] {
    return this.state.transfers;
  }

  find(id: string): StoredTransfer | undefined {
    return this.state.transfers.find((item) => item.id === id);
  }

  put(transfer: StoredTransfer): void {
    this.state.transfers = [...this.state.transfers.filter((item) => item.id !== transfer.id), transfer];
    this.save();
  }

  remove(id: string): void {
    this.state.transfers = this.state.transfers.filter((item) => item.id !== id);
    this.save();
  }

  /** Writes are queued: the last state always wins. */
  save(): void {
    const text = JSON.stringify(this.state);
    this.writing = this.writing.then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.${process.pid}.tmp`;
      await writeFile(temporary, text, { mode: 0o600 });
      await rename(temporary, this.path);
    }).catch(() => {});
  }

  flush(): Promise<void> {
    return this.writing;
  }
}

const IDENTITY = "drop_identity";
const PINS = "drop_pins";

/** This app's identity key, made once. */
export async function loadIdentity(secrets: Secrets): Promise<Identity> {
  const stored = await secrets.get(IDENTITY).catch(() => null);
  if (stored) {
    try {
      const privateKey = createPrivateKey({ key: stored, format: "der", type: "pkcs8" });
      if (privateKey.asymmetricKeyDetails?.namedCurve === "prime256v1") {
        return { privateKey, spki: createPublicKey(privateKey).export({ type: "spki", format: "der" }) };
      }
    } catch {
      // A broken key is replaced; the other apps then see it as changed.
    }
  }
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  await secrets.put(IDENTITY, pair.privateKey.export({ type: "pkcs8", format: "der" }));
  return { privateKey: pair.privateKey, spki: pair.publicKey.export({ type: "spki", format: "der" }) };
}

/** The key each peer device showed when its user confirmed the code. */
export class Pins {
  private pins: Record<string, string> = {};

  constructor(private readonly secrets: Secrets) {}

  async load(): Promise<void> {
    try {
      const raw = await this.secrets.get(PINS);
      const value: unknown = raw ? JSON.parse(raw.toString("utf8")) : {};
      if (record(value)) {
        this.pins = Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string" && /^[0-9a-f]{64}$/.test(entry[1])));
      }
    } catch {
      this.pins = {};
    }
  }

  trust(deviceId: string, peerKey: Buffer): Trust {
    const pinned = this.pins[deviceId];
    if (!pinned) return "new";
    return pinned === keyHash(peerKey) ? "trusted" : "changed";
  }

  async pin(deviceId: string, peerKey: Buffer): Promise<void> {
    this.pins = { ...this.pins, [deviceId]: keyHash(peerKey) };
    await this.secrets.put(PINS, Buffer.from(JSON.stringify(this.pins), "utf8"));
  }
}
