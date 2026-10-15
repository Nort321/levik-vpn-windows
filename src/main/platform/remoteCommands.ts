import { constants, createPublicKey, generateKeyPairSync, privateDecrypt, publicEncrypt, type KeyObject } from "node:crypto";

import {
  isRemoteCommand,
  type IssuedCommand,
  type RemoteCommandState,
  type RemoteDevice,
} from "../../shared/remote";

/** A command for this app; an unknown name is kept so the app can answer "unsupported". */
export interface DeliveredCommand {
  id: string;
  command: string;
  replyKey: string | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATES: readonly RemoteCommandState[] = ["pending", "delivered", "done", "failed", "unsupported", "expired"];
const PLATFORMS: readonly RemoteDevice["platform"][] = ["android", "windows", "macos", "linux"];
const NOTE_LINK = /^https:\/\/note\.leviknet\.(?:org|com)\/[A-Za-z0-9_-]+#[A-Za-z0-9_-]+$/;
const MAX_ITEMS = 50;

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function text(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

export function parseDeliveredCommands(value: unknown): DeliveredCommand[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_ITEMS).flatMap((item) => {
    const entry = record(item);
    const id = typeof entry?.id === "string" && UUID.test(entry.id) ? entry.id : null;
    const command = text(entry?.command, 40);
    if (!id || !command) return [];
    return [{ id, command, replyKey: text(entry?.replyKey, 1000) }];
  });
}

export function parseRemoteDevices(value: unknown): RemoteDevice[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_ITEMS).flatMap((item) => {
    const entry = record(item);
    const deviceId = text(entry?.deviceId, 160);
    const name = text(entry?.name, 160);
    const platform = PLATFORMS.find((candidate) => candidate === entry?.platform);
    if (!entry || !deviceId || !name || !platform) return [];
    const presence = record(entry.presence);
    const country = typeof presence?.country === "string" && /^[A-Z]{2}$/.test(presence.country) ? presence.country : null;
    return [{
      deviceId,
      name,
      platform,
      appVersion: text(entry.appVersion, 40),
      current: entry.current === true,
      remote: entry.remote === true,
      online: presence?.online === true,
      vpnConnected: presence?.vpnConnected === true,
      country,
    }];
  });
}

export function parseIssuedCommands(value: unknown): IssuedCommand[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_ITEMS).flatMap((item) => {
    const entry = record(item);
    const id = typeof entry?.id === "string" && UUID.test(entry.id) ? entry.id : null;
    const deviceId = text(entry?.deviceId, 160);
    const state = STATES.find((candidate) => candidate === entry?.state);
    if (!entry || !id || !deviceId || !state || !isRemoteCommand(entry.command)) return [];
    return [{ id, deviceId, command: entry.command, state, detail: text(entry.detail, 1000) }];
  });
}

/** The diagnostics note link, encrypted to the sender's key (RSA-OAEP, SHA-256). */
export function sealForReply(replyKey: string, link: string): string {
  const key = createPublicKey({ key: Buffer.from(replyKey, "base64"), format: "der", type: "spki" });
  return publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(link)).toString("base64");
}

/** A fresh key for one diagnostics request; the private half never leaves memory. */
export function createReplyKey(): { replyKey: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { replyKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"), privateKey };
}

/** The note link from a finished diagnostics command, or null when it is not one. */
export function openReply(privateKey: KeyObject, sealed: string): string | null {
  try {
    const link = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(sealed, "base64"))
      .toString("utf8");
    return NOTE_LINK.test(link) ? link : null;
  } catch {
    return null;
  }
}
