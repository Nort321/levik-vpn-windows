import { describe, expect, it, vi } from "vitest";
import type { AppSnapshot } from "../src/shared/contracts";
import {
  createSupportNote,
  encryptSupportNote,
  MAX_SUPPORT_NOTE_BYTES,
  supportNoteText,
} from "../src/main/diagnostics/supportNote";
import { supportReportText } from "../src/main/diagnostics/supportReport";

/** Hands out 0, 1, 2, … so the note matches a vector made with the site's web crypto code. */
function countingRandom() {
  let next = 0;
  return (length: number) => Uint8Array.from({ length }, () => next++ & 0xff);
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("support notes", () => {
  it("matches the note site format", async () => {
    await expect(encryptSupportNote("Отчёт 🔐\nline", countingRandom())).resolves.toEqual({
      id: "AAECAwQFBgcICQoLDA0ODw",
      keyFragment: "v1.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8",
      keyCommitment: "1WwAKQVULENk7CnBRNXJ68BNiBFkYHDf0U-EBjKwleM",
      iv: "MDEyMzQ1Njc4OTo7",
      ciphertext: "Ro70CyG6R8fFpMivuq4IEAEnjPlWEXqxtM_-cBACbRJFve43",
    });
  });

  it("keeps the newest whole log lines within the note limit", () => {
    const log = Array.from({ length: 400 }, (_, index) => `2026-10-10T12:00:00Z подключение ${index + 1}`).join("\n");
    const text = supportNoteText("REPORT", log);
    expect(text.startsWith("REPORT\n=== Recent app log ===\n")).toBe(true);
    expect(text.endsWith("подключение 400\n")).toBe(true);
    expect(text).not.toContain("подключение 1\n");
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(MAX_SUPPORT_NOTE_BYTES);
    expect(supportNoteText("REPORT", "  ")).toBe("REPORT");
    expect(supportNoteText("REPORT", "line", 10)).toBe("REPORT");
  });

  it("posts anonymously and falls back to the second domain", async () => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValueOnce(json(201, { ok: true }));
    const url = await createSupportNote("REPORT", fetchImpl);

    expect(url).toMatch(/^https:\/\/note\.leviknet\.org\/[A-Za-z0-9_-]{22}#v1\.[A-Za-z0-9_-]{43}$/);
    const [target, init] = fetchImpl.mock.calls[1]!;
    expect(target).toBe("https://note.leviknet.org/api/notes");
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error" });
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["ciphertext", "expiresInDays", "id", "iv", "keyCommitment"]);
    expect(url).toContain(String(body.id));
    expect(url).not.toContain(String(body.keyCommitment));
  });

  it("does not retry a rejected note on the other domain", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(json(429, { ok: false, message: "Слишком много заметок." }));
    await expect(createSupportNote("REPORT", fetchImpl)).rejects.toThrow("Слишком много заметок.");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("describes the connection without account details or addresses", () => {
    const snapshot = {
      appVersion: "1.4.0",
      status: "error",
      statusDetail: "Сервер 203.0.113.7 не отвечает",
      account: { userLabel: "user@example.com" },
      servers: [{ id: "a", name: "Amsterdam", outbound: { protocol: "vless", streamSettings: { security: "reality" } } }],
      selectedServerId: "a",
      sessionStartedAt: null,
      settings: {
        automaticServer: false, routingMode: "global", splitTunnelMode: "off", autoReconnect: true,
        killSwitch: false, preventDnsLeaks: true, useDoh: false, antiDpiEnabled: false,
      },
    } as unknown as AppSnapshot;
    const text = supportReportText(snapshot, { system: "Windows 10.0.26100 (x64)", now: new Date("2026-10-10T12:00:00Z") });

    expect(text).toContain("Levik VPN для Windows 1.4.0");
    expect(text).toContain("Состояние: error — Сервер <ip> не отвечает");
    expect(text).toContain("Сервер: Amsterdam (vless-reality)");
    expect(text).not.toContain("example.com");
  });
});
