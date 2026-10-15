export interface AuthChallengeResponse {
  ok: boolean;
  loginToken: string;
  activationCode?: string | null;
  activationUriComplete?: string | null;
  verificationCode?: string | null;
  verificationUriComplete?: string | null;
  pollIntervalSeconds: number;
  expiresAt: string;
  matchNumber?: number;
  approvalRequested?: boolean;
  telegramUriComplete?: string;
}

export interface AuthStatusResponse {
  ok: boolean;
  /** "declined": someone picked a wrong number or said it was not them. */
  state: "pending" | "authenticated" | "expired" | "denied" | "declined";
  pollIntervalSeconds?: number;
  accessToken?: string | null;
  accountHint?: string;
}

export interface ApprovalsResponse {
  ok: boolean;
  /** Checked by parseApprovals. */
  approvals: unknown;
}

/** docs/app-platform.md "Remote"; the lists are checked by remoteCommands.ts. */
export interface RemoteDevicesResponse {
  ok: boolean;
  devices: unknown;
  commands: unknown;
}

export interface RemoteCommandsResponse {
  ok: boolean;
  commands: unknown;
}

export interface IssueCommandResponse {
  ok: boolean;
  command: unknown;
}

export interface ApprovalDecisionResponse {
  ok: boolean;
  state: "approved" | "declined";
}

export interface MobileAccountResponse {
  ok: boolean;
  user: { userKey: string; userLabel: string };
  subscriptions: Array<{
    uuid: string;
    tariffId?: string;
    title: string;
    status: string;
    expireAt?: string | null;
    traffic: { usedBytes: number; limitBytes: number };
    devices: { used: number; limit: number; items: Array<{ id: string; label: string }> };
    shield?: { supported?: boolean; enabled?: boolean };
    actions?: { renew?: boolean; revokeDevice?: boolean };
  }>;
}

export interface TunnelProfileEnvelope {
  algorithm: string;
  encryptedKey: string;
  iv: string;
  ciphertext: string;
  aad: string;
}

export interface TunnelProfileResponse {
  ok: boolean;
  profile: TunnelProfileEnvelope;
}

export interface SettingsDocumentResponse {
  ok: boolean;
  settings: Record<string, unknown>;
  revision: number;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface WebHandoffResponse {
  ok: boolean;
  url: string;
  expiresAt: string;
}
