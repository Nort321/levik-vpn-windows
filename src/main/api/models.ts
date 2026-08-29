export interface AuthChallengeResponse {
  ok: boolean;
  loginToken: string;
  activationCode?: string | null;
  activationUriComplete?: string | null;
  verificationCode?: string | null;
  verificationUriComplete?: string | null;
  pollIntervalSeconds: number;
  expiresAt: string;
}

export interface AuthStatusResponse {
  ok: boolean;
  state: "pending" | "authenticated" | "expired" | "denied";
  pollIntervalSeconds?: number;
  accessToken?: string | null;
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
