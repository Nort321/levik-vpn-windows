import type { GuestSnapshot } from "../../shared/sharing";
import type { GuestInvitation } from "./guestSession";
import { buildGuestConfig } from "./guestSession";

export interface GuestConnectionDependencies {
  interfaceFor(host: string): string;
  enableProtection(): Promise<void>;
  protectionActive(): boolean;
  start(config: Record<string, unknown>, network: string, current: () => boolean): Promise<void>;
  allowTunnel(): Promise<void>;
  healthy(): Promise<boolean>;
  stop(): Promise<void>;
  releaseProtection(): Promise<void>;
  changed(snapshot: GuestSnapshot | null, detail: string): void;
}

/** Owns ephemeral credentials and protection independently from account VPN lifecycle. */
export class GuestConnection {
  private invitation: GuestInvitation | null = null;
  private currentState: GuestSnapshot | null = null;
  private generation = 0;
  private operation: Promise<void> = Promise.resolve();
  private deadline: ReturnType<typeof setTimeout> | null = null;
  private probing = false;
  private failedProbes = 0;

  constructor(private readonly dependencies: GuestConnectionDependencies) {}

  get active(): boolean { return this.invitation !== null; }
  get snapshot(): GuestSnapshot | null { return this.currentState; }

  connect(invitation: GuestInvitation): Promise<void> {
    if (this.active) throw new Error("Сначала завершите текущее гостевое подключение.");
    // Reject disconnected/mismatched local networks before changing Windows networking.
    const network = this.dependencies.interfaceFor(invitation.host);
    this.invitation = invitation;
    this.deadline = setTimeout(() => void this.block(true), Math.max(0, invitation.expiresAt - Date.now()));
    return this.begin(network);
  }

  retry(): Promise<void> {
    const invitation = this.invitation;
    if (!invitation || this.currentState?.phase === "connecting" || this.currentState?.phase === "connected") return Promise.resolve();
    if (invitation.expiresAt <= Date.now() || this.currentState?.phase === "expired") return this.block(true);
    return this.begin(this.dependencies.interfaceFor(invitation.host));
  }

  private begin(network: string): Promise<void> {
    const invitation = this.invitation;
    if (!invitation) return Promise.resolve();
    const generation = ++this.generation;
    const current = (): boolean => this.generation === generation && this.invitation === invitation && invitation.expiresAt > Date.now();
    this.publish("connecting", "Подключаемся к телефону. VPN владельца должен оставаться включённым.");
    return this.serialize(async () => {
      try {
        if (!current()) return;
        await this.dependencies.enableProtection();
        if (!current()) return;
        await this.dependencies.start(buildGuestConfig(invitation), network, current);
        if (!current()) return;
        await this.dependencies.allowTunnel();
        if (!current()) return;
        const healthy = await this.dependencies.healthy();
        if (!current()) return;
        if (!healthy) throw new Error("guest_unreachable");
        this.failedProbes = 0;
        this.publish("connected", `Интернет через ${invitation.name}. DNS и захваченный трафик идут через телефон.`);
      } catch {
        await this.dependencies.stop().catch(() => {});
        if (current()) this.publish("blocked", this.dependencies.protectionActive()
          ? "Не удалось подтвердить VPN телефона. Трафик заблокирован. Проверьте Wi-Fi, раздачу и VPN владельца, затем повторите подключение."
          : "Гостевое подключение не запущено: Windows не включила защиту от прямого выхода. Обычный интернет может оставаться доступным. Проверьте запуск от имени администратора.");
      }
    });
  }

  async probe(): Promise<void> {
    if (this.probing || this.currentState?.phase !== "connected") return;
    const generation = this.generation;
    this.probing = true;
    try {
      const healthy = await this.dependencies.healthy().catch(() => false);
      if (generation !== this.generation) return;
      this.failedProbes = healthy ? 0 : this.failedProbes + 1;
      if (this.failedProbes >= 3) await this.block(false);
    } finally { this.probing = false; }
  }

  coreExited(): void {
    if (this.currentState?.phase === "connected") void this.block(false);
  }

  private block(expired: boolean): Promise<void> {
    if (!this.invitation) return Promise.resolve();
    ++this.generation;
    const protectedTraffic = this.dependencies.protectionActive() ? "Трафик заблокирован." : "Защита от прямого выхода не подтверждена.";
    this.publish(expired ? "expired" : "blocked", expired
      ? `Время гостевого доступа истекло. ${protectedTraffic} Завершите подключение и получите новое приглашение.`
      : `Связь с телефоном потеряна. ${protectedTraffic} Вернитесь в Wi-Fi телефона и повторите подключение.`);
    return this.serialize(() => this.dependencies.stop().catch(() => {}));
  }

  disconnect(): Promise<void> {
    ++this.generation;
    if (this.deadline) clearTimeout(this.deadline);
    this.deadline = null;
    return this.serialize(async () => {
      await this.dependencies.stop();
      await this.dependencies.releaseProtection();
      this.invitation = null;
      this.currentState = null;
      this.dependencies.changed(null, "Гостевое подключение завершено. Обычное подключение к интернету восстановлено.");
    });
  }

  private publish(phase: GuestSnapshot["phase"], detail: string): void {
    if (!this.invitation) return;
    this.currentState = { name: this.invitation.name, expiresAt: this.invitation.expiresAt, phase };
    this.dependencies.changed(this.currentState, detail);
  }

  private serialize(action: () => Promise<void>): Promise<void> {
    const pending = this.operation.then(action);
    this.operation = pending.catch(() => {});
    return pending;
  }
}
