import type { FrameSocket } from "./framing";
import { joinRelay, relayControl } from "./relay";
import type { RelayEndpoint } from "./relay";
import { Session } from "./session";
import type { ReceiverWork, SenderWork, SessionOutcome } from "./session";

/**
 * One transfer's relay connection, docs/levik-drop.md "Relay": joins with a
 * fresh token, starts a session on every `peer`, rejoins after a break.
 */

export type LinkStatus = "connecting" | "waiting" | "session" | "retrying";

export interface LinkHost {
  /** The website's `connect`: a fresh token. Throws when the transfer cannot continue. */
  connect(): Promise<{ token: string; endpoints: RelayEndpoint[] }>;
  work(allowLan: boolean): SenderWork | ReceiverWork;
  status(status: LinkStatus): void;
  /** Every session's end; a final outcome stops the link. */
  outcome(outcome: SessionOutcome): void;
  /** The relay ended the connection for good (`ended`, `limit`) or `connect` failed. */
  stopped(reason: string, error?: unknown): void;
}

const RETRY_MS = [1_000, 3_000, 10_000, 30_000, 60_000];
/** Relay ends that mean: do not come back with this transfer. */
const FINAL_ENDS = new Set(["ended", "limit", "replaced"]);

export class RelayLink {
  private running = false;
  private socket: FrameSocket | null = null;
  private session: Session | null = null;
  private failures = 0;
  private allowLan = true;
  private wake: (() => void) | null = null;
  private readonly abort = new AbortController();

  constructor(private readonly host: LinkHost, private readonly join: typeof joinRelay = joinRelay) {}

  get current(): Session | null {
    return this.session;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    void this.loop();
  }

  /** Stops quietly: the session (if any) is only dropped, nothing is said to the other app. */
  stop(): void {
    this.running = false;
    this.abort.abort();
    this.session?.abort("stopped");
    this.socket?.close();
    this.wake?.();
  }

  /** After a pause or cancel the record leaves first, then the connection closes. */
  private closeAfterSaying(): void {
    this.running = false;
    this.abort.abort();
    this.socket?.closeGracefully();
    this.wake?.();
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      this.wake = () => {
        clearTimeout(timer);
        resolve();
      };
    });
    this.wake = null;
  }

  private async loop(): Promise<void> {
    while (this.running) {
      this.host.status(this.failures === 0 ? "connecting" : "retrying");
      let connection: { token: string; endpoints: RelayEndpoint[] };
      try {
        connection = await this.host.connect();
      } catch (error) {
        this.running = false;
        this.host.stopped("connect", error);
        return;
      }
      if (!this.running) return;
      try {
        this.socket = await this.join(connection.endpoints, connection.token, this.abort.signal);
      } catch {
        if (!this.running) return;
        await this.sleep(RETRY_MS[Math.min(this.failures++, RETRY_MS.length - 1)] ?? 60_000);
        continue;
      }
      const reason = await this.serve(this.socket);
      this.socket.close();
      this.socket = null;
      if (!this.running) return;
      if (reason && FINAL_ENDS.has(reason)) {
        this.running = false;
        this.host.stopped(reason);
        return;
      }
      await this.sleep(RETRY_MS[Math.min(this.failures++, RETRY_MS.length - 1)] ?? 60_000);
    }
  }

  /** Reads the relay until the connection ends; returns the relay's end reason, if it gave one. */
  private async serve(socket: FrameSocket): Promise<string | null> {
    for (;;) {
      let frame: Buffer;
      try {
        frame = await socket.next();
      } catch {
        this.session?.abort("relay connection closed");
        return null;
      }
      const control = relayControl(frame);
      if (!control) {
        this.session?.inbox.push(frame);
        continue;
      }
      switch (control.t) {
        case "wait":
          this.host.status("waiting");
          socket.watchIdle(0);
          break;
        case "gone":
          this.session?.abort("the other app left");
          this.host.status("waiting");
          socket.watchIdle(0);
          break;
        case "peer":
          this.session?.abort("new session");
          // The other app's keepalives come through now: silence means a dead path.
          socket.watchIdle(60_000);
          this.startSession(socket);
          break;
        case "end":
          this.session?.abort(`relay: ${control.reason}`);
          return control.reason;
      }
    }
  }

  private startSession(socket: FrameSocket): void {
    const session = new Session(socket, this.host.work(this.allowLan));
    this.session = session;
    this.host.status("session");
    void session.run().then((outcome) => {
      if (this.session === session) this.session = null;
      if (outcome.kind !== "lost") {
        this.host.outcome(outcome);
        this.closeAfterSaying();
        return;
      }
      if (outcome.lanBroke) this.allowLan = false;
      // A session that broke on its own needs a fresh `peer`: rejoining gives both apps one.
      const left = outcome.detail === "the other app left" || outcome.detail === "new session" || outcome.detail.startsWith("relay");
      this.host.outcome(outcome);
      if (!left && this.running && this.socket === socket) socket.close();
    });
  }

  /** Progress was made: the next break retries quickly again. */
  progressed(): void {
    this.failures = 0;
  }
}
