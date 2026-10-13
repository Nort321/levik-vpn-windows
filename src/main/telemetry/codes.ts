// Codes from docs/connection-telemetry.md. Raw errors and log lines never
// leave the device; only these fixed identifiers do.

export type ProtocolName =
  | "vless-reality" | "vless-xhttp" | "vless-ws" | "vless-grpc" | "vless-tcp"
  | "hysteria2" | "tuic" | "trojan" | "shadowsocks" | "relay" | "yandex" | "other";

/** Health probe failure code for an error raised by a socket or TLS layer. */
export function probeErrorCode(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : "";
  switch (code) {
    case "ECONNREFUSED":
      return "refused";
    case "ECONNRESET":
    case "EPIPE":
    case "ECONNABORTED":
      return "reset";
    case "ETIMEDOUT":
      return "timeout";
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return "dns";
  }
  if (/^ERR_(TLS|SSL)|CERT|^UNABLE_TO_VERIFY|SELF_SIGNED/.test(code)) return "tls";
  return "other";
}

const CORE_LOG_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/only one usage of each socket address|address already in use|access a socket in a way forbidden/i, "port_unavailable"],
  [/wintun|tun device|failed to (create|open|start) tun/i, "tun_failed"],
  [/reality/i, "reality_verify_failed"],
  [/no recent network activity|idle timeout/i, "quic_idle_timeout"],
  [/handshake did not complete|crypto_error|quic.*handshake/i, "quic_handshake"],
  [/tls: |tls handshake|x509|certificate/i, "tls_handshake"],
  [/authenticat\w* fail|invalid user|unauthori[sz]ed|status 40[13]\b/i, "auth_failed"],
  [/connection refused|actively refused/i, "dial_refused"],
  [/connection reset|forcibly closed|broken pipe|wsarecv|wsasend/i, "conn_reset"],
  [/closed pipe|use of closed network connection/i, "closed_pipe"],
  // An empty answer (an AAAA query without IPv6) differs from a failed lookup.
  [/empty response/i, "dns_empty"],
  [/no such host|failed to (resolve|lookup)|lookup .* (failed|timeout)|app\/dns/i, "dns_failed"],
  [/i\/o timeout|deadline exceeded|timed? ?out/i, "dial_timeout"],
];

const SEVERITY = /\[(warning|error)\]|\b(WARN|ERROR|FATAL)\b/i;
const FAILURE = /fail|error|timeout|timed out|refused|reset|closed|invalid|reject|unauthori/i;
// Xray prints why it could not start, and Go prints a crash, without a level.
const CORE_START_FAILURE = /\bFailed to start:/;
const CORE_CRASH = /\bpanic:|\bfatal error:/;

/**
 * Xray ("[Warning] ...") and sing-box ("ERROR ...") problem lines reduced to a
 * code. Informational lines, including Xray's own start banner, return null.
 */
export function classifyCoreLogLine(line: string): string | null {
  if (CORE_CRASH.test(line)) return "core_panic";
  const startFailure = CORE_START_FAILURE.test(line);
  if (!startFailure && (!SEVERITY.test(line) || !FAILURE.test(line))) return null;
  for (const [pattern, code] of CORE_LOG_PATTERNS) {
    if (pattern.test(line)) return code;
  }
  return startFailure ? "core_start" : "other";
}

/** Adapter names are localized and user-editable, so this is a best guess. */
export function networkTypeOfInterface(name: string | null): "wifi" | "cellular" | "ethernet" | "unknown" {
  if (!name) return "unknown";
  if (/wi-?fi|wlan|wireless|беспровод/i.test(name)) return "wifi";
  if (/cellular|mobile|wwan|lte|5g|сотов|мобильн/i.test(name)) return "cellular";
  if (/ethernet|local area connection|подключение по локальной сети/i.test(name)) return "ethernet";
  return "unknown";
}

type ServerLike = { tuic?: unknown; outbound: Record<string, unknown> };

export function protocolOf(server: ServerLike): ProtocolName {
  if (server.tuic) return "tuic";
  const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol.toLowerCase() : "";
  const stream = isRecord(server.outbound.streamSettings) ? server.outbound.streamSettings : {};
  const network = typeof stream.network === "string" ? stream.network.toLowerCase() : "tcp";
  const security = typeof stream.security === "string" ? stream.security.toLowerCase() : "none";
  switch (protocol) {
    case "vless":
      if (network === "xhttp" || network === "splithttp") return "vless-xhttp";
      if (network === "ws") return "vless-ws";
      if (network === "grpc") return "vless-grpc";
      return security === "reality" ? "vless-reality" : "vless-tcp";
    case "hysteria":
    case "hysteria2":
      return "hysteria2";
    case "tuic":
      return "tuic";
    case "trojan":
      return "trojan";
    case "shadowsocks":
      return "shadowsocks";
    default:
      return "other";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
