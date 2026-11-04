import { flagEnabled, type RemoteConfig } from "../platform/remoteConfig";
import type { LevikCoreStatus } from "./levikCore";

/**
 * Stage 2 of the Rust migration (docs/rust-desktop-migration-plan.md): logic
 * moves into the Rust core one function at a time, and both implementations
 * run side by side until the Rust one has proven itself on real computers.
 *
 * - "ts": TypeScript only, as before the migration (the remote kill switch).
 * - "shadow" (default): TypeScript decides; Rust computes the same answer and
 *   any difference is written to the diagnostics log.
 * - "rust": Rust decides; TypeScript answers when Rust fails or returns
 *   something malformed.
 */
export type CoreMode = "ts" | "shadow" | "rust";

/** What the app needs from the loaded module (bridge contract 2). */
export interface CoreBridge {
  functions(): string[];
  call(name: string, input: string): string;
}

export interface CoreStats {
  /** Calls answered by both implementations and compared. */
  compared: number;
  /** Calls where the answers differed. */
  differed: number;
  /** Calls where Rust threw or returned something unusable. */
  failed: number;
  /** Calls where the Rust answer was used ("rust" mode). */
  decided: number;
}

/** Counters since the app started, for the anonymous connection report. */
export interface CoreTally extends CoreStats {
  version: string;
  mode: CoreMode;
  /** Per function, only the ones that had a difference or a failure. */
  functions: Record<string, { differed: number; failed: number }>;
}

/** Lines per function and kind of problem per run; the counters keep counting. */
const REPORTS_PER_KIND = 3;
const MAX_PATH = 160;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** The value as `JSON.parse(JSON.stringify(value))` gives it: undefined fields gone, numbers plain. */
function toJson(value: unknown): Json {
  const text = JSON.stringify(value);
  if (text === undefined) return null;
  // JSON.parse of JSON.stringify output is JSON by construction.
  const parsed: Json = JSON.parse(text);
  return parsed;
}

function isObject(value: Json): value is { [key: string]: Json } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Where two JSON values first differ, as `$.services[2].name`; null when equal. Never includes values. */
export function jsonDifference(expected: Json, actual: Json, path = "$"): string | null {
  if (Array.isArray(expected) || Array.isArray(actual)) {
    if (!Array.isArray(expected) || !Array.isArray(actual)) return path;
    if (expected.length !== actual.length) return `${path} (длина ${expected.length} ≠ ${actual.length})`;
    for (let index = 0; index < expected.length; index += 1) {
      const found = jsonDifference(expected[index] ?? null, actual[index] ?? null, `${path}[${index}]`);
      if (found) return found;
    }
    return null;
  }
  if (isObject(expected) || isObject(actual)) {
    if (!isObject(expected) || !isObject(actual)) return path;
    const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
    for (const key of keys) {
      if (!(key in expected) || !(key in actual)) return `${path}.${safeKey(key)} (только с одной стороны)`;
      const found = jsonDifference(expected[key] ?? null, actual[key] ?? null, `${path}.${safeKey(key)}`);
      if (found) return found;
    }
    return null;
  }
  return Object.is(expected, actual) || expected === actual ? null : path;
}

/** Object keys can be server data (node ids); keep the shape, not the content. */
function safeKey(key: string): string {
  return /^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(key) ? key : "<ключ>";
}

/**
 * The mode the remote configuration asks for: `rust_core_off` is the kill
 * switch back to TypeScript, `rust_core_primary` hands decisions to Rust; both
 * roll out by the same private bucket as other flags. Shadow otherwise.
 */
export function coreModeFor(config: RemoteConfig | null, salt: string): CoreMode {
  if (flagEnabled(config, "rust_core_off", salt)) return "ts";
  if (flagEnabled(config, "rust_core_primary", salt)) return "rust";
  return "shadow";
}

/** Contract-2 functions of a loaded module, or null when the app runs on TypeScript alone. */
export function coreBridge(status: LevikCoreStatus): CoreBridge | null {
  return status.state === "loaded" ? status.module : null;
}

export class RustCore {
  private modeValue: CoreMode;
  private readonly available: ReadonlySet<string>;
  private readonly reported = new Map<string, number>();
  private readonly counters: CoreStats = { compared: 0, differed: 0, failed: 0, decided: 0 };
  private readonly problems = new Map<string, { differed: number; failed: number }>();

  constructor(
    private readonly bridge: CoreBridge | null,
    private readonly report: (line: string) => void,
    mode: CoreMode = "shadow",
    /** The loaded module's version, for the connection report. */
    private readonly version: string | null = null,
  ) {
    this.modeValue = mode;
    let names: string[] = [];
    try {
      names = bridge?.functions() ?? [];
    } catch (error) {
      this.report(`Rust-ядро: список функций недоступен (${messageOf(error)})`);
    }
    this.available = new Set(Array.isArray(names) ? names.filter((name) => typeof name === "string") : []);
  }

  get mode(): CoreMode {
    return this.modeValue;
  }

  setMode(mode: CoreMode): void {
    if (mode === this.modeValue) return;
    this.modeValue = mode;
    if (this.bridge) this.report(`Rust-ядро: режим ${mode}`);
  }

  stats(): CoreStats {
    return { ...this.counters };
  }

  /** Null when the app runs without the module. */
  tally(): CoreTally | null {
    if (!this.bridge || this.version === null) return null;
    const functions: CoreTally["functions"] = {};
    for (const [name, counts] of this.problems) functions[name] = { ...counts };
    return { ...this.counters, version: this.version, mode: this.modeValue, functions };
  }

  /** Whether `name` can run in Rust in this build. */
  has(name: string): boolean {
    return this.bridge !== null && this.available.has(name);
  }

  /**
   * One decision through the current mode. `typescript` is the existing code
   * and stays the answer unless the mode is "rust" and `accept` confirms the
   * Rust answer has the expected shape. Never throws because of Rust.
   */
  run<Output>(name: string, input: unknown, typescript: () => Output, accept?: (value: unknown) => value is Output): Output {
    if (this.modeValue === "ts" || !this.bridge || !this.available.has(name)) return typescript();
    if (this.modeValue === "rust" && accept) {
      const answer = this.ask(name, input);
      if (answer.ok && accept(answer.value)) {
        this.counters.decided += 1;
        return answer.value;
      }
      if (answer.ok) this.problem(name, "failed", "ответ не той формы");
      return typescript();
    }
    const expected = typescript();
    const answer = this.ask(name, input);
    if (answer.ok) {
      this.counters.compared += 1;
      const difference = jsonDifference(toJson(expected), toJson(answer.value));
      if (difference) this.problem(name, "differs", `расходится с TypeScript в ${difference.slice(0, MAX_PATH)}`);
    }
    return expected;
  }

  /** Pure operations on a typed native handle. Errors never expose key material. */
  runNative<Output>(name: string, rust: () => Output, typescript: () => Output, accept: (value: unknown) => value is Output): Output {
    if (this.modeValue === "ts") return typescript();
    const ask = (): { ok: true; value: Output } | { ok: false } => {
      try {
        const value = rust();
        if (!accept(value)) throw new Error("shape");
        return { ok: true, value };
      } catch {
        this.problem(name, "failed", "операция не выполнена");
        return { ok: false };
      }
    };
    if (this.modeValue === "rust") {
      const answer = ask();
      if (!answer.ok) return typescript();
      this.counters.decided += 1;
      return answer.value;
    }
    const expected = typescript();
    const answer = ask();
    if (answer.ok) {
      this.counters.compared += 1;
      // Crypto values are compared as scalars; no byte or value enters the journal.
      if (jsonDifference(toJson(expected), toJson(answer.value))) this.problem(name, "differs", "ответ расходится с TypeScript");
    }
    return expected;
  }

  private ask(name: string, input: unknown): { ok: true; value: unknown } | { ok: false } {
    try {
      const value: unknown = JSON.parse(this.bridge?.call(name, JSON.stringify(input) ?? "null") ?? "null");
      return { ok: true, value };
    } catch (error) {
      this.problem(name, "failed", `ошибка: ${messageOf(error).slice(0, MAX_PATH)}`);
      return { ok: false };
    }
  }

  private problem(name: string, kind: "differs" | "failed", detail: string): void {
    const counts = this.problems.get(name) ?? { differed: 0, failed: 0 };
    if (kind === "differs") {
      this.counters.differed += 1;
      counts.differed += 1;
    } else {
      this.counters.failed += 1;
      counts.failed += 1;
    }
    this.problems.set(name, counts);
    const key = `${name}:${kind}`;
    const count = (this.reported.get(key) ?? 0) + 1;
    this.reported.set(key, count);
    if (count <= REPORTS_PER_KIND) {
      this.report(`Rust-ядро: ${name} ${detail}${count === REPORTS_PER_KIND ? " (дальше только счётчик)" : ""}`);
    }
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
