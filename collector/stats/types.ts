import type { ZodType } from "zod";
import type { HttpOptions } from "../lib/http";
import type { Settings } from "../lib/config";

/**
 * A stats module fetches one source and returns the whole file it owns.
 * The runner decides whether it is due, keeps the previous file when it
 * fails or returns null, validates and writes the result
 * (collector/stats/index.ts).
 */
export interface StatsModule<T> {
  name: string;
  /** File name under data/stats/. */
  file: string;
  schema: ZodType<T>;
  /** Refetch once the previous file is older than this; 0 runs the module on every stats run. */
  maxAgeHours: number;
  /**
   * Stamps inside the file that move without the content changing (when an entry was last looked up). A file that
   * differs from the previous one only in these is still written, so the stamps persist, but it is reported as
   * `touched`, not `changed`: bookkeeping, no reason to rebuild the site.
   */
  volatile?: RegExp;
  /** The whole new file, or null when there is nothing to write this run (the previous file stays as it is). */
  fetch(ctx: StatsContext, previous: T | null): Promise<T | null>;
}

/** The HTTP client the modules use; tests inject a recorded one. */
export interface StatsHttp {
  json<T>(url: string, opts?: HttpOptions): Promise<T>;
  sleep(ms: number): Promise<void>;
}

export interface StatsContext {
  settings: Settings;
  now: Date;
  http: StatsHttp;
  /** CVE ids named by our published records, for the EPSS module. */
  recordCveIds: readonly string[];
  /** CVE ids named by our live records, for the fix module. */
  liveCveIds: readonly string[];
  /** CVE ids the other modules produced this run (recent CVEs, the KEV catalog), filled by the runner before the EPSS module runs. */
  extraCveIds: readonly string[];
  /** Each earlier module's file this run, by module name: what it just produced, or the previous file when it was skipped or failed (null when there is none). */
  produced: Readonly<Partial<Record<string, unknown>>>;
  log: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface StatsResult {
  changed: string[];
  /** Files written with only their volatile stamps moved (StatsModule.volatile): committed, but not a site change. */
  touched: string[];
  failed: string[];
  skipped: string[];
}
