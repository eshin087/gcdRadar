import type { LiveData } from "../live";
import type { PanelData } from "../panel";
import type { HomeStats } from "../stats-schema";
import type { Lane, PatchStatus, Severity } from "../taxonomy";

/**
 * The live layer's shapes and the rules the browser applies to them. The
 * site is rebuilt twice a day, the collector sweeps every fifteen minutes;
 * between rebuilds each sweep publishes what the home page and the live
 * board draw, as small ready-made files (lib/live/build.ts builds them with
 * the functions the site build uses, collector/live.ts publishes them, the
 * Worker's /v1/live serves them, components/live/useLive.ts swaps them in).
 *
 * A page shows one sweep at a time: its numbers, its rows and the time on
 * its label all come from the same file, so the label can never be fresher
 * than the data beside it.
 *
 * Nothing here imports a dataset module: the browser's bundle takes the
 * types and three small functions.
 */

/**
 * Bumped when a file's shape changes; the page ignores a version it does not know and keeps what it was built with.
 * 2: My stack's tiles carry their tier and new critical CVEs, and stack.json is written compactly (lib/panel/picks.ts packStack).
 */
export const LIVE_VERSION = 2;

/** The branch the collector publishes the files to (one commit, replaced every sweep; Vercel never deploys it). */
export const LIVE_BRANCH = "live";

/**
 * Records created in this many days travel in full with every file: a
 * record newer than the site's last rebuild has no page of its own yet, and
 * the page shows it from here instead of linking to a 404.
 */
export const FRESH_RECORD_DAYS = 3;

export const LIVE_FILES = { home: "home.json", board: "board.json", stack: "stack.json" } as const;

/** The file names the Worker passes through: the two views, the stack candidates, and the lists the home page's numbers open. */
export const LIVE_FILE_PATTERN = /^(?:home|board|stack|cves-day|cves-week|kev-week|breaches-\d{4}-\d{2})\.json$/;

/**
 * What the home page draws, under the names lib/home-data.ts gives them:
 * the page is built from one of these and redraws from a newer one.
 */
export interface HomeView {
  /** The instant the windows count back from: the build's clock, or the sweep's end. */
  now: string;
  today: string;
  /** When the sweep behind this view finished. */
  lastUpdated: string | null;
  columns: { patch: { live: number }; breach: { live: number }; supply_chain: number; research: number };
  /** The counters and the lists they open; the charts' series stay on /trends and are empty here. */
  stats: HomeStats;
  panel: Pick<PanelData, "verdict" | "stack" | "ledger" | "week" | "sieve">;
  briefing: { week: string; headline: string; start: string; end: string } | null;
}

/** What the live board draws: lib/live.ts's model without the radar scope (the board has none). */
export type BoardView = Omit<LiveData, "scope">;

/** A record too new to have a page, with enough to read it in a drawer and reach its sources. */
export interface FreshRecord {
  slug: string;
  id: string;
  title: string;
  summary: string;
  action: string;
  lane: Lane;
  severity: Severity;
  patch_status: PatchStatus;
  cvss: number | null;
  cve_ids: string[];
  products: string[];
  first_reported: string;
  created_at: string;
  /** The first sources, the primary one first. */
  sources: { publisher: string; title: string; url: string }[];
}

export interface LiveFile<V> {
  v: number;
  /** When the sweep that produced the file finished (ISO 8601): the time the page's label states. */
  sweep: string;
  /** Every record created at or after this instant is in `fresh`. */
  fresh_since: string;
  view: V;
  fresh: FreshRecord[];
}

export type HomeLive = LiveFile<HomeView>;
export type BoardLive = LiveFile<BoardView>;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * A fetched file, or null for anything the page cannot trust: another
 * version, a missing part, a time that does not parse or lies in the
 * future by more than a clock's drift. `has` names the keys the view must
 * hold, so a half-written or foreign payload never reaches a component.
 */
export function parseLiveFile<V>(json: unknown, has: readonly string[], nowMs: number): LiveFile<V> | null {
  if (!isObject(json) || json.v !== LIVE_VERSION) return null;
  if (typeof json.sweep !== "string" || typeof json.fresh_since !== "string") return null;
  const sweep = Date.parse(json.sweep);
  const since = Date.parse(json.fresh_since);
  if (!Number.isFinite(sweep) || !Number.isFinite(since) || since > sweep || sweep > nowMs + 5 * 60_000) return null;
  if (!isObject(json.view) || !Array.isArray(json.fresh)) return null;
  for (const key of has) if (json.view[key] === undefined || json.view[key] === null) return null;
  for (const r of json.fresh) if (!isObject(r) || typeof r.slug !== "string" || typeof r.created_at !== "string" || !Array.isArray(r.sources)) return null;
  return json as unknown as LiveFile<V>;
}

/**
 * Whether a file replaces what the page was built with. It must be from a
 * later sweep, and the build must be recent enough that every record
 * without a page is in the file's `fresh` list: a page built before
 * `fresh_since` could hold a row whose record has neither a page nor a
 * drawer, so it keeps its own snapshot and says how old that is.
 */
export function liveApplies(builtSweep: string | null, file: Pick<LiveFile<unknown>, "sweep" | "fresh_since">): boolean {
  if (!builtSweep) return false;
  const built = Date.parse(builtSweep);
  return Number.isFinite(built) && Date.parse(file.sweep) > built && Date.parse(file.fresh_since) <= built;
}

/** The records of a file that the built site has no page for: those created after the sweep the site was built from. */
export function pageless(file: Pick<LiveFile<unknown>, "fresh">, builtSweep: string | null): Map<string, FreshRecord> {
  const built = builtSweep ? Date.parse(builtSweep) : NaN;
  const out = new Map<string, FreshRecord>();
  if (!Number.isFinite(built)) return out;
  for (const r of file.fresh) if (Date.parse(r.created_at) > built) out.set(r.slug, r);
  return out;
}

/** A list file's address on the live layer: the build's "/stats/<name>" as "<base>/<name>?s=<sweep>", so each sweep's lists are fetched once. */
export function liveListUrl(base: string, file: string, sweep: string): string {
  return `${base}/${file.replace(/^\/stats\//, "")}?s=${encodeURIComponent(sweep)}`;
}

/** The view with its list files pointed at the sweep that produced it, so a number and the list it opens come from one sweep. */
export function withLiveLists(view: HomeView, base: string, sweep: string): HomeView {
  const l = view.stats.lists;
  const at = (file: string) => liveListUrl(base, file, sweep);
  return {
    ...view,
    stats: {
      ...view.stats,
      lists: {
        cves_day: { ...l.cves_day, file: at(l.cves_day.file) },
        cves_week: { ...l.cves_week, file: at(l.cves_week.file) },
        kev_week: { ...l.kev_week, file: at(l.kev_week.file) },
        breaches_month: { ...l.breaches_month, file: at(l.breaches_month.file) },
      },
    },
  };
}

/** The keys a home view and a board view must hold to be drawn (parseLiveFile). */
export const HOME_VIEW_KEYS = ["now", "today", "columns", "stats", "panel"] as const;
export const BOARD_VIEW_KEYS = ["now", "boards", "counters", "heatmap", "aiLens", "topTags"] as const;
