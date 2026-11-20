import { breachesMonthList, buildHome, dayCvesList, kevWeekList, weekCvesList, type HomeData } from "../home";
import type { FullIncident } from "../lifecycle";
import type { LiveData } from "../live";
import { packStack } from "../panel/picks";
import { productFamily } from "../products";
import type { Briefing } from "../schema";
import { SITE } from "../site";
import type { HomeStats, StatsFiles } from "../stats-schema";
import { FRESH_RECORD_DAYS, LIVE_FILES, LIVE_VERSION, type BoardLive, type BoardView, type FreshRecord, type HomeLive, type HomeView } from "./shape";

/**
 * Builds the live layer's files from the data directory, with the functions
 * the site build uses (lib/home.ts and, through it, lib/live.ts and
 * lib/panel): the page built at deploy time and the file a sweep publishes
 * are the same model at two instants, so a live number cannot disagree with
 * a built one. Everything is derived from the data and the sweep's time,
 * sorted the way the build sorts it, so two builds of one sweep are
 * byte-identical.
 */

const DAY_MS = 86_400_000;
const FRESH_SOURCES = 3;

type BriefingLine = HomeView["briefing"];

export function briefingLine(briefings: readonly Briefing[]): BriefingLine {
  const latest = briefings[0];
  return latest ? { week: latest.week, headline: latest.narrative?.headline ?? latest.week, start: latest.start, end: latest.end } : null;
}

/** The home page's part of the model: what its components read, and nothing a chart on another page needs. */
export function homeView(data: HomeData, briefing: BriefingLine): HomeView {
  const stats: HomeStats = { ...data.stats, series: { cves_by_year: [], ai_cves_by_quarter: [], kev_by_month: [], breaches_by_month: [], kev_lag_by_year: [] }, epss_top: [] };
  const p = data.panel;
  return {
    now: data.now,
    today: data.today,
    lastUpdated: data.lastUpdated,
    columns: { patch: { live: data.columns.patch.live }, breach: { live: data.columns.breach.live }, supply_chain: data.columns.supply_chain, research: data.columns.research },
    stats,
    panel: { verdict: p.verdict, stack: p.stack, news: p.news, ledger: { due: p.ledger.due, later: p.ledger.later }, week: p.week, sieve: p.sieve },
    briefing,
  };
}

/**
 * The live board's part: everything but the radar scope, which only the old home hero drew. The calendar's days are
 * put in order, so the file does not depend on the order the records were read in.
 */
export function boardView(live: LiveData): BoardView {
  const cells = Object.fromEntries(Object.entries(live.heatmap.cells).sort(([a], [b]) => a.localeCompare(b)));
  return { now: live.now, lastUpdated: live.lastUpdated, boards: live.boards, counters: live.counters, heatmap: { ...live.heatmap, cells }, aiLens: live.aiLens, topTags: live.topTags };
}

/** Published records created in the FRESH_RECORD_DAYS before the sweep, newest first. */
export function freshRecords(incidents: readonly FullIncident[], sweepMs: number): FreshRecord[] {
  const since = sweepMs - FRESH_RECORD_DAYS * DAY_MS;
  return incidents
    .filter((i) => {
      const t = Date.parse(i.created_at);
      return t >= since && t <= sweepMs;
    })
    .sort((a, b) => b.created_at.localeCompare(a.created_at) || a.slug.localeCompare(b.slug))
    .map((i) => ({
      slug: i.slug,
      id: i.id,
      title: i.title,
      summary: i.summary,
      action: i.action,
      lane: i.lane,
      severity: i.severity,
      patch_status: i.patch_status,
      cvss: i.cvss,
      cve_ids: [...i.cve_ids],
      products: [...new Set(i.products.map(productFamily))].slice(0, 3),
      first_reported: i.first_reported,
      created_at: i.created_at,
      sources: i.sources.slice(0, FRESH_SOURCES).map((s) => ({ publisher: s.publisher, title: s.title, url: s.url })),
    }));
}

/**
 * The fresh records a file can link: those whose slug appears in the text
 * its page is drawn from. Most of a few days' new records are disclosed
 * CVEs no row names, and a file carries only the ones it could send a
 * visitor to. A slug that merely contains another passes too, which costs
 * a spare record and never drops a needed one.
 */
export function namedIn(fresh: readonly FreshRecord[], text: string): FreshRecord[] {
  return fresh.filter((r) => text.includes(r.slug));
}

/** The lists the home page's numbers open, as prebuild writes them under public/stats and a sweep publishes them beside the views. */
export function statsListFiles(home: HomeData, stats: StatsFiles, now: Date): Record<string, unknown> {
  const month = home.stats.lists.breaches_month.month;
  return {
    "cves-day.json": { generated_at: home.now, days: 1, source: stats.cvesRecent?.source ?? null, cves: dayCvesList(stats, now) },
    "cves-week.json": { generated_at: home.now, days: 7, source: stats.cvesRecent?.source ?? null, cves: weekCvesList(stats, now) },
    "kev-week.json": { generated_at: home.now, days: 7, source: stats.kev?.source ?? null, entries: kevWeekList(stats, home.today) },
    [`breaches-${month}.json`]: { generated_at: home.now, month, source: stats.hibp?.source ?? null, breaches: breachesMonthList(stats, month) },
  };
}

export interface LiveInput {
  /** Published records with their lifecycle (lib/data.ts loadIncidents). */
  incidents: readonly FullIncident[];
  stats: StatsFiles;
  briefings: readonly Briefing[];
  /** When the sweep finished: the files' clock and the time the page's label states. */
  sweep: string;
}

/** Every file of one sweep by name, serialised: the two views, the stack candidates, and the lists. */
export function buildLiveFiles({ incidents, stats, briefings, sweep }: LiveInput): Record<string, string> {
  const now = new Date(sweep);
  const sweepMs = now.getTime();
  if (!Number.isFinite(sweepMs)) throw new Error(`live: the sweep time "${sweep}" is not a date`);
  const home = buildHome(incidents, stats, now, sweep, SITE.origin);
  const fresh = freshRecords(incidents, sweepMs);
  const head = { v: LIVE_VERSION, sweep, fresh_since: new Date(sweepMs - FRESH_RECORD_DAYS * DAY_MS).toISOString() };
  const home_ = homeView(home, briefingLine(briefings));
  const board = boardView(home.live);
  // the stack candidates travel the way the build writes them (lib/panel/picks.ts packStack): several hundred, compactly
  const stack = JSON.stringify(packStack(home.stackFile));
  // the home page can also link what the stack file lists (a chip's drawer), so its fresh records cover both
  const homeFile: HomeLive = { ...head, view: home_, fresh: namedIn(fresh, JSON.stringify(home_) + stack) };
  const boardFile: BoardLive = { ...head, view: board, fresh: namedIn(fresh, JSON.stringify(board)) };
  const out: Record<string, string> = {
    [LIVE_FILES.home]: JSON.stringify(homeFile),
    [LIVE_FILES.board]: JSON.stringify(boardFile),
    [LIVE_FILES.stack]: stack,
  };
  for (const [name, body] of Object.entries(statsListFiles(home, stats, now))) out[name] = JSON.stringify(body);
  for (const name of Object.keys(out)) out[name] += "\n";
  return out;
}
