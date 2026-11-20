import { isDisclosedIncident } from "../counting";
import type { FullIncident } from "../lifecycle";
import type { IncidentType, Lane, Severity } from "../taxonomy";
import { rowStack, stackHits, type StackFile } from "./picks";
import { DAY_MS, recordCves } from "./util";

/**
 * The home page's news lists: what happened this week, as our records, with
 * the outlets that reported each one named beside it.
 *
 * The week is the seven times 24 hours before the build (or the sweep): live
 * records that entered the dataset in it. A CVE that only vulnerability
 * databases list is not news and stays out (lib/counting.ts
 * isDisclosedIncident).
 *
 * A row counts its sources as distinct publishers, not links: two articles
 * from one outlet are one source. It names the first NEWS_NAMED of them in
 * the record's own order, the primary source first.
 *
 * Four lists share one pool of rows:
 *   top       ranked by the number of sources, then confirmed impact
 *             (severity 4) before everything else, then the newest;
 *   breaches  the breach lane, newest first;
 *   ai        records where AI was the target or the weapon, newest first;
 *   stack     rows that belong to the visitor's products, newest first. The
 *             build marks the default stack's; the browser marks a
 *             visitor's own picks the same way (lib/panel/picks.ts
 *             rowStack), so the pool also keeps the newest exploited
 *             records, which is what a product's list can hold.
 *
 * The page shows NEWS_ROWS of a list; the pool keeps NEWS_KEPT per list so a
 * row that leaves (a record closed since the build) has a successor.
 *
 * `contacts` places the week's exploited records on the radar picture: once
 * around the dial is the seven days, now at twelve o'clock and older
 * clockwise; the higher a record's CVSS score, the nearer the centre (no
 * score: the middle ring); red where impact is confirmed.
 */

export const NEWS_DAYS = 7;
export const NEWS_ROWS = 5;
export const NEWS_KEPT = 8;
/** The newest exploited records kept for the stack list, whichever other list holds them. */
export const NEWS_EXPLOITED_KEPT = 24;
export const NEWS_NAMED = 4;
export const NEWS_CONTACTS = 48;

export interface NewsRow {
  slug: string;
  title: string;
  lane: Lane;
  severity: Severity;
  type: IncidentType;
  /** When the record entered the dataset. */
  created: string;
  cvss: number | null;
  cves: string[];
  /** The first NEWS_NAMED distinct publishers, the primary source first. */
  by: string[];
  /** Distinct publishers. */
  sources: number;
  /** The labels of the default stack's picks the row belongs to. */
  stack: string[];
}

/** One record on the radar: how far round the dial (0 now, 1 seven days ago), how far out (0 centre, 1 rim), and whether impact is confirmed. */
export type Contact = [turn: number, range: number, impact: 0 | 1];

export interface News {
  /** The pool, newest first. */
  rows: NewsRow[];
  /** The top stories, in rank order, by slug. */
  top: string[];
  /** The week's records in all, in the breach lane, and with an AI role. */
  total: number;
  breaches: number;
  ai: number;
  /** The week's exploited records (severity 3 or more) and, of them, those with confirmed impact. */
  exploited: number;
  impact: number;
  contacts: Contact[];
}

/** Distinct publishers of a record, in the order of its sources. */
export function publishers(i: Pick<FullIncident, "sources">): string[] {
  return [...new Set(i.sources.map((s) => s.publisher))];
}

/** A stable number in [0, 1) from a string, so a record without a score keeps its place on the radar from build to build. */
function unit(s: string): number {
  let h = 2166136261;
  for (let k = 0; k < s.length; k++) h = Math.imul(h ^ s.charCodeAt(k), 16777619);
  return ((h >>> 0) % 1000) / 1000;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

export function buildNews(incidents: readonly FullIncident[], stackFile: Pick<StackFile, "default" | "candidates">, nowIso: string): News {
  const now = Date.parse(nowIso);
  const from = now - NEWS_DAYS * DAY_MS;
  const week = incidents
    .filter((i) => i.state === "live" && !isDisclosedIncident(i) && i.created_at <= nowIso && Date.parse(i.created_at) > from)
    .sort((a, b) => b.created_at.localeCompare(a.created_at) || a.slug.localeCompare(b.slug));
  const count = new Map(week.map((i) => [i.slug, publishers(i).length]));
  // confirmed impact is a yes or no here: among stories without it, the newer one leads whatever their severity
  const impact = (i: FullIncident) => (i.severity >= 4 ? 1 : 0);
  const ranked = [...week].sort((a, b) => count.get(b.slug)! - count.get(a.slug)! || impact(b) - impact(a) || b.created_at.localeCompare(a.created_at) || a.slug.localeCompare(b.slug));
  const exploited = week.filter((i) => i.severity >= 3);

  const hits = stackHits(stackFile, stackFile.default);
  const kept = new Set<string>([
    ...ranked.slice(0, NEWS_KEPT),
    ...week.filter((i) => i.lane === "breach").slice(0, NEWS_KEPT),
    ...week.filter((i) => i.type !== "not_ai").slice(0, NEWS_KEPT),
    ...exploited.slice(0, NEWS_EXPLOITED_KEPT),
  ].map((i) => i.slug));

  const rows: NewsRow[] = week
    .filter((i) => kept.has(i.slug))
    .map((i) => {
      const cves = recordCves(i).sort();
      return {
        slug: i.slug,
        title: i.title,
        lane: i.lane,
        severity: i.severity,
        type: i.type,
        created: i.created_at,
        cvss: i.cvss,
        cves,
        by: publishers(i).slice(0, NEWS_NAMED),
        sources: count.get(i.slug)!,
        stack: rowStack(hits, { cves, href: `/incidents/${i.slug}` }),
      };
    });

  const contacts: Contact[] = exploited.slice(0, NEWS_CONTACTS).map((i) => {
    const turn = Math.min(0.999, Math.max(0, (now - Date.parse(i.created_at)) / (NEWS_DAYS * DAY_MS)));
    const range = i.cvss !== null ? 0.2 + ((10 - Math.min(10, Math.max(0, i.cvss))) / 10) * 0.7 : 0.5 + unit(i.slug) * 0.3;
    return [round2(turn), round2(range), i.severity >= 4 ? 1 : 0];
  });

  return {
    rows,
    top: ranked.slice(0, NEWS_KEPT).map((i) => i.slug),
    total: week.length,
    breaches: week.filter((i) => i.lane === "breach").length,
    ai: week.filter((i) => i.type !== "not_ai").length,
    exploited: exploited.length,
    impact: exploited.filter((i) => i.severity >= 4).length,
    contacts,
  };
}

export type NewsTab = "top" | "breaches" | "ai" | "stack";

/** The rows of one list, in its order. `labels` gives a row's stack labels: the build's for the default stack, the browser's for a visitor's picks. */
export function newsList(news: Pick<News, "rows" | "top">, tab: NewsTab, labels: (r: NewsRow) => readonly string[] = (r) => r.stack): NewsRow[] {
  if (tab === "top") {
    const by = new Map(news.rows.map((r) => [r.slug, r]));
    return news.top.map((s) => by.get(s)).filter((r): r is NewsRow => Boolean(r));
  }
  if (tab === "breaches") return news.rows.filter((r) => r.lane === "breach");
  if (tab === "ai") return news.rows.filter((r) => r.type !== "not_ai");
  return news.rows.filter((r) => labels(r).length > 0);
}
