import { addDays, type FullIncident } from "./lifecycle";
import { buildFixView, kevEntryUrl, type FixView, type QuickLookFile } from "./fixes";
import { SITE } from "./site";
import type { FixEntry, KevStatEntry, StatsFiles, StatsSource } from "./stats-schema";

/**
 * The build-time join of the fix file (data/stats/fixes.json) to what the
 * site shows: a record's fix view for its page, its brief and its JSON, and
 * one small file per CVE for the quick-look drawer. The view itself is
 * lib/fixes.ts; this module only knows where the pieces come from.
 */

/** Which KEV entries get a quick-look file even before the fix stage has read them: the same window the stage keeps (settings.fix_lookup.kev_days). */
export const QUICK_LOOK_KEV_DAYS = 90;

/**
 * A record's fix view, or null for a record with no CVE id (there is no CVE
 * record or CISA entry to quote; the page shows our own sentence instead).
 * `site` is "" on the page, where the summary's citation links to the page's
 * own source list, and the site's URL in exports.
 */
export function fixViewForRecord(i: FullIncident, stats: Pick<StatsFiles, "fixes" | "kev">, today: string, site: string): FixView | null {
  if (i.cve_ids.length === 0) return null;
  return buildFixView({
    cves: i.cve_ids,
    entries: stats.fixes?.entries ?? [],
    kev: stats.kev?.entries ?? [],
    record: { action: i.action, fixed_in: i.fixed_in, source_count: i.source_count, sourcesUrl: site ? `${site}/incidents/${i.slug}#sources` : "#sources" },
    today,
    siteName: SITE.name,
  });
}

function sourcesOf(stats: Pick<StatsFiles, "fixes" | "kev">): StatsSource[] {
  return stats.fixes?.sources ?? (stats.kev ? [stats.kev.source] : []);
}

/**
 * One file per CVE the drawer can be asked about: every CVE the fix file
 * holds, every KEV entry of the last 90 days or with a deadline ahead, and
 * every CVE on a live record. A CVE with a record of ours carries the
 * record's slug, title and summary, and the record's own view (its fixed
 * versions and sentence included), so the drawer and the page agree.
 */
export function buildQuickLookFiles(incidents: readonly FullIncident[], stats: Pick<StatsFiles, "fixes" | "kev">, today: string, nowIso: string, site: string): QuickLookFile[] {
  const entries = new Map<string, FixEntry>((stats.fixes?.entries ?? []).map((e) => [e.cve, e]));
  const kev = new Map<string, KevStatEntry>((stats.kev?.entries ?? []).map((e) => [e.cve, e]));
  const from = addDays(today, -QUICK_LOOK_KEV_DAYS);
  const recordByCve = new Map<string, FullIncident>();
  // a live record wins over a closed one, then the newest
  const ranked = [...incidents].sort((a, b) => Number(b.state === "live") - Number(a.state === "live") || b.first_reported.localeCompare(a.first_reported));
  for (const i of ranked) for (const c of i.cve_ids) if (!recordByCve.has(c)) recordByCve.set(c, i);

  const wanted = new Set<string>(entries.keys());
  for (const e of kev.values()) if ((e.added > from && e.added <= today) || (e.due !== null && e.due >= today)) wanted.add(e.cve);
  for (const i of incidents) if (i.state === "live") for (const c of i.cve_ids) wanted.add(c);

  const sources = sourcesOf(stats);
  const out: QuickLookFile[] = [];
  for (const cve of [...wanted].sort()) {
    const entry = entries.get(cve) ?? null;
    const listed = kev.get(cve) ?? null;
    const record = recordByCve.get(cve) ?? null;
    const fix = record
      ? fixViewForRecord(record, stats, today, site)!
      : buildFixView({ cves: [cve], entries: entry ? [entry] : [], kev: listed ? [listed] : [], record: null, today, siteName: SITE.name });
    const description = entry?.kev?.description
      ? { text: entry.kev.description, by: "CISA", url: kevEntryUrl(cve) }
      : null;
    out.push({
      generated_at: nowIso,
      cve,
      title: listed?.name || entry?.title || cve,
      product: listed ? [listed.vendor, listed.product].filter(Boolean).join(" ") : "",
      description,
      cvss: listed?.cvss ?? record?.cvss ?? null,
      record: record ? { slug: record.slug, title: record.title, summary: record.summary } : null,
      fix,
      sources,
    });
  }
  return out;
}
