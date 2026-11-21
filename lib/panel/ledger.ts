import { isDisclosedIncident } from "../counting";
import { addDays, type FullIncident } from "../lifecycle";
import { productFamily } from "../products";
import type { Fixes, KevStatEntry } from "../stats-schema";
import type { IncidentType, Lane } from "../taxonomy";
import { LEDGER_SOON_DAYS } from "./deadlines";
import { rowStack, stackHits, type StackFile } from "./picks";
import { kevName, recordCves } from "./util";

/**
 * The ledger: what is exploited and still needs doing.
 *
 * Deadlines: CISA's due dates still ahead, nearest first. Entries are folded
 * per vendor, product and deadline, with the group's highest CVSS and every
 * CVE id; a row links our record when one names its first CVE, else NVD.
 * `due` holds the ones within seven days of today and `later` the rest; the
 * home page's "Next due" list runs through both in order and its drawer
 * lists them all. `fix` says whether a patch is published for the row's
 * first CVE (a fixed version or a patch link in data/stats/fixes.json), so
 * the page can say "patch" where there is one and "what to do" where CISA's
 * instruction is all there is.
 *
 * No full patch: our live patch-lane records of severity 3 or more with no
 * patch or a partial one, unpatched first, then the newest report first.
 * Their number is one of the hero's three; the rows are the list behind it
 * (public/stats/panel.json), which scripts/check-home.mjs counts.
 *
 * Every row names the stack picks it belongs to: the picks whose items
 * (lib/panel/stack.ts) hold the row's CVE id or record. The build computes
 * that for the default stack; the browser recomputes it for the visitor's
 * picks (lib/panel/picks.ts stackHits).
 */

export { NEXT_DUE_ROWS } from "./caps";
export { LEDGER_SOON_DAYS } from "./deadlines";

const ACTION_LANES: readonly Lane[] = ["patch", "breach", "supply_chain"];

export interface DueRow {
  kind: "due";
  name: string;
  cves: string[];
  cvss: number | null;
  due: string;
  /** The day CISA listed the newest entry of the group. */
  added: string;
  ransomware: boolean;
  href: string;
  external: boolean;
  /** A patch is published for the first CVE: a fixed version or a patch link in the fix file. */
  fix: boolean;
  /** The labels of the stack picks the row belongs to. */
  stack: string[];
}

export interface PatchRow {
  kind: "patch";
  slug: string;
  /** The first product's family, or the title when the record names no product. */
  name: string;
  title: string;
  cves: string[];
  cvss: number | null;
  patch: "unpatched" | "partial";
  reported: string;
  type: IncidentType;
  stack: string[];
}

export interface Ledger {
  due: DueRow[];
  later: DueRow[];
  /** Every live exploited record without a full patch. */
  patch: PatchRow[];
  /** Live records of severity 3 or more in the three action lanes. */
  exploitedLive: number;
  /** Live patch-lane records of severity 3 or more without a full patch: the hero's number. */
  noFullPatch: number;
}

interface KevGroup {
  vendor: string;
  product: string;
  due: string;
  added: string;
  cvss: number | null;
  cves: string[];
  ransomware: boolean;
}

/** CISA's entries with a deadline on or after today, one group per vendor, product and deadline, nearest deadline first. */
export function kevGroups(entries: readonly KevStatEntry[], today: string): KevGroup[] {
  const groups = new Map<string, KevGroup>();
  for (const e of entries) {
    if (!e.due || e.due < today) continue;
    const k = `${e.vendor}|${e.product}|${e.due}`;
    const g = groups.get(k) ?? { vendor: e.vendor, product: e.product, due: e.due, added: e.added, cvss: null, cves: [], ransomware: false };
    g.cves.push(e.cve);
    if (e.added > g.added) g.added = e.added;
    if (e.ransomware) g.ransomware = true;
    if (e.cvss !== null && (g.cvss === null || e.cvss > g.cvss)) g.cvss = e.cvss;
    groups.set(k, g);
  }
  return [...groups.values()]
    .map((g) => ({ ...g, cves: [...g.cves].sort() }))
    .sort((a, b) => a.due.localeCompare(b.due) || (b.cvss ?? -1) - (a.cvss ?? -1) || a.cves[0]!.localeCompare(b.cves[0]!));
}

/** The CVE ids the fix file holds a patch for: a fixed version, or a link tagged as a patch. */
export function patchedCves(fixes: Pick<Fixes, "entries"> | null | undefined): Set<string> {
  return new Set((fixes?.entries ?? []).filter((e) => e.patches.length > 0 || e.links.some((l) => l.kind === "patch")).map((e) => e.cve));
}

export function buildLedger(incidents: readonly FullIncident[], kev: readonly KevStatEntry[], stackFile: Pick<StackFile, "default" | "candidates">, today: string, fixes?: Pick<Fixes, "entries"> | null): Ledger {
  const live = incidents.filter((i) => i.state === "live" && !isDisclosedIncident(i));
  const slugByCve = new Map<string, string>();
  for (const i of incidents) for (const c of recordCves(i)) if (!slugByCve.has(c)) slugByCve.set(c, i.slug);
  const hits = stackHits(stackFile, stackFile.default);
  const patched = patchedCves(fixes);

  const dueRows: DueRow[] = kevGroups(kev, today).map((g) => {
    const slug = slugByCve.get(g.cves[0]!);
    const href = slug ? `/incidents/${slug}` : `https://nvd.nist.gov/vuln/detail/${g.cves[0]}`;
    return { kind: "due", name: kevName(g.vendor, g.product), cves: g.cves, cvss: g.cvss, due: g.due, added: g.added, ransomware: g.ransomware, href, external: !slug, fix: patched.has(g.cves[0]!), stack: rowStack(hits, { cves: g.cves, href }) };
  });
  const soonUntil = addDays(today, LEDGER_SOON_DAYS);

  const patch: PatchRow[] = live
    .filter((i) => i.lane === "patch" && i.severity >= 3 && (i.patch_status === "unpatched" || i.patch_status === "partial"))
    .sort((a, b) => (a.patch_status === b.patch_status ? 0 : a.patch_status === "unpatched" ? -1 : 1) || b.first_reported.localeCompare(a.first_reported) || b.created_at.localeCompare(a.created_at) || a.slug.localeCompare(b.slug))
    .map((i) => {
      const cves = recordCves(i).sort();
      return {
        kind: "patch",
        slug: i.slug,
        name: i.products[0] ? productFamily(i.products[0]) : i.title,
        title: i.title,
        cves,
        cvss: i.cvss,
        patch: i.patch_status as "unpatched" | "partial",
        reported: i.first_reported,
        type: i.type,
        stack: rowStack(hits, { cves, href: `/incidents/${i.slug}` }),
      };
    });

  return {
    due: dueRows.filter((r) => r.due <= soonUntil),
    later: dueRows.filter((r) => r.due > soonUntil),
    patch,
    exploitedLive: live.filter((i) => i.severity >= 3 && ACTION_LANES.includes(i.lane)).length,
    noFullPatch: patch.length,
  };
}
