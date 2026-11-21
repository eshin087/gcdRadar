import { CATALOG, TAIL_CATEGORY, ancestorsOf, catalogKey, descendants, type CatalogEntry } from "../catalog";
import type { Affected } from "../catalog/affected";
import { catalogMatchers, norm, termPattern } from "../catalog/match";
import { isDisclosedIncident } from "../counting";
import { addDays, type FullIncident } from "../lifecycle";
import { productIndex, productSlug } from "../products";
import type { KevStatEntry, RecentCve } from "../stats-schema";
import { kevName, recordCves, shortDate } from "./util";
import {
  CRITICAL_DAYS,
  CRITICAL_MIN,
  CRITS_KEPT,
  CRITS_ON_TILE,
  STACK_DAYS,
  STACK_LATE_DAYS,
  STACK_SOON_DAYS,
  byUrgency,
  kevCatalogHref,
  stackUrgency,
  type StackCandidate,
  type StackCrit,
  type StackFile,
  type StackItem,
} from "./picks";

export {
  CRITICAL_DAYS,
  CRITICAL_MIN,
  STACK_DAYS,
  STACK_FILE,
  STACK_MAX,
  STACK_STORAGE_KEY,
  byUrgency,
  kevCatalogHref,
  packStack,
  parsePicks,
  sortByUrgency,
  stackMatches,
  stackUrgency,
  unpackStack,
  type StackCandidate,
  type StackCrit,
  type StackFile,
  type StackItem,
  type StackMatch,
  type StackTier,
} from "./picks";

/**
 * My stack: products a visitor watches, each a tile with one number, the
 * exploitation in the last 90 days, and a flag only while something is
 * exploited and still open (the strip shows it as a coloured word, picks.ts
 * flagBadge).
 *
 * Candidates: every entry of the curated catalog (lib/catalog), always,
 * whether or not anything hit it lately, and after them the long tail: every
 * vendor on CISA's Known Exploited Vulnerabilities catalog with an entry no
 * curated entry holds, under the vendor's name as CISA has it.
 *
 * Membership (lib/catalog/match.ts): a KEV entry by CISA's vendor and product
 * columns first, then by the entry's terms; a record by its products, title
 * and tags. A vendor entry also holds everything its products hold. A
 * long-tail vendor holds CISA's rows under its name and the records that
 * name it or one of its listed products among their products.
 *
 * The number: KEV entries in the 90 days plus our exploited records (severity
 * 3 or more, no disclosed CVEs) first reported in the 90 days, counted once
 * per CVE id; a record with no CVE id counts once. The tile opens exactly
 * these items (`items`): a KEV entry links our record when one names its CVE,
 * else NVD; a record whose CVEs are all on KEV is that entry's link, not a
 * row of its own. Open items come first, then newest first.
 *
 * The flag, in the order of urgency: a KEV deadline within three days
 * ("patch by 31 Oct"), else one that passed in the last seven ("past due 28
 * Oct"), else a later deadline, else a live patch-lane record of severity 3
 * or more with no patch yet or a partial one ("no patch yet", "partly
 * patched"), else a live record of severity 4 ("confirmed impact"). Nothing
 * else colours a tile.
 *
 * New criticals, the quiet second signal: the CVEs NVD published in the last
 * 14 days with a CVSS score of 9.0 or more that name the entry, and that are
 * not known to be exploited: one on CISA's list or in one of our exploited
 * records (severity 3 or more) is an exploited item, not a new critical, so
 * the drawer can say of this list that none is known to be exploited. With the CVE
 * Program's vendor and product names (lib/catalog/affected.ts, when a file
 * carries them) they are matched on those names; without, on the description,
 * strictly (the entry has to be the subject of the sentence). They never flag
 * a tile; a product with nothing else is the fourth tier of five. Each
 * carries the product it names: the most specific entry that holds it.
 *
 * Two scores per candidate. `flagScore` is the one to show: the CVSS of the
 * item behind the flag, null while that item has no score. `cvss` is the one
 * the order goes by: the same, or where the flag's item has none yet, the
 * highest among the product's exploited items of the 90 days, so an
 * unscored, unpatched flaw does not sink below a scored minor one.
 *
 * The order (picks.ts stackUrgency, byUrgency) is the same wherever products
 * are listed: the strip, the chooser, this file.
 *
 * The default stack, until a visitor chooses: the most urgent of the
 * best-known products that day (the catalog's `popular` entries, so a first
 * visit recognises every name), one per vendor family, at most
 * STACK_DEFAULT_MAX; a quiet day is filled up to STACK_DEFAULT_MIN with the
 * most exploited. Picks live in the browser (localStorage STACK_STORAGE_KEY)
 * and travel in a URL as ?stack=key,key. A key that changed is in `aliases`:
 * one an entry lists as `was`, and any vendor name of CISA's whose rows a
 * curated entry holds.
 *
 * `href` is where the drawer points on from its list: an AI family's product
 * page when the site has one, else CISA's catalog searched for the name.
 */

export const STACK_DEFAULT_MAX = 8;
export const STACK_DEFAULT_MIN = 5;
/** Product names kept for search on an entry that covers more than its own name. */
export const ALSO_KEPT = 30;

export interface StackInputs {
  /** NVD's recent CVEs (data/stats/cves-recent.json). */
  criticals?: readonly RecentCve[];
  /** The CVE Program's vendor and product names per CVE id, when known. */
  affected?: ReadonlyMap<string, readonly Affected[]>;
}

/** Every CVE id known to be exploited, upper-cased: all of CISA's list, and the ids our exploited records (severity 3 or more) name, whatever their age. */
export function knownExploitedCves(incidents: readonly FullIncident[], kev: readonly KevStatEntry[]): Set<string> {
  const known = new Set(kev.map((e) => e.cve.toUpperCase()));
  for (const i of incidents) if (i.severity >= 3 && !isDisclosedIncident(i)) for (const c of recordCves(i)) known.add(c);
  return known;
}

/** Why an exploited record is still open, by the tile's rule; null when it is closed or nothing is pending. */
function openOf(i: FullIncident): StackItem["open"] {
  if (i.state !== "live" || i.severity < 3) return null;
  if (i.severity >= 4) return "loss";
  if (i.lane === "patch" && (i.patch_status === "unpatched" || i.patch_status === "partial")) return i.patch_status;
  return null;
}

/** Open items first (deadlines nearest first), then newest first. */
function sortItems(items: StackItem[]): StackItem[] {
  const rank = (x: StackItem) => (x.open ? 0 : 1);
  return items.sort((a, b) => rank(a) - rank(b) || (a.open === "due" && b.open === "due" ? a.due!.localeCompare(b.due!) : 0) || b.date.localeCompare(a.date) || a.name.localeCompare(b.name));
}

/** A candidate as the page's tile: everything but the item list, the full critical list and the search words, which the browser fetches from the file. */
export function tileOf(c: StackCandidate): StackCandidate {
  return {
    key: c.key,
    label: c.label,
    kind: c.kind,
    vendor: c.vendor,
    cat: c.cat,
    level: c.level,
    n: c.n,
    flag: c.flag,
    why: c.why,
    due: c.due,
    late: c.late,
    patch: c.patch,
    impact: c.impact,
    flagScore: c.flagScore,
    cvss: c.cvss,
    crit: c.crit,
    tier: c.tier,
    kev7: c.kev7,
    href: c.href,
    // the highest few of its new criticals, so the page can name them without fetching the file
    ...(c.crits?.length ? { crits: c.crits.slice(0, CRITS_ON_TILE) } : {}),
  };
}

/** A product name too vague to stand for its vendor in search or in a record's product list. */
const VAGUE = /^(multiple\b.*|server|client|core|frontend|platform|viewer|cli|desktop|docs|forms|firewall|sdk|routers?|devices?|web server|backup|compact|ipv6|.{0,4})$/i;

interface Base {
  key: string;
  label: string;
  vendor: string;
  cat: string;
  level: "vendor" | "product";
  kind: "vendor" | "ai";
  /** The label whose product page the drawer may point at. */
  page: string;
  aka: string[];
  also: string[];
  popular: boolean;
  tail: boolean;
}

function baseOf(e: CatalogEntry): Base {
  return { key: e.key, label: e.name, vendor: e.vendor || e.name, cat: e.cat, level: e.level, kind: e.cat === "ai" ? "ai" : "vendor", page: e.family ?? e.name, aka: e.aka, also: [], popular: e.popular, tail: false };
}

export function buildStack(incidents: readonly FullIncident[], kev: readonly KevStatEntry[], today: string, nowIso: string, extra: StackInputs = {}): StackFile {
  const from = addDays(today, -STACK_DAYS);
  const weekFrom = addDays(today, -7);
  const lateFrom = addDays(today, -STACK_LATE_DAYS);
  const matchers = catalogMatchers();
  const slot = new Map(matchers.map((m, n) => [m.entry.key, n]));
  const under = descendants();
  const slugByCve = new Map<string, string>();
  for (const i of incidents) for (const c of recordCves(i)) if (!slugByCve.has(c)) slugByCve.set(c, i.slug);
  const productPages = new Set(productIndex(incidents).map((p) => p.slug));

  /* ---------- what each curated entry holds ---------- */

  // KEV: the rows of the 90 days against every entry; older rows only need to know whether any entry holds them
  const kevHeld: Set<KevStatEntry>[] = matchers.map(() => new Set());
  const tailRows = new Map<string, KevStatEntry[]>();
  /** For each of CISA's vendor names, the first curated entry that holds one of its rows. */
  const holder = new Map<string, string>();
  for (const e of kev) {
    const recent = e.added > from && e.added <= today;
    let held = false;
    for (let n = 0; n < matchers.length; n++) {
      if (!matchers[n]!.columns(e.vendor, e.product, e.name)) continue;
      if (!held && !holder.has(e.vendor.trim())) holder.set(e.vendor.trim(), matchers[n]!.entry.key);
      held = true;
      if (!recent) break;
      kevHeld[n]!.add(e);
    }
    if (!held) tailRows.set(e.vendor.trim(), [...(tailRows.get(e.vendor.trim()) ?? []), e]);
  }

  // records: the exploited ones of the 90 days, and the live ones that can flag a tile
  const exploited = (i: FullIncident) => i.severity >= 3 && !isDisclosedIncident(i) && i.first_reported > from && i.first_reported <= today;
  const flags = (i: FullIncident) => i.state === "live" && i.severity >= 3 && (i.severity >= 4 || (i.lane === "patch" && (i.patch_status === "unpatched" || i.patch_status === "partial")));
  const pool = incidents.filter((i) => exploited(i) || flags(i));
  const recHeld: Set<FullIncident>[] = matchers.map((m) => new Set(pool.filter((i) => m.record(i))));

  // new criticals: never a CVE already known to be exploited, which is shown among the exploited items
  const critFrom = new Date(Date.parse(nowIso) - CRITICAL_DAYS * 86_400_000).toISOString();
  const knownExploited = knownExploitedCves(incidents, kev);
  const criticals = (extra.criticals ?? []).filter((c) => c.score !== null && c.score >= CRITICAL_MIN && c.published > critFrom && c.published <= nowIso && !knownExploited.has(c.id.toUpperCase()));
  const critHeld: Set<RecentCve>[] = matchers.map(() => new Set());
  /** The product a critical CVE names: the most specific entry that holds it (a product before its vendor, the catalog's order between equals). */
  const critName = new Map<RecentCve, { name: string; depth: number }>();
  const depthOf = matchers.map((m) => ancestorsOf(m.entry).length + (m.entry.level === "product" ? 1 : 0));
  for (const c of criticals) {
    const names = extra.affected?.get(c.id.toUpperCase());
    for (let n = 0; n < matchers.length; n++) {
      const m = matchers[n]!;
      if (!(names?.length ? names.some((a) => m.columns(a.vendor, a.product)) : m.describes(c.description))) continue;
      critHeld[n]!.add(c);
      if ((critName.get(c)?.depth ?? -1) < depthOf[n]!) critName.set(c, { name: m.entry.name, depth: depthOf[n]! });
    }
  }

  // a vendor holds what its products hold
  for (const [key, kids] of under) {
    const n = slot.get(key)!;
    for (const k of kids) {
      const kn = slot.get(k)!;
      for (const x of kevHeld[kn]!) kevHeld[n]!.add(x);
      for (const x of recHeld[kn]!) recHeld[n]!.add(x);
      for (const x of critHeld[kn]!) critHeld[n]!.add(x);
    }
  }

  /* ---------- a candidate from what it holds ---------- */

  const candidateOf = (b: Base, rows: Iterable<KevStatEntry>, recs: Iterable<FullIncident>, crits: Iterable<RecentCve>): StackCandidate => {
    const mine = [...rows].sort((a, b2) => b2.added.localeCompare(a.added) || a.cve.localeCompare(b2.cve));
    const records = [...recs];
    const seen = new Set(mine.map((e) => e.cve));
    const items: StackItem[] = mine.map((e) => {
      const slug = slugByCve.get(e.cve);
      return {
        kind: "kev",
        name: kevName(e.vendor, e.product),
        cves: [e.cve],
        date: e.added,
        due: e.due,
        cvss: e.cvss,
        open: e.due !== null && e.due >= lateFrom ? "due" : null,
        href: slug ? `/incidents/${slug}` : `https://nvd.nist.gov/vuln/detail/${e.cve}`,
        external: !slug,
      };
    });
    for (const i of records.filter(exploited).sort((a, b2) => b2.first_reported.localeCompare(a.first_reported) || a.slug.localeCompare(b2.slug))) {
      const ids = recordCves(i);
      if (ids.length === 0 || ids.some((c) => !seen.has(c))) {
        items.push({ kind: "record", name: i.title, cves: ids.sort(), date: i.first_reported, due: null, cvss: i.cvss, open: openOf(i), href: `/incidents/${i.slug}`, external: false });
      }
      for (const c of ids) seen.add(c);
    }

    const dues = mine.filter((e) => e.due !== null).map((e) => e.due!);
    const due = dues.filter((d) => d >= today).sort()[0] ?? null;
    const late = dues.filter((d) => d < today && d >= lateFrom).sort().pop() ?? null;
    const open = records.filter(flags);
    const patch = open.some((i) => i.lane === "patch" && i.patch_status === "unpatched") ? "unpatched" : open.some((i) => i.lane === "patch" && i.patch_status === "partial") ? "partial" : null;
    const impact = open.some((i) => i.severity >= 4);
    const why: string[] = [];
    if (due) why.push(`CISA deadline ${due}`);
    if (late) why.push(`CISA deadline passed ${late}`);
    if (patch) why.push(patch === "unpatched" ? "no patch yet" : "partly patched");
    if (impact) why.push("confirmed impact");
    const soon = due !== null && due <= addDays(today, STACK_SOON_DAYS);
    // the flag is the reason for the product's tier (picks.ts stackUrgency): a deadline within three days or just passed, then no full
    // patch, which also puts it in the first tier, and only then a later deadline, so a row never hides why it leads
    const flag = soon
      ? `patch by ${shortDate(due!)}`
      : late
        ? `past due ${shortDate(late)}`
        : patch === "unpatched"
          ? "no patch yet"
          : patch === "partial"
            ? "partly patched"
            : due
              ? `patch by ${shortDate(due)}`
              : impact
                ? "confirmed impact"
                : null;

    const critList = [...crits].sort((a, b2) => (b2.score ?? 0) - (a.score ?? 0) || b2.published.localeCompare(a.published) || a.id.localeCompare(b2.id));
    const highest = (list: readonly (number | null)[]) => list.reduce<number | null>((top, x) => (x !== null && (top === null || x > top) ? x : top), null);
    // the score to show: that of the item behind the flag, the same item the flag's words were taken from
    const behind = soon ? mine.filter((e) => e.due === due) : late ? mine.filter((e) => e.due === late) : !patch && due ? mine.filter((e) => e.due === due) : [];
    const flagScore =
      flag === null
        ? null
        : behind.length
          ? highest(behind.map((e) => e.cvss))
          : patch
            ? highest(open.filter((i) => i.lane === "patch" && i.patch_status === patch).map((i) => i.cvss))
            : highest(open.filter((i) => i.severity >= 4).map((i) => i.cvss));
    // the score the order goes by: the flag's; where that has none yet, the highest among everything of the 90 days; a product with new criticals only goes by theirs
    const cvss = flag === null ? (critList[0]?.score ?? null) : (flagScore ?? highest(items.map((x) => x.cvss)));
    const facts = { patch, due, late, impact, crit: critList.length } as const;
    const page = productSlug(b.page);
    return {
      key: b.key,
      label: b.label,
      kind: b.kind,
      vendor: b.vendor,
      cat: b.cat,
      level: b.level,
      n: items.length,
      flag,
      why,
      ...facts,
      flagScore,
      cvss,
      tier: stackUrgency(facts, today),
      kev7: mine.filter((e) => e.added > weekFrom).map((e) => ({ name: kevName(e.vendor, e.product), cve: e.cve, due: e.due })),
      href: b.kind === "ai" && productPages.has(page) ? `/products/${page}` : kevCatalogHref(b.label),
      items: sortItems(items),
      crits: critList.slice(0, CRITS_KEPT).map((c): StackCrit => ({ id: c.id, score: c.score!, published: c.published.slice(0, 10), name: critName.get(c)?.name ?? b.label })),
      ...(b.aka.length ? { aka: b.aka } : {}),
      ...(b.also.length ? { also: b.also } : {}),
      ...(b.popular ? { popular: true } : {}),
      ...(b.tail ? { tail: true } : {}),
    };
  };

  /* ---------- the curated entries ---------- */

  const candidates: StackCandidate[] = [];
  const keys = new Set(CATALOG.map((e) => e.key));
  const kevByVendor = new Map<string, KevStatEntry[]>();
  for (const e of kev) kevByVendor.set(norm(e.vendor), [...(kevByVendor.get(norm(e.vendor)) ?? []), e]);
  for (let n = 0; n < matchers.length; n++) {
    const m = matchers[n]!;
    const b = baseOf(m.entry);
    // product names CISA files under a vendor that none of its products holds: found by search, covered by the vendor
    if (m.entry.level === "vendor" && m.entry.kevVendors.length) {
      const kids = (under.get(m.entry.key) ?? []).map((k) => matchers[slot.get(k)!]!);
      const names = new Set<string>();
      for (const e of m.entry.kevVendors.flatMap((v) => kevByVendor.get(norm(v)) ?? [])) {
        if (VAGUE.test(e.product.trim()) || kids.some((k) => k.columns(e.vendor, e.product, e.name))) continue;
        names.add(e.product.trim());
      }
      b.also = [...names].filter((p) => norm(p) !== norm(b.label)).sort((a, b2) => a.length - b2.length || a.localeCompare(b2)).slice(0, ALSO_KEPT);
    }
    candidates.push(candidateOf(b, kevHeld[n]!, recHeld[n]!, critHeld[n]!));
  }

  /* ---------- the long tail ---------- */

  for (const [vendor] of tailRows) {
    if (!vendor) continue;
    let key = catalogKey(vendor);
    if (!key) continue;
    if (keys.has(key)) key = `${key}-on-cisa`;
    keys.add(key);
    // everything CISA lists under the vendor, not only the rows that brought it here
    const all = kev.filter((e) => e.vendor.trim() === vendor);
    const products = [...new Set(all.map((e) => e.product.trim()))].filter((p) => !VAGUE.test(p));
    const names = new Set(products.flatMap((p) => [norm(p), norm(kevName(vendor, p))]));
    const label = vendor.length >= 4 ? termPattern([vendor.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")]) : null;
    const holdsRecord = (i: FullIncident) => i.products.some((p) => names.has(norm(p)) || Boolean(label?.test(norm(p))));
    const b: Base = { key, label: vendor, vendor, cat: TAIL_CATEGORY, level: "vendor", kind: "vendor", page: vendor, aka: [], also: products.filter((p) => norm(p) !== norm(vendor)).slice(0, ALSO_KEPT), popular: false, tail: true };
    const namedBy = extra.affected ? criticals.filter((c) => extra.affected!.get(c.id.toUpperCase())?.some((a) => norm(a.vendor) === norm(vendor))) : [];
    candidates.push(
      candidateOf(
        b,
        all.filter((e) => e.added > from && e.added <= today),
        pool.filter(holdsRecord),
        namedBy,
      ),
    );
  }
  candidates.sort(byUrgency);

  /* ---------- keys that changed ---------- */

  const aliases: Record<string, string> = {};
  const alias = (old: string, key: string) => {
    if (old && !keys.has(old) && !(old in aliases)) aliases[old] = key;
  };
  for (const e of CATALOG) for (const w of e.was) alias(w, e.key);
  // a vendor name CISA uses whose rows a curated entry claims answers to that entry
  for (const e of CATALOG) for (const v of e.kevVendors) alias(catalogKey(v), e.key);
  // and so does one whose rows a curated entry holds by its terms ("Widget Factory" makes a Joomla editor)
  for (const [vendor, key] of holder) alias(catalogKey(vendor), key);

  /* ---------- the default stack ---------- */

  const related = (a: string, b: string) => a === b || (under.get(a) ?? []).includes(b) || (under.get(b) ?? []).includes(a);
  const picks: string[] = [];
  const take = (list: StackCandidate[], max: number) => {
    for (const c of list) {
      if (picks.length >= max) break;
      if (!picks.some((k) => related(k, c.key))) picks.push(c.key);
    }
  };
  // the best-known names only: a first visit should recognise what it is shown
  const known = candidates.filter((c) => c.popular);
  take(known.filter((c) => c.tier <= 4), STACK_DEFAULT_MAX);
  take([...known].sort((a, b) => b.n - a.n || a.label.localeCompare(b.label)), STACK_DEFAULT_MIN);
  const order = new Map(candidates.map((c, n) => [c.key, n]));
  picks.sort((a, b) => order.get(a)! - order.get(b)!);

  return { generated_at: nowIso, default: picks, aliases, candidates };
}

