/**
 * The browser's half of My stack (lib/panel/stack.ts holds the rules): the
 * shapes of public/stats/stack.json, where the picks are stored, the one
 * order every list of products uses, and the steps the page runs on the
 * picks. No dataset or catalog imports, so the page's script stays small.
 */

export const STACK_STORAGE_KEY = "gcd-radar:stack";
export const STACK_FILE = "/stats/stack.json";
/** How many products a stack holds. Forty keys are about 500 characters of ?stack=. */
export const STACK_MAX = 40;
export const STACK_DAYS = 90;
/** A new critical CVE: CVSS 9.0 or higher, published within the NVD file's window (14 days). */
export const CRITICAL_MIN = 9;
export const CRITICAL_DAYS = 14;
/** The newest critical CVEs a product's list keeps; `crit` counts them all. */
export const CRITS_KEPT = 8;
/** Of those, how many travel with a tile in the page's HTML, so the page can name the highest without the file. */
export const CRITS_ON_TILE = 3;
/** A CISA deadline this close puts a product in the first tier. */
export const STACK_SOON_DAYS = 3;
/** A CISA deadline that passed this recently still counts, as past due. */
export const STACK_LATE_DAYS = 7;

export interface StackMatch {
  name: string;
  cve: string;
  due: string | null;
}

/** What a tile's number is made of: one KEV entry, or one of our exploited records that no KEV entry already stands for. */
export interface StackItem {
  kind: "kev" | "record";
  /** The KEV entry's product, or the record's title. */
  name: string;
  /** Its CVE ids, if any. */
  cves: string[];
  /** The day CISA listed it, or the record's first report. */
  date: string;
  /** The CISA deadline, for a KEV entry that has one. */
  due: string | null;
  cvss: number | null;
  /** Why it is still open, the tile's reasons item by item; null once it is not. "due" also covers a deadline passed in the last STACK_LATE_DAYS. */
  open: "due" | "unpatched" | "partial" | "loss" | null;
  /** Our record when one names the CVE, else NVD. */
  href: string;
  external: boolean;
}

/** A new critical CVE that names the product: the quiet second signal, never a flag. */
export interface StackCrit {
  id: string;
  score: number;
  /** The day NVD published it. */
  published: string;
  /** The product it names: the most specific catalog entry that holds it ("Microsoft Entra ID" on Microsoft's list). */
  name: string;
}

/**
 * How urgent a product is, 1 first:
 * 1 exploited with no full patch, or a CISA deadline within STACK_SOON_DAYS or just passed;
 * 2 a CISA deadline later than that; 3 confirmed impact only; 4 new critical CVEs only; 5 quiet.
 */
export type StackTier = 1 | 2 | 3 | 4 | 5;

export interface StackCandidate {
  key: string;
  label: string;
  /** "ai" for an AI product, "vendor" for everything else; `cat` says more. */
  kind: "vendor" | "ai";
  /** The vendor's name; the label again for a vendor entry. */
  vendor: string;
  /** The catalog category (lib/catalog CATEGORIES). */
  cat: string;
  /** A vendor entry covers everything the vendor makes; a product entry only itself. */
  level: "vendor" | "product";
  /** Exploited in the 90 days. */
  n: number;
  /** The flag's words ("patch by 31 Oct", "past due 28 Oct", "no patch yet", "partly patched", "confirmed impact"), or null; flagBadge turns them into the tile's badge. */
  flag: string | null;
  /** Every reason it is flagged, for the tooltip. */
  why: string[];
  /** The nearest CISA deadline still ahead when the site was built. */
  due: string | null;
  /** The latest CISA deadline that passed within STACK_LATE_DAYS of the build. */
  late: string | null;
  /** Exploited records still without a full patch: the worst of them. */
  patch: "unpatched" | "partial" | null;
  /** A live record with confirmed impact (data, money or service lost). */
  impact: boolean;
  /**
   * The CVSS of the item behind the flag: the highest among the items the flag's words come from (the
   * entries with that deadline, the records without a patch, the records with confirmed impact). Null
   * when none of them has a score yet, and when there is no flag. This is the score to show.
   */
  flagScore: number | null;
  /**
   * The score the order goes by: `flagScore`; where the flag's own items have none yet, the highest among
   * its exploited items of the 90 days; for a product with new criticals only, the highest of those.
   */
  cvss: number | null;
  /** New critical CVEs (CRITICAL_MIN and up) of the last CRITICAL_DAYS days that name it. */
  crit: number;
  tier: StackTier;
  /** KEV entries CISA added in the 7 days that belong to it: the hero's "hit your stack this week" number. */
  kev7: StackMatch[];
  /** Where the tile's drawer points on: the family's product page, or CISA's catalog searched for the name. */
  href: string;
  /** Every item behind `n`, open ones first, then newest first. Only in /stats/stack.json; the page's tiles leave it out. */
  items?: StackItem[];
  /** The highest-scored of the `crit` CVEs, highest first: CRITS_KEPT of them in /stats/stack.json, CRITS_ON_TILE on a page's tile. */
  crits?: StackCrit[];
  /** Other words the chooser's search answers to. Only in /stats/stack.json. */
  aka?: string[];
  /** Product names CISA files under it that have no entry of their own, for search. Only in /stats/stack.json. */
  also?: string[];
  /** One of the short list offered on a first visit. */
  popular?: boolean;
  /** Not curated: a vendor found only on CISA's list. */
  tail?: boolean;
}

export interface StackFile {
  generated_at: string;
  default: string[];
  /** Keys that changed: the old key, and the entry that answers to it now. */
  aliases: Record<string, string>;
  candidates: StackCandidate[];
}

/* ---------- the order ---------- */

/** The rule in one sentence, shown in the chooser. */
export const STACK_ORDER_NOTE =
  "Most urgent first: exploited with no full patch or a CISA deadline within 3 days, then later deadlines (nearest first), then confirmed impact, then new critical CVEs, then everything quiet. Ties go to the higher CVSS score.";

function daysFrom(today: string, day: string): number {
  return Math.round((Date.parse(`${day}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / 86_400_000);
}

/** A product's tier on a given day, from the facts the build wrote on it. */
export function stackUrgency(c: Pick<StackCandidate, "patch" | "due" | "late" | "impact" | "crit">, today: string): StackTier {
  if (c.patch || c.late) return 1;
  if (c.due) return daysFrom(today, c.due) <= STACK_SOON_DAYS ? 1 : 2;
  if (c.impact) return 3;
  if (c.crit > 0) return 4;
  return 5;
}

type Ordered = Pick<StackCandidate, "tier" | "cvss" | "due" | "late" | "n" | "crit" | "label">;

/**
 * The one order for anything that lists products: tier, then inside a tier
 * the highest CVSS, the nearest deadline, the most items and the name. The
 * second tier is "a deadline later on", so there the nearest deadline leads.
 */
export function byUrgency(a: Ordered, b: Ordered): number {
  const deadline = (a.late ?? a.due ?? "9999").localeCompare(b.late ?? b.due ?? "9999");
  const cvss = (b.cvss ?? -1) - (a.cvss ?? -1);
  return a.tier - b.tier || (a.tier === 2 ? deadline || cvss : cvss || deadline) || b.n - a.n || b.crit - a.crit || a.label.localeCompare(b.label, "en", { sensitivity: "base" });
}

/** Candidates in the urgency order (a sorted copy). */
export function sortByUrgency<T extends Ordered>(list: readonly T[]): T[] {
  return [...list].sort(byUrgency);
}

/* ---------- flags ---------- */

/** The tones a flag's badge comes in: confirmed impact (data, money or service lost), open with no patch, a partial patch, a KEV due date. */
export type FlagTone = "harm" | "open" | "partial" | "due";

/**
 * A product's flag as the word on its chip: the fewest words that still
 * say why, and the tone that colours it. "patch by 10 Nov" reads "due 10
 * Nov"; the full reasons stay in the chip's hover note and its list.
 */
export function flagBadge(flag: string): { word: string; tone: FlagTone } {
  if (flag.startsWith("patch by ")) return { word: `due ${flag.slice("patch by ".length)}`, tone: "due" };
  if (flag.startsWith("past due ")) return { word: flag, tone: "due" };
  if (flag === "confirmed impact") return { word: "impact", tone: "harm" };
  if (flag === "no patch yet") return { word: "no patch", tone: "open" };
  return { word: "partial", tone: "partial" };
}

/** The quiet line for a product with new critical CVEs: "3 new critical CVEs". */
export function critNote(n: number): string {
  return `${n} new critical ${n === 1 ? "CVE" : "CVEs"}`;
}

/* ---------- the picks ---------- */

/** The KEV additions of the 7 days that belong to any of the picks, once each, nearest deadline first. */
export function stackMatches(file: Pick<StackFile, "candidates">, picks: readonly string[]): StackMatch[] {
  const out = new Map<string, StackMatch>();
  for (const k of picks) for (const m of file.candidates.find((c) => c.key === k)?.kev7 ?? []) if (!out.has(m.cve)) out.set(m.cve, m);
  return [...out.values()].sort((a, b) => (a.due ?? "9").localeCompare(b.due ?? "9") || a.cve.localeCompare(b.cve));
}

/** What the picks' items cover: every CVE id and record link, each with the labels of the picks that hold it, for marking the ledger's rows. */
export interface StackHits {
  cves: Map<string, string[]>;
  hrefs: Map<string, string[]>;
}

export function stackHits(file: Pick<StackFile, "candidates">, picks: readonly string[]): StackHits {
  const hits: StackHits = { cves: new Map(), hrefs: new Map() };
  const add = (m: Map<string, string[]>, key: string, label: string) => {
    const labels = m.get(key) ?? [];
    if (!labels.includes(label)) labels.push(label);
    m.set(key, labels);
  };
  for (const k of picks) {
    const c = file.candidates.find((x) => x.key === k);
    for (const it of c?.items ?? []) {
      for (const cve of it.cves) add(hits.cves, cve, c!.label);
      add(hits.hrefs, it.href, c!.label);
    }
  }
  return hits;
}

/** The picks a row belongs to, by its CVE ids or its link, in pick order, each once. */
export function rowStack(hits: StackHits, row: { cves?: readonly string[]; href?: string }): string[] {
  const out: string[] = [];
  for (const cve of row.cves ?? []) for (const l of hits.cves.get(cve) ?? []) if (!out.includes(l)) out.push(l);
  if (row.href) for (const l of hits.hrefs.get(row.href) ?? []) if (!out.includes(l)) out.push(l);
  return out;
}

/**
 * Picks from a URL or storage: known keys only, in order, no repeats, at
 * most STACK_MAX. A key that changed (`aliases`: "berriai" is "litellm" now)
 * opens the entry that took it over, so old links and saved stacks keep working.
 */
export function parsePicks(raw: string | null | undefined, known: ReadonlySet<string>, aliases: Readonly<Record<string, string>> = {}): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const k of raw.split(",").map((s) => s.trim().toLowerCase())) {
    const key = known.has(k) ? k : aliases[k];
    if (key && known.has(key) && !out.includes(key) && out.length < STACK_MAX) out.push(key);
  }
  return out;
}

/** Lower-case slug of a label, the key a pick travels under: "Palo Alto Networks" -> "palo-alto-networks". */
export function stackKey(label: string): string {
  return label
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function kevCatalogHref(label: string): string {
  return `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(label)}`;
}


/* ---------- the chooser's search ---------- */

export interface StackSearchHit {
  c: StackCandidate;
  /** How well it matched, 0 best: the name itself, its start, a word in it, anywhere in it, the vendor, another name it answers to, a product it covers. */
  rank: number;
  /** The other name or covered product that matched, when the name and vendor did not. */
  via: string | null;
}

/** Where `q` starts inside `text` (both lower case), preferring the start of a word; -1 when absent. */
export function findTyped(text: string, q: string): number {
  if (!q) return -1;
  for (let at = text.indexOf(q); at !== -1; at = text.indexOf(q, at + 1)) if (at === 0 || !/[a-z0-9]/.test(text[at - 1]!)) return at;
  return text.indexOf(q);
}

/**
 * Candidates for what was typed: names first (whole, then starting with it,
 * then a word starting with it, then anywhere), then vendors, then the other
 * names an entry answers to, then the products a vendor covers; inside a
 * rank, the urgency order. `total` counts every match, `hits` holds the first `limit`.
 */
export function searchStack(list: readonly StackCandidate[], query: string, limit = 60): { hits: StackSearchHit[]; total: number } {
  const q = query.trim().toLowerCase().replace(/\s+/g, " ");
  if (!q) return { hits: [], total: 0 };
  const wordStart = (text: string) => {
    const at = findTyped(text, q);
    return at !== -1 && (at === 0 || !/[a-z0-9]/.test(text[at - 1]!));
  };
  const hits: StackSearchHit[] = [];
  for (const c of list) {
    const label = c.label.toLowerCase();
    const vendor = c.vendor.toLowerCase();
    let rank = -1;
    let via: string | null = null;
    if (label === q) rank = 0;
    else if (label.startsWith(q)) rank = 1;
    else if (wordStart(label)) rank = 2;
    else if (label.includes(q)) rank = 3;
    else if (vendor !== label && (wordStart(vendor) || vendor.includes(q))) rank = 4;
    else {
      via = c.aka?.find((a) => wordStart(a.toLowerCase())) ?? null;
      if (via) rank = 5;
      else {
        via = c.also?.find((a) => wordStart(a.toLowerCase())) ?? c.also?.find((a) => a.toLowerCase().includes(q)) ?? null;
        if (via) rank = 6;
        else if (c.key.includes(q.replace(/ /g, "-"))) rank = 7;
      }
    }
    if (rank !== -1) hits.push({ c, rank, via });
  }
  hits.sort((a, b) => a.rank - b.rank || byUrgency(a.c, b.c));
  return { hits: hits.slice(0, limit), total: hits.length };
}

/* ---------- the file as it travels ---------- */

/**
 * public/stats/stack.json holds hundreds of candidates, most of them quiet,
 * so it is written compactly: every item and critical CVE once, as a row in a
 * table (a vendor and its products share them) that candidates point into by
 * index; categories by index; a key left out when it is the label's slug; and
 * any field left out when it holds the quiet value. unpackStack turns it back
 * into the StackFile the page works with.
 */

/** kind (0 KEV, 1 record), name, CVE ids, date, due or 0, CVSS, open or 0, href or 0 (a KEV entry's NVD page). */
export type StackWireItem = [0 | 1, string, string[], string, string | 0, number | null, NonNullable<StackItem["open"]> | 0, string | 0];
/** id, score, the day published, the product it names. */
export type StackWireCrit = [string, number, string, string];

export interface StackWireCandidate {
  /** Left out when it is stackKey(label). */
  key?: string;
  label: string;
  vendor?: string;
  /** Index into the file's `cats`. */
  c: number;
  /** 1 for a vendor entry. */
  v?: 1;
  n?: number;
  flag?: string;
  why?: string[];
  due?: string;
  late?: string;
  patch?: "unpatched" | "partial";
  impact?: 1;
  /** `flagScore`. */
  fs?: number;
  cvss?: number;
  crit?: number;
  tier?: StackTier;
  kev7?: StackMatch[];
  href?: string;
  /** Indexes into the file's `items`. */
  it?: number[];
  /** Indexes into the file's `crits`. */
  cr?: number[];
  aka?: string[];
  also?: string[];
  pop?: 1;
  tail?: 1;
}

export interface StackWire {
  generated_at: string;
  default: string[];
  aliases: Record<string, string>;
  cats: string[];
  items: StackWireItem[];
  crits: StackWireCrit[];
  candidates: StackWireCandidate[];
}

const nvdHref = (cve: string | undefined) => `https://nvd.nist.gov/vuln/detail/${cve ?? ""}`;

export function packStack(file: StackFile): StackWire {
  const cats: string[] = [];
  const items: StackWireItem[] = [];
  const itemIndex = new Map<string, number>();
  const crits: StackWireCrit[] = [];
  const critIndex = new Map<string, number>();
  const rowOf = <T>(table: T[], index: Map<string, number>, id: string, row: () => T) => {
    let n = index.get(id);
    if (n === undefined) {
      n = table.push(row()) - 1;
      index.set(id, n);
    }
    return n;
  };
  const candidates = file.candidates.map((c): StackWireCandidate => {
    if (!cats.includes(c.cat)) cats.push(c.cat);
    const w: StackWireCandidate = { label: c.label, c: cats.indexOf(c.cat) };
    if (c.key !== stackKey(c.label)) w.key = c.key;
    if (c.vendor !== c.label) w.vendor = c.vendor;
    if (c.level === "vendor") w.v = 1;
    if (c.n) w.n = c.n;
    if (c.flag) w.flag = c.flag;
    if (c.why.length) w.why = c.why;
    if (c.due) w.due = c.due;
    if (c.late) w.late = c.late;
    if (c.patch) w.patch = c.patch;
    if (c.impact) w.impact = 1;
    if (c.flagScore !== null) w.fs = c.flagScore;
    if (c.cvss !== null) w.cvss = c.cvss;
    if (c.crit) w.crit = c.crit;
    if (c.tier !== 5) w.tier = c.tier;
    if (c.kev7.length) w.kev7 = c.kev7;
    if (c.href !== kevCatalogHref(c.label)) w.href = c.href;
    if (c.items?.length) {
      w.it = c.items.map((it) =>
        rowOf(items, itemIndex, `${it.kind}|${it.href}|${it.cves.join(",")}|${it.name}`, () => [it.kind === "kev" ? 0 : 1, it.name, it.cves, it.date, it.due ?? 0, it.cvss, it.open ?? 0, it.kind === "kev" && it.href === nvdHref(it.cves[0]) ? 0 : it.href]),
      );
    }
    if (c.crits?.length) w.cr = c.crits.map((x) => rowOf(crits, critIndex, x.id, () => [x.id, x.score, x.published, x.name]));
    if (c.aka?.length) w.aka = c.aka;
    if (c.also?.length) w.also = c.also;
    if (c.popular) w.pop = 1;
    if (c.tail) w.tail = 1;
    return w;
  });
  return { generated_at: file.generated_at, default: file.default, aliases: file.aliases, cats, items, crits, candidates };
}

export function unpackStack(wire: StackWire): StackFile {
  const items = wire.items.map(([kind, name, cves, date, due, cvss, open, href]): StackItem => {
    const link = href || nvdHref(cves[0]);
    return { kind: kind === 0 ? "kev" : "record", name, cves, date, due: due || null, cvss, open: open || null, href: link, external: link.startsWith("http") };
  });
  const crits = wire.crits.map(([id, score, published, name]): StackCrit => ({ id, score, published, name }));
  const candidates = wire.candidates.map((w): StackCandidate => {
    const cat = wire.cats[w.c] ?? "";
    return {
      key: w.key ?? stackKey(w.label),
      label: w.label,
      kind: cat === "ai" ? "ai" : "vendor",
      vendor: w.vendor ?? w.label,
      cat,
      level: w.v ? "vendor" : "product",
      n: w.n ?? 0,
      flag: w.flag ?? null,
      why: w.why ?? [],
      due: w.due ?? null,
      late: w.late ?? null,
      patch: w.patch ?? null,
      impact: Boolean(w.impact),
      flagScore: w.fs ?? null,
      cvss: w.cvss ?? null,
      crit: w.crit ?? 0,
      tier: w.tier ?? 5,
      kev7: w.kev7 ?? [],
      href: w.href ?? kevCatalogHref(w.label),
      items: (w.it ?? []).map((n) => items[n]!).filter(Boolean),
      crits: (w.cr ?? []).map((n) => crits[n]!).filter(Boolean),
      ...(w.aka ? { aka: w.aka } : {}),
      ...(w.also ? { also: w.also } : {}),
      ...(w.pop ? { popular: true } : {}),
      ...(w.tail ? { tail: true } : {}),
    };
  });
  return { generated_at: wire.generated_at, default: wire.default, aliases: wire.aliases ?? {}, candidates };
}
