import type { FixEntry, FixLink, FixText, KevStatEntry, StatsSource } from "./stats-schema";

/**
 * "How do I fix this": the fix file's entries for a record's CVEs (or for one
 * CVE), joined with CISA's catalog and the record's own fields into one view
 * that answers three things, each with numbered citations that resolve to a
 * publisher, a title and a link:
 *
 *   patch       fixed versions, the vendor's own solution text, and the links
 *               a source tags as the patch or the vendor's advisory;
 *   workaround  the vendor's (or the CNA's) workaround text as written, or a
 *               plain statement that none is listed, never an invented one;
 *   deadline    CISA's due date and required action when the CVE is on the
 *               Known Exploited Vulnerabilities catalog.
 *
 * Built at build time by the record page and by prebuild (the per-CVE and
 * per-record JSON the quick-look drawer fetches), and rendered by
 * components/incidents/FixBlock.tsx. No dataset imports: the drawer's script
 * carries only these types.
 *
 * Whose words: text of kind `vendor`, `cna` or `cisa` is the publisher's,
 * quoted as written (the collector only tidies whitespace and cuts at a
 * length). `summary` is gcdRadar's own sentence, written by a language model
 * from the record's sources; it is shown only where no publisher's text
 * exists, labelled as ours, and its citation is the record's source list.
 */

export interface FixCitation {
  n: number;
  publisher: string;
  title: string;
  url: string;
}

export interface FixVersionRow {
  label: string;
  version: string;
  /** The affected branch or range the fix belongs to, "" when the source names none. */
  from: string;
  cite: number;
}

export interface FixPassage {
  text: string;
  /** The stored text was cut; the citation holds the rest. */
  cut: boolean;
  /** Who wrote it. */
  by: string;
  kind: FixText["kind"];
  cite: number;
}

export interface FixHref {
  /** "Patch", "Vendor advisory", "Advisory linked by CISA", … */
  label: string;
  /** The link's host, without "www.". */
  host: string;
  url: string;
  kind: FixLink["kind"];
  cite: number;
}

export interface FixDeadline {
  /** The CVE ids of this view that CISA lists. */
  cves: string[];
  /** The deadline shown: the nearest one still ahead on the build day, else the latest one passed; null when CISA set none. */
  due: string | null;
  /** The day CISA listed the CVE the deadline belongs to. */
  added: string;
  /** CISA's required action, as written; "" until the entry has been read. */
  action: string;
  /** A remark in CISA's notes, "" when there is none. */
  note: string;
  guidance: { label: string; url: string }[];
  cite: number;
}

/** Why the workaround slot says what it says. */
export type WorkaroundState = "text" | "stated_none" | "none_listed" | "no_record" | "unchecked";

export interface FixView {
  cves: string[];
  /** When the sources were last read: the oldest read among the entries; null when no CVE has an entry. */
  checked: string | null;
  patch: {
    versions: FixVersionRow[];
    /** Fixed versions the sources list beyond those shown. */
    more: number;
    /** The publisher's own solution text. */
    texts: FixPassage[];
    links: FixHref[];
    /** Fixed versions from our record when no source above gave one. */
    recorded: FixVersionRow[];
  };
  workaround: {
    state: WorkaroundState;
    texts: FixPassage[];
    links: FixHref[];
    /** Who states that there is none, with the citation (state "stated_none"). */
    none: { by: string; cite: number } | null;
  };
  deadline: FixDeadline | null;
  /** gcdRadar's own model-written sentence, only when no publisher's text is shown. */
  summary: { text: string; cite: number } | null;
  /** The reference row: per CVE, the same few places to read on. */
  refs: { cve: string; links: { key: "cve" | "nvd" | "kev" | "epss"; label: string; url: string }[] }[];
  citations: FixCitation[];
}

/** The record fields the view uses; a view for a bare CVE passes none. */
export interface FixRecord {
  action: string;
  fixed_in: readonly string[];
  /** How many sources the record has: what the summary was written from. */
  source_count: number;
  /** Where the record's source list is: its page's #sources (absolute for exports). */
  sourcesUrl: string;
}

export interface FixInput {
  cves: readonly string[];
  /** The fix file's entries, any order; those for other CVEs are ignored. */
  entries: readonly FixEntry[];
  /** CISA's catalog as the stats stage keeps it: the due date for a CVE the fix file has not read yet. */
  kev?: readonly Pick<KevStatEntry, "cve" | "added" | "due">[];
  record?: FixRecord | null;
  /** The build's UTC day: which deadline is still ahead. */
  today: string;
  siteName?: string;
}

export function cveOrgUrl(cve: string): string {
  return `https://www.cve.org/CVERecord?id=${cve}`;
}
export function nvdUrl(cve: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cve}`;
}
export function kevEntryUrl(cve: string): string {
  return `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${cve}`;
}
export function epssUrl(cve: string): string {
  return `https://api.first.org/data/v1/epss?cve=${cve}`;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host.replace(/^www\./, "");
  } catch {
    return "";
  }
}

/** A workaround field that only says there is none ("None", "No workarounds are available."). */
export function saysNone(text: string): boolean {
  return /^(none|n\/a|not applicable|no(?: known| specific)? workarounds?(?: (?:is|are|exists?))?(?: (?:available|known))?(?: (?:for|at) this (?:issue|vulnerability|time))?|there (?:is|are) no(?: known)? workarounds?(?: (?:available|that address this vulnerability))?)\.?$/i.test(text.trim());
}

const LINK_LABEL: Record<FixLink["kind"], Record<FixLink["source"], string>> = {
  patch: { cve: "Patch", nvd: "Patch", kev: "Patch", ghsa: "Patch" },
  advisory: { cve: "Vendor advisory", nvd: "Vendor advisory", kev: "Advisory linked by CISA", ghsa: "GitHub advisory" },
  mitigation: { cve: "Mitigation", nvd: "Mitigation", kev: "Mitigation", ghsa: "Mitigation" },
  release_notes: { cve: "Release notes", nvd: "Release notes", kev: "Release notes", ghsa: "Release notes" },
};

/** How a link came to be called what it is called: the provenance half of its citation. */
const LINK_VOUCHER: Record<FixLink["source"], string> = {
  cve: "tagged in the CVE record",
  nvd: "tagged by NVD",
  kev: "linked from CISA's KEV entry",
  ghsa: "GitHub Advisory Database",
};

/** The entries for these CVEs, in the CVEs' order. */
export function fixEntriesFor(cves: readonly string[], entries: readonly FixEntry[]): FixEntry[] {
  const by = new Map(entries.map((e) => [e.cve, e]));
  return cves.map((c) => by.get(c)).filter((e): e is FixEntry => Boolean(e));
}

export function buildFixView(input: FixInput): FixView {
  const cves = [...new Set(input.cves)];
  const entries = fixEntriesFor(cves, input.entries);
  const record = input.record ?? null;
  const siteName = input.siteName ?? "gcdRadar";

  // citations are numbered in the order the view first uses them, one number per link
  const citations: FixCitation[] = [];
  const cite = (c: { publisher: string; title: string; url: string }): number => {
    const had = citations.find((x) => x.url === c.url);
    if (had) return had.n;
    citations.push({ n: citations.length + 1, publisher: c.publisher, title: c.title, url: c.url });
    return citations.length;
  };
  const recordCite = (e: FixEntry) => cite({ publisher: e.by || "CVE Program", title: `CVE record ${e.cve}${e.by_vendor || !e.by ? "" : `, written by ${e.by} as the CNA`}`, url: cveOrgUrl(e.cve) });
  const href = (l: FixLink): FixHref => {
    const host = hostOf(l.url);
    const label = LINK_LABEL[l.kind][l.source];
    return { label, host, url: l.url, kind: l.kind, cite: cite({ publisher: host || "link", title: `${l.title || label} (${LINK_VOUCHER[l.source]})`, url: l.url }) };
  };
  const passage = (t: FixText): FixPassage => ({ text: t.text, cut: t.cut, by: t.source.publisher, kind: t.kind, cite: cite(t.source) });

  // PATCH: versions, the publisher's solution text, then the links
  const versions: FixVersionRow[] = [];
  let more = 0;
  for (const e of entries) {
    more += e.patches_more;
    for (const p of e.patches) {
      if (versions.some((v) => v.label === p.label && v.version === p.version && v.from === p.from)) continue;
      const n = p.source === "ghsa" && p.url ? cite({ publisher: "GitHub Advisory Database", title: e.links.find((l) => l.url === p.url)?.title || `Advisory for ${e.cve}`, url: p.url }) : recordCite(e);
      versions.push({ label: p.label, version: p.version, from: p.from, cite: n });
    }
  }
  const solutionTexts: FixPassage[] = [];
  for (const e of entries) for (const t of e.solutions) if (!solutionTexts.some((x) => x.text === t.text)) solutionTexts.push(passage(t));
  const allLinks: FixLink[] = [];
  for (const e of entries) for (const l of e.links) if (!allLinks.some((x) => x.url === l.url)) allLinks.push(l);
  const patchLinks = allLinks.filter((l) => l.kind !== "mitigation").map(href);

  // WORKAROUND: the publisher's text, or who says there is none, or that none is listed
  const texts: FixPassage[] = [];
  let none: FixView["workaround"]["none"] = null;
  for (const e of entries) {
    for (const t of e.workarounds) {
      if (saysNone(t.text)) none ??= { by: t.source.publisher, cite: cite(t.source) };
      else if (!texts.some((x) => x.text === t.text)) texts.push(passage(t));
    }
  }
  const mitigationLinks = allLinks.filter((l) => l.kind === "mitigation").map(href);
  const state: WorkaroundState = texts.length || mitigationLinks.length ? "text" : none ? "stated_none" : entries.length === 0 ? "unchecked" : entries.some((e) => e.found) ? "none_listed" : "no_record";

  // DEADLINE: CISA's entry; among several, the nearest deadline still ahead, else the latest one passed
  const listed = new Map<string, { added: string; due: string | null; entry: FixEntry | null }>();
  for (const k of input.kev ?? []) if (cves.includes(k.cve)) listed.set(k.cve, { added: k.added, due: k.due, entry: null });
  for (const e of entries) if (e.kev) listed.set(e.cve, { added: e.kev.added, due: e.kev.due, entry: e });
  let deadline: FixDeadline | null = null;
  if (listed.size) {
    const all = [...listed.entries()].map(([cve, v]) => ({ cve, ...v }));
    const ahead = all.filter((x) => x.due !== null && x.due >= input.today).sort((a, b) => a.due!.localeCompare(b.due!));
    const passed = all.filter((x) => x.due !== null && x.due < input.today).sort((a, b) => b.due!.localeCompare(a.due!));
    const pick = ahead[0] ?? passed[0] ?? all[0]!;
    const kev = pick.entry?.kev ?? null;
    deadline = {
      cves: cves.filter((c) => listed.has(c)),
      due: pick.due,
      added: pick.added,
      action: kev?.action ?? "",
      note: kev?.note ?? "",
      guidance: kev?.guidance ?? [],
      cite: cite({ publisher: "CISA", title: `Known Exploited Vulnerabilities catalog, ${pick.cve}`, url: kevEntryUrl(pick.cve) }),
    };
  }

  // our record: its own fixed versions when no source gave one, and its model-written sentence when no publisher's text is shown
  const recordCitation = () => cite({ publisher: siteName, title: `This record, written by a language model from its ${record!.source_count === 1 ? "one source" : `${record!.source_count} sources`}`, url: record!.sourcesUrl });
  const recorded: FixVersionRow[] = record && versions.length === 0 ? record.fixed_in.map((f) => ({ label: "", version: f, from: "", cite: recordCitation() })) : [];
  const summary = record && record.action.trim() && solutionTexts.length === 0 && texts.length === 0 ? { text: record.action.trim(), cite: recordCitation() } : null;

  const reads = entries.map((e) => e.fetched_at).sort();
  return {
    cves,
    checked: reads[0] ?? null,
    patch: { versions, more, texts: solutionTexts, links: patchLinks, recorded },
    workaround: { state, texts, links: mitigationLinks, none: state === "stated_none" ? none : null },
    deadline,
    summary,
    refs: cves.map((cve) => ({
      cve,
      links: [
        { key: "cve" as const, label: "cve.org", url: cveOrgUrl(cve) },
        { key: "nvd" as const, label: "NVD", url: nvdUrl(cve) },
        ...(listed.has(cve) ? [{ key: "kev" as const, label: "CISA KEV", url: kevEntryUrl(cve) }] : []),
        { key: "epss" as const, label: "EPSS", url: epssUrl(cve) },
      ],
    })),
    citations,
  };
}

/** The first link a reader should open to patch: a tagged patch, else the vendor's advisory, else what CISA links. */
export function bestFixLink(view: FixView): FixHref | null {
  return view.patch.links[0] ?? view.workaround.links[0] ?? null;
}

/** Whether the view has anything beyond the reference row: used to decide if a brief or an export mentions it. */
export function hasFixDetail(view: FixView): boolean {
  return view.patch.versions.length + view.patch.texts.length + view.patch.links.length + view.patch.recorded.length + view.workaround.texts.length + view.workaround.links.length > 0 || view.deadline !== null || view.summary !== null;
}

/* ---------- the quick-look drawer's files ---------- */

/** One CVE's file under public/data/fix/, fetched when the drawer opens. */
export const FIX_FILE_DIR = "/data/fix";
export function fixFileUrl(cve: string): string {
  return `${FIX_FILE_DIR}/${cve}.json`;
}

export interface QuickLookFile {
  generated_at: string;
  cve: string;
  /** What it is called: CISA's name for the vulnerability, else the CVE record's title, else the id. */
  title: string;
  /** "Vendor Product" from CISA's entry, "" otherwise. */
  product: string;
  /** One paragraph on what it is, in its publisher's words, with where it came from. */
  description: { text: string; by: string; url: string } | null;
  cvss: number | null;
  /** Our record about this CVE, when one exists. */
  record: { slug: string; title: string; summary: string } | null;
  fix: FixView;
  /** The sources the fix view was read from, with their licence notices. */
  sources: StatsSource[];
}
