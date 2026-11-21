import {
  FIX_AFFECTED_MAX,
  FIX_LINK_MAX,
  FIX_PATCH_MAX,
  FIX_TEXT_MAX,
  FixEntrySchema,
  FixesSchema,
  STATS_FILES,
  type FixEntry,
  type FixKev,
  type FixLink,
  type FixPatch,
  type FixText,
  type Fixes,
  type KevStats,
  type StatsSource,
} from "../../lib/stats-schema";
import { HttpError } from "../lib/http";
import { addDays } from "../lib/ids";
import type { Advisory } from "../sources/ghsa";
import type { KevEntry } from "../sources/kev";
import { KEV_SOURCE, KEV_URL } from "./kev";
import { NVD_SOURCE, nvdGet } from "./nvd";
import type { StatsContext, StatsModule } from "./types";

/**
 * How to fix a CVE, from sources that can be cited, for the CVEs the site
 * can show a fix for: those on live records, and CISA's KEV entries listed
 * in the last 90 days or with a deadline still ahead. One entry per CVE in
 * data/stats/fixes.json; the site joins it to a record's page and to the
 * quick-look drawer at build time (lib/fixes.ts). An entry leaves the file
 * when its CVE leaves that set.
 *
 * The sources, in the order they are trusted:
 *
 * 1. The CVE Program's own record (CVE Record Format 5), read as one small
 *    file per CVE from the CVE List repository, which the program updates
 *    about every seven minutes. From the CNA's container: the fixed versions
 *    in `affected`, the references it tags patch, vendor-advisory, mitigation
 *    or release-notes, and its `solutions` and `workarounds` text, kept as
 *    written. Terms (cve.org/Legal/TermsOfUse, read 2026-11-19 from the
 *    site's source): "MITRE hereby grants you a perpetual, worldwide,
 *    non-exclusive, no-charge, royalty-free, irrevocable copyright license to
 *    reproduce, prepare derivative works of, publicly display, publicly
 *    perform, sublicense, and distribute" CVE, "provided that you reproduce
 *    MITRE's copyright designation and this license in any such copy". The
 *    repository's README: "You may search, download, and use the content
 *    hosted in this repository, per the CVE Program Terms of Use."
 * 2. CISA's KEV catalog (CC0 1.0): the deadline, the required action in
 *    CISA's words, and the links in the entry's notes, which name the
 *    vendor's instructions. The stats stage's kev.json keeps none of these,
 *    so the raw catalog is read here, once per catalog release.
 * 3. NVD's reference tags (Patch, Vendor Advisory, Mitigation, Release
 *    Notes), asked only when the CVE record tags neither a patch nor a
 *    vendor advisory: one request per CVE on the stats stage's shared NVD
 *    clock (6.5 s apart without an API key).
 * 4. The GitHub Advisory Database (CC BY 4.0), asked only when the CVE
 *    record lists no fixed version: a reviewed advisory's first patched
 *    version per package.
 *
 * Nothing here is written by a model, and nothing is inferred beyond what a
 * source states: a fixed version is taken only from an explicit upper bound
 * of an affected range or an explicit "unaffected from" version.
 *
 * Budget (settings.fix_lookup): at most per_run CVE records a run, new CVEs
 * first, then those read longest ago once recheck_days have passed. The file
 * is its own cache: each entry carries when its sources were last read.
 * Those stamps are `volatile`, so a run that re-read entries and found
 * nothing new is committed as bookkeeping and does not rebuild the site.
 */

export const CVE_LIST_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves";
export const CVE_SOURCE: StatsSource = {
  name: "CVE Program (CVE List)",
  url: "https://www.cve.org/",
  license: "CVE Terms of Use (cve.org/Legal/TermsOfUse). Copyright © 1999-2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation.",
};
export const GHSA_SOURCE: StatsSource = { name: "GitHub Advisory Database", url: "https://github.com/advisories", license: "CC BY 4.0" };
export const FIX_SOURCE_LIST: readonly StatsSource[] = [CVE_SOURCE, KEV_SOURCE, NVD_SOURCE, GHSA_SOURCE];

const CVE = /^CVE-(\d{4})-(\d{4,})$/;
const SPACING_MS = 250;
/** Lookups stop for the run after this many CVE records in a row could not be read. */
const MAX_FAILURES = 3;

/** The file of one CVE in the CVE List: cves/<year>/<thousands>xxx/<id>.json. */
export function cveRecordUrl(cve: string): string {
  const m = CVE.exec(cve);
  if (!m) throw new Error(`not a CVE id: ${cve}`);
  const [, year, n] = m as unknown as [string, string, string];
  return `${CVE_LIST_BASE}/${year}/${n.slice(0, -3)}xxx/${cve}.json`;
}

export function cveOrgUrl(cve: string): string {
  return `https://www.cve.org/CVERecord?id=${cve}`;
}

/* ---------- text ---------- */

/** A publisher's text with its whitespace tidied: one line per line, no blank lines, no runs of spaces. Words are untouched. */
export function tidyText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((l) => l.replace(/[\s\p{Zs}]+/gu, " ").trim())
    .filter(Boolean)
    .join("\n");
}

/** Cuts at the last line or sentence end before `max`, else at a word, and says so. */
export function cutText(text: string, max = FIX_TEXT_MAX): { text: string; cut: boolean } {
  if (text.length <= max) return { text, cut: false };
  const head = text.slice(0, max);
  const stop = Math.max(head.lastIndexOf("\n"), head.lastIndexOf(". ") + 1);
  const at = stop > max * 0.5 ? stop : Math.max(head.lastIndexOf(" "), Math.floor(max * 0.8));
  return { text: `${head.slice(0, at).trimEnd()}…`, cut: true };
}

function webUrl(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  try {
    const u = new URL(raw.trim());
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

/**
 * Two spellings of one page compare equal: scheme, "www.", a trailing slash,
 * the fragment and a locale segment in the path are ignored (the CVE record
 * links msrc.microsoft.com/update-guide/vulnerability/<id>, CISA the same
 * page under /en-US/; Synology's advisory is linked as /en-global/ and
 * /zh-tw/). Used only to drop a repeat among one CVE's links.
 */
export function urlKey(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname
      .split("/")
      .filter((seg) => !/^[a-z]{2}[-_][a-z]{2,6}$/i.test(seg))
      .join("/")
      .replace(/\/+$/, "");
    return `${u.host.toLowerCase().replace(/^www\./, "")}${path}${u.search}`;
  } catch {
    return url;
  }
}

/* ---------- the CVE record ---------- */

interface CveVersion {
  version?: string;
  status?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
  changes?: { at?: string; status?: string }[];
}
interface CveAffected {
  vendor?: string;
  product?: string;
  packageName?: string;
  versions?: CveVersion[];
}
interface CveReference {
  url?: string;
  name?: string;
  tags?: string[];
}
interface CveLangText {
  lang?: string;
  value?: string;
}
interface CveContainer {
  title?: string;
  affected?: CveAffected[];
  references?: CveReference[];
  solutions?: CveLangText[];
  workarounds?: CveLangText[];
  providerMetadata?: { shortName?: string };
}
export interface CveRecord {
  cveMetadata?: { cveId?: string; state?: string; assignerShortName?: string };
  containers?: { cna?: CveContainer; adp?: CveContainer[] };
}

/** CNAs that are not the product's vendor, by the short name the record carries, as readers know them. */
const CNA_NAMES: Record<string, string> = {
  mitre: "MITRE",
  github_m: "GitHub",
  github_p: "GitHub",
  hackerone: "HackerOne",
  redhat: "Red Hat",
  "cisa-cg": "CISA",
  icscert: "CISA",
  vuldb: "VulDB",
  snyk: "Snyk",
  jpcert: "JPCERT/CC",
  certcc: "CERT/CC",
  "cert-pl": "CERT Polska",
  divd: "DIVD",
  zdi: "Zero Day Initiative",
  wordfence: "Wordfence",
  patchstack: "Patchstack",
  linux: "the Linux kernel CNA",
};
/** A CNA whose short name is a product of the vendor the record names. */
const CNA_VENDORS: Record<string, string[]> = { chrome: ["google"], netscaler: ["citrix"], palo_alto: ["palo alto networks"], talos: ["cisco"] };

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const EMPTY_NAME = /^(n\/a|na|unknown|unspecified|-|\*)?$/i;

/** Who a record's text is attributed to: the vendor it names when the CNA is that vendor, else the CNA. */
export function attribution(cna: string, vendors: readonly string[]): { by: string; by_vendor: boolean } {
  const key = norm(cna);
  const named = vendors.filter((v) => !EMPTY_NAME.test(v.trim()));
  const aliases = CNA_VENDORS[cna.toLowerCase()] ?? [];
  // the vendor's name holds the CNA's ("Palo Alto Networks" and palo_alto), or the CNA's holds a vendor name long enough
  // not to match by accident ("Google_Devices" and Google, but not GitHub_M and a vendor called "git")
  const vendor = named.find((v) => {
    const n = norm(v);
    return n === key || (key.length >= 3 && n.includes(key)) || (n.length >= 5 && key.includes(n)) || aliases.some((a) => n.includes(norm(a)));
  });
  if (vendor) return { by: vendor.trim().slice(0, 80), by_vendor: true };
  return { by: (CNA_NAMES[cna.toLowerCase()] ?? cna).slice(0, 80), by_vendor: false };
}

const OPEN_VERSION = /^(0|\*|n\/a|unspecified|unknown|all|-)?$/i;
const COMMIT = /^[0-9a-f]{12,40}$/i;

/** A version a reader could install: has a digit, is short, is not a wildcard or a commit hash. */
function concrete(v: string | undefined, type: string | undefined): v is string {
  if (!v) return false;
  const s = v.trim();
  return s.length <= 80 && /\d/.test(s) && !s.includes("*") && !OPEN_VERSION.test(s) && type !== "git" && !COMMIT.test(s);
}

function productLabel(a: CveAffected): string {
  const vendor = (a.vendor ?? "").trim();
  const product = (a.product ?? a.packageName ?? "").trim();
  const v = EMPTY_NAME.test(vendor) ? "" : vendor;
  const p = EMPTY_NAME.test(product) ? "" : product;
  // "Apache Software Foundation" + "Apache Roller" stays as it is; a product that already carries its vendor's name as a word is not prefixed again
  const named = v && new RegExp(`(^|[^a-z0-9])${v.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}($|[^a-z0-9])`).test(p.toLowerCase());
  if (v && p) return (named ? p : `${v} ${p}`).slice(0, 120);
  return (p || v).slice(0, 120);
}

/**
 * The fixed versions a record states, never a guess. Per product, in this
 * order of trust:
 *
 * 1. a version marked unaffected with an open range above it ("unaffected
 *    from 6.1.176 through 6.1.*", "unaffected from 7.2.2"): the CNA names
 *    the fix itself;
 * 2. where a product has none of those, the exclusive upper bound of an
 *    affected range ("affected from 7.2.2, less than 7.2.2-72806-1"), or a
 *    range's last change when that change is to unaffected.
 *
 * The first wins over the second because some CNAs use bounded affected
 * ranges for where a flaw was introduced (the Linux kernel's "5.4.73, less
 * than 5.5" is a branch, not a fix). An inclusive bound names the last
 * affected version and is left out, as are wildcards and commit hashes.
 *
 * 3. Where a product has neither, the versions the record marks unaffected
 *    on their own, with no range at all ("unaffected: 25.1.1.3"). These are
 *    kept with status "unaffected" and shown as "not affected", not as
 *    fixes: most are the fixed release (Ivanti, Atlassian, Adobe and VulDB
 *    write fixes this way), but a CNA also lists an older release the flaw
 *    never reached the same way (Ivanti's 22.7R2.14 for CVE-2026-104935,
 *    which its description says "or prior" is not impacted), and nothing in
 *    the record tells the two apart. A version marked unaffected with a
 *    bounded range ("unaffected from 0, less than 5.10") is an older range
 *    and is left out; so is "All", which says the product is not affected.
 */
export function fixedVersions(affected: readonly CveAffected[]): { patches: FixPatch[]; more: number } {
  const stated = new Map<string, FixPatch[]>();
  const bounds = new Map<string, FixPatch[]>();
  const listed = new Map<string, FixPatch[]>();
  const add = (to: Map<string, FixPatch[]>, label: string, version: string, from: string, status?: "unaffected") => {
    if (!label) return;
    const key = label.toLowerCase();
    const list = to.get(key) ?? [];
    if (!list.some((p) => p.version === version.trim() && p.from === from)) list.push({ label, version: version.trim(), from, url: null, source: "cve", ...(status ? { status } : {}) });
    to.set(key, list);
  };
  for (const a of affected) {
    const label = productLabel(a);
    for (const v of a.versions ?? []) {
      const from = concrete(v.version, v.versionType) && v.version !== v.lessThan ? v.version.trim() : "";
      const upper = v.lessThan ?? v.lessThanOrEqual;
      const open = upper ?? "";
      if (v.status === "unaffected" && concrete(v.version, v.versionType) && open.includes("*")) add(stated, label, v.version, open === "*" ? "" : open.trim().slice(0, 80));
      if (v.status === "unaffected" && upper === undefined) for (const one of standaloneVersions(v.version, v.versionType)) add(listed, label, one, "", "unaffected");
      if (v.status === "affected" && concrete(v.lessThan, v.versionType)) add(bounds, label, v.lessThan, from);
      const last = v.changes?.[v.changes.length - 1];
      if (v.status === "affected" && last?.status === "unaffected" && concrete(last.at, v.versionType)) add(bounds, label, last.at, from);
    }
  }
  const out: FixPatch[] = [];
  for (const key of new Set([...stated.keys(), ...bounds.keys(), ...listed.keys()])) out.push(...(stated.get(key) ?? bounds.get(key) ?? listed.get(key) ?? []));
  return { patches: out.slice(0, FIX_PATCH_MAX), more: Math.max(0, out.length - FIX_PATCH_MAX) };
}

/** A standalone version field as the versions it names: itself, or each of a comma-separated list (Adobe writes "2.4.9-2026-jul, 2.4.8-2026-jul, …" in one field). */
function standaloneVersions(version: string | undefined, type: string | undefined): string[] {
  const parts = (version ?? "").split(/,\s+/).map((s) => s.trim()).filter(Boolean);
  if (parts.length > 1 && parts.every((p) => concrete(p, type))) return parts;
  return concrete(version, type) ? [version.trim()] : [];
}

const CVE_TAGS: [string, FixLink["kind"]][] = [
  ["patch", "patch"],
  ["vendor-advisory", "advisory"],
  ["mitigation", "mitigation"],
  ["release-notes", "release_notes"],
];

function taggedLinks(refs: readonly CveReference[]): FixLink[] {
  const out: FixLink[] = [];
  for (const r of refs) {
    const url = webUrl(r.url);
    const tags = r.tags ?? [];
    if (!url || tags.includes("broken-link")) continue;
    const kind = CVE_TAGS.find(([tag]) => tags.includes(tag))?.[1];
    if (!kind) continue;
    const name = (r.name ?? "").trim();
    out.push({ url, kind, title: name && webUrl(name) === null ? name.slice(0, 200) : "", source: "cve" });
  }
  return out;
}

function texts(list: readonly CveLangText[] | undefined, section: string, cve: string, who: { by: string; by_vendor: boolean }): FixText[] {
  const out: FixText[] = [];
  for (const t of list ?? []) {
    if (t.lang && !/^en/i.test(t.lang)) continue;
    const tidy = tidyText(t.value ?? "");
    if (!tidy || out.some((o) => o.text.startsWith(tidy.slice(0, 80)))) continue;
    out.push({ ...cutText(tidy), kind: who.by_vendor ? "vendor" : "cna", source: { publisher: who.by || "CVE Program", title: `${cve}, CVE record: ${section}`, url: cveOrgUrl(cve) } });
    if (out.length === 2) break;
  }
  return out;
}

export type CveParts = Pick<FixEntry, "found" | "cna" | "by" | "by_vendor" | "title" | "affected" | "patches" | "patches_more" | "links" | "solutions" | "workarounds">;

export const NO_RECORD: CveParts = { found: false, cna: "", by: "", by_vendor: false, title: "", affected: [], patches: [], patches_more: 0, links: [], solutions: [], workarounds: [] };

/** The vendor and product pairs a record names as affected, each once, as the record spells them; a vendor left as n/a is "". */
export function affectedProducts(affected: readonly CveAffected[]): FixEntry["affected"] {
  const out: FixEntry["affected"] = [];
  for (const a of affected) {
    const vendor = EMPTY_NAME.test((a.vendor ?? "").trim()) ? "" : a.vendor!.trim().slice(0, 80);
    const named = (a.product ?? a.packageName ?? "").trim();
    const product = EMPTY_NAME.test(named) ? "" : named.slice(0, 120);
    if ((!vendor && !product) || out.some((x) => x.vendor.toLowerCase() === vendor.toLowerCase() && x.product.toLowerCase() === product.toLowerCase())) continue;
    out.push({ vendor, product });
    if (out.length === FIX_AFFECTED_MAX) break;
  }
  return out;
}

/** What a published CVE record says about fixing it; NO_RECORD for a reserved, rejected or malformed one. */
export function parseCveRecord(record: CveRecord, cve: string): CveParts {
  const cna = record.containers?.cna;
  if (!cna || record.cveMetadata?.state !== "PUBLISHED") return NO_RECORD;
  const short = (record.cveMetadata.assignerShortName ?? cna.providerMetadata?.shortName ?? "").trim().slice(0, 80);
  const affected = cna.affected ?? [];
  const who = attribution(short, affected.map((a) => a.vendor ?? ""));
  const { patches, more } = fixedVersions(affected);
  const refs = [...(cna.references ?? []), ...(record.containers?.adp ?? []).flatMap((a) => a.references ?? [])];
  return {
    found: true,
    cna: short,
    ...who,
    title: tidyText(cna.title ?? "").replace(/\n/g, " ").slice(0, 240),
    affected: affectedProducts(affected),
    patches,
    patches_more: more,
    links: taggedLinks(refs),
    solutions: texts(cna.solutions, "solution", cve, who),
    workarounds: texts(cna.workarounds, "workaround", cve, who),
  };
}

/* ---------- CISA KEV ---------- */

const NOTE_TAIL = /\s*For more information,? please see:?\s*$/i;

/**
 * True when a URL's hostname is `domain` itself or a subdomain of it:
 * "www.cisa.gov" for "cisa.gov", never "notcisa.gov" or
 * "cisa.gov.example.org". Every test of whose page a link is goes through
 * here, on the parsed hostname, never on a substring of the URL.
 */
export function isHostOf(url: string, domain: string): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return false;
  }
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

/**
 * An entry's notes: links and remarks separated by " ; ". A link on
 * cisa.gov is CISA's own guidance (the binding directive, labelled as the
 * note labels it); NVD's page is left to the reference row; any other link,
 * labelled or bare, is where CISA sends readers for the vendor's
 * instructions; anything else is a remark. Whose page a link is is decided
 * by its hostname alone: a label in the note never makes a link CISA's.
 */
export function parseKevNotes(notes: string | undefined): { links: FixLink[]; guidance: FixKev["guidance"]; note: string } {
  const links: FixLink[] = [];
  const guidance: FixKev["guidance"] = [];
  const remarks: string[] = [];
  const file = (url: string, label: string) => {
    if (isHostOf(url, "nvd.nist.gov")) return;
    if (isHostOf(url, "cisa.gov")) {
      if (guidance.length < 4) guidance.push({ label: label || "CISA", url });
    } else links.push({ url, kind: "advisory", title: label.slice(0, 200), source: "kev" });
  };
  for (const part of (notes ?? "").split(/\s+;\s*|;\s+/).map((s) => s.trim()).filter(Boolean)) {
    const labelled = /^([^:]{2,80}?):\s*(https?:\/\/\S+)$/.exec(part);
    if (labelled && !/^https?$/i.test(labelled[1]!)) {
      const url = webUrl(labelled[2]);
      if (url) file(url, labelled[1]!.trim());
      continue;
    }
    const urls = part.match(/https?:\/\/\S+/g) ?? [];
    for (const raw of urls) {
      const url = webUrl(raw.replace(/[),.]+$/, ""));
      if (url) file(url, "");
    }
    const text = part.replace(/https?:\/\/\S+/g, "").replace(NOTE_TAIL, "").trim();
    if (text.length > 3) remarks.push(text);
  }
  return { links, guidance, note: remarks.join(" ").slice(0, 400) };
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

export function kevBlock(v: KevEntry): { kev: FixKev; links: FixLink[] } {
  const { links, guidance, note } = parseKevNotes(v.notes);
  return {
    kev: {
      added: v.dateAdded,
      due: v.dueDate && DATE.test(v.dueDate) ? v.dueDate : null,
      action: tidyText(v.requiredAction ?? "").replace(/\n/g, " ").slice(0, 900),
      description: tidyText(v.shortDescription ?? "").replace(/\n/g, " ").slice(0, 700),
      note,
      guidance,
    },
    links,
  };
}

/* ---------- NVD and GitHub ---------- */

const NVD_TAGS: [string, FixLink["kind"]][] = [
  ["Patch", "patch"],
  ["Vendor Advisory", "advisory"],
  ["Mitigation", "mitigation"],
  ["Release Notes", "release_notes"],
];

export function nvdLinks(refs: readonly { url?: string; tags?: string[] }[] | undefined): FixLink[] {
  const out: FixLink[] = [];
  for (const r of refs ?? []) {
    const url = webUrl(r.url);
    const kind = NVD_TAGS.find(([tag]) => (r.tags ?? []).includes(tag))?.[1];
    if (url && kind && !(r.tags ?? []).includes("Broken Link")) out.push({ url, kind, title: "", source: "nvd" });
  }
  return out;
}

/** A reviewed advisory's first patched version per package, and the advisory itself as a link. An unreviewed one is NVD's text again and adds nothing. */
export function ghsaParts(adv: Advisory | null): { patches: FixPatch[]; links: FixLink[] } {
  const url = adv ? webUrl(adv.html_url) : null;
  // the link is shown as a GitHub advisory, so it must be a page on github.com
  if (!adv || !url || !isHostOf(url, "github.com") || adv.type !== "reviewed") return { patches: [], links: [] };
  const patches: FixPatch[] = [];
  for (const v of adv.vulnerabilities ?? []) {
    const name = v.package?.name?.trim();
    const fixed = v.first_patched_version?.trim();
    if (!name || !fixed) continue;
    const label = `${name}${v.package?.ecosystem ? ` (${v.package.ecosystem})` : ""}`.slice(0, 120);
    if (!patches.some((p) => p.label === label && p.version === fixed)) patches.push({ label, version: fixed.slice(0, 80), from: (v.vulnerable_version_range ?? "").trim().slice(0, 80), url, source: "ghsa" });
  }
  return { patches, links: [{ url, kind: "advisory", title: `${adv.ghsa_id}: ${adv.summary}`.slice(0, 200), source: "ghsa" }] };
}

/* ---------- putting an entry together ---------- */

const KIND_RANK: Record<FixLink["kind"], number> = { patch: 0, advisory: 1, mitigation: 2, release_notes: 3 };
const SOURCE_RANK: Record<FixLink["source"], number> = { cve: 0, nvd: 1, kev: 2, ghsa: 3 };

/**
 * One list of links: each page once (its best-ranked mention wins), ordered
 * patch, advisory, mitigation, release notes, and within a kind by how
 * directly the source vouches for it. The cap keeps a place for the best
 * link of every kind before the rest fill up.
 */
export function mergeLinks(...lists: readonly FixLink[][]): FixLink[] {
  const ranked = lists.flat().sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind] || SOURCE_RANK[a.source] - SOURCE_RANK[b.source]);
  const byKey = new Map<string, FixLink>();
  for (const l of ranked) {
    const key = urlKey(l.url);
    const had = byKey.get(key);
    if (!had) byKey.set(key, { ...l });
    else if (!had.title && l.title) had.title = l.title;
  }
  const all = [...byKey.values()];
  if (all.length <= FIX_LINK_MAX) return all;
  const firsts = (Object.keys(KIND_RANK) as FixLink["kind"][]).map((k) => all.find((l) => l.kind === k)).filter((l): l is FixLink => Boolean(l));
  const rest = all.filter((l) => !firsts.includes(l)).slice(0, FIX_LINK_MAX - firsts.length);
  return all.filter((l) => firsts.includes(l) || rest.includes(l));
}

function mergePatches(cve: readonly FixPatch[], more: number, ghsa: readonly FixPatch[]): { patches: FixPatch[]; patches_more: number } {
  const all = [...cve];
  for (const p of ghsa) if (!all.some((x) => x.version === p.version && norm(x.label).includes(norm(p.label.replace(/\s*\(.*\)$/, ""))))) all.push(p);
  return { patches: all.slice(0, FIX_PATCH_MAX), patches_more: more + Math.max(0, all.length - FIX_PATCH_MAX) };
}

export interface EntryParts {
  cve: string;
  fetched_at: string;
  record: CveParts;
  nvd: { at: string | null; links: FixLink[] };
  ghsa: { at: string | null; patches: FixPatch[]; links: FixLink[] };
  kev: { kev: FixKev; links: FixLink[] } | null;
}

export function buildEntry(p: EntryParts): FixEntry {
  const { record } = p;
  return {
    cve: p.cve,
    fetched_at: p.fetched_at,
    nvd_at: p.nvd.at,
    ghsa_at: p.ghsa.at,
    found: record.found,
    cna: record.cna,
    by: record.by,
    by_vendor: record.by_vendor,
    title: record.title,
    affected: record.affected,
    ...mergePatches(record.patches, record.patches_more, p.ghsa.patches),
    links: mergeLinks(record.links, p.nvd.links, p.kev?.links ?? [], p.ghsa.links),
    solutions: record.solutions,
    workarounds: record.workarounds,
    kev: p.kev?.kev ?? null,
  };
}

/* ---------- which CVEs, and which of them this run ---------- */

/** The CVEs the file holds: those on live records, KEV entries listed in the last `kevDays` days, and KEV entries whose deadline is today or later. */
export function wantedCves(liveCveIds: readonly string[], kev: readonly { cve: string; added: string; due: string | null }[], today: string, kevDays: number): string[] {
  const from = addDays(today, -kevDays);
  const out = new Set<string>();
  for (const id of liveCveIds) if (CVE.test(id)) out.add(id);
  for (const e of kev) if ((e.added > from && e.added <= today) || (e.due !== null && e.due >= today)) out.add(e.cve);
  return [...out].sort();
}

/**
 * This run's lookups: CVEs with no entry first (highest id first: the newest), then entries read at least
 * `recheckDays` ago, longest ago first. With `rechecks` false only the new ones: a re-read moves an entry's
 * stamps, which only a committed sweep keeps.
 */
export function planLookups(wanted: readonly string[], previous: ReadonlyMap<string, FixEntry>, now: Date, perRun: number, recheckDays: number, rechecks = true): string[] {
  const idOrder = (a: string, b: string) => {
    const [, ya, na] = CVE.exec(a)!;
    const [, yb, nb] = CVE.exec(b)!;
    return Number(yb) - Number(ya) || Number(nb) - Number(na);
  };
  const fresh = wanted.filter((id) => !previous.has(id)).sort(idOrder);
  const cutoff = now.getTime() - recheckDays * 86_400_000;
  const stale = wanted
    .filter((id) => previous.has(id) && Date.parse(previous.get(id)!.fetched_at) <= cutoff)
    .sort((a, b) => previous.get(a)!.fetched_at.localeCompare(previous.get(b)!.fetched_at) || a.localeCompare(b));
  return [...fresh, ...(rechecks ? stale : [])].slice(0, Math.max(0, perRun));
}

/* ---------- the module ---------- */

interface KevCatalog {
  catalogVersion?: string;
  vulnerabilities?: KevEntry[];
}

function githubHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  return { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", ...(token ? { authorization: `Bearer ${token}` } : {}) };
}

const short = (err: unknown) => (err instanceof Error ? err.message : String(err)).slice(0, 160);

/** The record's own parts of a stored entry, so an entry can be rebuilt (a new KEV block, a late NVD answer) without reading the CVE record again. */
function recordPartsOf(e: FixEntry): CveParts {
  return {
    found: e.found,
    cna: e.cna,
    by: e.by,
    by_vendor: e.by_vendor,
    title: e.title,
    affected: e.affected,
    patches: e.patches.filter((x) => x.source === "cve"),
    patches_more: e.patches_more,
    links: e.links.filter((l) => l.source === "cve"),
    solutions: e.solutions,
    workarounds: e.workarounds,
  };
}

/** NVD is asked only when the record itself tags neither a patch nor a vendor advisory. */
export function needsNvd(r: Pick<CveParts, "found" | "links">): boolean {
  return r.found && !r.links.some((l) => l.source === "cve" && (l.kind === "patch" || l.kind === "advisory"));
}

/** GitHub is asked only when the record itself lists no fixed version. */
export function needsGhsa(r: Pick<CveParts, "found" | "patches">): boolean {
  return r.found && !r.patches.some((p) => p.source === "cve");
}

export const fixesModule: StatsModule<Fixes> = {
  name: "fixes",
  file: STATS_FILES.fixes,
  schema: FixesSchema,
  maxAgeHours: 0,
  volatile: /"(?:fetched_at|nvd_at|ghsa_at)":\s?(?:"[^"]*"|null)/g,
  async fetch(ctx: StatsContext, previous: Fixes | null) {
    const cfg = ctx.settings.fix_lookup;
    if (cfg.per_run === 0) return null;
    const nowIso = ctx.now.toISOString();
    const today = nowIso.slice(0, 10);
    const kevStats = (ctx.produced["kev"] as KevStats | null | undefined) ?? null;
    const wanted = wantedCves(ctx.liveCveIds ?? [], kevStats?.entries ?? [], today, cfg.kev_days);
    const prev = new Map((previous?.entries ?? []).map((e) => [e.cve, e]));
    const listed = new Set((kevStats?.entries ?? []).map((e) => e.cve));
    const rechecks = ctx.rechecks !== false;
    const due = planLookups(wanted, prev, ctx.now, cfg.per_run, cfg.recheck_days, rechecks);
    const http = { userAgent: ctx.settings.fetch.user_agent, timeoutMs: ctx.settings.fetch.timeout_ms };

    // CISA's own words and links: the raw catalog, once per catalog release, or when an entry on it still lacks them
    let catalogVersion = previous?.kev_catalog_version ?? "";
    let raw: Map<string, KevEntry> | null = null;
    const onKev = wanted.filter((id) => listed.has(id));
    const missingBlock = onKev.some((id) => !prev.get(id)?.kev && (prev.has(id) || due.includes(id)));
    if (onKev.length && kevStats && (kevStats.catalog_version !== catalogVersion || missingBlock)) {
      try {
        const catalog = await ctx.http.json<KevCatalog>(KEV_URL, { ...http, timeoutMs: 40_000, retries: 2, maxBytes: 10_000_000 });
        raw = new Map((catalog.vulnerabilities ?? []).map((v) => [v.cveID, v]));
        catalogVersion = catalog.catalogVersion ?? kevStats.catalog_version;
      } catch (err) {
        ctx.log("stats fixes: the KEV catalog could not be read, keeping the previous deadlines and actions", { error: short(err) });
      }
    }
    const kevOf = (id: string, had: FixEntry | undefined): EntryParts["kev"] => {
      const v = raw?.get(id);
      if (v) return kevBlock(v);
      return had?.kev && listed.has(id) ? { kev: had.kev, links: had.links.filter((l) => l.source === "kev") } : null;
    };

    const counts = { looked_up: 0, not_published: 0, nvd: 0, ghsa: 0, failed: 0 };
    let ghsaOff = cfg.ghsa_per_run === 0;
    /** NVD's tags for one CVE; null when the budget is spent or the request failed (the entry asks again next run). */
    const askNvd = async (cve: string): Promise<EntryParts["nvd"] | null> => {
      if (counts.nvd >= cfg.nvd_per_run) return null;
      counts.nvd += 1;
      try {
        const res = await nvdGet(ctx, { cveId: cve }, []);
        return { at: nowIso, links: nvdLinks(res.vulnerabilities?.[0]?.cve.references) };
      } catch (err) {
        ctx.log(`stats fixes: NVD lookup for ${cve} failed`, { error: short(err) });
        return null;
      }
    };
    /** GitHub's advisory for one CVE; null when the budget is spent or GitHub refused (a rate limit ends the lookups for this run). */
    const askGhsa = async (cve: string): Promise<EntryParts["ghsa"] | null> => {
      if (ghsaOff || counts.ghsa >= cfg.ghsa_per_run) return null;
      counts.ghsa += 1;
      try {
        await ctx.http.sleep(SPACING_MS);
        const list = await ctx.http.json<Advisory[]>(`https://api.github.com/advisories?cve_id=${encodeURIComponent(cve)}&per_page=1`, { ...http, retries: 0, headers: githubHeaders() });
        return { at: nowIso, ...ghsaParts(Array.isArray(list) && list.length ? list[0]! : null) };
      } catch (err) {
        ghsaOff = true;
        ctx.log(`stats fixes: GitHub advisory lookup for ${cve} failed, no more this run`, { error: short(err) });
        return null;
      }
    };
    const keptNvd = (had: FixEntry | undefined): EntryParts["nvd"] => ({ at: had?.nvd_at ?? null, links: (had?.links ?? []).filter((l) => l.source === "nvd") });
    const keptGhsa = (had: FixEntry | undefined): EntryParts["ghsa"] => ({
      at: had?.ghsa_at ?? null,
      patches: (had?.patches ?? []).filter((x) => x.source === "ghsa"),
      links: (had?.links ?? []).filter((l) => l.source === "ghsa"),
    });

    // one odd record must not cost the run its whole file: an entry that does not fit the schema is logged and the previous one kept
    const fitting = (e: FixEntry, had: FixEntry | undefined): FixEntry | null => {
      const parsed = FixEntrySchema.safeParse(e);
      if (parsed.success) return e;
      const issue = parsed.error.issues[0];
      ctx.log(`stats fixes: ${e.cve} does not fit the schema, keeping what was there`, { at: issue?.path.join("."), issue: issue?.message });
      return had ?? null;
    };

    // this run's CVE records, each with the NVD and GitHub answers it needs while the budgets last
    const built = new Map<string, FixEntry>();
    let failures = 0;
    for (const cve of due) {
      if (failures >= MAX_FAILURES) break;
      const had = prev.get(cve);
      if (counts.looked_up + counts.failed > 0) await ctx.http.sleep(SPACING_MS);
      let record: CveParts;
      try {
        record = parseCveRecord(await ctx.http.json<CveRecord>(cveRecordUrl(cve), { ...http, retries: 1, maxBytes: 2_000_000 }), cve);
        failures = 0;
      } catch (err) {
        if (err instanceof HttpError && err.status === 404) record = NO_RECORD;
        else {
          failures += 1;
          counts.failed += 1;
          ctx.log(`stats fixes: ${cve} could not be read`, { error: short(err) });
          continue;
        }
      }
      counts.looked_up += 1;
      if (!record.found) counts.not_published += 1;
      const nvd = (needsNvd(record) ? await askNvd(cve) : null) ?? keptNvd(had);
      const ghsa = (needsGhsa(record) ? await askGhsa(cve) : null) ?? keptGhsa(had);
      const entry = fitting(buildEntry({ cve, fetched_at: nowIso, record, nvd, ghsa, kev: kevOf(cve, had) }), had);
      if (entry) built.set(cve, entry);
    }

    // entries not read this run keep what they had; one that has not yet had its NVD or GitHub answer gets it
    // while the budgets last, and a new catalog release refreshes every KEV block
    const entries: FixEntry[] = [];
    for (const cve of wanted) {
      const fresh = built.get(cve);
      if (fresh) {
        entries.push(fresh);
        continue;
      }
      const had = prev.get(cve);
      if (!had) continue;
      const record = recordPartsOf(had);
      const nvd = (rechecks && needsNvd(record) && had.nvd_at === null ? await askNvd(cve) : null) ?? keptNvd(had);
      const ghsa = (rechecks && needsGhsa(record) && had.ghsa_at === null ? await askGhsa(cve) : null) ?? keptGhsa(had);
      const entry = fitting(buildEntry({ cve, fetched_at: had.fetched_at, record, nvd, ghsa, kev: kevOf(cve, had) }), had);
      if (entry) entries.push(entry);
    }
    ctx.log("stats fixes: done", { rechecks, wanted: wanted.length, entries: entries.length, waiting: wanted.length - entries.length, ...counts, kev_catalog: raw ? "read" : "kept" });
    return { fetched_at: nowIso, sources: [...FIX_SOURCE_LIST], kev_catalog_version: catalogVersion, entries };
  },
};
