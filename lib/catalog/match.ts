import { productFamily } from "../products";
import { CATALOG, ancestorsOf } from "./index";
import type { CatalogEntry } from "./types";

/**
 * Matching catalog entries against the three things My stack reads
 * (lib/catalog/types.ts says which terms apply where):
 *
 *  - `columns`: a vendor and product pair, CISA's KEV columns or the CVE
 *    Program's affected names. Vendor names the entry claims first, then its
 *    product rules, then its terms on vendor and product together; a product
 *    with a parent tries its terms only on rows of its own vendor family.
 *    An add-on is filed under what it adds on to, as CISA files a WordPress
 *    plugin under WordPress; only "X for Y" is not Y.
 *  - `record`: one of our records, by its product names, then its title and
 *    tags. A product name that maps to an AI family (lib/products.ts) belongs
 *    to that family alone, so "MCP Atlassian" is an MCP server, not Atlassian;
 *    and a vendor that only reports the news ("Google disrupts …") is not hit.
 *  - `describes`: a CVE description, the strict one: the entry has to be the
 *    subject of the sentence (subjectOf), not a platform it mentions.
 *
 * Several hundred entries are tried against every row, so what does not
 * depend on the entry is worked out once per string and kept (the caches
 * below): the lower-cased text, a product's family, a sentence's subject.
 */

export interface RecordLike {
  title: string;
  products: readonly string[];
  tags: readonly string[];
}

export interface Matcher {
  entry: CatalogEntry;
  columns(vendor: string, product: string, name?: string): boolean;
  record(i: RecordLike): boolean;
  describes(description: string): boolean;
}

function memo<V>(make: (s: string) => V, max = 60_000): (s: string) => V {
  const kept = new Map<string, V>();
  return (s) => {
    let v = kept.get(s);
    if (v === undefined) {
      if (kept.size >= max) kept.clear();
      v = make(s);
      kept.set(s, v);
    }
    return v;
  };
}

/** Lower case, single spaces. */
export const norm = memo((s: string) => s.toLowerCase().replace(/\s+/g, " ").trim());

const familyOf = memo((name: string) => productFamily(name));

/** A set of term sources as one pattern with word boundaries; null for none. Throws on a source that does not compile. */
export function termPattern(sources: readonly string[], flags = ""): RegExp | null {
  if (sources.length === 0) return null;
  for (const s of sources) new RegExp(s);
  return new RegExp(`(?<![a-z0-9])(?:${sources.join("|")})(?![a-z0-9])`, flags);
}

/* ---------- CVE descriptions: is the entry the subject? ---------- */

/** Words before a name that make it the platform, not the product at fault. */
const PLATFORM_BEFORE = /(?:^|[^a-z0-9])(?:for|on|with|using|uses|use|via|from|to|into|by|as|under|against|like|than|supports?|including|e\.g\.|such as)(?: the| a| an| its| their)?$/;
/** Words after a name that make the hit something made for it. */
const ADDON_AFTER = /^(?:'s)? (?:plugins?|themes?|extensions?|add-?ons?|modules?|integrations?|connectors?|drivers?|adapters?|providers?|clients?|apps?|import|support|sdk|bot|mcp|accounts?)(?![a-z0-9])/;
/** "The <name> plugin for <platform>" and "The <name> WordPress plugin": only the name's first word is the subject. */
const ADDON_SUBJECT = /^the (.{1,120}?) (?:(?:plugins?|add-?ons?|themes?|extensions?|modules?) for [a-z]|wordpress (?:plugins?|themes?))/;
/** "<Name> is a …": an introduction, whose subject is the name. */
const INTRO_SUBJECT = /^(.{1,80}?) (?:is|are) (?:an?|the) /;
/** "<Name> before 1.2.3 …", "<Name> 4.0 through 4.2 …": the subject is what the versions belong to. */
const VERSIONED_SUBJECT = /^(.{1,60}?),? (?:(?:versions? )?(?:before|through|prior to|up to|below|from|until|<=?|>=?) ?(?:version |v)?\d|versions? v?\d|v?\d+\.\d)/;
/** Where the sentence stops naming its subject: the first version number or the verb that says what the flaw allows. */
const HEAD_END = /\d+\.\d+| (?:allows?|could|can|may|might|via|because|due to|leading|resulting|which|that|does not|do not|fails?|lets|permits?) /;
/** "… in <name>", "… of <vendor> <name>": named as the place of the flaw, wherever in the sentence. */
const NAMED_AS_PLACE = /(?:^|[^a-z0-9])(?:in|of|affects|affecting)(?: the)?(?: [a-z0-9][a-z0-9.+-]*){0,2}$/;

export interface Subject {
  /** The first and last index a subject hit may start at; null when the sentence has no recognisable subject span. */
  span: [number, number] | null;
  head: number;
}

/** Where a (lower-cased) description names what it is about. */
export const subjectOf = memo((text: string): Subject => {
  if (ADDON_SUBJECT.test(text)) return { span: [4, 4], head: 0 };
  const lead = INTRO_SUBJECT.exec(text) ?? VERSIONED_SUBJECT.exec(text);
  if (lead) return { span: [0, lead[1]!.length - 1], head: 0 };
  const end = HEAD_END.exec(text);
  return { span: null, head: end ? end.index : text.length };
});

/** A term hit in a description that is the subject, not a platform, an add-on's host or part of another name. */
function describesWith(rx: RegExp, text: string): boolean {
  rx.lastIndex = 0;
  let subject: Subject | null = null;
  for (let m = rx.exec(text); m; m = rx.exec(text)) {
    if (m[0].length === 0) {
      rx.lastIndex += 1;
      continue;
    }
    const start = m.index;
    const before = text.slice(Math.max(0, start - 44), start);
    const after = text.slice(start + m[0].length, start + m[0].length + 18);
    // part of another name: "mcp-atlassian", "rabbitmq-c", "asp.net-core-inventory"
    if (/[-_/@]$/.test(before) || /^[-_][a-z0-9]/.test(after)) continue;
    if (PLATFORM_BEFORE.test(before.trimEnd()) || ADDON_AFTER.test(after)) continue;
    subject ??= subjectOf(text);
    if (subject.span ? start >= subject.span[0] && start <= subject.span[1] : start < subject.head || NAMED_AS_PLACE.test(before.trimEnd())) return true;
  }
  return false;
}

/* ---------- names in columns and product lists ---------- */

/** A name that names the entry, not something made "for" it ("Driver for Windows", "Library for Node.js"). */
function namesProduct(rx: RegExp, name: string): boolean {
  const m = rx.exec(name);
  return m !== null && !/(?:^|[^a-z0-9])for$/.test(name.slice(0, m.index).trimEnd());
}

/* ---------- records ---------- */

/** A title that opens with who found or stopped something: that name is the reporter, not what was hit. */
const REPORTER = /^.{2,40}? (discovers|disrupts|uncovers|dismantles|tracks|attributes|links|sues|bans|takes down|seizes|identifies|observes|details)(?![a-z])/;

interface ReadRecord {
  /** The AI family of each product name that maps to one. */
  families: Set<string>;
  /** The product names that map to no family, lower-cased: the ones terms are tried on. */
  names: string[];
  /** The title and tags as free text, and the title alone. */
  text: string;
  title: string;
}

const read = new WeakMap<RecordLike, ReadRecord>();

function readRecord(i: RecordLike): ReadRecord {
  let r = read.get(i);
  if (r) return r;
  const families = new Set<string>();
  const names: string[] = [];
  // a family product's name is text that belongs to the family, in both spellings a title or tag uses
  const owned: string[] = [];
  for (const raw of i.products) {
    const fam = familyOf(raw);
    const n = norm(raw);
    if (fam === raw.trim()) names.push(n);
    else {
      families.add(fam);
      if (n) owned.push(n, n.replace(/ /g, "-"));
    }
  }
  owned.sort((a, b) => b.length - a.length);
  const strip = (s: string) => owned.reduce((t, n) => t.split(n).join(" "), s);
  const title = norm(i.title).replace(REPORTER, "$1");
  r = { families, names, text: strip(norm([title, ...i.tags].join(" "))), title: strip(title) };
  read.set(i, r);
  return r;
}

/** A record's title (and its tags), without the family product names and the reporter in them. */
export function recordFreeText(i: RecordLike, withTags = true): string {
  const r = readRecord(i);
  return withTags ? r.text : r.title;
}

export function compile(entry: CatalogEntry, all: readonly CatalogEntry[] = CATALOG): Matcher {
  const byKey = new Map(all.map((e) => [e.key, e]));
  const up = ancestorsOf(entry, byKey);
  const own = new Set(entry.kevVendors.map(norm));
  const family = new Set([...own, ...up.flatMap((a) => a.kevVendors.map(norm))]);
  const terms = termPattern(entry.terms);
  const text = termPattern(entry.text ?? entry.terms);
  const cve = termPattern(entry.cve ?? entry.text ?? entry.terms, "g");
  const upTerms = termPattern(up.flatMap((a) => a.terms));
  const scoped = entry.level === "product" && up.length > 0;
  // makers of security tools are named in tags as the source of a report, so their tags are not read
  const withTags = entry.cat !== "endpoint";
  const rules = entry.kev.map((r) => ({
    vendors: r.vendors ? new Set(r.vendors.map(norm)) : null,
    product: r.product ? new RegExp(r.product) : null,
    name: r.name ? new RegExp(r.name) : null,
  }));
  /** A vendor name inside the entry's own family: one it or its ancestors claim, or one their terms name ("Oracle Corporation"). */
  const inFamily = memo((v: string) => family.has(v) || Boolean(upTerms?.test(v)) || Boolean(terms?.test(v)), 5_000);

  return {
    entry,
    columns(vendor, product, name) {
      const v = norm(vendor);
      if (own.has(v)) return true;
      const p = norm(product);
      for (const r of rules) {
        if (r.vendors ? !r.vendors.has(v) : !inFamily(v)) continue;
        if (r.product && !r.product.test(p)) continue;
        if (r.name && !(name && r.name.test(norm(name)))) continue;
        return true;
      }
      if (entry.family && familyOf(product) === entry.family) return true;
      if (!terms || (scoped && !inFamily(v))) return false;
      return namesProduct(terms, `${v} ${p}`);
    },
    record(i) {
      const r = readRecord(i);
      if (entry.family && r.families.has(entry.family)) return true;
      if (terms) for (const n of r.names) if (namesProduct(terms, n)) return true;
      return text ? text.test(withTags ? r.text : r.title) : false;
    },
    describes(description) {
      return cve ? describesWith(cve, norm(description)) : false;
    },
  };
}

let compiled: Matcher[] | null = null;

/** Every curated entry's matcher, compiled once. */
export function catalogMatchers(): Matcher[] {
  compiled ??= CATALOG.map((e) => compile(e));
  return compiled;
}
