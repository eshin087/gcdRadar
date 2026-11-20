import { stackKey } from "../panel/picks";
import { PRODUCT_FAMILY_LABELS } from "../products";
import { AI } from "./entries/ai";
import { INFRASTRUCTURE } from "./entries/infrastructure";
import { SOFTWARE } from "./entries/software";
import { VENDORS } from "./entries/vendors";
import { S, type CatalogEntry } from "./types";

export { CATEGORIES, TAIL_CATEGORY, type CatalogEntry, type CategoryKey, type KevRule } from "./types";

/** Lower-case slug of a label: the key scheme My stack has always used ("Palo Alto Networks" -> "palo-alto-networks"). */
export const catalogKey = stackKey;

function assemble(): CatalogEntry[] {
  const list = [...VENDORS, ...INFRASTRUCTURE, ...SOFTWARE, ...AI];
  // a product family the AI list does not name still gets its entry, under its label's slug
  const families = new Set(list.map((e) => e.family).filter(Boolean));
  for (const label of PRODUCT_FAMILY_LABELS) if (!families.has(label)) list.push(S(catalogKey(label), label, label, "ai", { f: label }));
  const byKey = new Map(list.map((e) => [e.key, e]));
  // a product shows its parent's name as its vendor
  return list.map((e) => (e.level === "product" && e.parent && !e.vendor ? { ...e, vendor: byKey.get(e.parent)?.name ?? "" } : e));
}

/** The curated catalog: every vendor and product a visitor can always pick, whether or not anything hit it lately. */
export const CATALOG: readonly CatalogEntry[] = assemble();

const BY_KEY = new Map(CATALOG.map((e) => [e.key, e]));

export function catalogEntry(key: string): CatalogEntry | undefined {
  return BY_KEY.get(key);
}

/** The entries above an entry, nearest first: a product's vendor, and that vendor's own parent. */
export function ancestorsOf(e: CatalogEntry, byKey: ReadonlyMap<string, CatalogEntry> = BY_KEY): CatalogEntry[] {
  const out: CatalogEntry[] = [];
  let p = e.parent ? byKey.get(e.parent) : undefined;
  while (p && !out.includes(p) && p !== e) {
    out.push(p);
    p = p.parent ? byKey.get(p.parent) : undefined;
  }
  return out;
}

/** For each key, the keys of everything under it (a vendor's products, and theirs). */
export function descendants(entries: readonly CatalogEntry[] = CATALOG): Map<string, string[]> {
  const byKey = new Map(entries.map((e) => [e.key, e]));
  const out = new Map<string, string[]>();
  for (const e of entries) for (const a of ancestorsOf(e, byKey)) out.set(a.key, [...(out.get(a.key) ?? []), e.key]);
  return out;
}

/** The top of an entry's family: itself when nothing covers it. */
export function rootOf(e: CatalogEntry): CatalogEntry {
  const up = ancestorsOf(e);
  return up[up.length - 1] ?? e;
}
