/**
 * The CVE Program's vendor and product names per CVE, when a file on main
 * carries them (the fix-first detail work plans one, keyed by CVE id). With
 * them a new critical CVE is matched on names in columns, the way a KEV
 * entry is, instead of on its description (lib/catalog/match.ts). The file is
 * optional and its shape is not this module's to fix, so the reader takes the
 * common ones and returns an empty map for anything else:
 *
 *   { "CVE-2026-1": { vendor, product } }                      keyed by id
 *   { cves | fixes | entries | items: { "CVE-…": … } | [ … ] } one level down
 *   [ { cve | id | cve_id: "CVE-…", … } ]                      a list
 *
 * and inside an entry: `affected: [{ vendor, product }]`, or `vendor` and
 * `product` (strings or lists of strings).
 */

export interface Affected {
  vendor: string;
  product: string;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const HOLDERS = ["cves", "fixes", "entries", "items", "records"] as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function strings(v: unknown): string[] {
  if (typeof v === "string") return v.trim() ? [v.trim()] : [];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim() !== "").map((x) => x.trim()) : [];
}

function pairsOf(entry: unknown): Affected[] {
  if (!isRecord(entry)) return [];
  const out: Affected[] = [];
  const add = (vendor: string, product: string) => {
    if ((vendor || product) && !out.some((p) => p.vendor === vendor && p.product === product)) out.push({ vendor, product });
  };
  if (Array.isArray(entry.affected)) {
    for (const a of entry.affected) if (isRecord(a)) for (const v of strings(a.vendor).length ? strings(a.vendor) : [""]) for (const p of strings(a.product).length ? strings(a.product) : [""]) add(v, p);
  }
  const vendors = strings(entry.vendor ?? entry.vendors);
  const products = strings(entry.product ?? entry.products);
  for (const v of vendors.length ? vendors : products.length ? [""] : []) for (const p of products.length ? products : [""]) add(v, p);
  return out;
}

export function affectedByCve(raw: unknown): Map<string, Affected[]> {
  const out = new Map<string, Affected[]>();
  const put = (id: unknown, entry: unknown) => {
    if (typeof id !== "string" || !CVE_ID.test(id)) return;
    const pairs = pairsOf(entry);
    if (pairs.length) out.set(id.toUpperCase(), pairs);
  };
  const read = (v: unknown) => {
    if (Array.isArray(v)) for (const e of v) if (isRecord(e)) put(e.cve ?? e.id ?? e.cve_id, e);
    if (isRecord(v)) for (const [k, e] of Object.entries(v)) put(k, e);
  };
  read(raw);
  if (isRecord(raw)) for (const h of HOLDERS) read(raw[h]);
  return out;
}
