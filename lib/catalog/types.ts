/**
 * The My stack catalog: the vendors and products a visitor can watch
 * (lib/panel/stack.ts builds the page's candidates from it).
 *
 * Two levels. A vendor entry ("Microsoft") stands for everything the vendor
 * makes: it holds what its own rules match and everything its products
 * match. A product entry ("Windows", "Exchange Server") holds only its own.
 * Every entry has one category, the group the chooser lists it under.
 *
 * How an entry is matched (lib/catalog/match.ts) depends on what is being
 * read, because a name that is safe in a vendor column is not safe in a
 * sentence:
 *
 *  - CISA's KEV catalog and the CVE Program's vendor and product names are
 *    columns. `kevVendors` claims every row under a vendor name; `kev` rules
 *    read the product column (or the entry's name) of rows under the entry's
 *    own vendor names; `terms` are then tried on vendor and product together.
 *    A product with a parent tries its terms only on rows of its own vendor
 *    family, so "Edge" never claims another vendor's "SD-WAN Edge".
 *  - A record's product names are tried one by one against `terms`.
 *  - A record's title and tags are free text: `text` (default `terms`).
 *  - A CVE description is free text with platform mentions in it ("plugin
 *    for WordPress", "on Windows"): `cve` (default `text`), and the matcher
 *    skips a hit that follows "for", "on", "with" and the like.
 *
 * Terms are regular-expression sources in lower case; the matcher adds the
 * word boundaries. A short or common name (Teams, Edge, Git, Go, Rust,
 * Apple, Oracle) gets strict `text` and `cve` patterns, or none.
 */

export const CATEGORIES = [
  { key: "vendor", label: "Big vendors", note: "one pick covers everything the vendor makes" },
  { key: "os", label: "Operating systems" },
  { key: "browser", label: "Browsers" },
  { key: "email", label: "Email, chat & meetings" },
  { key: "network", label: "Network, firewalls & VPN" },
  { key: "cloud", label: "Cloud, virtual machines & containers" },
  { key: "identity", label: "Sign-in & identity" },
  { key: "database", label: "Databases & data platforms" },
  { key: "web", label: "Web servers, languages & libraries" },
  { key: "cms", label: "Websites, CMS & shops" },
  { key: "dev", label: "Developer tools & CI" },
  { key: "remote", label: "Remote access & IT management" },
  { key: "storage", label: "Backup, storage & file transfer" },
  { key: "endpoint", label: "Security & monitoring tools" },
  { key: "business", label: "Business & office software" },
  { key: "ai", label: "AI products" },
  { key: "devices", label: "Devices, chips & industrial" },
  { key: "kev", label: "More from CISA’s list", note: "every other vendor on CISA’s Known Exploited Vulnerabilities catalog" },
] as const;

export type CategoryKey = (typeof CATEGORIES)[number]["key"];

/** The category of an entry that is not curated: a vendor found only on CISA's list. */
export const TAIL_CATEGORY: CategoryKey = "kev";

export interface KevRule {
  /** A pattern over CISA's product column. */
  product?: string;
  /** A pattern over the entry's name ("Apple Multiple Products WebKit …"), for rows whose product column says nothing. */
  name?: string;
  /** Vendor names the rule reads; default: the entry's own vendor family. */
  vendors?: string[];
}

export interface CatalogEntry {
  /** Stable: the key a pick is stored and shared under. */
  key: string;
  name: string;
  /** The vendor's name as shown beside the product. */
  vendor: string;
  cat: CategoryKey;
  level: "vendor" | "product";
  /** The vendor entry that covers this one. */
  parent?: string;
  /** CISA vendor-column names (exact, any case) whose every row belongs here. */
  kevVendors: string[];
  kev: KevRule[];
  terms: string[];
  /** Free-text terms for a record's title and tags; undefined: `terms`; empty: never. */
  text?: string[];
  /** Free-text terms for a CVE description; undefined: `text`; empty: never. */
  cve?: string[];
  /** The AI product family (lib/products.ts productFamily) whose records and KEV entries belong here. */
  family?: string;
  /** Other words the chooser's search answers to. */
  aka: string[];
  /** Keys this entry was picked under before; saved picks and shared links still open it. */
  was: string[];
  /** One of the short list a first visit is offered. */
  popular: boolean;
}

/** The short option names the entry files use. */
export interface EntryOptions {
  /** terms, replacing the one derived from the name */
  t?: string[];
  /** text: free-text terms for titles and tags */
  x?: string[];
  /** cve: free-text terms for CVE descriptions */
  c?: string[];
  /** kevVendors */
  kv?: string[];
  /** a pattern over CISA's product column, within the entry's vendor family */
  k?: string;
  /** a pattern over CISA's entry name, within the entry's vendor family */
  kn?: string;
  /** further KEV rules */
  kev?: KevRule[];
  /** the AI product family */
  f?: string;
  aka?: string[];
  was?: string[];
  pop?: boolean;
}

/** A name as a term: lower case, regex-escaped. */
export function termOf(name: string): string {
  return name
    .toLowerCase()
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\s+/g, " ");
}

function make(level: CatalogEntry["level"], key: string, name: string, vendor: string, cat: CategoryKey, parent: string | undefined, o: EntryOptions, kevVendors: string[]): CatalogEntry {
  const kev: KevRule[] = [...(o.kev ?? [])];
  if (o.k) kev.push({ product: o.k });
  if (o.kn) kev.push({ name: o.kn });
  return {
    key,
    name,
    vendor,
    cat,
    level,
    ...(parent ? { parent } : {}),
    kevVendors,
    kev,
    terms: o.t ?? (o.f ? [] : [termOf(name)]),
    ...(o.x ? { text: o.x } : {}),
    ...(o.c ? { cve: o.c } : {}),
    ...(o.f ? { family: o.f } : {}),
    aka: o.aka ?? [],
    was: o.was ?? [],
    popular: Boolean(o.pop),
  };
}

/** A vendor: everything it makes. CISA's rows under its name belong to it unless `kv` says otherwise. */
export function V(key: string, name: string, cat: CategoryKey, o: EntryOptions = {}): CatalogEntry {
  return make("vendor", key, name, name, cat, undefined, o, o.kv ?? [name]);
}

/** A vendor that belongs to another vendor (VMware under Broadcom): covered by its parent, covering its own products. */
export function VP(key: string, name: string, parent: string, cat: CategoryKey, o: EntryOptions = {}): CatalogEntry {
  return make("vendor", key, name, name, cat, parent, o, o.kv ?? [name]);
}

/** A product of a vendor entry; `vendor` is filled in from the parent when the catalog is assembled. */
export function P(key: string, name: string, parent: string, cat: CategoryKey, o: EntryOptions = {}): CatalogEntry {
  return make("product", key, name, "", cat, parent, o, o.kv ?? []);
}

/** A product on its own: an open-source project, or the one product of a vendor not listed as a vendor. */
export function S(key: string, name: string, vendor: string, cat: CategoryKey, o: EntryOptions = {}): CatalogEntry {
  return make("product", key, name, vendor || name, cat, undefined, o, o.kv ?? []);
}
