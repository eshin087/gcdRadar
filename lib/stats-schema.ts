import { z } from "zod";

/**
 * The statistics files the collector's stats stage writes under
 * data/stats/ (collector/stats/*), and the public shape prebuild derives
 * from them for the home page (lib/home.ts). Each data file carries when it
 * was fetched and where it came from, so every number on the page can name
 * its source and its age. A file that is missing or fails its schema hides
 * its panel; it never fails a build (lib/data.ts loadStats).
 */

const isoDateTime = z.iso.datetime();
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "YYYY-MM-DD");
const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/);
const count = z.number().int().min(0);

export const StatsSourceSchema = z.object({
  name: z.string().min(1),
  url: z.url(),
  license: z.string().min(1),
});
export type StatsSource = z.infer<typeof StatsSourceSchema>;

/** CVEs published per year, from NVD's totalResults over publish-date windows. */
export const NvdCountsSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  years: z.array(z.object({ year: z.number().int().min(1999), total: count })),
});
export type NvdCounts = z.infer<typeof NvdCountsSchema>;

export const RecentCveSchema = z.object({
  id: cveId,
  /** Publish time in UTC. */
  published: isoDateTime,
  /** CVSS base score, the newest version NVD scored (4.0, then 3.1, then 3.0); null when unscored. */
  score: z.number().min(0).max(10).nullable(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).nullable(),
  version: z.enum(["4.0", "3.1", "3.0"]).nullable(),
  description: z.string().max(200),
});
export type RecentCve = z.infer<typeof RecentCveSchema>;

/** Every CVE published in the last `window_days`, from NVD. */
export const CvesRecentSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  window_days: z.number().int().positive(),
  cves: z.array(RecentCveSchema),
});
export type CvesRecent = z.infer<typeof CvesRecentSchema>;

/**
 * CVEs published per UTC day (and those scored 9.0 or higher), the newest
 * 120 complete days, counted from cves-recent on every stats run
 * (collector/stats/daily.ts).
 */
export const DailyStatsSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  days: z.record(isoDate, z.object({ cves: count, critical: count })),
});
export type DailyStats = z.infer<typeof DailyStatsSchema>;

export const KevStatEntrySchema = z.object({
  cve: cveId,
  added: isoDate,
  due: isoDate.nullable(),
  vendor: z.string(),
  product: z.string(),
  name: z.string(),
  ransomware: z.boolean(),
  /** NVD publish date, joined through the API's hasKev query; null until known. */
  published: isoDate.nullable(),
  cvss: z.number().min(0).max(10).nullable(),
});
export type KevStatEntry = z.infer<typeof KevStatEntrySchema>;

/** The whole CISA KEV catalog, reduced. */
export const KevStatsSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  catalog_version: z.string(),
  entries: z.array(KevStatEntrySchema),
});
export type KevStats = z.infer<typeof KevStatsSchema>;

export const BreachStatSchema = z.object({
  name: z.string().min(1),
  title: z.string().min(1),
  domain: z.string(),
  breach_date: isoDate.nullable(),
  added: isoDate,
  accounts: count,
  verified: z.boolean(),
  sensitive: z.boolean(),
  spam_list: z.boolean(),
  stealer_log: z.boolean(),
  malware: z.boolean(),
  fabricated: z.boolean(),
  retired: z.boolean(),
});
export type BreachStat = z.infer<typeof BreachStatSchema>;

/** Every breach Have I Been Pwned lists, reduced. */
export const HibpStatsSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  breaches: z.array(BreachStatSchema),
});
export type HibpStats = z.infer<typeof HibpStatsSchema>;

/** EPSS scores for the CVE ids the site shows: [probability, percentile]. */
export const EpssStatsSchema = z.object({
  fetched_at: isoDateTime,
  source: StatsSourceSchema,
  model_date: isoDate,
  scores: z.record(cveId, z.tuple([z.number().min(0).max(1), z.number().min(0).max(1)])),
});
export type EpssStats = z.infer<typeof EpssStatsSchema>;

/* ---------- data/stats/fixes.json: how to fix a CVE ---------- */

/** Only web URLs: every stored link is rendered as an <a href>. */
const webUrl = z.url({ protocol: /^https?$/ });

/** The longest piece of a publisher's text kept per entry; a longer one is cut at a line or word and marked `cut`. */
export const FIX_TEXT_MAX = 700;
export const FIX_PATCH_MAX = 12;
export const FIX_LINK_MAX = 8;

/** Where a fact came from: the CVE Program's record, CISA's KEV entry, NVD's reference tags, a GitHub advisory. */
export const FIX_SOURCES = ["cve", "kev", "nvd", "ghsa"] as const;
export type FixSource = (typeof FIX_SOURCES)[number];

/** What a citation resolves to: who published it, what it is called, where it is. */
export const FixCiteSchema = z.object({
  publisher: z.string().min(1).max(80),
  title: z.string().min(1).max(200),
  url: webUrl,
});
export type FixCite = z.infer<typeof FixCiteSchema>;

/** One fixed version: the product as the source names it and the first version that carries the fix. */
export const FixPatchSchema = z.object({
  label: z.string().min(1).max(120),
  version: z.string().min(1).max(80),
  /** The affected branch the fix belongs to, when the source names one ("7.2.2"); "" otherwise. */
  from: z.string().max(80),
  /** Where the source points for it; null when it states a version and no link. */
  url: webUrl.nullable(),
  source: z.enum(["cve", "ghsa"]),
});
export type FixPatch = z.infer<typeof FixPatchSchema>;

/** A link a source tags as the patch, the vendor's advisory, a mitigation or the release notes. */
export const FixLinkSchema = z.object({
  url: webUrl,
  kind: z.enum(["patch", "advisory", "mitigation", "release_notes"]),
  /** The link's own name when the source gives one ("Synology-SA-24:20 DSM"), else "". */
  title: z.string().max(200),
  source: z.enum(FIX_SOURCES),
});
export type FixLink = z.infer<typeof FixLinkSchema>;

/**
 * A publisher's own words, kept as written (whitespace tidied, cut at
 * FIX_TEXT_MAX): `vendor` when the CNA that wrote the CVE record is the
 * product's vendor, `cna` when another CNA wrote it (MITRE, GitHub, a CERT),
 * `cisa` for CISA's catalog. `summary` is gcdRadar's own model-written
 * sentence; the collector never stores one here, the site adds it from the
 * record's `action` (lib/fixes.ts).
 */
export const FixTextSchema = z.object({
  text: z.string().min(1).max(FIX_TEXT_MAX + 1),
  cut: z.boolean(),
  kind: z.enum(["vendor", "cna", "cisa", "summary"]),
  source: FixCiteSchema,
});
export type FixText = z.infer<typeof FixTextSchema>;

/** CISA's KEV entry for the CVE: the federal deadline, the required action in CISA's words and the links its notes carry. */
export const FixKevSchema = z.object({
  added: isoDate,
  due: isoDate.nullable(),
  /** CISA's "required action", as written. */
  action: z.string().max(900),
  /** CISA's one-paragraph description of the vulnerability. */
  description: z.string().max(700),
  /** Free text in the entry's notes (not a link), "" when there is none. */
  note: z.string().max(400),
  /** Labelled links in the notes: the binding directive and its guidance. */
  guidance: z.array(z.object({ label: z.string().min(1).max(80), url: webUrl })).max(4),
});
export type FixKev = z.infer<typeof FixKevSchema>;

export const FixEntrySchema = z.object({
  cve: cveId,
  /** When the CVE record was last read. */
  fetched_at: isoDateTime,
  /** When NVD and the GitHub Advisory Database were last asked; null when not asked. */
  nvd_at: isoDateTime.nullable(),
  ghsa_at: isoDateTime.nullable(),
  /** Whether the CVE Program has published a record for the id (false: reserved or not found). */
  found: z.boolean(),
  /** The CNA that assigned the CVE and wrote its record, as the record names it; "" when not found. */
  cna: z.string().max(80),
  /** Who the record's text is attributed to: the vendor's name when the CNA is the vendor, else the CNA. */
  by: z.string().max(80),
  by_vendor: z.boolean(),
  /** The record's own title, "" when it has none. */
  title: z.string().max(240),
  patches: z.array(FixPatchSchema).max(FIX_PATCH_MAX),
  /** Fixed versions the sources list beyond those kept. */
  patches_more: count,
  links: z.array(FixLinkSchema).max(FIX_LINK_MAX),
  solutions: z.array(FixTextSchema).max(2),
  workarounds: z.array(FixTextSchema).max(2),
  kev: FixKevSchema.nullable(),
});
export type FixEntry = z.infer<typeof FixEntrySchema>;

/**
 * Fix information by CVE id, for the CVEs the site can show a fix for: those
 * on live records and CISA's KEV entries of the last 90 days or with a
 * deadline ahead (collector/stats/fixes.ts). An entry leaves when its CVE
 * leaves that set.
 */
export const FixesSchema = z.object({
  fetched_at: isoDateTime,
  sources: z.array(StatsSourceSchema).min(1),
  /** The KEV catalog release the entries' deadlines and required actions were read from; "" before the first read. */
  kev_catalog_version: z.string(),
  entries: z.array(FixEntrySchema),
});
export type Fixes = z.infer<typeof FixesSchema>;

/** The seven files, each null when absent or invalid. */
export interface StatsFiles {
  nvdCounts: NvdCounts | null;
  cvesRecent: CvesRecent | null;
  daily: DailyStats | null;
  kev: KevStats | null;
  hibp: HibpStats | null;
  epss: EpssStats | null;
  fixes: Fixes | null;
}

export const STATS_FILES = {
  nvdCounts: "nvd-counts.json",
  cvesRecent: "cves-recent.json",
  daily: "daily.json",
  kev: "kev.json",
  hibp: "hibp.json",
  epss: "epss.json",
  fixes: "fixes.json",
} as const;

export const STATS_SCHEMAS = {
  nvdCounts: NvdCountsSchema,
  cvesRecent: CvesRecentSchema,
  daily: DailyStatsSchema,
  kev: KevStatsSchema,
  hibp: HibpStatsSchema,
  epss: EpssStatsSchema,
  fixes: FixesSchema,
} as const;

export function emptyStats(): StatsFiles {
  return { nvdCounts: null, cvesRecent: null, daily: null, kev: null, hibp: null, epss: null, fixes: null };
}

/* ---------- public/stats/home.json ---------- */

export const HomeStatsSchema = z.object({
  generated_at: isoDateTime,
  site: z.url(),
  /** When each source was last fetched; null when its file is absent. */
  fetched: z.object({
    nvd: isoDateTime.nullable(),
    kev: isoDateTime.nullable(),
    hibp: isoDateTime.nullable(),
    epss: isoDateTime.nullable(),
  }),
  sources: z.array(StatsSourceSchema),
  counters: z.object({
    cves_24h: count.nullable(),
    cves_7d: count.nullable(),
    critical_7d: count.nullable(),
    kev_7d: count.nullable(),
    /** The nearest federal remediation deadline on or after today, YYYY-MM-DD. */
    kev_next_due: isoDate.nullable(),
    breaches_month: count.nullable(),
    breached_accounts_month: count.nullable(),
    live: count,
  }),
  series: z.object({
    cves_by_year: z.array(z.object({ year: z.number().int(), total: count, provisional: z.boolean() })),
    ai_cves_by_quarter: z.array(z.object({ quarter: z.string(), total: count, provisional: z.boolean() })),
    kev_by_month: z.array(z.object({ month: z.string(), total: count, ransomware: count })),
    breaches_by_month: z.array(z.object({ month: z.string(), breaches: count, accounts: count })),
    kev_lag_by_year: z.array(z.object({ year: z.number().int(), n: count, median_days: z.number().min(0), within_7d: z.number().min(0).max(1) })),
  }),
  epss_top: z.array(
    z.object({
      cve: cveId,
      epss: z.number().min(0).max(1),
      percentile: z.number().min(0).max(1),
      score: z.number().nullable(),
      severity: z.string().nullable(),
      published: isoDate,
      description: z.string(),
      /** Our record about this CVE, when one exists. */
      slug: z.string().nullable(),
    }),
  ),
  lists: z.object({
    cves_day: z.object({ count: count, file: z.string() }),
    cves_week: z.object({ count: count, file: z.string() }),
    kev_week: z.object({ count: count, file: z.string() }),
    breaches_month: z.object({ month: z.string(), count: count, file: z.string() }),
  }),
});
export type HomeStats = z.infer<typeof HomeStatsSchema>;
