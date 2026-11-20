import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CopyBrief } from "@/components/incidents/CopyBrief";
import { FixBlock } from "@/components/incidents/FixBlock";
import { IncidentRow } from "@/components/incidents/IncidentRow";
import { SectionHead } from "@/components/incidents/SectionHead";
import { CategoryBadge, CvssChip, PatchBadge, StateDot } from "@/components/ui/Badge";
import { buildBrief } from "@/lib/brief";
import { ADVISORY_PUBLISHERS, VULN_DB_PUBLISHERS, isDisclosedIncident } from "@/lib/counting";
import { BUILD_DAY, incidentBySlug, loadIncidents, loadStats, siteUrl } from "@/lib/data";
import { EPSS_TOOLTIP, EPSS_URL, epssFor, epssPercentileLabel, epssScoreLabel } from "@/lib/epss";
import { fixViewForRecord } from "@/lib/fix-join";
import { approxDateLabel, dateLabel, timestampLabel } from "@/lib/format";
import { lastActivity, timelineOf } from "@/lib/lifecycle";
import { rowOf } from "@/lib/live";
import { isKevMarked } from "@/lib/products";
import { SITE } from "@/lib/site";
import { relatedIncidents } from "@/lib/slim";
import { normalizeTag, tagHref } from "@/lib/tags";
import {
  ATLAS_RELEASE,
  ATLAS_TECHNIQUES,
  LANE_META,
  ORIGIN_META,
  OWASP_LLM_EDITION,
  OWASP_LLM_META,
  SEVERITY_META,
  TARGET_META,
  TYPE_META,
  atlasFor,
  atlasUrl,
  isAiType,
  owaspFor,
  owaspLabel,
} from "@/lib/taxonomy";

/** The severity's words in its colour, as rows on the rest of the site show it. */
const SEVERITY_TEXT = { 1: "text-sev-1", 2: "text-sev-2", 3: "text-sev-3", 4: "text-sev-4" } as const;

export const dynamicParams = false;

export async function generateStaticParams() {
  const { incidents } = await loadIncidents();
  return incidents.map((i) => ({ slug: i.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const { incidents } = await loadIncidents();
  const incident = incidentBySlug(incidents, slug);
  if (!incident) return {};
  return {
    title: incident.title,
    description: incident.summary,
    openGraph: { title: incident.title, description: incident.summary, type: "article", images: ["/og/default.png"] },
  };
}

const RESEARCH_PUBLISHERS: ReadonlySet<string> = new Set(["arXiv", "MITRE ATLAS", "AVID", "AI Incident Database"]);

function sourceKind(publisher: string): "advisories" | "research" | "news" {
  if (VULN_DB_PUBLISHERS.has(publisher) || ADVISORY_PUBLISHERS.has(publisher)) return "advisories";
  if (RESEARCH_PUBLISHERS.has(publisher)) return "research";
  return "news";
}

const KIND_LABEL = { advisories: "Advisories and databases", research: "Research and catalogues", news: "News and write-ups" } as const;

/**
 * One fact: its name on the left, its value in mono on the right, a hairline
 * above. The facts sit in two columns of such rows on a wide screen, so the
 * lines run across both; nothing here is framed, the fix block above is the
 * page's one framed element.
 */
function Fact({ label, title, children }: { label: string; title?: string; children: React.ReactNode }) {
  return (
    <div data-fact={label} className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 border-t border-line-soft py-2.5">
      <dt className="label pt-0.5" title={title}>
        {label}
      </dt>
      <dd className="min-w-0 font-mono text-[13.5px] leading-relaxed text-ink">{children}</dd>
    </div>
  );
}

const KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

function Row({ label, title, children }: { label: string; title?: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 border-t border-line-soft py-2.5 text-[14px] sm:grid-cols-[10rem_1fr] sm:gap-3">
      <dt className="label pt-0.5" title={title}>
        {label}
      </dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

export default async function IncidentPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const { incidents } = await loadIncidents();
  const incident = incidentBySlug(incidents, slug);
  if (!incident) notFound();
  const stats = await loadStats();
  const related = relatedIncidents(incidents, incident);
  const owasp = owaspFor(incident);
  const atlas = atlasFor(incident);
  const disclosed = isDisclosedIncident(incident);
  const timeline = timelineOf(incident);
  const lane = LANE_META[incident.lane];
  const live = incident.state === "live";
  const showPatch = incident.lane === "patch" || incident.lane === "supply_chain";
  const sources = (["advisories", "news", "research"] as const)
    .map((kind) => ({ kind, items: incident.sources.filter((s) => sourceKind(s.publisher) === kind) }))
    .filter((g) => g.items.length > 0);
  const tags = [...new Set(incident.tags.map((t) => [t, normalizeTag(t)] as const).filter(([, s]) => s).map(([t, s]) => `${t}\u0000${s}`))].map((x) => x.split("\u0000") as [string, string]);
  const cves = incident.cve_ids;
  const kev = isKevMarked(incident);
  const lastUpdate = lastActivity(incident);
  const scored = incident.cvss !== null || cves.length > 0;
  // the highest EPSS score among the record's CVEs, from the stats stage's file; null when it knows none of them
  const epss = epssFor(cves, stats.epss);
  // how to fix it: the fix file's entries for the record's CVEs, joined with CISA's catalog (lib/fixes.ts); null for a record with no CVE id
  const fix = fixViewForRecord(incident, stats, BUILD_DAY, "");
  const brief = buildBrief(incident, siteUrl(), fixViewForRecord(incident, stats, BUILD_DAY, siteUrl()));

  return (
    <article className="max-w-4xl space-y-12">
      {/* What it is: the title and one paragraph. */}
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 font-mono text-[12px] text-dim">
          <Link href={live ? `/?lane=${incident.lane}` : "/incidents"} className="hover:text-ink">
            {live ? "live" : "archive"}
          </Link>
          <span className="text-faint">/</span>
          <Link href={lane.href} className="hover:text-ink">
            {lane.label}
          </Link>
          <span className="text-faint">/</span>
          <span>{incident.id}</span>
        </div>
        {/* one plain status line: whether it is live, how bad, and its AI role when it has one (the lane is in the line above) */}
        <p data-status-line="" className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[12.5px] uppercase tracking-[0.08em] text-dim">
          <span className="inline-flex items-center gap-1.5">
            <StateDot state={incident.state} />
            {live ? "live" : `closed${incident.closed_at ? ` ${dateLabel(incident.closed_at)}` : ""}`}
          </span>
          <span className={SEVERITY_TEXT[incident.severity]} title={SEVERITY_META[incident.severity].definition}>
            severity {incident.severity} · {SEVERITY_META[incident.severity].label}
          </span>
          {isAiType(incident.type) && (
            <span className="text-accent" title={TYPE_META[incident.type].definition}>
              {TYPE_META[incident.type].label}
            </span>
          )}
        </p>
        <h1 className="text-[26px] font-semibold leading-tight tracking-tight sm:text-[32px]">{incident.title}</h1>
        {incident.products.length > 0 && (
          <p className="font-mono text-[13px] text-dim">
            <span className="text-accent">{incident.products[0]}</span>
            {incident.products.length > 1 && `, ${incident.products.slice(1).join(", ")}`}
          </p>
        )}
        <p className="text-[16px] leading-relaxed text-soft">{incident.summary}</p>
        {incident.severity_note && (
          <p className="text-[13.5px] text-dim">
            <span className="label mr-2">why this severity</span>
            {incident.severity_note}
          </p>
        )}
        {disclosed && (
          <p className="border-l-2 border-line py-0.5 pl-3.5 text-[13.5px] text-soft">
            <span className="label mr-2">disclosed CVE</span>
            No confirmed exploitation, so this record is tracked as a disclosed vulnerability and not counted as an incident. It moves into the counts if CISA
            or the vendor confirms exploitation.{" "}
            <Link href="/methodology#cves" className="link">
              Why
            </Link>
          </p>
        )}
      </header>

      {/* How to fix it: the one framed element on the page. A record with no CVE id has no CVE record or CISA entry to quote, so it shows our own sentence, labelled as ours. */}
      {fix ? (
        <FixBlock view={fix} today={BUILD_DAY} />
      ) : (
        incident.action && (
          <section data-what-to-do="">
            <SectionHead>What to do</SectionHead>
            <p className="text-[15.5px] leading-relaxed text-ink">{incident.action}</p>
            <p className="mt-1.5 text-[12.5px] text-dim">
              gcdRadar&rsquo;s summary, written by a language model from the{" "}
              <a href="#sources" className="link">
                sources below
              </a>
              ; check it against them before acting.
            </p>
          </section>
        )
      )}

      {/* The facts: every number and date the record states. */}
      <section aria-label="Facts">
        <SectionHead>Facts</SectionHead>
        <dl data-facts="" className="grid gap-x-12 border-b border-line-soft sm:grid-cols-2">
          {scored && (
            <Fact label="CVSS" title="The CVSS base score a source states; the chip's colour is the band (red 9.0 and up, orange 7.0 to 8.9, blue 4.0 to 6.9, grey below)">
              {incident.cvss !== null ? <CvssChip score={incident.cvss} /> : <span className="text-faint">not scored</span>}
            </Fact>
          )}
          {/* EPSS: the score, the percentile and the model date ("0.94 · top 1% · 2026-10-26"); nothing when the file knows none of the record's CVEs, so no row shows a number it does not have */}
          {epss && (
            <Fact label="EPSS" title={EPSS_TOOLTIP}>
              {/* each token stays whole, so a narrow cell wraps at the separators and never inside the date */}
              <span className="num">{epssScoreLabel(epss.epss)}</span> · <span className="whitespace-nowrap">{epssPercentileLabel(epss.percentile)}</span> ·{" "}
              <span className="num whitespace-nowrap">{epss.model_date}</span>
              <div className="text-[12.5px] text-dim">
                <a href={EPSS_URL} rel="noopener noreferrer" target="_blank" className="hover:text-ink">
                  EPSS scores by FIRST
                </a>
                {cves.length > 1 && <span className="num"> · {epss.cve}</span>}
              </div>
            </Fact>
          )}
          {kev && (
            <Fact label="KEV" title="Listed in CISA's Known Exploited Vulnerabilities catalog">
              <span className="text-live">listed</span>{" "}
              <a href={cves[0] ? `${KEV_CATALOG_URL}?search_api_fulltext=${cves[0]}` : KEV_CATALOG_URL} rel="noopener noreferrer" target="_blank" className="link">
                CISA KEV
              </a>
            </Fact>
          )}
          {showPatch && (
            <Fact label="fix status">
              <PatchBadge status={incident.patch_status} />
            </Fact>
          )}
          {incident.affected.length > 0 && (
            <Fact label="affected">
              {incident.affected.map((a) => (
                <div key={a}>{a}</div>
              ))}
            </Fact>
          )}
          {incident.fixed_in.length > 0 && (
            <Fact label="fixed in">
              {incident.fixed_in.map((f) => (
                <div key={f}>{f}</div>
              ))}
            </Fact>
          )}
          <Fact label="first report" title="The earliest source date">
            <span className="num">{dateLabel(incident.first_reported)}</span>
          </Fact>
          <Fact label="last update" title="The newest dated activity: a timeline entry, a source or the first report">
            <span className="num">{dateLabel(lastUpdate)}</span>
          </Fact>
          {cves.length > 0 && (
            <Fact label="CVE ids">
              {cves.map((id) => (
                <div key={id} className="flex flex-wrap gap-x-2">
                  <a href={`https://nvd.nist.gov/vuln/detail/${id}`} rel="noopener noreferrer" target="_blank" className="link">
                    {id}
                  </a>
                  <Link href={`/incidents?q=${id}&kind=all`} className="text-[12.5px] text-dim hover:text-ink">
                    other records
                  </Link>
                </div>
              ))}
            </Fact>
          )}
        </dl>
      </section>

      <section>
        <SectionHead count={timeline.length}>Timeline</SectionHead>
        <ol className="border-l border-line pl-4">
          {timeline.map((t, n) => (
            <li key={`${t.date}-${n}`} className="relative py-2 text-[14px]">
              <span aria-hidden className="absolute -left-[21px] top-[15px] size-2 rounded-full border border-line bg-ground" />
              <span className="num mr-3 text-[12.5px] text-dim">{dateLabel(t.date)}</span>
              {t.source_url ? (
                <a href={t.source_url} rel="noopener noreferrer" target="_blank" className="text-ink hover:text-accent">
                  {t.title}
                </a>
              ) : (
                <span className="text-ink">{t.title}</span>
              )}
            </li>
          ))}
        </ol>
      </section>

      <section>
        <SectionHead id="sources" count={incident.source_count}>
          Sources
        </SectionHead>
        <div className="space-y-5">
          {sources.map((g) => (
            <div key={g.kind}>
              <h3 className="mb-1 font-mono text-[12.5px] text-dim">{KIND_LABEL[g.kind]}</h3>
              <ol className="border-y border-line-soft">
                {g.items.map((s) => (
                  <li key={s.url} className="grid gap-1 border-t border-line-soft py-2.5 text-[14px] first:border-t-0 sm:grid-cols-[6.5rem_1fr]">
                    <span className="num pt-0.5 text-[12.5px] text-dim">{s.published_at}</span>
                    <div className="min-w-0">
                      <a href={s.url} rel="noopener noreferrer" target="_blank" className="break-words text-ink hover:text-accent">
                        {s.title}
                      </a>
                      <div className="text-[12.5px] text-dim">
                        {s.publisher} · <span className="num break-all">{s.url.replace(/^https?:\/\//, "").slice(0, 80)}</span>
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
        <p className="mt-2 text-[12.5px] text-dim">
          Titles and links belong to their publishers. The summary above is written by {SITE.name} in its own words; data is CC BY-SA 4.0.
        </p>
      </section>

      <section>
        <SectionHead>Copy a brief</SectionHead>
        <p className="mb-2 text-[13.5px] text-dim">This record as a short Markdown brief, with the fix links and their sources, for a ticket, a chat or a coding agent.</p>
        <CopyBrief brief={brief} />
      </section>

      {related.length > 0 && (
        <section>
          <SectionHead count={related.length}>Related</SectionHead>
          <ol className="border-b border-line-soft">
            {related.map((r) => (
              <IncidentRow key={r.id} row={rowOf(r)} variant="compact" />
            ))}
          </ol>
        </section>
      )}

      {/* How the record is filed: useful to an analyst, not to someone patching, so it stays folded. */}
      <details data-classification="" className="group">
        <summary className="flex cursor-pointer list-none items-center gap-3 [&::-webkit-details-marker]:hidden">
          <span className="font-mono text-[13px] font-medium uppercase tracking-[0.12em] text-ink">Classification</span>
          <span aria-hidden className="h-px min-w-6 flex-1 border-t border-dotted border-faint" />
          <span className="font-mono text-[12.5px] text-dim group-open:hidden">show</span>
          <span className="hidden font-mono text-[12.5px] text-dim group-open:inline">hide</span>
        </summary>
        <dl className="mt-4">
          <Row label="lane" title={lane.definition}>
            <Link href={lane.href} className="link">
              {lane.label}
            </Link>
          </Row>
          <Row label="AI role" title={TYPE_META[incident.type].definition}>
            {TYPE_META[incident.type].label}
          </Row>
          <Row label="categories">
            <span className="flex flex-wrap gap-1.5">
              {incident.categories.map((c) => (
                <CategoryBadge key={c} category={c} short={false} />
              ))}
            </span>
          </Row>
          <Row label="severity" title={SEVERITY_META[incident.severity].definition}>
            <span className="num">{incident.severity}</span> · {SEVERITY_META[incident.severity].label}
          </Row>
          {showPatch && (
            <Row label="fix status">
              <PatchBadge status={incident.patch_status} />
            </Row>
          )}
          <Row label="targets">{incident.targets.map((t) => TARGET_META[t].label).join(", ")}</Row>
          <Row label="owasp llm top 10" title={`Derived from the categories, ${OWASP_LLM_EDITION} edition`}>
            {owasp.length > 0 ? (
              <span className="flex flex-wrap gap-x-3 gap-y-1">
                {owasp.map((id) => (
                  <a key={id} href={OWASP_LLM_META[id].url} rel="noopener noreferrer" target="_blank" className="link">
                    <span className="num">{owaspLabel(id)}</span> {OWASP_LLM_META[id].name}
                  </a>
                ))}
              </span>
            ) : (
              <span className="text-dim">no entry for these categories</span>
            )}
          </Row>
          <Row label="mitre atlas" title={`Derived from the categories, release ${ATLAS_RELEASE}`}>
            {atlas.length > 0 ? (
              <span className="flex flex-wrap gap-x-3 gap-y-1">
                {atlas.map((id) => (
                  <a key={id} href={atlasUrl(id)} rel="noopener noreferrer" target="_blank" className="link">
                    <span className="num">{id}</span> {ATLAS_TECHNIQUES[id]}
                  </a>
                ))}
              </span>
            ) : (
              <span className="text-dim">no technique for these categories</span>
            )}
          </Row>
          {tags.length > 0 && (
            <Row label="tags">
              <span className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-[12.5px]">
                {tags.map(([raw, s]) => (
                  <Link key={s} href={tagHref(s)} className="link">
                    {raw.replace(/_/g, "-")}
                  </Link>
                ))}
              </span>
            </Row>
          )}
          <Row label="dates">
            <span className="num">happened {approxDateLabel(incident.incident_date, incident.incident_date_precision)}</span> ·{" "}
            <span className="num">first reported {dateLabel(incident.first_reported)}</span>
          </Row>
          <Row label="origin">
            {ORIGIN_META[incident.origin].label}
            {incident.origin === "seed_aiid" && <div className="text-[12.5px] text-dim">Derived from the AI Incident Database (CC BY-SA 4.0).</div>}
            {incident.origin === "seed_atlas" && <div className="text-[12.5px] text-dim">Derived from MITRE ATLAS (Apache 2.0, © MITRE).</div>}
            {(incident.origin === "seed_nvd" || incident.origin === "seed_ghsa") && (
              <div className="text-[12.5px] text-dim">Vulnerability record from NVD / the GitHub Advisory Database. This product uses the NVD API but is not endorsed or certified by the NVD.</div>
            )}
          </Row>
          <Row label="record">
            <span className="num text-[12.5px] text-dim">
              confidence {incident.confidence.toFixed(2)} · created {timestampLabel(incident.created_at)} · updated {timestampLabel(incident.updated_at)}
            </span>
          </Row>
        </dl>
        <p className="mt-2 text-[12.5px] text-dim">
          Lane, AI role, categories and severity come from the classifier; the OWASP and ATLAS rows are derived from the categories.{" "}
          <Link href="/methodology" className="link">
            How these are assigned
          </Link>
        </p>
      </details>
    </article>
  );
}
