"use client";

import Link from "next/link";
import { useId } from "react";
import { useJson } from "@/components/home/useJson";
import { FixBlock } from "@/components/incidents/FixBlock";
import { CvssChip } from "@/components/ui/Badge";
import { Drawer } from "@/components/ui/Drawer";
import { buildFixView, cveOrgUrl, fixFileUrl, nvdUrl, quickLookView, type FixView, type QuickLookFile } from "@/lib/fixes";

/**
 * The quick look: "how do I fix this" for one CVE or one record, in the
 * shared drawer, without leaving the page. It shows the same fix block as
 * the record's page (components/incidents/FixBlock.tsx) under a title and
 * one paragraph on what the thing is, and points on to the full record when
 * the site has one, else to the CVE's own record.
 *
 *   const [look, setLook] = useState<QuickLookTarget | null>(null);
 *   <button onClick={() => setLook({ cve: "CVE-2026-0001" })}>…</button>
 *   <QuickLook target={look} onClose={() => setLook(null)} />
 *
 * Props: `target` (null keeps the drawer closed) and `onClose`. A target is
 * one of three things:
 *
 *   { cve }     a CVE id. Reads /data/fix/<CVE>.json, which prebuild writes
 *               for every CVE the fix file holds, every KEV entry of the last
 *               90 days or with a deadline ahead, and every CVE on a live
 *               record (lib/fix-join.ts). A CVE with no file still gets its
 *               cve.org and NVD links.
 *   { slug }    one of our records that has a page. Reads the record's own
 *               /data/incidents/<slug>.json.
 *   { record }  a record handed over as data (QuickLookRecord below), for one
 *               that has no page or file yet, such as a record newer than the
 *               last site build. Only `title` and `summary` are required.
 *               With CVE ids the drawer also reads the first CVE's file and
 *               joins whatever fix details the site already holds; with
 *               `fix` the caller's own view is shown as it is.
 *
 * Everything fetched is fetched when the drawer opens and kept for the life
 * of the page, so the host page's HTML carries none of it.
 *
 * Only one drawer is open at a time on this site: a host that opens the
 * quick look from inside another drawer hides that drawer while this one is
 * open (My stack does), so Esc and the close button mean one thing.
 */

/** A record handed to the drawer as data. Field names follow the record's own (lib/schema.ts). */
export interface QuickLookRecord {
  title: string;
  /** One paragraph on what happened, in our own words. */
  summary: string;
  cve_ids?: readonly string[];
  cvss?: number | null;
  /** The record's "what to do" sentence. It is written by a language model, and the drawer says so. */
  action?: string;
  fixed_in?: readonly string[];
  sources?: readonly { url: string; publisher: string; title: string; published_at?: string }[];
  /** A ready fix view (lib/fixes.ts buildFixView), when the caller has one; otherwise the drawer builds it. */
  fix?: FixView | null;
  /** The record's page, when it already has one. */
  slug?: string;
  /** One plain line under the title, for example why there is no full page yet. */
  note?: string;
}

export type QuickLookTarget = { cve: string } | { slug: string } | { record: QuickLookRecord };

/** The record file's fields the drawer reads (scripts/prebuild.ts writes the whole record, its brief and its fix view). */
interface RecordFile {
  slug: string;
  title: string;
  summary: string;
  cve_ids: string[];
  cvss: number | null;
  action: string;
  fix: FixView | null;
}

interface Shown {
  kicker: string;
  title: string;
  product: string;
  note: string;
  /** What it is: our summary for a record, the publisher's description for a bare CVE. */
  about: { text: string; by: string | null; url: string | null } | null;
  cvss: number | null;
  fix: FixView | null;
  /** Our own sentence for a record with no CVE id (no fix block to carry it). */
  action: string;
  sources: NonNullable<QuickLookRecord["sources"]>;
  slug: string | null;
  cve: string | null;
}

const EXT = { target: "_blank", rel: "noopener noreferrer" } as const;
const SOURCES_SHOWN = 8;

function fromCve(f: QuickLookFile, today: string): Shown {
  return {
    kicker: `Quick look · ${f.cve}`,
    title: f.record?.title ?? f.title,
    product: f.record ? "" : f.product,
    note: "",
    about: f.record ? { text: f.record.summary, by: null, url: null } : f.description,
    cvss: f.cvss,
    fix: quickLookView(f, today),
    action: "",
    sources: [],
    slug: f.record?.slug ?? null,
    cve: f.cve,
  };
}

function fromRecordFile(r: RecordFile): Shown {
  return { kicker: `Quick look · ${r.cve_ids[0] ?? "record"}`, title: r.title, product: "", note: "", about: { text: r.summary, by: null, url: null }, cvss: r.cvss, fix: r.fix, action: r.fix ? "" : r.action, sources: [], slug: r.slug, cve: r.cve_ids[0] ?? null };
}

/** A record passed in as data: the caller's view, else one built from the first CVE's file (when the site has it) and the record's own fields. */
function fromRecordData(r: QuickLookRecord, file: QuickLookFile | null, today: string, sourcesId: string): Shown {
  const cves = [...(r.cve_ids ?? [])];
  const sources = r.sources ?? [];
  const fix =
    r.fix ??
    (cves.length
      ? buildFixView({ cves, entries: file?.entries ?? [], kev: file?.kev ?? [], record: { action: r.action ?? "", fixed_in: r.fixed_in ?? [], source_count: Math.max(1, sources.length), sourcesUrl: `#${sourcesId}` }, today })
      : null);
  return { kicker: `Quick look · ${cves[0] ?? "record"}`, title: r.title, product: "", note: r.note ?? "", about: { text: r.summary, by: null, url: null }, cvss: r.cvss ?? file?.cvss ?? null, fix, action: fix ? "" : (r.action ?? ""), sources, slug: r.slug ?? null, cve: cves[0] ?? null };
}

export function QuickLook({ target, onClose }: { target: QuickLookTarget | null; onClose: () => void }) {
  const titleId = useId();
  const sourcesId = useId();
  const cve = target && "cve" in target ? target.cve : null;
  const slug = target && "slug" in target ? target.slug : null;
  const data = target && "record" in target ? target.record : null;
  // a record passed as data reads the first CVE's file too, unless the caller brought its own view
  const fileCve = cve ?? (data && !data.fix ? (data.cve_ids?.[0] ?? null) : null);
  const cveFile = useJson<QuickLookFile>(fileCve ? fixFileUrl(fileCve) : null);
  const recordFile = useJson<RecordFile>(slug ? `/data/incidents/${slug}.json` : null);
  if (!target) return null;
  const today = new Date().toISOString().slice(0, 10);
  let shown: Shown | null = null;
  let missing = false;
  if (data) shown = cveFile.loading ? null : fromRecordData(data, cveFile.data, today, sourcesId);
  else if (cve) {
    shown = cveFile.data ? fromCve(cveFile.data, today) : null;
    missing = Boolean(cveFile.error);
  } else {
    shown = recordFile.data ? fromRecordFile(recordFile.data) : null;
    missing = Boolean(recordFile.error);
  }
  const name = cve ?? slug ?? data?.cve_ids?.[0] ?? "record";
  const footer = shown?.slug ? { href: `/incidents/${shown.slug}`, label: "full record →" } : (shown?.cve ?? cve) ? { href: cveOrgUrl((shown?.cve ?? cve)!), label: "CVE record ↗", external: true } : null;
  return (
    <Drawer open onClose={onClose} titleId={titleId} kicker={shown?.kicker ?? `Quick look · ${name}`} footerLink={footer} closeLabel="Close the quick look">
      <div data-quicklook={name} data-quicklook-kind={data ? "record" : cve ? "cve" : "slug"} data-quicklook-state={shown ? "ready" : missing ? "missing" : "loading"} className="space-y-5">
        {shown ? (
          <>
            <header className="space-y-2">
              <h2 id={titleId} className="text-[20px] font-semibold leading-tight tracking-tight text-ink">
                {shown.title}
              </h2>
              {(shown.cvss !== null || shown.product || shown.cve) && (
                <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[13px] text-dim">
                  {shown.cvss !== null && <CvssChip score={shown.cvss} />}
                  {shown.product && <span className="text-accent">{shown.product}</span>}
                  {shown.cve && <span className="num">{shown.cve}</span>}
                </p>
              )}
              {shown.note && (
                <p data-quicklook-note="" className="text-[13px] text-dim">
                  {shown.note}
                </p>
              )}
              {shown.about && (
                <p className="text-[14.5px] leading-relaxed text-soft">
                  {shown.about.text}
                  {shown.about.by && shown.about.url && (
                    <span className="text-[12.5px] text-dim">
                      {" "}
                      (
                      <a href={shown.about.url} {...EXT} className="link">
                        {shown.about.by}&rsquo;s description ↗
                      </a>
                      )
                    </span>
                  )}
                </p>
              )}
            </header>
            {shown.fix ? (
              <FixBlock view={shown.fix} today={today} />
            ) : shown.action ? (
              <section data-what-to-do="">
                <h3 className="font-mono text-[12.5px] font-medium uppercase tracking-[0.12em] text-accent">What to do</h3>
                <p className="mt-1.5 text-[14.5px] leading-relaxed text-ink">{shown.action}</p>
                <p className="mt-1 text-[12.5px] text-dim">gcdRadar&rsquo;s summary, written by a language model from the record&rsquo;s sources; check it against them before acting.</p>
              </section>
            ) : (
              <p className="text-[14px] text-dim">This record names no CVE id, so there is no CVE record or CISA entry to quote. Its sources have what is known.</p>
            )}
            {shown.sources.length > 0 && (
              <section>
                <h3 id={sourcesId} className="font-mono text-[12.5px] font-medium uppercase tracking-[0.12em] text-ink">
                  Sources · <span className="num font-normal text-dim">{shown.sources.length}</span>
                </h3>
                <ul data-quicklook-sources="" className="mt-2 border-y border-line-soft">
                  {shown.sources.slice(0, SOURCES_SHOWN).map((s) => (
                    <li key={s.url} className="border-t border-line-soft py-2 text-[13.5px] first:border-t-0">
                      <a href={s.url} {...EXT} className="break-words text-ink hover:text-accent">
                        {s.title}
                      </a>
                      <div className="text-[12.5px] text-dim">
                        {s.publisher}
                        {s.published_at && <span className="num"> · {s.published_at}</span>}
                      </div>
                    </li>
                  ))}
                </ul>
                {shown.sources.length > SOURCES_SHOWN && <p className="mt-1 text-[12.5px] text-dim">and {shown.sources.length - SOURCES_SHOWN} more</p>}
              </section>
            )}
            {shown.slug && (
              <p>
                <Link href={`/incidents/${shown.slug}`} data-quicklook-record="" className="link text-[14px] text-ink">
                  Open the full record →
                </Link>
              </p>
            )}
          </>
        ) : missing ? (
          <div className="space-y-3">
            <h2 id={titleId} className="text-[20px] font-semibold leading-tight tracking-tight text-ink">
              {cve ?? "Record"}
            </h2>
            <p data-error className="text-[14px] text-soft">
              No fix details are kept for this one: they are read for live records and for CISA&rsquo;s listings of the last 90 days.
            </p>
            {cve && (
              <p className="flex flex-wrap gap-x-4 gap-y-1 text-[14px]">
                <a href={cveOrgUrl(cve)} {...EXT} className="link">
                  cve.org ↗
                </a>
                <a href={nvdUrl(cve)} {...EXT} className="link">
                  NVD ↗
                </a>
              </p>
            )}
          </div>
        ) : (
          <>
            <h2 id={titleId} className="text-[20px] font-semibold leading-tight tracking-tight text-ink">
              {data?.title ?? cve ?? "Record"}
            </h2>
            <p data-loading className="text-[14px] text-dim">
              Loading…
            </p>
          </>
        )}
      </div>
    </Drawer>
  );
}
