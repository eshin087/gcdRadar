"use client";

import Link from "next/link";
import { useId } from "react";
import { useJson } from "@/components/home/useJson";
import { FixBlock } from "@/components/incidents/FixBlock";
import { CvssChip } from "@/components/ui/Badge";
import { Drawer } from "@/components/ui/Drawer";
import { cveOrgUrl, fixFileUrl, nvdUrl, type FixView, type QuickLookFile } from "@/lib/fixes";

/**
 * The quick look: "how do I fix this" for one CVE id or one record, in the
 * shared drawer, without leaving the page. It shows the same fix block as
 * the record's page (components/incidents/FixBlock.tsx) under a title and
 * one paragraph on what the thing is, and points on to the full record when
 * the site has one, else to the CVE's own record.
 *
 * Usage, from any client component:
 *
 *   const [look, setLook] = useState<QuickLookTarget | null>(null);
 *   <button onClick={() => setLook({ cve: "CVE-2026-0001" })}>…</button>
 *   <QuickLook target={look} onClose={() => setLook(null)} />
 *
 * `{ cve }` reads /data/fix/<CVE>.json, a file prebuild writes for every CVE
 * the fix file holds, every KEV entry of the last 90 days or with a deadline
 * ahead, and every CVE on a live record (lib/fix-join.ts). `{ slug }` reads
 * the record's own /data/incidents/<slug>.json. Either is fetched when the
 * drawer opens and kept for the life of the page, so the host page's HTML
 * carries none of it. A CVE with no file still gets its two reference links.
 *
 * Only one drawer is open at a time on this site: a host that opens the
 * quick look from inside another drawer hides that drawer while this one is
 * open (My stack does), so Esc and the close button mean one thing.
 */

export type QuickLookTarget = { cve: string } | { slug: string };

/** The record file's fields the drawer reads (scripts/prebuild.ts writes the whole record, its brief and its fix view). */
interface RecordFile {
  slug: string;
  title: string;
  summary: string;
  cve_ids: string[];
  cvss: number | null;
  fix: FixView | null;
}

interface Shown {
  kicker: string;
  title: string;
  product: string;
  /** What it is: our summary for a record, the publisher's description for a bare CVE. */
  about: { text: string; by: string | null; url: string | null } | null;
  cvss: number | null;
  fix: FixView | null;
  record: { slug: string } | null;
  cve: string | null;
}

function fromCve(f: QuickLookFile): Shown {
  return {
    kicker: `Quick look · ${f.cve}`,
    title: f.record?.title ?? f.title,
    product: f.record ? "" : f.product,
    about: f.record ? { text: f.record.summary, by: null, url: null } : f.description,
    cvss: f.cvss,
    fix: f.fix,
    record: f.record ? { slug: f.record.slug } : null,
    cve: f.cve,
  };
}

function fromRecord(r: RecordFile): Shown {
  return { kicker: `Quick look · ${r.cve_ids[0] ?? "record"}`, title: r.title, product: "", about: { text: r.summary, by: null, url: null }, cvss: r.cvss, fix: r.fix, record: { slug: r.slug }, cve: r.cve_ids[0] ?? null };
}

const EXT = { target: "_blank", rel: "noopener noreferrer" } as const;

export function QuickLook({ target, onClose }: { target: QuickLookTarget | null; onClose: () => void }) {
  const titleId = useId();
  const cve = target && "cve" in target ? target.cve : null;
  const slug = target && "slug" in target ? target.slug : null;
  const cveFile = useJson<QuickLookFile>(cve ? fixFileUrl(cve) : null);
  const recordFile = useJson<RecordFile>(slug ? `/data/incidents/${slug}.json` : null);
  if (!target) return null;
  const state = cve ? cveFile : recordFile;
  const shown: Shown | null = cve ? (cveFile.data ? fromCve(cveFile.data) : null) : recordFile.data ? fromRecord(recordFile.data) : null;
  const today = new Date().toISOString().slice(0, 10);
  const footer = shown?.record ? { href: `/incidents/${shown.record.slug}`, label: "full record →" } : cve ? { href: cveOrgUrl(cve), label: "CVE record ↗", external: true } : null;
  return (
    <Drawer open onClose={onClose} titleId={titleId} kicker={shown?.kicker ?? `Quick look · ${cve ?? "record"}`} footerLink={footer} closeLabel="Close the quick look">
      <div data-quicklook={cve ?? slug ?? ""} data-quicklook-state={shown ? "ready" : state.error ? "missing" : "loading"} className="space-y-5">
        {shown ? (
          <>
            <header className="space-y-2">
              <h2 id={titleId} className="text-[20px] font-semibold leading-tight tracking-tight text-ink">
                {shown.title}
              </h2>
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[13px] text-dim">
                {shown.cvss !== null && <CvssChip score={shown.cvss} />}
                {shown.product && <span className="text-accent">{shown.product}</span>}
                {shown.cve && <span className="num">{shown.cve}</span>}
              </p>
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
            ) : (
              <p className="text-[14px] text-dim">This record names no CVE id, so there is no CVE record or CISA entry to quote. Its page has what the reports say.</p>
            )}
            {shown.record && (
              <p>
                <Link href={`/incidents/${shown.record.slug}`} data-quicklook-record="" className="link text-[14px] text-ink">
                  Open the full record →
                </Link>
              </p>
            )}
          </>
        ) : state.error ? (
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
              {cve ?? "Record"}
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
