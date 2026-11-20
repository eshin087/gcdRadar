"use client";

import { useEffect, useId, useState } from "react";
import { CvssChip } from "@/components/ui/Badge";
import { Drawer } from "@/components/ui/Drawer";
import { dateLabel } from "@/lib/format";
import type { FreshRecord } from "@/lib/live/shape";
import { LANE_META, PATCH_META } from "@/lib/taxonomy";

/**
 * Keeps a live row from sending anyone to a page that does not exist yet.
 * A record that a sweep published after the site's last rebuild has no
 * /incidents/<slug> page until the next one (at most half a day). This
 * component takes those records (`records`, by slug, from the live file)
 * and, for every link to one of them anywhere on the page:
 *
 *  - points the link at the record's primary source in a new tab, so a
 *    middle click, "open in new tab" and the address shown on hover never
 *    lead to a 404;
 *  - on a plain click, opens the record in a drawer instead: its summary,
 *    what to do, its CVE ids and its sources, all from the live file.
 *
 * It works on the document, not on particular components: whatever draws a
 * link to /incidents/<slug>, now or after a redesign, is covered, and a row
 * rendered later (a drawer's list, a filter) is picked up as it appears.
 * With no such record it does nothing.
 */

const PREFIX = "/incidents/";

/** The slug an anchor's own address names, or null for any other link. */
function slugOf(a: HTMLAnchorElement): string | null {
  const href = a.getAttribute("href") ?? "";
  if (!href.startsWith(PREFIX)) return null;
  const slug = href.slice(PREFIX.length).split(/[?#/]/)[0] ?? "";
  return slug || null;
}

function mark(a: HTMLAnchorElement, slug: string, r: FreshRecord) {
  const source = r.sources[0]?.url;
  a.dataset.freshSlug = slug;
  if (!source) return;
  a.setAttribute("href", source);
  a.setAttribute("target", "_blank");
  a.setAttribute("rel", "noopener noreferrer");
}

function unmark(a: HTMLAnchorElement) {
  const slug = a.dataset.freshSlug;
  if (!slug) return;
  delete a.dataset.freshSlug;
  // only when the address is still the one this component wrote: the page's own render may have set a new one
  if (!(a.getAttribute("href") ?? "").startsWith("/")) {
    a.setAttribute("href", `${PREFIX}${slug}`);
    a.removeAttribute("target");
    a.removeAttribute("rel");
  }
}

function sweepLinks(records: ReadonlyMap<string, FreshRecord>) {
  for (const a of document.querySelectorAll<HTMLAnchorElement>(`a[href^="${PREFIX}"]`)) {
    // an anchor the page re-rendered with another record's address: forget the old mark first
    if (a.dataset.freshSlug) {
      delete a.dataset.freshSlug;
      a.removeAttribute("target");
      a.removeAttribute("rel");
    }
    const slug = slugOf(a);
    const r = slug ? records.get(slug) : undefined;
    if (slug && r) mark(a, slug, r);
  }
}

const SEVERITY_WORDS: Record<number, string> = { 1: "research", 2: "disclosed", 3: "exploited", 4: "confirmed impact" };

function FreshDrawer({ record, onClose }: { record: FreshRecord | null; onClose: () => void }) {
  const titleId = useId();
  if (!record) return null;
  const source = record.sources[0];
  const patch = PATCH_META[record.patch_status];
  return (
    <Drawer
      open
      onClose={onClose}
      titleId={titleId}
      kicker={`${record.id} · new, no page yet`}
      footerLink={source ? { href: source.url, label: `${source.publisher} →`, external: true } : null}
      closeLabel="Close the record"
    >
      <div data-fresh-record={record.slug} className="space-y-4">
        <header className="space-y-2">
          <h2 id={titleId} className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
            {record.title}
          </h2>
          <p className="num flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-dim">
            <span>{LANE_META[record.lane].label}</span>
            <span aria-hidden>·</span>
            <span className={record.severity >= 4 ? "text-live" : undefined}>{SEVERITY_WORDS[record.severity]}</span>
            <span aria-hidden>·</span>
            <span>{patch.label}</span>
            {record.cvss !== null && <CvssChip score={record.cvss} />}
            <span aria-hidden>·</span>
            <span>reported {dateLabel(record.first_reported)}</span>
          </p>
        </header>
        <p className="text-[14.5px] leading-relaxed text-soft">{record.summary}</p>
        {record.action && (
          <section className="space-y-1">
            <h3 className="label">What to do</h3>
            <p className="text-[14.5px] leading-relaxed text-ink">{record.action}</p>
          </section>
        )}
        {record.cve_ids.length > 0 && (
          <section className="space-y-1">
            <h3 className="label">CVE</h3>
            <p className="num flex flex-wrap gap-x-3 gap-y-1 text-[13px]">
              {record.cve_ids.map((c) => (
                <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer" className="link">
                  {c}
                </a>
              ))}
            </p>
          </section>
        )}
        <section className="space-y-1">
          <h3 className="label">Sources</h3>
          <ol className="border-y border-line-soft">
            {record.sources.map((s) => (
              <li key={s.url} className="border-t border-line-soft py-2 first:border-t-0">
                <a href={s.url} target="_blank" rel="noopener noreferrer" className="text-[13.5px] text-ink hover:text-accent">
                  {s.title}
                </a>
                <p className="num mt-0.5 text-[12px] text-dim">{s.publisher}</p>
              </li>
            ))}
          </ol>
        </section>
        <p className="text-[13px] leading-relaxed text-dim">This record is newer than the site&rsquo;s last rebuild. Its own page, with the full timeline, arrives with the next one (the site is rebuilt twice a day).</p>
      </div>
    </Drawer>
  );
}

export function FreshLinks({ records }: { records: ReadonlyMap<string, FreshRecord> }) {
  const [open, setOpen] = useState<FreshRecord | null>(null);

  useEffect(() => {
    if (records.size === 0) return;
    sweepLinks(records);
    // rows that arrive later (a drawer's list, a filter, a redraw) and anchors the page gives a new address
    const observer = new MutationObserver((changes) => {
      // this component's own writes change href too; they are not addresses under /incidents/, so sweepLinks leaves them alone
      if (changes.some((c) => c.type === "childList" || (c.target as HTMLElement).getAttribute?.("href")?.startsWith(PREFIX))) sweepLinks(records);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["href"] });

    const onClick = (e: MouseEvent) => {
      // a plain click opens the drawer; a modified one follows the link, which now leads to the source
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as Element | null)?.closest?.("a");
      if (!a) return;
      const slug = a.dataset.freshSlug ?? slugOf(a);
      const r = slug ? records.get(slug) : undefined;
      if (!r) return;
      e.preventDefault();
      e.stopPropagation();
      setOpen(r);
    };
    // capture, on the document: ahead of the router's own click handling
    document.addEventListener("click", onClick, true);
    return () => {
      observer.disconnect();
      document.removeEventListener("click", onClick, true);
      for (const a of document.querySelectorAll<HTMLAnchorElement>("a[data-fresh-slug]")) unmark(a);
    };
  }, [records]);

  return <FreshDrawer record={open} onClose={() => setOpen(null)} />;
}
