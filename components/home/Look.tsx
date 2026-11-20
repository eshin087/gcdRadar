"use client";

import Link from "next/link";
import { createContext, useContext, useState, type MouseEvent, type ReactNode } from "react";
import { QuickLook, type QuickLookTarget } from "@/components/incidents/QuickLook";

/**
 * The home page's one quick look (components/incidents/QuickLook.tsx): a row
 * anywhere on the page opens "what is this and how do I fix it" in the
 * drawer instead of leaving the page. The provider holds the drawer; `Peek`
 * is a row's link. It is a real link (the record's page, or the CVE at NVD),
 * so a middle click, "open in new tab" and a reader without scripts all
 * still arrive somewhere; a plain click opens the drawer. A record newer
 * than the site's last rebuild is handled before this by
 * components/live/FreshLinks.tsx, which opens it from the live file.
 *
 * My stack keeps its own quick look, because it opens from inside the
 * product's list and Esc has to lead back to that list.
 */

const LookCtx = createContext<(t: QuickLookTarget) => void>(() => undefined);

export function LookProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<QuickLookTarget | null>(null);
  return (
    <LookCtx.Provider value={setTarget}>
      {children}
      <QuickLook target={target} onClose={() => setTarget(null)} />
    </LookCtx.Provider>
  );
}

export function useLook(): (t: QuickLookTarget) => void {
  return useContext(LookCtx);
}

const nvdHref = (cve: string) => `https://nvd.nist.gov/vuln/detail/${cve}`;

/** The slug of one of our record pages in an address, or null. */
export function slugOfHref(href: string): string | null {
  return href.startsWith("/incidents/") ? href.slice("/incidents/".length).split(/[?#/]/)[0] || null : null;
}

/**
 * A link that opens the quick look on a plain click. Give it `slug` (one of
 * our records) or `cve` (a CVE with no record of ours, such as a KEV entry).
 */
export function Peek({ slug, cve, title, className, children, ...rest }: { slug?: string | null; cve?: string | null; title?: string; className?: string; children: ReactNode } & Record<`data-${string}`, string | number | undefined>) {
  const look = useLook();
  const target: QuickLookTarget | null = slug ? { slug } : cve ? { cve } : null;
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (!target || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    look(target);
  };
  if (!target) return <span className={className}>{children}</span>;
  return slug ? (
    <Link href={`/incidents/${slug}`} prefetch={false} onClick={onClick} title={title} data-look={slug} className={className} {...rest}>
      {children}
    </Link>
  ) : (
    <a href={nvdHref(cve!)} target="_blank" rel="noopener noreferrer" onClick={onClick} title={title} data-look={cve!} className={className} {...rest}>
      {children}
    </a>
  );
}
