"use client";

import { useState } from "react";
import { QuickLook, type QuickLookRecord, type QuickLookTarget } from "@/components/incidents/QuickLook";

/**
 * The quick look's three kinds of target, each behind a button, on the
 * unlisted page /lab/quick-look: a working example for a session that wants
 * to open the drawer from its own rows, and what scripts/check-incident.mjs
 * clicks to check the kinds My stack does not use.
 */
export interface QuickLookDemoProps {
  /** A CVE with a quick-look file and no record of ours. */
  cve: string | null;
  /** A record with a page and a CVE id. */
  slug: string | null;
  /** A record handed over as data, as one newer than the last build would be: with a CVE id the site already holds fix details for. */
  record: QuickLookRecord | null;
  /** The same, for a record that names no CVE. */
  plain: QuickLookRecord | null;
}

export function QuickLookDemo({ cve, slug, record, plain }: QuickLookDemoProps) {
  const [look, setLook] = useState<QuickLookTarget | null>(null);
  const rows: { key: string; label: string; what: string; target: QuickLookTarget | null }[] = [
    { key: "cve", label: "{ cve }", what: cve ? `${cve}: a KEV entry with no record of ours` : "no such CVE in this build", target: cve ? { cve } : null },
    { key: "slug", label: "{ slug }", what: slug ? `${slug}: a record with a page` : "no such record in this build", target: slug ? { slug } : null },
    { key: "record", label: "{ record }", what: record ? `"${record.title}", passed as data, with a CVE id` : "no such record in this build", target: record ? { record } : null },
    { key: "plain", label: "{ record }", what: plain ? `"${plain.title}", passed as data, no CVE id` : "no such record in this build", target: plain ? { record: plain } : null },
    { key: "missing", label: "{ cve }", what: "CVE-1999-0001: a CVE the site keeps no fix details for", target: { cve: "CVE-1999-0001" } },
  ];
  return (
    <>
      <ul className="border-y border-line-soft">
        {rows.map((r) => (
          <li key={r.key} className="grid gap-x-4 gap-y-1 border-t border-line-soft py-3 first:border-t-0 sm:grid-cols-[7rem_minmax(0,1fr)]">
            <button type="button" data-demo={r.key} disabled={!r.target} onClick={() => setLook(r.target)} className="text-left font-mono text-[13px] text-accent hover:underline disabled:text-faint disabled:no-underline">
              {r.label}
            </button>
            <span className="min-w-0 break-words text-[14px] text-soft">{r.what}</span>
          </li>
        ))}
      </ul>
      <QuickLook target={look} onClose={() => setLook(null)} />
    </>
  );
}
