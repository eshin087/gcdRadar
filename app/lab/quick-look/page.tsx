import type { Metadata } from "next";
import { QuickLookDemo } from "@/components/incidents/QuickLookDemo";
import type { QuickLookRecord } from "@/components/incidents/QuickLook";
import { loadIncidents, loadStats } from "@/lib/data";

export const metadata: Metadata = {
  title: "Quick look: the three targets",
  robots: { index: false, follow: false },
};

/**
 * Unlisted review page, not linked anywhere: the quick-look drawer opened
 * each way it can be (a CVE id, a record's slug, a record passed as data),
 * on this build's own records. scripts/check-incident.mjs reads it.
 */
export default async function QuickLookLabPage() {
  const { incidents } = await loadIncidents();
  const stats = await loadStats();
  const withRecord = new Set(incidents.flatMap((i) => i.cve_ids));
  // a CVE the fix file holds with no record of ours; a live record with a CVE the fix file holds; a live record with none
  const cve = stats.fixes?.entries.find((e) => e.kev && !withRecord.has(e.cve))?.cve ?? null;
  const held = new Set((stats.fixes?.entries ?? []).map((e) => e.cve));
  const live = incidents.filter((i) => i.state === "live");
  const known = live.find((i) => i.cve_ids.length === 1 && held.has(i.cve_ids[0]!)) ?? null;
  const bare = live.find((i) => i.cve_ids.length === 0 && i.action) ?? null;
  const asData = (i: (typeof incidents)[number], note: string): QuickLookRecord => ({
    title: i.title,
    summary: i.summary,
    cve_ids: i.cve_ids,
    cvss: i.cvss,
    action: i.action,
    fixed_in: i.fixed_in,
    sources: i.sources,
    note,
  });
  const note = "Passed to the drawer as data, the way a record newer than the last site build would be.";
  return (
    <main className="mx-auto w-full max-w-3xl flex-1 space-y-6 px-4 py-10">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Quick look: the three targets</h1>
        <p className="text-[14px] leading-relaxed text-dim">
          The drawer from <span className="font-mono text-[13px]">components/incidents/QuickLook.tsx</span>, opened with a CVE id, with a record&rsquo;s slug, and with a record passed as
          data. An unlisted review page.
        </p>
      </header>
      <QuickLookDemo cve={cve} slug={known?.slug ?? null} record={known ? asData(known, note) : null} plain={bare ? asData(bare, note) : null} />
    </main>
  );
}
