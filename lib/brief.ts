import { hasFixDetail, type FixPassage, type FixView } from "./fixes";
import { timelineOf, type FullIncident } from "./lifecycle";
import { LANE_META, PATCH_META, SEVERITY_META, TYPE_META } from "./taxonomy";

/**
 * The brief: one record as a self-contained Markdown note for a coding
 * agent or an analyst (the "Copy brief" button, and the `brief` field of
 * /data/incidents/<slug>.json). Plain Markdown, no HTML, every fact from the
 * record, and a closing reminder to verify against the vendor's advisory.
 *
 * With a fix view (lib/fixes.ts) it also carries "How to fix": the fixed
 * versions, the patch and advisory links, the workaround in its publisher's
 * words (or that none is listed) and CISA's deadline, each with the number
 * of its source, and the numbered sources under it. A publisher's text is
 * quoted and named; our own sentence stays under "What to do", marked as
 * ours.
 */

const LATEST = 5;
/** Fixed versions and links listed in a brief before it points at the record's page for the rest. */
const BRIEF_VERSIONS = 8;
const BRIEF_LINKS = 4;

function line(label: string, value: string | null | undefined): string {
  return value ? `- ${label}: ${value}\n` : "";
}

/** A publisher's passage on one line: its line breaks become " / ", so the Markdown list stays a list. */
function quoted(p: FixPassage): string {
  return `"${p.text.replace(/\s*\n\s*/g, " / ")}"${p.cut ? " (cut; the source has the rest)" : ""} [${p.cite}]`;
}

function whose(p: FixPassage, what: string): string {
  if (p.kind === "vendor") return `${p.by}'s ${what}`;
  if (p.kind === "cisa") return `CISA's ${what}`;
  return `${what[0]!.toUpperCase()}${what.slice(1)} in the CVE record (written by ${p.by} as the CNA)`;
}

/** "How to fix" as Markdown: three short lists and the numbered sources. */
export function fixMarkdown(fix: FixView, pageUrl: string): string {
  const out: string[] = [];
  const patch: string[] = [];
  const versions = [...fix.patch.versions, ...fix.patch.recorded];
  for (const v of versions.slice(0, BRIEF_VERSIONS)) patch.push(`- ${v.label ? `${v.label}: ` : ""}fixed in ${v.version}${v.from ? ` (for ${v.from})` : ""} [${v.cite}]`);
  const moreVersions = versions.length - Math.min(versions.length, BRIEF_VERSIONS) + fix.patch.more;
  if (moreVersions > 0) patch.push(`- ${moreVersions} more fixed ${moreVersions === 1 ? "version" : "versions"}: ${pageUrl}`);
  for (const t of fix.patch.texts) patch.push(`- ${whose(t, "solution")}: ${quoted(t)}`);
  for (const l of fix.patch.links.slice(0, BRIEF_LINKS)) patch.push(`- ${l.label}: ${l.url} [${l.cite}]`);
  if (patch.length === 0) patch.push(fix.checked ? "- No fixed version or patch link in the CVE record, CISA's entry, NVD or GitHub's advisories yet." : "- Not looked up; see the CVE record below.");
  out.push(`Patch\n${patch.join("\n")}`);

  const work: string[] = [];
  for (const t of fix.workaround.texts) work.push(`- ${whose(t, "workaround")}: ${quoted(t)}`);
  for (const l of fix.workaround.links) work.push(`- ${l.label}: ${l.url} [${l.cite}]`);
  if (fix.workaround.state === "stated_none" && fix.workaround.none) work.push(`- ${fix.workaround.none.by} lists no workaround. [${fix.workaround.none.cite}]`);
  if (fix.workaround.state === "none_listed") work.push("- No workaround published in the CVE record or by CISA yet.");
  if (fix.workaround.state === "no_record") work.push("- The CVE Program has not published a record for this id yet.");
  if (fix.workaround.state === "unchecked") work.push("- Not looked up; see the CVE record below.");
  out.push(`Workaround\n${work.join("\n")}`);

  if (fix.deadline) {
    const d = fix.deadline;
    const dl = [`- CISA lists ${d.cves.join(", ")} as exploited in the wild (since ${d.added})${d.due ? `; US federal agencies must fix it by ${d.due}` : ""}. [${d.cite}]`];
    if (d.action) dl.push(`- CISA's required action: "${d.action}" [${d.cite}]`);
    out.push(`Deadline\n${dl.join("\n")}`);
  } else out.push("Deadline\n- Not on CISA's list of known exploited vulnerabilities, so no federal deadline.");

  out.push(`References\n${fix.refs.map((r) => `- ${r.cve}: ${r.links.map((l) => `${l.label} ${l.url}`).join(" · ")}`).join("\n")}`);
  // only the sources the lines above cite (our own sentence sits under "What to do", outside this section)
  const body = out.join("\n");
  const cited = fix.citations.filter((c) => body.includes(`[${c.n}]`));
  if (cited.length) out.push(`Sources for the fix\n${cited.map((c) => `[${c.n}] ${c.publisher} · ${c.title} · ${c.url}`).join("\n")}`);
  return out.join("\n\n");
}

export function buildBrief(i: FullIncident, site: string, fix: FixView | null = null): string {
  const url = `${site}/incidents/${i.slug}`;
  const sev = SEVERITY_META[i.severity];
  const timeline = timelineOf(i);
  const latest = timeline.slice(-LATEST).reverse();
  const out: string[] = [];
  out.push(`# ${i.title}\n`);
  out.push(`${url} · ${i.id} · ${i.state === "live" ? "live" : `closed${i.closed_at ? ` ${i.closed_at}` : ""}`}\n`);
  out.push(
    `- Lane: ${LANE_META[i.lane].label}\n` +
      `- Severity: ${i.severity} (${sev.label})${i.severity_note ? `: ${i.severity_note}` : ""}\n` +
      `- Fix status: ${PATCH_META[i.patch_status].label}\n` +
      `- First reported: ${i.first_reported}${i.incident_date !== i.first_reported ? ` (happened ${i.incident_date})` : ""}\n` +
      `- AI role: ${TYPE_META[i.type].label}\n` +
      line("Products", i.products.join(", ")) +
      line("CVE ids", i.cve_ids.join(", ")) +
      line("CVSS", i.cvss === null ? null : String(i.cvss)),
  );
  out.push(`## Summary\n\n${i.summary}\n`);
  out.push(`## What to do\n\n${i.action ? `${i.action}\n\n(gcdRadar's summary, written by a language model from the sources below; not the vendor's words.)` : "No action recorded; read the sources below and the vendor's advisory."}\n`);
  if (fix && hasFixDetail(fix)) out.push(`## How to fix\n\n${fixMarkdown(fix, url)}\n`);
  if (i.affected.length || i.fixed_in.length) {
    out.push(`## Affected and fixed versions\n\n${i.affected.map((a) => `- Affected: ${a}`).join("\n")}${i.affected.length && i.fixed_in.length ? "\n" : ""}${i.fixed_in.map((f) => `- Fixed in: ${f}`).join("\n")}\n`);
  }
  if (latest.length) {
    out.push(`## Latest updates\n\n${latest.map((t) => `- ${t.date}: ${t.title}${t.source_url ? ` (${t.source_url})` : ""}`).join("\n")}\n`);
  }
  out.push(`## Sources\n\n${i.sources.map((s) => `- ${s.published_at} ${s.publisher}: ${s.title} ${s.url}`).join("\n")}\n`);
  out.push(`Verify against the vendor's advisory before changing production. Data CC BY-SA 4.0, ${site}.`);
  return out.join("\n");
}
