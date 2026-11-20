import { dateLabel } from "@/lib/format";
import { CRITICAL_DAYS, CRITICAL_MIN, type StackCandidate, type StackCrit } from "@/lib/panel/picks";

/**
 * A product's new critical CVEs, under its exploited items in the drawer and
 * apart from them: the quiet second signal (lib/panel/stack.ts). Published in
 * the last 14 days with a CVSS score of 9.0 or more, not known to be
 * exploited, so nothing here is coloured: the score is a plain number, not
 * the red chip an exploited row carries. A `ul`, not the `ol` the drawer's
 * count line answers for (scripts/check-home.mjs counts `ol > li`).
 */
export function StackCriticals({ cand, crits }: { cand: StackCandidate; crits: StackCrit[] | null }) {
  if (!cand.crit || !crits) return null;
  return (
    <section data-stack-crits={cand.crit} className="space-y-2 pt-2">
      <h3 className="font-mono text-[12px] uppercase tracking-[0.1em] text-dim">New critical CVEs · last {CRITICAL_DAYS} days</h3>
      <p className="text-[13px] leading-relaxed text-dim">
        {cand.crit} published with a CVSS score of {CRITICAL_MIN.toFixed(1)} or more that name {cand.label}. None is known to be exploited; they are here so a patch can be planned.
        {cand.crit > crits.length ? ` The ${crits.length} highest are listed.` : ""}
      </p>
      <ul className="border-y border-line-soft">
        {crits.map((c) => (
          <li key={c.id} data-stack-crit={c.id} className="grid grid-cols-[3rem_minmax(0,1fr)_auto] items-baseline gap-3 border-t border-line-soft py-2 first:border-t-0">
            <span title={`CVSS base score ${c.score.toFixed(1)}`} className="num text-[13.5px] text-soft">
              {c.score.toFixed(1)}
            </span>
            <a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noopener noreferrer" className="num whitespace-nowrap text-[13.5px] text-ink hover:text-accent">
              {c.id}
            </a>
            <span className="num whitespace-nowrap text-[12px] text-dim">
              <span className="hidden sm:inline">published </span>
              {dateLabel(c.published)}
            </span>
          </li>
        ))}
      </ul>
      <p className="text-[12px] leading-relaxed text-faint">Matched by name in NVD’s description of each CVE, so the list can miss some.</p>
    </section>
  );
}
