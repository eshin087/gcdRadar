"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { Frame } from "@/components/home/Frame";
import { Peek, slugOfHref, useLook } from "@/components/home/Look";
import { ScoreOrDash } from "@/components/home/panel/marks";
import { Meter, Score } from "@/components/home/Score";
import { useNow, useStackLabels } from "@/components/home/useNow";
import { Drawer } from "@/components/ui/Drawer";
import { dateLabel } from "@/lib/format";
import { NEXT_DUE_ROWS } from "@/lib/panel/caps";
import { countdownParts, shortDate, timeLeft } from "@/lib/panel/dates";
import { dueEnd, windowUsed } from "@/lib/panel/deadlines";
import type { DueRow } from "@/lib/panel/ledger";

/**
 * Next due (lib/panel/ledger.ts): CISA's patch deadlines for exploited
 * vulnerabilities, nearest first. The nearest leads with its countdown (hours
 * and minutes, days and hours from two days out) and a link that says
 * "patch" where a patch is published and "what to do" where CISA's
 * instruction is all there is; NEXT_DUE_ROWS more follow, one line each: the
 * time left (once per due day), how much of CISA's window is used as ten
 * cells, the product, its CVSS score. A square marks a row in the visitor's
 * stack. Everything opens the quick look; "all N" opens every deadline ahead.
 *
 * The page judges a deadline by the visitor's clock: one that has passed
 * since the build drops off and the next takes its place.
 */

const KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const DUE_NOTE = "CISA's deadline for US federal agencies to patch; a good yardstick for everyone";

/** The cells of the window meter: at least one once CISA has listed it, ten at the deadline. */
const windowCells = (r: DueRow, now: number) => Math.max(1, Math.round(windowUsed(r.added, r.due, now) * 10));
const windowNote = (r: DueRow, now: number) => `${Math.round(windowUsed(r.added, r.due, now) * 100)}% of CISA's window used: listed ${shortDate(r.added)}, due ${shortDate(r.due)}`;
/** A deadline within a day is red, within three days amber, later grey. */
const urgency = (r: DueRow, now: number): 4 | 3 | 2 => (dueEnd(r.due) - now <= 86_400_000 ? 4 : dueEnd(r.due) - now <= 3 * 86_400_000 ? 3 : 2);

function StackSquare({ labels, ready }: { labels: readonly string[]; ready: boolean }) {
  return (
    <span data-stack={ready ? "ready" : "wait"} className="contents">
      {labels.length > 0 && <span data-stack-mark={labels.join(",")} title={`In your stack: ${labels.join(", ")}`} className="mr-2 inline-block size-[7px] bg-ink align-[1px]" />}
    </span>
  );
}

function target(r: DueRow): { slug?: string; cve?: string } {
  const slug = slugOfHref(r.href);
  return slug ? { slug } : { cve: r.cves[0] };
}

export function NextDue({ due, later, built }: { due: DueRow[]; later: DueRow[]; built: string }) {
  const now = useNow(Date.parse(built));
  const look = useLook();
  const { labelsOf, ready } = useStackLabels();
  const [open, setOpen] = useState(false);
  const titleId = useId();

  const ahead = [...due, ...later].filter((r) => dueEnd(r.due) > now);
  const lead = ahead[0] ?? null;
  const rows = ahead.slice(1, 1 + NEXT_DUE_ROWS);
  const more = ahead.length - 1 - rows.length;
  const anyStack = [lead, ...rows].some((r) => r && labelsOf(r, r.href).length > 0);
  const c = lead ? countdownParts(dueEnd(lead.due) - now) : null;

  return (
    <Frame
      id="due"
      label="The next CISA patch deadlines"
      data-instrument="due"
      data-count={ahead.length}
      title={<h2 title={DUE_NOTE}>Next due</h2>}
      control={
        ahead.length > 0 ? (
          <button type="button" data-due-all onClick={() => setOpen(true)}>
            all {ahead.length} →
          </button>
        ) : undefined
      }
    >
      {!lead || !c ? (
        <p data-note className="text-[14.5px] text-soft">
          No CISA deadline is ahead.
        </p>
      ) : (
        <>
          <div data-row="due" data-lead data-name={lead.name} data-due={lead.due} className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-4 gap-y-2 border-b border-line-soft pb-3">
            <p className="flex items-center gap-3">
              <span data-big-countdown={lead.due} title={`Due ${dateLabel(lead.due)}: ${DUE_NOTE}`} className="font-mono text-[26px] font-medium leading-none whitespace-nowrap text-ink" suppressHydrationWarning>
                {c.a}
                <span className="mx-[3px] text-[15px] text-dim">{c.au}</span>
                {c.b}
                <span className="ml-[3px] text-[15px] text-dim">{c.bu}</span>
              </span>
              <span suppressHydrationWarning className="contents">
                <Meter cells={windowCells(lead, now)} tone={urgency(lead, now)} title={windowNote(lead, now)} />
              </span>
            </p>
            <button type="button" data-due-fix={lead.fix ? "patch" : "advice"} onClick={() => look(target(lead) as { slug: string } | { cve: string })} className="font-mono text-[12.5px] uppercase tracking-[0.08em] text-accent hover:underline">
              {lead.fix ? "patch" : "what to do"} <span aria-hidden>→</span>
            </button>
            <p className="min-w-0 truncate text-[15px] font-medium">
              <StackSquare labels={labelsOf(lead, lead.href)} ready={ready} />
              <Peek {...target(lead)} title={`${lead.name}: ${lead.cves.join(", ")}${lead.ransomware ? " · known ransomware use" : ""}`} className="text-ink hover:text-accent">
                {lead.name}
              </Peek>
            </p>
            <span className="text-right">{lead.cvss !== null ? <Score score={lead.cvss} /> : <span className="font-mono text-[12.5px] text-dim">no score</span>}</span>
          </div>
          <ol data-due-rows>
            {rows.map((r, i) => {
              const sameDay = (i === 0 ? lead.due : rows[i - 1]!.due) === r.due;
              const left = dueEnd(r.due) - now;
              return (
                <li key={r.cves[0]} data-row="due" data-name={r.name} data-due={r.due} className="grid h-[34px] grid-cols-[3.4rem_58px_minmax(0,1fr)_2rem] items-center gap-x-3 border-b border-line-soft sm:h-[31px]">
                  <span data-countdown={r.due} className={`font-mono text-[12.5px] whitespace-nowrap ${sameDay ? "invisible" : "text-soft"}`} suppressHydrationWarning>
                    {timeLeft(left)}
                  </span>
                  <span suppressHydrationWarning className="contents">
                    <Meter cells={windowCells(r, now)} tone={urgency(r, now)} title={windowNote(r, now)} />
                  </span>
                  <span className="min-w-0 truncate text-[14.5px]">
                    <StackSquare labels={labelsOf(r, r.href)} ready={ready} />
                    <Peek {...target(r)} title={`${r.name}: ${r.cves.join(", ")} · due ${dateLabel(r.due)}${r.ransomware ? " · known ransomware use" : ""}`} className="text-soft hover:text-accent">
                      {r.name}
                    </Peek>
                  </span>
                  <span className="text-right">{r.cvss !== null ? <Score score={r.cvss} /> : <span className="font-mono text-[12.5px] text-faint">–</span>}</span>
                </li>
              );
            })}
          </ol>
          <p className="mt-2.5 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 font-mono text-[12.5px] text-dim">
            <span>
              {anyStack && (
                <>
                  <span aria-hidden className="mr-1.5 inline-block size-[7px] bg-ink align-[1px]" />
                  in your stack ·{" "}
                </>
              )}
              bar: CISA&rsquo;s window used
            </span>
            {more > 0 && (
              <button type="button" data-due-more onClick={() => setOpen(true)} className="hover:text-accent">
                {more} more →
              </button>
            )}
          </p>
        </>
      )}

      <Drawer open={open} onClose={() => setOpen(false)} titleId={titleId} kicker="CISA KEV · due dates ahead" footerLink={{ href: KEV_CATALOG, label: "CISA’s catalog →", external: true }} closeLabel="Close the list">
        <header className="space-y-1">
          <h2 id={titleId} className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
            Every CISA deadline ahead
          </h2>
          <p className="num text-[13px] text-dim">
            {ahead.length} due dates · {ahead.filter((r) => due.includes(r)).length} within a week
          </p>
        </header>
        <ol className="border-y border-line-soft">
          {ahead.map((r) => (
            <li key={r.cves[0]} className="grid grid-cols-[3rem_minmax(0,1fr)] gap-3 border-t border-line-soft py-2.5 first:border-t-0">
              <div className="pt-0.5">
                <ScoreOrDash score={r.cvss} />
              </div>
              <div className="min-w-0">
                {r.external ? (
                  <a href={r.href} target="_blank" rel="noopener noreferrer" className="text-[13.5px] text-ink hover:text-accent">
                    {r.name}
                  </a>
                ) : (
                  <Link href={r.href} className="text-[13.5px] text-ink hover:text-accent">
                    {r.name}
                  </Link>
                )}
                <span className="num ml-2 text-[12px] text-dim">
                  {r.cves[0]}
                  {r.cves.length > 1 ? ` +${r.cves.length - 1}` : ""}
                </span>
                <p className="num mt-0.5 text-[12px] text-dim">
                  listed by CISA {dateLabel(r.added)} · <span className="text-accent">patch by {dateLabel(r.due)}</span>
                  {r.ransomware && <span className="ml-2 text-live">ransomware</span>}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </Drawer>
    </Frame>
  );
}
