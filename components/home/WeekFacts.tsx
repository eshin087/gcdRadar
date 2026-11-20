"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { openCounter } from "@/components/hero/ExploitedWeek";
import { Frame } from "@/components/home/Frame";
import { usePanelState } from "@/components/home/panel/PanelState";
import { RadarScope } from "@/components/home/RadarScope";
import { shortDate } from "@/lib/panel/dates";
import { ratioLevel, type Level } from "@/lib/panel/levels";
import type { News } from "@/lib/panel/news";
import type { Week } from "@/lib/panel/week";

/**
 * This week (lib/panel/week.ts): six facts against a typical week, one line
 * each (the number, what it counts, one grey comparison), in two short
 * columns beside the radar scope. The only colour is amber on a week that
 * runs busy and on a Patch Tuesday that is here. A fact's name opens the
 * list behind its number (the hidden counters' drawers in
 * components/home/HomeCounters.tsx) or leads to /trends. Published follows
 * the live NVD count when the Worker has a newer one and says "live".
 *
 * `data-week`, `data-line`, `data-level` and `data-value` are what
 * scripts/check-home.mjs reads.
 */

const fmt = (n: number) => n.toLocaleString("en-US");
const DAY_MS = 86_400_000;

function Fact({ k, level, note, value, label, onOpen, href, fact, warm }: { k: string; level?: Level | null; note: string; value: string | null; label: string; onOpen?: () => void; href?: string; fact: ReactNode; warm?: boolean }) {
  const name = "text-[14.5px] text-ink";
  return (
    <li data-line={k} data-level={level ?? ""} title={note} className="grid h-10 grid-cols-[4.2rem_minmax(0,1fr)] items-baseline gap-x-3 border-b border-line-soft pt-[9px] sm:h-9 sm:pt-[7px]">
      <span data-value={value ?? ""} className="text-right font-mono text-[16px] font-medium text-ink tabular-nums">
        {value ?? "—"}
      </span>
      <span className="flex min-w-0 items-baseline gap-x-2.5 whitespace-nowrap">
        {onOpen && value !== null ? (
          <button type="button" onClick={onOpen} aria-label={`${label}, open the list`} className={`${name} hover:text-accent`}>
            {label}
          </button>
        ) : href ? (
          <Link href={href} className={`${name} hover:text-accent`}>
            {label}
          </Link>
        ) : (
          <span className={name}>{label}</span>
        )}
        <span className={`min-w-0 truncate font-mono text-[12.5px] ${warm ? "text-accent" : "text-dim"}`}>{fact}</span>
      </span>
    </li>
  );
}

export function WeekFacts({ week: w, news, today, briefing }: { week: Week; news: Pick<News, "exploited" | "impact" | "contacts">; today: string; briefing: { week: string } | null }) {
  const { pulse } = usePanelState();
  const published = pulse?.week ?? w.published.n;
  const publishedLevel = published === null ? null : pulse ? ratioLevel(pulse.week, w.published.typical) : w.published.level;
  const over = published !== null && w.published.typical ? Math.round((published / w.published.typical - 1) * 100) : null;
  const ptDays = Math.round((Date.parse(`${w.patchTuesday}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / DAY_MS);
  const ex = w.exploited;
  const br = w.breaches;
  const ai = w.ai;
  const aiN = ai.onAi + ai.usingAi;
  const aiTechniques = [ai.topTarget && `${ai.topTarget.n} ${ai.topTarget.label}`, ai.topWeapon && `${ai.topWeapon.n} ${ai.topWeapon.label}`].filter(Boolean).join(", ");
  const radarWords = `${news.exploited} new exploited ${news.exploited === 1 ? "record" : "records"} this week${news.impact ? `, ${news.impact} with confirmed impact` : ""}`;

  return (
    <Frame
      id="week"
      label="This week against a typical one"
      data-instrument="week"
      title={<h2>This week</h2>}
      control={
        <>
          {briefing && <Link href={`/briefing/${briefing.week}`}>briefing</Link>}
          <Link href="/trends">trends →</Link>
        </>
      }
    >
      <div className="grid items-center gap-x-12 gap-y-6 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="-mt-2.5 min-w-0">
          <ol data-week className="grid gap-x-11 sm:grid-flow-col sm:grid-cols-2 sm:grid-rows-3">
            <Fact
              k="published"
              level={publishedLevel}
              note={`CVEs published in the last 7 days (NVD)${w.published.typical !== null ? `; a typical week has ${fmt(w.published.typical)}` : ""}${pulse ? "; live from the Worker's count, newer than the build" : ""}. The name opens the list.`}
              value={published === null ? null : fmt(published)}
              label="CVEs published"
              onOpen={w.published.n === null ? undefined : () => openCounter("cves_7d")}
              warm={publishedLevel !== null && publishedLevel >= 2}
              fact={
                <>
                  {over !== null ? `${Math.abs(over)}% ${over >= 0 ? "above" : "below"} typical` : "in 7 days"}
                  {pulse && <span className="text-accent"> · live</span>}
                </>
              }
            />
            <Fact
              k="critical"
              level={w.critical.typical !== null ? w.critical.level : null}
              note={`CVEs scored 9.0 or higher in the last 7 days${w.critical.typical !== null ? `; a typical week has ${fmt(w.critical.typical)}` : ""}. The name opens the list.`}
              value={w.critical.n === null ? null : fmt(w.critical.n)}
              label="critical CVEs"
              onOpen={() => openCounter("critical_7d")}
              fact="CVSS 9.0 and up"
            />
            <Fact
              k="exploited"
              level={ex.n !== null ? ex.level : null}
              note={`Added to CISA's Known Exploited Vulnerabilities catalog in the last 7 days${ex.lastWeek !== null ? `; last week ${fmt(ex.lastWeek)}` : ""}. The name opens the list.`}
              value={ex.n === null ? null : fmt(ex.n)}
              label="newly exploited"
              onOpen={() => openCounter("kev_7d")}
              warm={ex.n !== null && ex.level >= 2}
              fact={ex.band ? `typical ${fmt(Math.round(ex.band.p25))} to ${fmt(Math.round(ex.band.p75))}` : "CISA KEV additions"}
            />
            <Fact
              k="breaches"
              note={`Breaches verified by Have I Been Pwned this month${br.typicalMonth !== null ? `; a typical month has ${fmt(br.typicalMonth)}` : ""}. The name opens the list.`}
              value={br.n === null ? null : fmt(br.n)}
              label="breaches this month"
              onOpen={() => openCounter("breached_accounts_month")}
              fact={br.accounts !== null ? `${(br.accounts / 1e6).toFixed(1)} M accounts` : "verified"}
            />
            <Fact
              k="ai"
              note={`This week's incidents where AI was the target or the weapon${aiTechniques ? ` (${aiTechniques})` : ""}: ${ai.onAi} attacks on AI, ${ai.usingAi} using AI. The name leads to Trends.`}
              value={fmt(aiN)}
              label="incidents involving AI"
              href="/trends#ai-security"
              fact={`of ${ai.total} this week`}
            />
            <Fact
              k="patch-tuesday"
              note="The second Tuesday of the month, when Microsoft, Adobe and SAP publish their security updates."
              value={String(Math.max(0, ptDays))}
              label={ptDays === 1 ? "day to Patch Tuesday" : "days to Patch Tuesday"}
              warm={ptDays <= 1}
              fact={ptDays === 0 ? "today" : shortDate(w.patchTuesday)}
            />
          </ol>
          <p data-radar-note className="mt-3 flex items-baseline gap-x-2 font-mono text-[12.5px] text-dim">
            <span aria-hidden className="inline-block size-[7px] flex-none bg-accent" />
            <span>
              on the radar: {radarWords}
              {news.impact > 0 && (
                <>
                  {" "}
                  (<span className="text-live">red</span>)
                </>
              )}
            </span>
          </p>
        </div>
        <RadarScope contacts={news.contacts} label={`A radar scope: ${radarWords}.`} className="h-[150px] w-full" />
      </div>
    </Frame>
  );
}
