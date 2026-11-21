"use client";

import Link from "next/link";
import { useState } from "react";
import { Frame } from "@/components/home/Frame";
import { Peek } from "@/components/home/Look";
import { shortAge, useNow, useStackLabels } from "@/components/home/useNow";
import { NEWS_ROWS, newsList, type News as NewsData, type NewsRow, type NewsTab } from "@/lib/panel/news";

/**
 * The week's news (lib/panel/news.ts), four lists behind four tabs on the
 * section's line: top stories (the records the most outlets reported),
 * breaches, AI, and the visitor's own stack. A row is its age, the record's
 * title, the outlets that reported it by name, and how many there are in
 * all. Red "impact" marks a record with data, money or service lost; "your
 * stack" one that belongs to the visitor's products (recomputed in the
 * browser for their own picks); "AI" one where AI was the target or the
 * weapon. A row opens the record's quick look.
 *
 * The selected tab is the section's heading. `data-news`, `data-row="news"`,
 * `data-slug` and `data-sources` are what scripts/check-home.mjs reads.
 */

const TABS: { key: NewsTab; label: string }[] = [
  { key: "top", label: "Top stories" },
  { key: "breaches", label: "Breaches" },
  { key: "ai", label: "AI" },
  { key: "stack", label: "My stack" },
];

const EMPTY: Record<NewsTab, string> = {
  top: "Nothing reported this week yet.",
  breaches: "No breach reported this week.",
  ai: "No record with an AI role this week.",
  stack: "Nothing this week names a product in your stack.",
};

function Row({ r, labels, ready, now }: { r: NewsRow; labels: readonly string[]; ready: boolean; now: number }) {
  const more = r.sources - r.by.length;
  return (
    <li data-row="news" data-slug={r.slug} data-sources={r.sources} data-ai={r.type === "not_ai" ? "0" : "1"} className="grid grid-cols-[2.6rem_minmax(0,1fr)] gap-x-3 border-b border-line-soft py-2.5 sm:grid-cols-[2.6rem_minmax(0,1fr)_auto]">
      <span className="pt-px font-mono text-[12.5px] text-dim" title={`${r.created.slice(0, 16).replace("T", " ")} UTC`} suppressHydrationWarning>
        {shortAge(r.created, now)}
      </span>
      <span className="min-w-0">
        <Peek slug={r.slug} title={r.title} className="line-clamp-2 text-[15px] leading-snug font-medium text-ink hover:text-accent sm:line-clamp-1">
          {r.title}
        </Peek>
        <span data-news-by className="mt-0.5 block truncate text-[13px] text-dim">
          {r.by.join(" · ")}
          {more > 0 && ` +${more}`}
        </span>
      </span>
      <span className="col-start-2 mt-1 flex items-baseline gap-x-3 font-mono text-[12.5px] whitespace-nowrap text-dim sm:col-start-3 sm:mt-0 sm:flex-col sm:items-end sm:gap-y-0.5">
        <span className={r.sources >= 3 ? "text-soft" : undefined}>
          {r.sources} {r.sources === 1 ? "source" : "sources"}
        </span>
        <span className="flex gap-x-2.5">
          {r.severity >= 4 && (
            <span data-news-impact className="text-live" title="Confirmed impact: data, money or service lost">
              impact
            </span>
          )}
          <span data-stack={ready ? "ready" : "wait"} className="contents">
            {labels.length > 0 && (
              <span data-stack-mark={labels.join(",")} className="text-ink" title={`In your stack: ${labels.join(", ")}`}>
                your stack
              </span>
            )}
          </span>
          {r.type !== "not_ai" && (
            <span data-ai-mark className="text-accent" title={r.type === "attack_on_ai" ? "Attack on AI: an AI model, agent or AI-powered product was the thing exploited" : "AI-enabled attack: attackers used AI as a meaningful part of the attack"}>
              AI
            </span>
          )}
        </span>
      </span>
    </li>
  );
}

export function News({ news, built, live }: { news: NewsData; built: string; live: number }) {
  const [tab, setTab] = useState<NewsTab>("top");
  const now = useNow(Date.parse(built));
  const { labelsOf, ready } = useStackLabels();
  const labels = (r: NewsRow) => labelsOf(r, `/incidents/${r.slug}`);
  const list = newsList(news, tab, labels);
  const rows = list.slice(0, NEWS_ROWS);
  const all = (
    <Link href="/live" data-news-all>
      all {live.toLocaleString("en-US")} live →
    </Link>
  );
  return (
    <Frame
      id="news"
      label="This week's news"
      data-instrument="news"
      title={
        <div role="tablist" aria-label="News lists" className="flex">
          {TABS.map((t) => (
            <button key={t.key} type="button" role="tab" id={`news-tab-${t.key}`} aria-selected={tab === t.key} aria-controls="news-list" data-news-tab={t.key} onClick={() => setTab(t.key)} className="px-2 first:pl-0 last:pr-0 sm:px-2.5">
              {t.label}
            </button>
          ))}
        </div>
      }
      control={all}
      controlFrom="sm"
    >
      <ol id="news-list" role="tabpanel" aria-labelledby={`news-tab-${tab}`} data-news={tab} data-count={list.length} className="-mt-2.5">
        {rows.map((r) => (
          <Row key={r.slug} r={r} labels={labels(r)} ready={ready} now={now} />
        ))}
        {rows.length === 0 && (
          <li data-note className="py-3 text-[14.5px] text-soft">
            {EMPTY[tab]}
          </li>
        )}
      </ol>
      <p className="mt-3 font-mono text-[12.5px] text-dim sm:hidden [&_a:hover]:text-accent">{all}</p>
    </Frame>
  );
}
