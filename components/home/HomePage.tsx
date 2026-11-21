"use client";

import { HomeCounters } from "@/components/home/HomeCounters";
import { HomeHero } from "@/components/home/HomeHero";
import { LookProvider } from "@/components/home/Look";
import { News } from "@/components/home/News";
import { NextDue } from "@/components/home/NextDue";
import { MyStack } from "@/components/home/panel/MyStack";
import { PanelState } from "@/components/home/panel/PanelState";
import { useLiveHome } from "@/components/home/useLiveHome";
import { WeekFacts } from "@/components/home/WeekFacts";
import { FreshLinks } from "@/components/live/FreshLinks";
import type { HomeView } from "@/lib/live/shape";

/**
 * The home page: the hero (headline and three numbers, this week's exploited
 * vulnerabilities as a block numeral, the live globe; see HomeHero), then
 * four sections, each under a ruled line that carries its title
 * (components/home/Frame.tsx):
 *
 *   My stack    the visitor's products that need action, with the CVSS score
 *               behind each (components/home/panel/MyStack.tsx)
 *   news        the week's top stories, breaches, AI and the stack's own,
 *               with the outlets named (News.tsx)
 *   Next due    CISA's patch deadlines, nearest first (NextDue.tsx)
 *   This week   six facts against a typical week, and the radar scope
 *               (WeekFacts.tsx)
 *
 * A row anywhere opens the record's quick look (Look.tsx) instead of leaving
 * the page.
 *
 * Built at deploy time from a HomeView (lib/live/shape.ts). The browser runs
 * the clocks, applies a visitor's own stack and the live NVD count, and
 * redraws the whole page from a newer sweep's view when the Worker has one
 * (useLiveHome): `data` below is whichever is on screen, and every component
 * takes it from there. A record newer than the site's last rebuild opens in
 * a drawer instead of a page it does not have yet (FreshLinks). Attack
 * types, the attack surface and how AI shows up live on /trends with the
 * web's charts.
 */
export function HomePage({ data: built }: { data: HomeView }) {
  const live = useLiveHome(built);
  const data = live.view;
  const p = data.panel;
  const liveRecords = data.columns.patch.live + data.columns.breach.live + data.columns.supply_chain + data.columns.research;
  return (
    // keyed by the default stack: when a newer sweep changes it, the stack's state starts over from the new default
    <PanelState key={live.stackKey} defaults={p.stack.tiles} defaultMatches={p.sieve.inStack} nvdFetched={p.sieve.nvdFetched} stackUrl={live.stackUrl}>
      <LookProvider>
        <HomeHero data={data} />
        <div className="mt-12 flex flex-col gap-12">
          <MyStack />
          <div className="grid gap-x-14 gap-y-12 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <News news={p.news} built={data.now} live={liveRecords} />
            <NextDue due={p.ledger.due} later={p.ledger.later} built={data.now} />
          </div>
          <WeekFacts week={p.week} news={p.news} today={data.today} briefing={data.briefing} />
        </div>
        {/* the numbers on the page open their lists by clicking these hidden counter buttons; the charts' series stay off the page */}
        <HomeCounters stats={data.stats} buttonsHidden />
        <FreshLinks records={live.fresh} />
      </LookProvider>
    </PanelState>
  );
}
