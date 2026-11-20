"use client";

import { useMemo } from "react";
import { useLive, type Live } from "@/components/live/useLive";
import { HOME_VIEW_KEYS, LIVE_FILES, liveListUrl, withLiveLists, type HomeView } from "@/lib/live/shape";
import { STACK_FILE } from "@/lib/panel/picks";
import { SITE } from "@/lib/site";

/**
 * The home page's live layer: the view the page was built from, or a newer
 * sweep's once the Worker has one (components/live/useLive.ts). Whatever
 * components draw the page take `view` as their data; they need not know
 * which sweep it is from.
 *
 * With a newer sweep on screen, the files behind its numbers move with it:
 * the lists the counters open and the stack candidates are fetched from the
 * same sweep, so a number never opens a list from another one.
 */
export interface LiveHome extends Live<HomeView> {
  /** Where every stack candidate is fetched from: the build's file, or the sweep's. */
  stackUrl: string;
  /** Changes when the default stack does, so the page can start the stack's state over. */
  stackKey: string;
}

export function useLiveHome(built: HomeView): LiveHome {
  const live = useLive<HomeView>(LIVE_FILES.home, built, built.lastUpdated, HOME_VIEW_KEYS);
  const swapped = live.state === "live" && live.sweep !== null;
  const view = useMemo(() => (swapped ? withLiveLists(live.view, SITE.liveApi, live.sweep!) : live.view), [swapped, live.view, live.sweep]);
  const stackUrl = swapped ? liveListUrl(SITE.liveApi, LIVE_FILES.stack, live.sweep!) : STACK_FILE;
  return { ...live, view, stackUrl, stackKey: view.panel.stack.default.join(",") };
}
