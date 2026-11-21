import { clockFrom } from "./clock";
import { lastUpdated, loadBriefings, loadIncidents, loadStats, siteUrl } from "./data";
import { buildHome, type HomeData } from "./home";
import { briefingLine, homeView } from "./live/build";
import type { HomeView } from "./live/shape";

export interface HomePayload extends HomeData {
  /** The newest weekly briefing, for the "this week" band; null before the first Monday run. */
  briefing: { week: string; headline: string; start: string; end: string } | null;
}

/** Build-time payload for the home page and /trends: the live columns plus the statistics (lib/home.ts), computed for the build's one clock (lib/clock.ts). */
export async function getHomeData(): Promise<HomePayload> {
  const [{ incidents }, stats, updated, briefings] = await Promise.all([loadIncidents(), loadStats(), lastUpdated(), loadBriefings()]);
  return {
    ...buildHome(incidents, stats, clockFrom(updated, Date.now()), updated, siteUrl()),
    briefing: briefingLine(briefings),
  };
}

/**
 * What the home page is built from: the part of the model its components
 * read, in the shape a sweep publishes between rebuilds (lib/live), so the
 * browser can redraw the page from a newer one.
 */
export async function getHomeView(): Promise<HomeView> {
  const data = await getHomeData();
  return homeView(data, data.briefing);
}
