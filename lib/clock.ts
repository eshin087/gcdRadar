import { lastUpdated } from "./data";

/**
 * The one instant a build computes its models for: when the newest sweep
 * in data/runs.json finished.
 *
 * A build runs in several processes (prebuild, then Next's page workers),
 * and each used to take its own `new Date()`. They read the same data
 * seconds apart, so a count with a time window could disagree between the
 * page and the file it was built beside: on 2026-11-20 two records created
 * seven days and a few seconds before the build were in
 * public/stats/panel.json (written at 06:51:21) and out of the page
 * (rendered at 06:51:59), and scripts/check-home.mjs read "new this week"
 * 53 against 51. Every process reads the same runs.json, so this clock is
 * the same everywhere in a build.
 *
 * It is also the honest one. The data is what that sweep saw; the page's
 * label states that sweep's time (components/live/SweepAgo.tsx); and a
 * sweep publishes its live files computed for the same instant
 * (lib/live/build.ts), so a page built from a sweep and that sweep's live
 * file are the same model.
 *
 * File timestamps ("generated_at" in meta.json and the like) keep the real
 * time: they say when the file was written. lib/data.ts BUILD_DAY, the day
 * a record's live window is judged by, is still the build's own day; it
 * can differ only for a build that straddles midnight UTC.
 */

/** The sweep's time when there is one and it is not in the future; the current time otherwise (no run yet, or a clock gone wrong). */
export function clockFrom(lastSweep: string | null, nowMs: number): Date {
  const t = lastSweep ? Date.parse(lastSweep) : NaN;
  return Number.isFinite(t) && t <= nowMs ? new Date(t) : new Date(nowMs);
}

/** The build's clock (see above). Reads data/runs.json, which does not change during a build, so every call agrees. */
export async function buildNow(): Promise<Date> {
  return clockFrom(await lastUpdated(), Date.now());
}
