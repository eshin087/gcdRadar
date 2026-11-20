import type { RunRecord } from "../lib/schema";
import type { Schedule } from "./lib/config";
import { FILES } from "./lib/state";

/**
 * How often a sweep reaches `main`, now that sweeps run every fifteen
 * minutes. Every push to `main` makes a Vercel deployment, and one that
 * vercel.json's ignoreCommand skips still counts against the Hobby plan's
 * hundred a day (Vercel's project settings docs: "Canceled builds are
 * counted as full deployments"). At two sweeps an hour the project spent
 * about 52 of them a day; four an hour committing every time would spend
 * about 96 and leave nothing for a merge or a preview.
 *
 * So a sweep that found nothing is not committed. Its result still reaches
 * the page: every sweep publishes the live files to their own branch
 * (collector/live.ts), which Vercel does not deploy. What a quiet sweep
 * leaves behind is only its line in the run ledger and the sources' clock,
 * and those are committed at least once an hour so the ledger keeps its
 * shape and a daily source is never asked more than a few times too often.
 *
 * And a fuse, for the day everything else fails: once `main` has taken
 * PUSH_BUDGET commits in 24 hours, a sweep that starts within
 * BUDGET_GAP_MINUTES of the last data commit does nothing, which is the old
 * half-hourly cadence until the count falls back.
 */

/** Files a sweep always touches: its own record and when each source last answered. */
export const LEDGER_FILES: ReadonlySet<string> = new Set([FILES.runs, FILES.collector]);
/** A quiet sweep's ledger lines are committed once this many minutes have passed since the last commit on main. */
export const HEARTBEAT_MINUTES = 60;
/** Commits on main in 24 hours after which sweeps fall back to half-hourly. */
export const PUSH_BUDGET = 75;
/** Under the fuse, a sweep runs only this long after the last data commit. */
export const BUDGET_GAP_MINUTES = 28;

export interface QuietInput {
  changedFiles: readonly string[];
  /** The radar sidebar file or a statistics file changed. */
  sideChanged: boolean;
  record: Pick<RunRecord, "errors" | "counts" | "llm" | "sources">;
  /** GitHub advisory lookups made this run: their answers live in collector-state.json and would be asked again. */
  lookedUp: number;
  /** Each source's schedule by id. */
  schedules: ReadonlyMap<string, Schedule>;
}

/**
 * True when a sweep left nothing worth a commit: only the ledger files
 * changed, nothing failed, nothing waits, the model was not asked, no
 * advisory was looked up, and every source it read is one read on every
 * sweep anyway (a daily source's clock must be kept, or the next sweep
 * would read it again).
 */
export function quietSweep(i: QuietInput): boolean {
  return (
    !i.sideChanged &&
    i.changedFiles.every((f) => LEDGER_FILES.has(f)) &&
    i.record.errors.length === 0 &&
    i.record.counts.pending === 0 &&
    i.record.llm.calls === 0 &&
    i.lookedUp === 0 &&
    i.record.sources.every((s) => s.ok && i.schedules.get(s.id) === "every_run")
  );
}

/** Whether a sweep's changes are committed: always when it found something, and for a quiet one once an hour (or when git cannot say how long it has been). */
export function commitsSweep(quiet: boolean, minutesSinceLastCommit: number | null): boolean {
  return !quiet || minutesSinceLastCommit === null || minutesSinceLastCommit >= HEARTBEAT_MINUTES;
}

/** The fuse: true when main has taken its day's commits and this sweep starts too soon after the last data commit. */
export function overPushBudget(commitsLastDay: number | null, minutesSinceLastDataCommit: number | null): boolean {
  if (commitsLastDay === null || commitsLastDay < PUSH_BUDGET) return false;
  return minutesSinceLastDataCommit !== null && minutesSinceLastDataCommit < BUDGET_GAP_MINUTES;
}
