"use client";

import { useEffect, useState } from "react";
import { usePageSweep, type SweepState } from "@/components/live/sweep";

/**
 * The label that says how old the data on screen is, in plain words and
 * never fresher than that data:
 *
 *   "checked 6 min ago"   the sweep on screen is the newest one (swapped in, or the build's own)
 *   "data from 11 h ago"  newer data could not be loaded; this is the built snapshot's real age
 *   "updated 11 h ago"    a page that does not swap (the header on the archive, say): when its data was built
 *
 * The server renders the absolute time, which is true whenever the page is
 * read; the browser turns it into one of the lines above once it knows
 * which applies, and rewrites the age every half minute (minutes, hours or
 * days: nothing ticks). The absolute time and what it means stay in the
 * hover note.
 */

const WORDS: Record<SweepState, string> = { pending: "data from", live: "checked", current: "checked", built: "data from" };

export function ageWords(iso: string, now: number): string {
  const mins = Math.max(0, Math.round((now - Date.parse(iso)) / 60000));
  return mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : mins < 48 * 60 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} d ago`;
}

const absolute = (iso: string) => `${iso.slice(0, 16).replace("T", " ")} UTC`;

/** The label's text and hover note for a state; `idle` is the word on a page without a live layer. */
export function sweepLabel(iso: string | null, state: SweepState | null, now: number | null, idle = "data from"): { text: string; title: string } {
  if (!iso) return { text: "not swept yet", title: "The collector has not run yet." };
  const at = absolute(iso);
  // until the browser knows the state and the clock, the absolute time: true whenever it is read
  if (now === null || state === "pending") return { text: `${idle} ${at}`, title: `Sources swept ${at}.` };
  if (state === null) return { text: `${idle} ${ageWords(iso, now)}`, title: `This page was built from the sweep of ${at}.` };
  if (state === "built") return { text: `${WORDS.built} ${ageWords(iso, now)}`, title: `This page was built from the sweep of ${at}; newer data could not be loaded just now.` };
  return { text: `${WORDS[state]} ${ageWords(iso, now)}`, title: `Sources last swept ${at}; the numbers on this page are from that sweep.` };
}

export function SweepAgo({ iso, idle, className }: { iso: string | null; idle?: string; className?: string }) {
  const page = usePageSweep();
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    const tick = () => setNow(Date.now());
    const first = window.setTimeout(tick, 0);
    const every = window.setInterval(tick, 30_000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(every);
    };
  }, []);
  const shown = page?.sweep ?? iso;
  const { text, title } = sweepLabel(shown, page?.state ?? null, now, idle);
  return (
    <span className={className} title={title} data-sweep={shown ?? ""} data-sweep-state={page?.state ?? "idle"} suppressHydrationWarning>
      {text}
    </span>
  );
}
