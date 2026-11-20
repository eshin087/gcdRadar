"use client";

import { useEffect, useMemo, useState } from "react";
import { usePanelState } from "@/components/home/panel/PanelState";
import { rowStack, stackHits } from "@/lib/panel/picks";

/** The visitor's clock, starting from the build's so the first paint matches the server's, then every half minute. */
export function useNow(built: number): number {
  const [now, setNow] = useState(built);
  useEffect(() => {
    const tick = () => setNow(Date.now());
    const first = window.setTimeout(tick, 0);
    const every = window.setInterval(tick, 30_000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(every);
    };
  }, []);
  return now;
}

/**
 * The stack picks a row belongs to: the build's own answer for the default
 * stack, recomputed for a visitor's picks from the candidates' items
 * (lib/panel/picks.ts stackHits) once the stack file is in. `ready` is the
 * panel's: false while a returning visitor's own stack is still loading.
 */
export function useStackLabels(): { labelsOf: (row: { cves: readonly string[]; stack: readonly string[] }, href: string) => readonly string[]; ready: boolean } {
  const { picks, isDefault, file, ready } = usePanelState();
  const hits = useMemo(() => (isDefault || !file ? null : stackHits(file, picks)), [isDefault, file, picks]);
  return { labelsOf: (row, href) => (hits ? rowStack(hits, { cves: row.cves, href }) : row.stack), ready };
}

/** An age in the fewest letters: "now", "12 min", "5 h", "3 d". */
export function shortAge(iso: string, now: number): string {
  const mins = Math.max(0, Math.floor((now - Date.parse(iso)) / 60_000));
  return mins < 1 ? "now" : mins < 60 ? `${mins} min` : mins < 2880 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} d`;
}
