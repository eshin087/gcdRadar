"use client";

import { useSyncExternalStore } from "react";

/**
 * Which sweep the page on screen shows, shared between the page's live hook
 * (useLive.ts, which sets it) and the labels that state it (SweepAgo.tsx in
 * the hero, on the live board and in the site header, which sits in the
 * layout above every page). One value for the whole window: a page with a
 * live hook sets it on mount and clears it when it leaves, so the header on
 * any other page falls back to the time that page was built from.
 *
 *  - "pending": the first answer is not in yet; the label keeps the absolute time the server rendered.
 *  - "live":    a sweep newer than the build is on screen.
 *  - "current": the build is the newest sweep there is.
 *  - "built":   newer data could not be loaded (or the build is too old to swap safely); the built snapshot stands.
 */
export type SweepState = "pending" | "live" | "current" | "built";

export interface PageSweep {
  /** When the sweep behind the data on screen finished. */
  sweep: string | null;
  state: SweepState;
}

let current: PageSweep | null = null;
const listeners = new Set<() => void>();

export function setPageSweep(next: PageSweep | null): void {
  if (current?.sweep === next?.sweep && current?.state === next?.state) return;
  current = next;
  for (const l of listeners) l();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The sweep on screen, or null on a page without a live hook (and on the server). */
export function usePageSweep(): PageSweep | null {
  return useSyncExternalStore(
    subscribe,
    () => current,
    () => null,
  );
}
