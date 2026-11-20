"use client";

import { useEffect, useMemo, useState } from "react";
import { setPageSweep, type SweepState } from "@/components/live/sweep";
import { liveApplies, pageless, parseLiveFile, type FreshRecord, type LiveFile } from "@/lib/live/shape";
import { SITE } from "@/lib/site";

/**
 * Keeps a page on the newest sweep. The page is built from a view twice a
 * day; the collector publishes a newer one every fifteen minutes
 * (lib/live), and this hook fetches it from the Worker on load, when the
 * tab comes back into view, and every five minutes while it stays visible.
 * A file from a later sweep than the build replaces the built view whole,
 * so every number, row and time a component draws comes from one sweep.
 *
 * When the fetch fails, or the file is not newer, nothing changes: the page
 * keeps what it has and its label states that data's real age
 * (components/live/SweepAgo.tsx reads the state this hook sets). The view is
 * handed on as data, so it does not matter which components draw it.
 */

/** How often an open, visible page asks again. */
export const LIVE_EVERY_MS = 5 * 60_000;
/** Coming back to the tab asks again unless the last answer is this recent. */
export const LIVE_REFOCUS_MS = 60_000;
/** After this long without a first answer the label stops waiting and states the built data's age. */
export const LIVE_PATIENCE_MS = 4000;

export interface Live<V> {
  view: V;
  /** When the sweep behind `view` finished. */
  sweep: string | null;
  state: SweepState;
  /** Records in the view that the built site has no page for yet, by slug. */
  fresh: ReadonlyMap<string, FreshRecord>;
}

const NO_FRESH: ReadonlyMap<string, FreshRecord> = new Map();

export function useLive<V>(name: string, built: V, builtSweep: string | null, keys: readonly string[]): Live<V> {
  const [file, setFile] = useState<LiveFile<V> | null>(null);
  /** What the last answer said, while no newer file is applied: the build is current, or the answer was no use. */
  const [settled, setSettled] = useState<"current" | "built" | null>(null);

  useEffect(() => {
    if (!SITE.liveApi) return;
    let stopped = false;
    let lastOk = 0;
    const load = async () => {
      if (document.visibilityState !== "visible") return;
      let got: LiveFile<V> | null = null;
      try {
        const r = await fetch(`${SITE.liveApi}/${name}`);
        if (r.ok) got = parseLiveFile<V>(await r.json(), keys, Date.now());
      } catch {
        // the Worker is optional: the page keeps what it was built with
      }
      if (stopped) return;
      if (!got) {
        setSettled((had) => had ?? "built");
        return;
      }
      lastOk = Date.now();
      if (liveApplies(builtSweep, got)) {
        const next = got;
        setFile((had) => (had && Date.parse(had.sweep) >= Date.parse(next.sweep) ? had : next));
      } else {
        // not newer: the build is the newest sweep. Newer but out of reach of its fresh list: the build stands as built.
        setSettled(builtSweep && Date.parse(got.sweep) <= Date.parse(builtSweep) ? "current" : "built");
      }
    };
    void load();
    const patience = window.setTimeout(() => setSettled((had) => had ?? "built"), LIVE_PATIENCE_MS);
    const every = window.setInterval(load, LIVE_EVERY_MS);
    const onShow = () => {
      if (document.visibilityState === "visible" && Date.now() - lastOk > LIVE_REFOCUS_MS) void load();
    };
    document.addEventListener("visibilitychange", onShow);
    return () => {
      stopped = true;
      window.clearTimeout(patience);
      window.clearInterval(every);
      document.removeEventListener("visibilitychange", onShow);
    };
  }, [name, builtSweep, keys]);

  const state: SweepState = file ? "live" : (settled ?? "pending");
  const sweep = file ? file.sweep : builtSweep;

  // the labels (hero, board, site header) read which sweep is on screen from one place
  useEffect(() => {
    setPageSweep({ sweep, state });
  }, [sweep, state]);
  useEffect(() => () => setPageSweep(null), []);

  const fresh = useMemo(() => (file ? pageless(file, builtSweep) : NO_FRESH), [file, builtSweep]);
  return { view: file ? file.view : built, sweep, state, fresh };
}
