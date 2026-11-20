"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { STACK_FILE, STACK_STORAGE_KEY, parsePicks, sortByUrgency, stackMatches, unpackStack, type StackCandidate, type StackFile, type StackMatch, type StackWire } from "@/lib/panel/picks";
import { SITE } from "@/lib/site";

/**
 * What the panel's instruments share in the browser: the visitor's stack,
 * the live NVD counts and the "AI only" lens (off on every load; the stack
 * strip holds its switch, the runway and its lists follow it).
 *
 * The stack: the build's default (the day's most urgent of the best-known
 * products) until the visitor chooses; from then on their own picks, however
 * the default moves. A ?stack=key,key URL applies and stores its picks;
 * otherwise localStorage holds them. Own picks need every candidate, fetched
 * once from /stats/stack.json and unpacked (lib/panel/picks.ts). Until that
 * settles, html.stack-custom (app/layout.tsx) hides the numbers that depend
 * on it; a failed fetch falls back to the default. The tiles come in the
 * urgency order (picks.ts byUrgency), whatever order they were picked in.
 *
 * The pulse: the Worker's /v1/pulse, fetched on load and every ten minutes
 * while the page is visible; used only when it is newer than the build's NVD
 * file. Until the Worker answers, the page keeps the build's numbers.
 */

export interface Pulse {
  fetched_at: string;
  day: number;
  week: number;
  stale: boolean;
}

interface PanelStateValue {
  /** The keys on the strip: the visitor's own, or the default's. */
  picks: string[];
  /** Nothing chosen yet: the strip shows the build's default. */
  isDefault: boolean;
  tiles: StackCandidate[];
  matches: StackMatch[];
  ready: boolean;
  file: StackFile | null;
  loadFile: () => Promise<StackFile | null>;
  setPicks: (picks: string[]) => void;
  pulse: Pulse | null;
  aiOnly: boolean;
  setAiOnly: (on: boolean) => void;
}

const Ctx = createContext<PanelStateValue | null>(null);

export function usePanelState(): PanelStateValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("usePanelState outside PanelState");
  return v;
}

const PULSE_EVERY_MS = 10 * 60_000;

// the build's file and a sweep's are written the same compact way (lib/panel/picks.ts packStack) and unpacked here
const fileRequests = new Map<string, Promise<StackFile | null>>();
function fetchStackFile(url: string = STACK_FILE): Promise<StackFile | null> {
  let request = fileRequests.get(url);
  if (!request) {
    request = fetch(url)
      .then((r) => (r.ok ? (r.json() as Promise<StackWire>).then(unpackStack) : null))
      .catch(() => null);
    fileRequests.set(url, request);
  }
  return request;
}

function readStored(): string | null {
  try {
    return localStorage.getItem(STACK_STORAGE_KEY);
  } catch {
    return null;
  }
}

function store(picks: string[] | null) {
  try {
    if (picks) localStorage.setItem(STACK_STORAGE_KEY, picks.join(","));
    else localStorage.removeItem(STACK_STORAGE_KEY);
  } catch {
    // private windows and blocked storage: the picks live for this visit only
  }
}

export function PanelState({ defaults, defaultMatches, nvdFetched, stackUrl = STACK_FILE, children }: { defaults: StackCandidate[]; defaultMatches: StackMatch[]; nvdFetched: string | null; stackUrl?: string; children: ReactNode }) {
  const defaultKeys = useMemo(() => defaults.map((t) => t.key), [defaults]);
  const [own, setOwn] = useState<string[] | null>(null);
  const [file, setFile] = useState<StackFile | null>(null);
  const [ready, setReady] = useState(false);
  const [pulse, setPulse] = useState<Pulse | null>(null);
  const [aiOnly, setAiOnly] = useState(false);

  // the visitor's own picks, from the URL or storage
  useEffect(() => {
    const fromUrl = new URLSearchParams(location.search).get("stack");
    const raw = fromUrl ?? readStored();
    // nothing stored: the default stack is already on the page, and html.stack-custom was never set
    if (!raw) return;
    let live = true;
    fetchStackFile().then((f) => {
      if (!live) return;
      if (f) {
        // a key that changed since it was saved opens the entry that took it over (the file's aliases)
        const parsed = parsePicks(raw, new Set(f.candidates.map((c) => c.key)), f.aliases);
        setFile(f);
        if (parsed.length) {
          setOwn(parsed);
          if (fromUrl || parsed.join(",") !== raw) store(parsed);
        }
      }
      setReady(true);
      document.documentElement.classList.remove("stack-custom");
    });
    return () => {
      live = false;
    };
  }, []);

  // the live NVD counts
  useEffect(() => {
    if (!SITE.pulseApi) return;
    let stopped = false;
    const built = nvdFetched ? Date.parse(nvdFetched) : 0;
    const load = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const r = await fetch(SITE.pulseApi, { cache: "no-store" });
        if (!r.ok) return;
        const j = (await r.json()) as { fetched_at?: string; nvd?: { day?: number; week?: number }; stale?: boolean };
        const t = Date.parse(j.fetched_at ?? "");
        if (stopped || !Number.isFinite(t) || t <= built || !Number.isInteger(j.nvd?.day) || !Number.isInteger(j.nvd?.week)) return;
        setPulse({ fetched_at: j.fetched_at!, day: j.nvd!.day!, week: j.nvd!.week!, stale: Boolean(j.stale) });
      } catch {
        // the Worker is optional: the page keeps the build's numbers
      }
    };
    const first = window.setTimeout(load, 1500);
    const every = window.setInterval(load, PULSE_EVERY_MS);
    const onShow = () => {
      if (document.visibilityState === "visible") load();
    };
    document.addEventListener("visibilitychange", onShow);
    return () => {
      stopped = true;
      window.clearTimeout(first);
      window.clearInterval(every);
      document.removeEventListener("visibilitychange", onShow);
    };
  }, [nvdFetched]);

  // a newer sweep on screen (components/home/useLiveHome.ts): once the candidates are in use, they come from that sweep too
  const hasFile = file !== null;
  useEffect(() => {
    if (!hasFile || stackUrl === STACK_FILE) return;
    let live = true;
    fetchStackFile(stackUrl).then((f) => {
      if (live && f) setFile(f);
    });
    return () => {
      live = false;
    };
  }, [stackUrl, hasFile]);

  const loadFile = useCallback(async () => {
    const f = file ?? (await fetchStackFile(stackUrl));
    if (f && !file) setFile(f);
    return f;
  }, [file, stackUrl]);

  // an empty list goes back to the default; anything else is the visitor's own stack, even when it equals today's default
  const setPicks = useCallback((next: string[]) => {
    setOwn(next.length ? next : null);
    store(next.length ? next : null);
  }, []);

  const isDefault = own === null;
  const picks = own ?? defaultKeys;
  const value = useMemo<PanelStateValue>(() => {
    const source = file?.candidates ?? defaults;
    const tiles = isDefault ? defaults : sortByUrgency(picks.map((k) => source.find((c) => c.key === k)).filter((c): c is StackCandidate => Boolean(c)));
    const matches = isDefault || !file ? defaultMatches : stackMatches(file, picks);
    return { picks, isDefault, tiles, matches, ready, file, loadFile, setPicks, pulse, aiOnly, setAiOnly };
  }, [picks, isDefault, file, defaults, defaultMatches, ready, loadFile, setPicks, pulse, aiOnly]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
