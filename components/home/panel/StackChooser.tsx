"use client";

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Drawer } from "@/components/ui/Drawer";
import { CATEGORIES } from "@/lib/catalog/types";
import { CRITICAL_DAYS, STACK_DAYS, STACK_MAX, STACK_ORDER_NOTE, critNote, findTyped, flagBadge, searchStack, sortByUrgency, type FlagTone, type StackCandidate, type StackFile, type StackSearchHit } from "@/lib/panel/picks";

/**
 * The product chooser: My stack's "edit" drawer, for a catalog of several
 * hundred entries (lib/catalog). Search comes first and answers to names,
 * vendors, other names an entry goes by and the products a vendor covers,
 * with what was typed picked out. With nothing typed it shows the visitor's
 * own picks (or, before a first pick, a short list of the best-known
 * products), then the categories with their counts; a category opens its
 * list. Every list is in the one urgency order (lib/panel/picks.ts
 * byUrgency), and a row carries a status word only when something is open:
 * the flag's word in its colour, or a grey count of new critical CVEs.
 *
 * Keys: the arrows move between the search box and the rows, Enter in the
 * search box ticks the first result, Esc closes. Rows are 44 px tall labels,
 * so the whole row is the touch target.
 *
 * The count line starts with digits and the rows are `ol > li`, the drawer
 * contract scripts/check-home.mjs reads.
 */

const TONE_INK: Record<FlagTone, string> = { harm: "text-live", open: "text-live", due: "text-accent", partial: "text-partial" };
const POPULAR_SHOWN = 12;
const RESULTS_SHOWN = 60;
const HEAD = "font-mono text-[12px] uppercase tracking-[0.1em] text-dim";

interface Props {
  open: boolean;
  onClose: () => void;
  file: StackFile | null;
  /** The visitor's own picks; empty while the strip shows the default. */
  picks: string[];
  isDefault: boolean;
  copied: string;
  onShare: () => void;
  onChange: (key: string, on: boolean) => void;
  onReset: () => void;
}

/** A name with the typed part picked out. */
function Typed({ text, q }: { text: string; q: string }) {
  const at = findTyped(text.toLowerCase(), q);
  if (at === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, at)}
      <mark className="bg-transparent text-accent">{text.slice(at, at + q.length)}</mark>
      {text.slice(at + q.length)}
    </>
  );
}

/** The word a row carries while something is open; nothing on a quiet product. */
function Status({ c }: { c: StackCandidate }) {
  if (c.flag) {
    const b = flagBadge(c.flag);
    return (
      <span data-chooser-status={b.tone} title={c.why.join(" · ")} className={`shrink-0 font-mono text-[12px] font-medium uppercase tracking-[0.04em] ${TONE_INK[b.tone]}`}>
        {b.word}
      </span>
    );
  }
  if (c.crit) {
    return (
      <span data-chooser-status="crit" title={`${critNote(c.crit)} in the last ${CRITICAL_DAYS} days, none known to be exploited`} className="shrink-0 font-mono text-[12px] uppercase tracking-[0.04em] text-dim">
        {c.crit} critical
      </span>
    );
  }
  return null;
}

/** What stands beside a name: the match that is not in the name, else the vendor, or what a vendor pick covers. */
function Beside({ c, hit, q }: { c: StackCandidate; hit?: StackSearchHit; q: string }) {
  if (hit?.via) {
    return (
      <>
        {hit.rank === 5 ? "also " : "covers "}
        <Typed text={hit.via} q={q} />
      </>
    );
  }
  if (c.tail) return <>{c.also?.slice(0, 2).join(", ") ?? ""}</>;
  if (c.level === "vendor") return <>all its products</>;
  if (c.vendor && !c.label.toLowerCase().includes(c.vendor.toLowerCase())) return <Typed text={c.vendor} q={q} />;
  return null;
}

function Row({ c, on, full, q, hit, onChange }: { c: StackCandidate; on: boolean; full: boolean; q: string; hit?: StackSearchHit; onChange: (key: string, on: boolean) => void }) {
  const off = !on && full;
  return (
    <li data-chooser-row={c.key} data-tier={c.tier} className="border-t border-line-soft first:border-t-0">
      <label className={`flex min-h-11 items-center gap-3 py-2 text-[14px] ${off ? "cursor-not-allowed text-faint" : "cursor-pointer text-soft hover:text-ink"}`}>
        <input type="checkbox" checked={on} disabled={off} onChange={(e) => onChange(c.key, e.target.checked)} className="size-4 shrink-0 accent-[#ffb35c]" />
        <span className="min-w-0 flex-1 truncate">
          <span className={on ? "text-ink" : undefined}>
            <Typed text={c.label} q={q} />
          </span>
          <span className="ml-2 text-[12.5px] text-dim">
            <Beside c={c} hit={hit} q={q} />
          </span>
        </span>
        <Status c={c} />
        {c.n > 0 && (
          <span title={`${c.n} exploited in the last ${STACK_DAYS} days`} className="num w-7 shrink-0 text-right text-[13px] text-soft">
            {c.n}
          </span>
        )}
      </label>
    </li>
  );
}

function Body({ onClose, file, picks, isDefault, copied, onShare, onChange, onReset }: Omit<Props, "open">) {
  const titleId = useId();
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // search first: the box takes the focus, except on a touch screen, where that would raise the keyboard over the list
  useEffect(() => {
    if (window.matchMedia("(pointer: fine)").matches) inputRef.current?.focus({ preventScroll: true });
  }, []);

  const all = useMemo(() => file?.candidates ?? [], [file]);
  const typed = q.trim().toLowerCase().replace(/\s+/g, " ");
  const found = useMemo(() => searchStack(all, typed, RESULTS_SHOWN), [all, typed]);
  const chosen = useMemo(() => sortByUrgency(picks.map((k) => all.find((c) => c.key === k)).filter((c): c is StackCandidate => Boolean(c))), [all, picks]);
  const groups = useMemo(() => CATEGORIES.map((g) => ({ ...g, list: all.filter((c) => c.cat === g.key) })).filter((g) => g.list.length > 0), [all]);
  // a first visit's short list: the best-known names, one per vendor family (a vendor, or one of its products, not both)
  const popular = useMemo(() => {
    const families = new Set<string>();
    const out: StackCandidate[] = [];
    for (const c of all) {
      const family = c.level === "vendor" ? c.label : c.vendor;
      if (!c.popular || families.has(family)) continue;
      families.add(family);
      out.push(c);
      if (out.length >= POPULAR_SHOWN) break;
    }
    return out;
  }, [all]);
  const open = cat ? groups.find((g) => g.key === cat) : undefined;
  const full = picks.length >= STACK_MAX;
  const row = (c: StackCandidate, hit?: StackSearchHit) => <Row key={c.key} c={c} on={picks.includes(c.key)} full={full} q={typed} hit={hit} onChange={onChange} />;

  // the arrows walk the search box and everything that can be ticked or opened under it
  const onKeys = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const stops = [...(listRef.current?.querySelectorAll<HTMLElement>('input[type="checkbox"]:not(:disabled), button[data-chooser-cat], button[data-chooser-back]') ?? [])];
    const at = stops.indexOf(document.activeElement as HTMLElement);
    if (e.key === "ArrowDown") stops[Math.min(at + 1, stops.length - 1)]?.focus();
    else if (at <= 0) inputRef.current?.focus();
    else stops[at - 1]?.focus();
    e.preventDefault();
  };
  const onEnter = (e: KeyboardEvent<HTMLInputElement>) => {
    const first = found.hits[0]?.c;
    if (e.key !== "Enter" || !first) return;
    const on = picks.includes(first.key);
    if (on || !full) onChange(first.key, !on);
  };

  return (
    <Drawer open onClose={onClose} titleId={titleId} kicker="My stack · kept in this browser" closeLabel="Close the product list">
      <div onKeyDown={onKeys} className="space-y-4">
        <header className="space-y-1.5">
          <h2 id={titleId} className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
            Choose your products
          </h2>
          <p data-chooser-count className="num text-[13px] text-dim">
            {picks.length} of up to {STACK_MAX} chosen{file ? ` · ${all.length} to pick from` : ""}
          </p>
          <p className="text-[13px] leading-relaxed text-dim">
            {isDefault ? "Until you choose, the strip shows today’s most urgent of the best-known products." : "Your choice stays in this browser; the share link carries it to another device or a teammate."} A vendor covers everything it makes.
          </p>
          <p className="flex flex-wrap gap-x-5 gap-y-1 font-mono text-[12.5px]">
            <button type="button" onClick={onShare} aria-live="polite" className="text-accent hover:underline">
              {copied ? `link ${copied}` : "copy share link"}
            </button>
            {!isDefault && (
              <button type="button" onClick={onReset} data-chooser-reset className="text-dim hover:text-accent">
                clear my choice
              </button>
            )}
          </p>
        </header>

        <div className="sticky -top-5 z-10 -mx-5 bg-panel px-5 py-2 sm:-top-7 sm:-mx-7 sm:px-7">
          <input
            ref={inputRef}
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onEnter}
            placeholder="Search products and vendors"
            aria-label="Search products and vendors"
            autoComplete="off"
            spellCheck={false}
            className="w-full rounded-[3px] border border-line bg-transparent px-3 py-2.5 text-[15px] text-ink placeholder:text-faint focus:border-accent focus:outline-none"
          />
        </div>

        <div ref={listRef} className="space-y-5">
          {!file ? (
            <p data-loading className="text-[13px] text-dim">
              Loading…
            </p>
          ) : typed ? (
            <section data-chooser-view="search">
              <h3 className={HEAD}>
                {found.total} {found.total === 1 ? "match" : "matches"}
                {found.total > found.hits.length ? ` · the first ${found.hits.length} shown, keep typing` : ""}
              </h3>
              {found.hits.length > 0 ? (
                <ol className="mt-1 border-y border-line-soft">{found.hits.map((h) => row(h.c, h))}</ol>
              ) : (
                <p data-empty className="mt-2 text-[13px] leading-relaxed text-dim">
                  Nothing by that name. Try the vendor: one pick covers everything it makes.
                </p>
              )}
            </section>
          ) : open ? (
            <section data-chooser-view="category">
              <button type="button" data-chooser-back onClick={() => setCat(null)} className="font-mono text-[12.5px] text-accent hover:underline">
                ← all categories
              </button>
              <h3 className={`mt-3 ${HEAD}`}>
                {open.label} · {open.list.length}
              </h3>
              <ol className="mt-1 border-y border-line-soft">{open.list.map((c) => row(c))}</ol>
            </section>
          ) : (
            <>
              {chosen.length > 0 && (
                <section data-chooser-view="mine">
                  <h3 className={HEAD}>Your stack · {chosen.length}</h3>
                  <ol className="mt-1 border-y border-line-soft">{chosen.map((c) => row(c))}</ol>
                  {full && <p className="mt-2 text-[13px] text-dim">That is the most a stack holds. Untick one to add another.</p>}
                </section>
              )}
              {isDefault && (
                <section data-chooser-view="popular">
                  <h3 className={HEAD}>Popular</h3>
                  <ol className="mt-1 border-y border-line-soft">{popular.map((c) => row(c))}</ol>
                </section>
              )}
              <section data-chooser-view="categories">
                <h3 className={HEAD}>Browse</h3>
                <ul className="mt-1 border-y border-line-soft">
                  {groups.map((g) => {
                    const mine = g.list.filter((c) => picks.includes(c.key)).length;
                    return (
                      <li key={g.key} className="border-t border-line-soft first:border-t-0">
                        <button type="button" data-chooser-cat={g.key} data-count={g.list.length} onClick={() => setCat(g.key)} className="flex min-h-11 w-full items-center gap-3 py-2 text-left text-[14px] text-soft hover:text-ink">
                          <span className="min-w-0 flex-1 truncate">
                            {g.label}
                            {"note" in g && <span className="ml-2 text-[12.5px] text-dim">{g.note}</span>}
                          </span>
                          {mine > 0 && <span className="num shrink-0 text-[12.5px] text-accent">{mine} chosen</span>}
                          <span className="num w-8 shrink-0 text-right text-[13px] text-dim">{g.list.length}</span>
                          <span aria-hidden className="shrink-0 text-dim">
                            ›
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </section>
            </>
          )}
          <p data-chooser-order className="text-[12.5px] leading-relaxed text-faint">
            {STACK_ORDER_NOTE} The number is what was exploited in the last {STACK_DAYS} days; a coloured word means something is still open, a grey one counts new critical CVEs.
          </p>
        </div>
      </div>
    </Drawer>
  );
}

/** Mounted only while open, so each opening starts from the search box with nothing typed. */
export function StackChooser({ open, ...rest }: Props) {
  return open ? <Body {...rest} /> : null;
}
