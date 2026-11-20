"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { Frame } from "@/components/home/Frame";
import { ScoreOrDash, Tag } from "@/components/home/panel/marks";
import { usePanelState } from "@/components/home/panel/PanelState";
import { StackChooser } from "@/components/home/panel/StackChooser";
import { StackCriticals } from "@/components/home/panel/StackCriticals";
import { Score } from "@/components/home/Score";
import { QuickLook } from "@/components/incidents/QuickLook";
import { Drawer } from "@/components/ui/Drawer";
import { dateLabel } from "@/lib/format";
import { STACK_CRITS_NAMED, STACK_ROWS } from "@/lib/panel/caps";
import { CRITICAL_DAYS, CRITICAL_MIN, STACK_DAYS, critNote, flagBadge, type FlagTone, type StackCandidate, type StackCrit, type StackFile, type StackItem } from "@/lib/panel/picks";

/**
 * My stack (lib/panel/stack.ts): the visitor's products that need action
 * today, and nothing else. A product is drawn when something of it is
 * exploited and still open (lib/panel/picks.ts tiers 1 to 3: no full patch,
 * a CISA deadline, confirmed impact), most urgent first as PanelState hands
 * them over. A row is a square light, the product, why it is here in the
 * light's colour ("no patch", "patch by 24 Nov", "confirmed impact") and the
 * CVSS score of the item behind that reason with its meter, or "no score
 * yet". Quiet products are counted at the line's right end ("8 products · 6
 * need action") and listed under "edit"; they are not drawn.
 *
 * Under the rows, one grey line names the highest new critical CVEs (9.0 and
 * up, not exploited) across the whole stack, score first; a name opens its
 * product's list, where all of them are. A row opens the list behind the
 * product (the candidate's `items`, fetched with /stats/stack.json on first
 * use). "edit" opens the product chooser (StackChooser.tsx), where "copy
 * share link" puts the picks in ?stack= so a bookmark or a teammate's link
 * opens the same stack.
 */

const TONE_INK: Record<FlagTone, string> = { harm: "text-live", open: "text-live", due: "text-accent", partial: "text-partial" };
const TONE_LIGHT: Record<FlagTone, string> = { harm: "bg-live", open: "bg-live", due: "bg-accent", partial: "bg-partial" };

function FlagBadge({ flag, title }: { flag: string; title?: string }) {
  const b = flagBadge(flag);
  return (
    <Tag tone={b.tone} title={title}>
      {b.word}
    </Tag>
  );
}

/** A flag in the row's words: the build's own, with "yet" dropped from "no patch yet". */
const flagWords = (flag: string) => (flag === "no patch yet" ? "no patch" : flag);

function Row({ t, onOpen }: { t: StackCandidate; onOpen: () => void }) {
  const b = flagBadge(t.flag!);
  return (
    <button
      type="button"
      onClick={onOpen}
      data-stack-tile={t.key}
      data-flag={t.flag ?? ""}
      data-n={t.n}
      data-tier={t.tier}
      data-crit={t.crit}
      data-score={t.flagScore ?? ""}
      title={`${t.why.join(" · ")} · ${t.n} exploited in the last ${STACK_DAYS} days${t.crit ? ` · ${critNote(t.crit)} in ${CRITICAL_DAYS} days` : ""}`}
      aria-label={`${t.label}: ${t.flag}, ${t.flagScore !== null ? `CVSS ${t.flagScore}` : "no score yet"}, open the list`}
      className="group grid h-11 w-full grid-cols-[7px_auto_minmax(0,1fr)_auto] items-center gap-x-2.5 border-b border-line-soft text-left sm:h-9"
    >
      <span aria-hidden className={`size-[7px] ${TONE_LIGHT[b.tone]}`} />
      <span className="truncate text-[14.5px] font-medium text-ink group-hover:text-accent">{t.label}</span>
      <span data-stack-badge={b.tone} className={`truncate font-mono text-[12.5px] ${TONE_INK[b.tone]}`}>
        {flagWords(t.flag!)}
      </span>
      <span className="flex items-center gap-2.5">
        {t.flagScore !== null ? (
          <Score score={t.flagScore} meter />
        ) : (
          <span data-score-none className="font-mono text-[12.5px] text-dim">
            no score yet
          </span>
        )}
      </span>
    </button>
  );
}

/**
 * The products the stack's new critical CVEs name, each once with its highest
 * score and the pick whose list holds it, highest score first. A tile carries
 * its few highest (lib/panel/picks.ts CRITS_ON_TILE), so a name stands for at
 * least the CVEs seen here; the pick's list has them all.
 */
function topCrits(tiles: readonly StackCandidate[]): { crit: StackCrit; tile: StackCandidate }[] {
  const byName = new Map<string, { crit: StackCrit; tile: StackCandidate }>();
  for (const tile of tiles)
    for (const crit of tile.crits ?? []) {
      const had = byName.get(crit.name);
      if (!had || crit.score > had.crit.score) byName.set(crit.name, { crit, tile });
    }
  return [...byName.values()].sort((a, b) => b.crit.score - a.crit.score || b.crit.published.localeCompare(a.crit.published) || a.crit.name.localeCompare(b.crit.name));
}

/* ---------- a product's list ---------- */

const OPEN_WORDS: Record<Exclude<StackItem["open"], null | "due">, { word: string; cls: string }> = {
  unpatched: { word: "no patch yet", cls: "text-live" },
  partial: { word: "partly patched", cls: "text-partial" },
  loss: { word: "confirmed impact", cls: "text-live" },
};

function ItemRow({ it, onLook }: { it: StackItem; onLook: (cve: string) => void }) {
  const cls = "text-[13.5px] text-ink hover:text-accent";
  const cve = it.cves.length > 1 ? `${it.cves[0]} +${it.cves.length - 1}` : it.cves[0];
  return (
    <li data-stack-item={it.kind} className="grid grid-cols-[3rem_minmax(0,1fr)] gap-3 border-t border-line-soft py-2.5 first:border-t-0">
      <div className="pt-0.5">
        <ScoreOrDash score={it.cvss} />
      </div>
      <div className="min-w-0">
        {it.external && it.cves[0] ? (
          // a KEV entry with no record of ours: its fix block opens here (components/incidents/QuickLook.tsx) instead of sending the reader to NVD
          <button type="button" data-quicklook-open={it.cves[0]} onClick={() => onLook(it.cves[0]!)} className={`${cls} text-left`}>
            {it.name}
          </button>
        ) : it.external ? (
          <a href={it.href} target="_blank" rel="noopener noreferrer" className={cls}>
            {it.name}
          </a>
        ) : (
          <Link href={it.href} className={cls}>
            {it.name}
          </Link>
        )}
        {cve && <span className="num ml-2 text-[12px] text-dim">{cve}</span>}
        <p className="num mt-0.5 text-[12px] text-dim">
          {it.kind === "kev" ? "listed by CISA" : "reported"} {dateLabel(it.date)}
          {it.due && (
            <>
              {" · "}
              <span className={it.open === "due" ? "text-accent" : ""}>due {dateLabel(it.due)}</span>
            </>
          )}
          {it.open && it.open !== "due" && <span className={`ml-2 ${OPEN_WORDS[it.open].cls}`}>{OPEN_WORDS[it.open].word}</span>}
        </p>
      </div>
    </li>
  );
}

/**
 * What a product's number counts, in the shared drawer shell: KEV entries
 * CISA listed in the 90 days and our exploited records no entry stands for,
 * open ones first. The count line starts with plain digits and the rows are
 * `ol > li`, the contract scripts/check-home.mjs reads; the line saying why
 * the product is flagged and the rows appear together once the file is in.
 */
function StackDrawer({ cand, file, onClose, onLook }: { cand: StackCandidate | null; file: StackFile | null; onClose: () => void; onLook: (cve: string) => void }) {
  const titleId = useId();
  if (!cand) return null;
  const full = file?.candidates.find((c) => c.key === cand.key);
  const items = full?.items ?? null;
  const kevN = items ? items.filter((x) => x.kind === "kev").length : 0;
  const external = cand.href.startsWith("http");
  return (
    <Drawer
      open
      onClose={onClose}
      titleId={titleId}
      kicker={`My stack · exploited in the last ${STACK_DAYS} days`}
      footerLink={{ href: cand.href, label: external ? "CISA’s catalog →" : "product page →", external }}
      closeLabel="Close the list"
    >
      <header className="space-y-1">
        <h2 id={titleId} className="text-[18px] font-semibold leading-tight tracking-tight text-ink">
          {cand.label}
        </h2>
        <p className="num text-[13px] text-dim">
          {String(cand.n)} exploited in {STACK_DAYS} days
          {items && (
            <>
              {" · "}
              {kevN} on CISA’s list · {items.length - kevN} in our records
            </>
          )}
        </p>
      </header>
      {!items ? (
        <p className="text-[13px] text-dim">Loading…</p>
      ) : (
        <>
          {cand.flag && (
            <p className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[12px] text-soft">
              <FlagBadge flag={cand.flag} />
              <span>{cand.why.join(" · ")}</span>
            </p>
          )}
          {items.length === 0 ? (
            <p className="text-[13px] text-dim">Nothing exploited in the last {STACK_DAYS} days.</p>
          ) : (
            <ol className="border-y border-line-soft">
              {items.map((it, i) => (
                <ItemRow key={`${it.kind}-${it.cves[0] ?? it.href}-${i}`} it={it} onLook={onLook} />
              ))}
            </ol>
          )}
          <StackCriticals cand={cand} crits={full?.crits ?? null} />
        </>
      )}
    </Drawer>
  );
}

/* ---------- the section ---------- */

export function MyStack() {
  const { tiles, picks, isDefault, ready, file, loadFile, setPicks } = usePanelState();
  const [open, setOpen] = useState(false);
  const [all, setAll] = useState(false);
  const [shown, setShown] = useState<StackCandidate | null>(null);
  const [look, setLook] = useState<string | null>(null);
  const [copied, setCopied] = useState<"" | "copied" | "in the address bar">("");

  const choose = async () => {
    setOpen(true);
    await loadFile();
  };
  const show = async (t: StackCandidate) => {
    setShown(t);
    await loadFile();
  };
  const share = async () => {
    const url = `${location.origin}/?stack=${picks.join(",")}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied("copied");
    } catch {
      history.replaceState(null, "", `/?stack=${picks.join(",")}`);
      setCopied("in the address bar");
    }
    window.setTimeout(() => setCopied(""), 2500);
  };
  // a first pick starts the visitor's own stack from nothing: the default is the day's news, not theirs
  const mine = isDefault ? [] : picks;
  const change = (key: string, on: boolean) => setPicks(on ? [...mine.filter((k) => k !== key), key] : mine.filter((k) => k !== key));

  // what needs action: something exploited and still open (tiers 1 to 3), in the order the tiles arrive in
  const urgent = tiles.filter((t) => t.tier <= 3 && t.flag);
  const rows = all ? urgent : urgent.slice(0, STACK_ROWS);
  const crits = topCrits(tiles);
  const critTotal = tiles.reduce((n, t) => n + t.crit, 0);
  const named = crits.slice(0, STACK_CRITS_NAMED);

  return (
    <Frame
      id="stack"
      label="My stack"
      data-instrument="stack"
      title={<h2>My stack</h2>}
      control={
        <>
          <span data-stack={ready ? "ready" : "wait"} data-stack-count>
            {tiles.length} {tiles.length === 1 ? "product" : "products"} · <span className={urgent.length ? "text-soft" : undefined}>{urgent.length} need action</span>
          </span>
          <button type="button" onClick={choose} className="text-accent">
            edit
          </button>
        </>
      }
    >
      <div data-stack={ready ? "ready" : "wait"} data-tiles={tiles.length} data-urgent={urgent.length} className="grid gap-x-11 sm:grid-cols-2 lg:grid-cols-3">
        {rows.map((t) => (
          <Row key={t.key} t={t} onOpen={() => show(t)} />
        ))}
        {urgent.length === 0 && (
          <p data-stack-calm className="col-span-full text-[14.5px] text-soft">
            Nothing in {isDefault ? "this stack" : "your stack"} is exploited and still open today.
          </p>
        )}
      </div>
      {urgent.length > STACK_ROWS && (
        <button type="button" data-stack-more onClick={() => setAll(!all)} className="mt-3 font-mono text-[12.5px] text-dim hover:text-accent">
          {all ? "show fewer" : `+${urgent.length - STACK_ROWS} more`}
        </button>
      )}
      {named.length > 0 && (
        <p data-stack={ready ? "ready" : "wait"} data-stack-crits={critTotal} className="mt-4 flex flex-wrap items-baseline gap-x-5 gap-y-1.5 font-mono text-[13px] text-dim">
          <span>
            new, not exploited yet · CVSS {CRITICAL_MIN.toFixed(1)} and up · {CRITICAL_DAYS} days
          </span>
          {named.map(({ crit, tile }) => (
            <button key={crit.name} type="button" data-stack-crit={crit.id} onClick={() => show(tile)} title={`${crit.id} · open ${tile.label}’s list`} className="group whitespace-nowrap hover:text-accent">
              <span className="text-soft group-hover:text-accent">{crit.score.toFixed(1)}</span> {crit.name}
            </button>
          ))}
          <span title="Counted per product in your stack; a product’s list holds its own.">{critTotal} in all</span>
        </p>
      )}
      {isDefault && (
        <p className="mt-3 text-[13.5px] text-dim">
          These are today&rsquo;s most urgent well-known products.{" "}
          <button type="button" onClick={choose} className="text-soft underline decoration-line underline-offset-4 hover:text-accent">
            Choose your own
          </button>
        </p>
      )}
      {/* one drawer at a time: the list steps aside while a quick look is open and is back when it closes */}
      <StackDrawer cand={look ? null : shown} file={file} onClose={() => setShown(null)} onLook={setLook} />
      <QuickLook target={look ? { cve: look } : null} onClose={() => setLook(null)} />
      <StackChooser open={open} onClose={() => setOpen(false)} file={file} picks={mine} isDefault={isDefault} copied={copied} onShare={share} onChange={change} onReset={() => setPicks([])} />
    </Frame>
  );
}
