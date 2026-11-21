import type { CSSProperties } from "react";
import { cvssLabel } from "@/lib/cvss";

/**
 * A CVSS score on the home page: the number in its band's colour (red from
 * 9.0, amber from 7.0, grey below) and, with `meter`, ten cells of which as
 * many are lit as the score rounds to (app/globals.css .hp-meter). The cells
 * repeat the number for the eye; the number is the fact.
 */

export type ScoreTone = 4 | 3 | 2;

export function scoreTone(score: number): ScoreTone {
  return score >= 9 ? 4 : score >= 7 ? 3 : 2;
}

const INK: Record<ScoreTone, string> = { 4: "text-live", 3: "text-accent", 2: "text-dim" };

/** Ten cells, `cells` of them lit in the tone's colour. */
export function Meter({ cells, tone, title }: { cells: number; tone: ScoreTone; title?: string }) {
  return <span aria-hidden data-meter={cells} title={title} className={`hp-meter hp-tone-${tone}`} style={{ "--n": Math.min(10, Math.max(0, cells)) } as CSSProperties} />;
}

export function Score({ score, meter = false, className = "" }: { score: number; meter?: boolean; className?: string }) {
  const tone = scoreTone(score);
  return (
    <>
      <span data-score={score} title={`CVSS base score ${cvssLabel(score)}`} className={`font-mono text-[13.5px] font-medium tabular-nums ${INK[tone]} ${className}`}>
        {cvssLabel(score)}
      </span>
      {meter && <Meter cells={Math.max(1, Math.round(score))} tone={tone} />}
    </>
  );
}
