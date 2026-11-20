"use client";

import dynamic from "next/dynamic";
import type { Contact } from "@/lib/panel/news";

/**
 * The home page's one moving picture: a radar scope drawn in glyphs by the
 * site's WebGL glyph engine (components/fx/glyph, scene radarScope). Its
 * contacts are the week's new exploited records (lib/panel/news.ts
 * `contacts`): once around the dial is seven days with now at twelve
 * o'clock, a higher CVSS score sits nearer the centre, and red means impact
 * is confirmed.
 *
 * The engine and the scene load on their own after the page is idle, so
 * the page's first script does not carry them; the field pauses off screen
 * and in a background tab, draws one still frame under reduced motion, and
 * leaves the space empty where WebGL2 is missing. It is decoration: the
 * numbers it pictures are in the line beside it.
 */

const GlyphField = dynamic(() => import("@/components/fx/glyph/GlyphField").then((m) => m.GlyphField), { ssr: false });

/** The page's ground (app/globals.css --color-ground), so the glyphs sit on it without an edge. */
const GROUND: [number, number, number] = [7 / 255, 9 / 255, 14 / 255];

export function RadarScope({ contacts, label, className = "" }: { contacts: readonly Contact[]; label: string; className?: string }) {
  return (
    <div data-radar={contacts.length} className={`hp-radar ${className}`}>
      <GlyphField
        // a newer sweep brings other contacts: the scene is built once per mount, so it mounts again
        key={contacts.map((c) => c.join(" ")).join("|")}
        scene={async () => (await import("@/components/fx/glyph/scenes/radarScope")).radarScope(contacts)}
        label={label}
        cell={5}
        glow={0.42}
        exposure={1.15}
        still={1.6}
        bg={GROUND}
        className="h-full w-full"
      />
    </div>
  );
}
