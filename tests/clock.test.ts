import { describe, expect, it } from "vitest";
import { clockFrom } from "@/lib/clock";
import { buildHome } from "@/lib/home";
import { buildLiveFiles, homeView } from "@/lib/live/build";
import type { HomeLive } from "@/lib/live/shape";
import { SITE } from "@/lib/site";
import { emptyStats } from "@/lib/stats-schema";
import { incident } from "./fixtures";

/** The build's one clock (lib/clock.ts): the newest sweep's time, the same in every process of a build. */

const SWEEP = "2026-11-20T06:48:10.000Z";
const at = (iso: string) => Date.parse(iso);
const DAY_MS = 86_400_000;

describe("the build's clock", () => {
  it("is the newest sweep's time, whenever the build reads it", () => {
    expect(clockFrom(SWEEP, at("2026-11-20T06:51:21.000Z")).toISOString()).toBe(SWEEP);
    expect(clockFrom(SWEEP, at("2026-11-20T06:51:59.000Z")).toISOString()).toBe(SWEEP);
  });

  it("falls back to the current time with no sweep, a bad time, or one in the future", () => {
    const now = at("2026-11-20T07:00:00.000Z");
    expect(clockFrom(null, now).getTime()).toBe(now);
    expect(clockFrom("not a time", now).getTime()).toBe(now);
    expect(clockFrom("2026-11-20T08:00:00.000Z", now).getTime()).toBe(now);
  });
});

describe("the race it closes", () => {
  // two records created seven days and a few seconds before the build, as on 2026-11-20
  const edge = [1, 2].map((n) =>
    incident({ id: `AIR-2026-010${n}`, slug: `edge-record-${n}`, severity: 3, lane: "breach", state: "live", first_reported: "2026-11-13", incident_date: "2026-11-13", created_at: new Date(at("2026-11-13T06:51:57.000Z") + n).toISOString() }),
  );
  const fresh = incident({ id: "AIR-2026-0103", slug: "a-fresh-record", severity: 3, lane: "breach", state: "live", first_reported: "2026-11-19", incident_date: "2026-11-19", created_at: "2026-11-19T10:00:00.000Z" });
  const incidents = [...edge, fresh];
  const prebuildAt = at("2026-11-20T06:51:21.000Z");
  const pageAt = at("2026-11-20T06:51:59.000Z");

  // compared whole, so the test does not depend on how the home model names its parts
  it("two clocks seconds apart built two different pages", () => {
    const early = buildHome(incidents, emptyStats(), new Date(prebuildAt), SWEEP, SITE.origin);
    const late = buildHome(incidents, emptyStats(), new Date(pageAt), SWEEP, SITE.origin);
    expect(JSON.stringify(late.panel)).not.toBe(JSON.stringify(early.panel));
  });

  it("one clock counts it once, in every process", () => {
    const early = buildHome(incidents, emptyStats(), clockFrom(SWEEP, prebuildAt), SWEEP, SITE.origin);
    const late = buildHome(incidents, emptyStats(), clockFrom(SWEEP, pageAt), SWEEP, SITE.origin);
    expect(late.panel).toEqual(early.panel);
    expect(late.stats.counters).toEqual(early.stats.counters);
    expect(late.live.counters).toEqual(early.live.counters);
  });

  it("makes a page built from a sweep the same model as that sweep's live file", () => {
    const built = homeView(buildHome(incidents, emptyStats(), clockFrom(SWEEP, pageAt + DAY_MS / 24), SWEEP, SITE.origin), null);
    const file = JSON.parse(buildLiveFiles({ incidents, stats: emptyStats(), briefings: [], sweep: SWEEP })["home.json"]!) as HomeLive;
    expect(file.view).toEqual(JSON.parse(JSON.stringify(built)));
  });
});
