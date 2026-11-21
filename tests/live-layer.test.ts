import { describe, expect, it } from "vitest";
import { ageWords, sweepLabel } from "@/components/live/SweepAgo";
import { buildHome } from "@/lib/home";
import { boardView, buildLiveFiles, freshRecords, homeView, namedIn, statsListFiles } from "@/lib/live/build";
import { BOARD_VIEW_KEYS, FRESH_RECORD_DAYS, HOME_VIEW_KEYS, LIVE_FILE_PATTERN, LIVE_VERSION, liveApplies, liveListUrl, pageless, parseLiveFile, withLiveLists, type BoardLive, type HomeLive, type HomeView } from "@/lib/live/shape";
import { unpackStack } from "@/lib/panel/picks";
import { SITE } from "@/lib/site";
import { emptyStats, type StatsFiles } from "@/lib/stats-schema";
import { LIVE_NAME } from "../worker/src/live";
import { disclosedCve, incident } from "./fixtures";

/**
 * The live layer (lib/live): the files a sweep publishes are the site
 * build's own model at the sweep's instant; the page applies one only when
 * it is newer and safe; the label says no more than the data.
 */

const SWEEP = "2026-11-20T05:36:00.000Z";
const SRC = { name: "Test source", url: "https://example.test/source", license: "CC0 1.0" };
const hoursBefore = (h: number) => new Date(Date.parse(SWEEP) - h * 3_600_000).toISOString();

function stats(): StatsFiles {
  return {
    ...emptyStats(),
    cvesRecent: {
      fetched_at: hoursBefore(2),
      source: { ...SRC, name: "NVD" },
      window_days: 30,
      cves: [
        { id: "CVE-2026-0001", published: hoursBefore(3), score: 9.8, severity: "CRITICAL", version: "3.1", description: "Fresh critical." },
        { id: "CVE-2026-0002", published: hoursBefore(72), score: 7.5, severity: "HIGH", version: "3.1", description: "Three days old." },
      ],
    },
    kev: {
      fetched_at: hoursBefore(1),
      source: { ...SRC, name: "CISA KEV" },
      catalog_version: "2026.11.19",
      entries: [{ cve: "CVE-2026-0001", added: "2026-11-19", due: "2026-11-24", vendor: "Acme", product: "Gateway", name: "Flaw", ransomware: false, published: "2026-11-18", cvss: 9.8 }],
    },
  };
}

const older = incident({ id: "AIR-2026-0001", slug: "an-older-record", title: "An older record about a gateway", first_reported: "2026-11-01", incident_date: "2026-11-01", created_at: "2026-11-01T08:00:00.000Z", updated_at: "2026-11-01T08:00:00.000Z" });
const fresh = incident({
  id: "AIR-2026-0002",
  slug: "acme-gateway-exploited",
  title: "Acme Gateway flaw exploited in the wild",
  severity: 3,
  lane: "patch",
  state: "live",
  patch_status: "unpatched",
  cve_ids: ["CVE-2026-0001"],
  first_reported: "2026-11-19",
  incident_date: "2026-11-19",
  created_at: hoursBefore(4),
  updated_at: hoursBefore(4),
});
const unnamed = disclosedCve({ id: "AIR-2026-0003", slug: "a-disclosed-cve-nobody-links", created_at: hoursBefore(5), updated_at: hoursBefore(5) });
const incidents = [older, fresh, unnamed];

describe("the files of a sweep", () => {
  const files = buildLiveFiles({ incidents, stats: stats(), briefings: [], sweep: SWEEP });
  const home = JSON.parse(files["home.json"]!) as HomeLive;
  const board = JSON.parse(files["board.json"]!) as BoardLive;

  it("are the site build's own model at the sweep's instant", () => {
    const built = buildHome(incidents, stats(), new Date(SWEEP), SWEEP, SITE.origin);
    expect(home.view).toEqual(JSON.parse(JSON.stringify(homeView(built, null))));
    expect(board.view).toEqual(JSON.parse(JSON.stringify(boardView(built.live))));
    // the stack candidates travel packed, as the build writes them, and unpack to the build's own
    expect(unpackStack(JSON.parse(files["stack.json"]!))).toEqual(JSON.parse(JSON.stringify(built.stackFile)));
    for (const [name, body] of Object.entries(statsListFiles(built, stats(), new Date(SWEEP)))) expect(JSON.parse(files[name]!)).toEqual(JSON.parse(JSON.stringify(body)));
  });

  it("carry one sweep time, which is also the view's own", () => {
    expect(home.v).toBe(LIVE_VERSION);
    expect(home.sweep).toBe(SWEEP);
    expect(home.view.lastUpdated).toBe(SWEEP);
    expect(home.view.now).toBe(SWEEP);
    expect(board.sweep).toBe(SWEEP);
    expect(Date.parse(SWEEP) - Date.parse(home.fresh_since)).toBe(FRESH_RECORD_DAYS * 86_400_000);
  });

  it("are byte-identical when built twice, and end with a newline", () => {
    const again = buildLiveFiles({ incidents: [...incidents].reverse(), stats: stats(), briefings: [], sweep: SWEEP });
    // by name, so a failure names the file instead of printing them all
    expect(Object.keys(again).filter((name) => again[name] !== files[name])).toEqual([]);
    for (const body of Object.values(files)) expect(body.endsWith("}\n")).toBe(true);
  });

  it("have only names the Worker serves, by the same pattern on both sides", () => {
    expect(Object.keys(files).sort()).toEqual(["board.json", "breaches-2026-11.json", "cves-day.json", "cves-week.json", "home.json", "kev-week.json", "stack.json"]);
    for (const name of Object.keys(files)) {
      expect(LIVE_FILE_PATTERN.test(name)).toBe(true);
      expect(LIVE_NAME.test(name)).toBe(true);
    }
    expect(LIVE_NAME.source).toBe(LIVE_FILE_PATTERN.source);
    for (const bad of ["vercel.json", "../home.json", "home.json/x", "runs.json", "home.JSON", ""]) expect(LIVE_NAME.test(bad)).toBe(false);
  });

  it("leave the charts' series off the home view", () => {
    expect(home.view.stats.series.cves_by_year).toEqual([]);
    expect(home.view.stats.epss_top).toEqual([]);
    expect(Object.keys(home.view.panel).sort()).toEqual(["ledger", "news", "sieve", "stack", "verdict", "week"]);
    // of the ledger, only the deadlines travel: the records without a patch are a number on the page
    expect(Object.keys(home.view.panel.ledger).sort()).toEqual(["due", "later"]);
    expect("scope" in board.view).toBe(false);
  });

  it("carry in full the recent records a page can link, and no others", () => {
    expect(home.fresh.map((r) => r.slug)).toEqual([fresh.slug]);
    expect(board.fresh.map((r) => r.slug)).toEqual([fresh.slug]);
    expect(home.fresh[0]).toMatchObject({ id: fresh.id, title: fresh.title, created_at: fresh.created_at, cve_ids: ["CVE-2026-0001"] });
    expect(home.fresh[0]!.sources[0]!.url).toBe(fresh.sources[0]!.url);
  });
});

describe("fresh records", () => {
  it("are the records created in the days before the sweep, newest first", () => {
    const sweepMs = Date.parse(SWEEP);
    expect(freshRecords(incidents, sweepMs).map((r) => r.slug)).toEqual([fresh.slug, unnamed.slug]);
    const late = incident({ slug: "after-the-sweep", created_at: new Date(sweepMs + 1000).toISOString() });
    expect(freshRecords([late], sweepMs)).toEqual([]);
  });

  it("namedIn keeps the ones the text names", () => {
    const all = freshRecords(incidents, Date.parse(SWEEP));
    expect(namedIn(all, `{"slug":"${fresh.slug}"}`).map((r) => r.slug)).toEqual([fresh.slug]);
    expect(namedIn(all, "{}")).toEqual([]);
  });
});

describe("what the page does with a file", () => {
  const BUILT = "2026-11-19T18:40:00.000Z";
  const now = Date.parse("2026-11-20T05:40:00.000Z");
  const file = { v: LIVE_VERSION, sweep: SWEEP, fresh_since: "2026-11-17T05:36:00.000Z", view: { now: SWEEP, today: "2026-11-20", columns: {}, stats: {}, panel: {} }, fresh: [] as unknown[] };

  it("accepts a well-formed file and nothing else", () => {
    expect(parseLiveFile(file, HOME_VIEW_KEYS, now)).toBe(file);
    expect(parseLiveFile({ ...file, v: LIVE_VERSION + 1 }, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile({ ...file, sweep: "soon" }, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile({ ...file, view: { ...file.view, panel: undefined } }, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile({ ...file, fresh: [{ slug: "x" }] }, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile(file, BOARD_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile({ error: "the live files are unavailable" }, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile(null, HOME_VIEW_KEYS, now)).toBeNull();
    expect(parseLiveFile("[]", HOME_VIEW_KEYS, now)).toBeNull();
  });

  it("refuses a sweep time from the future, beyond a clock's drift", () => {
    expect(parseLiveFile(file, HOME_VIEW_KEYS, Date.parse(SWEEP) - 4 * 60_000)).toBe(file);
    expect(parseLiveFile(file, HOME_VIEW_KEYS, Date.parse(SWEEP) - 6 * 60_000)).toBeNull();
  });

  it("applies a file only when its sweep is later than the build's", () => {
    expect(liveApplies(BUILT, file)).toBe(true);
    expect(liveApplies(SWEEP, file)).toBe(false);
    expect(liveApplies("2026-11-20T05:37:00.000Z", file)).toBe(false);
    expect(liveApplies(null, file)).toBe(false);
  });

  it("does not apply a file whose fresh list does not reach back to the build", () => {
    // a site last built four days ago could hold a row with neither a page nor a drawer
    expect(liveApplies("2026-11-16T06:00:00.000Z", file)).toBe(false);
    expect(liveApplies("2026-11-17T05:36:00.000Z", file)).toBe(true);
  });

  it("finds the records the built site has no page for", () => {
    const made = (slug: string, created_at: string) => ({ slug, created_at }) as HomeLive["fresh"][number];
    const f = { fresh: [made("before-the-build", "2026-11-19T18:00:00.000Z"), made("in-the-built-sweep", BUILT), made("after-it", "2026-11-19T19:10:00.000Z")] };
    expect([...pageless(f, BUILT).keys()]).toEqual(["after-it"]);
    expect(pageless(f, null).size).toBe(0);
  });

  it("points a swapped view's lists at the sweep that produced it", () => {
    const base = "https://worker.example/v1/live";
    expect(liveListUrl(base, "/stats/cves-week.json", SWEEP)).toBe(`${base}/cves-week.json?s=${encodeURIComponent(SWEEP)}`);
    const view = { stats: { lists: { cves_day: { count: 1, file: "/stats/cves-day.json" }, cves_week: { count: 2, file: "/stats/cves-week.json" }, kev_week: { count: 3, file: "/stats/kev-week.json" }, breaches_month: { month: "2026-11", count: 4, file: "/stats/breaches-2026-11.json" } } } } as HomeView;
    const moved = withLiveLists(view, base, SWEEP).stats.lists;
    expect(moved.breaches_month).toEqual({ month: "2026-11", count: 4, file: `${base}/breaches-2026-11.json?s=${encodeURIComponent(SWEEP)}` });
    expect(moved.kev_week.count).toBe(3);
    for (const l of Object.values(moved)) expect(LIVE_NAME.test(new URL(l.file).pathname.replace("/v1/live/", ""))).toBe(true);
    expect(view.stats.lists.cves_day.file).toBe("/stats/cves-day.json");
  });
});

describe("the sweep label", () => {
  const iso = "2026-11-19T18:42:10.000Z";
  const at = (min: number) => Date.parse(iso) + min * 60_000;

  it("says an age in minutes, hours or days, never seconds", () => {
    expect(ageWords(iso, at(0.4))).toBe("just now");
    expect(ageWords(iso, at(6))).toBe("6 min ago");
    expect(ageWords(iso, at(59))).toBe("59 min ago");
    expect(ageWords(iso, at(11 * 60))).toBe("11 h ago");
    expect(ageWords(iso, at(72 * 60))).toBe("3 d ago");
  });

  it("says 'checked' only of the newest sweep, and the built data's age otherwise", () => {
    expect(sweepLabel(iso, "live", at(6)).text).toBe("checked 6 min ago");
    expect(sweepLabel(iso, "current", at(6)).text).toBe("checked 6 min ago");
    expect(sweepLabel(iso, "built", at(660)).text).toBe("data from 11 h ago");
    expect(sweepLabel(iso, "built", at(660)).title).toContain("newer data could not be loaded");
    expect(sweepLabel(iso, null, at(660), "updated").text).toBe("updated 11 h ago");
  });

  it("shows the absolute time until the browser knows more", () => {
    expect(sweepLabel(iso, null, null).text).toBe("data from 2026-11-19 18:42 UTC");
    expect(sweepLabel(iso, "pending", at(6), "updated").text).toBe("updated 2026-11-19 18:42 UTC");
    expect(sweepLabel(null, null, null).text).toBe("not swept yet");
  });
});
